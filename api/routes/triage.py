"""Triage + triage-respond routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from api.schemas import TriageRequest, TriageRespondRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    enforce_process_action_policy = ctx["enforce_process_action_policy"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    observability_service = ctx["observability_service"]
    process_intel_service = ctx["process_intel_service"]
    malware_analyst_service = ctx["malware_analyst_service"]
    response_service = ctx["response_service"]
    integrity_service = ctx["integrity_service"]
    check_file_yaraify = ctx["check_file_yaraify"]
    run_local_yara_scan = ctx["run_local_yara_scan"]
    fuse_detection_verdict = ctx["fuse_detection_verdict"]
    scan_process = ctx["scan_process"]
    request_workspace_id = ctx["_request_workspace_id"]
    db = ctx["db"]

    @app.post("/triage/{pid}", dependencies=[Depends(require_analyst_or_admin)])
    def auto_triage(request: Request, pid: int, payload: TriageRequest) -> dict[str, Any]:
        apply_rate_limit(request, bucket="triage", detail="Too many triage requests. Wait briefly and retry.")
        import plugins.ai_analyst as ai_analyst
        import plugins.internals as internals
        import plugins.memory_forensics as memory_forensics
        import plugins.sandbox as sandbox
        import plugins.strings_analyser as strings_analyser

        observability_service.log_event("triage_requested", pid=pid)
        try:
            with observability_service.span(f"triage.pid.{pid}"):
                profile = process_intel_service.profile_process(pid)
                exe_path = profile.get("exe")
                strings = strings_analyser.extract_strings(exe_path, payload.strings_min_length)
                hits = strings_analyser.search_patterns(strings, payload.strings_patterns)
                yara_lookup = check_file_yaraify(profile.get("sha256", ""), payload.yaraify_auth_key) if profile.get("sha256") else {
                    "status": "skipped",
                    "reason": "Process hash unavailable",
                }
                local_yara = run_local_yara_scan(
                    exe_path,
                    pack=payload.local_yara_pack,
                    context={
                        "sha256": profile.get("sha256", "") or "",
                        "signature_status": profile.get("signature_status", ""),
                        "filepath": exe_path or "",
                    },
                ) if exe_path and (
                    str(yara_lookup.get("status", "")).lower() != "ok" or not yara_lookup.get("matched_rules")
                ) else {
                    "status": "skipped",
                    "reason": "YARAify already returned matches",
                    "matches": [],
                }
                static_pe = malware_analyst_service.analyze_file(exe_path) if exe_path else {
                    "status": "skipped",
                    "summary": "Executable path unavailable for static PE analysis.",
                }
                yara_matches = yara_lookup.get("matched_rules", []) if isinstance(yara_lookup, dict) else []
                trace = sandbox.ProcessTracer(pid).trace(duration=payload.trace_duration, interval=0.5)
                analyst = ai_analyst.AIAnalyst().analyze_process(profile)
                memory_result = memory_forensics.run_analysis(pid, profile.get("name", "process"))
                intel = None
                if payload.virustotal_api_key or payload.malwarebazaar_auth_key or payload.yaraify_auth_key:
                    intel = scan_process(
                        {"exe": exe_path, "pid": pid, "name": profile.get("name")},
                        virustotal_api_key=payload.virustotal_api_key,
                        malwarebazaar_auth_key=payload.malwarebazaar_auth_key,
                        yaraify_auth_key=payload.yaraify_auth_key,
                    )
                fused_verdict = fuse_detection_verdict(
                    yaraify_result=yara_lookup,
                    local_yara_result=local_yara,
                    virustotal_result=(intel or {}).get("virustotal", {}) if isinstance(intel, dict) else {},
                    malwarebazaar_result=(intel or {}).get("malwarebazaar", {}) if isinstance(intel, dict) else {},
                    static_result=static_pe,
                    memory_result=memory_result,
                )
                response_plan = response_service.build_triage_response_plan(
                    profile=profile,
                    fusion=fused_verdict,
                    local_yara=local_yara,
                    memory=memory_result,
                )
                triage_summary = {
                    "confidence": fused_verdict.get("confidence", "low"),
                    "severity": fused_verdict.get("severity", "low"),
                    "top_reasons": list(fused_verdict.get("reasons", []))[:5],
                    "remote_yara_hits": yara_matches[:10],
                    "local_yara_hits": local_yara.get("matched_rules", [])[:10] if isinstance(local_yara, dict) else [],
                    "inceptor_hits": [rule for rule in (local_yara.get("matched_rules", []) if isinstance(local_yara, dict) else []) if str(rule).startswith("Inceptor_")],
                    "static_pe_verdict": (
                        static_pe.get("combined_static", {}).get("verdict", "")
                        or static_pe.get("static_analysis", {}).get("verdict", "")
                    ) if isinstance(static_pe, dict) else "",
                    "static_pe_indicators": (
                        static_pe.get("combined_static", {}).get("suspicious_indicators", [])
                        or static_pe.get("static_analysis", {}).get("suspicious_indicators", [])
                    )[:6] if isinstance(static_pe, dict) else [],
                    "memory_verdict": memory_result.get("analysis", {}).get("verdict", "") if isinstance(memory_result, dict) else "",
                    "memory_confidence": memory_result.get("analysis", {}).get("fusion", {}).get("confidence", "low") if isinstance(memory_result, dict) else "low",
                    "parent_name": profile.get("parent_name", ""),
                    "child_process_count": len(profile.get("child_processes", []) or []),
                    "loaded_module_count": int(profile.get("loaded_module_count", 0) or 0),
                    "open_file_count": int(profile.get("open_file_count", 0) or 0),
                    "execution_context": profile.get("execution_context", {}),
                    "suspicious_chain_matches": profile.get("execution_context", {}).get("suspicious_chain_matches", [])[:5] if isinstance(profile.get("execution_context"), dict) else [],
                }
                observability_service.log_event("triage_completed", pid=pid, confidence=fused_verdict.get("confidence", "low"))
                return {
                    "profile": profile,
                    "internals_summary": {"handles": len(internals.get_process_handles(pid)), "modules": len(internals.get_process_libs(pid))},
                    "strings": {"total": len(strings), "hits": hits[:25]},
                    "yara": {
                        "provider": "YARAify",
                        "result": yara_lookup,
                        "matches": yara_matches,
                        "local_result": local_yara,
                        "local_matches": local_yara.get("matched_rules", []) if isinstance(local_yara, dict) else [],
                    },
                    "sandbox": trace,
                    "memory": memory_result,
                    "static_pe": static_pe,
                    "ai_analyst": analyst,
                    "threat_intel": intel,
                    "fusion": fused_verdict,
                    "triage_summary": triage_summary,
                    "response_plan": response_plan,
                }
        except HTTPException:
            raise
        except Exception as exc:
            observability_service.log_event("triage_failed", pid=pid, detail=str(exc))
            raise HTTPException(status_code=500, detail=f"Triage failed for PID {pid}: {exc}") from exc

    @app.post(
        "/triage/{pid}/respond",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def triage_respond(request: Request, pid: int, payload: TriageRespondRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="triage:respond")
        observability_service.log_event("triage_respond_requested", pid=pid)
        with observability_service.span(f"triage.respond.pid.{pid}"):
            profile = process_intel_service.profile_process(pid)
            process_name = str(profile.get("name") or payload.process_name or "process").strip()
            enforce_process_action_policy(request, process_name)
            executable_path = str(profile.get("exe") or "")
            intel = scan_process({"exe": executable_path, "pid": pid, "name": process_name}) if executable_path else {}
            memory_result = __import__("plugins.memory_forensics", fromlist=["run_analysis"]).run_analysis(pid, process_name)
            local_yara = (intel or {}).get("local_yara", {}) if isinstance(intel, dict) else {}
            static_pe = (intel or {}).get("static_pe", {}) if isinstance(intel, dict) else {}
            fusion = fuse_detection_verdict(
                yaraify_result=(intel or {}).get("yaraify", {}) if isinstance(intel, dict) else {},
                local_yara_result=local_yara,
                virustotal_result=(intel or {}).get("virustotal", {}) if isinstance(intel, dict) else {},
                malwarebazaar_result=(intel or {}).get("malwarebazaar", {}) if isinstance(intel, dict) else {},
                static_result=static_pe,
                memory_result=memory_result,
            )
            response_plan = response_service.build_triage_response_plan(
                profile=profile,
                fusion=fusion,
                local_yara=local_yara,
                memory=memory_result,
            )
            applied = response_service.apply_triage_response_plan(
                pid=pid,
                process_name=process_name,
                executable_path=executable_path,
                workspace_id=request_workspace_id(request),
                plan=response_plan,
            )
            if executable_path and any(item.get("action") == "quarantine" for item in applied.get("executed", [])):
                conn = db.create_connection()
                if conn:
                    try:
                        for item in applied.get("executed", []):
                            if item.get("action") == "quarantine":
                                db.log_quarantine(
                                    conn,
                                    pid,
                                    process_name,
                                    executable_path,
                                    item.get("result", {}).get("path", ""),
                                    "active",
                                    workspace_id=request_workspace_id(request),
                                )
                                break
                    finally:
                        conn.close()
                integrity_service.refresh_manifest()
            observability_service.log_event("triage_respond_completed", pid=pid, executed=len(applied.get("executed", [])))
            return {
                "pid": pid,
                "process_name": process_name,
                "fusion": fusion,
                "static_pe": static_pe,
                "response_plan": response_plan,
                "applied": applied,
            }
