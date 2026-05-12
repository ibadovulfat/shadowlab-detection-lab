from __future__ import annotations

from typing import Any

from fastapi import Body, Depends, HTTPException, Request


def register_routes(app, ctx: dict[str, Any]) -> None:
    # Schemas pulled back through ctx because moving them to module-top
    # (as done in integrations.py / enterprise.py) triggers a
    # pydantic-core "Circular reference detected" during response
    # serialization on /yara/local/update-workflow — investigated but
    # the interaction lives in FastAPI's TypeAdapter cache and isn't
    # worth untangling right now. The routes below that use these
    # schemas all go through `payload: dict[str, Any] = Body(...)` +
    # manual `model_validate()`, so there's no `payload: Model`
    # annotation that would fall through to Query anyway.
    StringScanRequest = ctx["StringScanRequest"]
    YaraLookupRequest = ctx["YaraLookupRequest"]
    SandboxTraceRequest = ctx["SandboxTraceRequest"]
    ProcessScanRequest = ctx["ProcessScanRequest"]
    LocalYaraPolicyRequest = ctx["LocalYaraPolicyRequest"]
    LocalYaraRuleTuningRequest = ctx["LocalYaraRuleTuningRequest"]
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    enforce_process_action_policy = ctx["enforce_process_action_policy"]
    process_intel_service = ctx["process_intel_service"]
    response_service = ctx["response_service"]
    antivirus_service = ctx["antivirus_service"]
    db = ctx["db"]
    integrity_service = ctx["integrity_service"]
    request_workspace_id = ctx["_request_workspace_id"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    check_file_yaraify = ctx["check_file_yaraify"]
    run_local_yara_scan = ctx["run_local_yara_scan"]
    scan_process = ctx["scan_process"]
    yara_scanner = ctx["yara_scanner"]
    json = ctx["json"]

    def _load_antivirus_policy() -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            return antivirus_service.default_policy()
        try:
            raw = db.get_app_setting(conn, "antivirus_policy_json")
        finally:
            conn.close()
        if not raw:
            return antivirus_service.default_policy()
        try:
            parsed = json.loads(raw)
        except Exception:
            return antivirus_service.default_policy()
        return antivirus_service.normalize_policy(parsed if isinstance(parsed, dict) else {})

    @app.get("/processes", dependencies=[Depends(require_analyst_or_admin)])
    def list_processes() -> list[dict[str, Any]]:
        return process_intel_service.snapshot_processes()

    @app.get("/processes/{pid}", dependencies=[Depends(require_analyst_or_admin)])
    def get_process(pid: int) -> dict[str, Any]:
        try:
            return process_intel_service.profile_process(pid)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/processes/{pid}/tree", dependencies=[Depends(require_analyst_or_admin)])
    def process_tree(pid: int) -> dict[str, Any]:
        snapshot = process_intel_service.snapshot_processes(include_deep_fields=False)
        indexed = {int(row["pid"]): row for row in snapshot if row.get("pid") is not None}
        if pid not in indexed:
            raise HTTPException(status_code=404, detail="Process not found")

        def build_node(current_pid: int, depth: int = 0) -> dict[str, Any]:
            current = indexed.get(current_pid, {})
            children = [
                build_node(int(row["pid"]), depth + 1)
                for row in snapshot
                if int(row.get("ppid", -1) or -1) == current_pid and depth < 3
            ]
            return {
                "pid": current_pid,
                "ppid": current.get("ppid"),
                "name": current.get("name"),
                "cmdline": current.get("cmdline"),
                "children": children,
            }

        lineage: list[dict[str, Any]] = []
        cursor = indexed[pid]
        seen: set[int] = set()
        while cursor and int(cursor.get("pid", -1)) not in seen:
            seen.add(int(cursor.get("pid", -1)))
            lineage.append(
                {
                    "pid": cursor.get("pid"),
                    "ppid": cursor.get("ppid"),
                    "name": cursor.get("name"),
                    "cmdline": cursor.get("cmdline"),
                }
            )
            parent_pid = int(cursor.get("ppid", -1) or -1)
            cursor = indexed.get(parent_pid)
        return {"root": build_node(pid), "lineage": lineage}

    @app.get("/processes/{pid}/internals", dependencies=[Depends(require_analyst_or_admin)])
    def process_internals(pid: int) -> dict[str, Any]:
        import plugins.internals as internals

        return {
            "pid": pid,
            "handles": internals.get_process_handles(pid),
            "modules": internals.get_process_libs(pid),
        }

    @app.post("/processes/{pid}/strings", dependencies=[Depends(require_analyst_or_admin)])
    def process_strings(pid: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        import plugins.strings_analyser as strings_analyser

        request_model = StringScanRequest.model_validate(payload)
        profile = process_intel_service.profile_process(pid)
        exe_path = profile.get("exe")
        strings = strings_analyser.extract_strings(exe_path, request_model.min_length)
        hits = strings_analyser.search_patterns(strings, request_model.patterns)
        return {
            "pid": pid,
            "exe": exe_path,
            "min_length": request_model.min_length,
            "patterns": request_model.patterns,
            "total_strings": len(strings),
            "sample": strings[:100],
            "pattern_hits": hits[:100],
        }

    @app.post("/processes/{pid}/yara", dependencies=[Depends(require_analyst_or_admin)])
    def process_yara(pid: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        request_model = YaraLookupRequest.model_validate(payload)
        profile = process_intel_service.profile_process(pid)
        file_hash = profile.get("sha256")
        exe_path = str(profile.get("exe") or "")
        result = {
            "status": "skipped",
            "reason": "Process hash unavailable for YARAify lookup",
        }
        if file_hash:
            result = check_file_yaraify(file_hash, request_model.yaraify_auth_key)
        local_result = (
            run_local_yara_scan(
                exe_path,
                pack=request_model.local_yara_pack,
                context={
                    "sha256": file_hash or "",
                    "signature_status": profile.get("signature_status", ""),
                    "filepath": exe_path,
                },
            )
            if exe_path
            else {
                "status": "skipped",
                "reason": "Executable path unavailable for local YARA scan",
                "matches": [],
            }
        )
        return {
            "pid": pid,
            "exe": exe_path,
            "hash": file_hash,
            "provider": "YARAify",
            "result": result,
            "local_result": local_result,
            "matches": result.get("matched_rules", []) if isinstance(result, dict) else [],
            "local_matches": local_result.get("matched_rules", []) if isinstance(local_result, dict) else [],
        }

    @app.post("/processes/{pid}/sandbox-trace", dependencies=[Depends(require_analyst_or_admin)])
    def process_sandbox_trace(pid: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        import plugins.sandbox as sandbox

        request_model = SandboxTraceRequest.model_validate(payload)
        tracer = sandbox.ProcessTracer(pid)
        return tracer.trace(duration=request_model.duration, interval=request_model.interval)

    @app.get("/processes/{pid}/ai-analysis", dependencies=[Depends(require_analyst_or_admin)])
    def process_ai_analysis(pid: int) -> dict[str, Any]:
        import plugins.ai_analyst as ai_analyst

        profile = process_intel_service.profile_process(pid)
        analyst = ai_analyst.AIAnalyst()
        return analyst.analyze_process(profile)

    @app.post("/processes/{pid}/scan", dependencies=[Depends(require_analyst_or_admin)])
    def scan_single_process(pid: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        request_model = ProcessScanRequest.model_validate(payload)
        process_rows = process_intel_service.snapshot_processes()
        target = next((row for row in process_rows if int(row.get("pid", -1)) == pid), None)
        if not target:
            raise HTTPException(status_code=404, detail="Process not found")
        result = scan_process(
            target,
            virustotal_api_key=request_model.virustotal_api_key,
            malwarebazaar_auth_key=request_model.malwarebazaar_auth_key,
            yaraify_auth_key=request_model.yaraify_auth_key,
        )
        antivirus = antivirus_service.scan_process(target, policy=_load_antivirus_policy())
        result["antivirus"] = antivirus
        fusion = result.get("fusion", {}) if isinstance(result.get("fusion"), dict) else {}
        av_summary = antivirus.get("summary", {}) if isinstance(antivirus.get("summary"), dict) else {}
        if av_summary.get("infected"):
            updated_score = min(100, int(fusion.get("score", 0) or 0) + 35)
            fusion["score"] = updated_score
            fusion["severity"] = "critical" if updated_score >= 80 else "high" if updated_score >= 55 else "medium" if updated_score >= 30 else "low"
            reasons = fusion.get("reasons", []) if isinstance(fusion.get("reasons"), list) else []
            reasons.extend(str(item) for item in av_summary.get("reasons", [])[:3])
            fusion["reasons"] = reasons
            fusion["confidence"] = "high"
        result["fusion"] = fusion
        return result

    @app.get("/processes/{pid}/memory-analysis", dependencies=[Depends(require_analyst_or_admin)])
    def memory_analysis(pid: int, process_name: str) -> dict[str, Any]:
        import plugins.memory_forensics as memory_forensics

        return memory_forensics.run_analysis(pid, process_name)

    @app.post("/processes/{pid}/actions/{action}", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
    def process_action(request: Request, pid: int, action: str, process_name: str) -> dict[str, Any]:
        require_enterprise_approval(request, action_name=f"process:{action.lower()}")
        action_name = action.lower()
        profile = process_intel_service.profile_process(pid)
        actual_process_name = str(profile.get("name") or "").strip()
        requested_process_name = process_name.strip()
        if actual_process_name and requested_process_name and actual_process_name.lower() != requested_process_name.lower():
            raise HTTPException(
                status_code=400,
                detail=f"Process name mismatch for PID {pid}: requested `{requested_process_name}` but host reports `{actual_process_name}`",
            )
        effective_process_name = actual_process_name or requested_process_name
        enforce_process_action_policy(request, effective_process_name)
        workspace_id = request_workspace_id(request)
        if action_name == "suspend":
            result = response_service.suspend(pid, effective_process_name, workspace_id=workspace_id)
        elif action_name == "resume":
            result = response_service.resume(pid, effective_process_name, workspace_id=workspace_id)
        elif action_name == "kill":
            result = response_service.kill(pid, effective_process_name, workspace_id=workspace_id)
        elif action_name == "kill-tree":
            result = response_service.kill_tree(pid, effective_process_name, workspace_id=workspace_id)
        elif action_name == "quarantine":
            result = response_service.quarantine_file(pid, effective_process_name, profile.get("exe"), workspace_id=workspace_id)
        else:
            raise HTTPException(status_code=400, detail="Unsupported action")
        if not result["ok"]:
            raise HTTPException(status_code=400, detail=result["message"])
        if action_name == "quarantine":
            conn = db.create_connection()
            if conn:
                try:
                    db.log_quarantine(
                        conn,
                        pid,
                        effective_process_name,
                        profile.get("exe"),
                        result.get("path", ""),
                        "active",
                        workspace_id=request_workspace_id(request),
                    )
                finally:
                    conn.close()
            integrity_service.refresh_manifest()
        return result

    @app.get("/yara/local/health", dependencies=[Depends(require_analyst_or_admin)])
    def local_yara_health() -> dict[str, Any]:
        return yara_scanner.build_health_report()

    @app.get("/yara/local/policy", dependencies=[Depends(require_admin)])
    def local_yara_policy() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy": yara_scanner.load_policy(),
            "health": yara_scanner.build_health_report(),
        }

    @app.put("/yara/local/policy", dependencies=[Depends(require_admin)])
    def update_local_yara_policy(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        request_model = LocalYaraPolicyRequest.model_validate(payload)
        saved = yara_scanner.save_policy(request_model.policy)
        conn = db.create_connection()
        if conn:
            try:
                db.set_app_setting(conn, "local_yara_policy_json", json.dumps(saved, ensure_ascii=False))
            finally:
                conn.close()
        return {
            "status": "updated",
            "policy": saved,
            "health": yara_scanner.build_health_report(),
        }

    @app.get("/yara/local/errors", dependencies=[Depends(require_analyst_or_admin)])
    def local_yara_errors() -> dict[str, Any]:
        health = yara_scanner.build_health_report()
        return {
            "status": "ok",
            "compile_error_count": health.get("compile_error_count", 0),
            "compile_errors": health.get("compile_errors", []),
            "policy_path": health.get("policy_path", ""),
        }

    @app.get("/yara/local/analytics", dependencies=[Depends(require_analyst_or_admin)])
    def local_yara_analytics(limit: int = 250) -> dict[str, Any]:
        return yara_scanner.analyze_sources(limit=max(25, min(int(limit), 1000)))

    @app.post("/yara/local/tuning/rule", dependencies=[Depends(require_admin)])
    def update_local_yara_rule_tuning(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        request_model = LocalYaraRuleTuningRequest.model_validate(payload)
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            db.upsert_detection_rule(
                conn,
                rule_id=request_model.rule_id,
                tuning_json=json.dumps({"score_delta": request_model.score_delta}, ensure_ascii=False),
                suppression_json=json.dumps({"disabled": request_model.disabled, "force": request_model.force}, ensure_ascii=False),
                notes=request_model.notes,
            )
            registry = db.get_detection_rules(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        yara_scanner.clear_registry_rule_override_cache()
        return {"status": "updated", "rule_id": request_model.rule_id, "registry": registry[:100]}

    @app.get("/yara/local/update-workflow", dependencies=[Depends(require_analyst_or_admin)])
    def local_yara_update_workflow() -> dict[str, Any]:
        return yara_scanner.build_update_workflow_report()

    @app.post("/yara/local/update-workflow/snapshot", dependencies=[Depends(require_admin)])
    def snapshot_local_yara_update_workflow() -> dict[str, Any]:
        return yara_scanner.save_update_snapshot()
