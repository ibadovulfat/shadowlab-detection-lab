from __future__ import annotations

import html
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.utils.antivirus_paths import allowed_antivirus_scan_roots, validate_antivirus_scan_target


class AntivirusPolicyRequest(BaseModel):
    enabled: bool = True
    providers: list[str] = Field(default_factory=lambda: ["aegis_core", "sentinel_cli"])
    max_file_size_mb: int = 128
    scan_profile: str = "balanced"
    quarantine_on_infected: bool = False
    auto_quarantine_threshold: str = "disabled"
    require_admin_for_quarantine: bool = True
    scan_timeout_seconds: int = 90
    scheduled_validation_minutes: int = 240
    signature_grace_hours: int = 48


class AntivirusFileScanRequest(BaseModel):
    file_path: str


class AntivirusQuarantineRequest(BaseModel):
    file_path: str = ""
    pid: int = -1
    process_name: str = ""
    case_id: int | None = None
    actor: str = ""
    source_scan: dict[str, Any] = Field(default_factory=dict)


class AntivirusEnterpriseCaseRequest(BaseModel):
    title: str = ""
    owner: str = ""
    priority: str = "high"
    source_scan: dict[str, Any] = Field(default_factory=dict)
    create_story: bool = True


class AntivirusDetectionExportRequest(BaseModel):
    source_scan: dict[str, Any] = Field(default_factory=dict)


class AntivirusQuarantineExportRequest(BaseModel):
    quarantine_record: dict[str, Any] = Field(default_factory=dict)


class AntivirusSignatureUpdateRequest(BaseModel):
    provider_key: str = "sentinel_cli"


class AntivirusVaultUnsealRequest(BaseModel):
    destination_path: str


class AntivirusProviderScanRequest(BaseModel):
    file_path: str
    yara_pack: str = "enterprise"


class AntivirusMitreCoverageRequest(BaseModel):
    source_scan: dict[str, Any] = Field(default_factory=dict)
    limit: int = 50


class AntivirusCredentialsRequest(BaseModel):
    """Push API keys for cloud providers — empty string clears the slot.

    Field names match the canonical short names the credential store
    uses (`virustotal`, `malwarebazaar`, `yaraify`, `hybrid_analysis`)
    so the route handler doesn't have to translate them."""
    virustotal: str | None = None
    malwarebazaar: str | None = None
    yaraify: str | None = None
    hybrid_analysis: str | None = None


def register_routes(app, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    antivirus_service = ctx["antivirus_service"]
    process_intel_service = ctx["process_intel_service"]
    db = ctx["db"]
    request_workspace_id = ctx["_request_workspace_id"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    response_service = ctx["response_service"]
    integrity_service = ctx["integrity_service"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    enterprise_service = ctx["enterprise_service"]
    investigation_service = ctx["investigation_service"]
    current_actor = ctx["current_actor"]
    workspace_artifact_dir = ctx["_workspace_artifact_dir"]
    artifact_manifest = ctx["_artifact_manifest"]

    def _allowed_antivirus_scan_roots() -> list[Path]:
        return allowed_antivirus_scan_roots(ctx["BASE_DIR"])

    def _validate_antivirus_scan_target(file_path: str) -> Path:
        return validate_antivirus_scan_target(file_path, ctx["BASE_DIR"])

    def _write_antivirus_report(target_dir: Path, base_name: str, title: str, payload: dict[str, Any], sections: list[tuple[str, str]]) -> dict[str, Any]:
        target_dir.mkdir(parents=True, exist_ok=True)
        json_path = target_dir / f"{base_name}.json"
        html_path = target_dir / f"{base_name}.html"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        body = "".join(
            f"<section><h2>{html.escape(section_title)}</h2><div>{section_html}</div></section>"
            for section_title, section_html in sections
        )
        html_path.write_text(
            (
                "<html><head><meta charset='utf-8'><title>"
                f"{html.escape(title)}</title>"
                "<style>body{background:#0f1823;color:#eef4fb;font-family:Segoe UI,Arial,sans-serif;padding:28px;}h1,h2{color:#f4f7fb;}section{background:#121b27;border:1px solid #243446;border-radius:10px;padding:16px;margin-bottom:14px;}table{width:100%;border-collapse:collapse;}th,td{border-bottom:1px solid #243446;padding:8px;text-align:left;}code,pre{background:#0e1720;border:1px solid #2b425b;border-radius:8px;padding:10px;display:block;white-space:pre-wrap;color:#eef4fb;}</style>"
                f"</head><body><h1>{html.escape(title)}</h1><p>Generated {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>{body}</body></html>"
            ),
            encoding="utf-8",
        )
        integrity_service.refresh_manifest()
        return {"status": "exported", "json_path": str(json_path), "html_path": str(html_path)}

    def _load_policy() -> dict[str, Any]:
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
        except json.JSONDecodeError:
            return antivirus_service.default_policy()
        return antivirus_service.normalize_policy(parsed if isinstance(parsed, dict) else {})

    def _save_policy(policy: dict[str, Any]) -> dict[str, Any]:
        normalized = antivirus_service.normalize_policy(policy)
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            db.set_app_setting(conn, "antivirus_policy_json", json.dumps(normalized, ensure_ascii=False))
        finally:
            conn.close()
        return normalized

    @app.get("/antivirus/status", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_status() -> dict[str, Any]:
        policy = _load_policy()
        providers = antivirus_service.provider_status()
        return {
            "status": "ok",
            "policy": policy,
            "providers": providers,
            "signature_health": antivirus_service.signature_health(provider_status=providers, policy=policy),
        }

    @app.get("/antivirus/policy", dependencies=[Depends(require_admin)])
    def antivirus_policy() -> dict[str, Any]:
        return {"status": "ok", "policy": _load_policy()}

    @app.put("/antivirus/policy", dependencies=[Depends(require_admin)])
    def update_antivirus_policy(payload: AntivirusPolicyRequest) -> dict[str, Any]:
        normalized = _save_policy(payload.model_dump())
        return {"status": "updated", "policy": normalized, "providers": antivirus_service.provider_status()}

    @app.post("/antivirus/scan/file", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_scan_file(request: Request, payload: AntivirusFileScanRequest) -> dict[str, Any]:
        apply_rate_limit(request, bucket="antivirus_scan_file", detail="Too many antivirus file scans. Wait briefly and retry.")
        target = _validate_antivirus_scan_target(payload.file_path)
        result = antivirus_service.scan_file(str(target), policy=_load_policy())
        if result.get("status") == "error":
            raise HTTPException(status_code=400, detail=result.get("error", "Scan failed"))
        return result

    @app.post("/antivirus/scan/processes/{pid}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_scan_process(pid: int) -> dict[str, Any]:
        profile = process_intel_service.profile_process(pid)
        return antivirus_service.scan_process(profile, policy=_load_policy())

    @app.post("/antivirus/respond/quarantine", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
    def antivirus_quarantine_file(request: Request, payload: AntivirusQuarantineRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="antivirus:quarantine")
        source_scan = payload.source_scan if isinstance(payload.source_scan, dict) else {}
        process_meta = source_scan.get("process", {}) if isinstance(source_scan.get("process", {}), dict) else {}
        target_path = str(payload.file_path or source_scan.get("path") or process_meta.get("exe") or "").strip()
        if not target_path:
            raise HTTPException(status_code=422, detail="file_path or source_scan.path is required")
        target = Path(target_path).expanduser()
        if not target.exists() or not target.is_file():
            raise HTTPException(status_code=404, detail="Target file not found")
        workspace_id = request_workspace_id(request)
        effective_name = payload.process_name.strip() or str(process_meta.get("name") or "").strip() or target.name
        effective_pid = int(payload.pid if payload.pid >= 0 else int(process_meta.get("pid", -1) or -1))
        actor = payload.actor.strip() or current_actor(request) or "desktop"
        result = response_service.quarantine_file(effective_pid, effective_name, str(target), workspace_id=workspace_id)
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result.get("message", "Quarantine failed"))
        record = {
            "id": 0,
            "process_name": effective_name,
            "original_path": str(target),
            "quarantine_path": result.get("path", ""),
            "status": "active",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pid": effective_pid,
            "workspace_id": workspace_id,
            "actor": actor,
            "sha256": str(source_scan.get("sha256", "") or ""),
            "severity": str((source_scan.get("summary", {}) or {}).get("severity", "") or ""),
            "fused_verdict": str((source_scan.get("summary", {}) or {}).get("fused_verdict", "") or ""),
        }
        conn = db.create_connection()
        if conn:
            try:
                db.log_quarantine(
                    conn,
                    effective_pid,
                    effective_name,
                    str(target),
                    result.get("path", ""),
                    "active",
                    workspace_id=workspace_id,
                )
                rows = db.get_quarantine(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
                matched = next(
                    (
                        item
                        for item in reversed(rows)
                        if str(item.get("original_path", "")) == str(target)
                        and str(item.get("quarantine_path", "")) == str(result.get("path", ""))
                    ),
                    None,
                )
                if isinstance(matched, dict):
                    record.update(matched)
                if payload.case_id is not None:
                    case_rows = db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
                    case_record = next((item for item in case_rows if int(item.get("id", 0) or 0) == int(payload.case_id or 0)), None)
                    if case_record is None:
                        raise HTTPException(status_code=404, detail="Enterprise case not found")
                    db.log_case_activity(
                        conn,
                        workspace_id=workspace_id,
                        case_id=int(payload.case_id),
                        event_type="antivirus_quarantine",
                        actor=actor,
                        summary=f"Quarantine executed for {effective_name}",
                        detail_json=json.dumps(
                            {
                                "target": str(target),
                                "quarantine_path": result.get("path", ""),
                                "pid": effective_pid,
                                "process_name": effective_name,
                            }
                        ),
                    )
                    db.log_evidence_chain(
                        conn,
                        int(payload.case_id),
                        "antivirus_quarantine",
                        actor=actor,
                        artifact_path=result.get("path", ""),
                        notes=f"Antivirus quarantine created for {effective_name}",
                    )
            finally:
                conn.close()
        integrity_service.refresh_manifest(workspace_id=workspace_id)
        return {
            "status": "quarantined",
            "workspace_id": workspace_id,
            "quarantine": result,
            "record": record,
            "target": str(target),
            "case_id": payload.case_id,
        }

    @app.post("/antivirus/enterprise/cases", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_create_enterprise_case(request: Request, payload: AntivirusEnterpriseCaseRequest) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        actor = current_actor(request) or payload.owner.strip() or "desktop"
        source_scan = payload.source_scan if isinstance(payload.source_scan, dict) else {}
        summary = source_scan.get("summary", {}) if isinstance(source_scan.get("summary", {}), dict) else {}
        providers = source_scan.get("providers", {}) if isinstance(source_scan.get("providers", {}), dict) else {}
        process_meta = source_scan.get("process", {}) if isinstance(source_scan.get("process", {}), dict) else {}
        target = str(process_meta.get("exe") or source_scan.get("path") or "unknown target")
        severity = str(summary.get("severity", "high") or "high").lower()
        priority = str(payload.priority or ("critical" if severity == "critical" else "high")).lower()
        title = payload.title.strip() or f"Antivirus detection: {Path(target).name}"
        provider_hits = summary.get("provider_hits", []) if isinstance(summary.get("provider_hits", []), list) else []
        narrative = (
            f"Dual-engine antivirus workflow flagged {target}. "
            f"Fused verdict={summary.get('fused_verdict', source_scan.get('status', 'unknown'))}, "
            f"severity={severity}, confidence={summary.get('confidence', 'low')}."
        )
        case_record = enterprise_service.create_case(
            workspace_id=workspace_id,
            title=title,
            owner=payload.owner.strip() or actor,
            priority=priority,
            stage="triage",
            sla_hours=8 if severity in {"critical", "high"} else 24,
            asset_criticality=float(summary.get("score", 0) or 0),
            tags=["antivirus", severity, *[str(item) for item in provider_hits[:2]]],
            narrative=narrative,
        )
        case_id = int(case_record.get("id", 0) or 0)
        conn = db.create_connection()
        if conn:
            try:
                db.log_case_activity(
                    conn,
                    workspace_id=workspace_id,
                    case_id=case_id,
                    event_type="antivirus_detection",
                    actor=actor,
                    summary=f"Antivirus detection linked from {Path(target).name}",
                    detail_json=json.dumps(
                        {
                            "target": target,
                            "severity": severity,
                            "confidence": summary.get("confidence", "low"),
                            "score": summary.get("score", 0),
                            "provider_hits": provider_hits,
                            "sha256": source_scan.get("sha256", ""),
                        }
                    ),
                )
                if source_scan.get("sha256") or source_scan.get("path"):
                    db.log_evidence_chain(
                        conn,
                        case_id,
                        "antivirus_detection",
                        actor=actor,
                        artifact_path=str(source_scan.get("path", "") or ""),
                        artifact_hash=str(source_scan.get("sha256", "") or ""),
                        notes=f"Initial antivirus verdict for {target}",
                    )
            finally:
                conn.close()
        note = investigation_service.create_note(
            workspace_id=workspace_id,
            case_id=case_id,
            note_text="Antivirus detection imported into enterprise case workflow.",
            item_type="antivirus_detection",
            item_title=title,
            tags=["antivirus", severity],
            author=actor,
        )
        story = None
        if payload.create_story:
            story = investigation_service.create_story(
                workspace_id=workspace_id,
                case_id=case_id,
                title=f"Antivirus containment hypothesis for {Path(target).name}",
                hypothesis=f"Detection likely represents a {summary.get('fused_verdict', source_scan.get('status', 'unknown'))} sample that requires analyst validation and scoped response.",
                summary=f"Provider hits: {', '.join(str(item) for item in provider_hits) or 'none'}",
                confidence=str(summary.get("confidence", "medium") or "medium"),
                tags=["antivirus", severity],
                created_by=actor,
            )
        return {
            "status": "created",
            "case": case_record,
            "note": note,
            "story": story,
            "source_scan": {
                "target": target,
                "severity": severity,
                "provider_hits": provider_hits,
            },
            "providers": providers,
        }

    @app.post("/antivirus/report/detection/export", dependencies=[Depends(require_analyst_or_admin)])
    def export_antivirus_detection_report(request: Request, payload: AntivirusDetectionExportRequest) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        source_scan = payload.source_scan if isinstance(payload.source_scan, dict) else {}
        summary = source_scan.get("summary", {}) if isinstance(source_scan.get("summary", {}), dict) else {}
        process_meta = source_scan.get("process", {}) if isinstance(source_scan.get("process", {}), dict) else {}
        providers = source_scan.get("providers", {}) if isinstance(source_scan.get("providers", {}), dict) else {}
        target = str(process_meta.get("exe") or source_scan.get("path") or "unknown target")
        provider_cards = summary.get("provider_cards", []) if isinstance(summary.get("provider_cards", []), list) else []
        provider_rows = "".join(
            "<tr>"
            f"<td>{html.escape(str(item.get('engine', item.get('provider', 'provider'))))}</td>"
            f"<td>{html.escape(str(item.get('status', 'unknown')))}</td>"
            f"<td>{html.escape(str(item.get('malware_name', '')))}</td>"
            f"<td>{html.escape(str(item.get('scan_time_ms', 0)))} ms</td>"
            "</tr>"
            for item in provider_cards
        )
        reasons = "".join(f"<li>{html.escape(str(item))}</li>" for item in summary.get("reasons", [])[:8])
        actions = "".join(f"<li>{html.escape(str(item))}</li>" for item in summary.get("recommended_actions", [])[:8])
        report_payload = {
            "workspace_id": workspace_id,
            "report_type": "antivirus_detection",
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "source_scan": source_scan,
            "artifacts": artifact_manifest(workspace_id),
        }
        return _write_antivirus_report(
            workspace_artifact_dir(workspace_id),
            "Antivirus_Detection_Report",
            "Antivirus Detection Report",
            report_payload,
            [
                (
                    "Executive Summary",
                    f"<p><b>Target:</b> {html.escape(target)}</p>"
                    f"<p><b>Verdict:</b> {html.escape(str(summary.get('fused_verdict', source_scan.get('status', 'unknown'))))}"
                    f" | <b>Severity:</b> {html.escape(str(summary.get('severity', 'low')))}"
                    f" | <b>Confidence:</b> {html.escape(str(summary.get('confidence', 'low')))}"
                    f" | <b>Score:</b> {html.escape(str(summary.get('score', 0)))}</p>",
                ),
                ("Provider Hits", f"<table><tr><th>Engine</th><th>Status</th><th>Detection</th><th>Scan Time</th></tr>{provider_rows or '<tr><td colspan=4>No provider data.</td></tr>'}</table>"),
                ("Analyst Rationale", f"<ul>{reasons or '<li>No rationale captured.</li>'}</ul>"),
                ("Recommended Actions", f"<ul>{actions or '<li>No actions captured.</li>'}</ul>"),
                ("Raw Payload", f"<pre>{html.escape(json.dumps({'summary': summary, 'providers': providers, 'sha256': source_scan.get('sha256', '')}, indent=2, ensure_ascii=False))}</pre>"),
            ],
        )

    @app.post("/antivirus/report/quarantine/export", dependencies=[Depends(require_analyst_or_admin)])
    def export_antivirus_quarantine_report(request: Request, payload: AntivirusQuarantineExportRequest) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        record = payload.quarantine_record if isinstance(payload.quarantine_record, dict) else {}
        report_payload = {
            "workspace_id": workspace_id,
            "report_type": "antivirus_quarantine",
            "generated_at": datetime.now().isoformat(),
            "quarantine_record": record,
            "artifacts": artifact_manifest(workspace_id),
        }
        return _write_antivirus_report(
            workspace_artifact_dir(workspace_id),
            "Antivirus_Quarantine_Report",
            "Antivirus Quarantine Report",
            report_payload,
            [
                (
                    "Containment Summary",
                    f"<p><b>ID:</b> {html.escape(str(record.get('id', '')))}</p>"
                    f"<p><b>Process:</b> {html.escape(str(record.get('process_name', '')))}"
                    f" | <b>Status:</b> {html.escape(str(record.get('status', 'unknown')))}"
                    f" | <b>Created:</b> {html.escape(str(record.get('created_at', '')))}</p>",
                ),
                (
                    "Artifact Paths",
                    f"<p><b>Original:</b> {html.escape(str(record.get('original_path', '')))}</p>"
                    f"<p><b>Quarantine Copy:</b> {html.escape(str(record.get('quarantine_path', '')))}</p>",
                ),
                ("Recovery Guidance", "<ul><li>Validate false-positive risk before restore.</li><li>Preserve the quarantine copy for evidence review.</li><li>Link this containment event to the active enterprise case when relevant.</li></ul>"),
                ("Raw Record", f"<pre>{html.escape(json.dumps(record, indent=2, ensure_ascii=False))}</pre>"),
            ],
        )

    # ------------------------------------------------------------------
    # Wave-1 routes — validation, signature updates, vault, stats
    # ------------------------------------------------------------------

    @app.post("/antivirus/validation/eicar", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_run_eicar_validation(request: Request) -> dict[str, Any]:
        apply_rate_limit(request, bucket="antivirus_validation", detail="Too many EICAR validations. Wait briefly and retry.")
        from services.antivirus.validation import run_eicar
        report = run_eicar(antivirus_service, policy=_load_policy())
        return {"status": "ok", "validation": report}

    @app.post("/antivirus/signatures/update", dependencies=[Depends(require_admin)])
    def antivirus_update_signatures(request: Request, payload: AntivirusSignatureUpdateRequest) -> dict[str, Any]:
        apply_rate_limit(request, bucket="antivirus_signature_update", detail="Too many signature updates queued. Wait briefly and retry.")
        actor = current_actor(request) or "desktop"
        provider_key = (payload.provider_key or "sentinel_cli").strip().lower() or "sentinel_cli"
        result = antivirus_service.signature_updater.update(provider_key=provider_key, trigger="manual", actor=actor)
        if result.get("status") == "error":
            raise HTTPException(status_code=502, detail=result.get("message", "Signature update failed"))
        return {"status": result.get("status", "ok"), "result": result}

    @app.get("/antivirus/signatures/history", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_signature_history(limit: int = 25) -> dict[str, Any]:
        rows = antivirus_service.signature_updater.history(limit=limit)
        return {"status": "ok", "rows": rows, "count": len(rows)}

    @app.get("/antivirus/vault", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_vault_list(request: Request) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        rows = antivirus_service.vault.list(workspace_id=workspace_id)
        return {"status": "ok", "rows": rows, "count": len(rows), "vault": antivirus_service.vault.status()}

    @app.post("/antivirus/vault/{file_id}/verify", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_vault_verify(file_id: str) -> dict[str, Any]:
        result = antivirus_service.vault.verify(file_id)
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "result": result}

    @app.post("/antivirus/vault/{file_id}/unseal", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
    def antivirus_vault_unseal(request: Request, file_id: str, payload: AntivirusVaultUnsealRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="antivirus:vault:unseal")
        destination = _validate_antivirus_scan_target(payload.destination_path) if payload.destination_path else None
        if destination is None:
            raise HTTPException(status_code=422, detail="destination_path is required")
        result = antivirus_service.vault.unseal(file_id, destination)
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "result": result}

    @app.delete("/antivirus/vault/{file_id}", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
    def antivirus_vault_delete(request: Request, file_id: str) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="antivirus:vault:delete")
        result = antivirus_service.vault.delete(file_id)
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "result": result}

    @app.get("/antivirus/stats", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_stats() -> dict[str, Any]:
        return {"status": "ok", "stats": antivirus_service.stats()}

    @app.put("/antivirus/credentials", dependencies=[Depends(require_admin)])
    def antivirus_set_credentials(payload: AntivirusCredentialsRequest) -> dict[str, Any]:
        """Push cloud-provider API keys into the encrypted credential
        store. Admin-only because keys grant outbound access to paid
        intelligence services. Field omitted => slot left untouched;
        field empty string => slot cleared. Never echoes raw keys back —
        the response is the same fingerprint snapshot `GET` returns."""
        from services.antivirus.credentials import get_credential_store
        store = get_credential_store()
        updates: list[str] = []
        for name in ("virustotal", "malwarebazaar", "yaraify", "hybrid_analysis"):
            value = getattr(payload, name, None)
            if value is None:
                continue
            store.set(name, value)
            updates.append(name)
        return {
            "status": "ok",
            "updated": updates,
            "credentials": store.status(),
        }

    @app.get("/antivirus/credentials/status", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_credentials_status() -> dict[str, Any]:
        """Per-provider configuration snapshot — `configured` boolean +
        last-4 fingerprint + source (`process`/`env`/`none`). Never
        returns raw keys."""
        from services.antivirus.credentials import get_credential_store
        return {"status": "ok", "credentials": get_credential_store().status()}

    @app.post("/antivirus/providers/{provider_key}/test", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_provider_test(request: Request, provider_key: str) -> dict[str, Any]:
        """Synthetic per-engine health probe — runs the EICAR sample
        through a single provider only, returns timing + outcome.

        Real EDR consoles offer this as a per-row 'Test connection' so
        the analyst can isolate which engine is misbehaving without
        triggering a full fused scan or burning a real sample. We reuse
        the EICAR validation file because it's the canonical
        non-malicious probe every signature engine recognises."""
        from services.antivirus.validation import materialise_eicar
        provider_key = provider_key.strip().lower()
        provider = antivirus_service.providers.get(provider_key)
        if provider is None:
            raise HTTPException(status_code=404, detail=f"Unknown provider {provider_key}")
        policy = antivirus_service.normalize_policy({"providers": [provider_key]})
        started = time.time()
        with materialise_eicar() as sample_path:
            try:
                result = provider.scan_file(sample_path, policy=policy)
            except Exception as exc:
                return {
                    "status": "error",
                    "provider": provider_key,
                    "elapsed_ms": int((time.time() - started) * 1000),
                    "error": str(exc),
                }
        elapsed_ms = int((time.time() - started) * 1000)
        outcome = str((result or {}).get("status", "")).lower()
        return {
            "status": "ok",
            "provider": provider_key,
            "elapsed_ms": elapsed_ms,
            "result": result,
            "verdict_status": outcome,
            "caught": outcome == "infected",
        }

    @app.get("/antivirus/providers/health", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_provider_health(window: int = 24 * 3600) -> dict[str, Any]:
        """Per-provider rolling health: success rate, p50/p95 latency,
        last error / last seen. Powers the Provider Matrix table."""
        return {"status": "ok", "window_seconds": int(window or 24 * 3600), "providers": antivirus_service.provider_health(window_seconds=int(window or 24 * 3600))}

    @app.get("/antivirus/sla", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_sla(request: Request, window: int = 7 * 24 * 3600) -> dict[str, Any]:
        """Aggregate SLA metrics over `window` seconds.

        Returns:
          * `mttd_ms` — mean time-to-detect: average duration_ms across
            scans that ended in `infected`. Proxy for "how fast does the
            pipeline confirm a verdict on a malicious sample".
          * `mttr_ms` — mean time-to-respond: average wall-clock between
            an infected scan and a quarantine event keyed on the same
            target_path within the window. NULL when no quarantines.
          * `scan_success_rate` — fraction of scans that didn't end in
            an `error`/`degraded` verdict.
          * `total_scans`, `infected_count`, `error_count` — raw counts
            so the UI can render context."""
        workspace_id = request_workspace_id(request)
        window = max(3600, min(int(window or 7 * 24 * 3600), 90 * 24 * 3600))
        cutoff = time.time() - window
        conn = db.create_connection()
        if conn is None:
            return {"status": "error", "error": "db_unavailable"}
        try:
            scans = conn.execute(
                """
                SELECT created_at, fused_verdict, duration_ms, target_path
                FROM av_scans
                WHERE workspace_id = ? AND created_at >= ?
                """,
                (workspace_id, float(cutoff)),
            ).fetchall()
            quarantines = []
            try:
                quarantines = conn.execute(
                    """
                    SELECT created_at, original_path
                    FROM av_vault_entries
                    WHERE workspace_id = ? AND created_at >= ?
                    """,
                    (workspace_id, float(cutoff)),
                ).fetchall()
            except Exception:
                quarantines = []
        except Exception as exc:
            return {"status": "error", "error": str(exc)}
        finally:
            try: conn.close()
            except Exception: pass

        total = len(scans)
        infected_durations = [int(r[2] or 0) for r in scans if str(r[1] or "").lower() in {"infected", "malicious"}]
        error_count = sum(1 for r in scans if str(r[1] or "").lower() in {"error", "degraded"})
        infected_count = len(infected_durations)
        mttd_ms = int(sum(infected_durations) / len(infected_durations)) if infected_durations else 0

        # MTTR — match infected scans to the *next* quarantine on the
        # same target_path within the window. The arithmetic is best-
        # effort: a quarantine without a matching scan is ignored.
        infected_by_path: dict[str, list[float]] = {}
        for r in scans:
            verdict = str(r[1] or "").lower()
            if verdict in {"infected", "malicious"}:
                infected_by_path.setdefault(str(r[3] or ""), []).append(float(r[0] or 0))
        deltas: list[float] = []
        for q in quarantines:
            q_time = float(q[0] or 0)
            q_path = str(q[1] or "")
            scan_times = infected_by_path.get(q_path, [])
            preceding = [t for t in scan_times if t <= q_time]
            if preceding:
                deltas.append(q_time - max(preceding))
        mttr_ms = int(sum(deltas) / len(deltas) * 1000) if deltas else 0
        success_rate = round(1.0 - (error_count / total), 4) if total else 1.0

        return {
            "status": "ok",
            "window_seconds": window,
            "total_scans": total,
            "infected_count": infected_count,
            "error_count": error_count,
            "scan_success_rate": success_rate,
            "mttd_ms": mttd_ms,
            "mttr_ms": mttr_ms,
            "quarantine_count": len(quarantines),
        }

    @app.get("/antivirus/report/executive", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_executive_report(request: Request, window: int = 7 * 24 * 3600) -> dict[str, Any]:
        """One-page executive snapshot of antivirus posture.

        Returns the rendered HTML inline so the desktop can show it in
        a preview pane and POST it to `/antivirus/report/executive/export`
        to write it to disk + manifest. Combines provider posture, SLA
        metrics, MITRE coverage, and recent verdicts into a printable
        summary."""
        workspace_id = request_workspace_id(request)
        # Reuse other endpoints' data flows so the report doesn't drift.
        provider_status = antivirus_service.provider_status()
        signature_health = antivirus_service.signature_health(provider_status=provider_status)
        sla = antivirus_sla(request, window=window)  # type: ignore[arg-type]
        mitre = antivirus_service.recent_mitre_coverage(limit=100)

        ready_engines = sum(
            1 for p in provider_status.values()
            if isinstance(p, dict) and p.get("available")
        )
        provider_rows = "".join(
            f"<tr><td>{html.escape(str(info.get('display_name', key)))}</td>"
            f"<td>{'ready' if info.get('available') else 'offline'}</td>"
            f"<td>{html.escape(str(info.get('version', '-')))}</td></tr>"
            for key, info in provider_status.items() if isinstance(info, dict)
        )
        coverage = mitre.get("coverage", {}) if isinstance(mitre.get("coverage"), dict) else {}
        tactic_rows = "".join(
            f"<li><b>{html.escape(t)}</b>: {len(rows)} technique(s)</li>"
            for t, rows in (coverage.get("by_tactic", {}) or {}).items()
        )
        body = (
            "<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0f1823;color:#eef4fb;padding:24px;}"
            "h1{color:#9fd0ff;}h2{color:#bda4ff;border-bottom:1px solid #2c4260;padding-bottom:4px;margin-top:24px;}"
            "table{border-collapse:collapse;width:100%;}td,th{padding:6px 10px;border-bottom:1px solid #2c4260;text-align:left;}"
            ".kpi{display:inline-block;background:#121b27;border:1px solid #2c4260;border-radius:9px;padding:10px 16px;margin:4px;}"
            ".kpi b{color:#9fd0ff;font-size:18px;}</style>"
            f"<h1>ShadowLab Antivirus Executive Snapshot</h1>"
            f"<p>Workspace <b>{html.escape(workspace_id)}</b> · Window {int(window)//3600}h · "
            f"Generated {datetime.now().isoformat()}</p>"
            f"<h2>Posture</h2>"
            f"<div class='kpi'>Engines ready <b>{ready_engines}/{len(provider_status)}</b></div>"
            f"<div class='kpi'>Signature health <b>{html.escape(str(signature_health.get('overall', '?')))}</b></div>"
            f"<div class='kpi'>Total scans <b>{sla.get('total_scans', 0)}</b></div>"
            f"<div class='kpi'>Infected <b>{sla.get('infected_count', 0)}</b></div>"
            f"<div class='kpi'>Errors <b>{sla.get('error_count', 0)}</b></div>"
            f"<div class='kpi'>Success rate <b>{int(sla.get('scan_success_rate', 1.0) * 100)}%</b></div>"
            f"<div class='kpi'>MTTD <b>{sla.get('mttd_ms', 0)} ms</b></div>"
            f"<div class='kpi'>MTTR <b>{sla.get('mttr_ms', 0)} ms</b></div>"
            f"<h2>Provider Matrix</h2>"
            f"<table><tr><th>Engine</th><th>State</th><th>Version</th></tr>{provider_rows}</table>"
            f"<h2>MITRE ATT&CK Coverage</h2>"
            f"<p>{coverage.get('total_techniques', 0)} unique techniques across "
            f"{len(coverage.get('tactics_covered', []))} tactic(s) in the last 100 scans.</p>"
            f"<ul>{tactic_rows or '<li>No techniques observed yet.</li>'}</ul>"
            f"<h2>Compliance Mapping</h2>"
            f"<ul>"
            f"<li>NIST 800-53 SI-3 (Malicious Code Protection): "
            f"{ready_engines}/{len(provider_status)} engines ready, success rate {int(sla.get('scan_success_rate', 1.0) * 100)}%.</li>"
            f"<li>NIST 800-53 IR-4 (Incident Handling): MTTD {sla.get('mttd_ms', 0)} ms, MTTR {sla.get('mttr_ms', 0)} ms.</li>"
            f"<li>MITRE D3FEND coverage: {coverage.get('total_techniques', 0)} ATT&CK techniques mapped.</li>"
            f"</ul>"
        )
        return {
            "status": "ok",
            "html": body,
            "generated_at": datetime.now().isoformat(),
            "workspace_id": workspace_id,
            "window_seconds": int(window),
            "kpis": {
                "engines_ready": ready_engines,
                "engines_total": len(provider_status),
                "signature_health": signature_health.get("overall", ""),
                **sla,
                "mitre_techniques": coverage.get("total_techniques", 0),
                "mitre_tactics": len(coverage.get("tactics_covered", [])),
            },
        }

    @app.get("/antivirus/scans/timeseries", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_scans_timeseries(request: Request, window: int = 24 * 3600, buckets: int = 24) -> dict[str, Any]:
        """Bucketed scan counts for sparkline rendering on the KPI strip.

        Returns `{bucket_seconds, points: [{ts, total, infected,
        suspicious}]}` over the past `window` seconds split into
        `buckets` equal-width slots. Workspace-scoped."""
        workspace_id = request_workspace_id(request)
        window = max(60, min(int(window or 24 * 3600), 30 * 24 * 3600))
        buckets = max(4, min(int(buckets or 24), 96))
        now = time.time()
        bucket_seconds = max(1, window // buckets)
        floor = int(now - window)
        # Pre-init slots so the sparkline is always `buckets` long even
        # if the DB is empty.
        points = [
            {"ts": floor + i * bucket_seconds, "total": 0, "infected": 0, "suspicious": 0}
            for i in range(buckets)
        ]
        conn = db.create_connection()
        if conn is None:
            return {"status": "ok", "bucket_seconds": bucket_seconds, "points": points}
        try:
            cursor = conn.execute(
                """
                SELECT created_at, fused_verdict
                FROM av_scans
                WHERE workspace_id = ? AND created_at >= ?
                """,
                (workspace_id, float(floor)),
            )
            for row in cursor.fetchall():
                ts = float(row[0] or 0)
                idx = max(0, min(buckets - 1, int((ts - floor) // bucket_seconds)))
                verdict = str(row[1] or "").lower()
                points[idx]["total"] += 1
                if verdict in {"malicious", "infected"}:
                    points[idx]["infected"] += 1
                elif verdict == "suspicious":
                    points[idx]["suspicious"] += 1
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return {"status": "ok", "bucket_seconds": bucket_seconds, "points": points, "now": now}

    @app.get("/antivirus/scans/recent", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_recent_scans(request: Request, since: float = 0.0, limit: int = 100) -> dict[str, Any]:
        """Pull scan rows from `av_scans` newer than `since` (epoch seconds).

        Powers the desktop's real-time verdict feed: the UI passes the
        timestamp of the newest row it already knows about, gets back
        every scan completed since then, and merges the delta into the
        verdict table without a full reload. Workspace-scoped — each
        client only sees its own workspace_id."""
        workspace_id = request_workspace_id(request)
        limit = max(1, min(int(limit or 100), 500))
        cutoff = float(since or 0.0)
        conn = db.create_connection()
        if conn is None:
            return {"status": "ok", "rows": [], "count": 0, "now": time.time()}
        try:
            cursor = conn.execute(
                """
                SELECT id, created_at, workspace_id, actor, scope, target_path, sha256,
                       size_bytes, fused_verdict, severity, score, confidence,
                       providers_set, source, duration_ms
                FROM av_scans
                WHERE workspace_id = ? AND created_at > ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (workspace_id, cutoff, limit),
            )
            rows: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                rows.append({
                    "id": int(row[0] or 0),
                    "created_at": float(row[1] or 0),
                    "workspace_id": str(row[2] or ""),
                    "actor": str(row[3] or ""),
                    "scope": str(row[4] or ""),
                    "target_path": str(row[5] or ""),
                    "sha256": str(row[6] or ""),
                    "size_bytes": int(row[7] or 0),
                    "fused_verdict": str(row[8] or ""),
                    "severity": str(row[9] or ""),
                    "score": int(row[10] or 0),
                    "confidence": str(row[11] or ""),
                    "providers_set": str(row[12] or ""),
                    "source": str(row[13] or ""),
                    "duration_ms": int(row[14] or 0),
                })
            return {"status": "ok", "rows": rows, "count": len(rows), "now": time.time()}
        except Exception as exc:
            return {"status": "error", "error": str(exc), "rows": [], "count": 0, "now": time.time()}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Wave-2 routes — direct provider scans + MITRE coverage
    # ------------------------------------------------------------------

    def _scan_via_provider(provider_key: str, payload: AntivirusProviderScanRequest, request: Request, *, bucket: str) -> dict[str, Any]:
        apply_rate_limit(request, bucket=bucket, detail=f"Too many {provider_key} scans. Wait briefly and retry.")
        target = _validate_antivirus_scan_target(payload.file_path)
        provider = antivirus_service.providers.get(provider_key)
        if provider is None:
            raise HTTPException(status_code=404, detail=f"Provider {provider_key} not registered")
        # Compose a provider-scoped policy so YARA pack selection rides
        # straight into the provider call without polluting the saved
        # default policy.
        policy = antivirus_service.normalize_policy(_load_policy())
        if payload.yara_pack:
            policy = dict(policy)
            policy["yara_pack"] = payload.yara_pack
        try:
            result = provider.scan_file(target, policy=policy)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"{provider_key} scan failed: {exc}") from exc
        return {"status": "ok", "provider": provider_key, "result": result, "target": str(target)}

    @app.post("/antivirus/scan/yara", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_scan_yara(request: Request, payload: AntivirusProviderScanRequest) -> dict[str, Any]:
        return _scan_via_provider("yara_x", payload, request, bucket="antivirus_scan_yara")

    @app.post("/antivirus/scan/behavioural", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_scan_behavioural(request: Request, payload: AntivirusProviderScanRequest) -> dict[str, Any]:
        return _scan_via_provider("behavioural", payload, request, bucket="antivirus_scan_behavioural")

    @app.post("/antivirus/scan/sandbox", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_scan_sandbox(request: Request, payload: AntivirusProviderScanRequest) -> dict[str, Any]:
        return _scan_via_provider("cloud_sandbox", payload, request, bucket="antivirus_scan_sandbox")

    @app.post("/antivirus/mitre/coverage", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_mitre_coverage(payload: AntivirusMitreCoverageRequest) -> dict[str, Any]:
        # Mode 1: client passed a single source_scan — return its coverage directly.
        source_scan = payload.source_scan if isinstance(payload.source_scan, dict) else {}
        if source_scan:
            summary = source_scan.get("summary", {}) if isinstance(source_scan.get("summary"), dict) else {}
            providers = source_scan.get("providers", {}) if isinstance(source_scan.get("providers"), dict) else {}
            techniques = summary.get("mitre_techniques") or antivirus_service._mitre_mapper.map_provider_results(providers)
            coverage = summary.get("mitre_coverage") or antivirus_service._mitre_mapper.coverage_summary(techniques)
            return {
                "status": "ok",
                "mode": "single_scan",
                "techniques": techniques,
                "coverage": coverage,
            }
        # Mode 2: aggregate from recent cached scans.
        aggregated = antivirus_service.recent_mitre_coverage(limit=int(payload.limit or 50))
        return {"status": "ok", "mode": "recent_scans", **aggregated}
