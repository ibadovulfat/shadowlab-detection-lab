"""Monitor + scenario routes: /monitor/run, /scenario/run."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from api.schemas import MonitorRequest, ScenarioRequest


# Cap concurrent long-running monitor/scenario calls so they cannot exhaust
# the FastAPI sync threadpool (default 40 workers). Pydantic already caps
# duration at 600s per request; this additionally caps the global fan-out.
_MONITOR_CONCURRENCY_LIMIT = 3
_monitor_run_semaphore = threading.BoundedSemaphore(_MONITOR_CONCURRENCY_LIMIT)


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    observability_service = ctx["observability_service"]
    request_workspace_id = ctx["_request_workspace_id"]
    workspace_artifact_dir = ctx["_workspace_artifact_dir"]
    config = ctx["config"]
    telemetry_service_cls = ctx["TelemetryMonitoringService"]
    detection_service = ctx["detection_service"]
    write_monitor_artifacts = ctx["_write_monitor_artifacts"]
    db = ctx["db"]
    fleet_service = ctx["fleet_service"]
    get_alert_webhook_url = ctx["_get_alert_webhook_url"]
    alert_service = ctx["alert_service"]
    alert_destination_type = ctx["_alert_destination_type"]
    collector_bridge = ctx["collector_bridge"]
    log_collector_exports = ctx["_log_collector_exports"]
    artifact_manifest = ctx["_artifact_manifest"]
    load_scenario_runner = ctx["_load_scenario_runner"]

    @app.post("/monitor/run", dependencies=[Depends(require_analyst_or_admin)])
    def run_monitor(request: Request, payload: MonitorRequest) -> dict[str, Any]:
        apply_rate_limit(request, bucket="monitor_run", detail="Too many monitor runs. Wait briefly and retry.")
        if not _monitor_run_semaphore.acquire(blocking=False):
            # Too many concurrent long-running samplers would starve the
            # threadpool and delay every other analyst/admin call.
            raise HTTPException(status_code=503, detail="Monitor concurrency limit reached, retry shortly")
        observability_service.log_event("monitor_run_requested", duration=payload.duration, interval=payload.interval)
        try:
            return _run_monitor_impl(request, payload)
        finally:
            _monitor_run_semaphore.release()

    def _run_monitor_impl(request: Request, payload: MonitorRequest) -> dict[str, Any]:
        with observability_service.span("monitor.run"):
            workspace_id = request_workspace_id(request)
            artifact_dir = workspace_artifact_dir(workspace_id)
            telemetry_service = telemetry_service_cls(config)
            telemetry_rows: list[dict[str, Any]] = []
            timeline_scores: list[float] = []

            defender_summary, sysmon_summary = telemetry_service.collect_event_context()
            start = time.time()
            while time.time() - start < payload.duration:
                row = telemetry_service.sample_once()
                telemetry_rows.append(row)
                score = detection_service.incremental_score(telemetry_rows, defender_summary, sysmon_summary)
                timeline_scores.append(float(score["likelihood"]))
                time.sleep(max(0.1, float(payload.interval)))

            final = detection_service.final_score(telemetry_rows, defender_summary, sysmon_summary)
            incident = detection_service.build_incident(telemetry_rows, defender_summary, sysmon_summary)

            write_monitor_artifacts(
                artifact_dir,
                telemetry_rows,
                defender_summary,
                sysmon_summary,
                final,
                payload.report_sections,
                incident,
            )

            conn = db.create_connection()
            if conn:
                db.insert_telemetry(conn, telemetry_rows, workspace_id=workspace_id)
                db.upsert_incident(
                    conn,
                    incident.incident_id,
                    incident.created_at,
                    incident.severity,
                    incident.title,
                    incident.summary,
                    status="open",
                    notes="\n".join(incident.notes),
                    recommended_actions=json.dumps(incident.recommended_actions),
                    attack_chain=json.dumps(incident.attack_chain),
                    mitre_mapping=json.dumps(incident.mitre_techniques),
                    correlation_story=incident.correlation_story,
                    workspace_id=workspace_id,
                )
                fleet_service.register_local_host(conn, workspace_id=workspace_id)
                conn.close()

            alert_webhook_url = get_alert_webhook_url()
            if alert_webhook_url and incident.severity.lower() in {"high", "critical"}:
                conn = db.create_connection()
                if conn:
                    try:
                        alert_result = alert_service.dispatch(
                            alert_webhook_url,
                            {
                                "product": "ShadowLab",
                                "incident_id": incident.incident_id,
                                "severity": incident.severity,
                                "title": incident.title,
                                "summary": incident.summary,
                                "findings": [finding.to_dict() for finding in incident.findings],
                            },
                        )
                        db.log_alert(
                            conn,
                            alert_webhook_url,
                            alert_destination_type(alert_webhook_url),
                            incident.severity,
                            incident.title,
                            alert_result.status,
                            alert_result.detail,
                            workspace_id=workspace_id,
                        )
                    finally:
                        conn.close()

            collector_export: dict[str, Any] = {"enabled": False}
            collector_config = config.get("telemetry_fabric") or {}
            if collector_bridge.is_enabled() and bool(collector_config.get("export_on_monitor", True)):
                collector_export = collector_bridge.export_monitor_session(
                    telemetry_rows,
                    defender_summary,
                    sysmon_summary,
                    final,
                    incident.to_dict(),
                )
                log_collector_exports(collector_export, workspace_id=workspace_id)

            observability_service.log_event("monitor_run_completed", telemetry_count=len(telemetry_rows), severity=incident.severity)
            return {
                "telemetry_count": len(telemetry_rows),
                "telemetry_rows": telemetry_rows,
                "timeline_scores": timeline_scores,
                "event_summaries": {
                    "defender": defender_summary,
                    "sysmon": sysmon_summary,
                },
                "final_score": final,
                "incident": incident.to_dict(),
                "collector_export": collector_export,
                "artifacts": artifact_manifest(workspace_id),
                "workspace_id": workspace_id,
            }

    @app.post("/scenario/run", dependencies=[Depends(require_admin)])
    def run_scenario(payload: ScenarioRequest) -> dict[str, Any]:
        runner = load_scenario_runner()
        if runner is None:
            raise HTTPException(status_code=500, detail="Scenario runner unavailable")
        runner.start(payload.profile, int(payload.duration))
        return {"status": "started", "profile": payload.profile, "duration": payload.duration}
