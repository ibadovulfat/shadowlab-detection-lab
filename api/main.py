from __future__ import annotations

import csv
import importlib.util
import json
import os
import platform
import socket
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import database as db
import monitor_core
from api.security import (
    SecurityContext,
    build_auth_context_payload,
    ensure_deception_enabled,
    enforce_process_action_policy,
    ensure_dangerous_actions_enabled,
    ensure_delete_enabled,
    ensure_network_warfare_enabled,
    get_active_policy_name,
    policy_requires_approval,
    require_admin,
    require_analyst_or_admin,
    require_api_key,
    safe_child_path,
    security_settings,
)
from report_export import generate_html, generate_pdf
from services.alerting_service import AlertingService
from services.detection_service import DetectionOrchestrator
from services.enterprise_service import EnterpriseService
from services.fleet_service import FleetService
from services.graph_service import GraphService
from services.incident_service import IncidentArtifactService
from services.process_intelligence_service import ProcessIntelligenceService
from services.response_service import ResponseOrchestrator
from services.telemetry_service import CollectorTelemetryBridge, TelemetryMonitoringService
from services.timeline_service import TimelineService
from threat_intelligence import check_file_malwarebazaar, check_file_vt, check_file_yaraify, check_ip, scan_process
import yaml


BASE_DIR = Path(__file__).resolve().parent.parent
OUT_DIR = BASE_DIR / "shadowlab_out"
OUT_DIR.mkdir(exist_ok=True, parents=True)


def load_config() -> dict[str, Any]:
    with (BASE_DIR / "config.yaml").open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


config = load_config()
db.init_db()

app = FastAPI(
    title="ShadowLab API",
    version="2.1.0",
    description="Streamlit-free backend for the ShadowLab defensive operations platform.",
    dependencies=[Depends(require_api_key)],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=security_settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-ShadowLab-Approval-Id",
        "X-ShadowLab-Timestamp",
        "X-ShadowLab-Nonce",
        "X-ShadowLab-Signature",
    ],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.method.upper() in {"POST", "PATCH", "DELETE"} and request.url.path not in {"/health"}:
        _audit_mutating_request(request, response.status_code)
    return response


process_intel_service = ProcessIntelligenceService()
response_service = ResponseOrchestrator()
detection_service = DetectionOrchestrator()
artifact_service = IncidentArtifactService(OUT_DIR)
alert_service = AlertingService()
fleet_service = FleetService(db)
timeline_service = TimelineService()
graph_service = GraphService(OUT_DIR)
collector_bridge = CollectorTelemetryBridge(config, OUT_DIR)
enterprise_service = EnterpriseService(BASE_DIR, process_intel_service, fleet_service)
honeypot_instance = None
canary_instance = None
canary_alerts: list[str] = []
network_warfare_instance = None
alert_webhook_url = os.environ.get("SHADOWLAB_ALERT_WEBHOOK", "")
connector_worker_enabled = os.environ.get("SHADOWLAB_CONNECTOR_QUEUE_WORKER", "true").strip().lower() in {"1", "true", "yes", "on"}
connector_worker_interval_seconds = max(5, int(os.environ.get("SHADOWLAB_CONNECTOR_QUEUE_INTERVAL_SECONDS", "20")))
_connector_worker_thread: threading.Thread | None = None
_connector_worker_stop = threading.Event()


class MonitorRequest(BaseModel):
    duration: int = Field(default=60, ge=5, le=600)
    interval: float = Field(default=1.0, ge=0.1, le=10.0)
    report_sections: list[str] = Field(default_factory=lambda: ["Telemetry", "Events Summary", "Detection Score"])


class ScenarioRequest(BaseModel):
    profile: str = Field(default="balanced")
    duration: int = Field(default=30, ge=5, le=300)


class ProcessScanRequest(BaseModel):
    virustotal_api_key: str | None = None
    malwarebazaar_auth_key: str | None = None
    yaraify_auth_key: str | None = None


class ThreatHashLookupRequest(BaseModel):
    file_hash: str
    malwarebazaar_auth_key: str | None = None
    yaraify_auth_key: str | None = None
    virustotal_api_key: str | None = None


class SnifferRequest(BaseModel):
    duration: int = Field(default=10, ge=5, le=60)


class StringScanRequest(BaseModel):
    min_length: int = Field(default=4, ge=3, le=20)
    patterns: list[str] = Field(default_factory=lambda: ["http", "powershell", "cmd", "token", "password", "api"])


class YaraLookupRequest(BaseModel):
    yaraify_auth_key: str | None = None


class SandboxTraceRequest(BaseModel):
    duration: int = Field(default=5, ge=2, le=60)
    interval: float = Field(default=0.5, ge=0.1, le=5.0)


class HoneypotRequest(BaseModel):
    filename: str = Field(default="passwords.txt")


class EvidenceRequest(BaseModel):
    alert_name: str = Field(default="incident")


class NetworkScanRequest(BaseModel):
    ip_range: str = Field(default="192.168.1.0/24")


class BlockerRequest(BaseModel):
    target_ip: str
    gateway_ip: str


class IncidentUpdateRequest(BaseModel):
    status: str | None = None
    notes: str | None = None
    owner: str | None = None


class PersistenceRemediationRequest(BaseModel):
    item_type: str
    path: str
    name: str = ""


class AlertWebhookRequest(BaseModel):
    webhook_url: str
    message: str = "ShadowLab test alert"


class TriageRequest(BaseModel):
    virustotal_api_key: str | None = None
    malwarebazaar_auth_key: str | None = None
    yaraify_auth_key: str | None = None
    trace_duration: int = Field(default=3, ge=1, le=20)
    strings_min_length: int = Field(default=4, ge=3, le=20)
    strings_patterns: list[str] = Field(default_factory=lambda: ["http", "powershell", "cmd", "password"])


class AgentRegistrationRequest(BaseModel):
    host_id: str | None = None
    host: str
    platform: str
    role: str = "agent"
    ip_address: str = ""
    agent_version: str = "2.1.0"
    api_status: str = "online"
    boot_time: float | None = None


class CaseCreateRequest(BaseModel):
    title: str
    incident_id: str = ""
    owner: str = ""
    priority: str = "medium"
    stage: str = "triage"
    sla_hours: int = Field(default=24, ge=1, le=720)
    asset_criticality: float = Field(default=0, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)
    narrative: str = ""


class ChainOfCustodyRequest(BaseModel):
    event_type: str
    actor: str = ""
    artifact_path: str = ""
    notes: str = ""


class ApprovalRequestModel(BaseModel):
    case_id: int
    action: str
    requested_by: str = ""
    approver: str = ""
    reason: str = ""


class ApprovalResolveRequest(BaseModel):
    status: str
    approver: str = ""


class DetectionLifecycleRequest(BaseModel):
    rule_id: str
    version: str = "1.0.0"
    tuning: dict[str, Any] = Field(default_factory=dict)
    suppressions: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class FalsePositiveRequest(BaseModel):
    rule_id: str
    incident_id: str = ""
    actor: str = ""
    reason: str


class ConnectorConfigRequest(BaseModel):
    name: str
    kind: str
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)


class ReplayRequest(BaseModel):
    artifact_path: str


class NetworkAssessmentRequest(BaseModel):
    ip_range: str = ""


class ConnectorDispatchRequest(BaseModel):
    event_type: str
    severity: str = "info"
    source: str = "shadowlab"
    payload: dict[str, Any] = Field(default_factory=dict)


class ConnectorQueueProcessRequest(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
def _startup_connector_worker() -> None:
    global _connector_worker_thread
    if not connector_worker_enabled or (_connector_worker_thread and _connector_worker_thread.is_alive()):
        return
    _connector_worker_stop.clear()
    _connector_worker_thread = threading.Thread(target=_connector_queue_worker_loop, name="connector-queue-worker", daemon=True)
    _connector_worker_thread.start()


@app.on_event("shutdown")
def _shutdown_connector_worker() -> None:
    _connector_worker_stop.set()


@app.get("/auth/context")
def auth_context(
    request: Request,
    context: SecurityContext = Depends(require_api_key),
) -> dict[str, Any]:
    return build_auth_context_payload(context, request)


@app.get("/enterprise/policy", dependencies=[Depends(require_admin)])
def enterprise_policy() -> dict[str, Any]:
    return enterprise_service.get_policy_profiles()


@app.get("/enterprise/assets", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_assets() -> dict[str, Any]:
    return enterprise_service.assess_asset_criticality()


@app.get("/enterprise/triage", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_triage() -> dict[str, Any]:
    return enterprise_service.triage_dashboard()


@app.post("/enterprise/cases", dependencies=[Depends(require_analyst_or_admin)])
def create_enterprise_case(payload: CaseCreateRequest) -> dict[str, Any]:
    return enterprise_service.create_case(**payload.model_dump())


@app.get("/enterprise/cases", dependencies=[Depends(require_analyst_or_admin)])
def list_enterprise_cases() -> list[dict[str, Any]]:
    return enterprise_service.list_cases()


@app.post("/enterprise/cases/{case_id}/chain", dependencies=[Depends(require_analyst_or_admin)])
def add_case_chain_event(case_id: int, payload: ChainOfCustodyRequest) -> dict[str, Any]:
    return enterprise_service.add_chain_of_custody_event(case_id, payload.event_type, payload.actor, payload.artifact_path, payload.notes)


@app.get("/enterprise/cases/{case_id}/chain", dependencies=[Depends(require_analyst_or_admin)])
def case_chain(case_id: int) -> list[dict[str, Any]]:
    return enterprise_service.get_chain_of_custody(case_id)


@app.post("/enterprise/approvals", dependencies=[Depends(require_analyst_or_admin)])
def request_enterprise_approval(payload: ApprovalRequestModel) -> dict[str, Any]:
    return enterprise_service.request_approval(**payload.model_dump())


@app.patch("/enterprise/approvals/{approval_id}", dependencies=[Depends(require_admin)])
def resolve_enterprise_approval(approval_id: int, payload: ApprovalResolveRequest) -> dict[str, Any]:
    return enterprise_service.resolve_approval(approval_id, payload.status, payload.approver)


@app.get("/enterprise/approvals", dependencies=[Depends(require_analyst_or_admin)])
def list_enterprise_approvals() -> list[dict[str, Any]]:
    return enterprise_service.list_approvals()


@app.get("/enterprise/detections/lifecycle", dependencies=[Depends(require_analyst_or_admin)])
def detection_lifecycle() -> dict[str, Any]:
    return enterprise_service.detection_lifecycle()


@app.post("/enterprise/detections/lifecycle", dependencies=[Depends(require_analyst_or_admin)])
def tune_detection_lifecycle(payload: DetectionLifecycleRequest) -> dict[str, Any]:
    return enterprise_service.tune_detection_rule(payload.rule_id, payload.version, payload.tuning, payload.suppressions, payload.notes)


@app.post("/enterprise/detections/false-positive", dependencies=[Depends(require_analyst_or_admin)])
def submit_false_positive(payload: FalsePositiveRequest) -> dict[str, Any]:
    return enterprise_service.log_false_positive(payload.rule_id, payload.incident_id, payload.actor, payload.reason)


@app.get("/enterprise/connectors", dependencies=[Depends(require_admin)])
def list_enterprise_connectors() -> list[dict[str, Any]]:
    return enterprise_service.list_connectors()


@app.post("/enterprise/connectors", dependencies=[Depends(require_admin)])
def configure_enterprise_connector(payload: ConnectorConfigRequest) -> dict[str, Any]:
    return enterprise_service.configure_connector(payload.name, payload.kind, payload.enabled, payload.config)


@app.post("/enterprise/connectors/dispatch", dependencies=[Depends(require_admin)])
def dispatch_enterprise_connector_event(payload: ConnectorDispatchRequest) -> dict[str, Any]:
    return enterprise_service.dispatch_connector_event(
        event_type=payload.event_type,
        payload=payload.payload,
        source=payload.source,
        severity=payload.severity,
    )


@app.post("/enterprise/connectors/queue/process", dependencies=[Depends(require_admin)])
def process_enterprise_connector_queue(payload: ConnectorQueueProcessRequest) -> dict[str, Any]:
    return enterprise_service.process_connector_queue(payload.limit)


@app.get("/enterprise/connectors/queue", dependencies=[Depends(require_admin)])
def enterprise_connector_queue(status: str = "", limit: int = 100) -> list[dict[str, Any]]:
    return enterprise_service.connector_queue_status(status=status, limit=limit)


@app.get("/enterprise/adversary/profiles", dependencies=[Depends(require_analyst_or_admin)])
def adversary_profiles() -> dict[str, Any]:
    return enterprise_service.adversary_emulation()


@app.post("/enterprise/purple/replay", dependencies=[Depends(require_analyst_or_admin)])
def purple_replay(payload: ReplayRequest) -> dict[str, Any]:
    return enterprise_service.replay_incident(payload.artifact_path)


@app.get("/enterprise/canary/bypass", dependencies=[Depends(require_analyst_or_admin)])
def canary_bypass_assessment() -> dict[str, Any]:
    return enterprise_service.assess_canary_bypass()


@app.get("/enterprise/telemetry/gaps", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_telemetry_gaps() -> dict[str, Any]:
    return enterprise_service.telemetry_gap_analysis()


@app.get("/enterprise/web/inspection", dependencies=[Depends(require_analyst_or_admin)])
def web_inspection() -> dict[str, Any]:
    return enterprise_service.inspect_web_surface()


@app.post("/enterprise/network/assessment", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_network_assessment(payload: NetworkAssessmentRequest) -> dict[str, Any]:
    return enterprise_service.network_pentest_overview(payload.ip_range)


@app.get("/config", dependencies=[Depends(require_admin)])
def get_config() -> dict[str, Any]:
    redacted = json.loads(json.dumps(config))
    if isinstance(redacted.get("virustotal_api_key"), str):
        redacted["virustotal_api_key"] = "***redacted***" if redacted["virustotal_api_key"] else ""
    telemetry_fabric = redacted.get("telemetry_fabric") or {}
    if isinstance(telemetry_fabric.get("headers"), dict) and telemetry_fabric.get("headers"):
        telemetry_fabric["headers"] = {key: "***redacted***" for key in telemetry_fabric["headers"].keys()}
    return redacted


@app.post("/monitor/run", dependencies=[Depends(require_analyst_or_admin)])
def run_monitor(payload: MonitorRequest) -> dict[str, Any]:
    telemetry_service = TelemetryMonitoringService(config)
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

    _write_monitor_artifacts(telemetry_rows, defender_summary, sysmon_summary, final, payload.report_sections, incident)

    conn = db.create_connection()
    if conn:
        db.insert_telemetry(conn, telemetry_rows)
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
        )
        fleet_service.register_local_host(conn)
        conn.close()

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
                    _alert_destination_type(alert_webhook_url),
                    incident.severity,
                    incident.title,
                    alert_result.status,
                    alert_result.detail,
                )
            finally:
                conn.close()

    collector_export = {"enabled": False}
    collector_config = config.get("telemetry_fabric") or {}
    if collector_bridge.is_enabled() and bool(collector_config.get("export_on_monitor", True)):
        collector_export = collector_bridge.export_monitor_session(
            telemetry_rows,
            defender_summary,
            sysmon_summary,
            final,
            incident.to_dict(),
        )
        _log_collector_exports(collector_export)

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
        "artifacts": _artifact_manifest(),
    }


@app.get("/processes")
def list_processes() -> list[dict[str, Any]]:
    return process_intel_service.snapshot_processes()


@app.get("/processes/{pid}")
def get_process(pid: int) -> dict[str, Any]:
    try:
        return process_intel_service.profile_process(pid)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/processes/{pid}/tree")
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
def process_strings(pid: int, payload: StringScanRequest) -> dict[str, Any]:
    import plugins.strings_analyser as strings_analyser

    profile = process_intel_service.profile_process(pid)
    exe_path = profile.get("exe")
    strings = strings_analyser.extract_strings(exe_path, payload.min_length)
    hits = strings_analyser.search_patterns(strings, payload.patterns)
    return {
        "pid": pid,
        "exe": exe_path,
        "min_length": payload.min_length,
        "patterns": payload.patterns,
        "total_strings": len(strings),
        "sample": strings[:100],
        "pattern_hits": hits[:100],
    }


@app.post("/processes/{pid}/yara", dependencies=[Depends(require_analyst_or_admin)])
def process_yara(pid: int, payload: YaraLookupRequest) -> dict[str, Any]:
    profile = process_intel_service.profile_process(pid)
    file_hash = profile.get("sha256")
    if not file_hash:
        raise HTTPException(status_code=400, detail="Process hash unavailable for YARAify lookup")
    result = check_file_yaraify(file_hash, payload.yaraify_auth_key)
    return {
        "pid": pid,
        "exe": profile.get("exe"),
        "hash": file_hash,
        "provider": "YARAify",
        "result": result,
        "matches": result.get("matched_rules", []) if isinstance(result, dict) else [],
    }


@app.post("/processes/{pid}/sandbox-trace", dependencies=[Depends(require_analyst_or_admin)])
def process_sandbox_trace(pid: int, payload: SandboxTraceRequest) -> dict[str, Any]:
    import plugins.sandbox as sandbox

    tracer = sandbox.ProcessTracer(pid)
    return tracer.trace(duration=payload.duration, interval=payload.interval)


@app.get("/processes/{pid}/ai-analysis", dependencies=[Depends(require_analyst_or_admin)])
def process_ai_analysis(pid: int) -> dict[str, Any]:
    import plugins.ai_analyst as ai_analyst

    profile = process_intel_service.profile_process(pid)
    analyst = ai_analyst.AIAnalyst()
    return analyst.analyze_process(profile)


@app.post("/processes/{pid}/scan", dependencies=[Depends(require_analyst_or_admin)])
def scan_single_process(pid: int, payload: ProcessScanRequest) -> dict[str, Any]:
    process_rows = process_intel_service.snapshot_processes()
    target = next((row for row in process_rows if int(row.get("pid", -1)) == pid), None)
    if not target:
        raise HTTPException(status_code=404, detail="Process not found")
    return scan_process(
        target,
        virustotal_api_key=payload.virustotal_api_key,
        malwarebazaar_auth_key=payload.malwarebazaar_auth_key,
        yaraify_auth_key=payload.yaraify_auth_key,
    )


@app.get("/processes/{pid}/memory-analysis", dependencies=[Depends(require_analyst_or_admin)])
def memory_analysis(pid: int, process_name: str) -> dict[str, Any]:
    import plugins.memory_forensics as memory_forensics

    return memory_forensics.run_analysis(pid, process_name)


@app.post("/processes/{pid}/actions/{action}", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def process_action(request: Request, pid: int, action: str, process_name: str) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name=f"process:{action.lower()}")
    action_name = action.lower()
    profile = process_intel_service.profile_process(pid)
    enforce_process_action_policy(request, process_name)
    if action_name == "suspend":
        result = response_service.suspend(pid, process_name)
    elif action_name == "resume":
        result = response_service.resume(pid, process_name)
    elif action_name == "kill":
        result = response_service.kill(pid, process_name)
    elif action_name == "kill-tree":
        result = response_service.kill_tree(pid, process_name)
    elif action_name == "quarantine":
        result = response_service.quarantine_file(pid, process_name, profile.get("exe"))
    else:
        raise HTTPException(status_code=400, detail="Unsupported action")
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    if action_name == "quarantine":
        conn = db.create_connection()
        if conn:
            try:
                db.log_quarantine(conn, pid, process_name, profile.get("exe"), result.get("path", ""), "active")
            finally:
                conn.close()
    return result


@app.get("/persistence", dependencies=[Depends(require_analyst_or_admin)])
def persistence_items() -> list[dict[str, Any]]:
    import plugins.persistence as persistence_scanner

    return persistence_scanner.get_persistence_items()


@app.post("/persistence/remediate", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def remediate_persistence(request: Request, payload: PersistenceRemediationRequest) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="persistence:remediate")
    import plugins.persistence as persistence_scanner

    result = persistence_scanner.remediate_persistence_item(payload.item_type, payload.path, payload.name)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("message", "Remediation failed"))
    conn = db.create_connection()
    if conn:
        try:
            remediation_id = db.log_remediation(
                conn,
                payload.item_type,
                payload.path,
                backup_path=result.get("backup_path", ""),
                rollback_data=json.dumps(result.get("rollback_data", {})),
                status="applied",
            )
        finally:
            conn.close()
        result["remediation_id"] = remediation_id
    return result


@app.post("/persistence/rollback/{remediation_id}", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def rollback_persistence(request: Request, remediation_id: int) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="persistence:rollback")
    import plugins.persistence as persistence_scanner

    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_remediations(conn)
        row = frame[frame["id"] == remediation_id]
        if row.empty:
            raise HTTPException(status_code=404, detail="Remediation record not found")
        item = row.iloc[0].to_dict()
        rollback_data = json.loads(item.get("rollback_data") or "{}")
        result = persistence_scanner.rollback_persistence_item(
            item.get("item_type", ""),
            item.get("target", ""),
            backup_path=item.get("backup_path", ""),
            rollback_data=rollback_data,
        )
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result.get("message", "Rollback failed"))
        db.update_remediation_status(conn, remediation_id, "rolled_back")
        return {"status": "rolled_back", "remediation_id": remediation_id, "result": result}
    finally:
        conn.close()


@app.get("/threat-intel/ip/{ip}")
def threat_intel_lookup(ip: str) -> dict[str, Any]:
    result = check_ip(ip)
    return {"ip": ip, "result": result}


@app.get("/threat-intel/hash/{file_hash}")
def threat_hash_lookup(file_hash: str) -> dict[str, Any]:
    return {
        "hash": file_hash,
        "malwarebazaar": check_file_malwarebazaar(file_hash),
        "yaraify": check_file_yaraify(file_hash),
    }


@app.post("/threat-intel/hash/lookup")
def threat_hash_lookup_with_auth(payload: ThreatHashLookupRequest) -> dict[str, Any]:
    return {
        "hash": payload.file_hash,
        "malwarebazaar": check_file_malwarebazaar(payload.file_hash, payload.malwarebazaar_auth_key),
        "yaraify": check_file_yaraify(payload.file_hash, payload.yaraify_auth_key),
        "virustotal": check_file_vt(payload.file_hash, payload.virustotal_api_key),
    }


@app.get("/history/telemetry")
def telemetry_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        history_df = db.get_historical_data(conn)
    finally:
        conn.close()
    return history_df.to_dict(orient="records")


@app.get("/history/responses")
def response_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        response_df = db.get_response_logs(conn)
    finally:
        conn.close()
    return response_df.to_dict(orient="records")


@app.get("/incidents")
def incidents() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_incidents(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.get("/history/alerts")
def alert_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_alerts(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.get("/history/remediations")
def remediation_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_remediations(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.get("/history/auth", dependencies=[Depends(require_admin)])
def auth_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_auth_logs(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.get("/history/actions", dependencies=[Depends(require_admin)])
def action_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_action_audits(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.get("/history/external", dependencies=[Depends(require_admin)])
def external_request_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_external_requests(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.get("/history/auth/anomalies", dependencies=[Depends(require_admin)])
def auth_anomalies() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        auth_rows = db.get_auth_logs(conn).fillna("").to_dict(orient="records")
        action_rows = db.get_action_audits(conn).fillna("").to_dict(orient="records")
    finally:
        conn.close()
    return _build_auth_anomalies(auth_rows, action_rows)


@app.patch("/incidents/{incident_id}", dependencies=[Depends(require_analyst_or_admin)])
def update_incident(incident_id: str, payload: IncidentUpdateRequest) -> dict[str, str]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        db.update_incident(conn, incident_id, status=payload.status, notes=payload.notes, owner=payload.owner)
    finally:
        conn.close()
    return {"status": "updated", "incident_id": incident_id}


@app.get("/quarantine", dependencies=[Depends(require_analyst_or_admin)])
def quarantine_items() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_quarantine(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.post("/quarantine/{quarantine_id}/restore", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def restore_quarantine(request: Request, quarantine_id: int) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="quarantine:restore")
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_quarantine(conn)
        row = frame[frame["id"] == quarantine_id]
        if row.empty:
            raise HTTPException(status_code=404, detail="Quarantine record not found")
        item = row.iloc[0].to_dict()
        source = Path(item["quarantine_path"])
        target = Path(item["original_path"])
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            source.replace(target)
        db.update_quarantine(conn, quarantine_id, "restored")
        return {"status": "restored", "path": str(target)}
    finally:
        conn.close()


@app.delete("/quarantine/{quarantine_id}", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled), Depends(ensure_delete_enabled)])
def delete_quarantine(request: Request, quarantine_id: int) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="quarantine:delete")
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_quarantine(conn)
        row = frame[frame["id"] == quarantine_id]
        if row.empty:
            raise HTTPException(status_code=404, detail="Quarantine record not found")
        item = row.iloc[0].to_dict()
        target = Path(item["quarantine_path"])
        if target.exists():
            target.unlink()
        db.update_quarantine(conn, quarantine_id, "deleted")
        return {"status": "deleted", "path": str(target)}
    finally:
        conn.close()


@app.get("/timeline")
def timeline() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        return []
    try:
        return timeline_service.build(
            telemetry_rows=db.get_historical_data(conn).to_dict(orient="records")[-100:],
            response_rows=db.get_response_logs(conn).to_dict(orient="records")[:100],
            incident_rows=db.get_incidents(conn).to_dict(orient="records")[:100],
            alert_rows=db.get_alerts(conn).to_dict(orient="records")[:100],
            remediation_rows=db.get_remediations(conn).to_dict(orient="records")[:100],
        )
    finally:
        conn.close()


@app.get("/timeline/graph")
def timeline_graph() -> dict[str, Any]:
    items = timeline()
    return timeline_service.build_graph(items)


@app.get("/hosts")
def hosts() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        return fleet_service.list_hosts(conn)
    finally:
        conn.close()


@app.get("/graph/entity-map")
def entity_map(pid: int | None = None) -> dict[str, Any]:
    conn = db.create_connection()
    incidents: list[dict[str, Any]] = []
    hosts_data: list[dict[str, Any]] = []
    if conn:
        try:
            incidents = db.get_incidents(conn).to_dict(orient="records")
            hosts_data = fleet_service.list_hosts(conn)
        finally:
            conn.close()
    processes = process_intel_service.snapshot_processes(include_deep_fields=False)
    connections = monitor_core.get_network_connections()
    try:
        import plugins.persistence as persistence_scanner

        persistence_items = persistence_scanner.get_persistence_items_fast()
    except Exception:
        persistence_items = []
    return graph_service.build_entity_graph(
        hosts=hosts_data,
        processes=processes,
        connections=connections,
        incidents=incidents,
        persistence_items=persistence_items,
        pid=pid,
    )


@app.get("/graph/entity-map/html")
def entity_map_html(pid: int | None = None):
    graph = entity_map(pid=pid)
    target = Path(graph["html_path"])
    if not target.exists():
        raise HTTPException(status_code=404, detail="Graph HTML not found")
    return FileResponse(target)


@app.post("/agents/register", dependencies=[Depends(require_admin)])
def register_agent(payload: AgentRegistrationRequest) -> dict[str, Any]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        return fleet_service.register_agent(conn, payload.model_dump())
    finally:
        conn.close()


@app.post("/alerts/test", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def test_alert_webhook(payload: AlertWebhookRequest) -> dict[str, Any]:
    webhook_url = _validate_webhook_url(payload.webhook_url)
    result = alert_service.dispatch(
        webhook_url,
        {"product": "ShadowLab", "title": "ShadowLab test alert", "summary": payload.message, "severity": "info"},
    )
    conn = db.create_connection()
    if conn:
        try:
            db.log_alert(
                conn,
                webhook_url,
                _alert_destination_type(webhook_url),
                "info",
                "ShadowLab test alert",
                result.status,
                result.detail,
            )
        finally:
            conn.close()
    return result.to_dict()


@app.post("/alerts/configure", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def configure_alert_webhook(payload: AlertWebhookRequest) -> dict[str, Any]:
    global alert_webhook_url
    alert_webhook_url = _validate_webhook_url(payload.webhook_url)
    return {"status": "configured", "webhook_url": alert_webhook_url}


@app.post("/triage/{pid}", dependencies=[Depends(require_analyst_or_admin)])
def auto_triage(pid: int, payload: TriageRequest) -> dict[str, Any]:
    import plugins.ai_analyst as ai_analyst
    import plugins.internals as internals
    import plugins.memory_forensics as memory_forensics
    import plugins.sandbox as sandbox
    import plugins.strings_analyser as strings_analyser

    try:
        profile = process_intel_service.profile_process(pid)
        exe_path = profile.get("exe")
        strings = strings_analyser.extract_strings(exe_path, payload.strings_min_length)
        hits = strings_analyser.search_patterns(strings, payload.strings_patterns)
        yara_lookup = check_file_yaraify(profile.get("sha256", ""), payload.yaraify_auth_key) if profile.get("sha256") else {
            "status": "skipped",
            "reason": "Process hash unavailable",
        }
        yara_matches = yara_lookup.get("matched_rules", []) if isinstance(yara_lookup, dict) else []
        trace = sandbox.ProcessTracer(pid).trace(duration=payload.trace_duration, interval=0.5)
        analyst = ai_analyst.AIAnalyst().analyze_process(profile)
        intel = None
        if payload.virustotal_api_key or payload.malwarebazaar_auth_key or payload.yaraify_auth_key:
            intel = scan_process(
                {"exe": exe_path, "pid": pid, "name": profile.get("name")},
                virustotal_api_key=payload.virustotal_api_key,
                malwarebazaar_auth_key=payload.malwarebazaar_auth_key,
                yaraify_auth_key=payload.yaraify_auth_key,
            )
        return {
            "profile": profile,
            "internals_summary": {"handles": len(internals.get_process_handles(pid)), "modules": len(internals.get_process_libs(pid))},
            "strings": {"total": len(strings), "hits": hits[:25]},
            "yara": {"provider": "YARAify", "result": yara_lookup, "matches": yara_matches},
            "sandbox": trace,
            "memory": memory_forensics.run_analysis(pid, profile.get("name", "process")),
            "ai_analyst": analyst,
            "threat_intel": intel,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Triage failed for PID {pid}: {exc}") from exc


@app.post("/scenario/run", dependencies=[Depends(require_admin)])
def run_scenario(payload: ScenarioRequest) -> dict[str, Any]:
    runner = _load_scenario_runner()
    if runner is None:
        raise HTTPException(status_code=500, detail="Scenario runner unavailable")
    runner.start(payload.profile, int(payload.duration))
    return {"status": "started", "profile": payload.profile, "duration": payload.duration}


@app.get("/network/connections")
def network_connections() -> list[dict[str, Any]]:
    return monitor_core.get_network_connections()


@app.post("/network/sniff", dependencies=[Depends(require_analyst_or_admin)])
def network_sniff(payload: SnifferRequest) -> dict[str, Any]:
    import plugins.sniffer as net_sniffer

    if not net_sniffer.SCAPY_AVAILABLE:
        raise HTTPException(status_code=500, detail="Scapy not available for packet capture")
    result = net_sniffer.run_sniffer_session(duration=payload.duration)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@app.get("/artifacts")
def list_artifacts() -> dict[str, str]:
    return _artifact_manifest()


@app.get("/integrations/telemetry-fabric/status", dependencies=[Depends(require_admin)])
def telemetry_fabric_status() -> dict[str, Any]:
    return collector_bridge.collector_status()


@app.post("/integrations/telemetry-fabric/start", dependencies=[Depends(require_admin)])
def start_telemetry_fabric() -> dict[str, Any]:
    result = collector_bridge.start_collector()
    _log_single_collector_export("collector_start", result)
    return result


@app.post("/integrations/telemetry-fabric/stop", dependencies=[Depends(require_admin)])
def stop_telemetry_fabric() -> dict[str, Any]:
    result = collector_bridge.stop_collector()
    _log_single_collector_export("collector_stop", result)
    return result


@app.post("/integrations/telemetry-fabric/export/incidents/{incident_id}", dependencies=[Depends(require_admin)])
def resend_incident_to_telemetry_fabric(incident_id: str) -> dict[str, Any]:
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        incident = db.get_incident_by_id(conn, incident_id)
    finally:
        conn.close()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = collector_bridge.export_incident_record(_normalize_incident_row(incident))
    _log_single_collector_export("incident_log", result, incident_id=incident_id)
    return result


@app.get("/integrations/telemetry-fabric/exports", dependencies=[Depends(require_admin)])
def list_telemetry_fabric_exports() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_integration_exports(conn)
    finally:
        conn.close()
    return frame.fillna("").to_dict(orient="records")


@app.get("/artifacts/{filename}")
def download_artifact(filename: str):
    target = safe_child_path(OUT_DIR, filename, allowed_suffixes={".csv", ".json", ".html", ".pdf"})
    if not target.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(target)


@app.get("/reports/html")
def html_report():
    target = OUT_DIR / "ShadowLab_Report.html"
    if not target.exists():
        raise HTTPException(status_code=404, detail="HTML report not found")
    return FileResponse(target)


@app.post("/deception/honeypot/deploy", dependencies=[Depends(require_admin), Depends(ensure_deception_enabled)])
def deploy_honeypot(payload: HoneypotRequest) -> dict[str, Any]:
    import plugins.honeypot as honeypot

    global honeypot_instance
    honeypot_instance = honeypot.FileHoneypot(filename=payload.filename)
    ok, message = honeypot_instance.deploy()
    if not ok:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "deployed", "message": message, "filepath": str(honeypot_instance.filepath)}


@app.get("/deception/honeypot/status", dependencies=[Depends(require_analyst_or_admin)])
def honeypot_status() -> dict[str, Any]:
    if honeypot_instance is None:
        return {"status": "inactive"}
    return {
        "status": honeypot_instance.check(),
        "filepath": str(honeypot_instance.filepath),
        "active": honeypot_instance.is_active,
    }


@app.delete("/deception/honeypot", dependencies=[Depends(require_admin), Depends(ensure_deception_enabled)])
def cleanup_honeypot() -> dict[str, str]:
    global honeypot_instance
    if honeypot_instance is not None:
        honeypot_instance.cleanup()
        honeypot_instance = None
    return {"status": "cleaned"}


@app.post("/deception/canary/deploy", dependencies=[Depends(require_admin), Depends(ensure_deception_enabled)])
def deploy_canary() -> dict[str, Any]:
    import plugins.canary as canary

    global canary_instance, canary_alerts
    canary_alerts = []

    def on_alert(message: str) -> None:
        canary_alerts.append(message)

    canary_instance = canary.RansomwareCanary(on_alert)
    created = canary_instance.deploy()
    return {"status": "deployed", "files": created}


@app.get("/deception/canary/status", dependencies=[Depends(require_analyst_or_admin)])
def canary_status() -> dict[str, Any]:
    active = canary_instance is not None
    canary_dir = getattr(canary_instance, "canary_dir", None)
    return {
        "active": active,
        "directory": str(canary_dir) if canary_dir else None,
        "alerts": canary_alerts[-20:],
    }


@app.delete("/deception/canary", dependencies=[Depends(require_admin), Depends(ensure_deception_enabled)])
def cleanup_canary() -> dict[str, str]:
    global canary_instance, canary_alerts
    if canary_instance is not None:
        canary_instance.cleanup()
        canary_instance = None
    canary_alerts = []
    return {"status": "cleaned"}


@app.post("/evidence/capture", dependencies=[Depends(require_analyst_or_admin)])
def capture_evidence(payload: EvidenceRequest) -> dict[str, Any]:
    import plugins.evidence as evidence

    collector = evidence.EvidenceCollector()
    path = collector.capture_screenshot(payload.alert_name)
    if str(path).startswith("Error"):
        raise HTTPException(status_code=500, detail=str(path))
    return {"status": "captured", "path": path}


@app.get("/evidence", dependencies=[Depends(require_analyst_or_admin)])
def list_evidence() -> dict[str, Any]:
    import plugins.evidence as evidence

    collector = evidence.EvidenceCollector()
    return {"items": collector.list_evidence()}


@app.delete("/evidence/{filename}", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled), Depends(ensure_delete_enabled)])
def delete_evidence(filename: str) -> dict[str, str]:
    target = safe_child_path(BASE_DIR / "evidence_locker", filename, allowed_suffixes={".png", ".jpg", ".jpeg", ".webp"})
    if not target.exists():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    target.unlink()
    return {"status": "deleted", "path": str(target)}


@app.post("/network/warfare/scan", dependencies=[Depends(require_admin), Depends(ensure_network_warfare_enabled), Depends(ensure_dangerous_actions_enabled)])
def network_warfare_scan(payload: NetworkScanRequest) -> dict[str, Any]:
    import plugins.net_warfare as net_warfare

    global network_warfare_instance
    network_warfare_instance = network_warfare_instance or net_warfare.NetworkWarfare()
    return {"devices": network_warfare_instance.scan_network(payload.ip_range), "ip_range": payload.ip_range}


@app.post("/network/warfare/block", dependencies=[Depends(require_admin), Depends(ensure_network_warfare_enabled), Depends(ensure_dangerous_actions_enabled)])
def network_warfare_block(request: Request, payload: BlockerRequest) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="network:warfare:block")
    import plugins.net_warfare as net_warfare

    global network_warfare_instance
    network_warfare_instance = network_warfare_instance or net_warfare.NetworkWarfare()
    network_warfare_instance.start_blocker(payload.target_ip, payload.gateway_ip)
    return {"status": "started", "target_ip": payload.target_ip, "gateway_ip": payload.gateway_ip}


@app.delete("/network/warfare/block", dependencies=[Depends(require_admin), Depends(ensure_network_warfare_enabled), Depends(ensure_dangerous_actions_enabled)])
def network_warfare_stop() -> dict[str, str]:
    if network_warfare_instance is not None:
        network_warfare_instance.stop_blocker()
    return {"status": "stopped"}


def _write_monitor_artifacts(
    telemetry_rows: list[dict[str, Any]],
    defender_summary: dict[str, Any],
    sysmon_summary: dict[str, Any],
    final: dict[str, Any],
    report_sections: list[str],
    incident,
) -> None:
    with (OUT_DIR / "telemetry.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "ts",
                "cpu",
                "mem_percent",
                "proc_threads",
                "proc_handles",
                "open_files",
                "tcp_conns",
                "bytes_sent_rate",
                "bytes_recv_rate",
                "remote_ips",
            ]
        )
        for row in telemetry_rows:
            writer.writerow(
                [
                    row["ts"],
                    row["cpu"],
                    row["mem_percent"],
                    row["proc_threads"],
                    row["proc_handles"] or "",
                    row["open_files"],
                    row["tcp_conns"],
                    row["bytes_sent_rate"],
                    row["bytes_recv_rate"],
                    row.get("remote_ips", []),
                ]
            )

    (OUT_DIR / "events_defender.json").write_text(json.dumps({"summary": defender_summary}, indent=2), encoding="utf-8")
    (OUT_DIR / "events_sysmon.json").write_text(json.dumps({"summary": sysmon_summary}, indent=2), encoding="utf-8")
    (OUT_DIR / "score.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    artifact_service.write_incident_bundle(incident, final, telemetry_rows)
    generate_pdf(OUT_DIR, author="Ulfat Ibadov", sections=report_sections)
    generate_html(OUT_DIR, author="Ulfat Ibadov")


def _artifact_manifest() -> dict[str, str]:
    files = [
        "telemetry.csv",
        "events_defender.json",
        "events_sysmon.json",
        "score.json",
        "incident_bundle.json",
        "ShadowLab_Report.pdf",
        "ShadowLab_Report.html",
        "ShadowLab_EntityGraph.html",
        "ShadowLab_EntityGraph.json",
    ]
    return {
        name: str(OUT_DIR / name)
        for name in files
        if (OUT_DIR / name).exists()
    }


def _load_scenario_runner():
    try:
        spec = importlib.util.spec_from_file_location("scenario_profiles", BASE_DIR / "plugins" / "scenario_profiles.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module.ScenarioRunner()
    except Exception:
        return None


def _send_webhook_alert(webhook_url: str, payload: dict[str, Any]) -> None:
    alert_service.dispatch(webhook_url, payload)


def _alert_destination_type(webhook_url: str) -> str:
    if "discord.com/api/webhooks" in webhook_url:
        return "discord"
    if "hooks.slack.com" in webhook_url:
        return "slack"
    if "api.telegram.org" in webhook_url:
        return "telegram"
    return "webhook"


def _validate_webhook_url(webhook_url: str) -> str:
    parsed = urlparse(webhook_url.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Webhook URL must be a valid http(s) URL")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise HTTPException(status_code=400, detail="Plain HTTP webhooks are restricted to localhost")
    return webhook_url.strip()


def _log_collector_exports(result: dict[str, Any]) -> None:
    for export_type, export_result in (result.get("exports") or {}).items():
        _log_single_collector_export(export_type, export_result)


def _log_single_collector_export(export_type: str, export_result: dict[str, Any], incident_id: str = "") -> None:
    conn = db.create_connection()
    if conn is None:
        return
    try:
        target = export_result.get("endpoint") or export_result.get("target") or collector_bridge.collector_status().get("otlp_http_endpoint", "")
        if incident_id:
            target = f"{target} incident={incident_id}".strip()
        db.log_integration_export(
            conn,
            "shadowlab-telemetry-fabric",
            export_type,
            str(target),
            str(export_result.get("status", "unknown")),
            str(export_result.get("detail", "")),
        )
    finally:
        conn.close()


def _normalize_incident_row(incident: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(incident)
    for key in ("recommended_actions", "attack_chain", "mitre_mapping"):
        value = normalized.get(key, "")
        if isinstance(value, str):
            try:
                normalized[key] = json.loads(value) if value else []
            except json.JSONDecodeError:
                normalized[key] = [value] if value else []
    notes = normalized.get("notes", "")
    if isinstance(notes, str):
        normalized["notes"] = [line for line in notes.splitlines() if line]
    normalized["mitre_techniques"] = normalized.get("mitre_mapping", [])
    return normalized


def _require_enterprise_approval(request: Request | None, action_name: str) -> None:
    if not policy_requires_approval():
        return
    if request is None:
        raise HTTPException(
            status_code=403,
            detail=f"Action `{action_name}` requires approved change control in profile `{get_active_policy_name()}`",
        )
    approval_id = str(request.headers.get("X-ShadowLab-Approval-Id", "") or "").strip()
    if not approval_id.isdigit():
        raise HTTPException(
            status_code=403,
            detail=(
                f"Action `{action_name}` requires an approved request in profile `{get_active_policy_name()}`. "
                "Provide X-ShadowLab-Approval-Id header."
            ),
        )
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        approvals = db.get_approval_requests(conn)
    finally:
        conn.close()
    row = approvals[approvals["id"] == int(approval_id)]
    if row.empty:
        raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` not found")
    item = row.iloc[0].to_dict()
    status_value = str(item.get("status", "")).lower()
    if status_value not in {"approved", "allow", "granted"}:
        raise HTTPException(
            status_code=403,
            detail=f"Approval `{approval_id}` status is `{status_value or 'unknown'}`; approved status required",
        )


def _connector_queue_worker_loop() -> None:
    while not _connector_worker_stop.wait(connector_worker_interval_seconds):
        try:
            enterprise_service.process_connector_queue(limit=50)
        except Exception:
            # Keep worker alive; failures are captured through queue state and export logs.
            continue


def _audit_mutating_request(request: Request, status_code: int) -> None:
    try:
        conn = db.create_connection()
        if conn is None:
            return
        try:
            context = getattr(request.state, "security_context", None)
            role = getattr(context, "role", "")
            client_ip = request.client.host if request.client else ""
            detail = request.url.query[:200] if request.url.query else ""
            db.log_action_audit(conn, request.method.upper(), request.url.path, int(status_code), role, client_ip, detail)
        finally:
            conn.close()
    except Exception:
        return


def _build_auth_anomalies(auth_rows: list[dict[str, Any]], action_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    failures_by_ip: dict[str, int] = {}
    for row in auth_rows:
        if str(row.get("event_type", "")) == "auth_failure":
            ip = str(row.get("client_ip", "") or "unknown")
            failures_by_ip[ip] = failures_by_ip.get(ip, 0) + 1
    for ip, count in failures_by_ip.items():
        if count >= 5:
            anomalies.append(
                {
                    "type": "repeated_auth_failures",
                    "severity": "high",
                    "client_ip": ip,
                    "count": count,
                    "summary": f"{count} failed authentication attempts observed from {ip}.",
                }
            )

    denied_by_role: dict[str, int] = {}
    for row in auth_rows:
        if str(row.get("event_type", "")) in {"authz_denied", "policy_denied", "signature_failure", "signature_replay"}:
            role = str(row.get("role", "") or "unknown")
            denied_by_role[role] = denied_by_role.get(role, 0) + 1
    for role, count in denied_by_role.items():
        if count >= 3:
            anomalies.append(
                {
                    "type": "privilege_or_policy_probe",
                    "severity": "medium",
                    "role": role,
                    "count": count,
                    "summary": f"{role} triggered {count} denied privileged requests.",
                }
            )

    dangerous_mutations = [
        row for row in action_rows
        if str(row.get("method", "")).upper() in {"POST", "PATCH", "DELETE"}
        and any(token in str(row.get("path", "")) for token in ["/actions/", "/network/warfare/", "/quarantine/", "/deception/"])
    ]
    if len(dangerous_mutations) >= 10:
        anomalies.append(
            {
                "type": "high_mutation_volume",
                "severity": "medium",
                "count": len(dangerous_mutations),
                "summary": "High volume of dangerous or destructive mutation requests detected.",
            }
        )

    return anomalies
