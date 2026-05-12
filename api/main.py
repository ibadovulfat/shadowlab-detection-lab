from __future__ import annotations

import csv
import html
import importlib.util
import json
import logging
import os
import re
import sys
import time
import requests
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

import database as db
import api.security as security_module
import monitor_core
from api.routes.auth import register_routes as register_auth_routes
from api.routes.mfa import register_routes as register_mfa_routes
from api.routes.enterprise import register_routes as register_enterprise_routes
from api.routes.monitor import register_routes as register_monitor_routes
from api.routes.persistence import register_routes as register_persistence_routes
from api.routes.threat_intel import register_routes as register_threat_intel_routes
from api.routes.audit import register_routes as register_audit_routes
from api.routes.history import register_routes as register_history_routes
from api.routes.quarantine import register_routes as register_quarantine_routes
from api.routes.hosts import register_routes as register_hosts_routes
from api.routes.graph import register_routes as register_graph_routes
from api.routes.alerts import register_routes as register_alerts_routes
from api.routes.triage import register_routes as register_triage_routes
from api.routes.network import register_routes as register_network_routes
from api.routes.network_warfare import register_routes as register_network_warfare_routes
from api.routes.artifacts import register_routes as register_artifacts_routes
from api.routes.integrity import register_routes as register_integrity_routes
from api.routes.evidence import register_routes as register_evidence_routes
from api.routes.integrations import register_routes as register_integrations_routes
from api.routes.antivirus import register_routes as register_antivirus_routes
from api.routes.antivirus_response import register_routes as register_antivirus_response_routes
from api.routes.antivirus_wave3 import register_routes as register_antivirus_wave3_routes
from api.routes.processes import register_routes as register_process_routes
from api.routes.timeline import register_routes as register_timeline_routes
from api.schemas import (
    AgentRegistrationRequest,
    AlertWebhookRequest,
    ApprovalRequestModel,
    ApprovalResolveRequest,
    ApprovalStatus,
    BlockerRequest,
    CaseAssignmentRequest,
    CaseCreateRequest,
    CasePriority,
    CaseStage,
    CaseTaskRequest,
    CaseTaskUpdateRequest,
    ChainOfCustodyRequest,
    ConnectorConfigRequest,
    ConnectorDispatchRequest,
    ConnectorKind,
    ConnectorQueueProcessRequest,
    DetectionLifecycleRequest,
    EventSeverity,
    EvidenceRequest,
    FalsePositiveRequest,
    IdentityRevokeRequest,
    IncidentResponseOrchestrationRequest,
    IncidentStatus,
    IncidentUpdateRequest,
    IntegrationFileImportRequest,
    IntegrationResponsePolicyRequest,
    InvestigationNoteRequest,
    InvestigationPinRequest,
    InvestigationStoryRequest,
    InvestigationViewRequest,
    LocalYaraPolicyRequest,
    LocalYaraRuleTuningRequest,
    MalwareAnalystFileRequest,
    MitreBundleLoadRequest,
    MitrePathRequest,
    MonitorRequest,
    NavigatorExportRequest,
    NetworkAssessmentRequest,
    NetworkScanRequest,
    OssecFileImportRequest,
    OssecLiveIngestRequest,
    PersistenceItemType,
    PersistenceRemediationRequest,
    ProcessScanRequest,
    ReplayRequest,
    RetentionCleanupRequest,
    SandboxTraceRequest,
    ScenarioRequest,
    SecretRotationRequest,
    SnifferRequest,
    StringScanRequest,
    ThreatHashLookupRequest,
    TriageRequest,
    TriageRespondRequest,
    WhidsArtifactsRequest,
    WhidsConfigRequest,
    WhidsIoCRequest,
    WhidsManagerImportRequest,
    WhidsRulesRequest,
    WhidsSchedulerRequest,
    YaraLookupRequest,
)
from api.utils.paths import (
    BASE_DIR,
    MITRE_IMPORT_ROOT,
    OUT_DIR,
    WHIDS_IMPORT_ROOT,
    validate_integration_import_path as _validate_integration_import_path,
    workspace_artifact_dir as _workspace_artifact_dir,
)
from api.utils.validators import (
    CONNECTOR_NAME_RE,
    INCIDENT_ID_RE,
    SEMVER_RE,
    SHA256_RE,
    parse_csv_query_values as _parse_csv_query_values,
    validated_incident_id as _validated_incident_id,
    validated_ip_address as _validated_ip_address,
    validated_network_range as _validated_network_range,
    validated_sha256 as _validated_sha256,
)
from api.utils.webhook import (
    alert_destination_type as _alert_destination_type_impl,
    send_webhook_alert as _send_webhook_alert_impl,
    validate_webhook_url as _validate_webhook_url_impl,
)
from api.utils.rate_limit import apply_rate_limit as _apply_rate_limit_impl
from api.utils.audit import (
    audit_mutating_request as _audit_mutating_request_impl,
    build_auth_anomalies as _build_auth_anomalies_impl,
    redact_audit_detail as _redact_audit_detail_impl,
)
from api.utils.workspace import (
    request_workspace_id as _request_workspace_id_impl,
    require_default_workspace_for_global_scope as _require_default_workspace_for_global_scope_impl,
)
from api.utils.artifacts import (
    artifact_manifest as _artifact_manifest_impl,
    safe_file_response as _safe_file_response_impl,
)
from api.utils.path_guards import (
    validate_quarantine_file_path as _validate_quarantine_file_path_impl,
    validate_quarantine_restore_paths as _validate_quarantine_restore_paths_impl,
    validate_replay_artifact_path as _validate_replay_artifact_path_impl,
)
from api.utils.persistence_guards import (
    validate_persistence_target as _validate_persistence_target_impl,
)
from api.utils.scenario import load_scenario_runner as _load_scenario_runner_impl
from api.utils.incidents import normalize_incident_row as _normalize_incident_row_impl
from api.utils.collector_exports import (
    log_collector_exports as _log_collector_exports_impl,
    log_single_collector_export as _log_single_collector_export_impl,
)
from api.utils.monitor_artifacts import write_monitor_artifacts as _write_monitor_artifacts_impl
from api.utils.approval import (
    consume_pending_approval as _consume_pending_approval_impl,
    require_enterprise_approval as _require_enterprise_approval_impl,
)
from api.utils.security_startup import (
    validate_startup_security_posture as _validate_startup_security_posture_impl,
)
from api.utils import runtime_state as _runtime_state
from api.bootstrap.services import build_services
from api.middleware.security_headers import (
    register as _register_security_headers_middleware,
    request_is_secure as _request_is_secure_impl,
    request_body_limit_bytes as _request_body_limit_bytes_impl,
)
from api.workers.connector_worker import (
    ConnectorQueueWorker,
    env_worker_enabled as _env_connector_worker_enabled,
    env_worker_interval_seconds as _env_connector_worker_interval_seconds,
)
from api.bootstrap.ctx import build_shared_ctx
from plugins import yara_scanner
from api.security import (
    SecurityContext,
    build_auth_context_payload,
    can_approve_workspace,
    current_actor,
    current_subject,
    enforce_process_action_policy,
    ensure_dangerous_actions_enabled,
    ensure_delete_enabled,
    ensure_network_warfare_enabled,
    get_active_policy_name,
    policy_requires_approval,
    request_from_trusted_proxy,
    require_admin,
    require_analyst_or_admin,
    require_api_key,
    safe_child_path,
    security_settings,
)
from report_export import generate_html, generate_pdf
from services.identity_provider import identity_provider
from services.outbound_security import normalize_outbound_url
from services.secret_store import is_encrypted_secret, secret_store
from services.telemetry_service import TelemetryMonitoringService
from threat_intelligence import check_file_malwarebazaar, check_file_vt, check_file_yaraify, check_ip, fuse_detection_verdict, run_local_yara_scan, scan_process
import yaml


logger = logging.getLogger(__name__)

# Opt-in JSON logging. Gated on `SHADOWLAB_JSON_LOGGING` so CI (which
# asserts against human-readable log lines in pytest -s captures) and
# local dev (which wants a readable tail) stay on the stdlib default.
# Production / container deployments set this to `1` so the root handler
# emits one JSON object per record — downstream log shippers (Loki,
# Splunk, Fluent Bit) can parse without regex gymnastics.
#
# Idempotent: `configure_json_logging()` guards with a sentinel on the
# root logger, so re-import during test collection doesn't stack handlers.
if os.environ.get("SHADOWLAB_JSON_LOGGING", "").strip().lower() in {"1", "true", "yes", "on"}:
    from api.observability import configure_json_logging as _configure_json_logging

    _configure_json_logging()

DEFAULT_MAX_REQUEST_BODY_BYTES = 1_048_576
IMPORT_MAX_REQUEST_BODY_BYTES = 10_485_760


# Thin shims around the middleware helpers. The middleware module owns the
# real logic now, but a handful of tests reach into api.main directly
# (e.g. `api.main._request_is_secure(request)`), so we preserve those
# module-level names here and delegate.
def _request_is_secure(request: Request) -> bool:
    return _request_is_secure_impl(request)


def _request_body_limit_bytes(request: Request) -> int:
    return _request_body_limit_bytes_impl(
        request,
        default_limit=DEFAULT_MAX_REQUEST_BODY_BYTES,
        import_limit=IMPORT_MAX_REQUEST_BODY_BYTES,
    )


def load_config() -> dict[str, Any]:
    with (BASE_DIR / "config.yaml").open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if isinstance(loaded, dict):
        loaded.pop("virustotal_api_key", None)
    return loaded


config = load_config()
db.init_db()


@asynccontextmanager
async def _app_lifespan(_app: FastAPI):
    """Replaces the legacy `@app.on_event("startup"/"shutdown")` handlers.

    FastAPI deprecated `on_event` in favour of the ASGI lifespan protocol.
    Body is identical to the previous startup/shutdown bodies; the only
    difference is that shutdown runs from the `finally` block so it still
    fires even if startup raises (e.g. migration failure) mid-flight.

    Names referenced inside (`migration_service`,
    `_validate_startup_security_posture`, `_connector_worker_thread`, etc.)
    are module-level globals that get bound AFTER this function is defined
    but BEFORE the ASGI server dispatches the startup event — the lookup
    happens at call time, not definition time, so forward references are
    fine.
    """
    # --- startup ---
    migration_service.ensure_applied()
    _validate_startup_security_posture()
    connector_worker.start()
    rotation_worker.start()
    try:
        yield
    finally:
        # --- shutdown ---
        connector_worker.stop()
        rotation_worker.stop()


app = FastAPI(
    title="ShadowLab API",
    version="0.0.8",
    description="Local-first defensive operations platform for Windows-focused detection, response, and casework.",
    dependencies=[Depends(require_api_key)],
    lifespan=_app_lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=security_settings.allowed_origins,
    allow_credentials=False,
    # Union of methods registered anywhere on the app — see the per-path
    # narrowing middleware below for the per-route allow-list. Keeping
    # this broad lets CORSMiddleware answer preflight OPTIONS for paths
    # the second middleware will then trim to the actual method set.
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-ShadowLab-Approval-Id",
        "X-ShadowLab-Workspace",
        "X-ShadowLab-Timestamp",
        "X-ShadowLab-Nonce",
        "X-ShadowLab-Signature",
    ],
)


@app.middleware("http")
async def narrow_cors_allow_methods(request, call_next):
    """Trim `Access-Control-Allow-Methods` to the methods actually
    registered for the request path.

    `CORSMiddleware` advertises the union of declared methods across
    every route, which over-discloses the API surface (a `GET`-only
    endpoint shouldn't claim it also accepts `DELETE`). At response
    time we look up the path in `app.routes` and rewrite the header to
    just the methods registered there.
    """
    response = await call_next(request)
    if "access-control-allow-methods" not in {k.lower() for k in response.headers.keys()}:
        return response
    path = request.url.path
    methods: set[str] = set()
    for route in app.routes:
        try:
            if getattr(route, "path", "") == path:
                methods.update(getattr(route, "methods", set()) or set())
        except Exception:
            continue
    if methods:
        # Always advertise OPTIONS so preflight stays valid.
        methods.add("OPTIONS")
        response.headers["Access-Control-Allow-Methods"] = ", ".join(sorted(methods))
    return response


# `add_security_headers` lives in api/middleware/security_headers.py. The
# `_audit_mutating_request` / `_consume_pending_approval` shims are defined
# later in this file, so we pass lambdas that do a late lookup at request
# time rather than a direct reference at install time.
# Capture the closure so tests can do `api.main.add_security_headers(...)`.
add_security_headers = _register_security_headers_middleware(
    app,
    security_settings=security_settings,
    default_body_limit=DEFAULT_MAX_REQUEST_BODY_BYTES,
    import_body_limit=IMPORT_MAX_REQUEST_BODY_BYTES,
    consume_pending_approval=lambda r, s: _consume_pending_approval(r, s),
    audit_mutating_request=lambda r, s: _audit_mutating_request(r, s),
)


# --- service singletons (tests patch these via mock.patch.object(api.main, ...))
_services = build_services(config=config, base_dir=BASE_DIR, out_dir=OUT_DIR, db=db)
process_intel_service = _services.process_intel_service
response_service = _services.response_service
detection_service = _services.detection_service
artifact_service = _services.artifact_service
alert_service = _services.alert_service
fleet_service = _services.fleet_service
timeline_service = _services.timeline_service
investigation_service = _services.investigation_service
graph_service = _services.graph_service
collector_bridge = _services.collector_bridge
enterprise_service = _services.enterprise_service
antivirus_service = _services.antivirus_service
mitre_service = _services.mitre_service
malware_analyst_service = _services.malware_analyst_service
hids_integration_service = _services.hids_integration_service
integrity_service = _services.integrity_service
observability_service = _services.observability_service
migration_service = _services.migration_service
metrics_registry = _services.metrics_registry
scan_job_queue = _services.scan_job_queue
webhook_dispatcher = _services.webhook_dispatcher
folder_watcher = _services.folder_watcher

# --- cross-thread runtime state (warfare plugin, alert webhook)
# Bootstrapped from env var or encrypted DB setting. Thin shims below expose
# the same `_get_/_set_` surface that the ctx dicts already thread through
# the route registrations.
_runtime_state.bootstrap_alert_webhook_url()


def _get_alert_webhook_url() -> str:
    return _runtime_state.get_alert_webhook_url()


def _set_alert_webhook_url(value: str) -> None:
    _runtime_state.set_alert_webhook_url(value)


def _get_network_warfare_instance():
    return _runtime_state.get_network_warfare_instance()


def _set_network_warfare_instance(value) -> None:
    _runtime_state.set_network_warfare_instance(value)


# Connector queue worker: drain loop lives in api/workers/connector_worker.py.
# Kept as module-level so tests can `mock.patch.object(api.main, "connector_worker", ...)`
# or flip `.enabled` before the lifespan runs.
connector_worker_enabled = _env_connector_worker_enabled()
connector_worker_interval_seconds = _env_connector_worker_interval_seconds()
connector_worker = ConnectorQueueWorker(
    enterprise_service=enterprise_service,
    observability_service=observability_service,
    logger=logger,
    enabled=connector_worker_enabled,
    interval_seconds=connector_worker_interval_seconds,
)

# Scheduled rotation — no-op unless SHADOWLAB_SECRET_ROTATION_ENABLED=1.
from services.rotation_worker import SecretRotationWorker  # noqa: E402
rotation_worker = SecretRotationWorker(
    webhook_dispatcher=webhook_dispatcher,
    integrity_service=integrity_service,
    db=db,
)

def _request_workspace_id(request: Request) -> str:
    return _request_workspace_id_impl(request)


def _require_default_workspace_for_global_scope(request: Request, feature_name: str) -> None:
    _require_default_workspace_for_global_scope_impl(request, feature_name)



# Startup/shutdown logic migrated to `_app_lifespan` (ASGI lifespan protocol).
# See the `FastAPI(..., lifespan=_app_lifespan)` call above.


def _write_monitor_artifacts(
    target_dir: Path,
    telemetry_rows: list[dict[str, Any]],
    defender_summary: dict[str, Any],
    sysmon_summary: dict[str, Any],
    final: dict[str, Any],
    report_sections: list[str],
    incident,
) -> None:
    _write_monitor_artifacts_impl(
        target_dir,
        telemetry_rows,
        defender_summary,
        sysmon_summary,
        final,
        report_sections,
        incident,
        integrity_service=integrity_service,
    )


def _artifact_manifest(workspace_id: str = "default") -> dict[str, str]:
    return _artifact_manifest_impl(_workspace_artifact_dir, workspace_id)


def _safe_file_response(target: Path, *, filename: str | None = None) -> FileResponse:
    return _safe_file_response_impl(target, filename=filename)


def _load_scenario_runner():
    return _load_scenario_runner_impl(BASE_DIR)


def _send_webhook_alert(webhook_url: str, payload: dict[str, Any]) -> None:
    _send_webhook_alert_impl(alert_service, webhook_url, payload)


def _alert_destination_type(webhook_url: str) -> str:
    return _alert_destination_type_impl(webhook_url)


def _validate_webhook_url(webhook_url: str) -> str:
    return _validate_webhook_url_impl(webhook_url)


def _validate_startup_security_posture() -> None:
    _validate_startup_security_posture_impl(
        security_module=security_module,
        get_active_policy_name=get_active_policy_name,
        observability_service=observability_service,
        logger=logger,
    )


def _apply_rate_limit(request: Request | None, *, bucket: str, detail: str) -> None:
    _apply_rate_limit_impl(request, bucket=bucket, detail=detail)


def _redact_audit_detail(detail: str) -> str:
    return _redact_audit_detail_impl(detail)


def _validate_replay_artifact_path(artifact_path: str) -> Path:
    return _validate_replay_artifact_path_impl(artifact_path, OUT_DIR)


def _validate_persistence_target(item_type: str, path: str, name: str) -> None:
    _validate_persistence_target_impl(item_type, path, name)


def _validate_quarantine_file_path(path_value: str) -> Path:
    return _validate_quarantine_file_path_impl(path_value, BASE_DIR)


def _validate_quarantine_restore_paths(quarantine_path: str, original_path: str) -> tuple[Path, Path]:
    return _validate_quarantine_restore_paths_impl(quarantine_path, original_path, BASE_DIR)


def _log_collector_exports(result: dict[str, Any], workspace_id: str = "default") -> None:
    _log_collector_exports_impl(collector_bridge, result, workspace_id=workspace_id)


def _log_single_collector_export(export_type: str, export_result: dict[str, Any], incident_id: str = "", workspace_id: str = "default") -> None:
    _log_single_collector_export_impl(
        collector_bridge,
        export_type,
        export_result,
        incident_id=incident_id,
        workspace_id=workspace_id,
    )


def _normalize_incident_row(incident: dict[str, Any]) -> dict[str, Any]:
    return _normalize_incident_row_impl(incident)


def _require_enterprise_approval(request: Request | None, action_name: str) -> None:
    _require_enterprise_approval_impl(
        request,
        action_name,
        policy_requires_approval=policy_requires_approval,
        get_active_policy_name=get_active_policy_name,
        request_workspace_id=_request_workspace_id,
    )


def _audit_mutating_request(request: Request, status_code: int) -> None:
    _audit_mutating_request_impl(db, request, status_code)


def _consume_pending_approval(request: Request, status_code: int) -> None:
    _consume_pending_approval_impl(request, status_code, observability_service=observability_service)


def _build_auth_anomalies(auth_rows: list[dict[str, Any]], action_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _build_auth_anomalies_impl(auth_rows, action_rows)


# --- Route registration -----------------------------------------------------
# Every `register_*_routes(app, ctx)` reads what it needs from a dict. The
# builder in `api.bootstrap.ctx` assembles one master ctx shared by all 21
# registrations; route modules that also need Pydantic schema classes get a
# tiny overlay merged on top via `shared_ctx | {"Schema": Schema, ...}`.

_shared_ctx = build_shared_ctx(
    sys.modules[__name__],
    db=db,
    config=config,
    base_dir=BASE_DIR,
    out_dir=OUT_DIR,
    monitor_core=monitor_core,
    yara_scanner=yara_scanner,
    requests=requests,
    html=html,
    json=json,
    secret_store=secret_store,
    identity_provider=identity_provider,
    SecurityContext=SecurityContext,
    build_auth_context_payload=build_auth_context_payload,
    current_actor=current_actor,
    current_subject=current_subject,
    can_approve_workspace=can_approve_workspace,
    require_admin=require_admin,
    require_analyst_or_admin=require_analyst_or_admin,
    require_api_key=require_api_key,
    safe_child_path=safe_child_path,
    ensure_dangerous_actions_enabled=ensure_dangerous_actions_enabled,
    ensure_delete_enabled=ensure_delete_enabled,
    ensure_network_warfare_enabled=ensure_network_warfare_enabled,
    enforce_process_action_policy=enforce_process_action_policy,
    alert_service=alert_service,
    antivirus_service=antivirus_service,
    collector_bridge=collector_bridge,
    detection_service=detection_service,
    enterprise_service=enterprise_service,
    fleet_service=fleet_service,
    graph_service=graph_service,
    hids_integration_service=hids_integration_service,
    integrity_service=integrity_service,
    investigation_service=investigation_service,
    malware_analyst_service=malware_analyst_service,
    migration_service=migration_service,
    mitre_service=mitre_service,
    observability_service=observability_service,
    process_intel_service=process_intel_service,
    response_service=response_service,
    timeline_service=timeline_service,
    TelemetryMonitoringService=TelemetryMonitoringService,
    metrics_registry=metrics_registry,
    scan_job_queue=scan_job_queue,
    webhook_dispatcher=webhook_dispatcher,
    folder_watcher=folder_watcher,
    rotation_worker=rotation_worker,
    request_workspace_id=_request_workspace_id,
    require_default_workspace_for_global_scope=_require_default_workspace_for_global_scope,
    apply_rate_limit=_apply_rate_limit,
    require_enterprise_approval=_require_enterprise_approval,
    alert_destination_type=_alert_destination_type,
    set_alert_webhook_url=_set_alert_webhook_url,
    get_alert_webhook_url=_get_alert_webhook_url,
    get_network_warfare_instance=_get_network_warfare_instance,
    set_network_warfare_instance=_set_network_warfare_instance,
    workspace_artifact_dir=_workspace_artifact_dir,
    artifact_manifest=_artifact_manifest,
    load_scenario_runner=_load_scenario_runner,
    normalize_incident_row=_normalize_incident_row,
    validate_persistence_target=_validate_persistence_target,
    write_monitor_artifacts=_write_monitor_artifacts,
    log_collector_exports=_log_collector_exports,
    log_single_collector_export=_log_single_collector_export,
    validated_incident_id=_validated_incident_id,
    validated_ip_address=_validated_ip_address,
    validated_sha256=_validated_sha256,
    parse_csv_query_values=_parse_csv_query_values,
    safe_file_response=_safe_file_response,
    validate_webhook_url=_validate_webhook_url,
    validate_replay_artifact_path=_validate_replay_artifact_path,
    validate_quarantine_file_path=_validate_quarantine_file_path,
    validate_quarantine_restore_paths=_validate_quarantine_restore_paths,
    build_auth_anomalies=_build_auth_anomalies,
)


register_timeline_routes(app, _shared_ctx)
register_auth_routes(app, _shared_ctx)
register_mfa_routes(app, _shared_ctx)
register_monitor_routes(app, _shared_ctx)
register_persistence_routes(app, _shared_ctx)
register_threat_intel_routes(app, _shared_ctx)
register_history_routes(app, _shared_ctx)
register_audit_routes(app, _shared_ctx)
register_quarantine_routes(app, _shared_ctx)
register_hosts_routes(app, _shared_ctx)
register_graph_routes(app, _shared_ctx)
register_alerts_routes(app, _shared_ctx)
register_triage_routes(app, _shared_ctx)
register_network_routes(app, _shared_ctx)
register_network_warfare_routes(app, _shared_ctx)
register_artifacts_routes(app, _shared_ctx)
register_integrity_routes(app, _shared_ctx)
register_evidence_routes(app, _shared_ctx)
register_antivirus_routes(app, _shared_ctx)
register_antivirus_wave3_routes(app, _shared_ctx)
register_antivirus_response_routes(app, _shared_ctx)
register_integrations_routes(app, _shared_ctx)

# Two registrations need route-specific Pydantic schema classes on top of
# the shared ctx. Kept as small overlays so the ctx builder stays generic.
# (integrations.py now imports its schemas at module scope — see the note
# at the top of that file for why the __future__-annotations + ctx trick
# cannot work once schemas move out of this module.)
register_enterprise_routes(
    app,
    _shared_ctx | {
        "MitreBundleLoadRequest": MitreBundleLoadRequest,
        "MitrePathRequest": MitrePathRequest,
        "NavigatorExportRequest": NavigatorExportRequest,
        "CaseCreateRequest": CaseCreateRequest,
        "ChainOfCustodyRequest": ChainOfCustodyRequest,
        "InvestigationViewRequest": InvestigationViewRequest,
        "InvestigationNoteRequest": InvestigationNoteRequest,
        "InvestigationStoryRequest": InvestigationStoryRequest,
        "InvestigationPinRequest": InvestigationPinRequest,
        "CaseAssignmentRequest": CaseAssignmentRequest,
        "CaseTaskRequest": CaseTaskRequest,
        "CaseTaskUpdateRequest": CaseTaskUpdateRequest,
        "ApprovalRequestModel": ApprovalRequestModel,
        "ApprovalResolveRequest": ApprovalResolveRequest,
        "DetectionLifecycleRequest": DetectionLifecycleRequest,
        "FalsePositiveRequest": FalsePositiveRequest,
        "ConnectorConfigRequest": ConnectorConfigRequest,
        "ConnectorDispatchRequest": ConnectorDispatchRequest,
        "ConnectorQueueProcessRequest": ConnectorQueueProcessRequest,
        "RetentionCleanupRequest": RetentionCleanupRequest,
        "SecretRotationRequest": SecretRotationRequest,
        "ReplayRequest": ReplayRequest,
        "NetworkAssessmentRequest": NetworkAssessmentRequest,
        "EventSeverity": EventSeverity,
    },
)

register_process_routes(
    app,
    _shared_ctx | {
        "StringScanRequest": StringScanRequest,
        "YaraLookupRequest": YaraLookupRequest,
        "SandboxTraceRequest": SandboxTraceRequest,
        "ProcessScanRequest": ProcessScanRequest,
        "LocalYaraPolicyRequest": LocalYaraPolicyRequest,
        "LocalYaraRuleTuningRequest": LocalYaraRuleTuningRequest,
    },
)
