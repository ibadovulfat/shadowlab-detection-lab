from __future__ import annotations

import csv
import importlib.util
import ipaddress
import json
import os
import platform
import re
import socket
import threading
import time
import requests
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

import database as db
import api.security as security_module
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
from services.hids_integration_service import HidsIntegrationService
from services.incident_service import IncidentArtifactService
from services.integrity_service import IntegrityService
from services.investigation_service import InvestigationService
from services.migration_service import MigrationService
from services.mitre_service import MitreAttackService
from services.observability_service import ObservabilityService
from services.outbound_security import normalize_outbound_url
from services.process_intelligence_service import ProcessIntelligenceService
from services.response_service import ResponseOrchestrator
from services.secret_store import secret_store
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
        _consume_pending_approval(request, response.status_code)
        _audit_mutating_request(request, response.status_code)
    return response


process_intel_service = ProcessIntelligenceService()
response_service = ResponseOrchestrator()
detection_service = DetectionOrchestrator()
artifact_service = IncidentArtifactService(OUT_DIR)
alert_service = AlertingService()
fleet_service = FleetService(db)
timeline_service = TimelineService()
investigation_service = InvestigationService(timeline_service)
graph_service = GraphService(OUT_DIR)
collector_bridge = CollectorTelemetryBridge(config, OUT_DIR)
enterprise_service = EnterpriseService(BASE_DIR, process_intel_service, fleet_service)
mitre_service = MitreAttackService(BASE_DIR, db)
hids_integration_service = HidsIntegrationService(
    db,
    enterprise_service=enterprise_service,
    investigation_service=investigation_service,
    response_service=response_service,
    mitre_service=mitre_service,
)
integrity_service = IntegrityService(BASE_DIR, OUT_DIR)
observability_service = ObservabilityService(OUT_DIR)
migration_service = MigrationService(BASE_DIR)
honeypot_instance = None
canary_instance = None
canary_alerts: list[str] = []
network_warfare_instance = None
_raw_alert_webhook = os.environ.get("SHADOWLAB_ALERT_WEBHOOK", "")
try:
    alert_webhook_url = secret_store.decrypt_text(_raw_alert_webhook) if _raw_alert_webhook.startswith("enc:v1:") else _raw_alert_webhook
except Exception:
    alert_webhook_url = ""
if not alert_webhook_url:
    conn = db.create_connection()
    if conn:
        try:
            stored_alert_webhook = db.get_app_setting(conn, "alert_webhook_url_enc")
            if stored_alert_webhook:
                alert_webhook_url = secret_store.decrypt_text(stored_alert_webhook)
        except Exception:
            alert_webhook_url = ""
        finally:
            conn.close()
connector_worker_enabled = os.environ.get("SHADOWLAB_CONNECTOR_QUEUE_WORKER", "true").strip().lower() in {"1", "true", "yes", "on"}
connector_worker_interval_seconds = max(5, int(os.environ.get("SHADOWLAB_CONNECTOR_QUEUE_INTERVAL_SECONDS", "20")))
_connector_worker_thread: threading.Thread | None = None
_connector_worker_stop = threading.Event()

SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{0,128}$")
CONNECTOR_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class CasePriority(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CaseStage(StrEnum):
    triage = "triage"
    investigation = "investigation"
    containment = "containment"
    eradication = "eradication"
    recovery = "recovery"
    closed = "closed"


class IncidentStatus(StrEnum):
    open = "open"
    in_progress = "in_progress"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    cancelled = "cancelled"


class ConnectorKind(StrEnum):
    siem = "siem"
    soar = "soar"


class EventSeverity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class PersistenceItemType(StrEnum):
    registry_run_key = "Registry Run Key"
    scheduled_task = "Scheduled Task"
    windows_service = "Windows Service"
    startup_folder = "Startup Folder"


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

    @field_validator("file_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return _validated_sha256(value)


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

    @field_validator("ip_range")
    @classmethod
    def _validate_ip_range(cls, value: str) -> str:
        return _validated_network_range(value)


class BlockerRequest(BaseModel):
    target_ip: str
    gateway_ip: str

    @field_validator("target_ip", "gateway_ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        return _validated_ip_address(value)


class IncidentUpdateRequest(BaseModel):
    status: IncidentStatus | None = None
    notes: str | None = None
    owner: str | None = None


class PersistenceRemediationRequest(BaseModel):
    item_type: PersistenceItemType
    path: str
    name: str = ""


class AlertWebhookRequest(BaseModel):
    webhook_url: str
    message: str = "ShadowLab test alert"

    @field_validator("webhook_url")
    @classmethod
    def _validate_webhook(cls, value: str) -> str:
        _validate_webhook_url(value)
        return value.strip()


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

    @field_validator("ip_address")
    @classmethod
    def _validate_optional_ip(cls, value: str) -> str:
        if not value:
            return ""
        return _validated_ip_address(value)


class IntegrationFileImportRequest(BaseModel):
    file_path: str
    limit: int = Field(default=200, ge=1, le=2000)

    @field_validator("file_path")
    @classmethod
    def _validate_file_path(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not str(path).strip():
            raise ValueError("File path is required")
        return str(path)


class WhidsManagerImportRequest(BaseModel):
    manager_url: str
    api_key: str
    limit: int = Field(default=200, ge=1, le=2000)
    endpoint_uuid: str = ""
    verify_tls: bool = True

    @field_validator("manager_url", "api_key")
    @classmethod
    def _validate_required_text(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Required field is missing")
        return trimmed


class WhidsArtifactsRequest(BaseModel):
    manager_url: str
    api_key: str
    endpoint_uuid: str
    since: str = ""
    max_files: int = Field(default=25, ge=1, le=250)
    verify_tls: bool = True

    @field_validator("manager_url", "api_key", "endpoint_uuid")
    @classmethod
    def _validate_required_artifact_text(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Required field is missing")
        return trimmed


class OssecLiveIngestRequest(BaseModel):
    file_path: str
    poll_interval: float = Field(default=2.0, ge=0.5, le=60.0)
    limit: int = Field(default=200, ge=1, le=2000)
    start_at_end: bool = True

    @field_validator("file_path")
    @classmethod
    def _validate_live_file_path(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not str(path).strip():
            raise ValueError("File path is required")
        return str(path)


class IncidentResponseOrchestrationRequest(BaseModel):
    apply_actions: bool = False


class IntegrationResponsePolicyRequest(BaseModel):
    policy: dict[str, Any] = Field(default_factory=dict)


class WhidsSchedulerRequest(BaseModel):
    manager_url: str
    api_key: str
    endpoint_uuid: str = ""
    poll_interval: float = Field(default=300.0, ge=30.0, le=86400.0)
    verify_tls: bool = True

    @field_validator("manager_url", "api_key")
    @classmethod
    def _validate_scheduler_text(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Required field is missing")
        return trimmed


class WhidsIoCRequest(BaseModel):
    manager_url: str
    api_key: str
    items: list[dict[str, Any]] = Field(default_factory=list)
    filters: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True

    @field_validator("manager_url", "api_key")
    @classmethod
    def _validate_whids_ioc_text(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Required field is missing")
        return trimmed


class WhidsRulesRequest(BaseModel):
    manager_url: str
    api_key: str
    rules: list[dict[str, Any]] = Field(default_factory=list)
    rule_name: str = ""
    name_filter: str = ""
    filters_only: bool = False
    update_existing: bool = True
    verify_tls: bool = True

    @field_validator("manager_url", "api_key")
    @classmethod
    def _validate_whids_rules_text(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Required field is missing")
        return trimmed


class WhidsConfigRequest(BaseModel):
    manager_url: str
    api_key: str
    endpoint_uuid: str
    config_format: str = "json"
    since: str = ""
    until: str = ""
    verify_tls: bool = True

    @field_validator("manager_url", "api_key", "endpoint_uuid")
    @classmethod
    def _validate_whids_config_text(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Required field is missing")
        return trimmed


class MitreBundleLoadRequest(BaseModel):
    file_path: str
    source: str = "manual"

    @field_validator("file_path")
    @classmethod
    def _validate_bundle_path(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not str(path).strip():
            raise ValueError("Bundle path is required")
        return str(path)

    @field_validator("source")
    @classmethod
    def _validate_bundle_source(cls, value: str) -> str:
        trimmed = value.strip() or "manual"
        if len(trimmed) > 40:
            raise ValueError("source must be 40 characters or fewer")
        return trimmed


class NavigatorExportRequest(BaseModel):
    incident_ids: list[str] = Field(default_factory=list)
    case_id: int | None = None
    layer_name: str = ""
    description: str = ""
    include_subtechniques: bool = True

    @field_validator("incident_ids")
    @classmethod
    def _validate_incident_ids(cls, value: list[str]) -> list[str]:
        return [_validated_incident_id(item) for item in value if _validated_incident_id(item)]

    @field_validator("layer_name")
    @classmethod
    def _validate_layer_name(cls, value: str) -> str:
        trimmed = value.strip()
        if len(trimmed) > 120:
            raise ValueError("layer_name must be 120 characters or fewer")
        return trimmed

    @field_validator("description")
    @classmethod
    def _validate_layer_description(cls, value: str) -> str:
        trimmed = value.strip()
        if len(trimmed) > 600:
            raise ValueError("description must be 600 characters or fewer")
        return trimmed


class MitrePathRequest(BaseModel):
    file_path: str

    @field_validator("file_path")
    @classmethod
    def _validate_mitre_path(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not str(path).strip():
            raise ValueError("File path is required")
        return str(path)


class CaseCreateRequest(BaseModel):
    title: str
    incident_id: str = ""
    owner: str = ""
    priority: CasePriority = CasePriority.medium
    stage: CaseStage = CaseStage.triage
    sla_hours: int = Field(default=24, ge=1, le=720)
    asset_criticality: float = Field(default=0, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)
    narrative: str = ""

    @field_validator("incident_id")
    @classmethod
    def _validate_incident_id(cls, value: str) -> str:
        return _validated_incident_id(value)


class InvestigationViewRequest(BaseModel):
    name: str
    description: str = ""
    query_text: str = ""
    event_types: list[str] = Field(default_factory=list)
    severities: list[EventSeverity] = Field(default_factory=list)
    start_time: float | None = None
    end_time: float | None = None
    case_id: int | None = None
    created_by: str = ""

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3 or len(value) > 80:
            raise ValueError("name must be between 3 and 80 characters")
        return value

    @field_validator("description", "query_text", "created_by")
    @classmethod
    def _trim_text(cls, value: str) -> str:
        return value.strip()


class InvestigationNoteRequest(BaseModel):
    note_text: str
    case_id: int | None = None
    view_id: int | None = None
    item_time: float = 0
    item_type: str = ""
    item_title: str = ""
    tags: list[str] = Field(default_factory=list)
    author: str = ""

    @field_validator("note_text")
    @classmethod
    def _validate_note_text(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 4 or len(value) > 2000:
            raise ValueError("note_text must be between 4 and 2000 characters")
        return value

    @field_validator("item_type", "item_title", "author")
    @classmethod
    def _trim_note_fields(cls, value: str) -> str:
        return value.strip()


class InvestigationStoryRequest(BaseModel):
    title: str
    hypothesis: str = ""
    summary: str = ""
    confidence: str = "medium"
    tags: list[str] = Field(default_factory=list)
    case_id: int | None = None
    created_by: str = ""

    @field_validator("title")
    @classmethod
    def _validate_story_title(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3 or len(value) > 120:
            raise ValueError("title must be between 3 and 120 characters")
        return value

    @field_validator("hypothesis", "summary", "created_by")
    @classmethod
    def _trim_story_fields(cls, value: str) -> str:
        return value.strip()

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, value: str) -> str:
        candidate = value.strip().lower()
        if candidate not in {"low", "medium", "high"}:
            raise ValueError("confidence must be low, medium, or high")
        return candidate


class InvestigationPinRequest(BaseModel):
    case_id: int | None = None
    view_id: int | None = None
    item_time: float = 0
    item_type: str
    item_title: str
    item_severity: str = ""
    item_payload: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    pinned_by: str = ""

    @field_validator("item_type", "item_title", "item_severity", "rationale", "pinned_by")
    @classmethod
    def _trim_pin_fields(cls, value: str) -> str:
        return value.strip()

    @field_validator("item_type")
    @classmethod
    def _validate_item_type(cls, value: str) -> str:
        if len(value) < 2 or len(value) > 40:
            raise ValueError("item_type must be between 2 and 40 characters")
        return value

    @field_validator("item_title")
    @classmethod
    def _validate_item_title(cls, value: str) -> str:
        if len(value) < 3 or len(value) > 200:
            raise ValueError("item_title must be between 3 and 200 characters")
        return value


class CaseAssignmentRequest(BaseModel):
    analyst: str
    role: str = "owner"
    status: str = "active"
    assigned_by: str = ""

    @field_validator("analyst", "role", "status", "assigned_by")
    @classmethod
    def _trim_assignment_fields(cls, value: str) -> str:
        value = value.strip()
        if not value and cls.__name__ == "CaseAssignmentRequest":
            return value
        return value


class CaseTaskRequest(BaseModel):
    title: str
    description: str = ""
    status: str = "todo"
    priority: str = "medium"
    assigned_to: str = ""
    due_at: float = 0
    created_by: str = ""

    @field_validator("title")
    @classmethod
    def _validate_task_title(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3 or len(value) > 120:
            raise ValueError("title must be between 3 and 120 characters")
        return value

    @field_validator("description", "status", "priority", "assigned_to", "created_by")
    @classmethod
    def _trim_task_fields(cls, value: str) -> str:
        return value.strip()


class CaseTaskUpdateRequest(BaseModel):
    status: str | None = None
    priority: str | None = None
    assigned_to: str | None = None
    due_at: float | None = None

    @field_validator("status", "priority", "assigned_to")
    @classmethod
    def _trim_update_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


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

    @field_validator("action")
    @classmethod
    def _validate_approval_action(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or len(value) > 80 or not re.fullmatch(r"[a-z0-9:_-]+", value):
            raise ValueError("action must be 1-80 chars and contain only lowercase letters, digits, colon, underscore, dash")
        return value


class ApprovalResolveRequest(BaseModel):
    status: ApprovalStatus
    approver: str = ""


class DetectionLifecycleRequest(BaseModel):
    rule_id: str
    version: str = "1.0.0"
    tuning: dict[str, Any] = Field(default_factory=dict)
    suppressions: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 128:
            raise ValueError("rule_id must be between 1 and 128 characters")
        return value

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        value = value.strip()
        if not SEMVER_RE.fullmatch(value):
            raise ValueError("version must use semantic version format like 1.2.3")
        return value


class FalsePositiveRequest(BaseModel):
    rule_id: str
    incident_id: str = ""
    actor: str = ""
    reason: str

    @field_validator("rule_id")
    @classmethod
    def _validate_fp_rule_id(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 128:
            raise ValueError("rule_id must be between 1 and 128 characters")
        return value

    @field_validator("incident_id")
    @classmethod
    def _validate_fp_incident_id(cls, value: str) -> str:
        return _validated_incident_id(value)

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 5 or len(value) > 500:
            raise ValueError("reason must be between 5 and 500 characters")
        return value


class ConnectorConfigRequest(BaseModel):
    name: str
    kind: ConnectorKind
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _validate_connector_name(cls, value: str) -> str:
        lowered = value.strip().lower()
        if not CONNECTOR_NAME_RE.fullmatch(lowered):
            raise ValueError("Connector name must be 2-32 chars and contain only lowercase letters, digits, dot, dash, underscore")
        return lowered


class ReplayRequest(BaseModel):
    artifact_path: str


class NetworkAssessmentRequest(BaseModel):
    ip_range: str = ""

    @field_validator("ip_range")
    @classmethod
    def _validate_optional_network(cls, value: str) -> str:
        if not value.strip():
            return ""
        return _validated_network_range(value)


class ConnectorDispatchRequest(BaseModel):
    event_type: str
    severity: EventSeverity = EventSeverity.info
    source: str = "shadowlab"
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type", "source")
    @classmethod
    def _validate_non_empty_label(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 80:
            raise ValueError("Value must be between 1 and 80 characters")
        return value


class ConnectorQueueProcessRequest(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)


class RetentionCleanupRequest(BaseModel):
    telemetry_days: int = Field(default=30, ge=1, le=3650)
    alerts_days: int = Field(default=90, ge=1, le=3650)
    auth_days: int = Field(default=90, ge=1, le=3650)
    action_audit_days: int = Field(default=90, ge=1, le=3650)
    external_days: int = Field(default=30, ge=1, le=3650)
    queue_days: int = Field(default=30, ge=1, le=3650)


class SecretRotationRequest(BaseModel):
    rotate_integrity_signing_key: bool = True
    reencrypt_webhook_secret: bool = True
    reencrypt_connector_secrets: bool = True
    clear_alert_webhook: bool = False


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
def _startup_connector_worker() -> None:
    migration_service.ensure_applied()
    _validate_startup_security_posture()
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


@app.get("/enterprise/mitre/status", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_status() -> dict[str, Any]:
    return mitre_service.status()


@app.post("/enterprise/mitre/load-bundle", dependencies=[Depends(require_admin)])
def enterprise_mitre_load_bundle(payload: MitreBundleLoadRequest) -> dict[str, Any]:
    try:
        return mitre_service.load_bundle(payload.file_path, source=payload.source)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/enterprise/mitre/summary", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_summary(limit: int = 50) -> dict[str, Any]:
    try:
        return mitre_service.enterprise_summary(limit=max(1, min(limit, 500)))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/enterprise/mitre/discover", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_discover() -> list[dict[str, Any]]:
    return mitre_service.discover_bundle_sources()


@app.post("/enterprise/mitre/compare", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_compare(payload: MitrePathRequest) -> dict[str, Any]:
    try:
        return mitre_service.compare_bundle(payload.file_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/enterprise/mitre/changelog", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_changelog(payload: MitrePathRequest) -> dict[str, Any]:
    try:
        return mitre_service.changelog_summary(payload.file_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/enterprise/mitre/techniques/{attack_id}", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_technique(attack_id: str) -> dict[str, Any]:
    try:
        return mitre_service.technique_details(attack_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/enterprise/mitre/incidents/{incident_id}/coverage", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_incident_coverage(incident_id: str) -> dict[str, Any]:
    try:
        return mitre_service.incident_coverage(_validated_incident_id(incident_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/enterprise/cases/{case_id}/mitre", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_case_coverage(case_id: int) -> dict[str, Any]:
    try:
        return mitre_service.case_coverage(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/enterprise/mitre/navigator/export", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_export_navigator(payload: NavigatorExportRequest) -> dict[str, Any]:
    try:
        return mitre_service.export_navigator_layer(
            incident_ids=payload.incident_ids,
            case_id=payload.case_id,
            layer_name=payload.layer_name,
            description=payload.description,
            include_subtechniques=payload.include_subtechniques,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/enterprise/mitre/workbench/export", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_mitre_export_workbench(payload: NavigatorExportRequest) -> dict[str, Any]:
    try:
        return mitre_service.workbench_export(incident_ids=payload.incident_ids, case_id=payload.case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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


@app.get("/enterprise/investigations/workspace", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_investigation_workspace(
    query_text: str = "",
    event_types: str = "",
    severities: str = "",
    start_time: float | None = None,
    end_time: float | None = None,
    limit: int = 150,
    case_id: int | None = None,
) -> dict[str, Any]:
    return investigation_service.workspace(
        query_text=query_text,
        event_types=_parse_csv_query_values(event_types),
        severities=_parse_csv_query_values(severities),
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        case_id=case_id,
    )


@app.post("/enterprise/investigations/views", dependencies=[Depends(require_analyst_or_admin)])
def create_investigation_view(payload: InvestigationViewRequest) -> dict[str, Any]:
    return investigation_service.create_saved_view(
        name=payload.name,
        description=payload.description,
        query_text=payload.query_text,
        event_types=payload.event_types,
        severities=[severity.value if isinstance(severity, EventSeverity) else str(severity) for severity in payload.severities],
        start_time=payload.start_time,
        end_time=payload.end_time,
        case_id=payload.case_id,
        created_by=payload.created_by,
    )


@app.get("/enterprise/investigations/views", dependencies=[Depends(require_analyst_or_admin)])
def list_investigation_views(case_id: int | None = None) -> list[dict[str, Any]]:
    return investigation_service.list_saved_views(case_id=case_id)


@app.post("/enterprise/investigations/notes", dependencies=[Depends(require_analyst_or_admin)])
def create_investigation_note(payload: InvestigationNoteRequest) -> dict[str, Any]:
    return investigation_service.create_note(**payload.model_dump())


@app.get("/enterprise/investigations/notes", dependencies=[Depends(require_analyst_or_admin)])
def list_investigation_notes(case_id: int | None = None, view_id: int | None = None) -> list[dict[str, Any]]:
    return investigation_service.list_notes(case_id=case_id, view_id=view_id)


@app.post("/enterprise/investigations/stories", dependencies=[Depends(require_analyst_or_admin)])
def create_investigation_story(payload: InvestigationStoryRequest) -> dict[str, Any]:
    return investigation_service.create_story(**payload.model_dump())


@app.get("/enterprise/investigations/stories", dependencies=[Depends(require_analyst_or_admin)])
def list_investigation_stories(case_id: int | None = None) -> list[dict[str, Any]]:
    return investigation_service.list_stories(case_id=case_id)


@app.post("/enterprise/investigations/pins", dependencies=[Depends(require_analyst_or_admin)])
def create_investigation_pin(payload: InvestigationPinRequest) -> dict[str, Any]:
    return investigation_service.create_pin(**payload.model_dump())


@app.get("/enterprise/investigations/pins", dependencies=[Depends(require_analyst_or_admin)])
def list_investigation_pins(case_id: int | None = None, view_id: int | None = None) -> list[dict[str, Any]]:
    return investigation_service.list_pins(case_id=case_id, view_id=view_id)


@app.get("/enterprise/cases/{case_id}/board", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_case_board(case_id: int) -> dict[str, Any]:
    return investigation_service.case_board(case_id=case_id)


@app.get("/enterprise/cases/{case_id}/graph", dependencies=[Depends(require_analyst_or_admin)])
def enterprise_case_graph(case_id: int) -> dict[str, Any]:
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        cases = db.get_case_records(conn).fillna("").to_dict(orient="records")
        case_record = next((item for item in cases if int(item.get("id", 0) or 0) == case_id), None)
        if case_record is None:
            raise HTTPException(status_code=404, detail="Case not found")
        assignments = db.get_case_assignments(conn, case_id).fillna("").to_dict(orient="records")
        tasks = db.get_case_tasks(conn, case_id).fillna("").to_dict(orient="records")
        activity = db.get_case_activity(conn, case_id).fillna("").to_dict(orient="records")
        pins = db.get_investigation_pins(conn, case_id=case_id).fillna("").to_dict(orient="records")
        notes = db.get_investigation_notes(conn, case_id=case_id).fillna("").to_dict(orient="records")
        stories = db.get_investigation_stories(conn, case_id=case_id).fillna("").to_dict(orient="records")
        incidents = db.get_incidents(conn).fillna("").to_dict(orient="records")
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
    return graph_service.build_case_graph(
        case_record=case_record,
        assignments=assignments,
        tasks=tasks,
        activity=activity,
        pins=pins,
        notes=notes,
        stories=stories,
        hosts=hosts_data,
        processes=processes,
        connections=connections,
        incidents=incidents,
        persistence_items=persistence_items,
    )


@app.post("/enterprise/cases/{case_id}/assignments", dependencies=[Depends(require_analyst_or_admin)])
def create_case_assignment(case_id: int, payload: CaseAssignmentRequest) -> dict[str, Any]:
    return investigation_service.assign_analyst(case_id=case_id, **payload.model_dump())


@app.get("/enterprise/cases/{case_id}/assignments", dependencies=[Depends(require_analyst_or_admin)])
def list_case_assignments(case_id: int) -> list[dict[str, Any]]:
    return investigation_service.list_assignments(case_id=case_id)


@app.post("/enterprise/cases/{case_id}/tasks", dependencies=[Depends(require_analyst_or_admin)])
def create_case_task(case_id: int, payload: CaseTaskRequest) -> dict[str, Any]:
    return investigation_service.create_task(case_id=case_id, **payload.model_dump())


@app.get("/enterprise/cases/{case_id}/tasks", dependencies=[Depends(require_analyst_or_admin)])
def list_case_tasks(case_id: int) -> list[dict[str, Any]]:
    return investigation_service.list_tasks(case_id=case_id)


@app.patch("/enterprise/cases/{case_id}/tasks/{task_id}", dependencies=[Depends(require_analyst_or_admin)])
def update_case_task(case_id: int, task_id: int, payload: CaseTaskUpdateRequest) -> dict[str, Any]:
    return investigation_service.update_task(case_id=case_id, task_id=task_id, **payload.model_dump())


@app.get("/enterprise/cases/{case_id}/activity", dependencies=[Depends(require_analyst_or_admin)])
def list_case_activity(case_id: int) -> list[dict[str, Any]]:
    return investigation_service.list_activity(case_id=case_id)


@app.post("/enterprise/cases/{case_id}/investigation-report/export", dependencies=[Depends(require_admin)])
def export_case_investigation_report(case_id: int) -> dict[str, Any]:
    result = investigation_service.export_case_report(case_id=case_id, out_dir=str(OUT_DIR))
    observability_service.log_event(
        "investigation_report_exported",
        case_id=case_id,
        json_path=result.get("json_path", ""),
        html_path=result.get("html_path", ""),
    )
    integrity_service.refresh_manifest()
    return result


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
def dispatch_enterprise_connector_event(request: Request, payload: ConnectorDispatchRequest) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="connector_dispatch", detail="Too many connector dispatch attempts. Wait briefly and retry.")
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


@app.get("/enterprise/abuse/summary", dependencies=[Depends(require_admin)])
def enterprise_abuse_summary() -> dict[str, Any]:
    return enterprise_service.abuse_summary()


@app.post("/enterprise/maintenance/retention", dependencies=[Depends(require_admin)])
def enterprise_retention_cleanup(payload: RetentionCleanupRequest) -> dict[str, Any]:
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        purged = db.purge_old_records(
            conn,
            {
                "telemetry": payload.telemetry_days,
                "alert_log": payload.alerts_days,
                "auth_log": payload.auth_days,
                "action_audit_log": payload.action_audit_days,
                "external_request_log": payload.external_days,
                "connector_delivery_queue": payload.queue_days,
            },
        )
        observability_service.log_event("retention_cleanup_completed", purged=purged)
        return {"status": "completed", "purged": purged}
    finally:
        conn.close()


@app.get("/enterprise/database/readiness", dependencies=[Depends(require_admin)])
def enterprise_database_readiness() -> dict[str, Any]:
    migrations = migration_service.ensure_applied()
    bootstrap_path = migration_service.export_postgres_bootstrap_sql()
    profile = db.database_runtime_profile()
    return {
        "database": profile,
        "migrations": migrations,
        "postgres_bootstrap_sql": bootstrap_path,
        "production_notes": [
            "SQLite stays the default embedded mode for local lab use.",
            "PostgreSQL can now run as the shared backend when SHADOWLAB_DATABASE_URL is configured with a supported driver.",
            "Bootstrap SQL is still exported so multi-node deployments can provision the shared database deterministically.",
        ],
    }


@app.get("/enterprise/report/security-ops", dependencies=[Depends(require_admin)])
def enterprise_security_ops_report() -> dict[str, Any]:
    return {
        "integrity": integrity_service.verify_manifest(),
        "abuse": enterprise_service.abuse_summary(),
        "observability": observability_service.summary(),
        "database": enterprise_database_readiness(),
        "artifacts": _artifact_manifest(),
    }


@app.post("/enterprise/report/security-ops/export", dependencies=[Depends(require_admin)])
def enterprise_security_ops_report_export() -> dict[str, Any]:
    report = enterprise_security_ops_report()
    report_json = OUT_DIR / "SecurityOps_Report.json"
    report_html = OUT_DIR / "SecurityOps_Report.html"
    report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_body = (
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;background:#10151d;color:#eef4fb;padding:24px;'>"
        "<h1>ShadowLab Security Ops Report</h1>"
        f"<pre style='white-space:pre-wrap;background:#16202c;border:1px solid #243446;padding:16px;border-radius:10px;'>{html.escape(json.dumps(report, indent=2))}</pre>"
        "</body></html>"
    )
    report_html.write_text(html_body, encoding="utf-8")
    observability_service.log_event("security_ops_report_exported", json_path=str(report_json), html_path=str(report_html))
    integrity_service.refresh_manifest()
    return {"status": "exported", "json_path": str(report_json), "html_path": str(report_html)}


@app.post("/enterprise/secrets/rotate", dependencies=[Depends(require_admin)])
def enterprise_rotate_secrets(payload: SecretRotationRequest) -> dict[str, Any]:
    global alert_webhook_url
    rotated: list[str] = []
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        if payload.reencrypt_connector_secrets:
            connectors = db.get_connectors(conn).fillna("").to_dict(orient="records")
            for item in connectors:
                name = str(item.get("name", "")).strip().lower()
                raw_config = item.get("config_json", "{}")
                parsed = json.loads(raw_config or "{}") if isinstance(raw_config, str) else (raw_config or {})
                revealed = secret_store.reveal_config(parsed)
                protected = secret_store.protect_config(revealed)
                db.upsert_connector(conn, name, str(item.get("kind", "")), bool(item.get("enabled")), json.dumps(protected))
            rotated.append("connector_secrets")
            db.log_secret_rotation(conn, "connector_secrets", "rotate", detail="Connector secrets were re-encrypted")
        if payload.clear_alert_webhook:
            alert_webhook_url = ""
            db.set_app_setting(conn, "alert_webhook_url_enc", "")
            rotated.append("alert_webhook_cleared")
            db.log_secret_rotation(conn, "alert_webhook", "clear", detail="Stored alert webhook secret cleared")
        elif payload.reencrypt_webhook_secret and alert_webhook_url:
            encrypted = secret_store.encrypt_text(alert_webhook_url)
            db.set_app_setting(conn, "alert_webhook_url_enc", encrypted)
            rotated.append("alert_webhook")
            db.log_secret_rotation(conn, "alert_webhook", "rotate", detail="Alert webhook secret was re-encrypted")
    finally:
        conn.close()
    if payload.rotate_integrity_signing_key:
        integrity_service.rotate_signing_key()
        conn = db.create_connection()
        if conn:
            try:
                db.log_secret_rotation(conn, "integrity_signing_key", "rotate", detail="Integrity signing key rotated and manifest refreshed")
            finally:
                conn.close()
        rotated.append("integrity_signing_key")
    observability_service.log_event("secrets_rotated", rotated=rotated)
    return {"status": "completed", "rotated": rotated}


@app.get("/enterprise/secrets/status", dependencies=[Depends(require_admin)])
def enterprise_secret_status() -> dict[str, Any]:
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        history = db.get_secret_rotations(conn, limit=100).fillna("").to_dict(orient="records")
        stored_webhook = bool(db.get_app_setting(conn, "alert_webhook_url_enc"))
    finally:
        conn.close()
    return {
        "stored_alert_webhook": stored_webhook,
        "rotation_history": history,
        "integrity_history": integrity_service.history(limit=20),
    }


@app.get("/enterprise/adversary/profiles", dependencies=[Depends(require_analyst_or_admin)])
def adversary_profiles() -> dict[str, Any]:
    return enterprise_service.adversary_emulation()


@app.post("/enterprise/purple/replay", dependencies=[Depends(require_analyst_or_admin)])
def purple_replay(payload: ReplayRequest) -> dict[str, Any]:
    target = _validate_replay_artifact_path(payload.artifact_path)
    return enterprise_service.replay_incident(str(target))


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
def run_monitor(request: Request, payload: MonitorRequest) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="monitor_run", detail="Too many monitor runs. Wait briefly and retry.")
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
    actual_process_name = str(profile.get("name") or "").strip()
    requested_process_name = process_name.strip()
    if actual_process_name and requested_process_name and actual_process_name.lower() != requested_process_name.lower():
        raise HTTPException(
            status_code=400,
            detail=f"Process name mismatch for PID {pid}: requested `{requested_process_name}` but host reports `{actual_process_name}`",
        )
    effective_process_name = actual_process_name or requested_process_name
    enforce_process_action_policy(request, effective_process_name)
    if action_name == "suspend":
        result = response_service.suspend(pid, effective_process_name)
    elif action_name == "resume":
        result = response_service.resume(pid, effective_process_name)
    elif action_name == "kill":
        result = response_service.kill(pid, effective_process_name)
    elif action_name == "kill-tree":
        result = response_service.kill_tree(pid, effective_process_name)
    elif action_name == "quarantine":
        result = response_service.quarantine_file(pid, effective_process_name, profile.get("exe"))
    else:
        raise HTTPException(status_code=400, detail="Unsupported action")
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    if action_name == "quarantine":
        conn = db.create_connection()
        if conn:
            try:
                db.log_quarantine(conn, pid, effective_process_name, profile.get("exe"), result.get("path", ""), "active")
            finally:
                conn.close()
        integrity_service.refresh_manifest()
    return result


@app.get("/persistence", dependencies=[Depends(require_analyst_or_admin)])
def persistence_items() -> list[dict[str, Any]]:
    import plugins.persistence as persistence_scanner

    return persistence_scanner.get_persistence_items()


@app.post("/persistence/remediate", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def remediate_persistence(request: Request, payload: PersistenceRemediationRequest) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="persistence:remediate")
    import plugins.persistence as persistence_scanner

    _validate_persistence_target(payload.item_type, payload.path, payload.name)
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
def threat_intel_lookup(request: Request, ip: str) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="threat_intel", detail="Too many threat-intelligence lookups. Wait briefly and retry.")
    ip = _validated_ip_address(ip)
    result = check_ip(ip)
    return {"ip": ip, "result": result}


@app.get("/threat-intel/hash/{file_hash}")
def threat_hash_lookup(request: Request, file_hash: str) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="threat_intel", detail="Too many threat-intelligence lookups. Wait briefly and retry.")
    file_hash = _validated_sha256(file_hash)
    return {
        "hash": file_hash,
        "malwarebazaar": check_file_malwarebazaar(file_hash),
        "yaraify": check_file_yaraify(file_hash),
    }


@app.post("/threat-intel/hash/lookup")
def threat_hash_lookup_with_auth(request: Request, payload: ThreatHashLookupRequest) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="threat_intel", detail="Too many threat-intelligence lookups. Wait briefly and retry.")
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
        source, target = _validate_quarantine_restore_paths(item["quarantine_path"], item["original_path"])
        if not source.exists():
            raise HTTPException(status_code=404, detail="Quarantine artifact not found")
        if target.exists():
            raise HTTPException(status_code=409, detail="Original path already exists; refusing to overwrite during restore")
        target.parent.mkdir(parents=True, exist_ok=True)
        source.replace(target)
        db.update_quarantine(conn, quarantine_id, "restored")
        integrity_service.refresh_manifest()
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
        target = _validate_quarantine_file_path(item["quarantine_path"])
        if target.exists():
            target.unlink()
        db.update_quarantine(conn, quarantine_id, "deleted")
        integrity_service.refresh_manifest()
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
    encrypted = secret_store.encrypt_text(alert_webhook_url)
    conn = db.create_connection()
    if conn:
        try:
            db.set_app_setting(conn, "alert_webhook_url_enc", encrypted)
        finally:
            conn.close()
    return {"status": "configured", "webhook_url": alert_webhook_url, "encrypted_webhook": encrypted}


@app.post("/triage/{pid}", dependencies=[Depends(require_analyst_or_admin)])
def auto_triage(request: Request, pid: int, payload: TriageRequest) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="triage", detail="Too many triage requests. Wait briefly and retry.")
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


@app.get("/integrity", dependencies=[Depends(require_analyst_or_admin)])
def verify_integrity() -> dict[str, Any]:
    observability_service.log_event("integrity_verify_requested")
    return integrity_service.verify_manifest()


@app.get("/integrity/history", dependencies=[Depends(require_admin)])
def integrity_history() -> list[dict[str, Any]]:
    return integrity_service.history()


@app.post("/integrity/refresh", dependencies=[Depends(require_admin)])
def refresh_integrity_manifest(request: Request) -> dict[str, Any]:
    _apply_rate_limit(request, bucket="integrity_refresh", detail="Too many integrity refresh requests. Wait briefly and retry.")
    manifest = integrity_service.refresh_manifest()
    observability_service.log_event("integrity_manifest_refreshed", file_count=len(manifest.get("files", {})))
    return {
        "status": "refreshed",
        "manifest_path": manifest.get("manifest_path", ""),
        "file_count": len(manifest.get("files", {})),
        "generated_at": manifest.get("generated_at", 0),
    }


@app.get("/observability/summary", dependencies=[Depends(require_admin)])
def observability_summary() -> dict[str, Any]:
    return observability_service.summary()


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


@app.post("/integrations/whids/import/file", dependencies=[Depends(require_admin)])
def import_whids_file(payload: IntegrationFileImportRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.import_whids_file(payload.file_path, limit=payload.limit)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/whids/import/manager", dependencies=[Depends(require_admin)])
def import_whids_manager(payload: WhidsManagerImportRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.import_whids_manager(
            payload.manager_url,
            payload.api_key,
            limit=payload.limit,
            endpoint_uuid=payload.endpoint_uuid,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS manager request failed: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/whids/reports", dependencies=[Depends(require_admin)])
def sync_whids_reports(payload: WhidsManagerImportRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.sync_whids_reports(
            payload.manager_url,
            payload.api_key,
            endpoint_uuid=payload.endpoint_uuid,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS reports request failed: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/whids/artifacts", dependencies=[Depends(require_admin)])
def download_whids_artifacts(payload: WhidsArtifactsRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.download_whids_artifacts(
            payload.manager_url,
            payload.api_key,
            endpoint_uuid=payload.endpoint_uuid,
            since=payload.since,
            max_files=payload.max_files,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS artifacts request failed: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/ossec/import/file", dependencies=[Depends(require_admin)])
def import_ossec_file(payload: IntegrationFileImportRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.import_ossec_file(payload.file_path, limit=payload.limit)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/ossec/live/start", dependencies=[Depends(require_admin)])
def start_ossec_live_ingest(payload: OssecLiveIngestRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.start_ossec_live_ingest(
            payload.file_path,
            poll_interval=payload.poll_interval,
            limit=payload.limit,
            start_at_end=payload.start_at_end,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/ossec/live/stop", dependencies=[Depends(require_admin)])
def stop_ossec_live_ingest() -> dict[str, Any]:
    return hids_integration_service.stop_ossec_live_ingest()


@app.get("/integrations/ossec/live/status", dependencies=[Depends(require_admin)])
def ossec_live_status() -> dict[str, Any]:
    return hids_integration_service.ossec_live_status()


@app.get("/integrations/response-policy", dependencies=[Depends(require_admin)])
def get_integration_response_policy() -> dict[str, Any]:
    return hids_integration_service.get_response_policy()


@app.post("/integrations/response-policy", dependencies=[Depends(require_admin)])
def update_integration_response_policy(payload: IntegrationResponsePolicyRequest) -> dict[str, Any]:
    return hids_integration_service.update_response_policy(payload.policy)


@app.post("/integrations/incidents/{incident_id}/response", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
def orchestrate_integration_incident_response(request: Request, incident_id: str, payload: IncidentResponseOrchestrationRequest) -> dict[str, Any]:
    _require_enterprise_approval(request, action_name="integration:incident:response")
    try:
        return hids_integration_service.orchestrate_incident_response(incident_id, apply_actions=payload.apply_actions)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/integrations/whids/iocs/query", dependencies=[Depends(require_admin)])
def query_whids_iocs(payload: WhidsIoCRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.list_whids_iocs(
            payload.manager_url,
            payload.api_key,
            filters=payload.filters,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS IoC query failed: {exc}") from exc


@app.post("/integrations/whids/iocs/add", dependencies=[Depends(require_admin)])
def add_whids_iocs(payload: WhidsIoCRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.add_whids_iocs(
            payload.manager_url,
            payload.api_key,
            payload.items,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS IoC add failed: {exc}") from exc


@app.post("/integrations/whids/iocs/delete", dependencies=[Depends(require_admin)])
def delete_whids_iocs(payload: WhidsIoCRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.delete_whids_iocs(
            payload.manager_url,
            payload.api_key,
            filters=payload.filters,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS IoC delete failed: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/whids/rules/query", dependencies=[Depends(require_admin)])
def query_whids_rules(payload: WhidsRulesRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.list_whids_rules(
            payload.manager_url,
            payload.api_key,
            name=payload.name_filter,
            filters_only=payload.filters_only,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS rules query failed: {exc}") from exc


@app.post("/integrations/whids/rules/add", dependencies=[Depends(require_admin)])
def add_whids_rules(payload: WhidsRulesRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.add_whids_rules(
            payload.manager_url,
            payload.api_key,
            payload.rules,
            update_existing=payload.update_existing,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS rules add failed: {exc}") from exc


@app.post("/integrations/whids/rules/delete", dependencies=[Depends(require_admin)])
def delete_whids_rules(payload: WhidsRulesRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.delete_whids_rules(
            payload.manager_url,
            payload.api_key,
            rule_name=payload.rule_name,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS rules delete failed: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/integrations/whids/config", dependencies=[Depends(require_admin)])
def get_whids_config(payload: WhidsConfigRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.get_whids_endpoint_config(
            payload.manager_url,
            payload.api_key,
            endpoint_uuid=payload.endpoint_uuid,
            config_format=payload.config_format,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS config query failed: {exc}") from exc


@app.post("/integrations/whids/report-archive", dependencies=[Depends(require_admin)])
def get_whids_report_archive(payload: WhidsConfigRequest) -> dict[str, Any]:
    try:
        return hids_integration_service.get_whids_report_archive(
            payload.manager_url,
            payload.api_key,
            endpoint_uuid=payload.endpoint_uuid,
            since=payload.since,
            until=payload.until,
            verify_tls=payload.verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"WHIDS report archive query failed: {exc}") from exc


@app.post("/integrations/whids/scheduler/start", dependencies=[Depends(require_admin)])
def start_whids_scheduler(payload: WhidsSchedulerRequest) -> dict[str, Any]:
    return hids_integration_service.start_whids_scheduler(
        payload.manager_url,
        payload.api_key,
        endpoint_uuid=payload.endpoint_uuid,
        poll_interval=payload.poll_interval,
        verify_tls=payload.verify_tls,
    )


@app.post("/integrations/whids/scheduler/stop", dependencies=[Depends(require_admin)])
def stop_whids_scheduler() -> dict[str, Any]:
    return hids_integration_service.stop_whids_scheduler()


@app.get("/integrations/whids/scheduler/status", dependencies=[Depends(require_admin)])
def whids_scheduler_status() -> dict[str, Any]:
    return hids_integration_service.whids_scheduler_status()


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
    integrity_service.refresh_manifest()
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
    integrity_service.refresh_manifest()
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
    integrity_service.refresh_manifest()


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
        "integrity_manifest.json",
        "SecurityOps_Report.json",
        "SecurityOps_Report.html",
        "observability.jsonl",
        "postgres_bootstrap.sql",
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
    normalized = normalize_outbound_url(webhook_url)
    if not normalized:
        raise HTTPException(status_code=400, detail="Webhook URL must be a safe http(s) destination")
    return normalized


def _validated_sha256(value: str) -> str:
    candidate = (value or "").strip().lower()
    if not SHA256_RE.fullmatch(candidate):
        raise ValueError("SHA-256 values must be 64 hexadecimal characters")
    return candidate


def _validated_ip_address(value: str) -> str:
    candidate = (value or "").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc


def _parse_csv_query_values(raw: str) -> list[str]:
    return [item.strip().lower() for item in (raw or "").split(",") if item.strip()]


def _validated_network_range(value: str) -> str:
    candidate = (value or "").strip()
    try:
        return str(ipaddress.ip_network(candidate, strict=False))
    except ValueError as exc:
        raise ValueError("Invalid IP range or CIDR") from exc


def _validated_incident_id(value: str) -> str:
    candidate = (value or "").strip()
    if candidate and not INCIDENT_ID_RE.fullmatch(candidate):
        raise ValueError("incident_id contains unsupported characters")
    return candidate


def _validate_startup_security_posture() -> None:
    profile = get_active_policy_name()
    issues: list[str] = []
    if profile in {"corp", "prod"} and not security_settings.auth_required:
        issues.append("authentication must be enabled")
    if profile in {"corp", "prod"} and any(origin.strip() == "*" for origin in security_settings.allowed_origins):
        issues.append("wildcard CORS origins are not allowed")
    if profile == "prod" and security_settings.enable_dangerous_actions:
        issues.append("dangerous actions must be disabled")
    if profile in {"corp", "prod"} and security_settings.enable_network_warfare:
        issues.append("network warfare must be disabled")
    if profile == "prod" and security_settings.allow_destructive_file_delete:
        issues.append("destructive file deletion must be disabled")
    if profile in {"corp", "prod"} and security_settings.api_keys:
        issues.append("raw SHADOWLAB_API_KEYS are not allowed; use SHA-256 hashed keys")
    if profile in {"corp", "prod"} and security_settings.api_key:
        issues.append("raw SHADOWLAB_API_KEY is not allowed; use SHADOWLAB_API_KEY_SHA256")
    if issues:
        raise RuntimeError(f"Insecure startup posture for profile `{profile}`: " + "; ".join(issues))
    observability_service.log_event("startup_security_posture_validated", profile=profile)


def _apply_rate_limit(request: Request | None, *, bucket: str, detail: str) -> None:
    target_request = request
    if target_request is None:
        class _Client:
            host = "internal"

        class _State:
            pass

        class _Url:
            path = f"/{bucket}"

        class _StubRequest:
            client = _Client()
            state = _State()
            url = _Url()

        target_request = _StubRequest()  # type: ignore[assignment]
    security_module._enforce_request_rate_limit(
        target_request,  # type: ignore[arg-type]
        bucket=bucket,
        limit=6 if bucket in {"monitor_run", "triage"} else 12,
        window_seconds=60,
        detail=detail,
    )


def _redact_audit_detail(detail: str) -> str:
    if not detail:
        return ""
    redacted = detail
    for token in ["api_key", "token", "signature", "shared_key", "secret", "webhook_url"]:
        redacted = re.sub(rf"(?i)({token}=)[^&]+", rf"\1***redacted***", redacted)
    return redacted[:500]


def _validate_replay_artifact_path(artifact_path: str) -> Path:
    candidate = Path(artifact_path or "").expanduser()
    if not str(candidate).strip():
        raise HTTPException(status_code=400, detail="artifact_path is required")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid artifact path: {exc}") from exc
    allowed_root = OUT_DIR.resolve()
    if allowed_root not in resolved.parents:
        raise HTTPException(status_code=400, detail="Replay artifacts must stay within shadowlab_out")
    if resolved.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Replay artifacts must be JSON files")
    return resolved


def _validate_persistence_target(item_type: str, path: str, name: str) -> None:
    import plugins.persistence as persistence_scanner

    candidates = persistence_scanner.get_persistence_items_fast()
    normalized_type = (item_type or "").strip().lower()
    normalized_path = (path or "").strip().lower()
    normalized_name = (name or "").strip().lower()
    for item in candidates:
        item_type_value = str(item.get("type", "")).strip().lower()
        item_path_value = str(item.get("path", "")).strip().lower()
        item_name_value = str(item.get("name", "")).strip().lower()
        if item_type_value != normalized_type or item_path_value != normalized_path:
            continue
        if normalized_name and item_name_value != normalized_name:
            continue
        return
    raise HTTPException(status_code=400, detail="Persistence target no longer matches current inventory")


def _validate_quarantine_file_path(path_value: str) -> Path:
    target = Path(path_value or "").expanduser()
    if not str(target).strip():
        raise HTTPException(status_code=400, detail="Quarantine path missing")
    resolved = target.resolve(strict=False)
    quarantine_root = (BASE_DIR / "shadowlab_quarantine").resolve()
    if quarantine_root not in resolved.parents:
        raise HTTPException(status_code=400, detail="Invalid quarantine path")
    return resolved


def _validate_quarantine_restore_paths(quarantine_path: str, original_path: str) -> tuple[Path, Path]:
    source = _validate_quarantine_file_path(quarantine_path)
    target = Path(original_path or "").expanduser()
    if not str(target).strip():
        raise HTTPException(status_code=400, detail="Original path missing")
    resolved_target = target.resolve(strict=False)
    if resolved_target == source:
        raise HTTPException(status_code=400, detail="Invalid restore target")
    return source, resolved_target


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
    now_value = time.time()
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        reserved = db.reserve_approval_request(conn, int(approval_id), action_name, now_value)
        if not reserved:
            approvals = db.get_approval_requests(conn)
            row = approvals[approvals["id"] == int(approval_id)]
        else:
            row = None
    finally:
        conn.close()
    if not reserved:
        if row is None or row.empty:
            raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` not found")
        item = row.iloc[0].to_dict()
        status_value = str(item.get("status", "")).lower()
        if status_value not in {"approved", "allow", "granted"}:
            raise HTTPException(
                status_code=403,
                detail=f"Approval `{approval_id}` status is `{status_value or 'unknown'}`; approved status required",
            )
        expected_action = str(item.get("action", "")).strip().lower()
        if expected_action != action_name.strip().lower():
            raise HTTPException(
                status_code=403,
                detail=f"Approval `{approval_id}` is scoped to `{expected_action or 'unknown'}` and cannot be used for `{action_name}`",
            )
        expires_at = float(item.get("expires_at", 0) or 0)
        if expires_at and now_value > expires_at:
            raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` has expired")
        used_at = float(item.get("used_at", 0) or 0)
        if used_at:
            raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` has already been consumed")
        raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` could not be reserved")
    request.state.pending_approval_id = int(approval_id)
    request.state.pending_approval_reserved = True


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
            detail = _redact_audit_detail(request.url.query[:500] if request.url.query else "")
            db.log_action_audit(conn, request.method.upper(), request.url.path, int(status_code), role, client_ip, detail)
        finally:
            conn.close()
    except Exception:
        return


def _consume_pending_approval(request: Request, status_code: int) -> None:
    approval_id = getattr(request.state, "pending_approval_id", None)
    if not approval_id:
        return
    try:
        conn = db.create_connection()
        if conn is None:
            return
        try:
            if status_code >= 400:
                db.release_approval_request(conn, int(approval_id))
            else:
                db.finalize_approval_request(conn, int(approval_id), time.time())
        finally:
            conn.close()
        observability_service.log_event(
            "approval_consumed" if status_code < 400 else "approval_released",
            approval_id=int(approval_id),
            status_code=int(status_code),
        )
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
