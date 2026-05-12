"""Pydantic request models for the ShadowLab API layer."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from api.schemas.enums import (
    ApprovalStatus,
    CasePriority,
    CaseStage,
    ConnectorKind,
    EventSeverity,
    IncidentStatus,
    PersistenceItemType,
)
from api.utils.paths import validate_integration_import_path
from api.utils.validators import (
    CONNECTOR_NAME_RE,
    SEMVER_RE,
    validated_incident_id,
    validated_ip_address,
    validated_network_range,
    validated_sha256,
)


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
        return validated_sha256(value)


class MalwareAnalystFileRequest(BaseModel):
    file_path: str

    @field_validator("file_path")
    @classmethod
    def _validate_file_path(cls, value: str) -> str:
        # Boundary input — reject the obvious shapes that lead to abuse
        # later (NUL injection, empty path, traversal). The downstream
        # service still resolves and bounds the path against an allow-
        # list, but a fail-fast pydantic guard keeps junk out of logs
        # and avoids tripping the malware-analyst subprocess on garbage.
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("file_path is required")
        if "\x00" in candidate:
            raise ValueError("file_path contains NUL byte")
        if len(candidate) > 4096:
            raise ValueError("file_path is too long")
        # `..` segments are not a hard error here (resolution happens in
        # the service layer with proper root anchoring) but obviously
        # malformed shapes are.
        if candidate.endswith(("/", "\\")):
            raise ValueError("file_path must point to a file, not a directory")
        return candidate


class SnifferRequest(BaseModel):
    duration: int = Field(default=10, ge=5, le=60)


class StringScanRequest(BaseModel):
    min_length: int = Field(default=4, ge=3, le=20)
    patterns: list[str] = Field(default_factory=lambda: ["http", "powershell", "cmd", "token", "password", "api"])


class YaraLookupRequest(BaseModel):
    yaraify_auth_key: str | None = None
    local_yara_pack: str = Field(default="enterprise")


class SandboxTraceRequest(BaseModel):
    duration: int = Field(default=5, ge=2, le=60)
    interval: float = Field(default=0.5, ge=0.1, le=5.0)


class EvidenceRequest(BaseModel):
    alert_name: str = Field(default="incident")

    @field_validator("alert_name")
    @classmethod
    def _validate_alert_name(cls, value: str) -> str:
        candidate = (value or "").strip() or "incident"
        if len(candidate) > 80:
            raise ValueError("alert_name must be 80 characters or fewer")
        if not re.fullmatch(r"[A-Za-z0-9._ -]+", candidate):
            raise ValueError("alert_name may contain only letters, digits, space, dot, underscore, and dash")
        return candidate


class NetworkScanRequest(BaseModel):
    ip_range: str = Field(default="192.168.1.0/24")

    @field_validator("ip_range")
    @classmethod
    def _validate_ip_range(cls, value: str) -> str:
        return validated_network_range(value)


class BlockerRequest(BaseModel):
    target_ip: str
    gateway_ip: str

    @field_validator("target_ip", "gateway_ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        return validated_ip_address(value)


class IncidentUpdateRequest(BaseModel):
    status: IncidentStatus | None = None
    notes: str | None = None
    owner: str | None = None


class PersistenceRemediationRequest(BaseModel):
    item_type: PersistenceItemType
    path: str
    name: str = ""

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        # The persistence guard in `api/utils/persistence_guards.py` does
        # the heavy lifting against item_type-specific allowlists. Here
        # we just reject the shapes that always indicate abuse: empty,
        # NUL bytes, or overlong values that bloat audit logs.
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("path is required")
        if "\x00" in candidate:
            raise ValueError("path contains NUL byte")
        if len(candidate) > 4096:
            raise ValueError("path is too long")
        return candidate

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        trimmed = (value or "").strip()
        if "\x00" in trimmed:
            raise ValueError("name contains NUL byte")
        if len(trimmed) > 512:
            raise ValueError("name is too long")
        return trimmed


class AlertWebhookRequest(BaseModel):
    webhook_url: str
    message: str = "ShadowLab test alert"

    @field_validator("webhook_url")
    @classmethod
    def _validate_webhook(cls, value: str) -> str:
        # Defer strict outbound URL validation to the route layer (handles HTTP-level
        # rejection via HTTPException) but normalize whitespace here.
        trimmed = (value or "").strip()
        if not trimmed:
            raise ValueError("webhook_url is required")
        return trimmed


class TriageRequest(BaseModel):
    virustotal_api_key: str | None = None
    malwarebazaar_auth_key: str | None = None
    yaraify_auth_key: str | None = None
    local_yara_pack: str = Field(default="enterprise")
    trace_duration: int = Field(default=3, ge=1, le=20)
    strings_min_length: int = Field(default=4, ge=3, le=20)
    strings_patterns: list[str] = Field(default_factory=lambda: ["http", "powershell", "cmd", "password"])


class TriageRespondRequest(BaseModel):
    process_name: str = ""


class LocalYaraPolicyRequest(BaseModel):
    policy: dict[str, Any] = Field(default_factory=dict)


class LocalYaraRuleTuningRequest(BaseModel):
    rule_id: str
    score_delta: int = Field(default=0, ge=0, le=20)
    disabled: bool = False
    force: bool = False
    notes: str = ""


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
        return validated_ip_address(value)


class IntegrationFileImportRequest(BaseModel):
    file_path: str
    limit: int = Field(default=200, ge=1, le=2000)

    @field_validator("file_path")
    @classmethod
    def _validate_file_path(cls, value: str) -> str:
        return validate_integration_import_path(value, kind="whids")


class OssecFileImportRequest(BaseModel):
    file_path: str
    limit: int = Field(default=200, ge=1, le=2000)

    @field_validator("file_path")
    @classmethod
    def _validate_file_path(cls, value: str) -> str:
        return validate_integration_import_path(value, kind="ossec")


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
        return validate_integration_import_path(value, kind="ossec")


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
        return validate_integration_import_path(value, kind="mitre")

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
        return [validated_incident_id(item) for item in value if validated_incident_id(item)]

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
        return validate_integration_import_path(value, kind="mitre")


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
        return validated_incident_id(value)


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


class IdentityRevokeRequest(BaseModel):
    subject: str = ""
    token_id: str = ""
    reason: str = ""
    expires_at: float = 0.0

    @field_validator("subject", "token_id", "reason")
    @classmethod
    def _normalize_identity_fields(cls, value: str) -> str:
        return str(value or "").strip()


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
        return validated_incident_id(value)

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
        return validated_network_range(value)


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
