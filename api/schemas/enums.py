"""String enum types shared by ShadowLab request schemas and route handlers."""
from __future__ import annotations

from enum import StrEnum


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
