from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class TelemetrySample:
    ts: float
    cpu: float
    mem_percent: float
    proc_threads: int
    proc_handles: int | None
    open_files: int
    tcp_conns: int
    bytes_sent_rate: float
    bytes_recv_rate: float
    remote_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SecurityEvent:
    timestamp: float
    source: str
    event_type: str
    severity: str
    title: str
    details: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DetectionFinding:
    rule_id: str
    title: str
    severity: str
    score: float
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IncidentRecord:
    incident_id: str
    created_at: float
    severity: str
    title: str
    summary: str
    likelihood: float
    findings: list[DetectionFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    telemetry_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data
