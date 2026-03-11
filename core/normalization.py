from __future__ import annotations

import time
from typing import Any

from core.models import SecurityEvent, TelemetrySample
from mitre import get_attack_technique


def normalize_telemetry_row(row: dict[str, Any]) -> TelemetrySample:
    return TelemetrySample(
        ts=float(row.get("ts", time.time())),
        cpu=float(row.get("cpu", 0.0)),
        mem_percent=float(row.get("mem_percent", 0.0)),
        proc_threads=int(row.get("proc_threads", 0)),
        proc_handles=int(row["proc_handles"]) if row.get("proc_handles") is not None else None,
        open_files=int(row.get("open_files", 0)),
        tcp_conns=int(row.get("tcp_conns", 0)),
        bytes_sent_rate=float(row.get("bytes_sent_rate", 0.0)),
        bytes_recv_rate=float(row.get("bytes_recv_rate", 0.0)),
        remote_ips=list(row.get("remote_ips", [])),
    )


def summarize_to_security_events(summary: dict[str, Any], source: str) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for label, count in (summary.get("by_id", {}) or {}).items():
        event_id = _extract_event_id(label)
        techniques = get_attack_technique(event_id) or []
        severity = _severity_from_count(int(count))
        events.append(
            SecurityEvent(
                timestamp=time.time(),
                source=source,
                event_type="event_summary",
                severity=severity,
                title=label,
                details={"count": int(count), "event_id": event_id},
                mitre_techniques=techniques,
                risk_score=min(100, int(count) * 10),
            )
        )
    return events


def _extract_event_id(label: str) -> int:
    for token in str(label).split():
        if token.isdigit():
            return int(token)
    return 0


def _severity_from_count(count: int) -> str:
    if count >= 10:
        return "high"
    if count >= 4:
        return "medium"
    return "low"

