from __future__ import annotations

from typing import Any

import monitor_core

from core.normalization import normalize_telemetry_row


class TelemetryMonitoringService:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.sampler = monitor_core.TelemetrySampler()

    def sample_once(self) -> dict[str, Any]:
        sample = normalize_telemetry_row(self.sampler.sample())
        return sample.to_dict()

    def collect_event_context(self) -> tuple[dict[str, Any], dict[str, Any]]:
        raw_defender, raw_sysmon = monitor_core.read_windows_events()
        defender_summary = monitor_core.summarize_events(
            raw_defender, self.config.get("defender_ids")
        ) if raw_defender else {"total": 0, "by_id": {}}
        sysmon_summary = monitor_core.summarize_events(
            raw_sysmon, self.config.get("sysmon_ids")
        ) if raw_sysmon else {"total": 0, "by_id": {}}
        return defender_summary, sysmon_summary

