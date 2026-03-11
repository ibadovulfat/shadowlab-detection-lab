from __future__ import annotations

import time
from typing import Any

from core.models import IncidentRecord
from core.normalization import summarize_to_security_events
from detections.rule_engine import RuleEngine
from plugins.detection_models.ai_engine import DetectionScorer


class DetectionOrchestrator:
    def __init__(self):
        self.scorer = DetectionScorer()
        self.rule_engine = RuleEngine()

    def compute_metrics(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> dict[str, float]:
        if not telemetry_rows:
            return {
                "avg_cpu": 0.0,
                "avg_threads": 0.0,
                "avg_tcp_conns": 0.0,
                "avg_bytes_sent_rate": 0.0,
                "avg_bytes_recv_rate": 0.0,
                "defender_total": float(defender_summary.get("total", 0)),
                "sysmon_total": float(sysmon_summary.get("total", 0)),
            }

        total = float(len(telemetry_rows))
        return {
            "avg_cpu": sum(float(row.get("cpu", 0.0)) for row in telemetry_rows) / total,
            "avg_threads": sum(float(row.get("proc_threads", 0.0)) for row in telemetry_rows) / total,
            "avg_tcp_conns": sum(float(row.get("tcp_conns", 0.0)) for row in telemetry_rows) / total,
            "avg_bytes_sent_rate": sum(float(row.get("bytes_sent_rate", 0.0)) for row in telemetry_rows) / total,
            "avg_bytes_recv_rate": sum(float(row.get("bytes_recv_rate", 0.0)) for row in telemetry_rows) / total,
            "defender_total": float(defender_summary.get("total", 0)),
            "sysmon_total": float(sysmon_summary.get("total", 0)),
        }

    def incremental_score(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> dict[str, Any]:
        base = self.scorer.heuristic(telemetry_rows, defender_summary, sysmon_summary)
        findings = self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        if findings:
            boost = min(0.35, sum(f.score for f in findings))
            base["likelihood"] = max(0.0, min(1.0, base["likelihood"] + boost))
            base["notes"] = list(base.get("notes", [])) + [finding.title for finding in findings]
            base["rule_findings"] = [finding.to_dict() for finding in findings]
        return base

    def final_score(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> dict[str, Any]:
        base = self.scorer.final_score(telemetry_rows, defender_summary, sysmon_summary)
        findings = self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        if findings:
            base["rule_findings"] = [finding.to_dict() for finding in findings]
            base["likelihood"] = max(0.0, min(1.0, base["likelihood"] + min(0.4, sum(f.score for f in findings))))
            base["notes"] = list(base.get("notes", [])) + [f"Rule matched: {finding.rule_id}" for finding in findings]
        base["security_events"] = [
            event.to_dict()
            for event in (
                summarize_to_security_events(defender_summary, "defender")
                + summarize_to_security_events(sysmon_summary, "sysmon")
            )
        ]
        return base

    def build_incident(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> IncidentRecord:
        final = self.final_score(telemetry_rows, defender_summary, sysmon_summary)
        findings = self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        severity = "high" if final["likelihood"] >= 0.75 else "medium" if final["likelihood"] >= 0.4 else "low"
        recommended_actions = self._recommended_actions(final["likelihood"], findings)
        return IncidentRecord(
            incident_id=f"INC-{int(time.time())}",
            created_at=time.time(),
            severity=severity,
            title="Behavioral detection incident",
            summary="Automated incident generated from telemetry, event logs, and rule correlation.",
            likelihood=float(final.get("likelihood", 0.0)),
            findings=findings,
            notes=list(final.get("notes", [])),
            recommended_actions=recommended_actions,
            telemetry_count=len(telemetry_rows),
        )

    def _recommended_actions(self, likelihood: float, findings) -> list[str]:
        actions = ["Review process ancestry and recent network activity."]
        if any(f.rule_id == "defender_hits" for f in findings):
            actions.append("Collect the flagged binary hash and compare against reputation sources.")
        if any(f.rule_id == "data_exfil_pattern" for f in findings):
            actions.append("Inspect outbound connections and consider temporary network isolation.")
        if likelihood >= 0.75:
            actions.append("Capture an evidence bundle and consider suspending the process before kill.")
        elif likelihood >= 0.4:
            actions.append("Run deeper memory and YARA analysis before containment.")
        return actions
