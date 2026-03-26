from __future__ import annotations

import time
from itertools import chain
from typing import Any

from core.models import IncidentRecord
from core.normalization import summarize_to_security_events
from detections.rule_engine import RuleEngine
from plugins.detection_models.ai_engine import DetectionScorer


class DetectionOrchestrator:
    def __init__(self):
        self.scorer = DetectionScorer()
        self.rule_engine = RuleEngine()

    def _event_count(self, mapping: dict[str, Any], *labels: str) -> float:
        for label in labels:
            if label in mapping:
                return float(mapping.get(label, 0) or 0)
        return 0.0

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
                "sysmon_dns_queries": 0.0,
                "sysmon_create_remote_thread": 0.0,
                "sysmon_process_create": 0.0,
                "sysmon_image_load": 0.0,
                "sysmon_process_access": 0.0,
                "sysmon_file_create": 0.0,
                "sysmon_registry_add": 0.0,
                "sysmon_registry_set": 0.0,
                "defender_remediation_failed": 0.0,
            }

        total = float(len(telemetry_rows))
        defender_by_id = defender_summary.get("by_id", {}) or {}
        sysmon_by_id = sysmon_summary.get("by_id", {}) or {}
        dns_queries = self._event_count(sysmon_by_id, "DNS query")
        remote_threads = self._event_count(sysmon_by_id, "CreateRemoteThread")
        process_creates = self._event_count(sysmon_by_id, "Process Create", "Process creation")
        image_loads = self._event_count(sysmon_by_id, "Image loaded")
        process_accesses = self._event_count(sysmon_by_id, "Process accessed")
        file_creates = self._event_count(sysmon_by_id, "File create")
        registry_adds = self._event_count(sysmon_by_id, "Registry add")
        registry_sets = self._event_count(sysmon_by_id, "Registry set")
        return {
            "avg_cpu": sum(float(row.get("cpu", 0.0)) for row in telemetry_rows) / total,
            "avg_threads": sum(float(row.get("proc_threads", 0.0)) for row in telemetry_rows) / total,
            "avg_tcp_conns": sum(float(row.get("tcp_conns", 0.0)) for row in telemetry_rows) / total,
            "avg_bytes_sent_rate": sum(float(row.get("bytes_sent_rate", 0.0)) for row in telemetry_rows) / total,
            "avg_bytes_recv_rate": sum(float(row.get("bytes_recv_rate", 0.0)) for row in telemetry_rows) / total,
            "defender_total": float(defender_summary.get("total", 0)),
            "sysmon_total": float(sysmon_summary.get("total", 0)),
            "defender_signal": float(
                defender_by_id.get("Malware detected (scan)", 0)
            ) + float(defender_by_id.get("Malware detected (on-access)", 0))
            + float(defender_by_id.get("Remediation failed", 0)),
            "defender_remediation_failed": float(defender_by_id.get("Remediation failed", 0)),
            "sysmon_signal": float(sysmon_by_id.get("Network connection", 0))
            + dns_queries
            + (remote_threads * 2.0),
            "sysmon_dns_queries": dns_queries,
            "sysmon_create_remote_thread": remote_threads,
            "sysmon_process_create": process_creates,
            "sysmon_image_load": image_loads,
            "sysmon_process_access": process_accesses,
            "sysmon_file_create": file_creates,
            "sysmon_registry_add": registry_adds,
            "sysmon_registry_set": registry_sets,
        }

    def incremental_score(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> dict[str, Any]:
        base = self.scorer.heuristic(telemetry_rows, defender_summary, sysmon_summary)
        findings = self._deduplicate_findings(
            self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        )
        if findings:
            boost = min(0.35, sum(f.score for f in findings))
            base["likelihood"] = max(0.0, min(1.0, base["likelihood"] + boost))
            base["notes"] = self._deduplicate_notes(list(base.get("notes", [])) + [finding.title for finding in findings])
            base["rule_findings"] = [finding.to_dict() for finding in findings]
            base["attack_chain"] = self._build_attack_chain(findings)
            base["mitre_mapping"] = sorted({tech for finding in findings for tech in finding.mitre_techniques})
            base["correlation_story"] = self._build_correlation_story(findings, base["likelihood"])
        return base

    def final_score(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> dict[str, Any]:
        base = self.scorer.final_score(telemetry_rows, defender_summary, sysmon_summary)
        findings = self._deduplicate_findings(
            self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        )
        if findings:
            base["rule_findings"] = [finding.to_dict() for finding in findings]
            base["likelihood"] = max(0.0, min(1.0, base["likelihood"] + min(0.4, sum(f.score for f in findings))))
            base["notes"] = self._deduplicate_notes(
                list(base.get("notes", [])) + [f"Rule matched: {finding.rule_id}" for finding in findings]
            )
            base["attack_chain"] = self._build_attack_chain(findings)
            base["mitre_mapping"] = sorted({tech for finding in findings for tech in finding.mitre_techniques})
            base["correlation_story"] = self._build_correlation_story(findings, base["likelihood"])
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
        findings = self._deduplicate_findings(
            self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        )
        severity = "high" if final["likelihood"] >= 0.85 else "medium" if final["likelihood"] >= 0.45 else "low"
        recommended_actions = self._recommended_actions(final["likelihood"], findings)
        return IncidentRecord(
            incident_id=f"INC-{int(time.time())}",
            created_at=time.time(),
            severity=severity,
            title="Behavioral detection incident",
            summary="Automated incident generated from telemetry, event logs, and rule correlation.",
            likelihood=float(final.get("likelihood", 0.0)),
            findings=findings,
            notes=self._deduplicate_notes(list(final.get("notes", []))),
            recommended_actions=recommended_actions,
            telemetry_count=len(telemetry_rows),
            attack_chain=list(final.get("attack_chain", [])),
            mitre_techniques=list(final.get("mitre_mapping", [])),
            correlation_story=str(final.get("correlation_story", "")),
        )

    def _recommended_actions(self, likelihood: float, findings) -> list[str]:
        actions = ["Review process ancestry and recent network activity."]
        if any(f.rule_id == "defender_hits" for f in findings):
            actions.append("Collect the flagged binary hash and compare against reputation sources.")
        if any(f.rule_id == "data_exfil_pattern" for f in findings):
            actions.append("Inspect outbound connections and consider temporary network isolation.")
        if likelihood >= 0.85:
            actions.append("Capture an evidence bundle and consider suspending the process before kill.")
        elif likelihood >= 0.45:
            actions.append("Run deeper memory and YARA analysis before containment.")
        return actions

    def _deduplicate_findings(self, findings):
        seen: dict[str, Any] = {}
        for finding in findings:
            key = finding.dedup_key or finding.rule_id
            current = seen.get(key)
            if current is None or float(finding.score) > float(current.score):
                seen[key] = finding
        return list(seen.values())

    def _deduplicate_notes(self, notes: list[str]) -> list[str]:
        deduped: list[str] = []
        for note in notes:
            if note and note not in deduped:
                deduped.append(note)
        return deduped

    def _build_attack_chain(self, findings) -> list[str]:
        ordered = []
        for tactic in chain.from_iterable(f.attack_tactics for f in findings):
            if tactic not in ordered:
                ordered.append(tactic)
        return ordered

    def _build_correlation_story(self, findings, likelihood: float) -> str:
        if not findings:
            return "No correlated attack path was identified."
        tactics = self._build_attack_chain(findings)
        titles = ", ".join(f.title for f in findings[:4])
        confidence = "high-confidence" if likelihood >= 0.85 else "moderate-confidence"
        return (
            f"ShadowLab correlated a {confidence} behavioral chain spanning "
            f"{' -> '.join(tactics) if tactics else 'multiple tactics'}, driven by {titles}."
        )
