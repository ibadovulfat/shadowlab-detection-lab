from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter
from itertools import chain
from pathlib import Path
from typing import Any

from core.models import IncidentRecord
from core.normalization import summarize_to_security_events
from detections.rule_engine import RuleEngine
from plugins.detection_models.ai_engine import DetectionScorer

# Likelihood at/above which a window is escalated to an incident
# (MEDIUM). Mirrors the severity thresholds in build_incident.
_INCIDENT_THRESHOLD = 0.45

# EWMA smoothing for the per-host/workspace resource baseline. ~0.2
# means each benign window nudges the baseline 20% toward the new
# observation, so the baseline tracks gradual drift (new workload) but
# resists single-window spikes.
_BASELINE_ALPHA = 0.2

# Baseline is only LEARNED from benign windows (no true signal). A
# compromised window must never poison the "normal" the host is scored
# against.
_BASELINE_KEYS = ("avg_cpu", "avg_threads", "avg_tcp_conns")


class _BaselineStore:
    """Persistent per-workspace resource baseline (EWMA).

    Stored as a small JSON doc under ``shadowlab_out`` rather than a new
    DB table to avoid a schema migration — it is host-local advisory
    state, not audit data. Updated ONLY with benign windows so a real
    incident can't shift "normal" and mask follow-on activity.
    """

    def __init__(self, path: Path | None = None) -> None:
        base = Path(__file__).resolve().parent.parent / "shadowlab_out"
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self._path = path or (base / "detection_baseline.json")
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def get(self, workspace_id: str) -> dict[str, float] | None:
        ws = str(workspace_id or "default").strip().lower() or "default"
        entry = self._load().get(ws)
        if not isinstance(entry, dict):
            return None
        out: dict[str, float] = {}
        for key in _BASELINE_KEYS:
            try:
                out[key] = float(entry[key])
            except (KeyError, TypeError, ValueError):
                continue
        return out or None

    def update(self, workspace_id: str, observed: dict[str, float]) -> None:
        ws = str(workspace_id or "default").strip().lower() or "default"
        with self._lock:
            data = self._load()
            entry = data.get(ws) if isinstance(data.get(ws), dict) else {}
            updated: dict[str, float] = {}
            for key in _BASELINE_KEYS:
                obs = observed.get(key)
                if obs is None:
                    continue
                obs = float(obs)
                prev = entry.get(key)
                if prev is None:
                    updated[key] = obs
                else:
                    updated[key] = (1.0 - _BASELINE_ALPHA) * float(prev) + _BASELINE_ALPHA * obs
            if not updated:
                return
            entry.update(updated)
            entry["updated_at"] = time.time()
            data[ws] = entry
            tmp = self._path.with_suffix(".tmp")
            try:
                with tmp.open("w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                os.replace(tmp, self._path)
            except OSError:
                # Baseline persistence is advisory; a write failure must
                # never break scoring.
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass


class DetectionOrchestrator:
    def __init__(self):
        self.scorer = DetectionScorer()
        self.rule_engine = RuleEngine()
        self._baseline = _BaselineStore()

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
                "max_cpu": 0.0,
                "cpu_spike_delta": 0.0,
                "avg_threads": 0.0,
                "max_threads": 0.0,
                "thread_spike_delta": 0.0,
                "avg_tcp_conns": 0.0,
                "max_tcp_conns": 0.0,
                "connection_burst_ratio": 0.0,
                "avg_bytes_sent_rate": 0.0,
                "avg_bytes_recv_rate": 0.0,
                "outbound_dominance_ratio": 0.0,
                "remote_ip_churn": 0.0,
                "stable_remote_fraction": 0.0,
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
        cpu_values = [float(row.get("cpu", 0.0)) for row in telemetry_rows]
        thread_values = [float(row.get("proc_threads", 0.0)) for row in telemetry_rows]
        tcp_values = [float(row.get("tcp_conns", 0.0)) for row in telemetry_rows]
        sent_values = [float(row.get("bytes_sent_rate", 0.0)) for row in telemetry_rows]
        recv_values = [float(row.get("bytes_recv_rate", 0.0)) for row in telemetry_rows]
        remote_ip_counter: Counter[str] = Counter()
        total_remote_ip_observations = 0
        for row in telemetry_rows:
            row_remote_ips = row.get("remote_ips", []) or []
            unique_row_ips = [str(ip).strip() for ip in row_remote_ips if str(ip).strip()]
            remote_ip_counter.update(unique_row_ips)
            total_remote_ip_observations += len(unique_row_ips)
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
        avg_tcp_conns = sum(tcp_values) / total
        avg_sent_rate = sum(sent_values) / total
        avg_recv_rate = sum(recv_values) / total
        max_remote_observations = max(remote_ip_counter.values()) if remote_ip_counter else 0
        return {
            "avg_cpu": sum(cpu_values) / total,
            "max_cpu": max(cpu_values),
            "cpu_spike_delta": max(cpu_values) - min(cpu_values),
            "avg_threads": sum(thread_values) / total,
            "max_threads": max(thread_values),
            "thread_spike_delta": max(thread_values) - min(thread_values),
            "avg_tcp_conns": avg_tcp_conns,
            "max_tcp_conns": max(tcp_values),
            "connection_burst_ratio": (max(tcp_values) / avg_tcp_conns) if avg_tcp_conns > 0 else 0.0,
            "avg_bytes_sent_rate": avg_sent_rate,
            "avg_bytes_recv_rate": avg_recv_rate,
            "outbound_dominance_ratio": (avg_sent_rate / max(avg_recv_rate, 1.0)) if avg_sent_rate > 0 else 0.0,
            "remote_ip_churn": float(len(remote_ip_counter)),
            "stable_remote_fraction": (max_remote_observations / total_remote_ip_observations) if total_remote_ip_observations else 0.0,
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

    def _window_resources(self, telemetry_rows: list[dict[str, Any]]) -> dict[str, float]:
        """avg_cpu / avg_threads / avg_tcp_conns for this window (baseline I/O)."""
        if not telemetry_rows:
            return {}
        n = float(len(telemetry_rows))
        return {
            "avg_cpu": sum(float(r.get("cpu", 0.0) or 0.0) for r in telemetry_rows) / n,
            "avg_threads": sum(float(r.get("proc_threads", 0.0) or 0.0) for r in telemetry_rows) / n,
            "avg_tcp_conns": sum(float(r.get("tcp_conns", 0.0) or 0.0) for r in telemetry_rows) / n,
        }

    def incremental_score(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        baseline = self._baseline.get(workspace_id)
        base = self.scorer.heuristic(telemetry_rows, defender_summary, sysmon_summary, baseline=baseline)
        findings = self._deduplicate_findings(
            self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        )
        if findings:
            # Rules surface correlation context regardless, but the
            # likelihood BOOST is gated on a true signal: a window with
            # no Defender malware verdict and no injection telemetry must
            # not be escalated to MEDIUM purely because volume-based
            # rules matched routine activity.
            base["rule_findings"] = [finding.to_dict() for finding in findings]
            base["notes"] = self._deduplicate_notes(
                list(base.get("notes", [])) + [finding.title for finding in findings]
            )
            base["attack_chain"] = self._build_attack_chain(findings)
            base["mitre_mapping"] = sorted({tech for finding in findings for tech in finding.mitre_techniques})
            if base.get("has_true_signal"):
                boost = min(0.35, sum(f.score for f in findings))
                base["likelihood"] = max(0.0, min(1.0, base["likelihood"] + boost))
            base["correlation_story"] = self._build_correlation_story(findings, base["likelihood"])
        return base

    def final_score(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        baseline = self._baseline.get(workspace_id)
        base = self.scorer.final_score(telemetry_rows, defender_summary, sysmon_summary, baseline=baseline)
        findings = self._deduplicate_findings(
            self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        )
        if findings:
            base["rule_findings"] = [finding.to_dict() for finding in findings]
            if base.get("has_true_signal"):
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
        workspace_id: str = "default",
    ) -> IncidentRecord:
        final = self.final_score(telemetry_rows, defender_summary, sysmon_summary, workspace_id=workspace_id)
        findings = self._deduplicate_findings(
            self.rule_engine.evaluate(self.compute_metrics(telemetry_rows, defender_summary, sysmon_summary))
        )
        likelihood = float(final.get("likelihood", 0.0))
        has_true_signal = bool(final.get("has_true_signal"))

        # Severity is gated on a true malicious indicator. Without one,
        # the window is informational ("low") no matter how much routine
        # volume it carried — this is what stops a clean production host
        # from showing a permanent phantom MEDIUM incident.
        if has_true_signal and likelihood >= 0.85:
            severity = "high"
        elif has_true_signal and likelihood >= _INCIDENT_THRESHOLD:
            severity = "medium"
        else:
            severity = "low"

        if has_true_signal:
            title = "Behavioral detection incident"
            summary = "Automated incident generated from telemetry, event logs, and rule correlation."
        else:
            title = "Baseline telemetry snapshot"
            summary = (
                "No malicious indicator detected. Host telemetry within learned baseline; "
                "correlation context retained for review only."
            )

        # Learn the host's "normal" ONLY from benign windows so a real
        # incident can't shift the baseline and mask follow-on activity.
        if not has_true_signal and likelihood < _INCIDENT_THRESHOLD:
            resources = self._window_resources(telemetry_rows)
            if resources:
                try:
                    self._baseline.update(workspace_id, resources)
                except Exception:
                    pass

        recommended_actions = self._recommended_actions(likelihood, findings)
        return IncidentRecord(
            incident_id=f"INC-{int(time.time())}",
            created_at=time.time(),
            severity=severity,
            title=title,
            summary=summary,
            likelihood=likelihood,
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
