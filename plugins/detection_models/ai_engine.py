from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

try:
    from sklearn.linear_model import LogisticRegression  # type: ignore
    import numpy as np  # type: ignore
except Exception:
    LogisticRegression = None
    np = None


class BaseDetectionScorer(ABC):
    @abstractmethod
    def heuristic(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def ml_component(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Optional[float]:
        pass

    @abstractmethod
    def final_score(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, Any]:
        pass


# Below this, the window has "no true malicious indicator" and
# resource/volume metrics may only contribute a tiny capped amount — so
# a clean production host scores ~0 instead of floating into MEDIUM on
# routine Sysmon/Defender log volume.
_TRUE_SIGNAL_EPSILON = 1e-6


class DetectionScorer(BaseDetectionScorer):
    """Signal-first behavioral scorer.

    Production contract (not lab-demo):

    * A host with **no genuine malicious indicator** — no Defender
      "Malware detected"/"Remediation failed" verdicts, no Sysmon
      CreateRemoteThread/injection telemetry — and resource usage within
      its own learned baseline MUST score ~0.0.
    * Likelihood is driven by *true signal*. Resource/volume terms (CPU,
      threads, TCP, raw Sysmon network/DNS/registry counts) are
      **baseline-relative modifiers only**, capped so they can never by
      themselves push a clean machine to MEDIUM.

    The old model summed ``min(avg_cpu/80,1)*0.14 + ... +
    min(sysmon_signal/12,1)*0.22`` where ``sysmon_signal`` counted
    routine "Network connection"/"DNS query"/"Registry set" volume.
    Every live Windows box exceeds those constants at rest, so a clean
    host floated at ~0.3-0.4 and tipped into MEDIUM — the
    "looks like a simulation" false-positive.
    """

    # Max contribution of baseline-relative resource deviation. Kept far
    # below the MEDIUM threshold (0.45) so resource noise alone never
    # raises an incident.
    _MAX_DEVIATION_WEIGHT = 0.12

    def _extract_signals(self, def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, float]:
        def_by = def_sum.get("by_id", {}) if isinstance(def_sum, dict) else {}
        sys_by = sys_sum.get("by_id", {}) if isinstance(sys_sum, dict) else {}

        def value(mapping: Dict[str, Any], key: str) -> float:
            raw = mapping.get(key, 0)
            return float(raw) if isinstance(raw, (int, float)) else 0.0

        # TRUE Defender signal — only actual malware verdicts / failed
        # remediation. NOT "Configuration changed"/"Remediation action
        # taken" and NOT raw `total`.
        defender_signal = (
            value(def_by, "Malware detected (scan)")
            + value(def_by, "Malware detected (on-access)") * 1.5
            + value(def_by, "Remediation failed") * 1.5
        )
        # TRUE injection signal — CreateRemoteThread is the canonical
        # cross-process injection primitive; process-access only counts
        # when it co-occurs with a remote-thread (a lone OpenProcess is
        # ubiquitous and benign).
        crt = value(sys_by, "CreateRemoteThread")
        proc_access = value(sys_by, "Process accessed")
        injection_signal = crt * 2.5 + (min(proc_access, crt * 2.0) if crt > 0 else 0.0)
        return {
            "defender_total": float(def_sum.get("total", 0) or 0.0),
            "sysmon_total": float(sys_sum.get("total", 0) or 0.0),
            "defender_signal": defender_signal,
            "injection_signal": injection_signal,
            # Retained for notes / rule-engine context only — NO LONGER
            # summed into likelihood (these are routine volume).
            "sys_conn": value(sys_by, "Network connection"),
            "sys_dns": value(sys_by, "DNS query"),
        }

    @staticmethod
    def _deviation(current: float, baseline: float | None, *, floor: float) -> float:
        """Fraction (0..1) by which `current` exceeds its learned baseline.

        Returns 0 when there is no baseline yet (first runs must not
        punish the host) or when current is within/under baseline.
        `floor` guards division and ignores trivially-small baselines.
        2x baseline saturates to 1.0.
        """
        if baseline is None:
            return 0.0
        ref = max(float(baseline), floor)
        if current <= ref:
            return 0.0
        return min((current - ref) / ref, 1.0)

    def heuristic(
        self,
        tele_rows: List[dict],
        def_sum: Dict[str, Any],
        sys_sum: Dict[str, Any],
        baseline: Dict[str, float] | None = None,
    ) -> Dict[str, Any]:
        if not tele_rows:
            return {"likelihood": 0.0, "parts": {}, "notes": ["no telemetry"], "has_true_signal": False}

        n = len(tele_rows)
        avg_cpu = sum(float(r.get("cpu", 0.0) or 0.0) for r in tele_rows) / n
        avg_thr = sum(float(r.get("proc_threads", 0.0) or 0.0) for r in tele_rows) / n
        avg_tcp = sum(float(r.get("tcp_conns", 0.0) or 0.0) for r in tele_rows) / n
        avg_sent = sum(float(r.get("bytes_sent_rate", 0.0) or 0.0) for r in tele_rows) / n
        signals = self._extract_signals(def_sum, sys_sum)

        parts: Dict[str, float] = {}
        notes: List[str] = []

        # --- TRUE-SIGNAL component (dominant) ----------------------- #
        # defender_signal of 2 already saturates the full weight: a
        # confirmed malware verdict alone is HIGH.
        parts["defender_malware"] = min(signals["defender_signal"] / 2.0, 1.0) * 0.55
        parts["process_injection"] = min(signals["injection_signal"] / 2.5, 1.0) * 0.30
        true_signal = signals["defender_signal"] + signals["injection_signal"]
        has_true_signal = true_signal > _TRUE_SIGNAL_EPSILON

        # --- Baseline-relative resource deviation (modifier only) --- #
        # Capped at _MAX_DEVIATION_WEIGHT (0.12 < 0.45) so resource noise
        # alone can never reach MEDIUM. Contributes only when the host
        # deviates from its OWN learned normal.
        b = baseline or {}
        cpu_dev = self._deviation(avg_cpu, b.get("avg_cpu"), floor=5.0)
        thr_dev = self._deviation(avg_thr, b.get("avg_threads"), floor=10.0)
        tcp_dev = self._deviation(avg_tcp, b.get("avg_tcp_conns"), floor=2.0)
        deviation = cpu_dev * 0.05 + thr_dev * 0.04 + tcp_dev * 0.03
        if avg_sent >= 50000 and avg_tcp >= 8 and (has_true_signal or deviation > 0):
            deviation += 0.04
        parts["baseline_deviation"] = min(deviation, self._MAX_DEVIATION_WEIGHT)

        # --- Notes ------------------------------------------------- #
        if signals["defender_signal"] >= 1:
            notes.append(f"Confirmed Defender malware signal: {signals['defender_signal']:.0f}")
        if signals["injection_signal"] >= 1:
            notes.append(f"Process-injection telemetry (CreateRemoteThread): {signals['injection_signal']:.1f}")
        if cpu_dev > 0:
            notes.append(f"CPU above host baseline ({avg_cpu:.1f}%)")
        if tcp_dev > 0:
            notes.append(f"TCP connections above host baseline ({avg_tcp:.0f})")
        if not has_true_signal and parts["baseline_deviation"] <= 0:
            notes.append("Within host baseline - no malicious indicator")

        likelihood = max(0.0, min(1.0, sum(parts.values())))
        return {
            "likelihood": likelihood,
            "parts": parts,
            "notes": notes,
            "has_true_signal": has_true_signal,
        }

    def ml_component(
        self,
        tele_rows: List[dict],
        def_sum: Dict[str, Any],
        sys_sum: Dict[str, Any],
    ) -> Optional[float]:
        # The illustrative logistic model trains on synthetic data and
        # historically added probability mass even with zero true signal
        # — a primary false-positive driver. It is now gated on a real
        # signal in final_score and kept only as a corroborating nudge.
        if not (LogisticRegression and np and tele_rows):
            return None

        n = len(tele_rows)
        avg_cpu = sum(float(r.get("cpu", 0.0) or 0.0) for r in tele_rows) / n
        avg_thr = sum(float(r.get("proc_threads", 0.0) or 0.0) for r in tele_rows) / n
        avg_tcp = sum(float(r.get("tcp_conns", 0.0) or 0.0) for r in tele_rows) / n
        signals = self._extract_signals(def_sum, sys_sum)

        x = np.array(
            [[avg_cpu, avg_thr, avg_tcp, signals["defender_signal"], signals["injection_signal"]]],
            dtype=float,
        )
        rng = np.random.default_rng(0)
        x_train = rng.normal(loc=[12, 14, 1, 0, 0], scale=[6, 8, 1, 0.8, 1.2], size=(200, 5))
        y_train = (
            0.4 * x_train[:, 0]
            + 0.2 * x_train[:, 1]
            + 1.0 * x_train[:, 2]
            + 16 * x_train[:, 3]
            + 10 * x_train[:, 4]
            > 70
        ).astype(int)
        if len(set(y_train.tolist())) < 2:
            return None
        model = LogisticRegression(max_iter=500)
        model.fit(x_train, y_train)
        return float(model.predict_proba(x)[0, 1])

    def final_score(
        self,
        tele_rows: List[dict],
        def_sum: Dict[str, Any],
        sys_sum: Dict[str, Any],
        baseline: Dict[str, float] | None = None,
    ) -> Dict[str, Any]:
        heuristic = self.heuristic(tele_rows, def_sum, sys_sum, baseline=baseline)
        # No true malicious indicator -> ML nudge suppressed entirely.
        # THE guard that keeps a clean production host at ~0 rather than
        # inheriting synthetic-model probability mass.
        if not heuristic.get("has_true_signal"):
            return heuristic
        ml = self.ml_component(tele_rows, def_sum, sys_sum)
        if ml is None:
            return heuristic
        blended = 0.30 * ml + 0.70 * heuristic["likelihood"]
        parts = dict(heuristic["parts"])
        parts["ml_component"] = ml
        return {
            "likelihood": max(0.0, min(1.0, blended)),
            "parts": parts,
            "notes": heuristic["notes"] + ["ML probability is corroborating only - gated on a true signal"],
            "has_true_signal": True,
        }
