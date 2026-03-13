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


class DetectionScorer(BaseDetectionScorer):
    def _extract_signals(self, def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, float]:
        def_by = def_sum.get("by_id", {}) if isinstance(def_sum, dict) else {}
        sys_by = sys_sum.get("by_id", {}) if isinstance(sys_sum, dict) else {}

        def value(mapping: Dict[str, Any], key: str) -> float:
            raw = mapping.get(key, 0)
            return float(raw) if isinstance(raw, (int, float)) else 0.0

        defender_signal = (
            value(def_by, "Malware detected (scan)")
            + value(def_by, "Malware detected (on-access)") * 1.5
            + value(def_by, "Remediation failed") * 1.5
        )
        sysmon_signal = (
            value(sys_by, "Network connection") * 1.0
            + value(sys_by, "DNS query") * 0.8
            + value(sys_by, "CreateRemoteThread") * 2.5
            + value(sys_by, "Registry add") * 0.7
            + value(sys_by, "Registry set") * 0.7
            + value(sys_by, "Process creation") * 0.1
        )
        return {
            "defender_total": float(def_sum.get("total", 0) or 0.0),
            "sysmon_total": float(sys_sum.get("total", 0) or 0.0),
            "defender_signal": defender_signal,
            "sysmon_signal": sysmon_signal,
            "sys_conn": value(sys_by, "Network connection"),
            "sys_dns": value(sys_by, "DNS query"),
        }

    def heuristic(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, Any]:
        if not tele_rows:
            return {"likelihood": 0.0, "parts": {}, "notes": ["no telemetry"]}

        avg_cpu = sum(float(r.get("cpu", 0.0)) for r in tele_rows) / len(tele_rows)
        avg_thr = sum(float(r.get("proc_threads", 0.0)) for r in tele_rows) / len(tele_rows)
        avg_tcp = sum(float(r.get("tcp_conns", 0.0)) for r in tele_rows) / len(tele_rows)
        avg_sent = sum(float(r.get("bytes_sent_rate", 0.0) or 0.0) for r in tele_rows) / len(tele_rows)
        signals = self._extract_signals(def_sum, sys_sum)

        parts: Dict[str, float] = {}
        notes: List[str] = []
        parts["cpu_activity"] = min(avg_cpu / 80.0, 1.0) * 0.14
        parts["threads"] = min(avg_thr / 80.0, 1.0) * 0.10
        parts["tcp_conns"] = min(avg_tcp / 20.0, 1.0) * 0.05
        parts["defender_events"] = min(signals["defender_signal"] / 3.0, 1.0) * 0.32
        parts["sys_activity"] = min(signals["sysmon_signal"] / 12.0, 1.0) * 0.22
        if avg_sent >= 50000 and avg_tcp >= 8:
            parts["egress_pattern"] = 0.10

        if avg_cpu > 45:
            notes.append(f"Elevated CPU: {avg_cpu:.1f}%")
        if avg_thr > 60:
            notes.append(f"High thread count: {avg_thr:.0f}")
        if avg_tcp > 12:
            notes.append(f"Multiple TCP connections: {avg_tcp:.0f}")
        if avg_sent >= 50000:
            notes.append(f"Elevated outbound throughput: {avg_sent:.0f} B/s")
        if signals["defender_signal"] >= 1:
            notes.append(f"Meaningful Defender detections: {signals['defender_signal']:.0f}")
        if (signals["sys_conn"] + signals["sys_dns"]) >= 8:
            notes.append(f"Elevated Sysmon net/dns: {(signals['sys_conn'] + signals['sys_dns']):.0f}")

        likelihood = max(0.0, min(1.0, sum(parts.values())))
        return {"likelihood": likelihood, "parts": parts, "notes": notes}

    def ml_component(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Optional[float]:
        if not (LogisticRegression and np and tele_rows):
            return None

        avg_cpu = sum(float(r.get("cpu", 0.0)) for r in tele_rows) / len(tele_rows)
        avg_thr = sum(float(r.get("proc_threads", 0.0)) for r in tele_rows) / len(tele_rows)
        avg_tcp = sum(float(r.get("tcp_conns", 0.0)) for r in tele_rows) / len(tele_rows)
        signals = self._extract_signals(def_sum, sys_sum)

        x = np.array(
            [[avg_cpu, avg_thr, avg_tcp, signals["defender_signal"], signals["sys_conn"], signals["sys_dns"]]],
            dtype=float,
        )

        rng = np.random.default_rng(0)
        x_train = rng.normal(loc=[12, 14, 1, 0, 0, 0], scale=[6, 8, 1, 0.8, 1.2, 1.0], size=(200, 6))
        y_train = (
            x_train[:, 0]
            + 0.3 * x_train[:, 1]
            + 1.5 * x_train[:, 2]
            + 14 * x_train[:, 3]
            + 3 * x_train[:, 4]
            + 2 * x_train[:, 5]
            > 60
        ).astype(int)
        if len(set(y_train.tolist())) < 2:
            return None

        model = LogisticRegression(max_iter=500)
        model.fit(x_train, y_train)
        probability = float(model.predict_proba(x)[0, 1])
        if signals["defender_signal"] <= 0 and signals["sys_conn"] <= 0 and signals["sys_dns"] <= 0:
            probability = min(probability, 0.62)
        return probability

    def final_score(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, Any]:
        heuristic = self.heuristic(tele_rows, def_sum, sys_sum)
        ml = self.ml_component(tele_rows, def_sum, sys_sum)
        if ml is None:
            return heuristic

        blended = 0.35 * ml + 0.65 * heuristic["likelihood"]
        parts = dict(heuristic["parts"])
        parts["ml_component"] = ml
        return {
            "likelihood": max(0.0, min(1.0, blended)),
            "parts": parts,
            "notes": heuristic["notes"] + ["ML probability is illustrative - not a real detector"],
        }
