
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

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
    def heuristic(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, Any]:
        if not tele_rows:
            return {"likelihood": 0.0, "parts": {}, "notes": ["no telemetry"]}
        avg_cpu = sum(r["cpu"] for r in tele_rows) / len(tele_rows)
        avg_thr = sum(r["proc_threads"] for r in tele_rows) / len(tele_rows)
        avg_tcp = sum(r["tcp_conns"] for r in tele_rows) / len(tele_rows)
        d_total = int(def_sum.get("total", 0))
        sys_by = sys_sum.get("by_id", {}) if isinstance(sys_sum, dict) else {}
        sys_conn = int(sys_by.get("Network connection", 0)) if isinstance(sys_by.get("Network connection", 0), int) else 0
        sys_dns  = int(sys_by.get("DNS query", 0)) if isinstance(sys_by.get("DNS query", 0), int) else 0

        parts = {}
        notes = []
        parts["cpu_activity"] = min(avg_cpu/50.0, 1.0) * 0.25
        parts["threads"] = min(avg_thr/50.0, 1.0) * 0.15
        parts["tcp_conns"] = min(avg_tcp/10.0, 1.0) * 0.10
        parts["defender_events"] = min(d_total/10.0, 1.0) * 0.30
        parts["sys_activity"] = min((sys_conn+sys_dns)/20.0, 1.0) * 0.20

        if avg_cpu > 30: notes.append(f"Elevated CPU: {avg_cpu:.1f}%")
        if avg_thr > 40: notes.append(f"High thread count: {avg_thr:.0f}")
        if avg_tcp > 5: notes.append(f"Multiple TCP connections: {avg_tcp:.0f}")
        if d_total: notes.append(f"Defender events observed: {d_total}")
        if (sys_conn+sys_dns) > 0: notes.append(f"Sysmon net/dns: {sys_conn+sys_dns}")

        likelihood = sum(parts.values())
        likelihood = max(0.0, min(1.0, likelihood))
        return {"likelihood": likelihood, "parts": parts, "notes": notes}

    def ml_component(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Optional[float]:
        if not (LogisticRegression and np and tele_rows):
            return None
        avg_cpu = sum(r["cpu"] for r in tele_rows) / len(tele_rows)
        avg_thr = sum(r["proc_threads"] for r in tele_rows) / len(tele_rows)
        avg_tcp = sum(r["tcp_conns"] for r in tele_rows) / len(tele_rows)
        d_total = float(def_sum.get("total", 0))
        sys_by = sys_sum.get("by_id", {}) if isinstance(sys_sum, dict) else {}
        sys_net = float(sys_by.get("Network connection", 0)) if isinstance(sys_by.get("Network connection", 0), int) else 0.0
        sys_dns = float(sys_by.get("DNS query", 0)) if isinstance(sys_by.get("DNS query", 0), int) else 0.0
        X = np.array([[avg_cpu, avg_thr, avg_tcp, d_total, sys_net, sys_dns]], dtype=float)

        rng = np.random.default_rng(0)
        X_train = rng.normal(loc=[10,10,1,0,0,0], scale=[5,5,1,1,1,1], size=(200,6))
        y_train = (X_train[:,0] + 0.5*X_train[:,1] + 5*X_train[:,2] + 10*X_train[:,3] + 2*X_train[:,4] + 2*X_train[:,5] > 40).astype(int)

        model = LogisticRegression(max_iter=500)
        model.fit(X_train, y_train)
        prob = float(model.predict_proba(X)[0,1])
        return prob

    def final_score(self, tele_rows: List[dict], def_sum: Dict[str, Any], sys_sum: Dict[str, Any]) -> Dict[str, Any]:
        h = self.heuristic(tele_rows, def_sum, sys_sum)
        ml = self.ml_component(tele_rows, def_sum, sys_sum)
        if ml is None:
            return h
        blended = 0.6*ml + 0.4*h["likelihood"]
        parts = dict(h["parts"])
        parts["ml_component"] = ml
        return {"likelihood": max(0.0, min(1.0, blended)), "parts": parts, "notes": h["notes"] + ["ML probability is illustrative — not a real detector"]}
