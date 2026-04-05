from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


class TimelineService:
    def build(
        self,
        telemetry_rows: list[dict[str, Any]] | None = None,
        response_rows: list[dict[str, Any]] | None = None,
        incident_rows: list[dict[str, Any]] | None = None,
        alert_rows: list[dict[str, Any]] | None = None,
        remediation_rows: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        for row in telemetry_rows or []:
            cpu_value = self._float_value(row.get("cpu"))
            mem_value = self._float_value(row.get("mem_percent"))
            items.append(
                {
                    "time": row.get("ts"),
                    "type": "telemetry",
                    "severity": self._telemetry_severity(row),
                    "title": f"CPU {cpu_value:.1f}% | MEM {mem_value:.1f}%",
                    "details": row,
                }
            )
        for row in response_rows or []:
            items.append(
                {
                    "time": row.get("timestamp"),
                    "type": "response",
                    "severity": "medium",
                    "title": f"{row.get('action', 'response')} on PID {row.get('pid', 'n/a')}",
                    "details": row,
                }
            )
        for row in incident_rows or []:
            items.append(
                {
                    "time": row.get("created_at"),
                    "type": "incident",
                    "severity": row.get("severity", "medium"),
                    "title": row.get("title", "Behavioral detection incident"),
                    "details": row,
                }
            )
        for row in alert_rows or []:
            items.append(
                {
                    "time": row.get("created_at"),
                    "type": "alert",
                    "severity": row.get("severity", "medium"),
                    "title": f"Alert to {row.get('destination_type', 'destination')}",
                    "details": row,
                }
            )
        for row in remediation_rows or []:
            items.append(
                {
                    "time": row.get("created_at"),
                    "type": "remediation",
                    "severity": "high" if row.get("status") == "rolled_back" else "medium",
                    "title": row.get("target", "Persistence remediation"),
                    "details": row,
                }
            )

        items.sort(key=lambda item: self._time_value(item.get("time")), reverse=True)
        return items

    def build_graph(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        previous_id: str | None = None
        severity_counter = Counter()

        for idx, item in enumerate(reversed(items[-50:]), start=1):
            node_id = f"event-{idx}"
            severity = item.get("severity", "low")
            severity_counter[severity] += 1
            nodes.append(
                {
                    "id": node_id,
                    "label": item.get("title", item.get("type", "event")),
                    "group": item.get("type", "event"),
                    "severity": severity,
                }
            )
            if previous_id:
                edges.append({"from": previous_id, "to": node_id})
            previous_id = node_id

        summary = {
            "total_events": len(items),
            "by_severity": dict(severity_counter),
            "latest_event": items[0]["title"] if items else "",
        }
        return {"nodes": nodes, "edges": edges, "summary": summary}

    def filter_items(
        self,
        items: list[dict[str, Any]],
        *,
        query_text: str = "",
        event_types: list[str] | None = None,
        severities: list[str] | None = None,
        start_time: float | None = None,
        end_time: float | None = None,
        limit: int = 150,
    ) -> list[dict[str, Any]]:
        normalized_query = (query_text or "").strip().lower()
        allowed_types = {str(value).strip().lower() for value in (event_types or []) if str(value).strip()}
        allowed_severities = {str(value).strip().lower() for value in (severities or []) if str(value).strip()}
        bounded_limit = max(1, min(int(limit), 500))

        filtered: list[dict[str, Any]] = []
        for item in items:
            item_time = self._time_value(item.get("time"))
            item_type = str(item.get("type", "") or "").lower()
            item_severity = str(item.get("severity", "") or "").lower()
            if allowed_types and item_type not in allowed_types:
                continue
            if allowed_severities and item_severity not in allowed_severities:
                continue
            if start_time is not None and item_time < float(start_time):
                continue
            if end_time is not None and item_time > float(end_time):
                continue
            if normalized_query and normalized_query not in self._search_blob(item):
                continue
            filtered.append(item)
            if len(filtered) >= bounded_limit:
                break
        return filtered

    def _float_value(self, value: Any) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0.0

    def build_summary(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        by_type = Counter(str(item.get("type", "unknown") or "unknown") for item in items)
        by_severity = Counter(str(item.get("severity", "unknown") or "unknown") for item in items)
        return {
            "total_events": len(items),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "latest_event": items[0].get("title", "") if items else "",
            "high_severity_titles": [item.get("title", "") for item in items if item.get("severity") == "high"][:5],
        }

    def _telemetry_severity(self, row: dict[str, Any]) -> str:
        cpu = float(row.get("cpu", 0.0) or 0.0)
        tcp = float(row.get("tcp_conns", 0.0) or 0.0)
        if cpu >= 90 or tcp >= 20:
            return "high"
        if cpu >= 70 or tcp >= 10:
            return "medium"
        return "low"

    def _search_blob(self, item: dict[str, Any]) -> str:
        parts = [
            str(item.get("title", "") or ""),
            str(item.get("type", "") or ""),
            str(item.get("severity", "") or ""),
            str(item.get("details", {}) or ""),
        ]
        return " ".join(parts).lower()

    def _time_value(self, raw: Any) -> float:
        if raw in (None, ""):
            return 0.0
        if isinstance(raw, (int, float)):
            return float(raw)
        candidate = str(raw).strip()
        if not candidate:
            return 0.0
        try:
            return float(candidate)
        except ValueError:
            pass
        for parser in (lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")), datetime.fromisoformat):
            try:
                return parser(candidate).timestamp()
            except ValueError:
                continue
        return 0.0
