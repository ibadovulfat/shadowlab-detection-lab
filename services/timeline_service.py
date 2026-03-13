from __future__ import annotations

from collections import Counter
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
            items.append(
                {
                    "time": row.get("ts"),
                    "type": "telemetry",
                    "severity": self._telemetry_severity(row),
                    "title": f"CPU {row.get('cpu', 0):.1f}% | MEM {row.get('mem_percent', 0):.1f}%",
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

        items.sort(key=lambda item: float(item.get("time") or 0.0), reverse=True)
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

    def _telemetry_severity(self, row: dict[str, Any]) -> str:
        cpu = float(row.get("cpu", 0.0) or 0.0)
        tcp = float(row.get("tcp_conns", 0.0) or 0.0)
        if cpu >= 90 or tcp >= 20:
            return "high"
        if cpu >= 70 or tcp >= 10:
            return "medium"
        return "low"
