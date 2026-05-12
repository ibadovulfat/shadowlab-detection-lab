"""Telemetry-collector export audit logging helpers.

Every time the OTLP forwarder ships telemetry to a downstream collector we
write an `integration_export` row so operators can audit the fabric without
reading collector logs. These helpers centralize the DB write so routes
don't have to re-plumb the bridge + connection each time.
"""
from __future__ import annotations

from typing import Any

import database as db


def log_single_collector_export(
    collector_bridge: Any,
    export_type: str,
    export_result: dict[str, Any],
    incident_id: str = "",
    workspace_id: str = "default",
) -> None:
    """Persist a single collector export result to `integration_exports`."""
    conn = db.create_connection()
    if conn is None:
        return
    try:
        target = (
            export_result.get("endpoint")
            or export_result.get("target")
            or collector_bridge.collector_status().get("otlp_http_endpoint", "")
        )
        if incident_id:
            target = f"{target} incident={incident_id}".strip()
        db.log_integration_export(
            conn,
            "shadowlab-telemetry-fabric",
            export_type,
            str(target),
            str(export_result.get("status", "unknown")),
            str(export_result.get("detail", "")),
            workspace_id=workspace_id,
        )
    finally:
        conn.close()


def log_collector_exports(
    collector_bridge: Any,
    result: dict[str, Any],
    workspace_id: str = "default",
) -> None:
    """Iterate `result["exports"]` and log each entry via `log_single_collector_export`."""
    for export_type, export_result in (result.get("exports") or {}).items():
        log_single_collector_export(
            collector_bridge,
            export_type,
            export_result,
            workspace_id=workspace_id,
        )
