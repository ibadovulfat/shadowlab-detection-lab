"""Graph / entity-map routes."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    db = ctx["db"]
    fleet_service = ctx["fleet_service"]
    process_intel_service = ctx["process_intel_service"]
    monitor_core = ctx["monitor_core"]
    graph_service = ctx["graph_service"]
    request_workspace_id = ctx["_request_workspace_id"]
    safe_child_path = ctx["safe_child_path"]
    safe_file_response = ctx["_safe_file_response"]
    OUT_DIR = ctx["OUT_DIR"]

    @app.get("/graph/entity-map", dependencies=[Depends(require_analyst_or_admin)])
    def entity_map(request: Request, pid: int | None = None) -> dict[str, Any]:
        conn = db.create_connection()
        incidents: list[dict[str, Any]] = []
        hosts_data: list[dict[str, Any]] = []
        if conn:
            try:
                workspace_id = request_workspace_id(request)
                incidents = db.get_incidents(conn, workspace_id=workspace_id).to_dict(orient="records")
                hosts_data = fleet_service.list_hosts(conn, workspace_id=workspace_id)
            finally:
                conn.close()
        processes = process_intel_service.snapshot_processes(include_deep_fields=False)
        connections = monitor_core.get_network_connections()
        try:
            import plugins.persistence as persistence_scanner

            persistence_items = persistence_scanner.get_persistence_items_fast()
        except Exception:
            persistence_items = []
        return graph_service.build_entity_graph(
            hosts=hosts_data,
            processes=processes,
            connections=connections,
            incidents=incidents,
            persistence_items=persistence_items,
            pid=pid,
        )

    @app.get("/graph/entity-map/html", dependencies=[Depends(require_analyst_or_admin)])
    def entity_map_html(request: Request, pid: int | None = None):
        graph = entity_map(request, pid=pid)
        target = safe_child_path(OUT_DIR, Path(graph["html_path"]).name, allowed_suffixes={".html"})
        if not target.exists():
            raise HTTPException(status_code=404, detail="Graph HTML not found")
        return safe_file_response(target)
