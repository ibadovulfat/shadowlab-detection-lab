from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import Depends, Request
from fastapi.responses import StreamingResponse


def register_routes(app, ctx: dict[str, Any]) -> None:
    db = ctx["db"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    timeline_service = ctx["timeline_service"]
    request_workspace_id = ctx["_request_workspace_id"]

    def _build_timeline_for(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            return []
        try:
            workspace_id = request_workspace_id(request)
            return timeline_service.build(
                telemetry_rows=db.get_historical_data(conn, workspace_id=workspace_id).to_dict(orient="records")[-100:],
                response_rows=db.get_response_logs(conn, workspace_id=workspace_id).to_dict(orient="records")[:100],
                incident_rows=db.get_incidents(conn, workspace_id=workspace_id).to_dict(orient="records")[:100],
                alert_rows=db.get_alerts(conn, workspace_id=workspace_id).to_dict(orient="records")[:100],
                remediation_rows=db.get_remediations(conn, workspace_id=workspace_id).to_dict(orient="records")[:100],
            )
        finally:
            conn.close()

    @app.get("/timeline", dependencies=[Depends(require_analyst_or_admin)])
    def timeline(request: Request) -> list[dict[str, Any]]:
        return _build_timeline_for(request)

    @app.get("/timeline/graph", dependencies=[Depends(require_analyst_or_admin)])
    def timeline_graph(request: Request) -> dict[str, Any]:
        items = _build_timeline_for(request)
        return timeline_service.build_graph(items)

    @app.get("/timeline/stream", dependencies=[Depends(require_analyst_or_admin)])
    async def timeline_stream(request: Request, interval: int = 5):
        """Server-Sent Events feed for the live investigation timeline.

        The stream emits a JSON payload of new events whenever the
        backing tables show new rows compared to the last cursor. The
        client (desktop Timeline tab) opens an EventSource-like
        connection and merges the payload into its in-memory event
        list, eliminating the manual `Refresh All` click during an
        active SOC shift.

        `interval` is the poll cadence in seconds (3-30 range). Smaller
        values mean tighter latency at the cost of more DB round-trips;
        5s matches the default refresh cadence the Antivirus tab
        already uses.

        Pre-loaded events go out as a single `init` event so the
        client has a complete baseline without needing to call
        `/timeline` separately.
        """
        poll_interval = max(3, min(30, int(interval)))

        def _identity(item: dict[str, Any]) -> tuple[str, str, str]:
            return (
                str(item.get("time", "")),
                str(item.get("type", "")),
                str(item.get("title", "")),
            )

        async def event_generator():
            seen: set[tuple[str, str, str]] = set()
            # Initial snapshot - send everything currently in the tables
            # so the client doesn't need a separate /timeline call.
            try:
                initial = _build_timeline_for(request)
            except Exception as exc:
                yield f"event: error\ndata: {json.dumps({'error': str(exc)})}\n\n"
                return
            for item in initial:
                seen.add(_identity(item))
            yield f"event: init\ndata: {json.dumps(initial)}\n\n"

            # Streaming loop - poll every `poll_interval` seconds; emit
            # only the delta. Heartbeat comments keep proxies happy
            # during quiet windows.
            heartbeat_every = 30  # seconds
            elapsed_quiet = 0
            while True:
                if await request.is_disconnected():
                    return
                await asyncio.sleep(poll_interval)
                try:
                    current = _build_timeline_for(request)
                except Exception:
                    # Transient DB error - keep the connection alive,
                    # try again on the next tick.
                    yield ": db-error retry\n\n"
                    continue
                new_items = [it for it in current if _identity(it) not in seen]
                if new_items:
                    for it in new_items:
                        seen.add(_identity(it))
                    yield f"event: delta\ndata: {json.dumps(new_items)}\n\n"
                    elapsed_quiet = 0
                else:
                    elapsed_quiet += poll_interval
                    if elapsed_quiet >= heartbeat_every:
                        yield ": heartbeat\n\n"
                        elapsed_quiet = 0

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

