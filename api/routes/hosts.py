"""Host inventory + agent registration routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from api.schemas import AgentRegistrationRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    db = ctx["db"]
    fleet_service = ctx["fleet_service"]
    request_workspace_id = ctx["_request_workspace_id"]

    @app.get("/hosts", dependencies=[Depends(require_analyst_or_admin)])
    def hosts(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            return fleet_service.list_hosts(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()

    @app.post("/agents/register", dependencies=[Depends(require_admin)])
    def register_agent(request: Request, payload: AgentRegistrationRequest) -> dict[str, Any]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            return fleet_service.register_agent(conn, payload.model_dump(), workspace_id=request_workspace_id(request))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        finally:
            conn.close()
