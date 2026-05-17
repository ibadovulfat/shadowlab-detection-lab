"""Historical telemetry/audit, incident read/patch routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request

from api.schemas import IncidentUpdateRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    db = ctx["db"]
    request_workspace_id = ctx["_request_workspace_id"]
    require_default_workspace_for_global_scope = ctx["_require_default_workspace_for_global_scope"]
    build_auth_anomalies = ctx["_build_auth_anomalies"]

    @app.get("/history/telemetry", dependencies=[Depends(require_analyst_or_admin)])
    def telemetry_history(request: Request, limit: int | None = Query(default=None, ge=1, le=5000)) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            history_df = db.get_historical_data(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        if limit is not None:
            history_df = history_df.head(limit)
        return history_df.to_dict(orient="records")

    @app.get("/history/responses", dependencies=[Depends(require_analyst_or_admin)])
    def response_history(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            response_df = db.get_response_logs(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return response_df.to_dict(orient="records")

    @app.get("/incidents", dependencies=[Depends(require_analyst_or_admin)])
    def incidents(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_incidents(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        workspace_id = request_workspace_id(request)
        return [item for item in frame.to_dict(orient="records") if str(item.get("workspace_id", "default")) == workspace_id]

    @app.get("/history/alerts", dependencies=[Depends(require_analyst_or_admin)])
    def alert_history(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_alerts(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.to_dict(orient="records")

    @app.get("/history/remediations", dependencies=[Depends(require_analyst_or_admin)])
    def remediation_history(request: Request) -> list[dict[str, Any]]:
        require_default_workspace_for_global_scope(request, "Remediation history")
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_remediations(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.to_dict(orient="records")

    @app.get("/history/auth", dependencies=[Depends(require_admin)])
    def auth_history(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_auth_logs(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.to_dict(orient="records")

    @app.get("/history/actions", dependencies=[Depends(require_admin)])
    def action_history(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_action_audits(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.to_dict(orient="records")

    @app.get("/history/external", dependencies=[Depends(require_admin)])
    def external_request_history(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_external_requests(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.to_dict(orient="records")

    @app.get("/history/auth/anomalies", dependencies=[Depends(require_admin)])
    def auth_anomalies(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            auth_rows = db.get_auth_logs(conn, workspace_id=request_workspace_id(request)).fillna("").to_dict(orient="records")
            action_rows = db.get_action_audits(conn, workspace_id=request_workspace_id(request)).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return build_auth_anomalies(auth_rows, action_rows)

    @app.patch("/incidents/{incident_id}", dependencies=[Depends(require_analyst_or_admin)])
    def update_incident(incident_id: str, payload: IncidentUpdateRequest) -> dict[str, str]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            db.update_incident(conn, incident_id, status=payload.status, notes=payload.notes, owner=payload.owner)
        finally:
            conn.close()
        return {"status": "updated", "incident_id": incident_id}
