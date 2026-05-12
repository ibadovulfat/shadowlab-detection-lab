"""Quarantine read / restore / delete routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    ensure_delete_enabled = ctx["ensure_delete_enabled"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    validate_quarantine_restore_paths = ctx["_validate_quarantine_restore_paths"]
    validate_quarantine_file_path = ctx["_validate_quarantine_file_path"]
    request_workspace_id = ctx["_request_workspace_id"]
    db = ctx["db"]
    integrity_service = ctx["integrity_service"]

    @app.get("/quarantine", dependencies=[Depends(require_analyst_or_admin)])
    def quarantine_items(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_quarantine(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.to_dict(orient="records")

    @app.post(
        "/quarantine/{quarantine_id}/restore",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def restore_quarantine(request: Request, quarantine_id: int) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="quarantine:restore")
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_quarantine(conn, workspace_id=request_workspace_id(request))
            row = frame[frame["id"] == quarantine_id]
            if row.empty:
                raise HTTPException(status_code=404, detail="Quarantine record not found")
            item = row.iloc[0].to_dict()
            source, target = validate_quarantine_restore_paths(item["quarantine_path"], item["original_path"])
            if not source.exists():
                raise HTTPException(status_code=404, detail="Quarantine artifact not found")
            if target.exists():
                raise HTTPException(status_code=409, detail="Original path already exists; refusing to overwrite during restore")
            target.parent.mkdir(parents=True, exist_ok=True)
            source.replace(target)
            db.update_quarantine(conn, quarantine_id, "restored", workspace_id=request_workspace_id(request))
            integrity_service.refresh_manifest()
            return {"status": "restored", "path": str(target)}
        finally:
            conn.close()

    @app.delete(
        "/quarantine/{quarantine_id}",
        dependencies=[
            Depends(require_admin),
            Depends(ensure_dangerous_actions_enabled),
            Depends(ensure_delete_enabled),
        ],
    )
    def delete_quarantine(request: Request, quarantine_id: int) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="quarantine:delete")
        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_quarantine(conn, workspace_id=request_workspace_id(request))
            row = frame[frame["id"] == quarantine_id]
            if row.empty:
                raise HTTPException(status_code=404, detail="Quarantine record not found")
            item = row.iloc[0].to_dict()
            target = validate_quarantine_file_path(item["quarantine_path"])
            if target.exists():
                target.unlink()
            db.update_quarantine(conn, quarantine_id, "deleted", workspace_id=request_workspace_id(request))
            integrity_service.refresh_manifest()
            return {"status": "deleted", "path": str(target)}
        finally:
            conn.close()
