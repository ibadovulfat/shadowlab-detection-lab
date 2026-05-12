"""Persistence detection + remediation routes."""
from __future__ import annotations

import json
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from api.schemas import PersistenceRemediationRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    validate_persistence_target = ctx["_validate_persistence_target"]
    request_workspace_id = ctx["_request_workspace_id"]
    db = ctx["db"]

    @app.get("/persistence", dependencies=[Depends(require_analyst_or_admin)])
    def persistence_items() -> list[dict[str, Any]]:
        import plugins.persistence as persistence_scanner

        return persistence_scanner.get_persistence_items()

    @app.post(
        "/persistence/remediate",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def remediate_persistence(request: Request, payload: PersistenceRemediationRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="persistence:remediate")
        import plugins.persistence as persistence_scanner

        validate_persistence_target(payload.item_type, payload.path, payload.name)
        result = persistence_scanner.remediate_persistence_item(payload.item_type, payload.path, payload.name)
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result.get("message", "Remediation failed"))
        conn = db.create_connection()
        if conn:
            try:
                remediation_id = db.log_remediation(
                    conn,
                    payload.item_type,
                    payload.path,
                    backup_path=result.get("backup_path", ""),
                    rollback_data=json.dumps(result.get("rollback_data", {})),
                    status="applied",
                    workspace_id=request_workspace_id(request),
                )
            finally:
                conn.close()
            result["remediation_id"] = remediation_id
        return result

    @app.post(
        "/persistence/rollback/{remediation_id}",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def rollback_persistence(request: Request, remediation_id: int) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="persistence:rollback")
        import plugins.persistence as persistence_scanner

        conn = db.create_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_remediations(conn, workspace_id=request_workspace_id(request))
            row = frame[frame["id"] == remediation_id]
            if row.empty:
                raise HTTPException(status_code=404, detail="Remediation record not found")
            item = row.iloc[0].to_dict()
            rollback_data = json.loads(item.get("rollback_data") or "{}")
            result = persistence_scanner.rollback_persistence_item(
                item.get("item_type", ""),
                item.get("target", ""),
                backup_path=item.get("backup_path", ""),
                rollback_data=rollback_data,
            )
            if not result.get("ok"):
                raise HTTPException(status_code=400, detail=result.get("message", "Rollback failed"))
            db.update_remediation_status(conn, remediation_id, "rolled_back", workspace_id=request_workspace_id(request))
            return {"status": "rolled_back", "remediation_id": remediation_id, "result": result}
        finally:
            conn.close()
