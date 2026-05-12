"""Evidence capture + listing + delete routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from api.schemas import EvidenceRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    ensure_delete_enabled = ctx["ensure_delete_enabled"]
    integrity_service = ctx["integrity_service"]
    request_workspace_id = ctx["_request_workspace_id"]
    safe_child_path = ctx["safe_child_path"]
    BASE_DIR = ctx["BASE_DIR"]

    @app.post("/evidence/capture", dependencies=[Depends(require_analyst_or_admin)])
    def capture_evidence(request: Request, payload: EvidenceRequest) -> dict[str, Any]:
        import plugins.evidence as evidence

        collector = evidence.EvidenceCollector()
        path = collector.capture_screenshot(payload.alert_name)
        if str(path).startswith("Error"):
            raise HTTPException(status_code=500, detail=str(path))
        integrity_service.refresh_manifest(workspace_id=request_workspace_id(request))
        return {"status": "captured", "path": path}

    @app.get("/evidence", dependencies=[Depends(require_analyst_or_admin)])
    def list_evidence() -> dict[str, Any]:
        import plugins.evidence as evidence

        collector = evidence.EvidenceCollector()
        return {"items": collector.list_evidence()}

    @app.delete(
        "/evidence/{filename}",
        dependencies=[
            Depends(require_admin),
            Depends(ensure_dangerous_actions_enabled),
            Depends(ensure_delete_enabled),
        ],
    )
    def delete_evidence(filename: str) -> dict[str, str]:
        target = safe_child_path(BASE_DIR / "evidence_locker", filename, allowed_suffixes={".png", ".jpg", ".jpeg", ".webp"})
        if not target.exists():
            raise HTTPException(status_code=404, detail="Evidence file not found")
        target.unlink()
        integrity_service.refresh_manifest()
        return {"status": "deleted", "path": str(target)}
