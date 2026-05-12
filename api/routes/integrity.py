"""Integrity manifest + observability summary routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    integrity_service = ctx["integrity_service"]
    observability_service = ctx["observability_service"]
    request_workspace_id = ctx["_request_workspace_id"]
    apply_rate_limit = ctx["_apply_rate_limit"]

    @app.get("/integrity", dependencies=[Depends(require_analyst_or_admin)])
    def verify_integrity(request: Request) -> dict[str, Any]:
        observability_service.log_event("integrity_verify_requested")
        return integrity_service.verify_manifest(workspace_id=request_workspace_id(request))

    @app.get("/integrity/history", dependencies=[Depends(require_admin)])
    def integrity_history(request: Request) -> list[dict[str, Any]]:
        return integrity_service.history(workspace_id=request_workspace_id(request))

    @app.post("/integrity/refresh", dependencies=[Depends(require_admin)])
    def refresh_integrity_manifest(request: Request) -> dict[str, Any]:
        apply_rate_limit(request, bucket="integrity_refresh", detail="Too many integrity refresh requests. Wait briefly and retry.")
        manifest = integrity_service.refresh_manifest(workspace_id=request_workspace_id(request))
        observability_service.log_event("integrity_manifest_refreshed", file_count=len(manifest.get("files", {})))
        return {
            "status": "refreshed",
            "manifest_path": manifest.get("manifest_path", ""),
            "file_count": len(manifest.get("files", {})),
            "generated_at": manifest.get("generated_at", 0),
        }

    @app.get("/observability/summary", dependencies=[Depends(require_admin)])
    def observability_summary() -> dict[str, Any]:
        return observability_service.summary()
