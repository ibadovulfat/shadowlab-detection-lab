"""Artifact listing / download / html-report routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    request_workspace_id = ctx["_request_workspace_id"]
    workspace_artifact_dir = ctx["_workspace_artifact_dir"]
    artifact_manifest = ctx["_artifact_manifest"]
    safe_child_path = ctx["safe_child_path"]
    safe_file_response = ctx["_safe_file_response"]

    @app.get("/artifacts", dependencies=[Depends(require_analyst_or_admin)])
    def list_artifacts(request: Request) -> dict[str, str]:
        return artifact_manifest(request_workspace_id(request))

    @app.get("/artifacts/{filename}", dependencies=[Depends(require_analyst_or_admin)])
    def download_artifact(request: Request, filename: str):
        target = safe_child_path(
            workspace_artifact_dir(request_workspace_id(request)),
            filename,
            allowed_suffixes={".csv", ".json", ".html", ".pdf"},
        )
        if not target.exists():
            raise HTTPException(status_code=404, detail="Artifact not found")
        return safe_file_response(target)

    @app.get("/reports/html", dependencies=[Depends(require_analyst_or_admin)])
    def html_report(request: Request):
        target = safe_child_path(
            workspace_artifact_dir(request_workspace_id(request)),
            "ShadowLab_Report.html",
            allowed_suffixes={".html"},
        )
        if not target.exists():
            raise HTTPException(status_code=404, detail="HTML report not found")
        return safe_file_response(target)
