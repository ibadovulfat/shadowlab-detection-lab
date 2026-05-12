"""Artifact listing + safe download helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from fastapi.responses import FileResponse


#: Fixed catalog of artifact filenames the manifest endpoint surfaces.
ARTIFACT_FILENAMES: tuple[str, ...] = (
    "telemetry.csv",
    "events_defender.json",
    "events_sysmon.json",
    "score.json",
    "incident_bundle.json",
    "ShadowLab_Report.pdf",
    "ShadowLab_Report.html",
    "ShadowLab_EntityGraph.html",
    "ShadowLab_EntityGraph.json",
    "integrity_manifest.json",
    "SecurityOps_Report.json",
    "SecurityOps_Report.html",
    "Antivirus_Detection_Report.json",
    "Antivirus_Detection_Report.html",
    "Antivirus_Quarantine_Report.json",
    "Antivirus_Quarantine_Report.html",
    "observability.jsonl",
    "postgres_bootstrap.sql",
)


def artifact_manifest(
    workspace_artifact_dir: Callable[[str], Path],
    workspace_id: str = "default",
) -> dict[str, str]:
    """Return a `{filename: absolute_path}` map for artifacts that exist on disk."""
    target_dir = workspace_artifact_dir(workspace_id)
    return {
        name: str(target_dir / name)
        for name in ARTIFACT_FILENAMES
        if (target_dir / name).exists()
    }


def safe_file_response(target: Path, *, filename: str | None = None) -> FileResponse:
    """Wrap FileResponse with hardening for HTML payloads.

    HTML artifacts are forced to download rather than render inline to avoid
    any rogue payload in a report being executed when the operator opens the
    URL directly in a browser.
    """
    response = FileResponse(target, filename=filename or target.name)
    if target.suffix.lower() == ".html":
        response.headers["Content-Disposition"] = f'attachment; filename="{filename or target.name}"'
        response.headers["X-Download-Options"] = "noopen"
    return response
