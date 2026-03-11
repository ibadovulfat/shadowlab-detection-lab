from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import IncidentRecord


class IncidentArtifactService:
    def __init__(self, out_dir: str | Path):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(exist_ok=True, parents=True)

    def write_incident_bundle(
        self,
        incident: IncidentRecord,
        final_score: dict[str, Any],
        telemetry_rows: list[dict[str, Any]],
    ) -> Path:
        incident_path = self.out_dir / "incident_bundle.json"
        payload = {
            "incident": incident.to_dict(),
            "score": final_score,
            "telemetry_preview": telemetry_rows[-25:],
        }
        incident_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return incident_path

