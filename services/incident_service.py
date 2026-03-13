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
        incident_data = incident.to_dict()
        payload = {
            "incident": incident_data,
            "score": final_score,
            "telemetry_preview": telemetry_rows[-25:],
            "incident_id": incident_data.get("incident_id", ""),
            "created_at": incident_data.get("created_at", 0),
            "severity": incident_data.get("severity", "unknown"),
            "title": incident_data.get("title", ""),
            "summary": incident_data.get("summary", ""),
            "likelihood": incident_data.get("likelihood", 0.0),
            "findings": incident_data.get("findings", []),
            "notes": incident_data.get("notes", []),
            "recommended_actions": incident_data.get("recommended_actions", []),
            "telemetry_count": incident_data.get("telemetry_count", 0),
            "attack_chain": incident_data.get("attack_chain", []),
            "mitre_techniques": incident_data.get("mitre_techniques", []),
            "correlation_story": incident_data.get("correlation_story", ""),
        }
        incident_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return incident_path

