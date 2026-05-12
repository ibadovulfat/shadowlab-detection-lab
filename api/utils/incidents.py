"""Incident row normalization for API responses."""
from __future__ import annotations

import json
from typing import Any


def normalize_incident_row(incident: dict[str, Any]) -> dict[str, Any]:
    """Expand JSON-encoded columns and newline-delimited notes into real types.

    The database stores list/dict columns as JSON strings for portability; the
    API must surface them as proper JSON arrays so the desktop UI doesn't have
    to double-parse.
    """
    normalized = dict(incident)
    for key in ("recommended_actions", "attack_chain", "mitre_mapping"):
        value = normalized.get(key, "")
        if isinstance(value, str):
            try:
                normalized[key] = json.loads(value) if value else []
            except json.JSONDecodeError:
                normalized[key] = [value] if value else []
    notes = normalized.get("notes", "")
    if isinstance(notes, str):
        normalized["notes"] = [line for line in notes.splitlines() if line]
    normalized["mitre_techniques"] = normalized.get("mitre_mapping", [])
    return normalized
