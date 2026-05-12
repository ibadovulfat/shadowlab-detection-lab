"""Persistence-inventory validation helpers."""
from __future__ import annotations

from fastapi import HTTPException


def validate_persistence_target(item_type: str, path: str, name: str) -> None:
    """Ensure `(type, path, name)` still matches a live persistence-inventory row.

    Prevents accidental deletion/remediation of a stale reference when the
    registry/scheduled-task has changed between enumeration and action.
    """
    import plugins.persistence as persistence_scanner

    candidates = persistence_scanner.get_persistence_items_fast()
    normalized_type = (item_type or "").strip().lower()
    normalized_path = (path or "").strip().lower()
    normalized_name = (name or "").strip().lower()
    for item in candidates:
        item_type_value = str(item.get("type", "")).strip().lower()
        item_path_value = str(item.get("path", "")).strip().lower()
        item_name_value = str(item.get("name", "")).strip().lower()
        if item_type_value != normalized_type or item_path_value != normalized_path:
            continue
        if normalized_name and item_name_value != normalized_name:
            continue
        return
    raise HTTPException(status_code=400, detail="Persistence target no longer matches current inventory")
