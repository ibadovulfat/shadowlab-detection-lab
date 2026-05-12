"""Operator-managed exclusion / blocklist / allowlist surface.

Three orthogonal lists, one storage mechanism:
  * **exclusions** — paths or hashes to *skip* during fused scans
    entirely. Useful for known-good binaries that trip a heuristic
    every scan (vendor signing tools, build artefacts, etc.).
  * **blocklist** — known-bad hashes that should *auto-quarantine* on
    first sight, regardless of provider verdict. Lets analysts
    pre-empt a rolling campaign without waiting for cloud intel to
    catch up.
  * **allowlist** — known-good hashes that bypass cloud feeds (saves
    API quota and analyst review time).

Each list is stored as a JSON array under `app_settings`
(`antivirus_list_<kind>`), so persistence and migration are free. Each
entry carries `value`, `kind` (hash/path), `actor`, `added_at`,
`note` — enough metadata to pass an audit.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any


VALID_KINDS = frozenset({"exclusions", "blocklist", "allowlist"})
ENTRY_TYPES = frozenset({"hash", "path"})

APP_SETTING_PREFIX = "antivirus_list_"

_HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")  # MD5/SHA1/SHA256


def _classify_value(value: str) -> str:
    """Heuristic — hash vs. path. Anything matching MD5/SHA1/SHA256 is a
    hash; everything else is treated as a path entry."""
    if _HASH_PATTERN.match(str(value or "").strip()):
        return "hash"
    return "path"


class AntivirusListStore:
    """JSON-array backed list manager keyed in `app_settings`."""

    def __init__(self, db: Any):
        self._db = db

    def get(self, kind: str) -> list[dict[str, Any]]:
        kind = self._validate_kind(kind)
        if kind is None or self._db is None:
            return []
        try:
            conn = self._db.create_connection()
        except Exception:
            return []
        if conn is None:
            return []
        try:
            raw = self._db.get_app_setting(conn, APP_SETTING_PREFIX + kind) or "[]"
        except Exception:
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def set(self, kind: str, items: list[dict[str, Any]], *, actor: str = "") -> dict[str, Any]:
        kind = self._validate_kind(kind)
        if kind is None:
            return {"ok": False, "reason": "invalid_kind"}
        cleaned = self._clean(items, default_actor=actor)
        if self._db is None:
            return {"ok": False, "reason": "no_db"}
        try:
            conn = self._db.create_connection()
        except Exception:
            return {"ok": False, "reason": "db_connect_failed"}
        if conn is None:
            return {"ok": False, "reason": "db_unavailable"}
        try:
            self._db.set_app_setting(conn, APP_SETTING_PREFIX + kind, json.dumps(cleaned, ensure_ascii=False))
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return {"ok": True, "kind": kind, "count": len(cleaned), "items": cleaned}

    def add_entry(self, kind: str, value: str, *, note: str = "", actor: str = "") -> dict[str, Any]:
        existing = self.get(kind)
        canonical = (value or "").strip()
        if not canonical:
            return {"ok": False, "reason": "empty_value"}
        # Dedupe — identical (kind+value) replaces silently.
        existing = [e for e in existing if str(e.get("value", "")).lower() != canonical.lower()]
        existing.append({
            "value": canonical,
            "kind": _classify_value(canonical),
            "note": (note or "")[:240],
            "actor": (actor or "")[:64],
            "added_at": time.time(),
        })
        return self.set(kind, existing, actor=actor)

    def remove_entry(self, kind: str, value: str, *, actor: str = "") -> dict[str, Any]:
        existing = self.get(kind)
        canonical = (value or "").strip().lower()
        new_list = [e for e in existing if str(e.get("value", "")).lower() != canonical]
        if len(new_list) == len(existing):
            return {"ok": False, "reason": "not_found"}
        return self.set(kind, new_list, actor=actor)

    def matches(self, kind: str, *, sha256: str = "", path: str = "") -> dict[str, Any] | None:
        """Return the matching entry if `sha256` or `path` is on the list."""
        sha = (sha256 or "").strip().lower()
        full_path = (path or "").strip()
        path_lower = full_path.lower()
        for entry in self.get(kind):
            entry_value = str(entry.get("value", "")).strip()
            entry_kind = str(entry.get("kind", "")).lower()
            if entry_kind == "hash" and sha and entry_value.lower() == sha:
                return entry
            if entry_kind == "path" and full_path:
                # Path entries match exact OR prefix (so "C:\\Tools" matches
                # any binary inside that tree).
                if entry_value.lower() == path_lower or path_lower.startswith(entry_value.lower().rstrip("\\/") + "\\") or path_lower.startswith(entry_value.lower().rstrip("\\/") + "/"):
                    return entry
        return None

    @staticmethod
    def _validate_kind(kind: str) -> str | None:
        canonical = (kind or "").strip().lower()
        if canonical not in VALID_KINDS:
            return None
        return canonical

    @staticmethod
    def _clean(items: list[dict[str, Any]], *, default_actor: str = "") -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items or []:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value", "")).strip()
            if not value:
                continue
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)
            entry_kind = str(item.get("kind", "") or "").lower()
            if entry_kind not in ENTRY_TYPES:
                entry_kind = _classify_value(value)
            out.append({
                "value": value,
                "kind": entry_kind,
                "note": str(item.get("note", ""))[:240],
                "actor": str(item.get("actor", default_actor))[:64],
                "added_at": float(item.get("added_at", time.time()) or time.time()),
            })
        return out
