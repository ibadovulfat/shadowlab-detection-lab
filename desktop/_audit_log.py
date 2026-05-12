"""Shared on-disk audit log for desktop response actions.

Used by Antivirus, History, and Process consoles to persist response /
state-change activity in a uniform JSON record. Replaces ad-hoc
in-memory lists that were lost on every desktop restart.

Each record is a flat dict so a `jq` / `grep` over the file recovers
the forensic chain without needing a database. Schema (all fields are
strings unless noted):

    timestamp        — local "YYYY-MM-DD HH:MM:SS" for legacy table render
    ts               — ISO-8601 with timezone offset
    actor            — operator name (from app.actor_name)
    workspace        — workspace ID
    category         — "response", "state-change", "intel", ...
    action           — the verb performed (kill, quarantine, close, ...)
    target           — string identifying what was acted on
    severity         — "low" | "medium" | "high" | "critical"
    status           — "ok" | "failed" | "blocked" | "partial"
    payload          — dict — the raw server response or error envelope
    ticket_id        — optional structured-reason fields
    reason_category
    reason_text

Records are stored newest-first.  Retention is bounded by
`AuditLogStore(retention=...)`.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

DEFAULT_RETENTION = 500


def utc_iso_with_offset() -> str:
    """ISO 8601 timestamp with the host's timezone offset.

    Used for the `ts` field on every audit row — the short `timestamp`
    string is left in local time for the legacy in-app table render.
    """
    return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


class AuditLogStore:
    """Tiny JSON-backed audit log.

    Construct with `path_provider` (callable returning a `Path`) so the
    location can be lazily resolved at write time — useful for tests
    that override the store's path after construction. The store
    keeps an in-memory list mirror so the controller doesn't need to
    re-read the JSON on every render.
    """

    def __init__(
        self,
        path_provider: Callable[[], Path],
        *,
        retention: int = DEFAULT_RETENTION,
        mirror_callback: Callable[[dict], None] | None = None,
    ) -> None:
        self._path_provider = path_provider
        self._retention = max(1, int(retention))
        self._cache: list[dict] | None = None
        # Optional best-effort sink fired AFTER each `append`. The
        # controller wires this to a backend POST so the audit chain
        # mirrors off-host without blocking the response action. Any
        # exception in the callback is swallowed — disk is the source
        # of truth, the mirror is a convenience.
        self._mirror_callback = mirror_callback

    def set_mirror_callback(self, callback: Callable[[dict], None] | None) -> None:
        self._mirror_callback = callback

    @property
    def path(self) -> Path:
        return self._path_provider()

    def load(self) -> list[dict]:
        """Read the on-disk log, populate the in-memory mirror."""
        path = self.path
        try:
            if not path.exists():
                self._cache = []
                return []
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            self._cache = []
            return []
        if not isinstance(raw, list):
            self._cache = []
            return []
        items = [item for item in raw if isinstance(item, dict)][: self._retention]
        self._cache = items
        return list(items)

    def entries(self) -> list[dict]:
        """Return a defensive copy of the in-memory mirror."""
        if self._cache is None:
            return self.load()
        return list(self._cache)

    def save(self, entries: Iterable[dict] | None = None) -> None:
        """Persist either an explicit list or the in-memory mirror.

        Best-effort I/O — disk failures are swallowed. The audit *write*
        path is never allowed to bring down a response action: the UI
        already shows the action result from the server response.
        """
        if entries is not None:
            self._cache = [item for item in entries if isinstance(item, dict)][: self._retention]
        if self._cache is None:
            self._cache = []
        path = self.path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self._cache, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception:
            return

    def append(
        self,
        *,
        category: str,
        action: str,
        target: str,
        severity: str,
        status: str,
        payload: Any,
        actor: str = "desktop",
        workspace: str = "default",
        reason: dict | None = None,
        extra: dict | None = None,
    ) -> dict:
        """Append a new record (newest-first), trim, and persist.

        Returns the inserted record so the caller can echo it into a
        UI-side history list (e.g. `app.antivirus_history_entries`)
        without rebuilding the dict.
        """
        if self._cache is None:
            self.load()
        entry: dict = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ts": utc_iso_with_offset(),
            "actor": actor or "desktop",
            "workspace": workspace or "default",
            "category": category,
            "action": action,
            "target": target,
            "severity": severity,
            "status": status,
            "payload": payload if isinstance(payload, (dict, list, str, int, float, bool)) or payload is None else str(payload),
        }
        if reason:
            entry["ticket_id"] = str(reason.get("ticket_id", "") or "")
            entry["reason_category"] = str(reason.get("reason_category", "") or "")
            entry["reason_text"] = str(reason.get("reason_text", "") or "")
        if extra:
            for key, value in extra.items():
                if key in entry:
                    continue
                entry[str(key)] = value
        # Newest-first.
        assert self._cache is not None
        self._cache.insert(0, entry)
        del self._cache[self._retention:]
        self.save()
        # Best-effort mirror — never let a backend hiccup tear down the
        # response action that just succeeded locally.
        if self._mirror_callback is not None:
            try:
                self._mirror_callback(entry)
            except Exception:
                pass
        return entry

    def trim(self, retention: int | None = None) -> None:
        if retention is not None:
            self._retention = max(1, int(retention))
        if self._cache is None:
            return
        del self._cache[self._retention:]
        self.save()


def actor_workspace_pair(app) -> tuple[str, str]:
    """Helper for callers — pulls (actor, workspace) off `app` safely.

    Either field may be absent in tests; both default to sane strings.
    """
    actor = "desktop"
    workspace = "default"
    try:
        if hasattr(app, "actor_name"):
            value = app.actor_name.text().strip()
            if value:
                actor = value
    except Exception:
        pass
    try:
        if hasattr(app, "workspace_id"):
            value = app.workspace_id.text().strip()
            if value:
                workspace = value
    except Exception:
        pass
    return actor, workspace
