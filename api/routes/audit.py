"""Receive desktop-side audit mirror writes.

Each desktop console (Process / Antivirus / Enterprise / History /
Intel / Network / Security Ops / Integrations / Persistence) keeps its
own on-disk audit log. The `AuditLogStore.mirror_callback` fires after
every successful append and best-effort POSTs to `/audit/desktop` so a
SOC manager can grep the entire chain across every operator's box from
a single appliance.

This route is fire-and-forget from the desktop's perspective — failures
are swallowed by the mirror callback, the local file remains the
source of truth. The appliance writes incoming records as JSON Lines
under `shadowlab_out/desktop-audit-mirror/<console>.jsonl` so a
follow-up release can ingest them into the database without changing
the wire format.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request


MIRROR_DIR = Path("shadowlab_out") / "desktop-audit-mirror"
# Per-console JSONL file caps so a runaway desktop can't fill the disk.
# 50 MB per console × 9 consoles = 450 MB worst case. Beyond that the
# oldest lines are trimmed.
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024


def _safe_console_slug(value: str) -> str:
    """Coerce a `source` field into a filesystem-safe slug.

    The desktop sends `desktop:enterprise`, `desktop:antivirus`, etc.
    Strip the prefix and reject anything that doesn't look like a
    plain identifier — defensive against a malicious payload trying
    to traverse out of the mirror directory.
    """
    if not isinstance(value, str):
        return "unknown"
    value = value.strip().lower()
    if value.startswith("desktop:"):
        value = value[len("desktop:"):]
    cleaned = "".join(ch for ch in value if ch.isalnum() or ch in {"-", "_"})
    return cleaned[:48] or "unknown"


def _trim_file_if_oversized(path: Path) -> None:
    """If the per-console JSONL grows past `MAX_FILE_SIZE_BYTES`,
    rotate the second half out so the appliance never crosses the
    disk-fill threshold."""
    try:
        if not path.exists() or path.stat().st_size <= MAX_FILE_SIZE_BYTES:
            return
        # Read second half of the file as the new contents — newest
        # entries are at the end so cutting the head is the safer
        # truncation strategy.
        with path.open("rb") as handle:
            handle.seek(-MAX_FILE_SIZE_BYTES // 2, 2)
            # Skip a partial line so we don't keep a corrupt opener.
            handle.readline()
            tail = handle.read()
        path.write_bytes(tail)
    except Exception:
        return


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    require_admin = ctx["require_admin"]
    db = ctx["db"]
    request_workspace_id = ctx.get("_request_workspace_id")

    @app.get("/audit/chain/verify", dependencies=[Depends(require_admin)])
    def audit_chain_verify(limit: int = 0) -> dict[str, Any]:
        """Recompute the SHA-256 audit-log hash chain end-to-end.

        Returns `{ok: true, rows_checked, tip}` on a clean walk, or
        `{ok: false, broken_at_id, ...}` on the first tamper. Operators
        export the `tip` field periodically so a subsequent silent
        rewrite of every row can be detected by comparing tips.
        """
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        try:
            return db.verify_action_audit_chain(conn, limit=int(limit or 0))
        finally:
            conn.close()

    @app.post("/audit/desktop", dependencies=[Depends(require_analyst_or_admin)])
    def receive_desktop_audit(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """Mirror endpoint — accepts a single desktop audit record.

        Body shape (sent by `_audit_log.AuditLogStore` mirror_callback):
            {
                "source": "desktop:<console>",
                "entry": {
                    "timestamp": "...",
                    "ts": "ISO-8601",
                    "actor": "...",
                    "workspace": "...",
                    "category": "...",
                    "action": "...",
                    "target": "...",
                    "severity": "low|medium|high|critical",
                    "status": "ok|failed|blocked|...",
                    "payload": {...},
                    "ticket_id": "...",  # optional
                    "reason_category": "...",
                    "reason_text": "..."
                }
            }
        """
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Body must be a JSON object")
        entry = payload.get("entry")
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail="`entry` must be an object")

        slug = _safe_console_slug(payload.get("source", "unknown"))
        target_path = MIRROR_DIR / f"{slug}.jsonl"
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Stamp server-side metadata: when the appliance received it
        # and the workspace seen by the API. The desktop already
        # writes its own `ts` + `workspace`, but auditors trust the
        # server's clock more than the operator's.
        server_envelope = {
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "server_workspace": request_workspace_id(request) if callable(request_workspace_id) else "default",
            "source": payload.get("source", "unknown"),
            "entry": entry,
        }
        line = json.dumps(server_envelope, ensure_ascii=False, default=str)

        try:
            with target_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            _trim_file_if_oversized(target_path)
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Audit mirror write failed: {exc}") from exc

        return {"status": "ok", "slug": slug, "received_at": server_envelope["received_at"]}

    @app.get("/audit/desktop/summary", dependencies=[Depends(require_analyst_or_admin)])
    def desktop_audit_summary() -> dict[str, Any]:
        """Lightweight readout — line counts per console + last entry.

        The full mirror lives in JSONL files; this endpoint exists so
        a SOC dashboard can poll a single number per console without
        downloading the whole chain.
        """
        if not MIRROR_DIR.exists():
            return {"consoles": {}, "total_lines": 0}
        consoles: dict[str, dict[str, Any]] = {}
        total = 0
        for path in MIRROR_DIR.glob("*.jsonl"):
            try:
                with path.open("rb") as handle:
                    line_count = sum(1 for _ in handle)
                last = ""
                if line_count:
                    with path.open("rb") as handle:
                        handle.seek(-min(4096, path.stat().st_size), 2)
                        chunk = handle.read().decode("utf-8", errors="ignore")
                        last_line = chunk.splitlines()[-1] if chunk else ""
                        try:
                            last = json.loads(last_line).get("entry", {}).get("ts", "") if last_line else ""
                        except Exception:
                            last = ""
            except Exception:
                line_count = 0
                last = ""
            consoles[path.stem] = {
                "line_count": line_count,
                "last_entry_ts": last,
                "size_bytes": path.stat().st_size if path.exists() else 0,
            }
            total += line_count
        return {"consoles": consoles, "total_lines": total}
