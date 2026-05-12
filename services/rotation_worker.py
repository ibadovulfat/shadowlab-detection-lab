"""Background worker that rotates long-lived secrets on a schedule.

Targets:
* **Webhook signing secrets** — per-workspace HMAC key used by
  `WebhookDispatcher.compute_signature`. Old secret stays valid for
  one rotation window so receivers can window-verify during cutover.
* **Integrity-manifest signing key** — drives `_sign_manifest` /
  `_signature_state`. Rotation re-signs the live manifest immediately.

Configuration:
* `SHADOWLAB_SECRET_ROTATION_ENABLED` (default `0`) — master switch.
* `SHADOWLAB_SECRET_ROTATION_INTERVAL_SECONDS` (default `86400` = 24h)
  — wake-up cadence. Each tick checks per-target `last_rotated_at` so
  short intervals don't over-rotate.
* `SHADOWLAB_SECRET_ROTATION_MAX_AGE_SECONDS` (default `2592000` = 30
  days) — rotate any secret older than this.
* `SHADOWLAB_SECRET_ROTATION_WORKSPACES` (default empty) — comma-
  separated workspace IDs to include. Empty means "every workspace
  the webhook subsystem has seen".
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any


_logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 24 * 3600
DEFAULT_MAX_AGE_SECONDS = 30 * 24 * 3600
TRUE_VALUES = {"1", "true", "yes", "on"}


def _enabled() -> bool:
    return (os.environ.get("SHADOWLAB_SECRET_ROTATION_ENABLED", "") or "").strip().lower() in TRUE_VALUES


def _interval_seconds() -> int:
    raw = (os.environ.get("SHADOWLAB_SECRET_ROTATION_INTERVAL_SECONDS", "") or "").strip()
    try:
        value = int(float(raw)) if raw else DEFAULT_INTERVAL_SECONDS
    except ValueError:
        value = DEFAULT_INTERVAL_SECONDS
    return max(60, min(value, 7 * 24 * 3600))


def _max_age_seconds() -> int:
    raw = (os.environ.get("SHADOWLAB_SECRET_ROTATION_MAX_AGE_SECONDS", "") or "").strip()
    try:
        value = int(float(raw)) if raw else DEFAULT_MAX_AGE_SECONDS
    except ValueError:
        value = DEFAULT_MAX_AGE_SECONDS
    return max(3600, value)


def _configured_workspaces() -> list[str]:
    raw = (os.environ.get("SHADOWLAB_SECRET_ROTATION_WORKSPACES", "") or "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


class SecretRotationWorker:
    """Daemon thread driving periodic rotation.

    Constructed at API bootstrap with the services it needs to drive.
    `start()` is a no-op when `_enabled()` returns False so the
    process stays at zero idle cost in lab profiles.
    """

    def __init__(
        self,
        *,
        webhook_dispatcher: Any | None,
        integrity_service: Any | None,
        db: Any | None,
    ) -> None:
        self._webhook = webhook_dispatcher
        self._integrity = integrity_service
        self._db = db
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_run_at: float = 0.0
        self._last_rotations: list[dict[str, Any]] = []

    def start(self) -> None:
        if not _enabled():
            _logger.info("Secret rotation worker disabled (SHADOWLAB_SECRET_ROTATION_ENABLED is off).")
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="secret-rotation-worker", daemon=True
        )
        self._thread.start()
        _logger.info("Secret rotation worker started (interval=%ss, max-age=%ss).", _interval_seconds(), _max_age_seconds())

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict[str, Any]:
        return {
            "enabled": _enabled(),
            "interval_seconds": _interval_seconds(),
            "max_age_seconds": _max_age_seconds(),
            "last_run_at": self._last_run_at,
            "recent_rotations": list(self._last_rotations[-20:]),
        }

    def trigger_now(self) -> dict[str, Any]:
        """Run one rotation pass synchronously. Useful for ops drills."""
        return self._rotate_pass()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._rotate_pass()
            except Exception:
                _logger.exception("rotation worker: pass failed")
            self._stop.wait(timeout=_interval_seconds())

    def _rotate_pass(self) -> dict[str, Any]:
        self._last_run_at = time.time()
        rotated: list[dict[str, Any]] = []
        max_age = _max_age_seconds()
        # Webhook signing secrets per workspace.
        if self._webhook is not None and self._db is not None:
            for workspace_id in self._enumerate_workspaces():
                if self._webhook_needs_rotation(workspace_id, max_age):
                    try:
                        result = self._webhook.rotate_secret(workspace_id)
                        rotated.append({
                            "target": "webhook",
                            "workspace_id": workspace_id,
                            "ok": bool(result.get("ok", True)),
                            "secret_id": str(result.get("secret_id", "")),
                            "at": time.time(),
                        })
                    except Exception as exc:
                        _logger.exception("webhook rotation failed for workspace %s", workspace_id)
                        rotated.append({
                            "target": "webhook",
                            "workspace_id": workspace_id,
                            "ok": False,
                            "reason": str(exc),
                            "at": time.time(),
                        })
        # Integrity manifest signing key.
        if self._integrity is not None and self._integrity_needs_rotation(max_age):
            try:
                result = self._integrity.rotate_signing_key()
                rotated.append({
                    "target": "integrity",
                    "ok": bool(result.get("status") == "rotated"),
                    "signature_status": str(result.get("signature_status", "")),
                    "at": time.time(),
                })
            except Exception as exc:
                _logger.exception("integrity rotation failed")
                rotated.append({"target": "integrity", "ok": False, "reason": str(exc), "at": time.time()})

        if rotated:
            _logger.info("rotation worker: rotated %d secret(s) this pass", len(rotated))
        self._last_rotations.extend(rotated)
        # Keep the in-memory tail bounded.
        if len(self._last_rotations) > 200:
            self._last_rotations = self._last_rotations[-200:]
        return {"rotated": rotated, "ran_at": self._last_run_at}

    def _enumerate_workspaces(self) -> list[str]:
        configured = _configured_workspaces()
        if configured:
            return configured
        # Default: walk the active webhook secrets so we only rotate
        # workspaces that actually have a key configured.
        if self._db is None:
            return ["default"]
        try:
            conn = self._db.create_connection()
        except Exception:
            return ["default"]
        if conn is None:
            return ["default"]
        try:
            cursor = conn.execute(
                "SELECT DISTINCT workspace_id FROM webhook_secrets WHERE active = 1"
            )
            rows = cursor.fetchall()
            return [str(row[0] or "default") for row in rows] or ["default"]
        except Exception:
            _logger.debug("rotation worker: workspace enumeration query failed", exc_info=True)
            return ["default"]
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _webhook_needs_rotation(self, workspace_id: str, max_age: int) -> bool:
        if self._db is None:
            return False
        try:
            conn = self._db.create_connection()
        except Exception:
            return False
        if conn is None:
            return False
        try:
            cursor = conn.execute(
                "SELECT created_at FROM webhook_secrets WHERE workspace_id = ? AND active = 1 ORDER BY created_at DESC LIMIT 1",
                (workspace_id,),
            )
            row = cursor.fetchone()
            if not row:
                # No active secret yet — first rotation creates one.
                return True
            return (time.time() - float(row[0] or 0)) >= max_age
        except Exception:
            _logger.debug("rotation worker: webhook age query failed for %s", workspace_id, exc_info=True)
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _integrity_needs_rotation(self, max_age: int) -> bool:
        # IntegrityService stores the signing key as an encrypted setting
        # but doesn't persist the rotation timestamp separately. We
        # approximate "old" by inspecting the manifest history file —
        # the oldest entry hints at when the key was last rotated.
        if self._integrity is None:
            return False
        try:
            history_path = getattr(self._integrity, "history_path", None)
            if not history_path:
                return False
            from pathlib import Path
            path = Path(history_path)
            if not path.exists():
                return True
            mtime = path.stat().st_mtime
            return (time.time() - mtime) >= max_age
        except Exception:
            _logger.debug("rotation worker: integrity age check failed", exc_info=True)
            return False
