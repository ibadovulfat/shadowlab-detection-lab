"""Signature / definition updater for the antivirus pipeline.

Real commercial antivirus products keep their detection database fresh
by pulling signed signature bundles from the vendor on a cadence — a
stale database is worse than no database because it lulls operators
into thinking they are covered. ShadowLab mirrors that behaviour
through this module.

Scope:
  * ClamAV / Sentinel — invokes the real `freshclam` binary discovered
    by `SentinelProvider`, which fetches signed CVD/CLD bundles from
    db.{local}.clamav.net. Exit codes are interpreted per the freshclam
    manual (0 = up-to-date, 1 = reloaded, higher = error).
  * KicomAV / Aegis — the vendored rule tree is code-resident; we do
    not attempt to mutate it from here. We still record an update row
    so the UI can show a consistent "last checked" timestamp.

Every update attempt — manual or scheduled — is persisted to the
`av_signature_updates` table so operators have an audit trail of
*when* definitions moved and *which* files changed. A background
scheduler thread can be started with `start_background_refresh()`
using the `scheduled_validation_minutes` policy knob; it cancels
cleanly on `stop()`.

Everything here degrades gracefully: no freshclam binary, no db
connection, a vanished database directory — all produce a structured
status row rather than an exception.
"""
from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .sentinel_provider import SentinelProvider


FRESHCLAM_TIMEOUT_SECONDS = 300


class SignatureUpdater:
    def __init__(
        self,
        base_dir: Path,
        *,
        sentinel: SentinelProvider | None = None,
        db: Any = None,
    ):
        self.base_dir = Path(base_dir)
        self._sentinel = sentinel
        self._db = db
        self._lock = threading.Lock()
        self._scheduler_thread: threading.Thread | None = None
        self._scheduler_stop = threading.Event()
        self._last_result: dict[str, Any] = {}

    def _get_sentinel(self) -> SentinelProvider:
        if self._sentinel is None:
            self._sentinel = SentinelProvider(self.base_dir)
        return self._sentinel

    def status(self) -> dict[str, Any]:
        sentinel = self._get_sentinel()
        database_dir = sentinel.database_dir
        database_files = sentinel._database_files()
        latest = 0.0
        for path in database_files:
            try:
                latest = max(latest, float(path.stat().st_mtime))
            except OSError:
                continue
        return {
            "freshclam_available": bool(sentinel.freshclam_path),
            "freshclam_path": str(sentinel.freshclam_path) if sentinel.freshclam_path else "",
            "database_dir": str(database_dir),
            "database_files": [path.name for path in database_files],
            "latest_signature_update": latest,
            "last_attempt": dict(self._last_result) if self._last_result else {},
            "scheduler_running": bool(self._scheduler_thread and self._scheduler_thread.is_alive()),
        }

    def update(self, *, provider_key: str = "sentinel_cli", trigger: str = "manual", actor: str = "") -> dict[str, Any]:
        """Run a signature update for the given provider. Blocks until
        freshclam returns or the timeout fires. Result is persisted and
        cached on the instance."""
        if provider_key == "sentinel_cli":
            result = self._update_sentinel(trigger=trigger, actor=actor)
        elif provider_key == "aegis_core":
            result = self._update_aegis(trigger=trigger, actor=actor)
        else:
            result = {
                "provider_key": provider_key,
                "status": "unsupported",
                "message": f"No update flow registered for provider {provider_key}",
                "trigger": trigger,
                "started_at": time.time(),
                "finished_at": time.time(),
                "files_changed": 0,
            }
        with self._lock:
            self._last_result = dict(result)
        self._persist(result)
        return result

    def history(self, *, limit: int = 25) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if self._db is None:
            return rows
        try:
            conn = self._db.create_connection()
        except Exception:
            return rows
        try:
            cursor = conn.execute(
                """
                SELECT provider_key, started_at, finished_at, status, message, files_changed, trigger
                FROM av_signature_updates
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), 500)),),
            )
            for provider_key, started_at, finished_at, status, message, files_changed, trigger in cursor.fetchall():
                rows.append(
                    {
                        "provider_key": provider_key,
                        "started_at": float(started_at or 0),
                        "finished_at": float(finished_at or 0),
                        "status": status or "",
                        "message": message or "",
                        "files_changed": int(files_changed or 0),
                        "trigger": trigger or "",
                    }
                )
        except Exception:
            return rows
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return rows

    def start_background_refresh(self, *, interval_minutes: int) -> bool:
        """Start a daemon thread that refreshes signatures every
        `interval_minutes` minutes. Returns True if a new scheduler was
        started, False if one was already running."""
        interval_seconds = max(15 * 60, int(interval_minutes) * 60)
        with self._lock:
            if self._scheduler_thread and self._scheduler_thread.is_alive():
                return False
            self._scheduler_stop.clear()
            thread = threading.Thread(
                target=self._scheduler_loop,
                args=(interval_seconds,),
                name="shadowlab-av-signature-updater",
                daemon=True,
            )
            self._scheduler_thread = thread
            thread.start()
            return True

    def stop(self) -> None:
        self._scheduler_stop.set()
        thread = self._scheduler_thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)

    def _scheduler_loop(self, interval_seconds: int) -> None:
        while not self._scheduler_stop.is_set():
            try:
                self.update(trigger="scheduled")
            except Exception:
                pass
            if self._scheduler_stop.wait(interval_seconds):
                return

    def _update_sentinel(self, *, trigger: str, actor: str) -> dict[str, Any]:
        sentinel = self._get_sentinel()
        started = time.time()
        baseline_files = {path.name: self._safe_mtime(path) for path in sentinel._database_files()}
        if not sentinel.freshclam_path:
            return {
                "provider_key": "sentinel_cli",
                "status": "unavailable",
                "message": "freshclam binary not discovered; set SHADOWLAB_SENTINEL_FRESHCLAM or install ClamAV",
                "trigger": trigger,
                "actor": actor,
                "started_at": started,
                "finished_at": time.time(),
                "files_changed": 0,
            }
        command = [
            str(sentinel.freshclam_path),
            "--stdout",
            "--no-warnings",
            f"--datadir={sentinel.database_dir}",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=FRESHCLAM_TIMEOUT_SECONDS,
            )
            stdout_tail = (completed.stdout or "").strip().splitlines()[-10:]
            stderr_tail = (completed.stderr or "").strip().splitlines()[-10:]
            message_lines = stdout_tail + (stderr_tail if completed.returncode != 0 else [])
            message = "\n".join(message_lines)[:2000]
            # freshclam: 0 = up-to-date, 1 = databases updated — both success.
            if completed.returncode in (0, 1):
                status = "ok"
            else:
                status = "error"
        except subprocess.TimeoutExpired:
            return {
                "provider_key": "sentinel_cli",
                "status": "error",
                "message": f"freshclam timed out after {FRESHCLAM_TIMEOUT_SECONDS}s",
                "trigger": trigger,
                "actor": actor,
                "started_at": started,
                "finished_at": time.time(),
                "files_changed": 0,
            }
        except Exception as exc:
            return {
                "provider_key": "sentinel_cli",
                "status": "error",
                "message": f"freshclam failed: {exc}",
                "trigger": trigger,
                "actor": actor,
                "started_at": started,
                "finished_at": time.time(),
                "files_changed": 0,
            }
        finished = time.time()
        # Count files whose mtime changed or that appeared.
        current = {path.name: self._safe_mtime(path) for path in sentinel._database_files()}
        files_changed = 0
        for name, mtime in current.items():
            if baseline_files.get(name, 0.0) != mtime:
                files_changed += 1
        for name in baseline_files:
            if name not in current:
                files_changed += 1
        return {
            "provider_key": "sentinel_cli",
            "status": status,
            "message": message,
            "trigger": trigger,
            "actor": actor,
            "started_at": started,
            "finished_at": finished,
            "files_changed": files_changed,
            "return_code": completed.returncode,
        }

    def _update_aegis(self, *, trigger: str, actor: str) -> dict[str, Any]:
        started = time.time()
        return {
            "provider_key": "aegis_core",
            "status": "noop",
            "message": "Aegis rules ship vendored with the application; no out-of-band update pulled.",
            "trigger": trigger,
            "actor": actor,
            "started_at": started,
            "finished_at": time.time(),
            "files_changed": 0,
        }

    def _persist(self, result: dict[str, Any]) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        try:
            conn.execute(
                """
                INSERT INTO av_signature_updates (
                    provider_key, started_at, finished_at, status, message, files_changed, trigger
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(result.get("provider_key", "")),
                    float(result.get("started_at", time.time()) or time.time()),
                    float(result.get("finished_at", time.time()) or time.time()),
                    str(result.get("status", "")),
                    str(result.get("message", ""))[:4000],
                    int(result.get("files_changed", 0) or 0),
                    str(result.get("trigger", "manual")),
                ),
            )
            conn.commit()
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _safe_mtime(path: Path) -> float:
        try:
            return float(path.stat().st_mtime)
        except OSError:
            return 0.0
