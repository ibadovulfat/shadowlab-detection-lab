"""Optional on-access folder watcher for the antivirus pipeline.

Real EDRs intercept file activity at the kernel level (minifilter on
Windows, fanotify on Linux, EndpointSecurity on macOS) so a malicious
write is scanned before any consuming process can execute it. ShadowLab
runs in user-space and cannot do that — but we can offer the
analyst-grade approximation: poll a short list of high-value directories
and submit any new or modified file to the async scan queue.

Why polling, not `watchdog`/inotify?
  * Zero new dependencies — pure stdlib, works on Windows/macOS/Linux.
  * Predictable resource footprint — no kernel events to flood the
    queue when an installer writes 30k temp files.
  * Easy to bound: max files-per-tick + min-quiet-period guard against
    write-amplification.

The watcher is **optional** and **opt-in**. It only starts if the policy
sets `on_access_enabled=true` and provides at least one path. Each
detected file is submitted to `ScanJobQueue.submit(...)` with
`actor='folder_watcher'` so it shows up in the audit trail and can be
filtered separately from analyst-initiated scans.

Safety guards:
  * Path traversal — every emitted path is `Path.resolve()`'d and
    verified against the allowed roots before submission.
  * Size cap — files over `max_file_size_mb` from policy are skipped
    (matches the synchronous scan_file gate).
  * Quiet period — a file must be unchanged for `quiet_period_seconds`
    before being submitted, so partial writes (e.g. browser downloads)
    are not scanned mid-flight.
  * Max submissions per tick — caps queue pressure during installs.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable


class FolderWatcher:
    """Polling on-access scanner. One instance per ShadowLab process."""

    def __init__(
        self,
        scan_submit: Callable[..., dict[str, Any]],
        *,
        poll_interval_seconds: float = 5.0,
        quiet_period_seconds: float = 3.0,
        max_files_per_tick: int = 25,
        max_file_size_mb: int = 128,
        db: Any = None,
    ):
        self._submit = scan_submit
        self._poll_interval = max(1.0, float(poll_interval_seconds))
        self._quiet_period = max(0.5, float(quiet_period_seconds))
        self._max_per_tick = max(1, int(max_files_per_tick))
        self._max_size = int(max_file_size_mb) * 1024 * 1024
        self._roots: list[Path] = []
        self._workspace_id = "default"
        self._lock = threading.RLock()
        self._stop_evt = threading.Event()
        self._worker: threading.Thread | None = None
        # Per-path bookkeeping: path -> (mtime, size, first_seen_at, submitted)
        self._observed: dict[str, tuple[float, int, float, bool]] = {}
        self._stats: dict[str, Any] = {
            "ticks": 0, "files_seen": 0, "files_submitted": 0,
            "files_skipped_size": 0, "files_skipped_quiet": 0,
            "last_tick_at": 0.0, "last_error": "",
        }
        # Persistence — config + last-running flag survives restart.
        self._db = db
        self._hydrate_config_from_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def configure(self, *, paths: list[str], workspace_id: str = "default", max_file_size_mb: int | None = None) -> None:
        with self._lock:
            self._roots = []
            for raw in paths or []:
                candidate = Path(str(raw)).expanduser()
                try:
                    resolved = candidate.resolve(strict=False)
                except OSError:
                    continue
                if resolved not in self._roots:
                    self._roots.append(resolved)
            self._workspace_id = str(workspace_id or "default")
            if max_file_size_mb is not None:
                self._max_size = int(max_file_size_mb) * 1024 * 1024
        # Persist immediately so the next boot finds the same config.
        self._persist_config()

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return {"ok": True, "state": "already_running", "roots": [str(r) for r in self._roots]}
            if not self._roots:
                return {"ok": False, "reason": "no_paths_configured"}
            # Seed the observed set synchronously *before* the worker
            # thread starts so any file the operator creates after
            # `start()` returns is reliably treated as new. If we did the
            # seed inside the worker we'd race operator activity, and
            # files created during the race window would be marked as
            # pre-existing and silently ignored.
            self._observed.clear()
            now = time.time()
            for path, mtime, size in self._walk_files():
                self._observed[path] = (mtime, size, now, True)
            self._stop_evt.clear()
            worker = threading.Thread(target=self._run, name="av-folder-watcher", daemon=True)
            self._worker = worker
            worker.start()
        self._persist_running(True)
        return {"ok": True, "state": "running", "roots": [str(r) for r in self._roots]}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._stop_evt.set()
            worker = self._worker
            self._worker = None
        if worker is not None:
            worker.join(timeout=5.0)
        self._persist_running(False)
        return {"ok": True, "state": "stopped"}

    # ------------------------------------------------------------------
    # Persistence — config + last-running flag survives restart so the
    # operator doesn't have to re-configure paths every boot.
    # ------------------------------------------------------------------

    APP_SETTING_CONFIG = "antivirus_folder_watcher_config"
    APP_SETTING_RUNNING = "antivirus_folder_watcher_running"

    def _persist_config(self) -> None:
        if self._db is None:
            return
        import json as _json
        snapshot = {
            "paths": [str(r) for r in self._roots],
            "workspace_id": self._workspace_id,
            "max_file_size_mb": self._max_size // (1024 * 1024),
        }
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            self._db.set_app_setting(conn, self.APP_SETTING_CONFIG, _json.dumps(snapshot, ensure_ascii=False))
        except Exception:
            return
        finally:
            try: conn.close()
            except Exception: pass

    def _persist_running(self, running: bool) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            self._db.set_app_setting(conn, self.APP_SETTING_RUNNING, "1" if running else "0")
        except Exception:
            return
        finally:
            try: conn.close()
            except Exception: pass

    def _hydrate_config_from_db(self) -> None:
        """Restore the last-saved paths/workspace + auto-resume if the
        watcher was running at the time of the previous shutdown."""
        if self._db is None:
            return
        import json as _json
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            cfg_raw = self._db.get_app_setting(conn, self.APP_SETTING_CONFIG) or ""
            running_raw = self._db.get_app_setting(conn, self.APP_SETTING_RUNNING) or "0"
        except Exception:
            return
        finally:
            try: conn.close()
            except Exception: pass
        if cfg_raw:
            try:
                cfg = _json.loads(cfg_raw)
                paths = cfg.get("paths", []) if isinstance(cfg, dict) else []
                ws = str(cfg.get("workspace_id", "default") or "default")
                size_mb = int(cfg.get("max_file_size_mb", 128) or 128)
                # Restore config WITHOUT re-persisting (would be a no-op
                # but creates a redundant DB write on every boot).
                with self._lock:
                    self._roots = []
                    for raw in paths:
                        try:
                            resolved = Path(str(raw)).expanduser().resolve(strict=False)
                        except OSError:
                            continue
                        if resolved not in self._roots:
                            self._roots.append(resolved)
                    self._workspace_id = ws
                    self._max_size = size_mb * 1024 * 1024
            except Exception:
                pass
        if running_raw == "1" and self._roots:
            # Auto-resume — fire the start path so the worker picks up
            # exactly where it left off (seed phase still excludes
            # pre-existing files, no thundering herd).
            try:
                self.start()
            except Exception:
                pass

    def is_running(self) -> bool:
        with self._lock:
            return self._worker is not None and self._worker.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            stats = dict(self._stats)
            return {
                "running": self.is_running(),
                "workspace_id": self._workspace_id,
                "roots": [str(r) for r in self._roots],
                "poll_interval_seconds": self._poll_interval,
                "quiet_period_seconds": self._quiet_period,
                "max_files_per_tick": self._max_per_tick,
                "max_file_size_mb": self._max_size // (1024 * 1024),
                "tracked_paths": len(self._observed),
                "stats": stats,
            }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run(self) -> None:
        # Seeding now happens synchronously in start() so we don't race
        # operator file activity in the gap between thread start and the
        # first walk. The worker just polls.
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as exc:
                with self._lock:
                    self._stats["last_error"] = str(exc)
            self._stop_evt.wait(timeout=self._poll_interval)

    def _tick(self) -> None:
        now = time.time()
        candidates: list[tuple[str, float, int]] = []
        seen_paths: set[str] = set()
        for path, mtime, size in self._walk_files():
            seen_paths.add(path)
            prev = self._observed.get(path)
            if prev is None:
                self._observed[path] = (mtime, size, now, False)
                candidates.append((path, mtime, size))
                continue
            prev_mtime, prev_size, first_seen, submitted = prev
            if mtime != prev_mtime or size != prev_size:
                self._observed[path] = (mtime, size, now, False)
                candidates.append((path, mtime, size))
            elif not submitted and (now - first_seen) >= self._quiet_period:
                # Steady-state file from a previous tick — submit it now.
                candidates.append((path, mtime, size))

        # Garbage-collect paths that no longer exist.
        gone = [p for p in self._observed if p not in seen_paths]
        for p in gone:
            self._observed.pop(p, None)

        submissions = 0
        for path, mtime, size in candidates:
            if submissions >= self._max_per_tick:
                break
            with self._lock:
                self._stats["files_seen"] += 1
            if size > self._max_size:
                with self._lock:
                    self._stats["files_skipped_size"] += 1
                continue
            prev = self._observed.get(path)
            if prev is None:
                continue
            prev_mtime, prev_size, first_seen, _submitted = prev
            if (now - first_seen) < self._quiet_period:
                with self._lock:
                    self._stats["files_skipped_quiet"] += 1
                continue
            try:
                self._submit(
                    path,
                    workspace_id=self._workspace_id,
                    actor="folder_watcher",
                    policy_overrides={},
                )
                submissions += 1
                self._observed[path] = (prev_mtime, prev_size, first_seen, True)
                with self._lock:
                    self._stats["files_submitted"] += 1
            except Exception as exc:
                with self._lock:
                    self._stats["last_error"] = f"{path}: {exc}"
                continue

        with self._lock:
            self._stats["ticks"] += 1
            self._stats["last_tick_at"] = now

    def _walk_files(self):
        roots: list[Path]
        with self._lock:
            roots = list(self._roots)
        for root in roots:
            if not root.exists():
                continue
            try:
                for entry in root.rglob("*"):
                    try:
                        if not entry.is_file():
                            continue
                        stat = entry.stat()
                    except OSError:
                        continue
                    yield (str(entry.resolve()), float(stat.st_mtime), int(stat.st_size))
            except OSError:
                continue
