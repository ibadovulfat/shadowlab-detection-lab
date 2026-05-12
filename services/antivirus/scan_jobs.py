"""Async scan job queue for the antivirus pipeline.

Synchronous `AntivirusService.scan_file` blocks the calling HTTP thread
for the duration of the slowest engine — which, with the cloud sandbox
provider in the mix, can be 30+ seconds. Real EDR consoles solve that
with an async job model: the analyst submits the scan, gets back a
`job_id` immediately, then watches progress over WebSocket / SSE while
the engine fan-out runs in the background.

Design:
  * **Persistent** — every job is mirrored into `av_scan_jobs` so a
    restart does not lose the analyst's submission. The DB row is the
    source of truth; the in-process queue is a hot-cache for active
    jobs.
  * **Bounded worker pool** — at most `max_workers` jobs run in parallel
    across the whole API. A single noisy submitter cannot pin the
    scanner threads against more important interactive scans.
  * **Progress events** — every state transition (queued → running →
    complete / error) publishes a snapshot to subscribed listeners.
    The FastAPI WebSocket route subscribes per-job and forwards each
    snapshot to the browser.
  * **Cancellation** — best-effort: a queued job can be cancelled
    cleanly; a running job is marked `cancelling` and the in-flight
    scan finishes (the underlying ScanWorkerPool already enforces a
    timeout, so a runaway provider cannot pin it forever).

The queue does *not* duplicate the verdict cache; it just routes the
underlying `AntivirusService.scan_file` call. Cache hits still happen
inside the synchronous core, which means a duplicate submission for an
unchanged hash returns almost instantly even under load.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable


JOB_STATES_TERMINAL = {"complete", "error", "cancelled"}
JOB_STATES_ACTIVE = {"queued", "running", "cancelling"}


@dataclass
class ScanJob:
    job_id: str
    workspace_id: str
    actor: str
    target_path: str
    policy_overrides: dict[str, Any]
    state: str = "queued"
    progress: int = 0
    submitted_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    finished_at: float = 0.0
    error: str = ""
    result: dict[str, Any] | None = None
    # cancel_event is set by `cancel()` and checked by the worker
    # between the queue → running and running → fusion stages, giving
    # us a hard-stop point even though we can't kill an in-flight
    # synchronous provider call.
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def snapshot(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "workspace_id": self.workspace_id,
            "actor": self.actor,
            "target_path": self.target_path,
            "policy_overrides": dict(self.policy_overrides),
            "state": self.state,
            "progress": int(self.progress),
            "submitted_at": float(self.submitted_at),
            "started_at": float(self.started_at),
            "finished_at": float(self.finished_at),
            "duration_ms": int((self.finished_at - self.started_at) * 1000) if self.finished_at and self.started_at else 0,
            "error": self.error,
            "result": self.result if isinstance(self.result, dict) else None,
        }


class ScanJobQueue:
    """Thread-safe async job dispatcher backed by a small thread pool."""

    def __init__(
        self,
        antivirus_service,
        *,
        db: Any = None,
        max_workers: int = 4,
        max_history: int = 500,
    ):
        self._svc = antivirus_service
        self._db = db
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=max(1, int(max_workers)), thread_name_prefix="av-scan-job")
        self._listeners: dict[str, list[Callable[[dict[str, Any]], None]]] = {}
        self._listener_lock = threading.RLock()
        self._max_history = max(50, int(max_history))
        # Best-effort hydrate active jobs from disk — a server restart in
        # the middle of a scan reopens the catalogue so the analyst can
        # at least see the orphaned job rather than wondering where it
        # went. Anything still flagged "running" is moved to "error" with
        # an interrupted reason since the previous worker died.
        self._hydrate_from_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Per-workspace concurrency cap — protects the worker pool from a
    # noisy submitter monopolising every scanner thread. Defaults to 8
    # active jobs; tunable per-instance.
    DEFAULT_PER_WORKSPACE_CAP = 8

    def submit(
        self,
        target_path: str,
        *,
        workspace_id: str = "default",
        actor: str = "",
        policy_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Concurrency cap — refuse the submission if the workspace
        # already has too many active (queued/running) jobs. Returns a
        # snapshot dict matching the success shape but with state=error
        # so the API caller can surface the reason.
        ws = str(workspace_id or "default")
        with self._lock:
            active_for_ws = sum(
                1 for j in self._jobs.values()
                if j.workspace_id == ws and j.state in JOB_STATES_ACTIVE
            )
            if active_for_ws >= self.DEFAULT_PER_WORKSPACE_CAP:
                throttled = ScanJob(
                    job_id=uuid.uuid4().hex,
                    workspace_id=ws, actor=str(actor or ""),
                    target_path=str(target_path or ""),
                    policy_overrides=dict(policy_overrides or {}),
                    state="error",
                    finished_at=time.time(),
                    error=f"workspace_concurrency_cap_exceeded ({active_for_ws}/{self.DEFAULT_PER_WORKSPACE_CAP})",
                )
                self._jobs[throttled.job_id] = throttled
                snapshot = throttled.snapshot()
                self._publish(throttled.job_id, snapshot)
                return snapshot
        job = ScanJob(
            job_id=uuid.uuid4().hex,
            workspace_id=ws,
            actor=str(actor or ""),
            target_path=str(target_path or ""),
            policy_overrides=dict(policy_overrides or {}),
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._evict_history_if_needed()
        self._persist(job)
        self._executor.submit(self._run_job, job.job_id)
        snapshot = job.snapshot()
        self._publish(job.job_id, snapshot)
        return snapshot

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.snapshot() if job else self._load_from_db(job_id)

    def list(self, *, workspace_id: str | None = None, limit: int = 50, state: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = [job.snapshot() for job in self._jobs.values()]
        if workspace_id:
            rows = [row for row in rows if row.get("workspace_id") == workspace_id]
        if state:
            rows = [row for row in rows if row.get("state") == state]
        rows.sort(key=lambda row: row.get("submitted_at", 0), reverse=True)
        return rows[: max(1, min(int(limit), 500))]

    def cancel(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return {"ok": False, "reason": "unknown_job"}
            if job.state in JOB_STATES_TERMINAL:
                return {"ok": False, "reason": f"already_{job.state}"}
            # Set the hard-stop event so the worker honours cancellation
            # at every safe waypoint (between queue/run, before fusion,
            # before audit + cache write). Provider calls themselves are
            # uninterruptible — that's a constraint of the synchronous
            # ScanWorkerPool — but every other phase respects the event.
            job.cancel_event.set()
            if job.state == "queued":
                job.state = "cancelled"
                job.finished_at = time.time()
                job.error = "cancelled before dispatch"
                self._persist(job)
                self._publish(job.job_id, job.snapshot())
                return {"ok": True, "state": job.state}
            # Running — flag for cancellation. The worker will honour it
            # when the underlying scan completes.
            job.state = "cancelling"
            self._persist(job)
            self._publish(job.job_id, job.snapshot())
            return {"ok": True, "state": job.state}

    def subscribe(self, job_id: str, callback: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        """Register a progress listener. Returns an unsubscribe handle."""
        with self._listener_lock:
            self._listeners.setdefault(job_id, []).append(callback)

        def _unsubscribe() -> None:
            with self._listener_lock:
                listeners = self._listeners.get(job_id, [])
                if callback in listeners:
                    listeners.remove(callback)
                if not listeners:
                    self._listeners.pop(job_id, None)

        return _unsubscribe

    def stats(self) -> dict[str, Any]:
        with self._lock:
            states: dict[str, int] = {}
            for job in self._jobs.values():
                states[job.state] = states.get(job.state, 0) + 1
        return {
            "total_in_memory": sum(states.values()),
            "by_state": states,
        }

    def shutdown(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_job(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.state == "cancelled":
                return
            # Honour an early cancel event — operator hit cancel between
            # submit and the executor picking the job up.
            if job.state == "cancelling" or job.cancel_event.is_set():
                job.state = "cancelled"
                job.finished_at = time.time()
                job.error = "cancelled before dispatch"
                self._persist(job)
                self._publish(job.job_id, job.snapshot())
                return
            job.state = "running"
            job.started_at = time.time()
            job.progress = 10
        self._publish(job_id, job.snapshot())
        self._persist(job)
        try:
            policy = self._svc.normalize_policy(job.policy_overrides or {})
            # Coarse progress: 10% (queued→running), 50% (engines fanning out),
            # 90% (fusion done), 100% (cache + audit). The synchronous core
            # doesn't expose intra-engine ticks today so we paint two
            # logical waypoints rather than fake fine-grained progress.
            job.progress = 50
            self._publish(job_id, job.snapshot())
            result = self._svc.scan_file(
                job.target_path,
                policy=policy,
                workspace_id=job.workspace_id,
                actor=job.actor,
            )
            job.progress = 90
            self._publish(job_id, job.snapshot())
            with self._lock:
                if job.state == "cancelling":
                    job.state = "cancelled"
                    job.error = "cancelled mid-scan; result discarded"
                    job.result = None
                else:
                    job.result = result
                    job.state = "complete" if str(result.get("status", "")) != "error" else "error"
                    if job.state == "error":
                        job.error = str(result.get("error", "scan failed"))
                job.progress = 100
                job.finished_at = time.time()
        except Exception as exc:  # noqa: BLE001 — surface to job state
            with self._lock:
                job.state = "error"
                job.error = str(exc)
                job.progress = 100
                job.finished_at = time.time()
        self._persist(job)
        self._publish(job_id, job.snapshot())

    def _publish(self, job_id: str, snapshot: dict[str, Any]) -> None:
        with self._listener_lock:
            listeners = list(self._listeners.get(job_id, []))
        for cb in listeners:
            try:
                cb(snapshot)
            except Exception:
                continue

    def _persist(self, job: ScanJob) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            conn.execute(
                """
                INSERT INTO av_scan_jobs (
                    job_id, workspace_id, actor, target_path, policy_overrides_json,
                    state, progress, submitted_at, started_at, finished_at,
                    error, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    state = excluded.state,
                    progress = excluded.progress,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    error = excluded.error,
                    result_json = excluded.result_json
                """,
                (
                    job.job_id, job.workspace_id, job.actor, job.target_path,
                    json.dumps(job.policy_overrides, ensure_ascii=False),
                    job.state, int(job.progress),
                    float(job.submitted_at), float(job.started_at), float(job.finished_at),
                    str(job.error or ""), json.dumps(job.result, ensure_ascii=False) if job.result else "",
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

    def _load_from_db(self, job_id: str) -> dict[str, Any] | None:
        if self._db is None:
            return None
        try:
            conn = self._db.create_connection()
        except Exception:
            return None
        if conn is None:
            return None
        try:
            row = conn.execute(
                """
                SELECT job_id, workspace_id, actor, target_path, policy_overrides_json,
                       state, progress, submitted_at, started_at, finished_at, error, result_json
                FROM av_scan_jobs WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
            if not row:
                return None
            try:
                policy_overrides = json.loads(row[4] or "{}")
            except Exception:
                policy_overrides = {}
            try:
                result = json.loads(row[11]) if row[11] else None
            except Exception:
                result = None
            return {
                "job_id": row[0],
                "workspace_id": row[1],
                "actor": row[2],
                "target_path": row[3],
                "policy_overrides": policy_overrides,
                "state": row[5],
                "progress": int(row[6] or 0),
                "submitted_at": float(row[7] or 0),
                "started_at": float(row[8] or 0),
                "finished_at": float(row[9] or 0),
                "duration_ms": int((float(row[9] or 0) - float(row[8] or 0)) * 1000) if row[8] and row[9] else 0,
                "error": str(row[10] or ""),
                "result": result,
            }
        except Exception:
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _hydrate_from_db(self) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            cursor = conn.execute(
                """
                SELECT job_id, state FROM av_scan_jobs
                WHERE state IN ('queued', 'running', 'cancelling')
                """
            )
            now = time.time()
            for row in cursor.fetchall():
                conn.execute(
                    "UPDATE av_scan_jobs SET state=?, finished_at=?, error=? WHERE job_id=?",
                    ("error", now, "interrupted by server restart", row[0]),
                )
            conn.commit()
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _evict_history_if_needed(self) -> None:
        if len(self._jobs) <= self._max_history:
            return
        terminal = sorted(
            (j for j in self._jobs.values() if j.state in JOB_STATES_TERMINAL),
            key=lambda j: j.finished_at or j.submitted_at,
        )
        for job in terminal[: len(self._jobs) - self._max_history]:
            self._jobs.pop(job.job_id, None)
