"""Background worker that drains the enterprise connector queue.

Split out of `api/main.py` so the loop has a proper name, its own test
surface, and is not entangled with module-level globals. The old code kept
the thread handle, stop event, interval, and loop body as four separate
module-level statements scattered across `api/main.py` — easy to break
and impossible to test without importing the entire FastAPI app.

Usage (from `api.main._app_lifespan`):

    worker = ConnectorQueueWorker(
        enterprise_service=enterprise_service,
        observability_service=observability_service,
        logger=logger,
        enabled=connector_worker_enabled,
        interval_seconds=connector_worker_interval_seconds,
    )
    worker.start()
    try:
        yield
    finally:
        worker.stop()

`start()` is idempotent — a second call while the thread is alive is a
no-op, matching the original `if not (_thread and _thread.is_alive())`
guard.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

from api.observability import default_registry
from api.observability.metrics import TimerContext

# Metric handles. Created at module import so the per-iteration path
# stays allocation-free — otherwise the exception fast-path would churn
# the registry lock for no reason.
_ITERATION_COUNTER = default_registry.counter(
    "shadowlab_connector_queue_iterations_total",
    help="Successful connector-queue drain iterations.",
)
_ITERATION_FAILURES = default_registry.counter(
    "shadowlab_connector_queue_failures_total",
    help="Connector-queue drain iterations that raised.",
)
_ITERATION_DURATION = default_registry.histogram(
    "shadowlab_connector_queue_iteration_seconds",
    help="Wall-clock seconds spent in a single connector-queue drain.",
)


def env_worker_enabled(env_var: str = "SHADOWLAB_CONNECTOR_QUEUE_WORKER") -> bool:
    """Parse the `SHADOWLAB_CONNECTOR_QUEUE_WORKER` env var.

    Truthy values (case-insensitive): `1`, `true`, `yes`, `on`. Anything
    else — including an unset variable's default `"true"` — flips off only
    when explicitly disabled. Kept as a free function so tests can pass
    `enabled=False` directly without touching the environment.
    """
    return os.environ.get(env_var, "true").strip().lower() in {"1", "true", "yes", "on"}


def env_worker_interval_seconds(env_var: str = "SHADOWLAB_CONNECTOR_QUEUE_INTERVAL_SECONDS") -> int:
    """Parse the interval env var, clamped to a 5-second floor.

    The floor protects against operators accidentally setting `0` or a
    negative value, which would turn the loop into a CPU-burning spin.
    """
    return max(5, int(os.environ.get(env_var, "20")))


class ConnectorQueueWorker:
    """Wraps the connector-queue drain loop in a startable/stoppable object."""

    def __init__(
        self,
        *,
        enterprise_service: Any,
        observability_service: Any,
        logger: logging.Logger | None = None,
        enabled: bool = True,
        interval_seconds: int = 20,
        batch_limit: int = 50,
        thread_name: str = "connector-queue-worker",
    ) -> None:
        self._enterprise_service = enterprise_service
        self._observability_service = observability_service
        self._logger = logger or logging.getLogger(__name__)
        self._enabled = enabled
        self._interval_seconds = interval_seconds
        self._batch_limit = batch_limit
        self._thread_name = thread_name
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        """Spin up the worker thread. Returns True if it was (re)started.

        Idempotent: if a thread is already alive, this is a no-op and
        returns False — matches the original guard in `api.main`.
        """
        if not self._enabled:
            return False
        if self.is_running:
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name=self._thread_name,
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self, *, join_timeout: float | None = None) -> None:
        """Signal the worker to exit at the next wake-up.

        `join_timeout` is mostly a testing affordance; production shutdown
        relies on the daemon=True flag so the process can exit promptly
        even if the final queue batch is still in flight.
        """
        self._stop.set()
        if join_timeout is not None and self._thread is not None:
            self._thread.join(timeout=join_timeout)

    def _loop(self) -> None:
        """The drain loop itself. `Event.wait(interval)` returns True once
        `_stop.set()` is called, so the `while not ...` form both sleeps
        AND checks the stop signal in a single atomic operation.
        """
        while not self._stop.wait(self._interval_seconds):
            try:
                with TimerContext(_ITERATION_DURATION):
                    self._enterprise_service.process_connector_queue(limit=self._batch_limit)
                _ITERATION_COUNTER.inc()
            except Exception:
                # Keep the worker alive so a transient DB blip does not
                # wedge the queue forever, but surface the failure loudly
                # — previously every connector exception was silently
                # dropped, masking real outages.
                _ITERATION_FAILURES.inc()
                self._logger.exception("connector_queue_worker_iteration_failed")
                try:
                    self._observability_service.log_event("connector_queue_worker_iteration_failed")
                except Exception:
                    pass
                continue
