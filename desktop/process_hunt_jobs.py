"""Worker + timeout helpers for the Process Hunt console.

Pulled out of `process_hunt_ops.py` so the QObject/Signal plumbing
lives next to the timeout-budget math that bulk operations rely on.
"""
from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, Signal


class ProcessWorker(QObject):
    """Tiny QObject worker that runs a no-arg callable and emits the result.

    Lives in its own module so the controller's `run_async_job` can
    schedule work without importing Qt-internal threading details
    inline.
    """

    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, work: Callable[[], Any]) -> None:
        super().__init__()
        self.work = work

    def run(self) -> None:
        try:
            self.finished.emit(self.work())
        except Exception as exc:
            self.failed.emit(str(exc))


def bulk_scan_timeout(per_call_seconds: int, count: int, *, total_cap: int = 600) -> int:
    """Compute a safe watchdog timeout for an N-call bulk operation.

    Replaces the previous `len(pids) * 70` formula — for 100 PIDs that
    expanded to a 7000-second UI timeout, while the backend caps each
    call at ~60s. The new policy: budget per-call slack on top of the
    largest single call, but never exceed `total_cap` (default 10
    minutes) so the UI watchdog still fires within a coffee break if
    the backend hangs.
    """
    base = max(60, int(per_call_seconds))
    expected = base + max(0, int(count) - 1) * 5
    return min(int(total_cap), max(base, expected))
