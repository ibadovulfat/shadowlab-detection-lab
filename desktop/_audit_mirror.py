"""Shared backend-mirror helper for desktop AuditLogStore instances.

Every desktop console that owns an `AuditLogStore` can wire it up with
`install_backend_mirror(store, app, source_slug)` to get fire-and-
forget POSTs to `/audit/desktop` after every successful append. The
local file remains the source of truth — backend failures are throttled
so a missing endpoint doesn't spam the status bar.

Centralising the wiring here keeps every controller's `__init__` short
and ensures the throttle / threading semantics are identical across
consoles. Without this helper, each controller would re-implement the
same QThread + retry-throttle dance.
"""
from __future__ import annotations

import time
from typing import Callable

from PySide6.QtCore import QThread

try:
    from process_hunt_jobs import ProcessWorker as _MirrorWorker
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker as _MirrorWorker


# Throttle window for "mirror endpoint unreachable" status-bar warnings.
# A backend without /audit/desktop yet would otherwise spam the status
# bar after every action.
_WARN_THROTTLE_SECONDS = 300


class _ThrottledWarner:
    """Per-console state holder — keeps last-warning ts so the status
    bar isn't spammed when the backend endpoint isn't deployed yet."""

    def __init__(self) -> None:
        self.last_warned_at: float = 0.0
        self.async_jobs: list[tuple[QThread, _MirrorWorker]] = []


def install_backend_mirror(
    audit_store,
    app,
    *,
    source_slug: str,
) -> None:
    """Bind `audit_store.mirror_callback` to a fire-and-forget POST.

    `source_slug` is the canonical console name (`process`, `antivirus`,
    `enterprise`, `intel`, `network`, `security-ops`, `history`,
    `integrations`, `persistence`). The backend uses the slug to route
    incoming records into per-console JSONL files.
    """
    state = _ThrottledWarner()

    def _mirror(entry: dict) -> None:
        if not hasattr(app, "_post"):
            return
        payload = {"source": f"desktop:{source_slug}", "entry": entry}

        def _work() -> None:
            try:
                app._post("/audit/desktop", json=payload, timeout=5)
            except Exception as exc:
                now = time.time()
                if now < state.last_warned_at + _WARN_THROTTLE_SECONDS:
                    return
                state.last_warned_at = now
                try:
                    app.statusBar().showMessage(
                        f"Audit mirror to /audit/desktop unavailable for `{source_slug}` "
                        f"({exc.__class__.__name__}); local log still authoritative.",
                        6000,
                    )
                except Exception:
                    pass

        thread = QThread(app)
        worker = _MirrorWorker(_work)
        worker.moveToThread(thread)

        def _cleanup(*_args) -> None:
            try:
                state.async_jobs.remove((thread, worker))
            except ValueError:
                pass
            thread.quit()
            thread.wait(1500)
            worker.deleteLater()
            thread.deleteLater()

        thread.started.connect(worker.run)
        worker.finished.connect(_cleanup)
        worker.failed.connect(_cleanup)
        state.async_jobs.append((thread, worker))
        thread.start()

    audit_store.set_mirror_callback(_mirror)
