"""Shared action plumbing for desktop response/state-change paths.

Every desktop console (Antivirus / Enterprise / Intel / Network /
Security Ops / Integrations / History / Process Hunt) implements the
same four helpers around its destructive actions:

    1. `_check_action_gate(action)` — debounce + allowlist check
    2. `_capture_reason(action)` — open the structured-reason modal
       when the action is in the reason-required set
    3. `_record_audit(...)` — wrap `AuditLogStore.append` with the
       controller's actor/workspace context
    4. `_submit_async(...)` — QThread + ProcessWorker + watchdog
       timeout for non-blocking backend calls

Each controller currently re-implements these inline (~60-90 lines per
controller × 7 controllers = ~500 lines of duplicate code). This module
extracts the pattern so:

    * One audit/debounce contract across consoles → identical
      operator UX
    * One bug fix or instrumentation hook updates every console
    * A new console (e.g. WHIDS standalone) needs ~50 lines, not 200

## Migration pattern

A controller wires this up in two steps:

    from desktop._action_common import ActionGate, ReasonCapture, submit_async_call

    class MyController:
        def __init__(self, app) -> None:
            self.app = app
            self._gate = ActionGate(
                allowlist=MY_ALLOWLIST,
                debounce_seconds=1.0,
                status_bar=lambda msg: app.statusBar().showMessage(msg),
            )
            self._reason = ReasonCapture(
                reason_required=MY_REASON_REQUIRED,
                parent=app,
                on_cancel=lambda action: app.statusBar().showMessage(
                    f"`{action}` cancelled — structured reason required."
                ),
            )

Action sites then call:

    if not self._gate.check("kill"):
        return
    reason = self._reason.capture("kill")
    if reason is None:
        return  # operator cancelled the modal
    submit_async_call(
        parent=self.app,
        label="kill PID 42",
        work=lambda: self.app._post(...).json(),
        on_success=...,
        on_failure=...,
        timeout_seconds=20,
    )

The local `_record_audit` wrapper is intentionally NOT promoted into
this module — the per-controller wrappers attach console-specific
metadata (workspace, slug, severity policy) that doesn't generalize
cleanly. They stay 4-line facades over `AuditLogStore.append`.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, QTimer

try:
    from process_hunt_jobs import ProcessWorker
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker

try:
    from _response_dialog import prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason


class ActionGate:
    """Debounce + allowlist gate for response actions.

    Construct once per controller with the controller's allowlist
    and per-action debounce window. Each `check(action)` call
    returns True if the action is permitted right now, False if the
    allowlist or debounce blocks it (status-bar message is emitted
    via the supplied callback).
    """

    def __init__(
        self,
        *,
        allowlist: frozenset[str] | set[str],
        debounce_seconds: float = 1.0,
        status_bar: Callable[[str], None] | None = None,
    ) -> None:
        # Coerce to frozenset so callers can't mutate the allowlist
        # mid-flight (a real risk if the caller passes a regular set
        # they later add to).
        self._allowlist = frozenset(allowlist)
        self._debounce_seconds = max(0.0, float(debounce_seconds))
        self._status_bar = status_bar
        self._last_click: dict[str, float] = {}

    def _emit(self, message: str) -> None:
        if self._status_bar is None:
            return
        try:
            self._status_bar(message)
        except Exception:
            pass

    def check(self, action: str) -> bool:
        if action not in self._allowlist:
            self._emit(f"`{action}` is not in the allowlist; UI blocked the request.")
            return False
        now = time.time()
        last = float(self._last_click.get(action, 0.0) or 0.0)
        if now - last < self._debounce_seconds:
            self._emit(f"`{action}` is rate-limited; try again in a moment.")
            return False
        self._last_click[action] = now
        return True

    def reset(self, action: str | None = None) -> None:
        """Clear the debounce timer for one action or all of them.

        Test-only: lets a test verify gate behaviour without sleeping
        through real wall-clock debounce windows.
        """
        if action is None:
            self._last_click.clear()
        else:
            self._last_click.pop(action, None)


class ReasonCapture:
    """Wraps the structured-reason modal with a per-controller policy.

    Construct with the set of actions that REQUIRE a reason (the
    rest get a `{}` empty-dict sentinel so the audit pipeline can
    still attach metadata uniformly). Returns:

        * `dict` with `ticket_id` / `reason_category` / `reason_text` /
          `reason_summary` when the action requires a reason and the
          operator submitted the modal
        * `{}` when the action doesn't require a reason
        * `None` when the operator cancelled the modal — caller must
          abort the action
    """

    def __init__(
        self,
        *,
        reason_required: frozenset[str] | set[str],
        parent,
        on_cancel: Callable[[str], None] | None = None,
    ) -> None:
        self._reason_required = frozenset(reason_required)
        self._parent = parent
        self._on_cancel = on_cancel

    def capture(self, action: str) -> dict | None:
        if action not in self._reason_required:
            return {}
        result = prompt_response_reason(self._parent, action)
        if result is None:
            if self._on_cancel is not None:
                try:
                    self._on_cancel(action)
                except Exception:
                    pass
            return None
        ticket, category, text = result
        return {
            "ticket_id": ticket,
            "reason_category": category,
            "reason_text": text,
            "reason_summary": f"[{category}] {ticket}: {text}",
        }


def submit_async_call(
    *,
    parent: QObject,
    label: str,
    work: Callable[[], Any],
    on_success: Callable[[Any], None],
    on_failure: Callable[[str], None],
    timeout_seconds: int = 60,
    job_registry: list | None = None,
) -> tuple[QThread, ProcessWorker]:
    """Run `work` on a fresh QThread+ProcessWorker with a watchdog.

    Generic enough to replace the per-controller `_submit_async`
    helpers. Returns the (thread, worker) pair so the caller can
    optionally append to its own job registry — the registry list
    keeps PySide from garbage-collecting the thread before it
    finishes.

    `on_success` is invoked with the worker result, `on_failure` is
    invoked with a string error message, and the watchdog calls
    neither — it just emits a status-bar message via the parent's
    `statusBar()` (best-effort) and tears the thread down.
    """
    thread = QThread(parent)
    worker = ProcessWorker(work)
    worker.moveToThread(thread)
    finished = {"value": False}

    def cleanup() -> None:
        if job_registry is not None:
            try:
                job_registry.remove((thread, worker))
            except ValueError:
                pass
        thread.quit()
        thread.wait(2000)
        worker.deleteLater()
        thread.deleteLater()

    def handle_success(result: Any) -> None:
        if finished["value"]:
            return
        finished["value"] = True
        try:
            on_success(result)
        finally:
            cleanup()

    def handle_failure(message: str) -> None:
        if finished["value"]:
            return
        finished["value"] = True
        try:
            on_failure(message)
        finally:
            cleanup()

    def watchdog() -> None:
        if finished["value"]:
            return
        finished["value"] = True
        try:
            if hasattr(parent, "statusBar"):
                parent.statusBar().showMessage(f"{label} timed out after {timeout_seconds}s.")
        except Exception:
            pass
        cleanup()

    thread.started.connect(worker.run)
    worker.finished.connect(handle_success)
    worker.failed.connect(handle_failure)
    if job_registry is not None:
        job_registry.append((thread, worker))
    QTimer.singleShot(int(max(1, timeout_seconds)) * 1000, watchdog)
    thread.start()
    return thread, worker
