"""Tests for the shared action plumbing (`desktop/_action_common.py`).

Each controller's `_check_action_gate` and `_capture_reason` are thin
facades over `ActionGate` and `ReasonCapture`. Testing the shared
module once removes the need to repeat the same gate/debounce/
allowlist tests across every per-controller test file.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from desktop._action_common import ActionGate, ReasonCapture


# --------------------------------------------------------------------------- #
# ActionGate
# --------------------------------------------------------------------------- #

def test_action_gate_allows_first_click_for_known_action():
    gate = ActionGate(allowlist={"kill", "scan"}, debounce_seconds=0.0)
    assert gate.check("kill") is True
    assert gate.check("scan") is True


def test_action_gate_rejects_unknown_action():
    captured: list[str] = []
    gate = ActionGate(
        allowlist={"kill"},
        debounce_seconds=0.0,
        status_bar=lambda msg: captured.append(msg),
    )
    assert gate.check("delete-everything") is False
    assert any("allowlist" in m for m in captured), captured


def test_action_gate_debounces_within_window():
    gate = ActionGate(allowlist={"kill"}, debounce_seconds=10.0)
    assert gate.check("kill") is True
    # Second click within the debounce window must be blocked.
    assert gate.check("kill") is False


def test_action_gate_per_action_independence():
    gate = ActionGate(allowlist={"kill", "isolate"}, debounce_seconds=10.0)
    assert gate.check("kill") is True
    # `isolate` cooldown is independent from `kill`.
    assert gate.check("isolate") is True
    assert gate.check("kill") is False


def test_action_gate_zero_debounce_never_blocks_repeats():
    gate = ActionGate(allowlist={"poll"}, debounce_seconds=0.0)
    for _ in range(5):
        assert gate.check("poll") is True


def test_action_gate_status_bar_callback_failure_is_swallowed():
    """If the status-bar callback raises, the gate must still return
    cleanly — the operator's UI should never crash because of an
    audit-side hiccup."""

    def boom(_msg: str) -> None:
        raise RuntimeError("status bar dead")

    gate = ActionGate(allowlist={"kill"}, debounce_seconds=10.0, status_bar=boom)
    # First click is allowed; second is blocked, which fires status_bar.
    assert gate.check("kill") is True
    # Must NOT raise even though boom() raises.
    assert gate.check("kill") is False


def test_action_gate_reset_clears_specific_action():
    gate = ActionGate(allowlist={"kill", "scan"}, debounce_seconds=10.0)
    assert gate.check("kill") is True
    assert gate.check("kill") is False
    gate.reset("kill")
    # After reset for kill, it's allowed again.
    assert gate.check("kill") is True
    # `scan` was never clicked — reset is a no-op for it.
    assert gate.check("scan") is True


def test_action_gate_reset_all_clears_every_action():
    gate = ActionGate(allowlist={"kill", "scan"}, debounce_seconds=10.0)
    assert gate.check("kill") is True
    assert gate.check("scan") is True
    gate.reset()  # no arg → clear all
    assert gate.check("kill") is True
    assert gate.check("scan") is True


def test_action_gate_allowlist_is_immutable_after_construction():
    """Caller passing a regular set shouldn't be able to mutate the
    allowlist mid-flight by appending to their original reference."""
    initial = {"kill"}
    gate = ActionGate(allowlist=initial, debounce_seconds=0.0)
    initial.add("new-action")
    # The new action is NOT visible to the gate.
    assert gate.check("new-action") is False
    assert gate.check("kill") is True


# --------------------------------------------------------------------------- #
# ReasonCapture
# --------------------------------------------------------------------------- #

def test_reason_capture_returns_empty_dict_for_non_required_action():
    """Actions outside the reason-required set get an empty dict
    sentinel. Audit pipelines can still attach metadata uniformly
    without forcing the operator through a modal for read-only work."""
    capture = ReasonCapture(
        reason_required=frozenset({"kill"}),
        parent=None,
    )
    assert capture.capture("readiness") == {}
    assert capture.capture("status-poll") == {}


def test_reason_capture_calls_on_cancel_when_modal_dismissed(monkeypatch):
    cancelled: list[str] = []
    capture = ReasonCapture(
        reason_required=frozenset({"kill"}),
        parent=None,
        on_cancel=lambda action: cancelled.append(action),
    )

    # Stub the modal so we don't open a real Qt dialog headless.
    monkeypatch.setattr("desktop._action_common.prompt_response_reason", lambda _parent, _action: None)
    result = capture.capture("kill")
    assert result is None
    assert cancelled == ["kill"]


def test_reason_capture_returns_structured_dict_when_modal_submitted(monkeypatch):
    capture = ReasonCapture(
        reason_required=frozenset({"kill"}),
        parent=None,
    )

    monkeypatch.setattr(
        "desktop._action_common.prompt_response_reason",
        lambda _parent, _action: ("SOC-99", "ioc-match", "active beaconing observed"),
    )
    result = capture.capture("kill")
    assert result == {
        "ticket_id": "SOC-99",
        "reason_category": "ioc-match",
        "reason_text": "active beaconing observed",
        "reason_summary": "[ioc-match] SOC-99: active beaconing observed",
    }


def test_reason_capture_on_cancel_failure_is_swallowed(monkeypatch):
    """A buggy on_cancel callback must not break the action flow."""

    def boom(_action: str) -> None:
        raise RuntimeError("on_cancel raised")

    capture = ReasonCapture(
        reason_required=frozenset({"kill"}),
        parent=None,
        on_cancel=boom,
    )
    monkeypatch.setattr("desktop._action_common.prompt_response_reason", lambda _p, _a: None)
    # Must NOT raise even though the cancel callback raises.
    assert capture.capture("kill") is None
