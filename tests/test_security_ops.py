"""Tests for the Security Ops console state-change paths."""
from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_security_ops_action_allowlist_matches_backend():
    from desktop.security_ops import SECURITY_OPS_ACTION_ALLOWLIST

    # Mirror of the backend secret-rotation + integrity + YARA policy
    # endpoints — adding an action requires updating both server route
    # and this set so a stray button can't reach an undocumented path.
    assert SECURITY_OPS_ACTION_ALLOWLIST == frozenset({
        "rotate-secrets", "clear-webhook", "save-yara-policy",
        "load-yara-policy", "refresh-integrity", "export-report",
        "refresh-workspace", "refresh-yara",
    })


def test_security_ops_reason_required_covers_destructive_actions():
    from desktop.security_ops import SECURITY_OPS_REASON_REQUIRED

    # Forensically destructive actions must require a structured reason —
    # secret rotation invalidates webhooks, webhook clear silences alerts,
    # YARA policy override changes detection, export sends data off-host.
    for action in ("rotate-secrets", "clear-webhook", "save-yara-policy", "export-report"):
        assert action in SECURITY_OPS_REASON_REQUIRED


def test_security_ops_audit_log_path_distinct(tmp_path, monkeypatch):
    from desktop.security_ops import SecurityOpsWorkspaceController

    monkeypatch.chdir(tmp_path)
    ctrl = SecurityOpsWorkspaceController.__new__(SecurityOpsWorkspaceController)
    ctrl.app = SimpleNamespace()

    path = ctrl.audit_log_path()
    assert path.name == "security-ops-audit-log.json"
    assert path.parent.name == "shadowlab_out"


def test_security_ops_debounce_window_is_at_least_one_second():
    """Tighter than 1s and rapid mouse jitter trips the gate."""
    from desktop.security_ops import SECURITY_OPS_DEBOUNCE_SECONDS

    assert SECURITY_OPS_DEBOUNCE_SECONDS >= 1.0


# Note: gate / debounce / reason-empty-sentinel behaviour now lives in
# `tests/test_action_common.py` against the shared `ActionGate` and
# `ReasonCapture` classes. Per-controller tests only assert allowlist /
# reason-required CONTENTS — not the gate mechanics.
