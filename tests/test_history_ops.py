from __future__ import annotations

from types import SimpleNamespace

import pytest

from desktop.history_ops import (
    HistoryWorkspaceController,
    INCIDENT_STATUS_ALLOWLIST,
    INCIDENT_TERMINAL_STATES,
)


def test_incident_status_allowlist_matches_backend():
    """Mirror of /incidents PATCH server-side accepted set.

    Adding a new state requires updating BOTH the backend route and
    this allowlist; otherwise the desktop will block the update with
    a clear status-bar message.
    """
    assert INCIDENT_STATUS_ALLOWLIST == frozenset({
        "open", "investigating", "contained", "closed",
    })


def test_terminal_states_require_reason():
    # Closing or containing flips a state machine that drives reporting,
    # SLA timers, and customer-facing dashboards. These two states
    # always trigger the structured-reason modal.
    assert "closed" in INCIDENT_TERMINAL_STATES
    assert "contained" in INCIDENT_TERMINAL_STATES
    assert "open" not in INCIDENT_TERMINAL_STATES
    assert "investigating" not in INCIDENT_TERMINAL_STATES


def test_passes_incident_filter_status_and_severity():
    # Build a minimal controller stub — _passes_incident_filter only
    # needs the filter dict, not Qt widgets.
    ctrl = HistoryWorkspaceController.__new__(HistoryWorkspaceController)
    ctrl._incident_filters = {"status": "open", "severity": "high"}

    assert ctrl._passes_incident_filter({"status": "open", "severity": "high"}) is True
    assert ctrl._passes_incident_filter({"status": "closed", "severity": "high"}) is False
    assert ctrl._passes_incident_filter({"status": "open", "severity": "low"}) is False


def test_passes_incident_filter_all_means_no_constraint():
    ctrl = HistoryWorkspaceController.__new__(HistoryWorkspaceController)
    ctrl._incident_filters = {"status": "all", "severity": "all"}

    for item in (
        {"status": "open", "severity": "high"},
        {"status": "closed", "severity": "low"},
        {"status": "investigating", "severity": "critical"},
    ):
        assert ctrl._passes_incident_filter(item) is True


def test_filter_update_is_lower_cased():
    ctrl = HistoryWorkspaceController.__new__(HistoryWorkspaceController)
    ctrl._incident_filters = {"status": "all", "severity": "all"}
    ctrl._incident_inventory = []
    ctrl.app = SimpleNamespace(inc_table=SimpleNamespace(setRowCount=lambda _n: None))
    ctrl.app.incident_filter_status_label = SimpleNamespace(setText=lambda _t: None)
    ctrl._update_incident_filter("status", "  CLOSED  ")
    assert ctrl._incident_filters["status"] == "closed"


def test_audit_log_path_is_distinct_from_other_consoles(tmp_path, monkeypatch):
    # The History audit chain must NOT collide with the Antivirus or
    # Process consoles' on-disk file — each console grep-able alone.
    monkeypatch.chdir(tmp_path)
    ctrl = HistoryWorkspaceController.__new__(HistoryWorkspaceController)
    ctrl.app = SimpleNamespace()

    path = ctrl.audit_log_path()
    assert path.name == "history-audit-log.json"
    assert path.parent.name == "shadowlab_out"
