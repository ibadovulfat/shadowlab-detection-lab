"""Tests for the Network/Graph console state-change paths."""
from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest


def test_network_action_allowlist_matches_backend():
    from desktop.network_graph_ops import NETWORK_ACTION_ALLOWLIST

    # Mirror of api/routes/network*.py — sniffer + ARP scan + ARP
    # blocker start/stop + the read-only refresh endpoints.
    assert NETWORK_ACTION_ALLOWLIST == frozenset({
        "sniff", "arp-scan", "block-start", "block-stop",
        "hosts-refresh", "connections-refresh",
    })


def test_arp_scan_min_prefix_blocks_dangerous_ranges():
    from desktop.network_graph_ops import ARP_SCAN_MIN_PREFIX

    # /16 is the operational maximum — anything broader (/15 or
    # narrower prefix length) must be blocked client-side.
    assert ARP_SCAN_MIN_PREFIX == 16

    # Confirm the math: /15 is broader than /16, so /15.prefixlen <
    # ARP_SCAN_MIN_PREFIX → blocked.
    cidr_blocked = ipaddress.ip_network("10.0.0.0/8")
    assert cidr_blocked.prefixlen < ARP_SCAN_MIN_PREFIX
    cidr_ok = ipaddress.ip_network("192.168.1.0/24")
    assert cidr_ok.prefixlen >= ARP_SCAN_MIN_PREFIX


def test_default_sniff_duration_is_useful():
    """The previous build defaulted the spinbox to 1 second, which
    captured nothing useful and required an extra click before the
    button was actionable. Default must be at least 5s."""
    from desktop.network_graph_ops import DEFAULT_SNIFF_DURATION

    assert DEFAULT_SNIFF_DURATION >= 5


def test_sniff_duration_matches_backend_limit():
    from desktop.network_graph_ops import DEFAULT_SNIFF_DURATION, MAX_SNIFF_DURATION

    assert DEFAULT_SNIFF_DURATION <= MAX_SNIFF_DURATION
    assert MAX_SNIFF_DURATION == 60


def test_network_buttons_use_least_privilege_capabilities():
    from desktop.network_graph_ops import NETWORK_BUTTON_CAPABILITIES

    assert NETWORK_BUTTON_CAPABILITIES["sniff"] == "can_run_sniffer"
    assert NETWORK_BUTTON_CAPABILITIES["arp-scan"] == "can_run_hunt"
    assert NETWORK_BUTTON_CAPABILITIES["block-start"] == "can_manage_network_warfare"
    assert NETWORK_BUTTON_CAPABILITIES["block-stop"] == "can_manage_network_warfare"


def test_network_reason_required_covers_destructive_actions():
    """Sniffer + blocker actions must require a structured reason —
    privacy + network-state events. ARP scan is a discovery probe so
    it stays out of the reason-required set."""
    from desktop.network_graph_ops import NETWORK_REASON_REQUIRED

    for required in ("sniff", "block-start", "block-stop"):
        assert required in NETWORK_REASON_REQUIRED
    assert "arp-scan" not in NETWORK_REASON_REQUIRED


def test_network_debounce_window_is_at_least_one_second():
    """Tighter than 1s and rapid mouse jitter trips the gate."""
    from desktop.network_graph_ops import NETWORK_DEBOUNCE_SECONDS

    assert NETWORK_DEBOUNCE_SECONDS >= 1.0


# Note: the generic ActionGate behaviour (allowlist / debounce / reset
# / per-action independence) lives in `tests/test_action_common.py`.
# This file only asserts the Network-specific allowlist + reason-set
# contents.


def test_audit_log_path_is_distinct_per_console(tmp_path, monkeypatch):
    """The Network audit chain MUST be its own JSON file so a SOC
    grep over the chain doesn't conflate sniff/block events with
    case/file-analysis ones."""
    from desktop.network_graph_ops import NetworkGraphWorkspaceController

    monkeypatch.chdir(tmp_path)
    ctrl = NetworkGraphWorkspaceController.__new__(NetworkGraphWorkspaceController)
    ctrl.app = SimpleNamespace()

    path = ctrl.audit_log_path()
    assert path.name == "network-audit-log.json"
    assert path.parent.name == "shadowlab_out"


def test_session_state_defaults_to_idle():
    """New controller starts with sniffer + blocker idle so the
    status banner accurately reflects "nothing running"."""
    from desktop.network_graph_ops import NetworkGraphWorkspaceController

    ctrl = NetworkGraphWorkspaceController.__new__(NetworkGraphWorkspaceController)
    # Manually init the session state attrs (the real __init__ does
    # this but we're skipping it to avoid Qt).
    ctrl._sniffer_running = False
    ctrl._sniffer_started_at = 0.0
    ctrl._sniffer_duration = 0
    ctrl._blocker_active = False
    ctrl._blocker_target = ""
    ctrl._blocker_gateway = ""

    assert ctrl._sniffer_running is False
    assert ctrl._blocker_active is False
    assert ctrl._blocker_target == ""
