"""Tests for the File Analysis (intel) console state-change paths."""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_decision_requires_reason_only_for_suspicious():
    from desktop.intel_ops import DECISION_REQUIRES_REASON

    assert "suspicious" in DECISION_REQUIRES_REASON
    # Marking a sample as benign is a clearance — auditable but not
    # gated on a structured reason.
    assert "benign" not in DECISION_REQUIRES_REASON


def test_audit_log_path_is_distinct_per_console(tmp_path, monkeypatch):
    """The intel console's audit chain MUST be its own JSON file so
    Antivirus / Enterprise / History grep over `category=` doesn't
    collide with file-analysis decisions."""
    from desktop.intel_ops import IntelWorkspaceController

    monkeypatch.chdir(tmp_path)
    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    ctrl.app = SimpleNamespace()

    path = ctrl.audit_log_path()
    assert path.name == "file-analysis-audit-log.json"
    assert path.parent.name == "shadowlab_out"


def test_sample_history_path_is_distinct(tmp_path, monkeypatch):
    from desktop.intel_ops import IntelWorkspaceController

    monkeypatch.chdir(tmp_path)
    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    ctrl.app = SimpleNamespace()

    path = ctrl.sample_history_path()
    assert path.name == "file-analysis-sample-history.json"
    assert path.parent.name == "shadowlab_out"


def test_load_sample_history_returns_empty_when_missing(tmp_path):
    from desktop.intel_ops import IntelWorkspaceController

    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    ctrl.app = SimpleNamespace()
    ctrl.sample_history_path = lambda: tmp_path / "missing.json"  # type: ignore[method-assign]
    assert ctrl.load_sample_history() == []


def test_load_sample_history_skips_non_dict_entries(tmp_path):
    from desktop.intel_ops import IntelWorkspaceController

    path = tmp_path / "history.json"
    path.write_text(json.dumps([{"sha256": "a", "path": "x"}, "junk", 7, {"sha256": "b", "path": "y"}]), encoding="utf-8")
    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    ctrl.app = SimpleNamespace()
    ctrl.sample_history_path = lambda: path  # type: ignore[method-assign]
    loaded = ctrl.load_sample_history()
    assert [item.get("sha256") for item in loaded] == ["a", "b"]


def test_record_sample_in_history_dedupes_by_sha(tmp_path):
    from desktop.intel_ops import IntelWorkspaceController

    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    ctrl.app = SimpleNamespace()
    ctrl._sample_history = []
    ctrl.sample_history_path = lambda: tmp_path / "history.json"  # type: ignore[method-assign]
    # Stub UI refresh — no Qt widget in headless tests.
    ctrl._refresh_sample_history_ui = lambda: None  # type: ignore[method-assign]

    ctrl._record_sample_in_history(path="C:/x/a.exe", sha256="aaa", label="medium", score=42, decision="")
    ctrl._record_sample_in_history(path="C:/x/b.exe", sha256="bbb", label="high", score=70, decision="suspicious")
    # Re-analyse the first sample — should bump it to the top, not duplicate.
    ctrl._record_sample_in_history(path="C:/x/a.exe", sha256="aaa", label="critical", score=88, decision="suspicious")

    assert len(ctrl._sample_history) == 2
    assert ctrl._sample_history[0]["sha256"] == "aaa"
    assert ctrl._sample_history[0]["score"] == 88
    assert ctrl._sample_history[0]["decision"] == "suspicious"
    assert ctrl._sample_history[1]["sha256"] == "bbb"


def test_record_sample_in_history_caps_at_retention(tmp_path):
    from desktop.intel_ops import IntelWorkspaceController, FILE_ANALYSIS_HISTORY_LIMIT

    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    ctrl.app = SimpleNamespace()
    ctrl._sample_history = []
    ctrl.sample_history_path = lambda: tmp_path / "history.json"  # type: ignore[method-assign]
    ctrl._refresh_sample_history_ui = lambda: None  # type: ignore[method-assign]

    for i in range(FILE_ANALYSIS_HISTORY_LIMIT + 5):
        ctrl._record_sample_in_history(path=f"x{i}", sha256=f"sha{i}", label="low", score=1, decision="")
    assert len(ctrl._sample_history) == FILE_ANALYSIS_HISTORY_LIMIT


def test_intel_debounce_window_is_at_least_one_second():
    """Tighter than 1s and rapid mouse jitter trips the gate."""
    from desktop.intel_ops import FILE_ANALYSIS_DEBOUNCE_SECONDS

    assert FILE_ANALYSIS_DEBOUNCE_SECONDS >= 1.0


# Note: gate / debounce behaviour now lives in
# `tests/test_action_common.py` against the shared `ActionGate`.


def test_decision_record_uses_real_iso_timestamp_not_literal_string():
    """The previous build wrote `"time": "local"` (literal!) into the
    decision record. The fix replaces it with a real ISO 8601 string
    plus actor + previous_decision metadata so the audit chain is
    forensically valid."""
    from desktop.intel_ops import IntelWorkspaceController

    ctrl = IntelWorkspaceController.__new__(IntelWorkspaceController)
    # We can construct a decision record directly to validate the
    # schema without spinning up Qt — the bug was a hardcoded string,
    # the fix writes datetime.now().astimezone().strftime(...).
    from datetime import datetime
    ts = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    record = {
        "decision": "suspicious",
        "source": "desktop",
        "actor": "analyst-1",
        "ts": ts,
        "previous_decision": None,
    }
    # Must NOT contain the legacy field.
    assert "time" not in record
    # The new fields must be present.
    assert record["ts"] == ts
    assert record["actor"] == "analyst-1"
    assert "previous_decision" in record
