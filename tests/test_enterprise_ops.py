from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from desktop.enterprise_ops import (
    CASE_PRIORITY_ALLOWLIST,
    ENTERPRISE_DEBOUNCE_SECONDS,
    ENTERPRISE_REASON_REQUIRED_ACTIONS,
    EnterpriseWorkspaceController,
    _default_mitre_bundle_path,
)


def test_priority_allowlist_matches_combo_values():
    # The combo box exposes priority values back to the backend; this
    # set is mirrored client-side so a stray button can't POST an
    # unsupported value.
    assert CASE_PRIORITY_ALLOWLIST == frozenset({"low", "medium", "high", "critical"})


def test_reason_required_actions_cover_destructive_workflow():
    """All compliance-critical case actions must require structured reason.

    Adding a destructive action without bringing it into this set
    silently bypasses the audit chain — which is exactly the failure
    mode this allowlist exists to prevent.
    """
    for required in ("assign", "approval", "export-report", "purple-replay"):
        assert required in ENTERPRISE_REASON_REQUIRED_ACTIONS, (
            f"Action `{required}` should require a structured response reason."
        )


def test_default_mitre_bundle_path_is_repo_relative():
    # The previous build hard-coded a path under
    # `C:/Users/ulfat/...` which broke on every machine that wasn't
    # `ulfat`. The replacement must resolve to a path INSIDE the
    # repository, never a user-named absolute path.
    path = _default_mitre_bundle_path()
    assert isinstance(path, Path)
    repo_root = Path(__file__).resolve().parent.parent
    # Path lives below the repo regardless of whether it currently
    # exists on disk.
    assert str(path).startswith(str(repo_root)), (
        f"MITRE bundle default {path} should be repo-relative, not a hardcoded user path."
    )


def test_default_mitre_bundle_path_does_not_reference_unknown_users():
    path_str = str(_default_mitre_bundle_path()).lower()
    # The previous bug embedded "ulfat" — this assertion ensures the
    # regression doesn't sneak back in.
    for forbidden in ("ulfat", "users\\anonymous", "/home/"):
        assert forbidden not in path_str, (
            f"Default MITRE bundle path leaks `{forbidden}` from a developer's machine."
        )


def test_audit_log_path_is_distinct_per_console(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctrl = EnterpriseWorkspaceController.__new__(EnterpriseWorkspaceController)
    ctrl.app = SimpleNamespace()

    path = ctrl.audit_log_path()
    assert path.name == "enterprise-audit-log.json"
    assert path.parent.name == "shadowlab_out"


# Note: ActionGate behaviour (debounce / per-action independence) now
# lives in `tests/test_action_common.py` against the shared class. The
# Enterprise-specific assertions below cover only the Enterprise
# allowlist + reason-required contents.


def test_action_gate_constant_is_at_least_one_second():
    # Tighter than this and rapid mouse jitter trips the gate.
    assert ENTERPRISE_DEBOUNCE_SECONDS >= 1.0
