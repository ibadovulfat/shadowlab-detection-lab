from __future__ import annotations

from copy import deepcopy
from typing import Any


POLICY_MATRIX: dict[str, dict[str, Any]] = {
    "lab": {
        "dangerous_actions": True,
        "network_warfare": True,
        "deception": True,
        "external_connectors": True,
        "approval_required": False,
        "workspace_mode": "single-tenant",
        "operator_notes": [
            "Use for isolated validation, canary exercises, and controlled simulation.",
            "Keep credentials and test assets separate from corporate production data.",
        ],
    },
    "corp": {
        "dangerous_actions": False,
        "network_warfare": False,
        "deception": True,
        "external_connectors": True,
        "approval_required": True,
        "workspace_mode": "team-scoped",
        "operator_notes": [
            "Require approval IDs for destructive or remote-impacting actions.",
            "Keep canary and deception activity inside approved team workspaces only.",
        ],
    },
    "prod": {
        "dangerous_actions": False,
        "network_warfare": False,
        "deception": False,
        "external_connectors": True,
        "approval_required": True,
        "workspace_mode": "tenant-isolated",
        "operator_notes": [
            "Disable offensive-style controls and use review-heavy workflows.",
            "Plan for strict workspace separation, immutable audit export, and remote approval gates.",
        ],
    },
}

WORKSPACE_GOVERNANCE: dict[str, Any] = {
    "default_workspace_id": "default",
    "rules": [
        "Every shared enterprise record should carry a workspace_id.",
        "Single-node lab mode can continue using the default workspace.",
        "Corp and prod deployments should pass explicit workspace identifiers from UI and API layers.",
    ],
}


def build_policy_matrix() -> dict[str, Any]:
    return {
        "profiles": deepcopy(POLICY_MATRIX),
        "workspace_governance": deepcopy(WORKSPACE_GOVERNANCE),
        "recommendations": [
            "Use lab for safe adversary simulation and canary exercises.",
            "Use corp to require approval for destructive containment.",
            "Use prod to disable offensive-style controls and force review-heavy workflows.",
        ],
    }
