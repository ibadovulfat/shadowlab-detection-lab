"""Request \u2192 workspace resolution helpers + multi-tenant guardrails."""
from __future__ import annotations

from fastapi import HTTPException, Request

import api.security as security_module


def request_workspace_id(request: Request) -> str:
    """Return the workspace id stamped onto the request by auth middleware."""
    return str(getattr(request.state, "workspace_id", "default") or "default")


def require_default_workspace_for_global_scope(request: Request, feature_name: str) -> None:
    """Block features that have not been fully tenant-scoped yet outside lab.

    Some read endpoints still return cross-workspace data by design. In
    corp/prod we refuse to serve them except when the caller is scoped to the
    `default` workspace to avoid accidental data leakage across tenants.
    """
    workspace_id = request_workspace_id(request)
    profile = str(getattr(security_module.security_settings, "policy_profile", "lab") or "lab").strip().lower() or "lab"
    if profile in {"corp", "prod"} and workspace_id != "default":
        raise HTTPException(
            status_code=403,
            detail=(
                f"{feature_name} is not fully tenant-scoped yet; "
                f"use the default workspace or a tenant-scoped endpoint in the {profile} profile"
            ),
        )
