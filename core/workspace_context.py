from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
import os
import re


DEFAULT_WORKSPACE_ID = "default"
WORKSPACE_HEADER = "X-ShadowLab-Workspace"
WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class WorkspaceAccess:
    workspace_id: str
    allowed_workspaces: tuple[str, ...]
    explicit_required: bool
    used_default: bool
    restriction_source: str
    actor: str = ""


def normalize_workspace_id(value: str | None, *, allow_empty: bool = False) -> str:
    candidate = str(value or "").strip().lower()
    if not candidate:
        if allow_empty:
            return ""
        raise ValueError("workspace_id is required")
    if not WORKSPACE_ID_RE.fullmatch(candidate):
        raise ValueError("workspace_id must be 1-64 chars and contain only letters, digits, dot, dash, and underscore")
    return candidate


def workspace_required_for_profile(profile: str) -> bool:
    return str(profile or "").strip().lower() in {"corp", "prod"}


def filter_rows_by_workspace(rows: Iterable[dict], workspace_id: str) -> list[dict]:
    expected = normalize_workspace_id(workspace_id)
    filtered: list[dict] = []
    for row in rows:
        current = str((row or {}).get("workspace_id", DEFAULT_WORKSPACE_ID) or DEFAULT_WORKSPACE_ID).strip().lower()
        if current == expected:
            filtered.append(row)
    return filtered


def workspace_matches_row(row: dict | None, workspace_id: str) -> bool:
    if not isinstance(row, dict):
        return False
    current = str(row.get("workspace_id", DEFAULT_WORKSPACE_ID) or DEFAULT_WORKSPACE_ID).strip().lower()
    return current == normalize_workspace_id(workspace_id)


def resolve_workspace_access(
    role: str,
    requested_workspace: str | None,
    policy_profile: str,
    actor: str | None = None,
    allowed_workspaces: Iterable[str] | None = None,
) -> WorkspaceAccess:
    explicit_required = workspace_required_for_profile(policy_profile)
    requested = normalize_workspace_id(requested_workspace, allow_empty=True)
    if explicit_required and not requested:
        raise ValueError("X-ShadowLab-Workspace is required for corp/prod profiles")
    workspace_id = requested or DEFAULT_WORKSPACE_ID
    role_name = str(role or "").strip().lower() or "viewer"
    actor_name = str(actor or "").strip().lower()

    role_map = _parse_role_workspace_map(os.environ.get("SHADOWLAB_ROLE_WORKSPACES", ""))
    actor_map = _parse_role_workspace_map(os.environ.get("SHADOWLAB_ACTOR_WORKSPACES", ""))
    global_allowed = _parse_workspace_list(os.environ.get("SHADOWLAB_ALLOWED_WORKSPACES", ""))
    allowed_for_actor = actor_map.get(actor_name) if actor_name else None
    allowed_for_role = role_map.get(role_name)

    explicit_allowed = tuple(sorted({normalize_workspace_id(item) for item in (allowed_workspaces or []) if str(item).strip()}))

    if explicit_allowed:
        allowed = explicit_allowed
        restriction_source = "identity"
    elif allowed_for_actor is not None:
        allowed = tuple(sorted(allowed_for_actor))
        restriction_source = "actor"
    elif allowed_for_role is not None:
        allowed = tuple(sorted(allowed_for_role))
        restriction_source = "role"
    elif global_allowed:
        allowed = tuple(sorted(global_allowed))
        restriction_source = "global"
    elif explicit_required and role_name in {"analyst", "admin"}:
        allowed = (workspace_id,)
        restriction_source = "request"
    else:
        allowed = (DEFAULT_WORKSPACE_ID,)
        restriction_source = "default"

    if workspace_id not in allowed:
        raise ValueError(f"Workspace `{workspace_id}` is not allowed for role `{role_name}`")

    return WorkspaceAccess(
        workspace_id=workspace_id,
        allowed_workspaces=allowed,
        explicit_required=explicit_required,
        used_default=(workspace_id == DEFAULT_WORKSPACE_ID and not requested),
        restriction_source=restriction_source,
        actor=actor_name,
    )


def _parse_workspace_list(raw: str) -> set[str]:
    values: set[str] = set()
    for item in str(raw or "").split(","):
        candidate = str(item or "").strip()
        if not candidate:
            continue
        values.add(normalize_workspace_id(candidate))
    return values


def _parse_role_workspace_map(raw: str) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for chunk in str(raw or "").split(";"):
        item = str(chunk or "").strip()
        if not item or ":" not in item:
            continue
        role, workspaces = item.split(":", 1)
        role_name = str(role or "").strip().lower()
        if not role_name:
            continue
        parsed = _parse_workspace_list(workspaces.replace("|", ","))
        if parsed:
            mapping[role_name] = parsed
    return mapping
