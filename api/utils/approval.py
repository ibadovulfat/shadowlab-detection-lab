"""Enterprise change-control approval enforcement helpers.

`require_enterprise_approval` gates a mutating request behind a reserved
approval row (scoped per workspace + action). `consume_pending_approval` is
called by the middleware/finalizer to either finalize the reservation on
success or release it on failure so the same approval can be retried.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from fastapi import HTTPException, Request

import database as db


def require_enterprise_approval(
    request: Request | None,
    action_name: str,
    *,
    policy_requires_approval: Callable[[], bool],
    get_active_policy_name: Callable[[], str],
    request_workspace_id: Callable[[Request], str],
) -> None:
    """Raise 403 unless the request carries a valid, reserveable approval id."""
    if not policy_requires_approval():
        return
    if request is None:
        raise HTTPException(
            status_code=403,
            detail=f"Action `{action_name}` requires approved change control in profile `{get_active_policy_name()}`",
        )
    approval_id = str(request.headers.get("X-ShadowLab-Approval-Id", "") or "").strip()
    if not approval_id.isdigit():
        raise HTTPException(
            status_code=403,
            detail=(
                f"Action `{action_name}` requires an approved request in profile `{get_active_policy_name()}`. "
                "Provide X-ShadowLab-Approval-Id header."
            ),
        )
    now_value = time.time()
    workspace_id = request_workspace_id(request)
    conn = db.create_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        reserved = db.reserve_approval_request(
            conn, int(approval_id), action_name, now_value, workspace_id=workspace_id
        )
        if not reserved:
            approvals = db.get_approval_requests(conn, workspace_id=workspace_id)
            row = approvals[approvals["id"] == int(approval_id)]
        else:
            row = None
    finally:
        conn.close()
    if not reserved:
        if row is None or row.empty:
            raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` not found")
        item = row.iloc[0].to_dict()
        status_value = str(item.get("status", "")).lower()
        if status_value not in {"approved", "allow", "granted"}:
            raise HTTPException(
                status_code=403,
                detail=f"Approval `{approval_id}` status is `{status_value or 'unknown'}`; approved status required",
            )
        expected_action = str(item.get("action", "")).strip().lower()
        if expected_action != action_name.strip().lower():
            raise HTTPException(
                status_code=403,
                detail=f"Approval `{approval_id}` is scoped to `{expected_action or 'unknown'}` and cannot be used for `{action_name}`",
            )
        approval_workspace = str(item.get("workspace_id", "default") or "default").strip().lower()
        if approval_workspace != workspace_id:
            raise HTTPException(
                status_code=403,
                detail=f"Approval `{approval_id}` belongs to workspace `{approval_workspace}`",
            )
        expires_at = float(item.get("expires_at", 0) or 0)
        if expires_at and now_value > expires_at:
            raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` has expired")
        used_at = float(item.get("used_at", 0) or 0)
        if used_at:
            raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` has already been consumed")
        raise HTTPException(status_code=403, detail=f"Approval `{approval_id}` could not be reserved")
    request.state.pending_approval_id = int(approval_id)
    request.state.pending_approval_reserved = True


def consume_pending_approval(
    request: Request,
    status_code: int,
    *,
    observability_service: Any,
) -> None:
    """Finalize (success) or release (failure) the approval reservation for this request."""
    approval_id = getattr(request.state, "pending_approval_id", None)
    if not approval_id:
        return
    try:
        conn = db.create_connection()
        if conn is None:
            return
        try:
            if status_code >= 400:
                db.release_approval_request(conn, int(approval_id))
            else:
                db.finalize_approval_request(conn, int(approval_id), time.time())
        finally:
            conn.close()
        observability_service.log_event(
            "approval_consumed" if status_code < 400 else "approval_released",
            approval_id=int(approval_id),
            status_code=int(status_code),
        )
    except Exception:
        return
