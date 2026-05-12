"""TOTP MFA enrollment / verification endpoints.

Each principal (`subject` from the OIDC token or the API-key role label)
enrolls once, then verifies a 6-digit TOTP code per session. Mutating
requests check `mfa_service.session_is_valid(subject, token_id)` when
`SHADOWLAB_REQUIRE_MFA_FOR_ROLES` includes the caller's role.
"""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from services import mfa_service


# Allowed characters inside the otpauth URI account label. The label is
# concatenated into a URL and then surfaced inside QR codes; CR/LF or `:`
# could split the URI and trick authenticator apps. Keep the character
# class tight on purpose.
_SUBJECT_PATTERN = r"^[A-Za-z0-9._@\-]{1,120}$"
_ACCOUNT_LABEL_PATTERN = r"^[A-Za-z0-9._@\- ]{0,64}$"


class MfaEnrollRequest(BaseModel):
    subject: str = Field(
        default="",
        max_length=120,
        pattern=r"^$|" + _SUBJECT_PATTERN[1:-1],
        description="Defaults to the calling principal.",
    )
    account_label: str = Field(
        default="",
        max_length=64,
        pattern=_ACCOUNT_LABEL_PATTERN,
        description="Optional account label embedded in the otpauth URI.",
    )


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=mfa_service.TOTP_DIGITS, max_length=mfa_service.TOTP_DIGITS, pattern=r"^\d{6}$")


class MfaRevokeRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=120, pattern=_SUBJECT_PATTERN)


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_api_key = ctx["require_api_key"]
    current_subject = ctx["current_subject"]
    SecurityContext = ctx["SecurityContext"]

    def _resolve_subject(context: Any, override: str = "") -> str:
        """Pick the subject to enroll/verify against.

        Order of preference:
        1. Explicit `subject` parameter (admin only — used to enroll a
           teammate by handle).
        2. `context.subject` (OIDC `sub` claim).
        3. `context.actor` (operator label).
        4. `context.token_id` (last resort — shape `sha256:<12hex>`).
        """
        if override:
            return override.strip().lower()
        for candidate in (
            getattr(context, "subject", "") or "",
            getattr(context, "actor", "") or "",
            getattr(context, "token_id", "") or "",
        ):
            if str(candidate).strip():
                return str(candidate).strip().lower()
        return ""

    @app.post("/auth/mfa/enroll", dependencies=[Depends(require_admin)])
    def mfa_enroll(request: Request, payload: MfaEnrollRequest) -> dict[str, Any]:
        context = getattr(request.state, "security_context", None)
        if context is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        target = (payload.subject or "").strip().lower() or _resolve_subject(context)
        if not target:
            raise HTTPException(status_code=400, detail="subject could not be resolved")
        try:
            return mfa_service.enroll(
                target,
                account_label=(payload.account_label or target),
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # IP-bound rate limit on `/auth/mfa/verify`. The subject-bound lockout
    # in `services/mfa_service` already caps per-account brute force, but
    # this stops a single client from hammering the endpoint across many
    # subjects (e.g. credential-stuffing the resolved-subject path before
    # the DB record exists). 10 attempts / 60s is far above any legitimate
    # operator pace and well below brute-force throughput.
    apply_rate_limit = ctx.get("apply_rate_limit") or ctx.get("_apply_rate_limit")

    @app.post("/auth/mfa/verify")
    def mfa_verify(
        request: Request,
        payload: MfaVerifyRequest,
        context: SecurityContext = Depends(require_api_key),
    ) -> dict[str, Any]:
        if callable(apply_rate_limit):
            apply_rate_limit(
                request,
                bucket="mfa_verify",
                detail="Too many MFA verification attempts. Slow down and retry shortly.",
            )
        target = _resolve_subject(context)
        if not target:
            raise HTTPException(status_code=400, detail="subject could not be resolved")
        token_id = getattr(context, "token_id", "") or ""
        if not token_id:
            raise HTTPException(status_code=400, detail="token_id missing from session")
        result = mfa_service.verify(target, token_id, payload.code)
        if not result.get("ok"):
            # 423 Locked when we hit the brute-force lockout, 401 otherwise,
            # so clients can distinguish "wrong code" from "you're locked out".
            status_code = 423 if result.get("reason") == "mfa_locked" else 401
            raise HTTPException(status_code=status_code, detail=result)
        return result

    @app.get("/auth/mfa/status")
    def mfa_status(
        request: Request,
        context: SecurityContext = Depends(require_api_key),
    ) -> dict[str, Any]:
        target = _resolve_subject(context)
        if not target:
            return {"enrolled": False, "verified_session": False}
        token_id = getattr(context, "token_id", "") or ""
        return mfa_service.status(target, token_id)

    @app.post("/auth/mfa/revoke", dependencies=[Depends(require_admin)])
    def mfa_revoke(payload: MfaRevokeRequest) -> dict[str, Any]:
        target = (payload.subject or "").strip().lower()
        if not target:
            raise HTTPException(status_code=400, detail="subject is required")
        ok = mfa_service.revoke(target)
        return {"ok": ok, "subject": target}
