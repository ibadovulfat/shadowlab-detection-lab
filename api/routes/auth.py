"""Authentication, identity, config, health, and metrics routes."""
from __future__ import annotations

import json
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from api.observability import default_registry
from api.schemas import IdentityRevokeRequest
from services.secret_store import secret_store as _secret_store


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    db = ctx["db"]
    require_admin = ctx["require_admin"]
    require_api_key = ctx["require_api_key"]
    identity_provider = ctx["identity_provider"]
    SecurityContext = ctx["SecurityContext"]
    build_auth_context_payload = ctx["build_auth_context_payload"]
    current_actor = ctx["current_actor"]
    current_subject = ctx["current_subject"]
    can_approve_workspace = ctx["can_approve_workspace"]
    request_workspace_id = ctx["_request_workspace_id"]
    config = ctx["config"]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics", dependencies=[Depends(require_admin)])
    def metrics() -> PlainTextResponse:
        """Prometheus exposition endpoint.

        Admin-only — the same counter set covers auth failures, body-limit
        rejections, and connector-queue backlogs, which is sensitive
        operational telemetry. Scrapers need an admin API key.
        """
        return PlainTextResponse(
            default_registry.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/auth/context")
    def auth_context(
        request: Request,
        context: SecurityContext = Depends(require_api_key),
    ) -> dict[str, Any]:
        return build_auth_context_payload(context, request)

    @app.get("/auth/oidc/status", dependencies=[Depends(require_admin)])
    def auth_oidc_status() -> dict[str, Any]:
        settings = identity_provider.settings()
        metadata: dict[str, Any] = {}
        error = ""
        if settings.enabled:
            try:
                discovered = identity_provider.discovery_metadata(settings)
                metadata = {
                    "issuer": str(discovered.get("issuer", settings.issuer_url) or settings.issuer_url),
                    "jwks_uri": str(discovered.get("jwks_uri", settings.jwks_url) or settings.jwks_url),
                    "authorization_endpoint": str(discovered.get("authorization_endpoint", "") or ""),
                    "token_endpoint": str(discovered.get("token_endpoint", "") or ""),
                }
            except Exception as exc:
                error = str(exc)
        return {
            "enabled": settings.enabled,
            "issuer_url": settings.issuer_url,
            "audience": settings.audience,
            "client_id": settings.client_id,
            "workspace_claim": settings.workspace_claim,
            "role_claim": settings.role_claim,
            "approver_claim": settings.approver_claim,
            "metadata": metadata,
            "error": error,
        }

    @app.post("/auth/identity/revoke", dependencies=[Depends(require_admin)])
    def revoke_identity_session(request: Request, payload: IdentityRevokeRequest) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        actor = current_actor(request)
        subject = payload.subject or current_subject(request)
        if not subject:
            raise HTTPException(status_code=400, detail="subject is required")
        if not can_approve_workspace(request, workspace_id):
            raise HTTPException(status_code=403, detail="Current identity may not manage approvals for this workspace")
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        try:
            revocation_id = db.revoke_identity_token(
                conn,
                issuer=identity_provider.settings().issuer_url,
                subject=subject,
                token_id=payload.token_id,
                workspace_id=workspace_id,
                actor=actor,
                reason=payload.reason,
                expires_at=float(payload.expires_at or 0),
            )
        finally:
            conn.close()
        return {
            "revocation_id": revocation_id,
            "workspace_id": workspace_id,
            "subject": subject,
            "token_id": payload.token_id,
            "actor": actor,
            "reason": payload.reason,
        }

    @app.get("/auth/identity/revocations", dependencies=[Depends(require_admin)])
    def list_identity_revocations(request: Request, subject: str = "") -> list[dict[str, Any]]:
        workspace_id = request_workspace_id(request)
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        try:
            rows = db.get_identity_revocations(
                conn,
                workspace_id=workspace_id,
                subject=str(subject or "").strip(),
                issuer=identity_provider.settings().issuer_url,
            ).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return rows

    @app.get("/auth/rotation/status", dependencies=[Depends(require_admin)])
    def rotation_status() -> dict[str, Any]:
        """Read-only view of the scheduled rotation worker."""
        worker = ctx.get("rotation_worker")
        if worker is None:
            return {"enabled": False, "reason": "worker_not_configured"}
        return worker.status()

    @app.post("/auth/rotation/run", dependencies=[Depends(require_admin)])
    def rotation_run() -> dict[str, Any]:
        """Run one rotation pass synchronously. Useful for ops drills."""
        worker = ctx.get("rotation_worker")
        if worker is None:
            raise HTTPException(status_code=503, detail="Rotation worker not configured")
        return worker.trigger_now()

    @app.get("/config", dependencies=[Depends(require_admin)])
    def get_config() -> dict[str, Any]:
        # Deep-copy via JSON round-trip so the in-memory `config` dict is
        # never mutated. `secret_store.redact_config` walks the tree and
        # masks every key matching the canonical sensitive-key list
        # (api_key, authorization, client_secret, password, secret,
        # shared_key, token). The previous hand-rolled redaction only
        # covered `virustotal_api_key` and `telemetry_fabric.headers`,
        # leaving newly-added secrets exposed on each new release.
        cloned = json.loads(json.dumps(config))
        redacted = _secret_store.redact_config(cloned)
        # Belt-and-braces: also flatten the telemetry-fabric headers
        # dict (key NAMES can still be sensitive, e.g. when a vendor
        # ships a bearer-style auth header under a custom name).
        telemetry_fabric = redacted.get("telemetry_fabric") or {}
        if isinstance(telemetry_fabric.get("headers"), dict) and telemetry_fabric.get("headers"):
            telemetry_fabric["headers"] = {key: "***redacted***" for key in telemetry_fabric["headers"].keys()}
        return redacted
