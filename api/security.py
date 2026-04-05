from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl

import database as db
from core.policy_matrix import POLICY_MATRIX
from core.workspace_context import WORKSPACE_HEADER, workspace_required_for_profile, resolve_workspace_access
from fastapi import Depends, Header, HTTPException, Request, status
from services.identity_provider import IdentityPrincipal, identity_provider


@dataclass(frozen=True)
class SecuritySettings:
    api_key: str
    api_key_sha256: str
    api_key_role: str
    api_keys: dict[str, str]
    api_keys_sha256: dict[str, str]
    auth_required: bool
    require_tls: bool
    enable_dangerous_actions: bool
    enable_network_warfare: bool
    allow_destructive_file_delete: bool
    allowed_origins: list[str]
    protected_process_names: list[str]
    policy_profile: str
    noauth_default_role: str
    oidc_enabled: bool


@dataclass(frozen=True)
class SecurityContext:
    token: str
    role: str
    actor: str = ""
    workspace_id: str = "default"
    allowed_workspaces: tuple[str, ...] = ("default",)
    approval_workspaces: tuple[str, ...] = ()
    subject: str = ""
    auth_source: str = "api_key"
    token_id: str = ""
    session_expires_at: float = 0.0


TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_ROLE = "viewer"
ALLOWED_ROLES = {"viewer", "analyst", "admin"}
ALLOWED_POLICY_PROFILES = set(POLICY_MATRIX.keys())
AUTH_FAILURE_LIMIT = 8
AUTH_FAILURE_WINDOW_SECONDS = 60
DANGEROUS_ACTION_LIMIT = 6
DANGEROUS_ACTION_WINDOW_SECONDS = 60
_RATE_LIMIT_BUCKETS: dict[str, list[float]] = {}
_SIGNATURE_NONCES: dict[str, float] = {}
SIGNED_REQUEST_WINDOW_SECONDS = 300
logger = logging.getLogger(__name__)
POLICY_PROFILES = POLICY_MATRIX


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def _normalize_origins(raw: str | None) -> list[str]:
    if not raw:
        return ["http://127.0.0.1", "http://localhost"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def _normalize_process_names(raw: str | None) -> list[str]:
    if not raw:
        return ["lsass.exe", "wininit.exe", "services.exe", "csrss.exe"]
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _parse_role_keys(raw: str | None, *, field_name: str, hashed: bool = False) -> dict[str, str]:
    if not raw:
        return {}
    parsed: dict[str, str] = {}
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"{field_name} entries must use role:value format")
        role, token = item.split(":", 1)
        role = role.strip().lower()
        token = token.strip()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"{field_name} contains unsupported role: {role}")
        if role in parsed:
            raise ValueError(f"{field_name} contains duplicate role: {role}")
        if not token:
            raise ValueError(f"{field_name} contains an empty token for role: {role}")
        if hashed:
            if not _is_sha256_hex(token):
                raise ValueError(f"{field_name} contains an invalid SHA-256 digest for role: {role}")
            token = token.lower()
        parsed[role] = token
    return parsed


def _is_sha256_hex(value: str) -> bool:
    candidate = value.strip().lower()
    return len(candidate) == 64 and all(ch in "0123456789abcdef" for ch in candidate)


def _validate_settings(settings: SecuritySettings) -> SecuritySettings:
    if settings.api_key and settings.api_keys:
        raise ValueError("Configure either SHADOWLAB_API_KEY or SHADOWLAB_API_KEYS, not both")
    if settings.api_key_sha256 and settings.api_keys_sha256:
        raise ValueError("Configure either SHADOWLAB_API_KEY_SHA256 or SHADOWLAB_API_KEYS_SHA256, not both")
    if (settings.api_key or settings.api_keys) and (settings.api_key_sha256 or settings.api_keys_sha256):
        raise ValueError("Use raw API keys or SHA-256 API keys, not both at the same time")
    if settings.api_key_sha256 and not _is_sha256_hex(settings.api_key_sha256):
        raise ValueError("SHADOWLAB_API_KEY_SHA256 must be a valid 64-character SHA-256 digest")
    if settings.api_key_role not in ALLOWED_ROLES:
        raise ValueError("SHADOWLAB_API_KEY_ROLE must be one of: viewer, analyst, admin")
    if settings.auth_required and not any(
        [settings.api_key, settings.api_key_sha256, settings.api_keys, settings.api_keys_sha256, settings.oidc_enabled]
    ):
        raise ValueError("SHADOWLAB_REQUIRE_AUTH=true requires at least one API key or OIDC configuration")
    if settings.require_tls and not settings.auth_required:
        logger.warning("TLS is required while authentication is disabled; unauthenticated traffic will still be restricted to viewer role.")
    if settings.policy_profile not in ALLOWED_POLICY_PROFILES:
        raise ValueError("SHADOWLAB_POLICY_PROFILE must be one of: lab, corp, prod")
    if settings.noauth_default_role not in ALLOWED_ROLES:
        raise ValueError("SHADOWLAB_NOAUTH_DEFAULT_ROLE must be one of: viewer, analyst, admin")
    if not settings.auth_required and settings.noauth_default_role != DEFAULT_ROLE:
        raise ValueError("SHADOWLAB_NOAUTH_DEFAULT_ROLE must remain viewer when authentication is disabled")
    if settings.oidc_enabled and not os.environ.get("SHADOWLAB_OIDC_ISSUER_URL", "").strip() and not os.environ.get("SHADOWLAB_OIDC_DISCOVERY_URL", "").strip():
        raise ValueError("OIDC requires SHADOWLAB_OIDC_ISSUER_URL or SHADOWLAB_OIDC_DISCOVERY_URL")
    return settings


def load_security_settings() -> SecuritySettings:
    settings = SecuritySettings(
        api_key=os.environ.get("SHADOWLAB_API_KEY", "").strip(),
        api_key_sha256=os.environ.get("SHADOWLAB_API_KEY_SHA256", "").strip().lower(),
        api_key_role=os.environ.get("SHADOWLAB_API_KEY_ROLE", DEFAULT_ROLE).strip().lower() or DEFAULT_ROLE,
        api_keys=_parse_role_keys(os.environ.get("SHADOWLAB_API_KEYS"), field_name="SHADOWLAB_API_KEYS"),
        api_keys_sha256=_parse_role_keys(
            os.environ.get("SHADOWLAB_API_KEYS_SHA256"),
            field_name="SHADOWLAB_API_KEYS_SHA256",
            hashed=True,
        ),
        auth_required=False,
        require_tls=_as_bool(os.environ.get("SHADOWLAB_REQUIRE_TLS"), False),
        enable_dangerous_actions=_as_bool(os.environ.get("SHADOWLAB_ENABLE_DANGEROUS_ACTIONS"), False),
        enable_network_warfare=_as_bool(os.environ.get("SHADOWLAB_ENABLE_NETWORK_WARFARE"), False),
        allow_destructive_file_delete=_as_bool(os.environ.get("SHADOWLAB_ALLOW_FILE_DELETE"), False),
        allowed_origins=_normalize_origins(os.environ.get("SHADOWLAB_ALLOWED_ORIGINS")),
        protected_process_names=_normalize_process_names(os.environ.get("SHADOWLAB_PROTECTED_PROCESS_NAMES")),
        policy_profile=os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab").strip().lower() or "lab",
        noauth_default_role=os.environ.get("SHADOWLAB_NOAUTH_DEFAULT_ROLE", DEFAULT_ROLE).strip().lower() or DEFAULT_ROLE,
        oidc_enabled=identity_provider.enabled(),
    )
    auth_required = _as_bool(
        os.environ.get("SHADOWLAB_REQUIRE_AUTH"),
        bool(settings.api_key or settings.api_key_sha256 or settings.api_keys or settings.api_keys_sha256 or settings.oidc_enabled),
    )
    effective_noauth_role = settings.noauth_default_role if auth_required else DEFAULT_ROLE
    validated = _validate_settings(
        SecuritySettings(
            api_key=settings.api_key,
            api_key_sha256=settings.api_key_sha256,
            api_key_role=settings.api_key_role,
            api_keys=settings.api_keys,
            api_keys_sha256=settings.api_keys_sha256,
            auth_required=auth_required,
            require_tls=settings.require_tls,
            enable_dangerous_actions=settings.enable_dangerous_actions,
            enable_network_warfare=settings.enable_network_warfare,
            allow_destructive_file_delete=settings.allow_destructive_file_delete,
            allowed_origins=settings.allowed_origins,
            protected_process_names=settings.protected_process_names,
            policy_profile=settings.policy_profile,
            noauth_default_role=effective_noauth_role,
            oidc_enabled=settings.oidc_enabled,
        )
    )
    if not validated.auth_required:
        logger.warning("ShadowLab authentication is disabled; unauthenticated requests will be limited to the viewer role.")
    return validated


security_settings = load_security_settings()


def build_capabilities(role: str, settings: SecuritySettings | None = None) -> dict[str, bool]:
    active = settings or security_settings
    profile = POLICY_PROFILES.get(active.policy_profile, POLICY_PROFILES["lab"])
    is_analyst = role in {"analyst", "admin"}
    is_admin = role == "admin"
    return {
        "can_run_monitor": is_analyst,
        "can_run_hunt": is_analyst,
        "can_manage_incidents": is_analyst,
        "can_view_persistence": is_analyst,
        "can_view_quarantine": is_analyst,
        "can_view_deception": is_analyst,
        "can_view_evidence": is_analyst,
        "can_manage_persistence": is_admin and active.enable_dangerous_actions and bool(profile.get("dangerous_actions", False)),
        "can_manage_process_actions": is_admin and active.enable_dangerous_actions and bool(profile.get("dangerous_actions", False)),
        "can_run_triage": is_analyst,
        "can_manage_quarantine": is_admin and active.enable_dangerous_actions and bool(profile.get("dangerous_actions", False)),
        "can_manage_alerts": is_admin and active.enable_dangerous_actions,
        "can_manage_deception": is_admin and bool(profile.get("deception", False)),
        "can_capture_evidence": is_analyst,
        "can_delete_evidence": is_admin and active.enable_dangerous_actions and active.allow_destructive_file_delete and bool(profile.get("dangerous_actions", False)),
        "can_run_sniffer": is_analyst,
        "can_manage_network_warfare": is_admin and active.enable_network_warfare and active.enable_dangerous_actions and bool(profile.get("network_warfare", False)),
        "can_manage_integrations": is_admin,
        "can_run_scenarios": is_admin,
    }


def build_auth_context_payload(context: SecurityContext, request: Request | None = None) -> dict[str, object]:
    return {
        "role": context.role,
        "actor": context.actor,
        "subject": context.subject,
        "auth_source": context.auth_source,
        "workspace_id": context.workspace_id,
        "allowed_workspaces": list(context.allowed_workspaces),
        "approval_workspaces": list(context.approval_workspaces),
        "auth_required": security_settings.auth_required,
        "client_ip": _client_ip(request) if request is not None else "",
        "features": {
            "dangerous_actions_enabled": security_settings.enable_dangerous_actions,
            "network_warfare_enabled": security_settings.enable_network_warfare,
            "destructive_file_delete_enabled": security_settings.allow_destructive_file_delete,
            "protected_process_names": security_settings.protected_process_names,
            "policy_profile": security_settings.policy_profile,
            "policy": get_active_policy(),
            "workspace_header": WORKSPACE_HEADER,
            "workspace_explicit_required": workspace_required_for_profile(security_settings.policy_profile),
            "oidc_enabled": security_settings.oidc_enabled,
        },
        "capabilities": build_capabilities(context.role),
    }


def get_active_policy_name() -> str:
    return security_settings.policy_profile


def get_active_policy() -> dict[str, bool]:
    return POLICY_PROFILES.get(get_active_policy_name(), POLICY_PROFILES["lab"])


def policy_requires_approval() -> bool:
    return bool(get_active_policy().get("approval_required", False))


def policy_allows_deception() -> bool:
    return bool(get_active_policy().get("deception", False))


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_shadowlab_workspace: str | None = Header(default=None),
    x_shadowlab_actor: str | None = Header(default=None),
) -> SecurityContext:
    if request.url.path in {"/health"}:
        return SecurityContext(token="", role="public")
    bearer_token = _extract_bearer_token(authorization)
    provided = x_api_key or bearer_token
    if not security_settings.auth_required:
        if provided:
            resolved = _resolve_context(provided)
            if resolved is None and bearer_token and security_settings.oidc_enabled:
                resolved = _resolve_oidc_context(bearer_token)
            if resolved is not None:
                resolved = _attach_workspace_context(resolved, x_shadowlab_workspace, x_shadowlab_actor, request)
                request.state.security_context = resolved
                request.state.workspace_id = resolved.workspace_id
                _log_auth_event("auth_success", "allowed", resolved.role, _client_ip(request), request.url.path, "authenticated (auth disabled)", workspace_id=resolved.workspace_id)
                return resolved
            context = _attach_workspace_context(SecurityContext(token="", role="viewer", actor=_normalize_actor(x_shadowlab_actor)), x_shadowlab_workspace, x_shadowlab_actor, request)
            request.state.security_context = context
            request.state.workspace_id = context.workspace_id
            _log_auth_event("auth_failure", "denied", context.role, _client_ip(request), request.url.path, "invalid_api_key_auth_disabled", workspace_id=context.workspace_id)
            return context
        context = _attach_workspace_context(SecurityContext(token="", role=security_settings.noauth_default_role, actor=_normalize_actor(x_shadowlab_actor)), x_shadowlab_workspace, x_shadowlab_actor, request)
        request.state.security_context = context
        request.state.workspace_id = context.workspace_id
        return context

    _enforce_auth_failure_limit(request)
    if not provided:
        _record_auth_failure(request, detail="missing_api_key")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    context = _resolve_context(provided)
    if context is None and bearer_token and security_settings.oidc_enabled:
        context = _resolve_oidc_context(bearer_token)
    if context is None:
        _record_auth_failure(request, detail="invalid_api_key")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    context = _attach_workspace_context(context, x_shadowlab_workspace, x_shadowlab_actor, request)
    request.state.security_context = context
    request.state.workspace_id = context.workspace_id
    _log_auth_event("auth_success", "allowed", context.role, _client_ip(request), request.url.path, "authenticated", workspace_id=context.workspace_id)
    return context


async def require_analyst_or_admin(
    request: Request,
    context: SecurityContext = Depends(require_api_key),
) -> SecurityContext:
    if context.role not in {"analyst", "admin"}:
        _log_auth_event(
            "authz_denied",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Analyst or admin role required",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst or admin role required")
    if request.method.upper() in {"POST", "PATCH", "DELETE"}:
        await _require_signed_request(request, context)
    return context


async def require_admin(
    request: Request,
    context: SecurityContext = Depends(require_api_key),
) -> SecurityContext:
    if context.role != "admin":
        _log_auth_event(
            "authz_denied",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Admin role required",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    if request.method.upper() in {"POST", "PATCH", "DELETE"}:
        await _require_signed_request(request, context)
    return context


def ensure_dangerous_actions_enabled(request: Request) -> None:
    _enforce_request_rate_limit(
        request,
        bucket="dangerous",
        limit=DANGEROUS_ACTION_LIMIT,
        window_seconds=DANGEROUS_ACTION_WINDOW_SECONDS,
        detail="Too many dangerous action attempts. Slow down and retry shortly.",
    )
    if not security_settings.enable_dangerous_actions:
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            "Dangerous host response actions are disabled by policy",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dangerous host response actions are disabled by policy",
        )
    if not bool(get_active_policy().get("dangerous_actions", False)):
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            f"Dangerous actions disabled by active profile: {get_active_policy_name()}",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Dangerous actions are disabled by active policy profile: {get_active_policy_name()}",
        )
def ensure_network_warfare_enabled(request: Request) -> None:
    _enforce_request_rate_limit(
        request,
        bucket="network_warfare",
        limit=DANGEROUS_ACTION_LIMIT,
        window_seconds=DANGEROUS_ACTION_WINDOW_SECONDS,
        detail="Too many network warfare attempts. Slow down and retry shortly.",
    )
    if not security_settings.enable_network_warfare:
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            "Network warfare controls are disabled by policy",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Network warfare controls are disabled by policy",
        )
    if not bool(get_active_policy().get("network_warfare", False)):
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            f"Network warfare disabled by active profile: {get_active_policy_name()}",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Network warfare controls are disabled by active policy profile: {get_active_policy_name()}",
        )


def ensure_delete_enabled(request: Request) -> None:
    if not security_settings.allow_destructive_file_delete:
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            "Destructive file deletion is disabled by policy",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Destructive file deletion is disabled by policy",
        )


def ensure_deception_enabled(request: Request) -> None:
    if not policy_allows_deception():
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            f"Deception controls disabled by active profile: {get_active_policy_name()}",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Deception controls are disabled by active policy profile: {get_active_policy_name()}",
        )


def safe_child_path(base_dir: Path, filename: str, allowed_suffixes: Iterable[str] | None = None) -> Path:
    if not filename or Path(filename).name != filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    target = (base_dir / filename).resolve()
    resolved_base = base_dir.resolve()
    if resolved_base not in target.parents and target != resolved_base:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path traversal rejected")
    if allowed_suffixes:
        suffix = target.suffix.lower()
        if suffix not in {item.lower() for item in allowed_suffixes}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File type not allowed")
    return target


def enforce_process_action_policy(request: Request, process_name: str) -> None:
    lowered = (process_name or "").strip().lower()
    if lowered and lowered in set(security_settings.protected_process_names):
        _log_auth_event(
            "policy_denied",
            "denied",
            _context_role(request),
            _client_ip(request),
            request.url.path,
            f"Protected process action denied for {process_name}",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Policy blocks dangerous actions against protected process: {process_name}",
        )


def _resolve_context(provided: str) -> SecurityContext | None:
    provided_sha256 = _sha256_hex(provided)

    if security_settings.api_keys_sha256:
        for role, token_sha256 in security_settings.api_keys_sha256.items():
            if hmac.compare_digest(provided_sha256, token_sha256):
                return SecurityContext(token=provided, role=role)
        return None

    if security_settings.api_keys:
        for role, token in security_settings.api_keys.items():
            if hmac.compare_digest(provided, token):
                return SecurityContext(token=provided, role=role)
        return None

    if security_settings.api_key_sha256 and hmac.compare_digest(provided_sha256, security_settings.api_key_sha256):
        return SecurityContext(token=provided, role=security_settings.api_key_role)

    if security_settings.api_key and hmac.compare_digest(provided, security_settings.api_key):
        return SecurityContext(token=provided, role=security_settings.api_key_role)

    return None


def _resolve_oidc_context(provided: str) -> SecurityContext | None:
    try:
        principal = identity_provider.authenticate_token(provided)
        _ensure_identity_not_revoked(principal)
    except Exception:
        return None
    return SecurityContext(
        token=provided,
        role=principal.role,
        actor=principal.actor,
        allowed_workspaces=principal.allowed_workspaces or ("default",),
        approval_workspaces=principal.approval_workspaces,
        subject=principal.subject,
        auth_source="oidc",
        token_id=principal.token_id,
        session_expires_at=principal.expires_at,
    )


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "bearer "
    if authorization.lower().startswith(prefix):
        return authorization[len(prefix):].strip()
    return None


def _client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def _context_role(request: Request | None) -> str:
    if request is None:
        return ""
    context = getattr(request.state, "security_context", None)
    return getattr(context, "role", "")


def _context_workspace(request: Request | None) -> str:
    if request is None:
        return "default"
    context = getattr(request.state, "security_context", None)
    return getattr(context, "workspace_id", "default") or "default"


def current_actor(request: Request | None) -> str:
    if request is None:
        return ""
    context = getattr(request.state, "security_context", None)
    return str(getattr(context, "actor", "") or "")


def current_subject(request: Request | None) -> str:
    if request is None:
        return ""
    context = getattr(request.state, "security_context", None)
    return str(getattr(context, "subject", "") or "")


def can_approve_workspace(request: Request | None, workspace_id: str) -> bool:
    if request is None:
        return False
    context = getattr(request.state, "security_context", None)
    allowed = tuple(getattr(context, "approval_workspaces", ()) or ())
    if not allowed:
        return getattr(context, "role", "") == "admin"
    return str(workspace_id or "").strip().lower() in {str(item).strip().lower() for item in allowed}


def _bucket_key(bucket: str, subject: str) -> str:
    return f"{bucket}:{subject}"


def _prune_rate_limit(bucket: str, subject: str, window_seconds: int) -> list[float]:
    now = time.time()
    cutoff = now - window_seconds
    conn = db.create_connection()
    if conn is not None:
        try:
            db.prune_rate_limit_hits(conn, bucket, subject, cutoff)
            count = db.count_rate_limit_hits(conn, bucket, subject, cutoff)
            return [now] * count
        finally:
            conn.close()
    key = _bucket_key(bucket, subject)
    values = [ts for ts in _RATE_LIMIT_BUCKETS.get(key, []) if now - ts < window_seconds]
    _RATE_LIMIT_BUCKETS[key] = values
    return values


def _record_rate_limit_hit(bucket: str, subject: str) -> None:
    now = time.time()
    conn = db.create_connection()
    if conn is not None:
        try:
            db.record_rate_limit_hit(conn, bucket, subject, now)
            return
        finally:
            conn.close()
    key = _bucket_key(bucket, subject)
    hits = _RATE_LIMIT_BUCKETS.setdefault(key, [])
    hits.append(now)


def _enforce_request_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    detail: str,
) -> None:
    subject = _client_ip(request)
    marker = f"{bucket}:{subject}"
    consumed = getattr(request.state, "_rate_limit_consumed", set())
    if marker in consumed:
        return
    hits = _prune_rate_limit(bucket, subject, window_seconds)
    if len(hits) >= limit:
        _log_auth_event("rate_limited", "denied", _context_role(request), subject, request.url.path, detail, workspace_id=_context_workspace(request))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)
    _record_rate_limit_hit(bucket, subject)
    consumed.add(marker)
    request.state._rate_limit_consumed = consumed


def _enforce_auth_failure_limit(request: Request) -> None:
    subject = _client_ip(request)
    hits = _prune_rate_limit("auth_fail", subject, AUTH_FAILURE_WINDOW_SECONDS)
    if len(hits) >= AUTH_FAILURE_LIMIT:
        detail = "Too many failed authentication attempts. Retry after a short cooldown."
        _log_auth_event("rate_limited", "denied", "", subject, request.url.path, detail, workspace_id=_context_workspace(request))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)


def _record_auth_failure(request: Request, *, detail: str) -> None:
    subject = _client_ip(request)
    _record_rate_limit_hit("auth_fail", subject)
    _log_auth_event("auth_failure", "denied", "", subject, request.url.path, detail, workspace_id=_context_workspace(request))


def _log_auth_event(event_type: str, outcome: str, role: str, client_ip: str, path: str, detail: str, workspace_id: str = "default") -> None:
    try:
        import database as db

        conn = db.create_connection()
        if conn is None:
            logger.warning("Auth event not persisted because the database connection is unavailable.")
            return
        try:
            db.log_auth_event(conn, event_type, outcome, role, client_ip, path, detail, workspace_id=workspace_id)
        finally:
            conn.close()
    except Exception:
        logger.exception("Failed to persist auth event")
        return


def _attach_workspace_context(context: SecurityContext, requested_workspace: str | None, requested_actor: str | None, request: Request) -> SecurityContext:
    actor = _normalize_actor(requested_actor or context.actor)
    try:
        access = resolve_workspace_access(
            context.role,
            requested_workspace,
            security_settings.policy_profile,
            actor=actor,
            allowed_workspaces=context.allowed_workspaces if context.auth_source == "oidc" else None,
        )
    except ValueError as exc:
        _log_auth_event("workspace_denied", "denied", context.role, _client_ip(request), request.url.path, str(exc), workspace_id="default")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    request.state.workspace_access = access
    return SecurityContext(
        token=context.token,
        role=context.role,
        actor=actor,
        workspace_id=access.workspace_id,
        allowed_workspaces=access.allowed_workspaces,
        approval_workspaces=context.approval_workspaces,
        subject=context.subject,
        auth_source=context.auth_source,
        token_id=context.token_id,
        session_expires_at=context.session_expires_at,
    )


def _normalize_actor(value: str | None) -> str:
    candidate = str(value or "").strip().lower()
    if not candidate:
        return ""
    cleaned = "".join(ch for ch in candidate if ch.isalnum() or ch in {".", "_", "-", "@"})
    return cleaned[:120]


def _ensure_identity_not_revoked(principal: IdentityPrincipal) -> None:
    conn = db.create_connection()
    if conn is None:
        return
    try:
        if db.is_identity_token_revoked(
            conn,
            issuer=principal.issuer,
            subject=principal.subject,
            token_id=principal.token_id,
            issued_at=principal.issued_at,
        ):
            raise ValueError("OIDC token has been revoked")
    finally:
        conn.close()


async def _require_signed_request(request: Request, context: SecurityContext) -> None:
    if not security_settings.auth_required or not context.token:
        return
    timestamp = (request.headers.get("X-ShadowLab-Timestamp") or "").strip()
    nonce = (request.headers.get("X-ShadowLab-Nonce") or "").strip()
    signature = (request.headers.get("X-ShadowLab-Signature") or "").strip().lower()
    if not timestamp or not nonce or not signature:
        _log_auth_event(
            "signature_failure",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Missing request signature headers",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signed request headers are required")
    try:
        timestamp_value = int(timestamp)
    except ValueError:
        _log_auth_event(
            "signature_failure",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Invalid request signature timestamp",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signed request timestamp")
    now = int(time.time())
    if abs(now - timestamp_value) > SIGNED_REQUEST_WINDOW_SECONDS:
        _log_auth_event(
            "signature_failure",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Expired request signature timestamp",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signed request timestamp expired")
    nonce_key = f"{context.role}:{nonce}"
    _prune_signature_nonces(now)
    payload = "\n".join(
        [
            request.method.upper(),
            request.url.path,
            _canonical_query_string(request),
            _request_body_sha256(await request.body()),
            timestamp,
            nonce,
        ]
    )
    expected = hmac.new(context.token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        _log_auth_event(
            "signature_failure",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Signed request HMAC mismatch",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signed request signature")
    conn = db.create_connection()
    if conn is not None:
        try:
            reserved = db.reserve_request_nonce(conn, nonce_key, float(now))
        finally:
            conn.close()
    else:
        reserved = nonce_key not in _SIGNATURE_NONCES
        if reserved:
            _SIGNATURE_NONCES[nonce_key] = float(now)
    if not reserved:
        _log_auth_event(
            "signature_replay",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Replayed signed request nonce",
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Signed request nonce has already been used")


def _canonical_query_string(request: Request) -> str:
    raw_query = request.scope.get("query_string", b"")
    if not raw_query:
        return ""
    pairs = parse_qsl(raw_query.decode("utf-8", errors="strict"), keep_blank_values=True)
    pairs.sort()
    return "&".join(f"{key}={value}" for key, value in pairs)


def _request_body_sha256(body: bytes) -> str:
    if not body:
        return hashlib.sha256(b"").hexdigest()
    try:
        loaded = json.loads(body)
    except (TypeError, ValueError):
        canonical = body
    else:
        canonical = json.dumps(loaded, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _prune_signature_nonces(now: int | None = None) -> None:
    current = float(now or int(time.time()))
    conn = db.create_connection()
    if conn is not None:
        try:
            db.prune_request_nonces(conn, current - SIGNED_REQUEST_WINDOW_SECONDS)
            return
        finally:
            conn.close()
    stale = [
        key
        for key, timestamp in _SIGNATURE_NONCES.items()
        if current - float(timestamp) > SIGNED_REQUEST_WINDOW_SECONDS
    ]
    for key in stale:
        _SIGNATURE_NONCES.pop(key, None)
