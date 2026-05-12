from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from collections import OrderedDict
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
    trusted_proxies: list[str]
    policy_profile: str
    noauth_default_role: str
    oidc_enabled: bool
    signed_request_window_seconds: int


@dataclass(frozen=True)
class SecurityContext:
    token: str
    role: str
    signing_secret: str = ""
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
# `_RATE_LIMIT_BUCKETS` is kept as a module-level alias to the live
# in-memory bucket store inside `services.rate_limit_backend`. Tests
# clear it between cases to reset window state; production code routes
# through the backend interface in `_enforce_request_rate_limit`.
from services.rate_limit_backend import _MEMORY_BUCKETS as _RATE_LIMIT_BUCKETS  # noqa: E402,F401
# Use an OrderedDict so the lab-profile fallback gets O(1) FIFO eviction
# via `popitem(last=False)` and the lock keeps compound check-then-pop
# operations atomic under uvicorn's worker-thread pool. Production /
# corp profiles route nonces through the DB-backed store and never
# touch this dict.
_SIGNATURE_NONCES: "OrderedDict[str, float]" = OrderedDict()
_SIGNATURE_NONCES_LOCK = threading.Lock()
# Hard cap so a flood of partially-failed signed requests cannot OOM
# the lab-profile in-memory nonce store. Older entries are evicted on
# insert; corp/prod profiles use the DB-backed store and never hit this.
_SIGNATURE_NONCES_MAX = 10_000
DEFAULT_SIGNED_REQUEST_WINDOW_SECONDS = 60
logger = logging.getLogger(__name__)
POLICY_PROFILES = POLICY_MATRIX
_SECURITY_SETTINGS_ERROR = ""


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


def _normalize_trusted_proxies(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


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
    # Prevent role-confusion through a shared token: if the same secret is
    # bound to two roles, `_resolve_context` returns whichever role iterates
    # first in `dict.items()` (insertion order). Fail closed at config-load
    # so an operator never accidentally maps the same key to `viewer` AND
    # `admin` and gets silent privilege escalation later.
    for label, mapping in (
        ("SHADOWLAB_API_KEYS", settings.api_keys),
        ("SHADOWLAB_API_KEYS_SHA256", settings.api_keys_sha256),
    ):
        seen: dict[str, str] = {}
        for role, token in (mapping or {}).items():
            existing = seen.get(token)
            if existing is not None and existing != role:
                raise ValueError(
                    f"{label} reuses the same token across roles ({existing}, {role}); "
                    "each role must have its own unique secret"
                )
            seen[token] = role
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
    if settings.signed_request_window_seconds < 30 or settings.signed_request_window_seconds > 300:
        raise ValueError("SHADOWLAB_SIGNED_REQUEST_WINDOW_SECONDS must be between 30 and 300 seconds")
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
        auth_required=True,
        require_tls=_as_bool(os.environ.get("SHADOWLAB_REQUIRE_TLS"), False),
        enable_dangerous_actions=_as_bool(os.environ.get("SHADOWLAB_ENABLE_DANGEROUS_ACTIONS"), False),
        enable_network_warfare=_as_bool(os.environ.get("SHADOWLAB_ENABLE_NETWORK_WARFARE"), False),
        allow_destructive_file_delete=_as_bool(os.environ.get("SHADOWLAB_ALLOW_FILE_DELETE"), False),
        allowed_origins=_normalize_origins(os.environ.get("SHADOWLAB_ALLOWED_ORIGINS")),
        protected_process_names=_normalize_process_names(os.environ.get("SHADOWLAB_PROTECTED_PROCESS_NAMES")),
        trusted_proxies=_normalize_trusted_proxies(os.environ.get("SHADOWLAB_TRUSTED_PROXIES")),
        policy_profile=os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab").strip().lower() or "lab",
        noauth_default_role=os.environ.get("SHADOWLAB_NOAUTH_DEFAULT_ROLE", DEFAULT_ROLE).strip().lower() or DEFAULT_ROLE,
        oidc_enabled=identity_provider.enabled(),
        signed_request_window_seconds=max(
            30,
            min(
                300,
                int((os.environ.get("SHADOWLAB_SIGNED_REQUEST_WINDOW_SECONDS", str(DEFAULT_SIGNED_REQUEST_WINDOW_SECONDS)) or str(DEFAULT_SIGNED_REQUEST_WINDOW_SECONDS)).strip()),
            ),
        ),
    )
    auth_required = _as_bool(
        os.environ.get("SHADOWLAB_REQUIRE_AUTH"),
        True,
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
            trusted_proxies=settings.trusted_proxies,
            policy_profile=settings.policy_profile,
            noauth_default_role=effective_noauth_role,
            oidc_enabled=settings.oidc_enabled,
            signed_request_window_seconds=settings.signed_request_window_seconds,
        )
    )
    if not validated.auth_required:
        logger.warning(
            "ShadowLab authentication is disabled because SHADOWLAB_REQUIRE_AUTH=false was set; unauthenticated requests will be limited to the viewer role."
        )
    return validated


try:
    security_settings = load_security_settings()
except ValueError as exc:
    _SECURITY_SETTINGS_ERROR = str(exc)
    logger.error("ShadowLab security configuration is invalid: %s", exc)
    security_settings = SecuritySettings(
        api_key="",
        api_key_sha256="",
        api_key_role=DEFAULT_ROLE,
        api_keys={},
        api_keys_sha256={},
        auth_required=True,
        require_tls=False,
        enable_dangerous_actions=False,
        enable_network_warfare=False,
        allow_destructive_file_delete=False,
        allowed_origins=_normalize_origins(None),
        protected_process_names=_normalize_process_names(None),
        trusted_proxies=[],
        policy_profile="lab",
        noauth_default_role=DEFAULT_ROLE,
        oidc_enabled=False,
        signed_request_window_seconds=DEFAULT_SIGNED_REQUEST_WINDOW_SECONDS,
    )


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
        "can_view_evidence": is_analyst,
        "can_manage_persistence": is_admin and active.enable_dangerous_actions and bool(profile.get("dangerous_actions", False)),
        "can_manage_process_actions": is_admin and active.enable_dangerous_actions and bool(profile.get("dangerous_actions", False)),
        "can_run_triage": is_analyst,
        "can_manage_quarantine": is_admin and active.enable_dangerous_actions and bool(profile.get("dangerous_actions", False)),
        "can_manage_alerts": is_admin and active.enable_dangerous_actions,
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


def _is_health_path(path: str) -> bool:
    """Return True only for the canonical `/health` probe.

    The legacy check used `path in {"/health"}` — exact match by design,
    but easy to drift: a future refactor adding `/health/` or `/HEALTH`
    would silently open an auth-bypass. Centralise the predicate so the
    match stays anchored and obvious. We deliberately reject trailing
    slashes (FastAPI strict-slashes is on, so `/health/` would 404
    anyway, but it shouldn't pre-empt the auth gate).
    """
    return path == "/health"


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_shadowlab_workspace: str | None = Header(default=None),
    x_shadowlab_actor: str | None = Header(default=None),
) -> SecurityContext:
    if _is_health_path(request.url.path):
        return SecurityContext(token="", signing_secret="", role="public")
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
            context = _attach_workspace_context(
                SecurityContext(token="", signing_secret="", role="viewer", actor=_normalize_actor(x_shadowlab_actor)),
                x_shadowlab_workspace,
                x_shadowlab_actor,
                request,
            )
            request.state.security_context = context
            request.state.workspace_id = context.workspace_id
            _log_auth_event("auth_failure", "denied", context.role, _client_ip(request), request.url.path, "invalid_api_key_auth_disabled", workspace_id=context.workspace_id)
            return context
        context = _attach_workspace_context(
            SecurityContext(token="", signing_secret="", role=security_settings.noauth_default_role, actor=_normalize_actor(x_shadowlab_actor)),
            x_shadowlab_workspace,
            x_shadowlab_actor,
            request,
        )
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


# Methods that mutate server state. MUST stay in sync with
# `_MUTATING_METHODS` in api/middleware/security_headers.py — the two
# sets together gate signed-request validation, MFA enforcement,
# Origin allow-list, audit logging, and approval consumption. Forgetting
# `PUT` here historically allowed admin-only endpoints (antivirus
# credentials, YARA policy, AV lists) to skip every one of those checks.
_MUTATING_METHODS_AUTH = frozenset({"POST", "PUT", "PATCH", "DELETE"})


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
    if request.method.upper() in _MUTATING_METHODS_AUTH:
        await _require_signed_request(request, context)
        _require_mfa_when_enforced(request, context)
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
    if request.method.upper() in _MUTATING_METHODS_AUTH:
        await _require_signed_request(request, context)
        _require_mfa_when_enforced(request, context)
    return context


# Paths the MFA enforcement gate exempts so the operator can actually
# COMPLETE a verification without already holding a verified session.
_MFA_EXEMPT_PATHS = frozenset({"/auth/mfa/verify", "/auth/mfa/enroll", "/auth/mfa/status"})


def _require_mfa_when_enforced(request: Request, context: SecurityContext) -> None:
    """Block mutating requests when MFA is required but no recent verify exists."""
    if request.url.path in _MFA_EXEMPT_PATHS:
        return
    try:
        from services import mfa_service
    except Exception:
        return
    if not mfa_service.enforce_for_role(context.role):
        return
    subject = (
        (context.subject or "").strip().lower()
        or (context.actor or "").strip().lower()
        or (context.token_id or "").strip().lower()
    )
    token_id = (context.token_id or "").strip()
    if not subject or not token_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required but session has no subject/token id",
        )
    if not mfa_service.session_is_valid(subject, token_id):
        _log_auth_event(
            "mfa_required",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "MFA verification required for this role",
            workspace_id=_context_workspace(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required — POST /auth/mfa/verify first",
        )


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


def safe_child_path(base_dir: Path, filename: str, allowed_suffixes: Iterable[str] | None = None) -> Path:
    # `Path(filename).name != filename` rejects any separator or drive
    # component; NUL/control chars (which would later trip Path resolve
    # on POSIX but not Windows) are filtered explicitly.
    if not filename or Path(filename).name != filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    if any(ord(ch) < 0x20 for ch in filename) or "\x00" in filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    # Use os.path.realpath on both ends so an attacker who plants a
    # symlink inside `base_dir` (e.g. via an earlier artifact upload)
    # cannot use Path.resolve()'s case-folding to escape the root on
    # Windows. `is_relative_to` keeps the comparison anchored at the
    # canonical parent rather than the parents chain (which fails for
    # nested case-different mount points).
    target = Path(os.path.realpath(str(base_dir / filename)))
    resolved_base = Path(os.path.realpath(str(base_dir)))
    if target != resolved_base and not target.is_relative_to(resolved_base):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path traversal rejected")
    if allowed_suffixes:
        suffix = target.suffix.lower()
        if suffix not in {item.lower() for item in allowed_suffixes}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File type not allowed")
    # Final TOCTOU guard: between the realpath() above and the time the
    # caller actually opens the file, an attacker with write access
    # inside `base_dir` could swap the target for a symlink pointing
    # elsewhere. `lstat` checks the *direct* entry without following
    # links, so a symlink at the exact target path is rejected outright.
    # The file may still legitimately not exist yet (e.g. caller is
    # about to create it) — in that case the lstat raises FileNotFoundError
    # and we let the call proceed.
    try:
        stat_result = os.lstat(str(target))
    except FileNotFoundError:
        return target
    except OSError:
        # Permission denied / other lstat failures are not a bypass
        # vector; let the caller deal with the I/O error on open().
        return target
    # On POSIX `S_ISLNK` covers symlinks; on Windows, `lstat` returns
    # reparse-point info — `stat.S_ISLNK` correctly identifies symlinks
    # but NOT junctions. Checking `st_file_attributes` for
    # FILE_ATTRIBUTE_REPARSE_POINT (0x400) catches junctions too.
    import stat as _stat
    is_reparse = False
    if hasattr(stat_result, "st_file_attributes"):
        is_reparse = bool(stat_result.st_file_attributes & 0x400)
    if _stat.S_ISLNK(stat_result.st_mode) or is_reparse:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Symbolic links and reparse points are not allowed under this root",
        )
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
    token_id = _token_identifier(provided)

    if security_settings.api_keys_sha256:
        for role, token_sha256 in security_settings.api_keys_sha256.items():
            if hmac.compare_digest(provided_sha256, token_sha256):
                return SecurityContext(token=token_id, signing_secret=provided, role=role, token_id=token_id)
        return None

    if security_settings.api_keys:
        for role, token in security_settings.api_keys.items():
            if hmac.compare_digest(provided, token):
                return SecurityContext(token=token_id, signing_secret=provided, role=role, token_id=token_id)
        return None

    if security_settings.api_key_sha256 and hmac.compare_digest(provided_sha256, security_settings.api_key_sha256):
        return SecurityContext(token=token_id, signing_secret=provided, role=security_settings.api_key_role, token_id=token_id)

    if security_settings.api_key and hmac.compare_digest(provided, security_settings.api_key):
        return SecurityContext(token=token_id, signing_secret=provided, role=security_settings.api_key_role, token_id=token_id)

    return None


def _resolve_oidc_context(provided: str) -> SecurityContext | None:
    try:
        principal = identity_provider.authenticate_token(provided)
        _ensure_identity_not_revoked(principal)
    except Exception as exc:
        # Three-tier visibility on OIDC rejection:
        #
        # 1. WARNING-level log line with the exception class — production
        #    operators NEED this to debug "valid IdP, rejected JWT"
        #    incidents without enabling DEBUG globally. Token content is
        #    NOT logged (PII / replay risk).
        # 2. Prometheus counter bucketed by exception class so a SOC can
        #    alarm on `rate(shadowlab_oidc_rejections_total[5m])` and
        #    spot IdP key rotations or token-forgery probes.
        # 3. The auth-failure path already increments
        #    `shadowlab_auth_failures_total`, so this metric is
        #    deliberately additive (denominator vs reason).
        logger.warning("OIDC authentication rejected (reason=%s)", type(exc).__name__[:48])
        try:
            from api.observability import default_registry as _registry
            _registry.counter(
                "shadowlab_oidc_rejections_total",
                {"reason": type(exc).__name__[:48]},
                help="OIDC token rejections bucketed by exception class.",
            ).inc()
        except Exception:
            # Metrics are best-effort; never let an observability bug
            # turn an OIDC denial into a 500.
            pass
        return None
    return SecurityContext(
        token=_token_identifier(provided),
        signing_secret=provided,
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


def _token_identifier(value: str) -> str:
    digest = _sha256_hex(value)
    return f"sha256:{digest[:12]}"


def _extract_bearer_token(authorization: str | None) -> str | None:
    """Parse an `Authorization: Bearer <token>` header per RFC 6750 §2.1.

    Strict version of the original loose parser:

    * The scheme prefix must be exactly `Bearer` (case-insensitive,
      RFC 7235 §2.1) followed by exactly one ASCII space. Tab, CR/LF,
      and multiple spaces are rejected — they have no legitimate use
      and have historically been HTTP-smuggling vectors.
    * The token body itself MUST match the `b64token` grammar
      (`[A-Za-z0-9._~+/=-]+`). Anything outside that set is a malformed
      header, not a recoverable case.

    Returns `None` for missing / malformed headers so the caller falls
    through to the usual auth-failure path (with rate limiting).
    """
    if not authorization:
        return None
    raw = str(authorization)
    # Reject CR/LF / NUL up front (HTTP smuggling).
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in raw):
        return None
    parts = raw.split(" ")
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme.lower() != "bearer" or not token:
        return None
    # RFC 6750 b64token grammar — keep this conservative; real JWTs and
    # API keys all sit inside this class.
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=-")
    if not all(ch in allowed for ch in token):
        return None
    return token


def _client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return "unknown"
    direct_ip = request.client.host or "unknown"
    trusted = {_normalize_proxy_value(item) for item in security_settings.trusted_proxies}
    if not trusted or _normalize_proxy_value(direct_ip) not in trusted:
        return direct_ip
    forwarded_for = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip") or ""
    first_hop = forwarded_for.split(",", 1)[0].strip()
    return first_hop or direct_ip


def request_from_trusted_proxy(request: Request | None) -> bool:
    if request is None or request.client is None:
        return False
    trusted = {_normalize_proxy_value(item) for item in security_settings.trusted_proxies}
    if not trusted:
        return False
    return _normalize_proxy_value(request.client.host or "") in trusted


def _normalize_proxy_value(value: str) -> str:
    return str(value or "").strip().lower()


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
    # Returns a synthetic list whose length is the live hit count so the
    # caller's `len(hits) >= limit` check works against any backend. We
    # don't need the actual timestamps anywhere else.
    try:
        from services.rate_limit_backend import active_backend
        count = active_backend().prune_and_count(bucket, subject, window_seconds)
    except Exception:
        logger.exception("rate-limit prune_and_count failed; failing closed for corp/prod")
        if security_settings.policy_profile in {"corp", "prod"}:
            return [time.time()] * (window_seconds + 1)
        return []
    return [time.time()] * int(count)


def _record_rate_limit_hit(bucket: str, subject: str) -> None:
    try:
        from services.rate_limit_backend import active_backend
        active_backend().record_hit(bucket, subject)
    except Exception:
        logger.exception("rate-limit record_hit failed; failing closed for corp/prod")
        if security_settings.policy_profile in {"corp", "prod"}:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limit state store unavailable",
            )


def _rate_limit_subject(request: Request) -> str:
    """Subject key for rate-limit buckets.

    IPv4 → exact address. IPv6 → /64 prefix (a single IPv6 host gets a
    /64 block from its ISP, so per-address limits are trivially bypassed
    by rolling addresses inside the same /64).
    """
    raw = _client_ip(request)
    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(ip_obj, ipaddress.IPv6Address):
        try:
            return str(ipaddress.ip_network(f"{ip_obj}/64", strict=False).network_address) + "/64"
        except ValueError:
            return raw
    return str(ip_obj)


def _enforce_request_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    detail: str,
) -> None:
    subject = _rate_limit_subject(request)
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
    subject = _rate_limit_subject(request)
    hits = _prune_rate_limit("auth_fail", subject, AUTH_FAILURE_WINDOW_SECONDS)
    if len(hits) >= AUTH_FAILURE_LIMIT:
        detail = "Too many failed authentication attempts. Retry after a short cooldown."
        _log_auth_event("rate_limited", "denied", "", subject, request.url.path, detail, workspace_id=_context_workspace(request))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)


def _record_auth_failure(request: Request, *, detail: str) -> None:
    subject = _rate_limit_subject(request)
    _record_rate_limit_hit("auth_fail", subject)
    _log_auth_event("auth_failure", "denied", "", subject, request.url.path, detail, workspace_id=_context_workspace(request))
    # Surface the failure into the Prometheus surface so a SOC can alarm
    # on `rate(shadowlab_auth_failures_total[5m]) > threshold` instead of
    # having to tail audit logs in real time. Bucketed by failure reason
    # (missing/invalid/etc.) so it doesn't collapse into a single bar.
    try:
        from api.observability import default_registry as _registry
        _registry.counter(
            "shadowlab_auth_failures_total",
            {"reason": str(detail or "unknown")[:64]},
            help="Authentication rejections, labelled by failure reason.",
        ).inc()
    except Exception:
        # Metrics are best-effort; never block the auth path on an
        # exposition bug.
        pass


def _log_auth_event(event_type: str, outcome: str, role: str, client_ip: str, path: str, detail: str, workspace_id: str = "default") -> None:
    """Persist an auth_log row + bump the Prometheus counter.

    Connection-per-event is intentionally kept simple — adding a real
    pool here means touching every code path that owns its own
    `db.create_connection()`. For high-throughput deployments operators
    should switch SQLite → PostgreSQL (the adapter is already there)
    and the connection cost drops to a pgbouncer round-trip.
    """
    # Always surface to metrics first — even if the DB write fails, the
    # SOC can graph the failure trend from `/metrics`.
    try:
        from api.observability import default_registry as _registry
        _registry.counter(
            "shadowlab_auth_events_total",
            {"event_type": str(event_type or "unknown")[:48], "outcome": str(outcome or "unknown")[:24]},
            help="Authentication / authorization events bucketed by type and outcome.",
        ).inc()
    except Exception:
        pass
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
        signing_secret=context.signing_secret,
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


SHADOWLAB_SIGNING_HKDF_INFO = b"shadowlab-signing-v1"


def derive_signing_secret(api_key: str) -> bytes:
    """Derive a request-signing key from the raw API key via HKDF-SHA256.

    Layered key separation: the bearer token authenticates the principal
    while a *different* key (HKDF derivation of the same root secret)
    signs request bodies. A leak of one no longer trivially compromises
    the other downstream (e.g. an audit-log dump containing signing
    material can't be replayed as a bearer token).

    Both the API and the desktop client run the same derivation, so the
    raw API key remains the only secret the operator has to handle.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if not api_key:
        return b""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=SHADOWLAB_SIGNING_HKDF_INFO,
    )
    return hkdf.derive(api_key.encode("utf-8"))


async def _require_signed_request(request: Request, context: SecurityContext) -> None:
    if not security_settings.auth_required or not context.signing_secret:
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
    if abs(now - timestamp_value) > security_settings.signed_request_window_seconds:
        _log_auth_event(
            "signature_failure",
            "denied",
            context.role,
            _client_ip(request),
            request.url.path,
            "Expired request signature timestamp",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signed request timestamp expired")
    # Per-token (not per-role) keying so two admins with different API
    # keys cannot accidentally invalidate each other's nonces, and a
    # leaked viewer nonce can never be replayed against an admin token.
    nonce_scope = context.token_id or context.role
    nonce_key = f"{nonce_scope}:{nonce}"
    _prune_signature_nonces(now)
    body_bytes = await request.body()
    method_path_query = [
        request.method.upper(),
        request.url.path,
        _canonical_query_string(request),
    ]
    payload_canonical = "\n".join(method_path_query + [_request_body_sha256(body_bytes), timestamp, nonce])
    payload_raw = "\n".join(method_path_query + [_request_body_sha256_raw(body_bytes), timestamp, nonce])
    # Four expected signatures: {HKDF, legacy raw API key} × {canonical
    # body hash, raw body hash}. Constant-time compare against each in
    # turn so neither rollout dimension (signing-key derivation OR body-
    # hash form) blocks the other.
    derived = derive_signing_secret(context.signing_secret)
    raw_key = context.signing_secret.encode("utf-8")
    candidates: list[str] = []
    for body_payload in (payload_canonical, payload_raw):
        if derived:
            candidates.append(hmac.new(derived, body_payload.encode("utf-8"), hashlib.sha256).hexdigest())
        candidates.append(hmac.new(raw_key, body_payload.encode("utf-8"), hashlib.sha256).hexdigest())
    matched = any(hmac.compare_digest(signature, candidate) for candidate in candidates)
    if not matched:
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
        if security_settings.policy_profile in {"corp", "prod"}:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Signed request state store unavailable")
        # Atomic check-and-insert: without the lock a race between two
        # worker threads with the same nonce key would let both pass
        # the membership test, defeating replay protection. FIFO
        # eviction via OrderedDict makes the cap bound truly O(1).
        with _SIGNATURE_NONCES_LOCK:
            reserved = nonce_key not in _SIGNATURE_NONCES
            if reserved:
                if len(_SIGNATURE_NONCES) >= _SIGNATURE_NONCES_MAX:
                    try:
                        _SIGNATURE_NONCES.popitem(last=False)
                    except KeyError:
                        pass
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
    """Produce a deterministic, RFC3986-encoded query-string for HMAC signing.

    Two behaviours matter here:

    * Decode-then-re-encode every (key, value) pair so the client and
      server agree on the exact byte string even when the wire form
      uses different but equivalent percent-encodings (`%2C` vs `,`,
      `+` vs `%20`).
    * Treat a non-UTF-8 query string as a client error (400) instead of
      letting `errors="strict"` bubble up as a generic 500, which both
      leaks a stack trace and skews uptime metrics.
    """
    from urllib.parse import quote as _quote

    raw_query = request.scope.get("query_string", b"")
    if not raw_query:
        return ""
    try:
        decoded = raw_query.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Query string is not valid UTF-8") from exc
    pairs = parse_qsl(decoded, keep_blank_values=True)
    pairs.sort()
    return "&".join(f"{_quote(key, safe='')}={_quote(value, safe='')}" for key, value in pairs)


def _request_body_sha256(body: bytes) -> str:
    """Canonical body hash used in the signed-request payload.

    Two forms exist in the wild:

    1. **Canonical-JSON form** (legacy desktop client): the client
       computes `json.dumps(payload, sort_keys=True, separators=(",", ":"),
       ensure_ascii=False).encode("utf-8")` itself, hashes that, then
       hands the *unsorted* JSON to the HTTP library — which means the
       bytes on the wire differ from the bytes the client hashed.
       Server-side we parse and re-canonicalize to recover the same
       form the client computed.

    2. **Raw-bytes form** (new): client signs the literal byte string
       it puts on the wire. No parse/re-serialize round-trip, which
       avoids drift on edge cases (NaN/Inf, non-BMP escapes, integer
       overflow on some JS clients).

    The signed-request validator accepts BOTH hashes so a fleet of
    mixed clients can roll over without coordinated cutovers. This
    function returns the canonical-JSON form; `_request_body_sha256_raw`
    returns the raw-bytes form.
    """
    if not body:
        return hashlib.sha256(b"").hexdigest()
    try:
        loaded = json.loads(body)
    except (TypeError, ValueError):
        canonical = body
    else:
        canonical = json.dumps(loaded, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _request_body_sha256_raw(body: bytes) -> str:
    """SHA-256 of the literal request body — see `_request_body_sha256`."""
    if not body:
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(body).hexdigest()


def _prune_signature_nonces(now: int | None = None) -> None:
    current = float(now or int(time.time()))
    conn = db.create_connection()
    if conn is not None:
        try:
            db.prune_request_nonces(conn, current - security_settings.signed_request_window_seconds)
            return
        finally:
            conn.close()
    if security_settings.policy_profile in {"corp", "prod"}:
        return
    # Snapshot under the lock so the iterator isn't invalidated by a
    # concurrent insert in `_require_signed_request`.
    with _SIGNATURE_NONCES_LOCK:
        stale = [
            key
            for key, timestamp in _SIGNATURE_NONCES.items()
            if current - float(timestamp) > security_settings.signed_request_window_seconds
        ]
        for key in stale:
            _SIGNATURE_NONCES.pop(key, None)
