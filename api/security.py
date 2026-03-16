from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from fastapi import Depends, Header, HTTPException, Request, status


@dataclass(frozen=True)
class SecuritySettings:
    api_key: str
    api_key_sha256: str
    api_keys: dict[str, str]
    api_keys_sha256: dict[str, str]
    auth_required: bool
    enable_dangerous_actions: bool
    enable_network_warfare: bool
    allow_destructive_file_delete: bool
    allowed_origins: list[str]


@dataclass(frozen=True)
class SecurityContext:
    token: str
    role: str


TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_ROLE = "admin"


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def _normalize_origins(raw: str | None) -> list[str]:
    if not raw:
        return ["http://127.0.0.1", "http://localhost"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_role_keys(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    parsed: dict[str, str] = {}
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item or ":" not in item:
            continue
        role, token = item.split(":", 1)
        role = role.strip().lower()
        token = token.strip()
        if role and token:
            parsed[role] = token
    return parsed


def load_security_settings() -> SecuritySettings:
    api_key = os.environ.get("SHADOWLAB_API_KEY", "")
    api_key_sha256 = os.environ.get("SHADOWLAB_API_KEY_SHA256", "").strip().lower()
    api_keys = _parse_role_keys(os.environ.get("SHADOWLAB_API_KEYS"))
    api_keys_sha256 = _parse_role_keys(os.environ.get("SHADOWLAB_API_KEYS_SHA256"))
    auth_required = _as_bool(os.environ.get("SHADOWLAB_REQUIRE_AUTH"), bool(api_key or api_key_sha256 or api_keys or api_keys_sha256))
    enable_dangerous_actions = _as_bool(os.environ.get("SHADOWLAB_ENABLE_DANGEROUS_ACTIONS"), False)
    enable_network_warfare = _as_bool(os.environ.get("SHADOWLAB_ENABLE_NETWORK_WARFARE"), False)
    allow_destructive_file_delete = _as_bool(os.environ.get("SHADOWLAB_ALLOW_FILE_DELETE"), False)
    allowed_origins = _normalize_origins(os.environ.get("SHADOWLAB_ALLOWED_ORIGINS"))
    return SecuritySettings(
        api_key=api_key,
        api_key_sha256=api_key_sha256,
        api_keys=api_keys,
        api_keys_sha256=api_keys_sha256,
        auth_required=auth_required,
        enable_dangerous_actions=enable_dangerous_actions,
        enable_network_warfare=enable_network_warfare,
        allow_destructive_file_delete=allow_destructive_file_delete,
        allowed_origins=allowed_origins,
    )


security_settings = load_security_settings()


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> SecurityContext:
    if request.url.path in {"/health"}:
        return SecurityContext(token="", role="public")
    if not security_settings.auth_required:
        return SecurityContext(token="", role="admin")

    provided = x_api_key or _extract_bearer_token(authorization)
    if not provided:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    context = _resolve_context(provided)
    if context is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    request.state.security_context = context
    return context


def require_analyst_or_admin(context: SecurityContext = Depends(require_api_key)) -> SecurityContext:
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst or admin role required")
    return context


def require_admin(context: SecurityContext = Depends(require_api_key)) -> SecurityContext:
    if context.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return context


def ensure_dangerous_actions_enabled() -> None:
    if not security_settings.enable_dangerous_actions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dangerous host response actions are disabled by policy",
        )


def ensure_network_warfare_enabled() -> None:
    if not security_settings.enable_network_warfare:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Network warfare controls are disabled by policy",
        )


def ensure_delete_enabled() -> None:
    if not security_settings.allow_destructive_file_delete:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Destructive file deletion is disabled by policy",
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


def _resolve_context(provided: str) -> SecurityContext | None:
    provided_sha256 = _sha256_hex(provided)

    if security_settings.api_keys_sha256:
        for role, token_sha256 in security_settings.api_keys_sha256.items():
            if hmac.compare_digest(provided_sha256, token_sha256.lower()):
                return SecurityContext(token=provided, role=role)
        return None

    if security_settings.api_keys:
        for role, token in security_settings.api_keys.items():
            if hmac.compare_digest(provided, token):
                return SecurityContext(token=provided, role=role)
        return None

    if security_settings.api_key_sha256 and hmac.compare_digest(provided_sha256, security_settings.api_key_sha256.lower()):
        return SecurityContext(token=provided, role=DEFAULT_ROLE)

    if security_settings.api_key and hmac.compare_digest(provided, security_settings.api_key):
        return SecurityContext(token=provided, role=DEFAULT_ROLE)

    return None


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "bearer "
    if authorization.lower().startswith(prefix):
        return authorization[len(prefix):].strip()
    return None
