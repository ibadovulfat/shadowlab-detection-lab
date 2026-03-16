from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from fastapi import Header, HTTPException, Request, status


@dataclass(frozen=True)
class SecuritySettings:
    api_key: str
    auth_required: bool
    enable_dangerous_actions: bool
    enable_network_warfare: bool
    allow_destructive_file_delete: bool
    allowed_origins: list[str]


TRUE_VALUES = {"1", "true", "yes", "on"}


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def _normalize_origins(raw: str | None) -> list[str]:
    if not raw:
        return ["http://127.0.0.1", "http://localhost"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def load_security_settings() -> SecuritySettings:
    api_key = os.environ.get("SHADOWLAB_API_KEY", "")
    auth_required = _as_bool(os.environ.get("SHADOWLAB_REQUIRE_AUTH"), bool(api_key))
    enable_dangerous_actions = _as_bool(os.environ.get("SHADOWLAB_ENABLE_DANGEROUS_ACTIONS"), False)
    enable_network_warfare = _as_bool(os.environ.get("SHADOWLAB_ENABLE_NETWORK_WARFARE"), False)
    allow_destructive_file_delete = _as_bool(os.environ.get("SHADOWLAB_ALLOW_FILE_DELETE"), False)
    allowed_origins = _normalize_origins(os.environ.get("SHADOWLAB_ALLOWED_ORIGINS"))
    return SecuritySettings(
        api_key=api_key,
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
) -> None:
    if request.url.path in {"/health"}:
        return
    if not security_settings.auth_required:
        return
    provided = x_api_key or _extract_bearer_token(authorization)
    if not provided or not security_settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not hmac.compare_digest(provided, security_settings.api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


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


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "bearer "
    if authorization.lower().startswith(prefix):
        return authorization[len(prefix):].strip()
    return None
