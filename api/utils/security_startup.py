"""Startup-time policy posture validation.

Runs once in the FastAPI `startup` hook to refuse to serve traffic when the
configured security settings are incompatible with the active policy
profile (lab / corp / prod). Any detected issue raises `RuntimeError` so
the process exits before binding the port.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import database as db

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def validate_startup_security_posture(
    *,
    security_module: Any,
    get_active_policy_name,
    observability_service: Any,
    logger: logging.Logger,
) -> None:
    """Raise if the running configuration violates the policy profile."""
    security_settings = security_module.security_settings
    profile = get_active_policy_name()
    issues: list[str] = []
    bind_host = (os.environ.get("SHADOWLAB_HOST", "127.0.0.1") or "127.0.0.1").strip().lower()
    if not security_settings.auth_required and bind_host not in LOOPBACK_HOSTS:
        # Hardened from the original (role-gated) check: any auth-disabled
        # mode that binds to a non-loopback interface is a LAN exposure
        # regardless of the default role. A "viewer" still enumerates
        # workspaces, history, incidents, artifacts — sensitive material.
        issues.append("authentication-disabled mode must bind to loopback only")
    if (
        not security_settings.auth_required
        and security_settings.noauth_default_role != "viewer"
        and profile != "lab"
    ):
        issues.append("non-viewer auth-disabled defaults are only allowed in the lab policy profile")
    if (
        not security_settings.auth_required
        and security_settings.noauth_default_role != "viewer"
        and bind_host not in LOOPBACK_HOSTS
    ):
        issues.append("non-viewer auth-disabled defaults require loopback binding")
    if profile in {"corp", "prod"} and not security_settings.auth_required:
        issues.append("authentication must be enabled")
    if profile in {"corp", "prod"} and any(origin.strip() == "*" for origin in security_settings.allowed_origins):
        issues.append("wildcard CORS origins are not allowed")
    if profile in {"corp", "prod"} and not security_settings.require_tls:
        issues.append("TLS must be required")
    if profile == "prod" and security_settings.enable_dangerous_actions:
        issues.append("dangerous actions must be disabled")
    if profile in {"corp", "prod"} and security_settings.enable_network_warfare:
        issues.append("network warfare must be disabled")
    if profile == "prod" and security_settings.allow_destructive_file_delete:
        issues.append("destructive file deletion must be disabled")
    if os.environ.get("SHADOWLAB_CORS_ALLOW_CREDENTIALS", "").strip().lower() in {"1", "true", "yes", "on"}:
        issues.append("cookie-based credentialed CORS is not supported without CSRF protection")
    if profile in {"corp", "prod"} and security_settings.api_keys:
        issues.append("raw SHADOWLAB_API_KEYS are not allowed; use SHA-256 hashed keys")
    if profile in {"corp", "prod"} and security_settings.api_key:
        issues.append("raw SHADOWLAB_API_KEY is not allowed; use SHADOWLAB_API_KEY_SHA256")
    if (
        getattr(security_module, "_SECURITY_SETTINGS_ERROR", "")
        and security_settings.auth_required
        and not any(
            [
                security_settings.api_key,
                security_settings.api_key_sha256,
                security_settings.api_keys,
                security_settings.api_keys_sha256,
                security_settings.oidc_enabled,
            ]
        )
    ):
        issues.append(security_module._SECURITY_SETTINGS_ERROR)
    if profile in {"corp", "prod"}:
        conn = db.create_connection()
        if conn is None:
            issues.append("database connectivity is required")
        else:
            conn.close()
    if issues:
        raise RuntimeError(f"Insecure startup posture for profile `{profile}`: " + "; ".join(issues))
    logger.info("startup_security_posture_validated profile=%s", profile)
    observability_service.log_event("startup_security_posture_validated", profile=profile)
