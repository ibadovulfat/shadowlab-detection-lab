"""Audit + anomaly helpers used by the request middleware and history routes."""
from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from fastapi import Request

#: Tokens whose values are scrubbed out of audit detail strings.
_REDACT_TOKENS = ("api_key", "token", "signature", "shared_key", "secret", "webhook_url")
_TRUE_VALUES = {"1", "true", "yes", "on"}


def redact_audit_detail(detail: str) -> str:
    """Replace sensitive query-string values with `***redacted***` and cap length."""
    if not detail:
        return ""
    redacted = detail
    for token in _REDACT_TOKENS:
        redacted = re.sub(rf"(?i)({token}=)[^&]+", rf"\1***redacted***", redacted)
    return redacted[:500]


def _ip_redaction_enabled() -> bool:
    return (os.environ.get("SHADOWLAB_AUDIT_REDACT_IP", "") or "").strip().lower() in _TRUE_VALUES


def redact_client_ip(value: str) -> str:
    """Optional GDPR-friendly truncation of audit-logged client IPs.

    Off by default — most lab/corp deployments want the full address for
    incident response. Set `SHADOWLAB_AUDIT_REDACT_IP=1` to truncate
    IPv4 to a `/24` and IPv6 to a `/48` prefix before persistence.
    """
    raw = (value or "").strip()
    if not raw or not _ip_redaction_enabled():
        return raw
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(addr, ipaddress.IPv4Address):
        try:
            net = ipaddress.ip_network(f"{addr}/24", strict=False)
            return f"{net.network_address}/24"
        except ValueError:
            return raw
    try:
        net = ipaddress.ip_network(f"{addr}/48", strict=False)
        return f"{net.network_address}/48"
    except ValueError:
        return raw


def audit_mutating_request(db_module: Any, request: Request, status_code: int) -> None:
    """Persist an action_audit row for the mutating request.

    Errors are caught (we never want the audit path to break a real
    request) but logged so silent persistence failures don't go
    unnoticed in production.
    """
    import logging
    _logger = logging.getLogger(__name__)
    try:
        conn = db_module.create_connection()
        if conn is None:
            _logger.warning("audit_mutating_request: database connection unavailable")
            return
        try:
            context = getattr(request.state, "security_context", None)
            role = getattr(context, "role", "")
            workspace_id = getattr(context, "workspace_id", "default")
            client_ip = redact_client_ip(request.client.host if request.client else "")
            # Redact BEFORE truncation — truncating first can drop the "&" that
            # ends a sensitive value and leave the secret's tail unredacted.
            detail = redact_audit_detail(request.url.query or "")
            db_module.log_action_audit(
                conn,
                request.method.upper(),
                request.url.path,
                int(status_code),
                role,
                client_ip,
                detail,
                workspace_id=workspace_id,
            )
        finally:
            conn.close()
    except Exception:
        _logger.exception("audit_mutating_request: persistence failed")
        return


def build_auth_anomalies(
    auth_rows: list[dict[str, Any]],
    action_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Summarize the last N authentication + action rows into anomaly findings."""
    anomalies: list[dict[str, Any]] = []

    failures_by_ip: dict[str, int] = {}
    for row in auth_rows:
        if str(row.get("event_type", "")) == "auth_failure":
            ip = str(row.get("client_ip", "") or "unknown")
            failures_by_ip[ip] = failures_by_ip.get(ip, 0) + 1
    for ip, count in failures_by_ip.items():
        if count >= 5:
            anomalies.append(
                {
                    "type": "repeated_auth_failures",
                    "severity": "high",
                    "client_ip": ip,
                    "count": count,
                    "summary": f"{count} failed authentication attempts observed from {ip}.",
                }
            )

    denied_by_role: dict[str, int] = {}
    for row in auth_rows:
        if str(row.get("event_type", "")) in {"authz_denied", "policy_denied", "signature_failure", "signature_replay"}:
            role = str(row.get("role", "") or "unknown")
            denied_by_role[role] = denied_by_role.get(role, 0) + 1
    for role, count in denied_by_role.items():
        if count >= 3:
            anomalies.append(
                {
                    "type": "privilege_or_policy_probe",
                    "severity": "medium",
                    "role": role,
                    "count": count,
                    "summary": f"{role} triggered {count} denied privileged requests.",
                }
            )

    dangerous_mutations = [
        row for row in action_rows
        if str(row.get("method", "")).upper() in {"POST", "PATCH", "DELETE"}
        and any(token in str(row.get("path", "")) for token in ["/actions/", "/network/warfare/", "/quarantine/"])
    ]
    if len(dangerous_mutations) >= 10:
        anomalies.append(
            {
                "type": "high_mutation_volume",
                "severity": "medium",
                "count": len(dangerous_mutations),
                "summary": "High volume of dangerous or destructive mutation requests detected.",
            }
        )

    return anomalies
