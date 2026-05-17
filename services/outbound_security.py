from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse


TRUE_VALUES = {"1", "true", "yes", "on"}

# Hostnames whose loopback-IP resolution is intentional. Anything else
# that DNS-resolves to 127.0.0.1 / ::1 (e.g. `lvh.me`, `localtest.me`,
# or an attacker-controlled public domain) is rejected so an operator
# who whitelists `https://api.partner.example` cannot be redirected to
# their own admin API via a hostile DNS answer.
_LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})


def _hostname_is_loopback_literal(hostname: str) -> bool:
    return (hostname or "").strip().lower() in _LOOPBACK_HOSTNAMES


def normalize_outbound_url(raw_url: Any, *, allow_http_localhost: bool = True) -> str:
    candidate = str(raw_url or "").strip()
    if not candidate:
        return ""
    parsed = urlparse(candidate)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return ""
    hostname = parsed.hostname or ""
    if parsed.scheme == "http" and (not allow_http_localhost or hostname not in {"127.0.0.1", "localhost"}):
        return ""
    if not _host_is_allowed(hostname):
        return ""
    return candidate


def resolve_safe_outbound_address(raw_url: Any, *, allow_http_localhost: bool = True) -> tuple[str, str] | None:
    """Validate the URL AND pin a specific destination IP for connect().

    Returns `(normalized_url, ip_address)` when the URL is safe and at
    least one resolved IP passes `_ip_is_allowed`. The caller is
    expected to dial that exact IP (with SNI set to the original host)
    instead of letting the HTTP stack re-resolve DNS, which closes the
    classic DNS-rebinding TOCTOU between validation and connect.

    Returns `None` when the URL is unsafe / nothing resolves.
    """
    normalized = normalize_outbound_url(raw_url, allow_http_localhost=allow_http_localhost)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return None
    # Hostname == literal IP: we already vetted it inside
    # `_host_is_allowed`; reuse it verbatim.
    try:
        ipaddress.ip_address(hostname)
        return normalized, hostname
    except ValueError:
        pass
    if hostname == "localhost":
        # `localhost` is a fixed allow-listed name; pin to loopback so
        # a malicious `/etc/hosts` entry can't redirect us.
        return normalized, "127.0.0.1"
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    hostname_is_loopback = _hostname_is_loopback_literal(hostname)
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            continue
        if _ip_is_allowed(ip_obj, hostname_is_loopback_literal=hostname_is_loopback):
            return normalized, str(ip_obj)
    return None


def _host_is_allowed(hostname: str) -> bool:
    # NOTE: Intentionally NOT cached. Caching the allow/deny decision enables
    # a DNS-rebinding attack: a hostname that first resolves to a public IP
    # (cached as allowed) later resolves to 169.254.169.254 or 10.x at
    # request time. The actual HTTP dispatcher re-resolves anyway, so the
    # cache offers only a tiny win and a real SSRF gap.
    lowered = (hostname or "").strip().lower()
    if not lowered:
        return False
    if lowered == "localhost":
        return True
    hostname_is_loopback = _hostname_is_loopback_literal(lowered)
    try:
        ip_obj = ipaddress.ip_address(lowered)
        return _ip_is_allowed(ip_obj, hostname_is_loopback_literal=hostname_is_loopback)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(lowered, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    resolved_any = False
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            return False
        resolved_any = True
        if not _ip_is_allowed(ip_obj, hostname_is_loopback_literal=hostname_is_loopback):
            return False
    return resolved_any


def _ip_is_allowed(
    ip_obj: ipaddress._BaseAddress,
    *,
    hostname_is_loopback_literal: bool = False,
) -> bool:
    if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_reserved:
        return False
    if ip_obj.is_loopback:
        # A public hostname that resolves to 127.0.0.1 (e.g. `lvh.me`,
        # `localtest.me`, attacker-controlled DNS) is SSRF dressed up as
        # a webhook. Only accept loopback IPs when the URL hostname was
        # itself a literal loopback name (`localhost`, `127.0.0.1`,
        # `::1`) — anything else means a public name is being rebound
        # to point at our own admin surface.
        return hostname_is_loopback_literal
    if ip_obj.is_link_local:
        return False
    if ip_obj.is_private and not _allow_private_egress():
        return False
    return True


def _allow_private_egress() -> bool:
    raw = os.environ.get("SHADOWLAB_ALLOW_PRIVATE_EGRESS", "")
    return raw.strip().lower() in TRUE_VALUES
