from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse


TRUE_VALUES = {"1", "true", "yes", "on"}


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
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            continue
        if _ip_is_allowed(ip_obj):
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
    try:
        ip_obj = ipaddress.ip_address(lowered)
        return _ip_is_allowed(ip_obj)
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
        if not _ip_is_allowed(ip_obj):
            return False
    return resolved_any


def _ip_is_allowed(ip_obj: ipaddress._BaseAddress) -> bool:
    if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_reserved:
        return False
    if ip_obj.is_loopback:
        return True
    if ip_obj.is_link_local:
        return False
    if ip_obj.is_private and not _allow_private_egress():
        return False
    return True


def _allow_private_egress() -> bool:
    raw = os.environ.get("SHADOWLAB_ALLOW_PRIVATE_EGRESS", "")
    return raw.strip().lower() in TRUE_VALUES
