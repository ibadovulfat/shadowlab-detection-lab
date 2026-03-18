from __future__ import annotations

import ipaddress
import os
import socket
from functools import lru_cache
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


@lru_cache(maxsize=256)
def _host_is_allowed(hostname: str) -> bool:
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
