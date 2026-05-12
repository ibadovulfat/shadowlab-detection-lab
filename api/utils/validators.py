"""Low-level value validators used by request schemas and route handlers."""
from __future__ import annotations

import ipaddress
import re

SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{0,128}$")
CONNECTOR_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
MAX_NETWORK_SCAN_PREFIXLEN = 16


def validated_sha256(value: str) -> str:
    candidate = (value or "").strip().lower()
    if not SHA256_RE.fullmatch(candidate):
        raise ValueError("SHA-256 values must be 64 hexadecimal characters")
    return candidate


def validated_ip_address(value: str) -> str:
    candidate = (value or "").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc


def validated_network_range(value: str) -> str:
    candidate = (value or "").strip()
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid IP range or CIDR") from exc
    if network.version != 4:
        raise ValueError("Network scans support IPv4 CIDR ranges only")
    if network.prefixlen < MAX_NETWORK_SCAN_PREFIXLEN:
        raise ValueError(f"Network scan range must be /{MAX_NETWORK_SCAN_PREFIXLEN} or smaller")
    return str(network)


def validated_incident_id(value: str) -> str:
    candidate = (value or "").strip()
    if candidate and not INCIDENT_ID_RE.fullmatch(candidate):
        raise ValueError("incident_id contains unsupported characters")
    return candidate


def parse_csv_query_values(raw: str) -> list[str]:
    return [item.strip().lower() for item in (raw or "").split(",") if item.strip()]
