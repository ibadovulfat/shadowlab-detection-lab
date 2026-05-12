"""Shared rate-limit invocation helper.

Wraps security_module._enforce_request_rate_limit so routes do not need to
construct stub Request objects when limiting background/internal calls.
"""
from __future__ import annotations

from fastapi import Request

import api.security as security_module


class _StubClient:
    host = "internal"


class _StubState:  # noqa: D401 — attribute container
    pass


class _StubUrl:
    def __init__(self, bucket: str) -> None:
        self.path = f"/{bucket}"


class _StubRequest:
    def __init__(self, bucket: str) -> None:
        self.client = _StubClient()
        self.state = _StubState()
        self.url = _StubUrl(bucket)


#: Buckets that apply the tighter 6-per-minute limit.
_TIGHT_BUCKETS = {"monitor_run", "triage"}
#: Security-critical buckets that get the strictest cap (brute-force
#: surfaces). 10 / 60s is multiple orders of magnitude below the
#: throughput needed to brute force a 6-digit TOTP or replay a stolen
#: signed-request envelope, but still leaves headroom for an operator
#: fat-fingering their authenticator a few times.
_STRICT_BUCKETS = {"mfa_verify"}


def apply_rate_limit(request: Request | None, *, bucket: str, detail: str) -> None:
    """Apply the configured per-bucket rate limit, raising HTTP 429 when tripped."""
    target_request = request if request is not None else _StubRequest(bucket)
    if bucket in _STRICT_BUCKETS:
        limit = 10
    elif bucket in _TIGHT_BUCKETS:
        limit = 6
    else:
        limit = 12
    security_module._enforce_request_rate_limit(  # type: ignore[attr-defined]
        target_request,  # type: ignore[arg-type]
        bucket=bucket,
        limit=limit,
        window_seconds=60,
        detail=detail,
    )
