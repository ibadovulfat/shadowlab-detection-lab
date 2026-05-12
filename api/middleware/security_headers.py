"""ASGI middleware: TLS enforcement, body-limit, security headers, approval finalization.

Split out of `api/main.py` for clarity. `register(app, ...)` installs a
single `http` middleware that:

1. Rejects plaintext HTTP when `require_tls` is on (except `/health`).
2. Caps request body size by path (imports get a larger quota).
3. Wraps `call_next` in try/except so that an approval reservation is
   always finalized or released — previously an unhandled exception left
   the approval pinned forever.
4. Stamps hardening headers (CSP, HSTS, X-Frame-Options, etc.).
5. Fires mutating-request audit + approval consume on both the happy and
   failure paths.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.observability import default_registry
from api.security import request_from_trusted_proxy

# Metric handles — created once at import so request path stays allocation-free.
_REQUEST_COUNTER = default_registry.counter(
    "shadowlab_http_requests_total",
    help="Total HTTP requests by method and final status bucket.",
)
_BODY_LIMIT_REJECTS = default_registry.counter(
    "shadowlab_body_limit_rejects_total",
    help="Requests rejected by the body-size guard (HTTP 413).",
)
_TLS_REJECTS = default_registry.counter(
    "shadowlab_tls_rejects_total",
    help="Plaintext requests rejected when require_tls is enabled.",
)

# Paths exempt from TLS enforcement and audit/approval bookkeeping. `/health`
# is the only one we leave open because it must answer without auth/TLS for
# load balancers.
_EXEMPT_PATHS: frozenset[str] = frozenset({"/health"})
# MUST include every method that can mutate server state. Keep in sync with
# `_MUTATING_METHODS_AUTH` in api/security.py — these two sets together
# enforce signed-request validation, MFA, Origin allow-list, audit log
# and approval-consume. Omitting `PUT` previously let admin endpoints
# (antivirus credentials, YARA policy, AV lists) bypass all of these.
_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_BODY_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})


def _origin_matches_allow_list(origin: str, allow_list: list[str]) -> bool:
    """True if `origin` matches one of the configured CORS allow-list entries.

    Origin is compared case-insensitively, after stripping trailing `/`.
    A literal `*` entry in the allow-list disables the check (existing
    posture validation already forbids `*` in corp/prod).
    """
    if not origin:
        return False
    candidate = origin.strip().rstrip("/").lower()
    for entry in allow_list:
        normalized = str(entry or "").strip().rstrip("/").lower()
        if not normalized:
            continue
        if normalized == "*" or normalized == candidate:
            return True
    return False


def request_is_secure(request: Request) -> bool:
    """True if this request arrived over HTTPS (directly or via trusted proxy)."""
    if request.url.scheme == "https":
        return True
    if not request_from_trusted_proxy(request):
        return False
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip().lower()
    return forwarded_proto == "https"


def request_body_limit_bytes(
    request: Request,
    *,
    default_limit: int,
    import_limit: int,
) -> int:
    """Per-path body-size cap: `/import` routes get the larger quota."""
    if "/import" in request.url.path:
        return import_limit
    return default_limit


def register(
    app: FastAPI,
    *,
    security_settings: Any,
    default_body_limit: int,
    import_body_limit: int,
    consume_pending_approval: Callable[[Request, int], None],
    audit_mutating_request: Callable[[Request, int], None],
) -> Callable[[Request, Callable[[Request], Any]], Any]:
    """Install the `add_security_headers` middleware on `app` and return it.

    Returning the closure lets callers (notably `api.main`) re-expose it as a
    module attribute — several tests invoke `api.main.add_security_headers`
    directly to exercise the middleware without spinning up the full app.
    """

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Callable[[Request], Any]):
        if (
            security_settings.require_tls
            and not request_is_secure(request)
            and request.url.path not in _EXEMPT_PATHS
        ):
            _TLS_REJECTS.inc()
            return JSONResponse(status_code=400, content={"detail": "HTTPS is required for this endpoint"})

        method = request.method.upper()

        # Defense-in-depth Origin check on mutating requests. Native
        # clients (desktop, curl, CI) don't send `Origin`, so absence is
        # accepted. When a browser DOES set it, the value must appear in
        # the configured CORS allow-list — otherwise a malicious page on
        # another origin can't ride along on an analyst's API key.
        # Returning a JSONResponse directly (vs raising HTTPException)
        # is the supported pattern inside an `@app.middleware("http")`
        # body: raised HTTPExceptions are NOT caught by FastAPI's
        # exception handlers here and end up as 500s.
        if method in _MUTATING_METHODS and request.url.path not in _EXEMPT_PATHS:
            origin = (request.headers.get("origin") or "").strip()
            if origin and not _origin_matches_allow_list(origin, list(security_settings.allowed_origins)):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Request Origin is not in the configured allow-list"},
                )
        if method in _BODY_METHODS:
            limit = request_body_limit_bytes(
                request,
                default_limit=default_body_limit,
                import_limit=import_body_limit,
            )
            content_length = (request.headers.get("content-length") or "").strip()
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
                if declared_length < 0:
                    return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
                if declared_length > limit:
                    _BODY_LIMIT_REJECTS.inc()
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds limit of {limit} bytes"},
                    )
            # Stream the body and abort as soon as accumulated bytes exceed the
            # limit — the previous `await request.body()` buffered the ENTIRE
            # payload into RAM before checking, so a client could send
            # `Content-Length: 10` and then actually stream gigabytes (chunked
            # transfer encoding, or misreported length with connection close).
            # Early-abort caps RSS growth at `limit + one chunk` regardless of
            # what the client claims up front.
            total = 0
            chunks: list[bytes] = []
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > limit:
                    _BODY_LIMIT_REJECTS.inc()
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds limit of {limit} bytes"},
                    )
                chunks.append(chunk)
            # Cache the consumed body on the Request so downstream handlers
            # that call `await request.body()` / `await request.json()` see
            # the full payload. Starlette's Request.body() returns `_body`
            # when present instead of re-draining the (now exhausted) stream.
            request._body = b"".join(chunks)  # type: ignore[attr-defined]

        # Wrap the downstream handler so that an approval reservation is
        # always released/consumed, even when an unhandled exception
        # propagates past the route — otherwise the approval stays pinned
        # with used_at=-1 forever and the operator has no way to recover it.
        approval_status = 500
        try:
            response = await call_next(request)
            approval_status = response.status_code
        except Exception:
            # Re-raise after clean-up; Starlette turns this into a 500.
            if method in _MUTATING_METHODS and request.url.path not in _EXEMPT_PATHS:
                consume_pending_approval(request, 500)
                audit_mutating_request(request, 500)
            raise

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Strict CSP: explicit `script-src`/`object-src`/`form-action`
        # so a browser that ignores `default-src 'none'` (very few, but
        # CSP3 tooling lints expect them spelled out) still refuses to
        # execute or submit anything. We're a JSON API — there is no
        # legitimate inline script or form post anywhere in the surface.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'none'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'none'; "
            "base-uri 'none'"
        )
        if request_is_secure(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if method in _MUTATING_METHODS and request.url.path not in _EXEMPT_PATHS:
            consume_pending_approval(request, approval_status)
            audit_mutating_request(request, approval_status)
        # Bucket the response status class so the label cardinality stays
        # bounded (2xx/3xx/4xx/5xx). Per-code labels blow up the series
        # count and aren't useful for dashboards.
        default_registry.counter(
            "shadowlab_http_requests_total",
            {
                "method": method,
                "status_class": f"{approval_status // 100}xx",
            },
        ).inc()
        return response

    return add_security_headers
