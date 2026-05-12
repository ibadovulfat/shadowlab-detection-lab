from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

import requests
from requests import Response


# Must mirror api.security.SHADOWLAB_SIGNING_HKDF_INFO. Hard-coding here
# (rather than importing from `api.security`) keeps the desktop bundle
# importable without the server-side `services` / FastAPI dependencies.
_SHADOWLAB_SIGNING_HKDF_INFO = b"shadowlab-signing-v1"


def _derive_signing_secret(api_key: str) -> bytes:
    """HKDF-SHA256 derivation of the per-request signing key from the
    bearer API key. See api.security.derive_signing_secret for the
    rationale. Implemented locally so the desktop ships without the
    `cryptography` package as a hard requirement — falls back to a
    pure-stdlib HKDF when `cryptography` isn't installed.
    """
    if not api_key:
        return b""
    ikm = api_key.encode("utf-8")
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_SHADOWLAB_SIGNING_HKDF_INFO,
        )
        return hkdf.derive(ikm)
    except Exception:
        return _hkdf_sha256_stdlib(ikm, _SHADOWLAB_SIGNING_HKDF_INFO, 32)


def _hkdf_sha256_stdlib(ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Extract-and-Expand on stdlib hmac/hashlib only."""
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


class ShadowLabApiClient:
    def __init__(
        self,
        *,
        base_url_getter: Callable[[], str],
        api_key_getter: Callable[[], str],
        workspace_id_getter: Callable[[], str],
        actor_getter: Callable[[], str],
        approval_id_getter: Callable[[], str],
    ) -> None:
        self._base_url_getter = base_url_getter
        self._api_key_getter = api_key_getter
        self._workspace_id_getter = workspace_id_getter
        self._actor_getter = actor_getter
        self._approval_id_getter = approval_id_getter

    def url(self, path: str) -> str:
        return self._base_url_getter().rstrip("/") + path

    def auth_headers(self) -> dict[str, str]:
        api_key = self._api_key_getter().strip()
        return {"X-API-Key": api_key} if api_key else {}

    def canonical_request_components(self, path: str, kwargs: dict) -> tuple[str, str, str]:
        split = urlsplit(path)
        query_pairs = parse_qsl(split.query, keep_blank_values=True)
        params = kwargs.get("params")
        if isinstance(params, dict):
            for key, value in params.items():
                if isinstance(value, (list, tuple)):
                    for item in value:
                        query_pairs.append((str(key), "" if item is None else str(item)))
                else:
                    query_pairs.append((str(key), "" if value is None else str(value)))
        elif isinstance(params, (list, tuple)):
            for key, value in params:
                query_pairs.append((str(key), "" if value is None else str(value)))
        query_pairs.sort()
        canonical_query = "&".join(f"{key}={value}" for key, value in query_pairs)

        body_bytes = b""
        if "json" in kwargs and kwargs["json"] is not None:
            body_bytes = json.dumps(kwargs["json"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        elif "data" in kwargs and kwargs["data"] is not None:
            data = kwargs["data"]
            if isinstance(data, bytes):
                body_bytes = data
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, dict):
                body_pairs: list[tuple[str, str]] = []
                for key, value in data.items():
                    if isinstance(value, (list, tuple)):
                        for item in value:
                            body_pairs.append((str(key), "" if item is None else str(item)))
                    else:
                        body_pairs.append((str(key), "" if value is None else str(value)))
                body_pairs.sort()
                body_bytes = "&".join(f"{key}={value}" for key, value in body_pairs).encode("utf-8")
            else:
                body_bytes = str(data).encode("utf-8")
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        return split.path or path, canonical_query, body_hash

    def signed_headers(self, method: str, path: str, kwargs: dict | None = None) -> dict[str, str]:
        api_key = self._api_key_getter().strip()
        if not api_key or method.upper() not in {"POST", "PATCH", "DELETE"}:
            return {}
        request_kwargs = kwargs or {}
        canonical_path, canonical_query, body_hash = self.canonical_request_components(path, request_kwargs)
        timestamp = str(int(time.time()))
        nonce = hashlib.sha256(f"{timestamp}:{path}:{time.time_ns()}".encode("utf-8")).hexdigest()[:24]
        payload = "\n".join([method.upper(), canonical_path, canonical_query, body_hash, timestamp, nonce])
        # HKDF-derived signing secret — see _derive_signing_secret().
        signing_key = _derive_signing_secret(api_key)
        signature = hmac.new(signing_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-ShadowLab-Timestamp": timestamp,
            "X-ShadowLab-Nonce": nonce,
            "X-ShadowLab-Signature": signature,
        }

    def approval_headers(self, method: str) -> dict[str, str]:
        if method.upper() not in {"POST", "PATCH", "DELETE"}:
            return {}
        approval_id = self._approval_id_getter().strip()
        if not approval_id:
            return {}
        return {"X-ShadowLab-Approval-Id": approval_id}

    def workspace_headers(self) -> dict[str, str]:
        workspace_id = self._workspace_id_getter().strip().lower() or "default"
        headers = {"X-ShadowLab-Workspace": workspace_id}
        actor = self._actor_getter().strip().lower()
        if actor:
            headers["X-ShadowLab-Actor"] = actor
        return headers

    def permission_guidance(self, detail: str) -> str:
        message = (detail or "").strip().lower()
        if "analyst or admin role required" in message:
            return "This action requires an analyst or admin API key. Apply a higher-privilege key and press OK."
        if "admin role required" in message:
            return "This action requires an admin API key. Apply the admin key and press OK."
        if "invalid api key" in message:
            return "The API key was rejected. Re-enter a valid viewer, analyst, or admin key and press OK."
        if "https is required" in message:
            return "The backend requires HTTPS. Update the API Base URL to an https:// endpoint."
        return ""

    def format_api_exception(self, exc: Exception) -> str:
        message = str(exc).strip()
        guidance = ""
        response = getattr(exc, "response", None)
        if response is not None:
            try:
                payload = response.json()
            except ValueError:
                payload = None
            detail = ""
            if isinstance(payload, dict):
                detail = str(payload.get("detail") or payload.get("message") or "").strip()
            if not detail:
                detail = (getattr(response, "text", "") or "").strip()
            guidance = self.permission_guidance(detail)
        if not guidance:
            guidance = self.permission_guidance(message)
        if guidance and guidance not in message:
            return f"{message}\n\n{guidance}"
        return message

    def raise_for_api_error(self, response: Response) -> None:
        if response.ok:
            return
        detail = ""
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            detail = str(payload.get("detail") or payload.get("message") or "").strip()
        if not detail:
            detail = (response.text or "").strip()[:300]
        if not detail:
            detail = f"HTTP {response.status_code}"
        raise requests.HTTPError(f"HTTP {response.status_code}: {detail}", response=response)

    def request(self, method: str, path: str, **kwargs) -> Response:
        should_raise = kwargs.pop("raise_for_status", True)
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(self.auth_headers())
        headers.update(self.workspace_headers())
        headers.update(self.signed_headers(method, path, kwargs))
        headers.update(self.approval_headers(method))
        # mTLS support — picked up from env so a fleet deploy can opt in
        # without touching every call site. Pair `SHADOWLAB_CLIENT_CERT`
        # with `SHADOWLAB_CLIENT_KEY` (or a single combined PEM); set
        # `SHADOWLAB_TLS_CA_BUNDLE` to point at the API server's CA so
        # the desktop trusts the lab-issued cert without polluting the
        # system trust store.
        import os as _os
        cert_path = (_os.environ.get("SHADOWLAB_CLIENT_CERT", "") or "").strip()
        key_path = (_os.environ.get("SHADOWLAB_CLIENT_KEY", "") or "").strip()
        ca_bundle = (_os.environ.get("SHADOWLAB_TLS_CA_BUNDLE", "") or "").strip()
        if cert_path and key_path and "cert" not in kwargs:
            kwargs["cert"] = (cert_path, key_path)
        elif cert_path and "cert" not in kwargs:
            kwargs["cert"] = cert_path
        if ca_bundle and "verify" not in kwargs:
            kwargs["verify"] = ca_bundle
        response = requests.request(
            method,
            self.url(path),
            headers=headers,
            timeout=kwargs.pop("timeout", 20),
            **kwargs,
        )
        if should_raise:
            self.raise_for_api_error(response)
        return response

    def get(self, path: str, **kwargs) -> Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> Response:
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs) -> Response:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs) -> Response:
        return self.request("DELETE", path, **kwargs)
