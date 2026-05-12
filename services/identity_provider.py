from __future__ import annotations

import base64
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_ROLE = "viewer"
ALLOWED_ROLES = {"viewer", "analyst", "admin"}


@dataclass(frozen=True)
class OIDCSettings:
    enabled: bool
    issuer_url: str
    audience: str
    client_id: str
    discovery_url: str
    jwks_url: str
    username_claim: str
    role_claim: str
    workspace_claim: str
    approver_claim: str
    role_map: dict[str, tuple[str, ...]]
    approver_values: tuple[str, ...]
    clock_skew_seconds: int
    metadata_ttl_seconds: int
    request_timeout_seconds: float


@dataclass(frozen=True)
class IdentityPrincipal:
    subject: str
    actor: str
    role: str
    allowed_workspaces: tuple[str, ...]
    approval_workspaces: tuple[str, ...]
    issuer: str
    audience: str
    token_id: str
    expires_at: float
    issued_at: float
    claims: dict[str, Any]


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in TRUE_VALUES


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _json_b64url(value: str) -> dict[str, Any]:
    loaded = json.loads(_b64url_decode(value))
    return loaded if isinstance(loaded, dict) else {}


def _normalize_workspace_list(raw: Any) -> tuple[str, ...]:
    values: list[str] = []
    if isinstance(raw, str):
        candidates = [item.strip().lower() for item in raw.replace("|", ",").split(",")]
    elif isinstance(raw, list):
        candidates = [str(item).strip().lower() for item in raw]
    else:
        candidates = []
    for item in candidates:
        if item and item not in values:
            values.append(item)
    return tuple(values)


def _parse_role_map(raw: str | None) -> dict[str, tuple[str, ...]]:
    mapping: dict[str, tuple[str, ...]] = {}
    for chunk in str(raw or "").split(";"):
        item = str(chunk).strip()
        if not item or ":" not in item:
            continue
        role, values = item.split(":", 1)
        role_name = str(role).strip().lower()
        if role_name not in ALLOWED_ROLES:
            continue
        parsed = _normalize_workspace_list(values)
        if parsed:
            mapping[role_name] = parsed
    return mapping


def load_oidc_settings() -> OIDCSettings:
    issuer = str(os.environ.get("SHADOWLAB_OIDC_ISSUER_URL", "") or "").strip()
    discovery = str(os.environ.get("SHADOWLAB_OIDC_DISCOVERY_URL", "") or "").strip()
    enabled = _as_bool(os.environ.get("SHADOWLAB_OIDC_ENABLED"), bool(issuer or discovery))
    role_map = _parse_role_map(
        os.environ.get(
            "SHADOWLAB_OIDC_ROLE_MAP",
            "admin:shadowlab-admin|shadowlab-admins;analyst:shadowlab-analyst|shadowlab-analysts;viewer:shadowlab-viewer|shadowlab-viewers",
        )
    )
    approver_values = _normalize_workspace_list(os.environ.get("SHADOWLAB_OIDC_APPROVER_VALUES", "shadowlab-approver|shadowlab-approvers"))
    return OIDCSettings(
        enabled=enabled,
        issuer_url=issuer.rstrip("/"),
        audience=str(os.environ.get("SHADOWLAB_OIDC_AUDIENCE", "") or "").strip(),
        client_id=str(os.environ.get("SHADOWLAB_OIDC_CLIENT_ID", "") or "").strip(),
        discovery_url=discovery,
        jwks_url=str(os.environ.get("SHADOWLAB_OIDC_JWKS_URL", "") or "").strip(),
        username_claim=str(os.environ.get("SHADOWLAB_OIDC_USERNAME_CLAIM", "preferred_username") or "preferred_username").strip(),
        role_claim=str(os.environ.get("SHADOWLAB_OIDC_ROLE_CLAIM", "roles") or "roles").strip(),
        workspace_claim=str(os.environ.get("SHADOWLAB_OIDC_WORKSPACE_CLAIM", "shadowlab_workspaces") or "shadowlab_workspaces").strip(),
        approver_claim=str(os.environ.get("SHADOWLAB_OIDC_APPROVER_CLAIM", "shadowlab_approvals") or "shadowlab_approvals").strip(),
        role_map=role_map,
        approver_values=approver_values,
        clock_skew_seconds=max(0, int(float(os.environ.get("SHADOWLAB_OIDC_CLOCK_SKEW_SECONDS", "60") or 60))),
        metadata_ttl_seconds=max(30, int(float(os.environ.get("SHADOWLAB_OIDC_METADATA_TTL_SECONDS", "300") or 300))),
        request_timeout_seconds=max(1.0, float(os.environ.get("SHADOWLAB_OIDC_REQUEST_TIMEOUT_SECONDS", "5") or 5)),
    )


class IdentityProvider:
    def __init__(self) -> None:
        # JWKS / discovery cache; concurrent workers + JWKS rotation can
        # race on a plain dict. The lock keeps reads/writes serialised
        # without holding it across the HTTP fetch (we copy out and then
        # rebuild the entry once requests returns).
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_lock = threading.Lock()

    def settings(self) -> OIDCSettings:
        return load_oidc_settings()

    def enabled(self) -> bool:
        return self.settings().enabled

    def discovery_metadata(self, settings: OIDCSettings | None = None) -> dict[str, Any]:
        active = settings or self.settings()
        if not active.enabled:
            return {"enabled": False}
        discovery_url = active.discovery_url
        if not discovery_url:
            if not active.issuer_url:
                raise ValueError("OIDC issuer URL is required when OIDC is enabled")
            discovery_url = f"{active.issuer_url}/.well-known/openid-configuration"
        payload = self._cached_json(discovery_url, active)
        if not isinstance(payload, dict):
            raise ValueError("OIDC discovery response must be a JSON object")
        return payload

    def clear_cache(self) -> None:
        """Drop the JWKS/discovery cache. Use after IdP key rotation."""
        with self._cache_lock:
            self._cache.clear()

    def authenticate_token(self, token: str) -> IdentityPrincipal:
        settings = self.settings()
        if not settings.enabled:
            raise ValueError("OIDC authentication is disabled")
        header_b64, payload_b64, signature_b64 = self._split_token(token)
        header = _json_b64url(header_b64)
        claims = _json_b64url(payload_b64)
        algorithm = str(header.get("alg", "") or "").strip()
        if algorithm not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}:
            raise ValueError(f"Unsupported OIDC token algorithm: {algorithm or 'unknown'}")
        jwk = self._resolve_jwk(header, settings)
        self._verify_signature(f"{header_b64}.{payload_b64}".encode("ascii"), _b64url_decode(signature_b64), jwk, algorithm)
        # Pass the resolved discovery issuer in alongside the static
        # `issuer_url` so `_validate_claims` can enforce `iss` even when
        # only a discovery URL was configured (i.e. `issuer_url` is empty).
        discovered_issuer = self._discovered_issuer(settings)
        self._validate_claims(claims, settings, discovered_issuer=discovered_issuer)
        subject = str(claims.get("sub", "") or "").strip()
        if not subject:
            raise ValueError("OIDC token is missing `sub`")
        actor = self._actor_from_claims(claims, settings)
        role = self._role_from_claims(claims, settings)
        allowed_workspaces = _normalize_workspace_list(claims.get(settings.workspace_claim))
        approval_workspaces = self._approval_workspaces_from_claims(claims, settings, allowed_workspaces, role)
        audience = claims.get("aud", settings.audience or settings.client_id or "")
        if isinstance(audience, list):
            audience = ",".join(str(item) for item in audience if str(item).strip())
        return IdentityPrincipal(
            subject=subject,
            actor=actor or subject,
            role=role,
            allowed_workspaces=allowed_workspaces,
            approval_workspaces=approval_workspaces,
            issuer=str(claims.get("iss", settings.issuer_url) or settings.issuer_url),
            audience=str(audience or ""),
            token_id=str(claims.get("jti", "") or ""),
            expires_at=float(claims.get("exp") or 0.0),
            issued_at=float(claims.get("iat") or 0.0),
            claims=self._sanitize_claims(claims),
        )

    def _split_token(self, token: str) -> tuple[str, str, str]:
        parts = str(token or "").strip().split(".")
        if len(parts) != 3 or not all(parts):
            raise ValueError("OIDC bearer token must be a compact JWT")
        return parts[0], parts[1], parts[2]

    def _cached_json(self, url: str, settings: OIDCSettings) -> dict[str, Any]:
        now = time.time()
        with self._cache_lock:
            cached = self._cache.get(url)
        if cached and now < cached[0]:
            return dict(cached[1])
        response = requests.get(url, timeout=settings.request_timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OIDC metadata response must be a JSON object")
        with self._cache_lock:
            self._cache[url] = (now + settings.metadata_ttl_seconds, payload)
        return dict(payload)

    def _resolve_jwk(self, header: dict[str, Any], settings: OIDCSettings) -> dict[str, Any]:
        metadata = self.discovery_metadata(settings)
        jwks_url = settings.jwks_url or str(metadata.get("jwks_uri", "") or "").strip()
        if not jwks_url:
            raise ValueError("OIDC discovery metadata did not include a JWKS URI")
        jwks = self._cached_json(jwks_url, settings)
        keys = jwks.get("keys", [])
        if not isinstance(keys, list):
            raise ValueError("OIDC JWKS payload must include a `keys` array")
        kid = str(header.get("kid", "") or "").strip()
        header_alg = str(header.get("alg", "") or "").strip()
        # Fail closed when the token omits `kid`: picking "the first key" opens
        # a key-confusion attack when the IdP rotates or serves multiple JWKs.
        if not kid:
            if len(keys) == 1 and isinstance(keys[0], dict):
                candidate = keys[0]
            else:
                raise ValueError("OIDC token missing required `kid` header")
        else:
            candidate = None
            for key in keys:
                if not isinstance(key, dict):
                    continue
                if str(key.get("kid", "") or "").strip() == kid:
                    candidate = key
                    break
            if candidate is None:
                raise ValueError(f"OIDC JWKS key not found for kid `{kid}`")
        # Enforce per-key constraints: only use signing keys and require the
        # token alg to match the JWK alg if the IdP publishes one.
        key_use = str(candidate.get("use", "") or "").strip().lower()
        if key_use and key_use != "sig":
            raise ValueError("OIDC JWK is not a signing key")
        key_alg = str(candidate.get("alg", "") or "").strip()
        if key_alg and header_alg and key_alg != header_alg:
            raise ValueError("OIDC token alg does not match JWK alg")
        return candidate

    def _verify_signature(self, signed_data: bytes, signature: bytes, jwk: dict[str, Any], algorithm: str) -> None:
        if algorithm.startswith("RS"):
            key = self._rsa_public_key(jwk)
            digest = self._hash_for_algorithm(algorithm)
            key.verify(signature, signed_data, padding.PKCS1v15(), digest)
            return
        if algorithm.startswith("ES"):
            key = self._ec_public_key(jwk)
            curve_size = (key.curve.key_size + 7) // 8
            if len(signature) != curve_size * 2:
                raise ValueError("ECDSA JWT signature length is invalid")
            r = int.from_bytes(signature[:curve_size], "big")
            s = int.from_bytes(signature[curve_size:], "big")
            der_signature = encode_dss_signature(r, s)
            key.verify(der_signature, signed_data, ec.ECDSA(self._hash_for_algorithm(algorithm)))
            return
        raise ValueError(f"Unsupported OIDC token algorithm: {algorithm}")

    # Per NIST SP 800-131A Rev. 2 and current industry guidance, RSA-1024
    # is disallowed and 2048 is the floor for general-purpose signing
    # through 2030. Fail closed against a compromised or misconfigured
    # IdP that ships a short modulus in JWKS.
    _RSA_MIN_BITS = 2048

    def _rsa_public_key(self, jwk: dict[str, Any]) -> rsa.RSAPublicKey:
        if str(jwk.get("kty", "") or "").upper() != "RSA":
            raise ValueError("OIDC JWK key type must be RSA for RS* tokens")
        n = int.from_bytes(_b64url_decode(str(jwk.get("n", "") or "")), "big")
        e = int.from_bytes(_b64url_decode(str(jwk.get("e", "") or "")), "big")
        if n.bit_length() < self._RSA_MIN_BITS:
            raise ValueError(
                f"OIDC JWK RSA modulus is too small ({n.bit_length()} bits); "
                f"minimum {self._RSA_MIN_BITS} required"
            )
        # Reject exotic / weak public exponents. e=1 means the signature
        # check degenerates; e=2 is non-RSA-OAEP; e=3 has been linked to
        # padding-oracle issues with implementations that don't strictly
        # follow PKCS#1 v1.5. The de-facto safe exponent is 65537.
        if e < 3 or e % 2 == 0:
            raise ValueError("OIDC JWK RSA exponent is invalid")
        return rsa.RSAPublicNumbers(e, n).public_key()

    def _ec_public_key(self, jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
        if str(jwk.get("kty", "") or "").upper() != "EC":
            raise ValueError("OIDC JWK key type must be EC for ES* tokens")
        curve_name = str(jwk.get("crv", "") or "").upper()
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}.get(curve_name)
        if curve is None:
            raise ValueError(f"Unsupported OIDC EC curve `{curve_name or 'unknown'}`")
        x = int.from_bytes(_b64url_decode(str(jwk.get("x", "") or "")), "big")
        y = int.from_bytes(_b64url_decode(str(jwk.get("y", "") or "")), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()

    def _hash_for_algorithm(self, algorithm: str):
        mapping = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
            "ES256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }
        return mapping[algorithm]

    def _discovered_issuer(self, settings: OIDCSettings) -> str:
        """Best-effort resolution of the `issuer` field from discovery metadata.

        Returns an empty string when discovery is unreachable or the
        metadata doesn't carry the field — the caller treats that as
        "no discovery-side anchor, use configured issuer".
        """
        try:
            metadata = self.discovery_metadata(settings)
        except Exception:
            return ""
        return str(metadata.get("issuer", "") or "").strip().rstrip("/")

    def _validate_claims(
        self,
        claims: dict[str, Any],
        settings: OIDCSettings,
        *,
        discovered_issuer: str = "",
    ) -> None:
        now = int(time.time())
        skew = settings.clock_skew_seconds
        issuer = str(claims.get("iss", "") or "").strip().rstrip("/")
        # Anchor the `iss` claim against EITHER the explicitly configured
        # issuer OR (when only a discovery URL is set) the issuer field
        # the IdP advertised through that discovery document. Without
        # this, a deployment using only `SHADOWLAB_OIDC_DISCOVERY_URL`
        # silently accepted any token signed by the right JWKS regardless
        # of which tenant minted it.
        expected_issuer = settings.issuer_url or discovered_issuer
        if not expected_issuer:
            raise ValueError(
                "OIDC issuer is not pinned; set SHADOWLAB_OIDC_ISSUER_URL "
                "or configure a discovery URL that advertises `issuer`"
            )
        if issuer != expected_issuer:
            raise ValueError("OIDC token issuer does not match configured issuer")
        audiences = claims.get("aud", [])
        if isinstance(audiences, str):
            audience_values = {audiences}
        elif isinstance(audiences, list):
            audience_values = {str(item) for item in audiences if str(item).strip()}
        else:
            audience_values = set()
        required_audiences = {item for item in {settings.audience, settings.client_id} if item}
        # Fail closed when neither audience nor client_id is configured;
        # otherwise any IdP-signed JWT (correct issuer, valid signature)
        # is accepted regardless of which application it was minted for.
        if not required_audiences:
            raise ValueError(
                "OIDC audience is not configured; set SHADOWLAB_OIDC_AUDIENCE or SHADOWLAB_OIDC_CLIENT_ID"
            )
        if not (audience_values & required_audiences):
            raise ValueError("OIDC token audience does not match configured client or audience")
        exp = int(float(claims.get("exp") or 0))
        if exp and now > exp + skew:
            raise ValueError("OIDC token has expired")
        nbf = int(float(claims.get("nbf") or 0))
        if nbf and now + skew < nbf:
            raise ValueError("OIDC token is not active yet")
        iat = int(float(claims.get("iat") or 0))
        if iat and now + skew < iat:
            raise ValueError("OIDC token issue time is in the future")

    def _actor_from_claims(self, claims: dict[str, Any], settings: OIDCSettings) -> str:
        for key in [settings.username_claim, "email", "preferred_username", "upn", "sub"]:
            value = str(claims.get(key, "") or "").strip().lower()
            if value:
                return value[:120]
        return ""

    def _role_from_claims(self, claims: dict[str, Any], settings: OIDCSettings) -> str:
        claim_values = self._claim_values(claims, settings.role_claim)
        claim_values.update(self._claim_values(claims, "groups"))
        claim_values.update(self._claim_values(claims, "roles"))
        for role in ("admin", "analyst", "viewer"):
            expected = set(settings.role_map.get(role, ()))
            if expected and claim_values & expected:
                return role
        return DEFAULT_ROLE

    def _approval_workspaces_from_claims(
        self,
        claims: dict[str, Any],
        settings: OIDCSettings,
        allowed_workspaces: tuple[str, ...],
        role: str,
    ) -> tuple[str, ...]:
        explicit = _normalize_workspace_list(claims.get(settings.approver_claim))
        if explicit:
            return explicit
        claim_values = self._claim_values(claims, settings.approver_claim)
        claim_values.update(self._claim_values(claims, "groups"))
        if settings.approver_values and claim_values & set(settings.approver_values):
            return allowed_workspaces
        if role == "admin":
            return allowed_workspaces
        return ()

    def _claim_values(self, claims: dict[str, Any], key: str) -> set[str]:
        if not key:
            return set()
        raw = claims.get(key)
        if isinstance(raw, str):
            return {item for item in _normalize_workspace_list(raw)}
        if isinstance(raw, list):
            return {str(item).strip().lower() for item in raw if str(item).strip()}
        return set()

    def _sanitize_claims(self, claims: dict[str, Any]) -> dict[str, Any]:
        sanitized: dict[str, Any] = {}
        for key, value in claims.items():
            lower_key = str(key).lower()
            if lower_key in {"nonce", "at_hash", "c_hash", "sid"}:
                continue
            if isinstance(value, (str, int, float, bool)):
                sanitized[str(key)] = value
            elif isinstance(value, list):
                sanitized[str(key)] = [str(item) for item in value[:20]]
        return sanitized
identity_provider = IdentityProvider()
