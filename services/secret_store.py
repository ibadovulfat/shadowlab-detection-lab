from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import logging
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_logger = logging.getLogger(__name__)


SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "client_secret",
    "password",
    "secret",
    "shared_key",
    "token",
}
ENCRYPTED_PREFIX = "enc:v2:"
ENCRYPTED_PREFIX_DPAPI = "enc:v3:dpapi:"
ENCRYPTED_PREFIX_AES = "enc:v3:aes:"
LEGACY_ENCRYPTED_PREFIX = "enc:v1:"
SECRET_MASK = "***redacted***"


def is_encrypted_secret(value: str | None) -> bool:
    candidate = str(value or "")
    return (
        candidate.startswith(ENCRYPTED_PREFIX_DPAPI)
        or candidate.startswith(ENCRYPTED_PREFIX_AES)
        or candidate.startswith(ENCRYPTED_PREFIX)
        or candidate.startswith(LEGACY_ENCRYPTED_PREFIX)
    )


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


class SecretStore:
    def protect_config(self, config: dict[str, Any]) -> dict[str, Any]:
        protected: dict[str, Any] = {}
        for key, value in (config or {}).items():
            if isinstance(value, dict):
                protected[key] = self.protect_config(value)
                continue
            if self._is_sensitive_key(key) and isinstance(value, str) and value.strip():
                protected[key] = self.encrypt_text(value)
                continue
            protected[key] = value
        return protected

    def reveal_config(self, config: dict[str, Any]) -> dict[str, Any]:
        revealed: dict[str, Any] = {}
        for key, value in (config or {}).items():
            if isinstance(value, dict):
                revealed[key] = self.reveal_config(value)
                continue
            if isinstance(value, str) and self._is_encrypted_value(value):
                revealed[key] = self.decrypt_text(value)
                continue
            revealed[key] = value
        return revealed

    def redact_config(self, config: dict[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for key, value in (config or {}).items():
            if isinstance(value, dict):
                redacted[key] = self.redact_config(value)
                continue
            if self._is_sensitive_key(key) and value not in {None, ""}:
                redacted[key] = SECRET_MASK
                continue
            redacted[key] = value
        return redacted

    def encrypt_text(self, plaintext: str) -> str:
        # v3 blobs explicitly tag the wrap algorithm (`dpapi` or `aes`)
        # so decrypt knows which path to take without probing. The old
        # v2 blob format relied on `os.name` matching at decrypt time
        # which silently fell through to AES when DPAPI failed — now
        # the tag tells us exactly what to expect.
        raw = plaintext.encode("utf-8")
        if os.name == "nt":
            return ENCRYPTED_PREFIX_DPAPI + self._dpapi_encrypt(raw)
        return ENCRYPTED_PREFIX_AES + self._aesgcm_encrypt(raw)

    def decrypt_text(self, ciphertext: str) -> str:
        # v3: explicit algorithm tag.
        if ciphertext.startswith(ENCRYPTED_PREFIX_DPAPI):
            token = ciphertext[len(ENCRYPTED_PREFIX_DPAPI):]
            return self._dpapi_decrypt(token).decode("utf-8")
        if ciphertext.startswith(ENCRYPTED_PREFIX_AES):
            token = ciphertext[len(ENCRYPTED_PREFIX_AES):]
            return self._aesgcm_decrypt(token).decode("utf-8")
        # v2: implicit — try the host's native wrap first, fall back.
        if ciphertext.startswith(ENCRYPTED_PREFIX):
            token = ciphertext[len(ENCRYPTED_PREFIX):]
            if os.name == "nt":
                try:
                    return self._dpapi_decrypt(token).decode("utf-8")
                except Exception:
                    _logger.debug("v2 DPAPI decrypt failed; falling back to AES-GCM", exc_info=True)
            return self._aesgcm_decrypt(token).decode("utf-8")
        if ciphertext.startswith(LEGACY_ENCRYPTED_PREFIX):
            token = ciphertext[len(LEGACY_ENCRYPTED_PREFIX):]
            if os.name == "nt":
                try:
                    return self._dpapi_decrypt(token).decode("utf-8")
                except Exception:
                    _logger.debug("v1 DPAPI decrypt failed; falling back to legacy AES", exc_info=True)
            return self._legacy_fallback_decrypt(token).decode("utf-8")
        raise ValueError("Unsupported encrypted secret format")

    def _is_encrypted_value(self, value: str) -> bool:
        return is_encrypted_secret(value)

    def _aesgcm_encrypt(self, plaintext: bytes) -> str:
        # OWASP 2024 baseline: PBKDF2-HMAC-SHA256 ≥ 600k iterations.
        # Legacy ciphertexts produced with 120k still decrypt because
        # `_aesgcm_decrypt` tries the new and legacy iteration counts in
        # order — new encrypts always use the hardened iteration count.
        key = self._fallback_master_key()
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, 600_000, dklen=32)
        ciphertext = AESGCM(derived).encrypt(nonce, plaintext, salt)
        payload = b"".join([salt, nonce, ciphertext])
        return base64.b64encode(payload).decode("ascii")

    # Operators rotating a fleet off the pre-2024 120k iteration count
    # need a window where both schedules decrypt, but on a hardened
    # production install (`SHADOWLAB_REQUIRE_HARDENED_KDF=1`) we refuse
    # the legacy schedule outright. The intent is: once you've re-
    # encrypted everything at 600k, you flip the flag and any blob still
    # at 120k either points to forgotten state OR is an attacker-
    # supplied ciphertext probing for an iteration oracle.
    _LEGACY_PBKDF2_ITERATIONS = 120_000
    _CURRENT_PBKDF2_ITERATIONS = 600_000

    def _hardened_kdf_required(self) -> bool:
        raw = os.environ.get("SHADOWLAB_REQUIRE_HARDENED_KDF", "")
        return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}

    def _aesgcm_decrypt(self, token: str) -> bytes:
        key = self._fallback_master_key()
        payload = base64.b64decode(token.encode("ascii"))
        if len(payload) < 44:
            raise ValueError("Encrypted payload is truncated")
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        # Current schedule first (matches every freshly-encrypted blob).
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, self._CURRENT_PBKDF2_ITERATIONS, dklen=32)
        try:
            return AESGCM(derived).decrypt(nonce, ciphertext, salt)
        except Exception as current_error:
            if self._hardened_kdf_required():
                # No legacy fallback — fail closed so an attacker can't
                # probe "which iteration count works" as an oracle.
                raise current_error
        derived_legacy = hashlib.pbkdf2_hmac("sha256", key, salt, self._LEGACY_PBKDF2_ITERATIONS, dklen=32)
        return AESGCM(derived_legacy).decrypt(nonce, ciphertext, salt)

    def _is_sensitive_key(self, key: str) -> bool:
        return str(key or "").strip().lower() in SENSITIVE_KEYS

    def _legacy_fallback_decrypt(self, token: str) -> bytes:
        key = self._fallback_master_key()
        payload = base64.b64decode(token.encode("ascii"))
        if len(payload) < 64:
            raise ValueError("Encrypted payload is truncated")
        salt = payload[:16]
        nonce = payload[16:32]
        tag = payload[-32:]
        ciphertext = payload[32:-32]
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, 120_000, dklen=32)
        expected = hmac.new(derived, salt + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Encrypted payload integrity check failed")
        keystream = _keystream(derived, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))

    def _fallback_master_key(self) -> bytes:
        raw = os.environ.get("SHADOWLAB_SECRET_KEY", "").strip()
        if not raw:
            raise RuntimeError("SHADOWLAB_SECRET_KEY is required for encrypted secret storage on non-Windows hosts")
        # Minimum 32 bytes (≈256 bits) so a short / dictionary master key
        # cannot weaken every derived AES-GCM key downstream.
        if len(raw.encode("utf-8")) < 32:
            raise RuntimeError("SHADOWLAB_SECRET_KEY must be at least 32 bytes of high-entropy material")
        return raw.encode("utf-8")

    def _dpapi_encrypt(self, plaintext: bytes) -> str:
        blob_in = _build_blob(plaintext)
        blob_out = _DataBlob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptProtectData(
            ctypes.byref(blob_in),
            "shadowlab",
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out),
        ):
            raise ctypes.WinError()
        try:
            data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            return base64.b64encode(data).decode("ascii")
        finally:
            kernel32.LocalFree(blob_out.pbData)

    def _dpapi_decrypt(self, token: str) -> bytes:
        encrypted = base64.b64decode(token.encode("ascii"))
        blob_in = _build_blob(encrypted)
        blob_out = _DataBlob()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out),
        ):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)


def _build_blob(data: bytes) -> _DataBlob:
    if not data:
        return _DataBlob(0, None)  # type: ignore[arg-type]
    buffer = ctypes.create_string_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


secret_store = SecretStore()
