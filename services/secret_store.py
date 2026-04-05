from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
LEGACY_ENCRYPTED_PREFIX = "enc:v1:"
SECRET_MASK = "***redacted***"


def is_encrypted_secret(value: str | None) -> bool:
    candidate = str(value or "")
    return candidate.startswith(ENCRYPTED_PREFIX) or candidate.startswith(LEGACY_ENCRYPTED_PREFIX)


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
        raw = plaintext.encode("utf-8")
        if os.name == "nt":
            return ENCRYPTED_PREFIX + self._dpapi_encrypt(raw)
        return ENCRYPTED_PREFIX + self._aesgcm_encrypt(raw)

    def decrypt_text(self, ciphertext: str) -> str:
        if ciphertext.startswith(ENCRYPTED_PREFIX):
            token = ciphertext[len(ENCRYPTED_PREFIX):]
            if os.name == "nt":
                try:
                    return self._dpapi_decrypt(token).decode("utf-8")
                except Exception:
                    pass
            return self._aesgcm_decrypt(token).decode("utf-8")
        if ciphertext.startswith(LEGACY_ENCRYPTED_PREFIX):
            token = ciphertext[len(LEGACY_ENCRYPTED_PREFIX):]
            if os.name == "nt":
                try:
                    return self._dpapi_decrypt(token).decode("utf-8")
                except Exception:
                    pass
            return self._legacy_fallback_decrypt(token).decode("utf-8")
        raise ValueError("Unsupported encrypted secret format")

    def _is_encrypted_value(self, value: str) -> bool:
        return is_encrypted_secret(value)

    def _aesgcm_encrypt(self, plaintext: bytes) -> str:
        key = self._fallback_master_key()
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, 120_000, dklen=32)
        ciphertext = AESGCM(derived).encrypt(nonce, plaintext, salt)
        payload = b"".join([salt, nonce, ciphertext])
        return base64.b64encode(payload).decode("ascii")

    def _aesgcm_decrypt(self, token: str) -> bytes:
        key = self._fallback_master_key()
        payload = base64.b64decode(token.encode("ascii"))
        if len(payload) < 44:
            raise ValueError("Encrypted payload is truncated")
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        derived = hashlib.pbkdf2_hmac("sha256", key, salt, 120_000, dklen=32)
        if os.name == "nt":
            return AESGCM(derived).decrypt(nonce, ciphertext, salt)
        return AESGCM(derived).decrypt(nonce, ciphertext, salt)

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
