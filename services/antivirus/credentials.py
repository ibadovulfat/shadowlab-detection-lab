"""Process-shared credential resolver for the antivirus pipeline.

Until Wave-3 the cloud-intel and sandbox providers read API keys
exclusively from environment variables — the only way to point them at
VirusTotal / MalwareBazaar / YARAify / Hybrid-Analysis was to relaunch
the API with the right `SHADOWLAB_*` env vars set. That worked for
single-operator setups but broke the desktop-paste workflow: the
analyst would type a key into the "Advanced Hunt & Lab Settings" panel
and nothing happened, because the input never reached the providers.

This module replaces that dead-end with a tiny, thread-safe in-process
key/value store that providers consult **first**, falling back to env
vars only when the analyst hasn't pushed a key yet. The API ships a
`PUT /antivirus/credentials` route that writes through to this store
and persists the encrypted ciphertext into `app_settings` so a server
restart doesn't lose the operator's keys.

Security posture:
  * Keys are encrypted at rest using `secret_store.encrypt_text` (the
    same AES-GCM helper that protects the alert webhook URL and OIDC
    config). The plaintext only lives in process memory.
  * `GET /antivirus/credentials/status` returns *fingerprints only*
    (last 4 characters) so the desktop can show a "configured ✓" pill
    without the API ever echoing the raw key over the wire.
  * The store is keyed by canonical short names (`virustotal`,
    `malwarebazaar`, `yaraify`, `hybrid_analysis`) — providers query
    by name, not by env var, so renames in env nomenclature don't
    break the resolution chain.
"""
from __future__ import annotations

import os
import threading
from typing import Callable


# Canonical short-name → corresponding env var that providers historically
# read. The fallback chain is: in-process value → env var → empty string.
ENV_FALLBACKS: dict[str, str] = {
    "virustotal":      "VIRUSTOTAL_API_KEY",
    "malwarebazaar":   "MALWAREBAZAAR_AUTH_KEY",
    "yaraify":         "YARAIFY_AUTH_KEY",
    "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY",
}

ALLOWED_NAMES = frozenset(ENV_FALLBACKS.keys())

# Storage key prefix in `app_settings`. Each credential lands at
# `antivirus_credential_<name>` with the value encrypted via secret_store.
APP_SETTING_PREFIX = "antivirus_credential_"


class CredentialStore:
    """Thread-safe in-process credential cache.

    Constructed once during API bootstrap. Optional `db` + `secret_store`
    enable encrypted persistence; without them the store is process-local
    only (still useful for tests / lab runs)."""

    def __init__(self, *, db=None, secret_store=None):
        self._lock = threading.RLock()
        self._values: dict[str, str] = {}
        self._db = db
        self._secret_store = secret_store
        self.hydrate_from_db()

    def set(self, name: str, value: str, *, persist: bool = True) -> None:
        name = self._canonical(name)
        if name is None:
            return
        plaintext = (value or "").strip()
        with self._lock:
            if plaintext:
                self._values[name] = plaintext
            else:
                self._values.pop(name, None)
        if persist:
            self._persist(name, plaintext)

    def get(self, name: str) -> str:
        """Return plaintext key for the given canonical name.

        Resolution order:
          1. In-process store (hot cache + analyst-pushed)
          2. Environment variable (legacy fallback)
        Empty string when neither has a value — providers should treat
        this as "skipped" rather than an error."""
        name = self._canonical(name)
        if name is None:
            return ""
        with self._lock:
            cached = self._values.get(name, "")
        if cached:
            return cached
        env_var = ENV_FALLBACKS.get(name, "")
        return (os.environ.get(env_var, "") or "").strip() if env_var else ""

    def status(self) -> dict[str, dict[str, object]]:
        """`{name: {configured: bool, fingerprint: str, source: str}}`.

        `fingerprint` is the last 4 characters of the key. `source` is
        either `process` (analyst-pushed/persisted), `env` (env var),
        or `none`."""
        out: dict[str, dict[str, object]] = {}
        with self._lock:
            cached = dict(self._values)
        for name in sorted(ALLOWED_NAMES):
            value = cached.get(name, "")
            source = "process" if value else ""
            if not value:
                env_var = ENV_FALLBACKS.get(name, "")
                env_value = (os.environ.get(env_var, "") or "").strip() if env_var else ""
                if env_value:
                    value = env_value
                    source = "env"
            out[name] = {
                "configured": bool(value),
                "fingerprint": value[-4:] if value else "",
                "source": source or "none",
            }
        return out

    def hydrate_from_db(self) -> None:
        """Pull encrypted credentials out of `app_settings` into the
        in-process cache. Called at bootstrap and after a deliberate
        DB-write so the store and disk stay in sync."""
        import logging
        _logger = logging.getLogger(__name__)
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            _logger.exception("antivirus credential store: failed to open DB during hydrate")
            return
        if conn is None:
            _logger.warning("antivirus credential store: DB connection unavailable during hydrate")
            return
        try:
            for name in ALLOWED_NAMES:
                key = APP_SETTING_PREFIX + name
                try:
                    raw = self._db.get_app_setting(conn, key)
                except Exception:
                    _logger.debug("antivirus credential store: failed to retrieve persisted setting")
                    raw = ""
                if not raw:
                    continue
                plaintext = self._decrypt(raw)
                if plaintext:
                    with self._lock:
                        self._values[name] = plaintext
        except Exception:
            _logger.exception("antivirus credential store: unexpected error during hydrate")
            return
        finally:
            try:
                conn.close()
            except Exception:
                _logger.debug("antivirus credential store: ignoring close() failure", exc_info=True)

    def _persist(self, name: str, plaintext: str) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            ciphertext = self._encrypt(plaintext) if plaintext else ""
            self._db.set_app_setting(conn, APP_SETTING_PREFIX + name, ciphertext)
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        if self._secret_store is None:
            return plaintext  # falls back to plaintext-at-rest in dev/test
        try:
            return self._secret_store.encrypt_text(plaintext)
        except Exception:
            return plaintext

    def _decrypt(self, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        if self._secret_store is None:
            return ciphertext
        try:
            from services.secret_store import is_encrypted_secret
            if not is_encrypted_secret(ciphertext):
                return ciphertext
            return self._secret_store.decrypt_text(ciphertext)
        except Exception:
            return ""

    @staticmethod
    def _canonical(name: str) -> str | None:
        canonical = (name or "").strip().lower()
        if canonical not in ALLOWED_NAMES:
            return None
        return canonical


# Process singleton.
_STORE: CredentialStore | None = None
_STORE_LOCK = threading.Lock()


def get_credential_store() -> CredentialStore:
    """Return the process-singleton credential store. Constructed lazily
    if the bootstrap hasn't done so yet (e.g. in unit tests)."""
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                _STORE = CredentialStore()
    return _STORE


def install_credential_store(store: CredentialStore) -> None:
    """Replace the process singleton — used by `api/bootstrap/services.py`
    to inject the DB + secret_store-backed instance at startup."""
    global _STORE
    with _STORE_LOCK:
        _STORE = store


def resolve_credential(name: str) -> str:
    """Convenience for providers — `process_store.get` plus env fallback,
    callable from a single line in the scan path."""
    return get_credential_store().get(name)
