"""Thread-safe container for long-lived singleton plugin instances.

FastAPI runs sync handlers on a threadpool and some plugin callbacks fire
from their own worker threads, so bare module-level mutables race on
deploy/cleanup. This module wraps every cross-thread global behind a lock
and exposes get/set/append/reset helpers.

Covered state:
- network-warfare plugin handle
- alert webhook URL (hot-swappable from /alerts/configure)
"""
from __future__ import annotations

import os
import threading
from typing import Any

from services.outbound_security import normalize_outbound_url
from services.secret_store import is_encrypted_secret, secret_store

import database as db


# Locks for every module-level mutable. Kept as separate locks (rather than
# one global one) so that an alert-webhook configure doesn't serialize every
# network control read.
_warfare_state_lock = threading.Lock()
_alert_webhook_lock = threading.Lock()


# --- network-warfare plugin state -------------------------------------------
_network_warfare_instance: Any = None


def get_network_warfare_instance() -> Any:
    with _warfare_state_lock:
        return _network_warfare_instance


def set_network_warfare_instance(value: Any) -> None:
    global _network_warfare_instance
    with _warfare_state_lock:
        _network_warfare_instance = value


# --- alert webhook URL ------------------------------------------------------
_alert_webhook_url: str = ""


def get_alert_webhook_url() -> str:
    with _alert_webhook_lock:
        return _alert_webhook_url


def set_alert_webhook_url(value: str) -> None:
    global _alert_webhook_url
    normalized = normalize_outbound_url(value)
    with _alert_webhook_lock:
        _alert_webhook_url = normalized or ""


def bootstrap_alert_webhook_url() -> None:
    """Resolve the webhook URL from env var or the encrypted DB setting.

    Called once at startup. The env var wins when present; otherwise we fall
    back to the `alert_webhook_url_enc` app-setting so operators can rotate
    without restarting.
    """
    global _alert_webhook_url
    raw = os.environ.get("SHADOWLAB_ALERT_WEBHOOK", "")
    try:
        resolved = secret_store.decrypt_text(raw) if is_encrypted_secret(raw) else raw
    except Exception:
        resolved = ""
    if not resolved:
        conn = db.create_connection()
        if conn is not None:
            try:
                stored = db.get_app_setting(conn, "alert_webhook_url_enc")
                if stored:
                    resolved = secret_store.decrypt_text(stored)
            except Exception:
                resolved = ""
            finally:
                conn.close()
    resolved = normalize_outbound_url(resolved)
    with _alert_webhook_lock:
        _alert_webhook_url = resolved or ""
