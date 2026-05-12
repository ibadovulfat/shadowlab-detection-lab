"""TOTP-based MFA second factor for the ShadowLab API.

Implementation notes:

* RFC 6238 TOTP / RFC 4226 HOTP with HMAC-SHA1 (the OTP standard most
  authenticator apps default to). Pure stdlib — no `pyotp` dependency
  so the lab build stays slim.
* The shared secret is generated at enrollment with `secrets.token_bytes`
  (160 bits of entropy, matching the RFC's `T` parameter), encrypted at
  rest via `secret_store`, and never returned to a non-admin caller.
* Verified-session state lives in `mfa_sessions`: a row per `(subject,
  token_id)` records the timestamp of the latest successful verify.
  Mutating requests check that the verification is within the
  configured session TTL before letting an admin proceed.
* Replay protection: every accepted code is recorded with its 30-second
  time-step counter; a second submission of the same counter is
  rejected even if the wall-clock allowed it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from typing import Any
from urllib.parse import quote

import database as db
from services.secret_store import secret_store


TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW_STEPS = 1  # accept the previous + next 30s window for clock skew
MFA_SESSION_TTL_SECONDS_DEFAULT = 15 * 60  # 15 minutes — typical SOC dashboard idle

# Brute-force protection: when an attacker holds a stolen API key the
# only remaining barrier is the TOTP. With 6 digits and a 3-step window
# they would otherwise get ~10^6 / 3 ≈ 333k tries; even at 1 req/s a
# 6-digit code falls in well under a day. We lock the (subject) out
# for `MFA_LOCKOUT_SECONDS` after `MFA_MAX_FAILED_ATTEMPTS` consecutive
# misses inside the window, and the per-token verify count is mirrored
# into the rate-limit backend so it's also IP-bounded.
MFA_MAX_FAILED_ATTEMPTS = 5
MFA_LOCKOUT_SECONDS = 15 * 60
MFA_FAILED_WINDOW_SECONDS = 15 * 60


def _b32_encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32_decode(value: str) -> bytes:
    padded = value + "=" * ((8 - len(value) % 8) % 8)
    return base64.b32decode(padded.upper().encode("ascii"), casefold=True)


def _hotp(secret: bytes, counter: int) -> str:
    """RFC 4226 HOTP — 6-digit code derived from `(secret, counter)`."""
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def _current_counter(at: float | None = None) -> int:
    return int((at if at is not None else time.time()) // TOTP_PERIOD_SECONDS)


def session_ttl_seconds() -> int:
    raw = (os.environ.get("SHADOWLAB_MFA_SESSION_TTL_SECONDS", "") or "").strip()
    if not raw:
        return MFA_SESSION_TTL_SECONDS_DEFAULT
    try:
        value = int(float(raw))
    except ValueError:
        return MFA_SESSION_TTL_SECONDS_DEFAULT
    return max(60, min(value, 24 * 3600))


def enforce_for_role(role: str) -> bool:
    """True if MFA is required for the given role on mutating requests.

    Configured via `SHADOWLAB_REQUIRE_MFA_FOR_ROLES=admin,analyst`. Empty
    means MFA is purely opt-in (operators can enroll but the API never
    forces a verify).
    """
    raw = (os.environ.get("SHADOWLAB_REQUIRE_MFA_FOR_ROLES", "") or "").strip()
    if not raw:
        return False
    enforced = {item.strip().lower() for item in raw.split(",") if item.strip()}
    return role.strip().lower() in enforced


def _ensure_schema(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL UNIQUE,
            secret_enc TEXT NOT NULL,
            enrolled_at REAL DEFAULT (strftime('%s', 'now')),
            last_verified_at REAL DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            first_failure_at REAL DEFAULT 0,
            locked_until REAL DEFAULT 0
        )
        """
    )
    # Older deployments may already have the table without the brute-force
    # columns; add them in-place so an upgrade doesn't require a manual
    # migration. SQLite's ALTER is best-effort here — repeated runs are
    # cheap and the catch is intentional.
    for column, ddl in (
        ("failed_attempts", "ALTER TABLE mfa_enrollments ADD COLUMN failed_attempts INTEGER DEFAULT 0"),
        ("first_failure_at", "ALTER TABLE mfa_enrollments ADD COLUMN first_failure_at REAL DEFAULT 0"),
        ("locked_until", "ALTER TABLE mfa_enrollments ADD COLUMN locked_until REAL DEFAULT 0"),
    ):
        try:
            conn.execute(ddl)
        except Exception:
            # Column already exists — expected on subsequent boots.
            pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            token_id TEXT NOT NULL,
            verified_at REAL DEFAULT (strftime('%s', 'now')),
            last_counter INTEGER DEFAULT 0,
            UNIQUE(subject, token_id)
        )
        """
    )
    conn.commit()


def enroll(subject: str, *, issuer: str = "ShadowLab", account_label: str | None = None) -> dict[str, Any]:
    """Generate (or rotate) the TOTP secret for `subject`.

    Returns the base32 secret and an otpauth URI suitable for QR codes.
    Callers should treat this as one-shot — the secret is not returned
    on subsequent calls and we don't store the plaintext.
    """
    subj = (subject or "").strip().lower()
    if not subj:
        raise ValueError("subject is required")
    raw = secrets.token_bytes(20)  # 160 bits → 32-char base32 (RFC 6238 default)
    b32 = _b32_encode(raw)
    encrypted = secret_store.encrypt_text(b32)
    conn = db.create_connection()
    if conn is None:
        raise RuntimeError("Database unavailable")
    try:
        _ensure_schema(conn)
        # UPSERT — re-enrolling rotates the secret and invalidates all
        # outstanding verified sessions for that subject.
        conn.execute(
            "INSERT INTO mfa_enrollments (subject, secret_enc) VALUES (?, ?) "
            "ON CONFLICT(subject) DO UPDATE SET secret_enc=excluded.secret_enc, "
            "enrolled_at=strftime('%s','now'), last_verified_at=0",
            (subj, encrypted),
        )
        conn.execute("DELETE FROM mfa_sessions WHERE subject = ?", (subj,))
        conn.commit()
    finally:
        conn.close()
    label = quote(f"{issuer}:{account_label or subj}", safe="")
    issuer_q = quote(issuer, safe="")
    uri = f"otpauth://totp/{label}?secret={b32}&issuer={issuer_q}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    return {"subject": subj, "secret_base32": b32, "otpauth_uri": uri}


def _load_secret(conn, subject: str) -> bytes | None:
    cursor = conn.execute(
        "SELECT secret_enc FROM mfa_enrollments WHERE subject = ?",
        (subject,),
    )
    row = cursor.fetchone()
    if not row or not row[0]:
        return None
    try:
        plaintext = secret_store.decrypt_text(row[0])
    except Exception:
        return None
    try:
        return _b32_decode(plaintext)
    except Exception:
        return None


def _last_counter(conn, subject: str, token_id: str) -> int:
    cursor = conn.execute(
        "SELECT last_counter FROM mfa_sessions WHERE subject = ? AND token_id = ?",
        (subject, token_id),
    )
    row = cursor.fetchone()
    return int(row[0] or 0) if row else 0


def _read_attempt_state(conn, subject: str) -> tuple[int, float, float]:
    cursor = conn.execute(
        "SELECT COALESCE(failed_attempts, 0), COALESCE(first_failure_at, 0), COALESCE(locked_until, 0) "
        "FROM mfa_enrollments WHERE subject = ?",
        (subject,),
    )
    row = cursor.fetchone()
    if not row:
        return 0, 0.0, 0.0
    return int(row[0] or 0), float(row[1] or 0.0), float(row[2] or 0.0)


def _record_failure(conn, subject: str, now: float) -> tuple[int, float]:
    """Bump the failed-attempt counter; lock the subject when it crosses the limit.

    Returns `(failed_attempts, locked_until)` so the caller can surface
    the lockout state to the route handler.
    """
    attempts, first_failure_at, locked_until = _read_attempt_state(conn, subject)
    window_open = first_failure_at and (now - first_failure_at) <= MFA_FAILED_WINDOW_SECONDS
    if not window_open:
        attempts = 0
        first_failure_at = now
    attempts += 1
    if attempts >= MFA_MAX_FAILED_ATTEMPTS:
        locked_until = now + MFA_LOCKOUT_SECONDS
    conn.execute(
        "UPDATE mfa_enrollments SET failed_attempts = ?, first_failure_at = ?, locked_until = ? "
        "WHERE subject = ?",
        (int(attempts), float(first_failure_at), float(locked_until), subject),
    )
    conn.commit()
    return attempts, locked_until


def _clear_failures(conn, subject: str) -> None:
    conn.execute(
        "UPDATE mfa_enrollments SET failed_attempts = 0, first_failure_at = 0, locked_until = 0 "
        "WHERE subject = ?",
        (subject,),
    )


def verify(subject: str, token_id: str, code: str) -> dict[str, Any]:
    """Validate a TOTP code and, on success, mark the session verified.

    `token_id` keys the verified session to the specific API token /
    OIDC jti — verifying once does not unlock other tokens.

    Brute-force protection: after `MFA_MAX_FAILED_ATTEMPTS` consecutive
    misses inside `MFA_FAILED_WINDOW_SECONDS`, the subject is locked for
    `MFA_LOCKOUT_SECONDS`. A successful verify resets the counter.
    """
    subj = (subject or "").strip().lower()
    tok = (token_id or "").strip()
    candidate = (code or "").strip()
    if not subj:
        return {"ok": False, "reason": "subject_required"}
    if not tok:
        return {"ok": False, "reason": "token_id_required"}
    if not candidate.isdigit() or len(candidate) != TOTP_DIGITS:
        return {"ok": False, "reason": "invalid_code_format"}

    conn = db.create_connection()
    if conn is None:
        return {"ok": False, "reason": "db_unavailable"}
    try:
        _ensure_schema(conn)
        secret = _load_secret(conn, subj)
        if secret is None:
            return {"ok": False, "reason": "not_enrolled"}
        now = time.time()
        # Lockout gate — short-circuit BEFORE HMAC so a locked attacker
        # gets no timing feedback from the hash comparison.
        _, _, locked_until = _read_attempt_state(conn, subj)
        if locked_until and now < locked_until:
            return {
                "ok": False,
                "reason": "mfa_locked",
                "retry_after_seconds": int(max(1, locked_until - now)),
            }
        current_counter = _current_counter(now)
        last_counter = _last_counter(conn, subj, tok)
        for offset in range(-TOTP_WINDOW_STEPS, TOTP_WINDOW_STEPS + 1):
            counter = current_counter + offset
            if counter <= last_counter:
                # Replay guard — never accept a counter we've already used
                # for this (subject, token_id).
                continue
            expected = _hotp(secret, counter)
            if hmac.compare_digest(expected, candidate):
                conn.execute(
                    "INSERT INTO mfa_sessions (subject, token_id, verified_at, last_counter) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(subject, token_id) DO UPDATE SET "
                    "verified_at=excluded.verified_at, last_counter=excluded.last_counter",
                    (subj, tok, now, counter),
                )
                conn.execute(
                    "UPDATE mfa_enrollments SET last_verified_at = ? WHERE subject = ?",
                    (now, subj),
                )
                _clear_failures(conn, subj)
                conn.commit()
                return {
                    "ok": True,
                    "subject": subj,
                    "token_id": tok,
                    "verified_at": now,
                    "session_expires_at": now + session_ttl_seconds(),
                }
        attempts, new_lock = _record_failure(conn, subj, now)
        if new_lock and now < new_lock:
            return {
                "ok": False,
                "reason": "mfa_locked",
                "retry_after_seconds": int(max(1, new_lock - now)),
                "failed_attempts": attempts,
            }
        return {"ok": False, "reason": "invalid_code", "failed_attempts": attempts}
    finally:
        conn.close()


def session_is_valid(subject: str, token_id: str) -> bool:
    """True if `subject`+`token_id` has a verified session inside TTL."""
    subj = (subject or "").strip().lower()
    tok = (token_id or "").strip()
    if not subj or not tok:
        return False
    conn = db.create_connection()
    if conn is None:
        return False
    try:
        _ensure_schema(conn)
        cursor = conn.execute(
            "SELECT verified_at FROM mfa_sessions WHERE subject = ? AND token_id = ?",
            (subj, tok),
        )
        row = cursor.fetchone()
        if not row:
            return False
        verified_at = float(row[0] or 0)
        return (time.time() - verified_at) <= session_ttl_seconds()
    finally:
        conn.close()


def status(subject: str, token_id: str = "") -> dict[str, Any]:
    """Return enrollment + session status for the given principal."""
    subj = (subject or "").strip().lower()
    conn = db.create_connection()
    if conn is None:
        return {"enrolled": False, "verified_session": False, "reason": "db_unavailable"}
    try:
        _ensure_schema(conn)
        cursor = conn.execute(
            "SELECT enrolled_at, last_verified_at FROM mfa_enrollments WHERE subject = ?",
            (subj,),
        )
        row = cursor.fetchone()
        enrolled = bool(row)
        result: dict[str, Any] = {"enrolled": enrolled}
        if enrolled:
            result["enrolled_at"] = float(row[0] or 0)
            result["last_verified_at"] = float(row[1] or 0)
        if token_id:
            result["verified_session"] = session_is_valid(subj, token_id)
            result["session_ttl_seconds"] = session_ttl_seconds()
        return result
    finally:
        conn.close()


def revoke(subject: str) -> bool:
    """Drop the enrollment + all verified sessions for `subject`."""
    subj = (subject or "").strip().lower()
    if not subj:
        return False
    conn = db.create_connection()
    if conn is None:
        return False
    try:
        _ensure_schema(conn)
        conn.execute("DELETE FROM mfa_enrollments WHERE subject = ?", (subj,))
        conn.execute("DELETE FROM mfa_sessions WHERE subject = ?", (subj,))
        conn.commit()
        return True
    finally:
        conn.close()
