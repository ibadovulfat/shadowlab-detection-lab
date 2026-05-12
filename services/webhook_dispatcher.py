"""Outbound webhook dispatcher with HMAC signing, retry, and DLQ.

ShadowLab's pre-Wave-3 alert webhook code did the simplest possible
thing: POST the JSON, log the response, move on. Two production-grade
problems followed:

  1. **No tamper detection downstream.** Receivers had no way to verify
     the payload actually came from ShadowLab — anyone with the URL
     could spoof an alert.
  2. **No retry / no DLQ.** A transient 5xx or network blip lost the
     event silently. There was no way for an operator to see "we tried
     but the receiver was down" or to re-deliver after the fact.

This module fixes both:

  * **HMAC-SHA256 signing.** Each delivery is signed with the
    workspace's webhook secret and the signature is sent in the
    `X-ShadowLab-Signature` header (alongside `X-ShadowLab-Timestamp`
    so receivers can guard against replay).
  * **In-process retry queue with exponential backoff.** A background
    worker pulls due deliveries from a small priority queue. Default
    schedule: 5 s, 30 s, 2 min, 10 min, 30 min — capped at 5 attempts.
  * **Persistent DLQ.** When max retries are exhausted, the delivery
    goes to `webhook_dlq` for analyst review. The same row keeps the
    last response code, body excerpt, and full retry history for
    forensics.
  * **Per-workspace secret rotation.** Secrets live in
    `webhook_secrets`; rotating only invalidates new signatures, so
    receivers can window-validate during the rotation cutover.

The dispatcher is intentionally not coupled to the antivirus pipeline —
any subsystem that wants signed outbound webhooks (enterprise case events,
scenario completions, response actions) can call `enqueue` with a
typed payload and get the same delivery semantics.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request

# Serializes DNS-pinning swaps in `_default_http_post`. `socket.getaddrinfo`
# is a process-global, so concurrent webhook deliveries would otherwise
# stomp on each other's pinned hostnames. The dispatcher already
# serializes attempts through a single worker thread, but `deliver_sync`
# (used by "Test webhook") can race with the worker — the lock keeps
# the swap atomic regardless of caller.
_DNS_PIN_LOCK = threading.Lock()
from dataclasses import dataclass, field
from typing import Any


DEFAULT_RETRY_SCHEDULE_SECONDS = (5, 30, 120, 600, 1800)  # 5 retries
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
# Cap individual webhook payloads at 256 KiB by default. Receivers
# (Slack, Discord, Stripe-style consumers) all reject anything close to
# this size, so the limit doubles as a sanity check against an oversize
# payload silently filling the DLQ / on-disk webhook_deliveries table
# with multi-MB rows. Operators with bespoke receivers can raise via
# `SHADOWLAB_WEBHOOK_PAYLOAD_MAX_BYTES`.
DEFAULT_PAYLOAD_MAX_BYTES = 256 * 1024
SIGNATURE_HEADER = "X-ShadowLab-Signature"
TIMESTAMP_HEADER = "X-ShadowLab-Timestamp"
EVENT_HEADER = "X-ShadowLab-Event"
DELIVERY_HEADER = "X-ShadowLab-Delivery-Id"


def _configured_payload_max_bytes() -> int:
    raw = (os.environ.get("SHADOWLAB_WEBHOOK_PAYLOAD_MAX_BYTES", "") or "").strip()
    if not raw:
        return DEFAULT_PAYLOAD_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_PAYLOAD_MAX_BYTES
    # 4 KiB floor (smaller is almost never legitimate and trivially DoS-able);
    # 8 MiB ceiling so an operator typo can't blow up the dispatcher.
    return max(4 * 1024, min(value, 8 * 1024 * 1024))


@dataclass
class WebhookDelivery:
    delivery_id: str
    workspace_id: str
    target_url: str
    event_type: str
    payload: dict[str, Any]
    secret_id: str = ""
    attempts: int = 0
    next_attempt_at: float = field(default_factory=time.time)
    last_status: int = 0
    last_response_excerpt: str = ""
    state: str = "pending"  # pending, delivered, retrying, dlq
    history: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    delivered_at: float = 0.0


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block 30x redirects so SSRF allow-list checks stay enforceable.

    Without this, a public webhook URL the operator approved at enqueue
    time can 301-bounce us to 169.254.169.254 / 10.x / localhost. We
    surface the redirect as an `HTTPError` the caller treats as a
    transport failure.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, f"redirect_blocked: {newurl}", headers, fp)


def compute_signature(secret: str, timestamp: str, raw_body: bytes) -> str:
    """`v1=hex(hmac_sha256(secret, f"{timestamp}.{raw_body}"))`.

    Same shape as Stripe's webhook signing — analysts already know how
    to verify it on the receiving side."""
    if not secret:
        return ""
    msg = timestamp.encode("utf-8") + b"." + (raw_body or b"")
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"v1={digest}"


class WebhookDispatcher:
    def __init__(
        self,
        *,
        db: Any = None,
        retry_schedule_seconds: tuple[int, ...] = DEFAULT_RETRY_SCHEDULE_SECONDS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        metrics_registry: Any = None,
        http_post: Any = None,
    ):
        self._db = db
        self._retry_schedule = tuple(int(x) for x in retry_schedule_seconds)
        self._request_timeout = float(request_timeout_seconds)
        self._metrics = metrics_registry
        self._http_post = http_post or self._default_http_post
        self._queue: list[WebhookDelivery] = []
        self._queue_lock = threading.RLock()
        self._stop_evt = threading.Event()
        self._worker = threading.Thread(target=self._run_worker, name="webhook-dispatcher", daemon=True)
        self._secret_cache: dict[str, str] = {}
        # Hydrate pending/retrying deliveries from disk so a server
        # restart in the middle of a retry window doesn't silently lose
        # the queue. Without this every operator who bounced the API
        # got "missing" alerts for whatever was retrying.
        self._hydrate_pending_from_db()
        self._worker.start()

    def _hydrate_pending_from_db(self) -> None:
        import logging as _logging
        _logger = _logging.getLogger(__name__)
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            _logger.exception("webhook dispatcher: failed to open DB during hydrate")
            return
        if conn is None:
            _logger.warning("webhook dispatcher: DB connection unavailable during hydrate")
            return
        try:
            cursor = conn.execute(
                """
                SELECT delivery_id, workspace_id, target_url, event_type,
                       payload_json, secret_id, attempts, next_attempt_at,
                       last_status, last_response_excerpt, state, history_json,
                       created_at, delivered_at
                FROM webhook_deliveries
                WHERE state IN ('pending', 'retrying')
                """
            )
            rows = cursor.fetchall()
        except Exception:
            _logger.exception("webhook dispatcher: SELECT during hydrate failed")
            return
        finally:
            try:
                conn.close()
            except Exception:
                _logger.debug("webhook dispatcher: ignoring close() failure during hydrate", exc_info=True)
        rehydrated = 0
        for row in rows:
            try:
                payload = json.loads(row[4] or "{}")
            except Exception:
                payload = {}
            try:
                history = json.loads(row[11] or "[]")
            except Exception:
                history = []
            delivery = WebhookDelivery(
                delivery_id=str(row[0]), workspace_id=str(row[1] or "default"),
                target_url=str(row[2] or ""), event_type=str(row[3] or "generic"),
                payload=payload, secret_id=str(row[5] or ""),
                attempts=int(row[6] or 0), next_attempt_at=float(row[7] or 0),
                last_status=int(row[8] or 0), last_response_excerpt=str(row[9] or ""),
                state=str(row[10] or "retrying"),
                history=history if isinstance(history, list) else [],
                created_at=float(row[12] or time.time()),
                delivered_at=float(row[13] or 0),
            )
            with self._queue_lock:
                self._queue.append(delivery)
            rehydrated += 1
        if rehydrated and self._metrics is not None:
            try:
                self._metrics.counter(
                    "shadowlab_webhook_rehydrated_total",
                    help="Webhook deliveries re-queued from disk on server restart.",
                ).inc(rehydrated)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_payload_size(payload: dict[str, Any]) -> dict[str, Any] | None:
        """Return an error dict if `payload` exceeds the configured size cap.

        Returns `None` when the payload is OK to enqueue. Performing the
        check at enqueue time (vs at attempt time) avoids persisting an
        oversize row to the DB and keeps the DLQ free of garbage.
        """
        try:
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return {"ok": False, "reason": "payload_not_json_serializable", "detail": str(exc)}
        limit = _configured_payload_max_bytes()
        if len(encoded) > limit:
            return {
                "ok": False,
                "reason": "payload_too_large",
                "size_bytes": len(encoded),
                "limit_bytes": limit,
            }
        return None

    def enqueue(
        self,
        *,
        workspace_id: str,
        target_url: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if not target_url:
            return {"ok": False, "reason": "missing_target_url"}
        normalized_payload = dict(payload or {})
        size_error = self._validate_payload_size(normalized_payload)
        if size_error is not None:
            return size_error
        delivery = WebhookDelivery(
            delivery_id=secrets.token_hex(12),
            workspace_id=str(workspace_id or "default"),
            target_url=str(target_url).strip(),
            event_type=str(event_type or "generic"),
            payload=normalized_payload,
            secret_id=self._active_secret_id(workspace_id),
        )
        self._persist(delivery)
        with self._queue_lock:
            self._queue.append(delivery)
        return {"ok": True, "delivery_id": delivery.delivery_id, "queued_at": delivery.created_at}

    def deliver_sync(
        self,
        *,
        workspace_id: str,
        target_url: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Bypass queue — POST immediately. Used for `Test webhook`."""
        normalized_payload = dict(payload or {})
        size_error = self._validate_payload_size(normalized_payload)
        if size_error is not None:
            return size_error
        delivery = WebhookDelivery(
            delivery_id=secrets.token_hex(12),
            workspace_id=str(workspace_id or "default"),
            target_url=str(target_url).strip(),
            event_type=str(event_type or "test"),
            payload=normalized_payload,
            secret_id=self._active_secret_id(workspace_id),
        )
        self._attempt(delivery)
        return {
            "ok": delivery.state == "delivered",
            "delivery_id": delivery.delivery_id,
            "state": delivery.state,
            "status_code": delivery.last_status,
            "response_excerpt": delivery.last_response_excerpt,
        }

    def list_deliveries(self, *, workspace_id: str | None = None, limit: int = 50, state: str | None = None) -> list[dict[str, Any]]:
        with self._queue_lock:
            in_memory = list(self._queue)
        rows = [self._delivery_snapshot(d) for d in in_memory]
        if workspace_id:
            rows = [r for r in rows if r["workspace_id"] == workspace_id]
        if state:
            rows = [r for r in rows if r["state"] == state]
        rows.sort(key=lambda r: r.get("created_at", 0), reverse=True)
        return rows[: max(1, min(int(limit), 500))]

    def list_dlq(self, *, workspace_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if self._db is None:
            return []
        try:
            conn = self._db.create_connection()
        except Exception:
            return []
        if conn is None:
            return []
        try:
            params: list[Any] = []
            sql = "SELECT delivery_id, workspace_id, target_url, event_type, last_status, last_response_excerpt, attempts, created_at, delivered_at, payload_json FROM webhook_dlq"
            if workspace_id:
                sql += " WHERE workspace_id = ?"
                params.append(workspace_id)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(int(limit))
            cursor = conn.execute(sql, params)
            out: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                try:
                    payload = json.loads(row[9] or "{}")
                except Exception:
                    payload = {}
                out.append({
                    "delivery_id": row[0], "workspace_id": row[1], "target_url": row[2],
                    "event_type": row[3], "last_status": int(row[4] or 0),
                    "last_response_excerpt": row[5], "attempts": int(row[6] or 0),
                    "created_at": float(row[7] or 0), "delivered_at": float(row[8] or 0),
                    "payload": payload,
                })
            return out
        except Exception:
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def purge_dlq(
        self,
        *,
        delivery_id: str | None = None,
        older_than_seconds: int | None = None,
        workspace_id: str | None = None,
        confirm_purge_all: bool = False,
    ) -> dict[str, Any]:
        """Permanently delete failed deliveries from the dead-letter queue.

        At least ONE of `delivery_id`, `older_than_seconds`, or
        `workspace_id` MUST be supplied, OR the caller must pass
        `confirm_purge_all=True`. A bare DELETE used to wipe every row in
        every workspace — a stolen admin token + the previously-bypassed
        `PUT`/CSRF path could destroy the entire forensic trail in one
        request. Requiring an explicit confirm flag turns that into a
        deliberate, auditable action.
        """
        if self._db is None:
            return {"ok": False, "reason": "no_db"}
        # Refuse unbounded deletes unless the caller explicitly opted in.
        if not (delivery_id or (older_than_seconds is not None and older_than_seconds > 0) or workspace_id or confirm_purge_all):
            return {
                "ok": False,
                "reason": "filter_required",
                "detail": "Provide delivery_id, older_than_seconds, workspace_id, or confirm_purge_all=true",
            }
        try:
            conn = self._db.create_connection()
        except Exception:
            return {"ok": False, "reason": "db_connect_failed"}
        if conn is None:
            return {"ok": False, "reason": "db_unavailable"}
        try:
            params: list[Any] = []
            sql = "DELETE FROM webhook_dlq WHERE 1=1"
            if delivery_id:
                sql += " AND delivery_id = ?"; params.append(delivery_id)
            if older_than_seconds is not None and older_than_seconds > 0:
                cutoff = time.time() - float(older_than_seconds)
                sql += " AND created_at < ?"; params.append(cutoff)
            if workspace_id:
                sql += " AND workspace_id = ?"; params.append(workspace_id)
            cursor = conn.execute(sql, params)
            removed = int(getattr(cursor, "rowcount", 0) or 0)
            conn.commit()
            return {"ok": True, "removed": removed}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}
        finally:
            try: conn.close()
            except Exception: pass

    def replay_from_dlq(self, delivery_id: str) -> dict[str, Any]:
        """Re-enqueue a failed delivery from the dead-letter queue."""
        if self._db is None:
            return {"ok": False, "reason": "no_db"}
        try:
            conn = self._db.create_connection()
        except Exception:
            return {"ok": False, "reason": "db_connect_failed"}
        if conn is None:
            return {"ok": False, "reason": "db_unavailable"}
        try:
            row = conn.execute(
                "SELECT workspace_id, target_url, event_type, payload_json FROM webhook_dlq WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if not row:
                return {"ok": False, "reason": "unknown_delivery"}
            try:
                payload = json.loads(row[3] or "{}")
            except Exception:
                payload = {}
            new_delivery = self.enqueue(
                workspace_id=row[0], target_url=row[1], event_type=row[2], payload=payload
            )
            return {"ok": True, "replayed_as": new_delivery.get("delivery_id", "")}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def rotate_secret(self, workspace_id: str) -> dict[str, Any]:
        new_secret = secrets.token_urlsafe(32)
        secret_id = secrets.token_hex(8)
        self._store_secret(workspace_id, secret_id, new_secret)
        return {"ok": True, "secret_id": secret_id, "secret": new_secret}

    def get_active_secret(self, workspace_id: str) -> tuple[str, str] | None:
        if self._db is None:
            return None
        try:
            conn = self._db.create_connection()
        except Exception:
            return None
        if conn is None:
            return None
        try:
            row = conn.execute(
                "SELECT secret_id, secret FROM webhook_secrets WHERE workspace_id = ? AND active = 1 ORDER BY created_at DESC LIMIT 1",
                (workspace_id,),
            ).fetchone()
            if row:
                return (str(row[0]), str(row[1]))
        except Exception:
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return None

    def shutdown(self) -> None:
        self._stop_evt.set()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_worker(self) -> None:
        while not self._stop_evt.is_set():
            now = time.time()
            due: list[WebhookDelivery] = []
            with self._queue_lock:
                remaining: list[WebhookDelivery] = []
                for delivery in self._queue:
                    if delivery.next_attempt_at <= now and delivery.state in {"pending", "retrying"}:
                        due.append(delivery)
                    else:
                        remaining.append(delivery)
                self._queue = remaining
            for delivery in due:
                self._attempt(delivery)
                if delivery.state in {"pending", "retrying"}:
                    with self._queue_lock:
                        self._queue.append(delivery)
            self._stop_evt.wait(timeout=1.0)

    def _attempt(self, delivery: WebhookDelivery) -> None:
        delivery.attempts += 1
        body_bytes = json.dumps(delivery.payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        secret = self._lookup_secret(delivery.workspace_id, delivery.secret_id)
        signature = compute_signature(secret, timestamp, body_bytes) if secret else ""
        headers = {
            "Content-Type": "application/json",
            EVENT_HEADER: delivery.event_type,
            DELIVERY_HEADER: delivery.delivery_id,
            TIMESTAMP_HEADER: timestamp,
        }
        if signature:
            headers[SIGNATURE_HEADER] = signature

        started = time.time()
        try:
            status, body_excerpt = self._http_post(delivery.target_url, body_bytes, headers, self._request_timeout)
        except Exception as exc:
            status, body_excerpt = 0, f"transport_error: {str(exc)[:240]}"
        duration = time.time() - started

        delivery.last_status = int(status)
        delivery.last_response_excerpt = body_excerpt[:512]
        delivery.history.append({
            "attempt": delivery.attempts,
            "at": started,
            "status": int(status),
            "duration_ms": int(duration * 1000),
            "excerpt": body_excerpt[:240],
        })

        outcome = ""
        if 200 <= status < 300:
            delivery.state = "delivered"
            delivery.delivered_at = time.time()
            outcome = "delivered"
        elif delivery.attempts >= len(self._retry_schedule):
            delivery.state = "dlq"
            outcome = "dlq"
            self._move_to_dlq(delivery)
        else:
            delivery.state = "retrying"
            delivery.next_attempt_at = time.time() + self._retry_schedule[delivery.attempts - 1]
            outcome = "retried"

        self._persist(delivery)
        if self._metrics is not None:
            try:
                self._metrics.record_webhook_outcome(outcome=outcome, duration_seconds=duration)
            except Exception:
                pass

    def _default_http_post(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        # Re-validate at dispatch time AND pin the resolved IP. Enqueue-time
        # `normalize_outbound_url` can be sidestepped by a DNS-rebinding
        # entry that resolved to a public IP earlier and now points at
        # 169.254.169.254 / 10.x / localhost. `resolve_safe_outbound_address`
        # returns one safe URL + one already-vetted IP; we dial that exact
        # IP so the HTTP stack cannot re-resolve to something different.
        # Redirects are blocked outright so a public-looking host cannot
        # 301-bounce us to a metadata endpoint after the validation gate.
        from services.outbound_security import resolve_safe_outbound_address

        resolved = resolve_safe_outbound_address(url)
        if not resolved:
            return 0, "transport_error: unsafe_destination_blocked"
        safe_url, pinned_ip = resolved

        # Pin DNS for the duration of this request: replace
        # `socket.getaddrinfo` with a wrapper that ONLY returns our
        # vetted IP for the original hostname. urllib/requests/httpx all
        # call `getaddrinfo` so this is the single chokepoint. SNI / Host
        # header stay the original hostname (required for TLS validation
        # and the receiver's virtual hosting). Other hostnames resolve
        # normally — important because the operator's DNS may still
        # need to resolve proxy/CDN hostnames if those are involved.
        from urllib.parse import urlparse

        original_host = (urlparse(safe_url).hostname or "").lower()
        real_getaddrinfo = socket.getaddrinfo

        def _pinned_getaddrinfo(host, port, *args, **kwargs):
            if (host or "").lower() == original_host:
                try:
                    family = socket.AF_INET6 if ":" in pinned_ip else socket.AF_INET
                    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (pinned_ip, port))]
                except Exception:
                    pass
            return real_getaddrinfo(host, port, *args, **kwargs)

        # Bound the response read to (excerpt + drain budget). A
        # legitimate webhook receiver answers with a few KB at most;
        # capping the body at `_RESPONSE_DRAIN_MAX` bytes stops a hostile
        # receiver from holding the dispatcher hostage by streaming
        # gigabytes back. `_excerpt_bytes` is what we surface to the
        # operator, everything beyond is read into /dev/null just to let
        # the kernel close the socket cleanly.
        _EXCERPT_BYTES = 512
        _RESPONSE_DRAIN_MAX = 64 * 1024

        def _bounded_read(fp) -> str:
            try:
                excerpt_bytes = fp.read(_EXCERPT_BYTES)
            except Exception:
                return ""
            # Drain a bounded remainder so the underlying connection
            # gets closed promptly even when the receiver chunk-streams.
            remaining = _RESPONSE_DRAIN_MAX
            while remaining > 0:
                try:
                    chunk = fp.read(min(8192, remaining))
                except Exception:
                    break
                if not chunk:
                    break
                remaining -= len(chunk)
            return excerpt_bytes.decode("utf-8", errors="replace")

        req = urllib.request.Request(safe_url, data=body, headers=headers, method="POST")
        with _DNS_PIN_LOCK:
            socket.getaddrinfo = _pinned_getaddrinfo  # type: ignore[assignment]
            try:
                opener = urllib.request.build_opener(_NoRedirectHandler())
                with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — webhook is operator-supplied URL
                    return int(resp.status), _bounded_read(resp)
            except urllib.error.HTTPError as exc:
                return int(exc.code), _bounded_read(exc)
            finally:
                socket.getaddrinfo = real_getaddrinfo  # type: ignore[assignment]

    def _persist(self, delivery: WebhookDelivery) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    delivery_id, workspace_id, target_url, event_type, payload_json,
                    secret_id, attempts, next_attempt_at, last_status, last_response_excerpt,
                    state, history_json, created_at, delivered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(delivery_id) DO UPDATE SET
                    attempts = excluded.attempts,
                    next_attempt_at = excluded.next_attempt_at,
                    last_status = excluded.last_status,
                    last_response_excerpt = excluded.last_response_excerpt,
                    state = excluded.state,
                    history_json = excluded.history_json,
                    delivered_at = excluded.delivered_at
                """,
                (
                    delivery.delivery_id, delivery.workspace_id, delivery.target_url,
                    delivery.event_type, json.dumps(delivery.payload, ensure_ascii=False),
                    delivery.secret_id, int(delivery.attempts), float(delivery.next_attempt_at),
                    int(delivery.last_status), str(delivery.last_response_excerpt or ""),
                    delivery.state, json.dumps(delivery.history, ensure_ascii=False),
                    float(delivery.created_at), float(delivery.delivered_at),
                ),
            )
            conn.commit()
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _move_to_dlq(self, delivery: WebhookDelivery) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            conn.execute(
                """
                INSERT INTO webhook_dlq (
                    delivery_id, workspace_id, target_url, event_type, payload_json,
                    last_status, last_response_excerpt, attempts, created_at, delivered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(delivery_id) DO UPDATE SET
                    last_status = excluded.last_status,
                    last_response_excerpt = excluded.last_response_excerpt,
                    attempts = excluded.attempts,
                    delivered_at = excluded.delivered_at
                """,
                (
                    delivery.delivery_id, delivery.workspace_id, delivery.target_url,
                    delivery.event_type, json.dumps(delivery.payload, ensure_ascii=False),
                    int(delivery.last_status), str(delivery.last_response_excerpt or ""),
                    int(delivery.attempts), float(delivery.created_at), float(delivery.delivered_at),
                ),
            )
            conn.commit()
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _store_secret(self, workspace_id: str, secret_id: str, secret: str) -> None:
        cache_key = f"{workspace_id}:{secret_id}"
        self._secret_cache[cache_key] = secret
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        if conn is None:
            return
        try:
            conn.execute("UPDATE webhook_secrets SET active = 0 WHERE workspace_id = ?", (workspace_id,))
            conn.execute(
                """
                INSERT INTO webhook_secrets (secret_id, workspace_id, secret, active, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (secret_id, workspace_id, secret, time.time()),
            )
            conn.commit()
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _lookup_secret(self, workspace_id: str, secret_id: str) -> str:
        if not workspace_id or not secret_id:
            return ""
        cache_key = f"{workspace_id}:{secret_id}"
        cached = self._secret_cache.get(cache_key)
        if cached:
            return cached
        if self._db is None:
            return ""
        try:
            conn = self._db.create_connection()
        except Exception:
            return ""
        if conn is None:
            return ""
        try:
            row = conn.execute(
                "SELECT secret FROM webhook_secrets WHERE workspace_id = ? AND secret_id = ?",
                (workspace_id, secret_id),
            ).fetchone()
            if row:
                self._secret_cache[cache_key] = str(row[0] or "")
                return self._secret_cache[cache_key]
        except Exception:
            return ""
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return ""

    def _active_secret_id(self, workspace_id: str) -> str:
        active = self.get_active_secret(workspace_id)
        if active:
            return active[0]
        # Auto-provision on first use so a brand-new workspace doesn't
        # need an explicit rotate before its first webhook fires.
        rotation = self.rotate_secret(workspace_id)
        return str(rotation.get("secret_id", "") or "")

    def _delivery_snapshot(self, delivery: WebhookDelivery) -> dict[str, Any]:
        return {
            "delivery_id": delivery.delivery_id,
            "workspace_id": delivery.workspace_id,
            "target_url": delivery.target_url,
            "event_type": delivery.event_type,
            "state": delivery.state,
            "attempts": delivery.attempts,
            "next_attempt_at": delivery.next_attempt_at,
            "last_status": delivery.last_status,
            "last_response_excerpt": delivery.last_response_excerpt,
            "created_at": delivery.created_at,
            "delivered_at": delivery.delivered_at,
            "history": list(delivery.history),
        }
