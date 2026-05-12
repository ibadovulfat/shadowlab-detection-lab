"""Pluggable rate-limit storage backends.

`api.security` calls the active backend's `prune_and_count` /
`record_hit` to enforce the per-bucket-per-subject sliding window. The
backend is chosen at import time from `SHADOWLAB_RATE_LIMIT_BACKEND`:

* `memory` (default for lab) — single-process dict; lost on restart.
* `database` (default for corp/prod when Redis isn't configured) —
  uses `database.record_rate_limit_hit` / `prune_rate_limit_hits` /
  `count_rate_limit_hits`. Shared across multiple workers on the
  same DB.
* `redis` — sliding window via `ZADD` + `ZCOUNT`. Required for
  multi-host / multi-worker production deployments because the
  database backend, while shared, costs a round-trip per request.
  Connection string in `SHADOWLAB_REDIS_URL` (e.g.
  `redis://127.0.0.1:6379/0`). Falls back to `database` if the
  `redis` package isn't installed or the URL is unreachable.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Protocol

import database as db


_BUCKET_LOCK = threading.RLock()
_MEMORY_BUCKETS: dict[str, list[float]] = {}


class RateLimitBackend(Protocol):
    """Minimal surface every backend exposes."""

    name: str

    def prune_and_count(self, bucket: str, subject: str, window_seconds: int) -> int:
        ...

    def record_hit(self, bucket: str, subject: str) -> None:
        ...

    def is_durable(self) -> bool:
        """True if a process restart preserves window state."""
        ...


class _MemoryBackend:
    name = "memory"

    def prune_and_count(self, bucket: str, subject: str, window_seconds: int) -> int:
        now = time.time()
        cutoff = now - window_seconds
        key = f"{bucket}:{subject}"
        with _BUCKET_LOCK:
            values = [ts for ts in _MEMORY_BUCKETS.get(key, []) if ts >= cutoff]
            _MEMORY_BUCKETS[key] = values
            return len(values)

    def record_hit(self, bucket: str, subject: str) -> None:
        now = time.time()
        key = f"{bucket}:{subject}"
        with _BUCKET_LOCK:
            _MEMORY_BUCKETS.setdefault(key, []).append(now)

    def is_durable(self) -> bool:
        return False


class _DatabaseBackend:
    name = "database"

    def prune_and_count(self, bucket: str, subject: str, window_seconds: int) -> int:
        now = time.time()
        cutoff = now - window_seconds
        conn = db.create_connection()
        if conn is None:
            return 0
        try:
            db.prune_rate_limit_hits(conn, bucket, subject, cutoff)
            return int(db.count_rate_limit_hits(conn, bucket, subject, cutoff))
        finally:
            conn.close()

    def record_hit(self, bucket: str, subject: str) -> None:
        conn = db.create_connection()
        if conn is None:
            return
        try:
            db.record_rate_limit_hit(conn, bucket, subject, time.time())
        finally:
            conn.close()

    def is_durable(self) -> bool:
        return True


class _RedisBackend:
    """Sliding window via sorted set.

    Each `(bucket, subject)` pair maps to a `rl:{bucket}:{subject}` zset
    whose members are nonce strings scored by their UNIX epoch ms. A
    `ZREMRANGEBYSCORE` ranges the cutoff, and `ZCARD` returns the
    current count. Cheap and correct.
    """

    name = "redis"

    def __init__(self, url: str) -> None:
        import redis  # local import — soft dependency

        self._client = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2.0)
        # Smoke ping so a misconfigured URL fails fast at import time
        # rather than silently dropping every rate-limit check.
        self._client.ping()

    def _key(self, bucket: str, subject: str) -> str:
        return f"shadowlab:rl:{bucket}:{subject}"

    def prune_and_count(self, bucket: str, subject: str, window_seconds: int) -> int:
        now_ms = int(time.time() * 1000)
        cutoff = now_ms - int(window_seconds * 1000)
        key = self._key(bucket, subject)
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zcard(key)
        _, count = pipe.execute()
        return int(count or 0)

    def record_hit(self, bucket: str, subject: str) -> None:
        now_ms = int(time.time() * 1000)
        key = self._key(bucket, subject)
        # Member must be unique per insert; combine ms timestamp with a
        # 6-hex-char suffix so two hits in the same millisecond from the
        # same process don't collapse.
        import secrets as _secrets
        member = f"{now_ms}:{_secrets.token_hex(3)}"
        pipe = self._client.pipeline()
        pipe.zadd(key, {member: now_ms})
        # Bound the key — keep at most a generous 600 entries per
        # (bucket, subject) so a long-lived attacker can't make the
        # zset grow unbounded. The window check already rejects long
        # before that, this is belt-and-braces.
        pipe.zremrangebyrank(key, 0, -601)
        # 1-hour idle TTL — any bucket+subject quiet for an hour drops
        # off Redis automatically.
        pipe.expire(key, 3600)
        pipe.execute()

    def is_durable(self) -> bool:
        return True


def _build_backend() -> RateLimitBackend:
    requested = (os.environ.get("SHADOWLAB_RATE_LIMIT_BACKEND", "") or "").strip().lower()
    redis_url = (os.environ.get("SHADOWLAB_REDIS_URL", "") or "").strip()
    policy = (os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab") or "lab").strip().lower()

    if requested in {"", "auto"}:
        # Auto-select: Redis if URL set, else database in corp/prod, else memory.
        if redis_url:
            requested = "redis"
        elif policy in {"corp", "prod"}:
            requested = "database"
        else:
            requested = "memory"

    if requested == "redis":
        if not redis_url:
            raise RuntimeError("SHADOWLAB_REDIS_URL is required when rate-limit backend is `redis`")
        try:
            return _RedisBackend(redis_url)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Redis rate-limit backend unavailable (%s); falling back to database",
                exc,
            )
            return _DatabaseBackend()
    if requested == "database":
        return _DatabaseBackend()
    if requested == "memory":
        return _MemoryBackend()
    raise ValueError(f"Unsupported SHADOWLAB_RATE_LIMIT_BACKEND: {requested}")


_BACKEND: RateLimitBackend | None = None
_BACKEND_FINGERPRINT: tuple[str, str, str] = ("", "", "")
_BACKEND_LOCK = threading.Lock()


def _env_fingerprint() -> tuple[str, str, str]:
    return (
        (os.environ.get("SHADOWLAB_RATE_LIMIT_BACKEND", "") or "").strip().lower(),
        (os.environ.get("SHADOWLAB_REDIS_URL", "") or "").strip(),
        (os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab") or "lab").strip().lower(),
    )


def active_backend() -> RateLimitBackend:
    """Process-cached accessor for the configured rate-limit backend.

    The cache key is the env fingerprint (`backend`, `redis_url`,
    `policy`). When tests flip `SHADOWLAB_POLICY_PROFILE` between
    `lab` and `corp`, the singleton is rebuilt so the policy-specific
    fail-closed behaviour kicks in.
    """
    global _BACKEND, _BACKEND_FINGERPRINT
    current = _env_fingerprint()
    if _BACKEND is None or current != _BACKEND_FINGERPRINT:
        with _BACKEND_LOCK:
            if _BACKEND is None or current != _BACKEND_FINGERPRINT:
                _BACKEND = _build_backend()
                _BACKEND_FINGERPRINT = current
    return _BACKEND


def reset_backend_for_tests() -> None:
    """Force the next `active_backend()` call to re-read environment."""
    global _BACKEND, _BACKEND_FINGERPRINT
    with _BACKEND_LOCK:
        _BACKEND = None
        _BACKEND_FINGERPRINT = ("", "", "")
    with _BUCKET_LOCK:
        _MEMORY_BUCKETS.clear()
