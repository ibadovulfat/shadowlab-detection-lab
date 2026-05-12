"""SHA-256 keyed verdict cache for the antivirus pipeline.

Production AV products dedupe aggressively: the same hash should not
re-execute every signature, every YARA rule, every cloud lookup just
because the file landed at a different path. This module owns that
dedupe, keyed on `(sha256, providers_fingerprint)` so that changing the
provider set (e.g. enabling the cloud provider) correctly bypasses
older cached verdicts.

The cache is db-backed when a `db` connection is available and falls
back to an in-process LRU when not (lab/test runs). Entries carry an
absolute `expires_at` timestamp so eviction is lazy and deterministic
across processes. Negative results (clean) are cached too — that is
the whole point of the dedupe — but `error`/`degraded` verdicts are
deliberately *not* cached so a transient provider failure cannot
poison subsequent scans.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any


DEFAULT_TTL_SECONDS = 24 * 3600
NON_CACHEABLE_STATUSES = {"error", "degraded", "skipped", "disabled", "unavailable"}


class VerdictCache:
    def __init__(self, *, db: Any = None, default_ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._db = db
        self._ttl = max(60, int(default_ttl_seconds))
        self._lock = threading.RLock()
        self._memory: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}

    @staticmethod
    def fingerprint(providers: list[str]) -> str:
        """Stable fingerprint independent of list order."""
        material = "|".join(sorted({str(item).strip().lower() for item in providers if str(item).strip()}))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def lookup(self, sha256: str, providers_fp: str) -> dict[str, Any] | None:
        if not sha256 or not providers_fp:
            return None
        now = time.time()
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    row = conn.execute(
                        """
                        SELECT payload_json, expires_at
                        FROM av_verdict_cache
                        WHERE sha256 = ? AND providers_fp = ?
                        """,
                        (sha256.lower(), providers_fp),
                    ).fetchone()
                    if row and float(row[1] or 0) > now:
                        try:
                            return json.loads(row[0])
                        except Exception:
                            return None
                    if row:
                        # Expired — evict opportunistically.
                        conn.execute(
                            "DELETE FROM av_verdict_cache WHERE sha256 = ? AND providers_fp = ?",
                            (sha256.lower(), providers_fp),
                        )
                        conn.commit()
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        with self._lock:
            cached = self._memory.get((sha256.lower(), providers_fp))
            if not cached:
                return None
            expires_at, payload = cached
            if expires_at <= now:
                self._memory.pop((sha256.lower(), providers_fp), None)
                return None
            return dict(payload)

    def store(
        self,
        sha256: str,
        providers_fp: str,
        result: dict[str, Any],
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        if not sha256 or not providers_fp or not isinstance(result, dict):
            return
        status = str(result.get("status", "")).lower()
        if status in NON_CACHEABLE_STATUSES:
            return
        ttl = max(60, int(ttl_seconds if ttl_seconds is not None else self._ttl))
        expires_at = time.time() + ttl
        summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    payload_json = json.dumps(result, ensure_ascii=False)
                    conn.execute(
                        """
                        INSERT INTO av_verdict_cache (
                            sha256, providers_fp, fused_verdict, severity,
                            score, confidence, payload_json, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(sha256, providers_fp) DO UPDATE SET
                            fused_verdict = excluded.fused_verdict,
                            severity = excluded.severity,
                            score = excluded.score,
                            confidence = excluded.confidence,
                            payload_json = excluded.payload_json,
                            expires_at = excluded.expires_at
                        """,
                        (
                            sha256.lower(),
                            providers_fp,
                            str(summary.get("fused_verdict", result.get("status", ""))),
                            str(summary.get("severity", "low")),
                            int(summary.get("score", 0) or 0),
                            str(summary.get("confidence", "low")),
                            payload_json,
                            float(expires_at),
                        ),
                    )
                    conn.commit()
                    return
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        with self._lock:
            self._memory[(sha256.lower(), providers_fp)] = (expires_at, dict(result))

    def invalidate(self, sha256: str, providers_fp: str | None = None) -> int:
        sha = sha256.lower()
        removed = 0
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    if providers_fp:
                        cursor = conn.execute(
                            "DELETE FROM av_verdict_cache WHERE sha256 = ? AND providers_fp = ?",
                            (sha, providers_fp),
                        )
                    else:
                        cursor = conn.execute("DELETE FROM av_verdict_cache WHERE sha256 = ?", (sha,))
                    removed = int(getattr(cursor, "rowcount", 0) or 0)
                    conn.commit()
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        with self._lock:
            keys = [key for key in self._memory if key[0] == sha and (providers_fp is None or key[1] == providers_fp)]
            for key in keys:
                self._memory.pop(key, None)
                removed += 1
        return removed

    def stats(self) -> dict[str, Any]:
        live = 0
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM av_verdict_cache WHERE expires_at > ?",
                        (time.time(),),
                    ).fetchone()
                    live = int((row or [0])[0] or 0)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        memory_live = 0
        now = time.time()
        with self._lock:
            for expires_at, _ in self._memory.values():
                if expires_at > now:
                    memory_live += 1
        return {"db_live": live, "memory_live": memory_live, "ttl_seconds": self._ttl}
