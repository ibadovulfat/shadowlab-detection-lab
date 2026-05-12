"""Scan worker pool for the antivirus pipeline.

Before this module existed, every provider scan ran sequentially on the
request thread: ClamAV's subprocess blocked the event loop, KicomAV's
in-process scanner blocked the next provider, and a single slow engine
dragged every scan to its worst-case latency. Production AV pipelines
run engines concurrently with hard wall-clock timeouts so that one
misbehaving engine degrades only *that* engine's verdict, not the
whole scan.

This module owns:
  * Concurrent provider execution via `ThreadPoolExecutor`
  * Per-provider wall-clock timeout enforced with `Future.result(...)`
  * Structured failure surfacing — a timeout or crash becomes a
    `status=error` provider result, never a raised exception, so the
    fusion layer above can still emit a verdict from the engines that
    did complete.
  * Telemetry: per-scan duration, per-provider duration, concurrency,
    and active-scan gauge — exposed through `snapshot()` for the
    observability service / API.

Process-level isolation (ProcessPoolExecutor) is intentionally *not*
used here. KicomAV's scanner relies on in-process `sys.path`
manipulation to import the vendored tree, which does not survive
pickling. Threads give us provider parallelism and timeouts without
breaking that contract; a future wave can move to subprocess scanners
by shipping a standalone scan CLI.
"""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FutureTimeoutError
from pathlib import Path
from typing import Any, Callable


DEFAULT_MAX_WORKERS = max(2, min(8, (os.cpu_count() or 4)))


class ScanWorkerPool:
    def __init__(self, *, max_workers: int | None = None):
        workers = int(max_workers or DEFAULT_MAX_WORKERS)
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix="shadowlab-av-worker",
        )
        self._max_workers = max(1, workers)
        self._lock = threading.Lock()
        self._active = 0
        self._peak = 0
        self._total = 0
        self._total_duration_ms = 0

    @property
    def max_workers(self) -> int:
        return self._max_workers

    def run_providers(
        self,
        providers: dict[str, Callable[[], dict[str, Any]]],
        *,
        timeout_seconds: float,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        """Execute every provider callable concurrently.

        `providers` is `{provider_key: thunk}` where each thunk, when
        invoked, performs the actual scan and returns the provider
        result dict. The callable is responsible for catching its own
        internal failures; this pool additionally wraps the invocation
        so a raised exception becomes `status=error`.

        Returns `(results, telemetry)`. Telemetry contains per-provider
        duration_ms, concurrency used, and total wall-clock duration.
        """
        if not providers:
            return {}, {"duration_ms": 0, "concurrency": 0, "providers": {}}
        started = time.time()
        futures: dict[str, Future] = {}
        submitted_at: dict[str, float] = {}
        with self._lock:
            self._active += 1
            self._peak = max(self._peak, self._active)
        try:
            for provider_key, thunk in providers.items():
                submitted_at[provider_key] = time.time()
                futures[provider_key] = self._executor.submit(_safe_thunk_runner, provider_key, thunk)
            results: dict[str, dict[str, Any]] = {}
            provider_telemetry: dict[str, dict[str, Any]] = {}
            deadline = started + max(1.0, float(timeout_seconds))
            for provider_key, future in futures.items():
                remaining = max(0.05, deadline - time.time())
                provider_started = submitted_at[provider_key]
                try:
                    payload = future.result(timeout=remaining)
                    if not isinstance(payload, dict):
                        payload = {"status": "error", "engine": provider_key, "error": "provider returned non-dict"}
                except FutureTimeoutError:
                    future.cancel()
                    payload = {
                        "status": "error",
                        "engine": provider_key,
                        "error": f"Scan timed out after {timeout_seconds} seconds in worker pool",
                    }
                except Exception as exc:
                    payload = {
                        "status": "error",
                        "engine": provider_key,
                        "error": f"Scan crashed: {exc}",
                    }
                duration_ms = int((time.time() - provider_started) * 1000)
                payload.setdefault("scan_time_ms", duration_ms)
                results[provider_key] = payload
                provider_telemetry[provider_key] = {
                    "duration_ms": duration_ms,
                    "status": str(payload.get("status", "unknown")),
                }
        finally:
            with self._lock:
                self._active = max(0, self._active - 1)
                self._total += 1
                self._total_duration_ms += int((time.time() - started) * 1000)
        telemetry = {
            "duration_ms": int((time.time() - started) * 1000),
            "concurrency": len(futures),
            "providers": provider_telemetry,
        }
        return results, telemetry

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            avg_ms = int(self._total_duration_ms / self._total) if self._total else 0
            return {
                "max_workers": self._max_workers,
                "active_scans": self._active,
                "peak_concurrency": self._peak,
                "total_scans": self._total,
                "avg_scan_ms": avg_ms,
            }

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


def _safe_thunk_runner(provider_key: str, thunk: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return thunk()
    except Exception as exc:
        return {"status": "error", "engine": provider_key, "error": str(exc)}
