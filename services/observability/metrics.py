"""Pure-Python Prometheus exposition for ShadowLab.

We deliberately don't pull in `prometheus_client` — the deployment story
matters. The text exposition format is small and stable enough to
implement directly in ~150 lines, which keeps the ShadowLab API binary
free of an additional runtime dependency and avoids version-skew bugs
between `prometheus_client` major releases.

What is exposed (Wave-3 antivirus posture):

  * `shadowlab_av_scans_total{verdict,scope,source}` — Counter. One
    increment per fused scan; labels let an analyst see the
    clean/suspicious/infected ratio per scope (file/process/job).
  * `shadowlab_av_scan_duration_seconds` — Histogram. Wall-clock end-to-end
    fusion latency. Buckets tuned for typical AV scan timings (sub-second
    cache hits to ~120 s sandbox runs).
  * `shadowlab_av_engine_errors_total{provider,reason}` — Counter. Bumped
    every time a provider returns `status: error` (timeouts, missing
    binaries, network failures).
  * `shadowlab_av_engine_status{provider}` — Gauge. 1 when the provider
    reports `available=true` in the latest status snapshot, 0 otherwise.
  * `shadowlab_av_signature_age_seconds{provider}` — Gauge. Seconds since
    the provider's last signature/definition update. Drives the "stale"
    SLO alerts.
  * `shadowlab_av_jobs_total{state}` — Counter. Async scan job state
    transitions (queued / running / complete / error / cancelled).
  * `shadowlab_webhook_deliveries_total{outcome}` — Counter. Webhook send
    outcomes (delivered / retried / dlq).

All counters are monotonically-increasing in-process; gauges are
last-seen values updated by the responsible service. The registry is
thread-safe, so observers from FastAPI workers (sync) and background
threads (job queue, folder watcher) can both contribute.
"""
from __future__ import annotations

import threading
import time
from typing import Any


# Histogram buckets (seconds). Tuned for AV scan latency distribution:
# - <0.05 s   cache hit
# - 0.5–2 s   local engines warm
# - 5–30 s    cloud lookups
# - 60+ s     sandbox detonation timeouts
DEFAULT_DURATION_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
    10.0, 30.0, 60.0, 120.0, 300.0,
)


def _label_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in labels)
    return "{" + inner + "}"


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class _Counter:
    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help = help_text
        self.kind = "counter"
        self._values: dict[tuple[tuple[str, str], ...], float] = {}
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = _label_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + float(amount)

    def lines(self) -> list[str]:
        with self._lock:
            snapshot = list(self._values.items())
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        for labels, value in snapshot:
            out.append(f"{self.name}{_format_labels(labels)} {value}")
        if not snapshot:
            out.append(f"{self.name} 0")
        return out


class _Gauge:
    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help = help_text
        self.kind = "gauge"
        self._values: dict[tuple[tuple[str, str], ...], float] = {}
        self._lock = threading.Lock()

    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = _label_key(labels)
        with self._lock:
            self._values[key] = float(value)

    def lines(self) -> list[str]:
        with self._lock:
            snapshot = list(self._values.items())
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} gauge"]
        for labels, value in snapshot:
            out.append(f"{self.name}{_format_labels(labels)} {value}")
        if not snapshot:
            out.append(f"{self.name} 0")
        return out


class _Histogram:
    def __init__(self, name: str, help_text: str, buckets: tuple[float, ...] = DEFAULT_DURATION_BUCKETS):
        self.name = name
        self.help = help_text
        self.kind = "histogram"
        self._buckets = tuple(sorted(buckets))
        # Per-label-set: (bucket_counts list, sum, count)
        self._series: dict[tuple[tuple[str, str], ...], tuple[list[int], float, int]] = {}
        self._lock = threading.Lock()

    def observe(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = _label_key(labels)
        v = float(value)
        with self._lock:
            bucket_counts, total, count = self._series.get(key, ([0] * len(self._buckets), 0.0, 0))
            for idx, threshold in enumerate(self._buckets):
                if v <= threshold:
                    bucket_counts[idx] += 1
            self._series[key] = (bucket_counts, total + v, count + 1)

    def lines(self) -> list[str]:
        with self._lock:
            snapshot = list(self._series.items())
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        for labels, (bucket_counts, total, count) in snapshot:
            base_labels = list(labels)
            for idx, threshold in enumerate(self._buckets):
                bucket_labels = tuple(base_labels + [("le", _format_bucket(threshold))])
                out.append(f"{self.name}_bucket{_format_labels(bucket_labels)} {bucket_counts[idx]}")
            inf_labels = tuple(base_labels + [("le", "+Inf")])
            out.append(f"{self.name}_bucket{_format_labels(inf_labels)} {count}")
            out.append(f"{self.name}_sum{_format_labels(labels)} {total}")
            out.append(f"{self.name}_count{_format_labels(labels)} {count}")
        if not snapshot:
            for threshold in self._buckets:
                out.append(f'{self.name}_bucket{{le="{_format_bucket(threshold)}"}} 0')
            out.append(f'{self.name}_bucket{{le="+Inf"}} 0')
            out.append(f"{self.name}_sum 0")
            out.append(f"{self.name}_count 0")
        return out


def _format_bucket(value: float) -> str:
    if value == int(value):
        return str(int(value))
    return f"{value:g}"


class MetricsRegistry:
    """Process-singleton metrics registry."""

    def __init__(self) -> None:
        self._metrics: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._bootstrap_default_metrics()
        self._process_started_at = time.time()

    def _bootstrap_default_metrics(self) -> None:
        self.counter("shadowlab_av_scans_total", "Total fused antivirus scans by verdict / scope / source.")
        self.histogram("shadowlab_av_scan_duration_seconds", "Wall-clock antivirus scan duration in seconds.")
        self.counter("shadowlab_av_engine_errors_total", "Per-provider engine errors during fusion.")
        self.gauge("shadowlab_av_engine_status", "1 when the engine is available, 0 otherwise.")
        self.gauge("shadowlab_av_signature_age_seconds", "Seconds since each provider's last signature update.")
        self.counter("shadowlab_av_jobs_total", "Async scan job state transitions.")
        self.counter("shadowlab_webhook_deliveries_total", "Webhook delivery outcomes (delivered/retried/dlq).")
        self.histogram(
            "shadowlab_webhook_delivery_seconds",
            "Webhook delivery latency.",
            buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
        )
        self.gauge("shadowlab_process_uptime_seconds", "Seconds since the API process booted.")

    def counter(self, name: str, help_text: str = "") -> _Counter:
        with self._lock:
            metric = self._metrics.get(name)
            if metric is None or metric.kind != "counter":
                metric = _Counter(name, help_text)
                self._metrics[name] = metric
            return metric

    def gauge(self, name: str, help_text: str = "") -> _Gauge:
        with self._lock:
            metric = self._metrics.get(name)
            if metric is None or metric.kind != "gauge":
                metric = _Gauge(name, help_text)
                self._metrics[name] = metric
            return metric

    def histogram(self, name: str, help_text: str = "", buckets: tuple[float, ...] = DEFAULT_DURATION_BUCKETS) -> _Histogram:
        with self._lock:
            metric = self._metrics.get(name)
            if metric is None or metric.kind != "histogram":
                metric = _Histogram(name, help_text, buckets=buckets)
                self._metrics[name] = metric
            return metric

    # ------------------------------------------------------------------
    # Convenience adapters for the antivirus pipeline
    # ------------------------------------------------------------------

    def record_scan(self, *, verdict: str, scope: str, source: str, duration_seconds: float) -> None:
        labels = {"verdict": verdict or "unknown", "scope": scope or "file", "source": source or "live"}
        self.counter("shadowlab_av_scans_total").inc(1.0, labels=labels)
        self.histogram("shadowlab_av_scan_duration_seconds").observe(max(0.0, float(duration_seconds)), labels={"scope": scope or "file"})

    def record_engine_error(self, *, provider: str, reason: str) -> None:
        self.counter("shadowlab_av_engine_errors_total").inc(
            1.0, labels={"provider": provider or "unknown", "reason": (reason or "error")[:64]}
        )

    def update_engine_posture(self, providers: dict[str, Any]) -> None:
        if not isinstance(providers, dict):
            return
        for key, info in providers.items():
            if not isinstance(info, dict):
                continue
            self.gauge("shadowlab_av_engine_status").set(
                1.0 if info.get("available") else 0.0, labels={"provider": str(key)}
            )
            updated = float(info.get("latest_signature_update", 0) or 0)
            if updated > 0:
                self.gauge("shadowlab_av_signature_age_seconds").set(
                    max(0.0, time.time() - updated), labels={"provider": str(key)}
                )

    def record_job_transition(self, state: str) -> None:
        self.counter("shadowlab_av_jobs_total").inc(1.0, labels={"state": state or "unknown"})

    def record_webhook_outcome(self, *, outcome: str, duration_seconds: float = 0.0) -> None:
        self.counter("shadowlab_webhook_deliveries_total").inc(1.0, labels={"outcome": outcome or "unknown"})
        if duration_seconds > 0:
            self.histogram("shadowlab_webhook_delivery_seconds").observe(float(duration_seconds))

    def render(self) -> str:
        # Refresh process uptime gauge each render — it's a derived metric.
        self.gauge("shadowlab_process_uptime_seconds").set(max(0.0, time.time() - self._process_started_at))
        with self._lock:
            metrics = list(self._metrics.values())
        out: list[str] = []
        for metric in metrics:
            out.extend(metric.lines())
            out.append("")
        return "\n".join(out)


class _DelegatingRegistry:
    """Convenience-method facade over `api.observability.default_registry`.

    The API package shipped its own zero-dep Prometheus registry months
    before Wave-3, and the `/metrics` endpoint already renders from it.
    Rather than maintain two parallel registries (and confuse scrapers
    by hosting the AV / job / webhook series on a *separate* `/metrics`
    that doesn't exist), we forward every Wave-3 `record_*` call into
    the existing registry so the single canonical scrape surface picks
    up the new series automatically.

    The convenience methods (`record_scan`, `update_engine_posture`,
    etc.) are kept here so callers don't need to know the underlying
    `(name, labels).counter(...).inc()` idiom — they just write
    `metrics.record_scan(verdict='clean', scope='file', ...)`."""

    def __init__(self) -> None:
        from api.observability import default_registry  # local import: avoid load-order cycles
        self._reg = default_registry
        self._process_started_at = time.time()

    # Pass-throughs so callers that hold the registry can still use
    # the raw counter/gauge/histogram API.
    def counter(self, name: str, labels: dict[str, str] | None = None, *, help: str = ""):
        return self._reg.counter(name, labels or {}, help=help)

    def gauge(self, name: str, labels: dict[str, str] | None = None, *, help: str = ""):
        return self._reg.gauge(name, labels or {}, help=help)

    def histogram(self, name: str, labels: dict[str, str] | None = None, *, help: str = "", buckets: tuple[float, ...] = DEFAULT_DURATION_BUCKETS):
        return self._reg.histogram(name, labels or {}, help=help, buckets=buckets)

    # Convenience adapters used by the antivirus pipeline.

    def record_scan(self, *, verdict: str, scope: str, source: str, duration_seconds: float) -> None:
        labels = {"verdict": verdict or "unknown", "scope": scope or "file", "source": source or "live"}
        self._reg.counter(
            "shadowlab_av_scans_total", labels,
            help="Total fused antivirus scans by verdict / scope / source.",
        ).inc(1.0)
        self._reg.histogram(
            "shadowlab_av_scan_duration_seconds", {"scope": scope or "file"},
            help="Wall-clock antivirus scan duration in seconds.",
            buckets=DEFAULT_DURATION_BUCKETS,
        ).observe(max(0.0, float(duration_seconds)))

    def record_engine_error(self, *, provider: str, reason: str) -> None:
        self._reg.counter(
            "shadowlab_av_engine_errors_total",
            {"provider": provider or "unknown", "reason": (reason or "error")[:64]},
            help="Per-provider engine errors during fusion.",
        ).inc(1.0)

    def update_engine_posture(self, providers: dict[str, Any]) -> None:
        if not isinstance(providers, dict):
            return
        for key, info in providers.items():
            if not isinstance(info, dict):
                continue
            self._reg.gauge(
                "shadowlab_av_engine_status", {"provider": str(key)},
                help="1 when the engine is available, 0 otherwise.",
            ).set(1.0 if info.get("available") else 0.0)
            updated = float(info.get("latest_signature_update", 0) or 0)
            if updated > 0:
                self._reg.gauge(
                    "shadowlab_av_signature_age_seconds", {"provider": str(key)},
                    help="Seconds since each provider's last signature update.",
                ).set(max(0.0, time.time() - updated))

    def record_job_transition(self, state: str) -> None:
        self._reg.counter(
            "shadowlab_av_jobs_total", {"state": state or "unknown"},
            help="Async scan job state transitions.",
        ).inc(1.0)

    def record_webhook_outcome(self, *, outcome: str, duration_seconds: float = 0.0) -> None:
        self._reg.counter(
            "shadowlab_webhook_deliveries_total", {"outcome": outcome or "unknown"},
            help="Webhook delivery outcomes (delivered/retried/dlq).",
        ).inc(1.0)
        if duration_seconds > 0:
            self._reg.histogram(
                "shadowlab_webhook_delivery_seconds", {},
                help="Webhook delivery latency.",
                buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
            ).observe(float(duration_seconds))

    def render(self) -> str:
        return self._reg.render()


_REGISTRY: Any = None
_REGISTRY_LOCK = threading.Lock()


def get_registry():
    """Return the process-singleton Wave-3 metrics adapter (delegates
    to `api.observability.default_registry`)."""
    global _REGISTRY
    if _REGISTRY is None:
        with _REGISTRY_LOCK:
            if _REGISTRY is None:
                try:
                    _REGISTRY = _DelegatingRegistry()
                except Exception:
                    # Standalone use (e.g. unit tests) — fall back to
                    # the self-contained MetricsRegistry so callers
                    # don't blow up when `api.observability` is absent.
                    _REGISTRY = MetricsRegistry()
    return _REGISTRY


def render_prometheus_text() -> str:
    return get_registry().render()
