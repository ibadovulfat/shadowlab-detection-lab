"""Minimal Prometheus-compatible metrics registry — zero extra deps.

The app already ships without `prometheus_client`, and pulling it in just
for `Counter` / `Gauge` would add 30k LOC of vendor code to an offline
lab install. The exposition format is a handful of text rules, so we
hand-roll it here.

Thread safety: every mutation goes through `self._lock` so a background
worker (`api.workers.connector_worker`) and an HTTP request thread can
bump counters without racing.

Usage:

    from api.observability import default_registry

    default_registry.counter("shadowlab_requests_total", {"status": "200"}).inc()
    default_registry.histogram("shadowlab_request_duration_seconds").observe(0.042)

    # /metrics endpoint
    text = default_registry.render()
"""
from __future__ import annotations

import threading
import time
from typing import Iterable


# Default histogram buckets — chosen for sub-second API latency. Callers
# that need longer spans (e.g. a connector batch loop) should create
# their own histogram with explicit buckets.
_DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


def _format_labels(labels: dict[str, str] | None) -> str:
    """Render a label set in Prometheus exposition syntax: `{k="v",k2="v2"}`.

    Empty labels render as empty string so the metric line becomes
    `name value` — matches the spec for unlabelled series.
    """
    if not labels:
        return ""
    parts = []
    for key in sorted(labels):
        value = str(labels[key]).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        parts.append(f'{key}="{value}"')
    return "{" + ",".join(parts) + "}"


def _label_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    """Hashable, order-independent label-set key for dict lookup."""
    if not labels:
        return ()
    return tuple(sorted(labels.items()))


class _Counter:
    """Monotonic counter. `inc(n)` rejects negative `n` to catch misuse."""

    __slots__ = ("_value",)

    def __init__(self) -> None:
        self._value = 0.0

    def inc(self, amount: float = 1.0) -> None:
        if amount < 0:
            raise ValueError("Counter.inc requires a non-negative amount")
        self._value += amount

    @property
    def value(self) -> float:
        return self._value


class _Gauge:
    """Arbitrary-value gauge. `set`, `inc`, `dec`."""

    __slots__ = ("_value",)

    def __init__(self) -> None:
        self._value = 0.0

    def set(self, value: float) -> None:
        self._value = float(value)

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        self._value -= amount

    @property
    def value(self) -> float:
        return self._value


class _Histogram:
    """Cumulative-bucket histogram. Mirrors Prometheus semantics:
    every bucket counts observations ≤ its upper bound, plus a `+Inf`
    bucket that equals `count`."""

    __slots__ = ("_buckets", "_counts", "_sum", "_count")

    def __init__(self, buckets: Iterable[float]) -> None:
        sorted_buckets = tuple(sorted(float(b) for b in buckets))
        self._buckets = sorted_buckets
        self._counts = [0] * len(sorted_buckets)
        self._sum = 0.0
        self._count = 0

    def observe(self, value: float) -> None:
        self._sum += value
        self._count += 1
        for idx, upper in enumerate(self._buckets):
            if value <= upper:
                self._counts[idx] += 1

    @property
    def buckets(self) -> tuple[float, ...]:
        return self._buckets

    @property
    def counts(self) -> list[int]:
        return list(self._counts)

    @property
    def sum(self) -> float:
        return self._sum

    @property
    def count(self) -> int:
        return self._count


class MetricsRegistry:
    """Holds every metric in the process and renders them as Prometheus text.

    Each metric is identified by `(name, label_values)`. The first call
    with a given name also records the help string + metric type for the
    `# HELP` / `# TYPE` header — subsequent calls with the same name
    ignore their help arg to avoid accidental overrides.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], _Counter]] = {}
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], _Gauge]] = {}
        self._histograms: dict[str, dict[tuple[tuple[str, str], ...], _Histogram]] = {}
        self._meta: dict[str, tuple[str, str]] = {}  # name -> (type, help)

    # --- registration helpers -------------------------------------------------

    def counter(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        *,
        help: str = "",
    ) -> _Counter:
        key = _label_key(labels)
        with self._lock:
            bucket = self._counters.setdefault(name, {})
            if key not in bucket:
                bucket[key] = _Counter()
            self._meta.setdefault(name, ("counter", help))
            return bucket[key]

    def gauge(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        *,
        help: str = "",
    ) -> _Gauge:
        key = _label_key(labels)
        with self._lock:
            bucket = self._gauges.setdefault(name, {})
            if key not in bucket:
                bucket[key] = _Gauge()
            self._meta.setdefault(name, ("gauge", help))
            return bucket[key]

    def histogram(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        *,
        help: str = "",
        buckets: Iterable[float] = _DEFAULT_BUCKETS,
    ) -> _Histogram:
        key = _label_key(labels)
        with self._lock:
            bucket = self._histograms.setdefault(name, {})
            if key not in bucket:
                bucket[key] = _Histogram(buckets)
            self._meta.setdefault(name, ("histogram", help))
            return bucket[key]

    # --- exposition -----------------------------------------------------------

    def render(self) -> str:
        """Return the full registry in Prometheus text exposition format."""
        lines: list[str] = []
        with self._lock:
            for name in sorted(self._meta):
                metric_type, help_text = self._meta[name]
                if help_text:
                    lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} {metric_type}")
                if metric_type == "counter":
                    for key, counter in self._counters.get(name, {}).items():
                        lines.append(f"{name}{_format_labels(dict(key))} {counter.value}")
                elif metric_type == "gauge":
                    for key, gauge in self._gauges.get(name, {}).items():
                        lines.append(f"{name}{_format_labels(dict(key))} {gauge.value}")
                elif metric_type == "histogram":
                    for key, histogram in self._histograms.get(name, {}).items():
                        base_labels = dict(key)
                        for upper, count in zip(histogram.buckets, histogram.counts):
                            bucket_labels = dict(base_labels, le=str(upper))
                            lines.append(f"{name}_bucket{_format_labels(bucket_labels)} {count}")
                        inf_labels = dict(base_labels, le="+Inf")
                        lines.append(f"{name}_bucket{_format_labels(inf_labels)} {histogram.count}")
                        lines.append(f"{name}_sum{_format_labels(base_labels)} {histogram.sum}")
                        lines.append(f"{name}_count{_format_labels(base_labels)} {histogram.count}")
        # Prometheus requires a trailing newline after the final line.
        return "\n".join(lines) + "\n"


default_registry = MetricsRegistry()


class TimerContext:
    """Context manager that observes elapsed wall-clock seconds into a histogram.

    Example:

        with TimerContext(default_registry.histogram("request_duration_seconds")):
            do_work()
    """

    __slots__ = ("_histogram", "_start")

    def __init__(self, histogram: _Histogram) -> None:
        self._histogram = histogram
        self._start = 0.0

    def __enter__(self) -> "TimerContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._histogram.observe(time.perf_counter() - self._start)
