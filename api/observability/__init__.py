"""Observability primitives — structured logging, in-process metrics.

Split into its own package so the app can render `/metrics` and emit JSON
log lines without pulling heavyweight deps like `prometheus_client` or
`opentelemetry-sdk`. Both modules are hand-rolled and have zero external
dependencies — a deliberate choice to keep the offline-lab install
footprint small.
"""
from api.observability.metrics import MetricsRegistry, default_registry  # noqa: F401
from api.observability.logging import JsonLogFormatter, configure_json_logging  # noqa: F401
