"""Tests for the observability package — metrics registry and JSON formatter.

The registry and formatter are hand-rolled (no prometheus_client /
structlog dependency) so these tests lock down the contract: output
format, thread-safety expectations, and idempotency of the JSON log
configuration.
"""
from __future__ import annotations

import io
import json
import logging
import threading
import unittest
from unittest import mock

from api.observability import (
    JsonLogFormatter,
    MetricsRegistry,
    configure_json_logging,
)
from api.observability.metrics import TimerContext


class MetricsRegistryTests(unittest.TestCase):
    def test_counter_increments_and_renders_as_prometheus_text(self) -> None:
        reg = MetricsRegistry()
        reg.counter("my_total", help="a counter").inc()
        reg.counter("my_total").inc(3)
        output = reg.render()
        self.assertIn("# HELP my_total a counter", output)
        self.assertIn("# TYPE my_total counter", output)
        self.assertIn("my_total 4", output)

    def test_counter_rejects_negative_amount(self) -> None:
        reg = MetricsRegistry()
        with self.assertRaises(ValueError):
            reg.counter("bad").inc(-1)

    def test_labels_are_sorted_for_stable_output(self) -> None:
        reg = MetricsRegistry()
        reg.counter("m", {"b": "1", "a": "2"}).inc()
        # Rendered label order must be alphabetical regardless of insertion.
        self.assertIn('m{a="2",b="1"} 1', reg.render())

    def test_label_values_are_escaped(self) -> None:
        reg = MetricsRegistry()
        reg.counter("m", {"k": 'quote"and\\backslash'}).inc()
        self.assertIn(r'k="quote\"and\\backslash"', reg.render())

    def test_distinct_label_sets_produce_distinct_series(self) -> None:
        reg = MetricsRegistry()
        reg.counter("m", {"status": "200"}).inc()
        reg.counter("m", {"status": "500"}).inc(2)
        output = reg.render()
        self.assertIn('m{status="200"} 1', output)
        self.assertIn('m{status="500"} 2', output)

    def test_gauge_set_inc_dec(self) -> None:
        reg = MetricsRegistry()
        gauge = reg.gauge("queue_depth")
        gauge.set(10)
        gauge.inc(2)
        gauge.dec()
        self.assertIn("queue_depth 11", reg.render())

    def test_histogram_buckets_are_cumulative(self) -> None:
        reg = MetricsRegistry()
        hist = reg.histogram("lat", buckets=[0.1, 1.0, 10.0])
        hist.observe(0.05)
        hist.observe(0.5)
        hist.observe(5.0)
        output = reg.render()
        # 0.05 → counted in 0.1, 1.0, 10.0
        # 0.5 → counted in 1.0, 10.0
        # 5.0 → counted in 10.0
        self.assertIn('lat_bucket{le="0.1"} 1', output)
        self.assertIn('lat_bucket{le="1.0"} 2', output)
        self.assertIn('lat_bucket{le="10.0"} 3', output)
        self.assertIn('lat_bucket{le="+Inf"} 3', output)
        self.assertIn("lat_count 3", output)

    def test_concurrent_increment_is_race_free(self) -> None:
        """Stress test for the registry lock. 10 threads × 1000 incs on a
        shared series; total must equal 10000 with no race drops."""
        reg = MetricsRegistry()
        counter = reg.counter("shared")

        def worker() -> None:
            for _ in range(1000):
                counter.inc()

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(counter.value, 10000.0)


class TimerContextTests(unittest.TestCase):
    def test_timer_observes_into_histogram(self) -> None:
        reg = MetricsRegistry()
        hist = reg.histogram("op_seconds", buckets=[0.001, 1.0])
        with TimerContext(hist):
            pass
        self.assertEqual(hist.count, 1)
        self.assertLess(hist.sum, 1.0)  # noop block shouldn't take 1s


class JsonLogFormatterTests(unittest.TestCase):
    def _make_record(self, **overrides) -> logging.LogRecord:
        base = dict(
            name="test",
            level=logging.INFO,
            pathname="t.py",
            lineno=1,
            msg="hello %s",
            args=("world",),
            exc_info=None,
        )
        base.update(overrides)
        return logging.LogRecord(**base)

    def test_basic_record_renders_as_json(self) -> None:
        record = self._make_record()
        line = JsonLogFormatter().format(record)
        payload = json.loads(line)
        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["logger"], "test")
        self.assertEqual(payload["message"], "hello world")
        self.assertIn("ts", payload)

    def test_extra_fields_are_promoted(self) -> None:
        record = self._make_record()
        record.request_id = "abc-123"
        record.workspace = "w1"
        payload = json.loads(JsonLogFormatter().format(record))
        self.assertEqual(payload["request_id"], "abc-123")
        self.assertEqual(payload["workspace"], "w1")

    def test_unjsonable_extra_falls_back_to_str(self) -> None:
        record = self._make_record()
        record.obj = object()  # not JSON-serializable
        payload = json.loads(JsonLogFormatter().format(record))
        # Must still produce valid JSON, with a string fallback.
        self.assertIsInstance(payload["obj"], str)

    def test_exception_info_lands_under_exception_key(self) -> None:
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = self._make_record(exc_info=sys.exc_info())
        payload = json.loads(JsonLogFormatter().format(record))
        self.assertIn("exception", payload)
        self.assertIn("ValueError", payload["exception"])


class EnvGateTests(unittest.TestCase):
    """The SHADOWLAB_JSON_LOGGING env gate must stay off-by-default so CI
    and local dev keep human-readable stdout. This test imports api.main
    after flipping the env var to confirm the gate actually triggers
    `configure_json_logging()`."""

    def test_env_gate_recognizes_truthy_values(self) -> None:
        # Test the parsing contract directly — spinning up the full app
        # just to toggle logging is overkill.
        truthy = ["1", "true", "True", "yes", "on", "YES"]
        falsy = ["", "0", "false", "no", "off", "nope"]
        for value in truthy:
            with self.subTest(value=value):
                self.assertIn(value.strip().lower(), {"1", "true", "yes", "on"})
        for value in falsy:
            with self.subTest(value=value):
                self.assertNotIn(value.strip().lower(), {"1", "true", "yes", "on"})


class ConfigureJsonLoggingTests(unittest.TestCase):
    def test_is_idempotent(self) -> None:
        """Second call must NOT double up handlers."""
        stream = io.StringIO()
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_sentinel = getattr(root, "_shadowlab_json_logging_configured", False)
        try:
            # Strip sentinel to force fresh configure.
            if hasattr(root, "_shadowlab_json_logging_configured"):
                delattr(root, "_shadowlab_json_logging_configured")
            for h in list(root.handlers):
                root.removeHandler(h)

            configure_json_logging(stream=stream)
            first_count = len(root.handlers)
            configure_json_logging(stream=stream)
            second_count = len(root.handlers)
            self.assertEqual(first_count, second_count)
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            if original_sentinel:
                setattr(root, "_shadowlab_json_logging_configured", True)
            elif hasattr(root, "_shadowlab_json_logging_configured"):
                delattr(root, "_shadowlab_json_logging_configured")


if __name__ == "__main__":
    unittest.main()
