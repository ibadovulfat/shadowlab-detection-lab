from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from services.telemetry_service import CollectorTelemetryBridge


class CollectorBridgeTests(unittest.TestCase):
    def test_status_closes_finished_process_log_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bridge = CollectorTelemetryBridge(config={}, out_dir=Path(temp_dir))
            log_path = Path(temp_dir) / "collector.log"
            handle = log_path.open("a", encoding="utf-8")
            bridge._collector_log_handle = handle
            bridge._collector_process = mock.Mock()
            bridge._collector_process.poll.return_value = 0

            status = bridge.collector_status()

            self.assertFalse(status["process_running"])
            self.assertTrue(handle.closed)

    def test_ingest_endpoint_falls_back_when_configured_url_is_unsafe(self) -> None:
        bridge = CollectorTelemetryBridge(
            config={"telemetry_fabric": {"otlp_http_endpoint": "http://169.254.169.254:4318"}},
        )
        self.assertEqual(bridge._collector_ingest_endpoint(), "http://127.0.0.1:4318")

    def test_ingest_endpoint_honors_safe_explicit_value(self) -> None:
        bridge = CollectorTelemetryBridge(
            config={"telemetry_fabric": {"otlp_http_endpoint": "http://127.0.0.1:4318"}},
        )
        self.assertEqual(bridge._collector_ingest_endpoint(), "http://127.0.0.1:4318")

    def test_zpages_url_falls_back_when_env_url_is_unsafe(self) -> None:
        bridge = CollectorTelemetryBridge(config={})
        with mock.patch.dict(os.environ, {"SHADOWLAB_OTEL_ZPAGES_URL": "http://169.254.169.254/debug/servicez"}, clear=False):
            self.assertEqual(bridge._collector_zpages_url(), "http://127.0.0.1:55679/debug/servicez")


if __name__ == "__main__":
    unittest.main()
