from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
