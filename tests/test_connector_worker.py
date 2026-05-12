"""Unit tests for api.workers.connector_worker.

Written after the worker was extracted out of api/main.py — previously the
drain loop was untestable in isolation because it was glued to module
globals (`_connector_worker_thread`, `_connector_worker_stop`) and imported
the full app to reach `enterprise_service`. The class now accepts both
dependencies as constructor args so we can exercise it with plain mocks.
"""
from __future__ import annotations

import logging
import threading
import time
import unittest
from unittest import mock

from api.workers.connector_worker import (
    ConnectorQueueWorker,
    env_worker_enabled,
    env_worker_interval_seconds,
)


class ConnectorQueueWorkerTests(unittest.TestCase):
    def _make_worker(self, **overrides):
        enterprise = mock.MagicMock()
        observability = mock.MagicMock()
        kwargs = dict(
            enterprise_service=enterprise,
            observability_service=observability,
            logger=logging.getLogger("test.connector_worker"),
            enabled=True,
            interval_seconds=1,
        )
        kwargs.update(overrides)
        return ConnectorQueueWorker(**kwargs), enterprise, observability

    def test_start_is_no_op_when_disabled(self) -> None:
        worker, enterprise, _ = self._make_worker(enabled=False)
        started = worker.start()
        self.assertFalse(started)
        self.assertFalse(worker.is_running)
        enterprise.process_connector_queue.assert_not_called()

    def test_start_is_idempotent_when_already_running(self) -> None:
        worker, _, _ = self._make_worker(interval_seconds=3600)  # never ticks in test window
        try:
            self.assertTrue(worker.start())
            self.assertFalse(worker.start())  # second call no-ops
            self.assertTrue(worker.is_running)
        finally:
            worker.stop(join_timeout=2.0)

    def test_loop_invokes_process_connector_queue_until_stopped(self) -> None:
        """Sub-second interval — confirm at least one iteration before stop."""
        worker, enterprise, _ = self._make_worker(interval_seconds=1)
        # First wait() still sleeps ~1s, so we need to poll rather than
        # synchronously assert immediately after start.
        worker.start()
        deadline = time.time() + 3.0
        while time.time() < deadline and enterprise.process_connector_queue.call_count == 0:
            time.sleep(0.1)
        worker.stop(join_timeout=2.0)
        self.assertGreaterEqual(enterprise.process_connector_queue.call_count, 1)
        enterprise.process_connector_queue.assert_called_with(limit=50)

    def test_loop_survives_exception_and_logs_to_observability(self) -> None:
        """A raising queue drain must NOT crash the loop — this was the bug
        before the `try/except ... continue` pattern was added."""
        worker, enterprise, observability = self._make_worker(interval_seconds=1)
        enterprise.process_connector_queue.side_effect = RuntimeError("db blip")
        worker.start()
        deadline = time.time() + 3.0
        while time.time() < deadline and enterprise.process_connector_queue.call_count < 1:
            time.sleep(0.1)
        worker.stop(join_timeout=2.0)
        self.assertGreaterEqual(enterprise.process_connector_queue.call_count, 1)
        observability.log_event.assert_called_with("connector_queue_worker_iteration_failed")

    def test_stop_unblocks_wait_even_without_start(self) -> None:
        worker, _, _ = self._make_worker(enabled=False)
        # Must not raise or deadlock.
        worker.stop(join_timeout=0.5)


class EnvParserTests(unittest.TestCase):
    def test_env_worker_enabled_defaults_true(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("SHADOWLAB_CONNECTOR_QUEUE_WORKER", None)
            self.assertTrue(env_worker_enabled())

    def test_env_worker_enabled_respects_false(self) -> None:
        with mock.patch.dict("os.environ", {"SHADOWLAB_CONNECTOR_QUEUE_WORKER": "false"}):
            self.assertFalse(env_worker_enabled())

    def test_env_worker_interval_has_five_second_floor(self) -> None:
        with mock.patch.dict("os.environ", {"SHADOWLAB_CONNECTOR_QUEUE_INTERVAL_SECONDS": "0"}):
            self.assertEqual(env_worker_interval_seconds(), 5)

    def test_env_worker_interval_honors_valid_value(self) -> None:
        with mock.patch.dict("os.environ", {"SHADOWLAB_CONNECTOR_QUEUE_INTERVAL_SECONDS": "42"}):
            self.assertEqual(env_worker_interval_seconds(), 42)


if __name__ == "__main__":
    unittest.main()
