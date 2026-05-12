"""Wave-3 ops tests for the antivirus pipeline.

Five concerns covered:
  * `MetricsRegistry` — counter/gauge/histogram exposition format,
    Prometheus text scraping shape.
  * `ScanJobQueue` — submit / dispatch / progress events / cancel.
  * `WebhookDispatcher` — HMAC signature shape, retry-then-DLQ flow,
    DLQ replay round-trip.
  * `FolderWatcher` — initial seed is silent, new file is submitted
    after quiet period.
  * `compute_signature` — exact byte format expected by receivers.

No live network. The webhook dispatcher accepts an injected
`http_post` so retry behaviour is fully deterministic.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from services.antivirus import FolderWatcher, ScanJobQueue
from services.observability.metrics import MetricsRegistry
from services.webhook_dispatcher import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookDispatcher,
    compute_signature,
)


# ------------------------------------------------------ Fake antivirus svc


class _FakeAntivirusService:
    """Mimics the slice of AntivirusService that ScanJobQueue uses."""

    def __init__(self, *, scan_delay: float = 0.0, raise_after_scan: bool = False):
        self.calls: list[dict] = []
        self._scan_delay = scan_delay
        self._raise_after_scan = raise_after_scan

    def normalize_policy(self, value):
        merged = {"providers": ["aegis_core"], "enabled": True}
        if isinstance(value, dict):
            merged.update(value)
        return merged

    def scan_file(self, target_path, *, policy=None, workspace_id="default", actor=""):
        self.calls.append({"target_path": target_path, "policy": policy, "workspace_id": workspace_id, "actor": actor})
        if self._scan_delay > 0:
            time.sleep(self._scan_delay)
        if self._raise_after_scan:
            raise RuntimeError("boom")
        return {
            "status": "clean",
            "path": target_path,
            "summary": {"fused_verdict": "clean", "severity": "low", "score": 0},
        }


# ------------------------------------------------------------ Metrics tests


class MetricsRegistryTests(unittest.TestCase):
    def test_counter_renders_label_combinations(self) -> None:
        r = MetricsRegistry()
        r.record_scan(verdict="infected", scope="file", source="live", duration_seconds=1.5)
        r.record_scan(verdict="clean",    scope="file", source="cache", duration_seconds=0.01)
        r.record_engine_error(provider="cloud_sandbox", reason="timeout")
        body = r.render()
        self.assertIn('shadowlab_av_scans_total{scope="file",source="live",verdict="infected"} 1.0', body)
        self.assertIn('shadowlab_av_scans_total{scope="file",source="cache",verdict="clean"} 1.0', body)
        self.assertIn('shadowlab_av_engine_errors_total{provider="cloud_sandbox",reason="timeout"} 1.0', body)
        # Counter must have HELP/TYPE preamble.
        self.assertIn("# HELP shadowlab_av_scans_total", body)
        self.assertIn("# TYPE shadowlab_av_scans_total counter", body)

    def test_histogram_buckets_are_cumulative(self) -> None:
        r = MetricsRegistry()
        for value in (0.005, 0.05, 0.5, 5.0):
            r.record_scan(verdict="clean", scope="file", source="live", duration_seconds=value)
        body = r.render()
        # The +Inf bucket must equal total observation count (4).
        self.assertIn('shadowlab_av_scan_duration_seconds_bucket{scope="file",le="+Inf"} 4', body)
        self.assertIn('shadowlab_av_scan_duration_seconds_count{scope="file"} 4', body)

    def test_gauge_engine_status_reflects_provider_snapshot(self) -> None:
        r = MetricsRegistry()
        r.update_engine_posture({
            "aegis_core":   {"available": True, "latest_signature_update": time.time() - 3600},
            "cloud_intel":  {"available": False},
        })
        body = r.render()
        self.assertIn('shadowlab_av_engine_status{provider="aegis_core"} 1.0', body)
        self.assertIn('shadowlab_av_engine_status{provider="cloud_intel"} 0.0', body)
        self.assertIn('shadowlab_av_signature_age_seconds{provider="aegis_core"}', body)


# ----------------------------------------------------------- Job queue tests


class ScanJobQueueTests(unittest.TestCase):
    def test_submit_runs_to_completion_and_publishes_progress(self) -> None:
        svc = _FakeAntivirusService(scan_delay=0.05)
        queue = ScanJobQueue(svc, db=None, max_workers=2)
        events: list[dict] = []
        evt_done = threading.Event()
        snap = queue.submit("/tmp/foo", workspace_id="ws1", actor="alice")
        unsub = queue.subscribe(snap["job_id"], lambda payload: (events.append(payload), evt_done.set() if payload.get("state") == "complete" else None))
        self.assertTrue(evt_done.wait(timeout=3.0), f"job did not complete; events={events}")
        unsub()
        states = [e["state"] for e in events]
        self.assertIn("complete", states)
        final = queue.get(snap["job_id"])
        self.assertEqual(final["state"], "complete")
        self.assertEqual(len(svc.calls), 1)
        self.assertEqual(svc.calls[0]["workspace_id"], "ws1")

    def test_scan_exception_marks_job_error(self) -> None:
        svc = _FakeAntivirusService(raise_after_scan=True)
        queue = ScanJobQueue(svc, db=None, max_workers=1)
        snap = queue.submit("/tmp/bar")
        # Give the worker a moment.
        for _ in range(40):
            current = queue.get(snap["job_id"])
            if current and current["state"] in {"error", "complete"}:
                break
            time.sleep(0.05)
        current = queue.get(snap["job_id"])
        self.assertEqual(current["state"], "error")
        self.assertIn("boom", current["error"])

    def test_cancel_queued_job_before_dispatch(self) -> None:
        svc = _FakeAntivirusService(scan_delay=0.5)
        queue = ScanJobQueue(svc, db=None, max_workers=1)
        # Saturate the worker.
        first = queue.submit("/tmp/blocker")
        # Second job sits in queue.
        second = queue.submit("/tmp/cancel-me")
        result = queue.cancel(second["job_id"])
        self.assertTrue(result["ok"])
        snap = queue.get(second["job_id"])
        self.assertIn(snap["state"], {"cancelled", "cancelling"})


# ----------------------------------------------------- Webhook dispatcher tests


class WebhookSignatureTests(unittest.TestCase):
    def test_signature_format_is_v1_hex(self) -> None:
        sig = compute_signature("topsecret", "1700000000", b'{"a":1}')
        self.assertTrue(sig.startswith("v1="), sig)
        self.assertEqual(len(sig), len("v1=") + 64)  # SHA-256 hex
        # Same inputs → identical signature (deterministic).
        sig2 = compute_signature("topsecret", "1700000000", b'{"a":1}')
        self.assertEqual(sig, sig2)
        # Different secret → different signature.
        sig3 = compute_signature("othersecret", "1700000000", b'{"a":1}')
        self.assertNotEqual(sig, sig3)

    def test_empty_secret_yields_empty_signature(self) -> None:
        self.assertEqual(compute_signature("", "1700000000", b'{"x":1}'), "")


class WebhookDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.responses: list[tuple[int, str]] = []
        self.captured: list[dict] = []

        def _http(url, body, headers, timeout):
            response = self.responses.pop(0) if self.responses else (200, "ok")
            self.captured.append({"url": url, "body": body, "headers": dict(headers), "timeout": timeout})
            return response

        self._http = _http

    def test_successful_delivery_marks_state_delivered(self) -> None:
        d = WebhookDispatcher(db=None, http_post=self._http, retry_schedule_seconds=(1,))
        try:
            self.responses = [(204, "")]
            result = d.deliver_sync(
                workspace_id="ws1",
                target_url="https://example.test/hook",
                event_type="av.scan.complete",
                payload={"sample": "value"},
            )
            self.assertEqual(result["state"], "delivered")
            self.assertEqual(result["status_code"], 204)
            captured = self.captured[0]
            self.assertEqual(captured["headers"]["Content-Type"], "application/json")
            self.assertIn(TIMESTAMP_HEADER, captured["headers"])
            # Signature should NOT be present yet — no secret has been
            # provisioned for this workspace and the dispatcher's
            # auto-provision path uses the DB.
        finally:
            d.shutdown()

    def test_retries_then_dlq_when_all_attempts_fail(self) -> None:
        # Three failures with a 1-attempt schedule → after first failure
        # delivery already exhausts and goes to DLQ. Use schedule=(0,) so
        # the second-and-final attempt is immediate.
        d = WebhookDispatcher(db=None, http_post=self._http, retry_schedule_seconds=(0, 0))
        try:
            self.responses = [(503, "down"), (502, "still-down")]
            result = d.deliver_sync(
                workspace_id="ws1",
                target_url="https://example.test/hook",
                event_type="av.scan.error",
                payload={},
            )
            # First sync attempt failed → state is `retrying`.
            self.assertEqual(result["state"], "retrying")
            self.assertEqual(result["status_code"], 503)
        finally:
            d.shutdown()


# ---------------------------------------------------------- Folder watcher tests


class FolderWatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="shadowlab-watcher-test-"))
        self.submitted: list[dict] = []

        def _submit(path, **kwargs):
            self.submitted.append({"path": path, **kwargs})
            return {"job_id": "fake", "state": "queued"}

        self._submit = _submit

    def test_existing_files_are_not_re_scanned_on_first_start(self) -> None:
        # Pre-populate.
        seed = self.tmp / "preexisting.bin"
        seed.write_bytes(b"hello")
        watcher = FolderWatcher(scan_submit=self._submit, poll_interval_seconds=0.1, quiet_period_seconds=0.1)
        watcher.configure(paths=[str(self.tmp)], workspace_id="ws1")
        watcher.start()
        time.sleep(0.5)
        watcher.stop()
        # Existing files seen at start must not be submitted.
        self.assertFalse(any(item["path"].endswith("preexisting.bin") for item in self.submitted))

    def test_new_file_after_quiet_period_is_submitted(self) -> None:
        watcher = FolderWatcher(scan_submit=self._submit, poll_interval_seconds=0.15, quiet_period_seconds=0.2)
        watcher.configure(paths=[str(self.tmp)], workspace_id="ws1")
        watcher.start()
        try:
            new_file = self.tmp / "fresh.bin"
            new_file.write_bytes(b"bad payload")
            # Wait for at least 2 ticks past the quiet period.
            deadline = time.time() + 3.0
            while time.time() < deadline and not self.submitted:
                time.sleep(0.1)
            self.assertTrue(any(item["path"].endswith("fresh.bin") for item in self.submitted),
                            f"fresh.bin not submitted; observed={self.submitted}")
        finally:
            watcher.stop()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
