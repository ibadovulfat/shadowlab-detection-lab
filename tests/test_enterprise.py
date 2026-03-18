from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import database as db
from services.connector_delivery_service import ConnectorDeliveryService
from services.enterprise_service import EnterpriseService


class DummyProcessService:
    def snapshot_processes(self, include_deep_fields: bool = False):
        return [
            {"pid": 10, "name": "lsass.exe", "memory_percent": 2.0, "cpu_percent": 0.1, "signature_status": "Valid"},
            {"pid": 20, "name": "python.exe", "memory_percent": 8.0, "cpu_percent": 12.0, "signature_status": "unknown"},
        ]


class EnterpriseServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        db.init_db()
        self.service = EnterpriseService(Path("."), DummyProcessService(), mock.Mock())

    def test_asset_criticality_prioritizes_os_processes(self) -> None:
        result = self.service.assess_asset_criticality()
        self.assertTrue(result["top_assets"])
        self.assertEqual(result["top_assets"][0]["name"], "lsass.exe")
        self.assertGreaterEqual(float(result["top_assets"][0]["criticality_score"]), 85.0)

    def test_policy_profiles_include_prod(self) -> None:
        result = self.service.get_policy_profiles()
        self.assertIn("prod", result["profiles"])
        self.assertTrue(result["profiles"]["corp"]["approval_required"])

    def test_canary_bypass_assessment_lists_tests(self) -> None:
        result = self.service.assess_canary_bypass()
        self.assertEqual(result["status"], "ready")
        self.assertGreaterEqual(len(result["tests"]), 3)

    def test_connector_dispatch_queues_failures(self) -> None:
        self.service.configure_connector(
            name="splunk",
            kind="siem",
            enabled=True,
            config={"hec_url": "https://invalid.local/hec", "token": "token"},
        )
        with mock.patch.object(
            self.service.connector_delivery,
            "deliver",
            return_value={"ok": False, "status": "exception", "detail": "timeout"},
        ):
            result = self.service.dispatch_connector_event("unit_test_event", {"title": "Unit test"})
        self.assertTrue(result["queued"])
        queue = self.service.connector_queue_status(status="retry", limit=20)
        self.assertTrue(queue)

    def test_connector_delivery_rejects_plain_http_non_localhost(self) -> None:
        delivery = ConnectorDeliveryService(timeout=1)
        result = delivery.deliver(
            {"name": "shuffle", "config_json": {"webhook_url": "http://example.com/hook"}},
            {"title": "Unit test"},
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "invalid_config")

    def test_connector_config_is_encrypted_at_rest_and_redacted_on_read(self) -> None:
        self.service.configure_connector(
            name="splunk",
            kind="siem",
            enabled=True,
            config={"hec_url": "https://splunk.example", "token": "super-secret-token"},
        )
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            rows = db.get_connectors(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        stored = next(item for item in rows if item["name"] == "splunk")
        self.assertNotIn("super-secret-token", stored["config_json"])
        listed = next(item for item in self.service.list_connectors() if item["name"] == "splunk")
        self.assertEqual(listed["config"]["token"], "***redacted***")

    def test_connector_queue_moves_poison_event_to_dead_letter(self) -> None:
        self.service.configure_connector(
            name="splunk",
            kind="siem",
            enabled=True,
            config={"hec_url": "https://splunk.example", "token": "token"},
        )
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.enqueue_connector_delivery(
                conn,
                connector_name="splunk",
                event_type="unit_test",
                payload_json='{"title":"test"}',
                status="retry",
                attempts=5,
                next_retry_at=0,
                last_error="timeout",
            )
        finally:
            conn.close()
        with mock.patch.object(
            self.service.connector_delivery,
            "deliver",
            return_value={"ok": False, "status": "exception", "detail": "timeout"},
        ):
            self.service.process_connector_queue(limit=10)
        queue = self.service.connector_queue_status(status="dead_letter", limit=20)
        self.assertTrue(any(str(item.get("connector_name", "")) == "splunk" for item in queue))


if __name__ == "__main__":
    unittest.main()
