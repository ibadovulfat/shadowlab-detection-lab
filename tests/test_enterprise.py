from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import database as db
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


if __name__ == "__main__":
    unittest.main()
