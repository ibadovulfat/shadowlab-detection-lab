from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

import api.main
import api.security as security
from tests.test_security import make_settings


class ApiE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(api.main.app)

    def test_security_ops_report_and_observability_summary(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                report = self.client.get("/enterprise/report/security-ops")
                summary = self.client.get("/observability/summary")
                db_readiness = self.client.get("/enterprise/database/readiness")
                graph = self.client.get("/graph/entity-map")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(db_readiness.status_code, 200)
        self.assertEqual(graph.status_code, 200)
        self.assertIn("integrity", report.json())
        self.assertIn("database", report.json())
        self.assertIn("by_type", summary.json())
        self.assertIn("production_notes", db_readiness.json())
        self.assertIn("overall_risk", graph.json()["summary"])


if __name__ == "__main__":
    unittest.main()
