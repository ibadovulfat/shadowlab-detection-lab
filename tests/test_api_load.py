from __future__ import annotations

import concurrent.futures
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from fastapi.testclient import TestClient

import api.main
import api.security as security
import plugins.yara_scanner as yara_scanner
import threat_intelligence
from tests.test_security import make_settings


class ApiLoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(api.main.app)

    def test_health_endpoint_handles_parallel_requests(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    responses = list(executor.map(lambda _: self.client.get("/health").status_code, range(24)))
        self.assertTrue(all(status == 200 for status in responses))

    def test_local_yara_health_endpoint_loads(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.get("/yara/local/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertIn("pack_counts", payload)

    def test_local_yara_policy_roundtrip_and_analytics(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        policy = {
            "allowlist_hashes": [],
            "allowlist_path_prefixes": [],
            "allowlist_rule_patterns": ["unit_test_rule"],
            "suppressed_rule_patterns": [],
            "boost_rule_patterns": {"inceptor": 9},
        }
        original_policy = yara_scanner.POLICY_PATH.read_text(encoding="utf-8") if yara_scanner.POLICY_PATH.exists() else ""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                sample = Path(temp_dir) / "sample.bin"
                sample.write_text("powershell -enc BBBB", encoding="utf-8")
                threat_intelligence.run_local_yara_scan(str(sample), pack="fast")
                with mock.patch.object(api.main, "security_settings", settings):
                    with mock.patch.object(security, "security_settings", settings):
                        put_response = self.client.put("/yara/local/policy", json={"policy": policy})
                        analytics_response = self.client.get("/yara/local/analytics")
        finally:
            yara_scanner.POLICY_PATH.write_text(original_policy, encoding="utf-8")
            yara_scanner._load_policy.cache_clear()
        self.assertEqual(put_response.status_code, 200)
        self.assertEqual(put_response.json()["status"], "updated")
        self.assertEqual(put_response.json()["policy"]["boost_rule_patterns"]["inceptor"], 9)
        self.assertEqual(analytics_response.status_code, 200)
        analytics = analytics_response.json()
        self.assertEqual(analytics["status"], "ok")
        self.assertIn("sources", analytics)

    def test_local_yara_rule_tuning_and_update_workflow_endpoints(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                tuning_response = self.client.post(
                    "/yara/local/tuning/rule",
                    json={"rule_id": "Inceptor_AMSI_WLDP_ETW_Bypass", "score_delta": 7, "disabled": False, "force": False, "notes": "unit test"},
                )
                workflow_response = self.client.get("/yara/local/update-workflow")
                snapshot_response = self.client.post("/yara/local/update-workflow/snapshot")
        self.assertEqual(tuning_response.status_code, 200)
        self.assertEqual(workflow_response.status_code, 200)
        self.assertEqual(snapshot_response.status_code, 200)
        self.assertEqual(workflow_response.json()["status"], "ok")
        self.assertIn("inventory", workflow_response.json())
        self.assertEqual(snapshot_response.json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
