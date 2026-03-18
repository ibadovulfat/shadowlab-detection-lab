from __future__ import annotations

import hmac
import hashlib
import os
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import api.main
import api.security as security
from api.security import SecuritySettings


def make_settings(**overrides) -> SecuritySettings:
    base = SecuritySettings(
        api_key="",
        api_key_sha256="",
        api_keys={},
        api_keys_sha256={},
        auth_required=True,
        enable_dangerous_actions=True,
        enable_network_warfare=False,
        allow_destructive_file_delete=False,
        allowed_origins=["http://127.0.0.1", "http://localhost"],
        protected_process_names=["lsass.exe", "wininit.exe"],
        policy_profile="lab",
    )
    return SecuritySettings(**{**base.__dict__, **overrides})


class SecurityValidationTests(unittest.TestCase):
    def test_load_security_settings_rejects_mixed_raw_and_hashed_keys(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SHADOWLAB_REQUIRE_AUTH": "true",
                "SHADOWLAB_API_KEYS": "viewer:viewer-secret",
                "SHADOWLAB_API_KEYS_SHA256": f"admin:{hashlib.sha256(b'admin-secret').hexdigest()}",
            },
            clear=True,
        ):
            with self.assertRaises(ValueError):
                security.load_security_settings()

    def test_load_security_settings_rejects_unknown_roles(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SHADOWLAB_REQUIRE_AUTH": "true",
                "SHADOWLAB_API_KEYS_SHA256": f"operator:{hashlib.sha256(b'secret').hexdigest()}",
            },
            clear=True,
        ):
            with self.assertRaises(ValueError):
                security.load_security_settings()

    def test_build_capabilities_respects_prod_policy_profile(self) -> None:
        settings = make_settings(
            policy_profile="prod",
            enable_dangerous_actions=True,
            enable_network_warfare=True,
            allow_destructive_file_delete=True,
        )
        caps = security.build_capabilities("admin", settings=settings)
        self.assertFalse(caps["can_manage_process_actions"])
        self.assertFalse(caps["can_manage_quarantine"])
        self.assertFalse(caps["can_manage_network_warfare"])
        self.assertFalse(caps["can_manage_deception"])


class AuthApiTests(unittest.TestCase):
    def setUp(self) -> None:
        security._RATE_LIMIT_BUCKETS.clear()
        self.client = TestClient(api.main.app)

    def tearDown(self) -> None:
        security._RATE_LIMIT_BUCKETS.clear()

    def test_auth_context_reports_viewer_capabilities(self) -> None:
        viewer_key = "viewer-secret"
        settings = make_settings(
            api_keys_sha256={"viewer": hashlib.sha256(viewer_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context", headers={"X-API-Key": viewer_key})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], "viewer")
        self.assertFalse(payload["capabilities"]["can_manage_process_actions"])
        self.assertFalse(payload["capabilities"]["can_run_monitor"])

    def test_admin_only_endpoint_blocks_viewer(self) -> None:
        viewer_key = "viewer-secret"
        settings = make_settings(
            api_keys_sha256={"viewer": hashlib.sha256(viewer_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/integrations/telemetry-fabric/start", headers={"X-API-Key": viewer_key})
        self.assertEqual(response.status_code, 403)
        self.assertIn("Admin role required", response.text)

    def test_failed_authentication_is_rate_limited(self) -> None:
        settings = make_settings(api_keys_sha256={"viewer": hashlib.sha256(b"viewer-secret").hexdigest()})
        with mock.patch.object(security, "security_settings", settings):
            for _ in range(security.AUTH_FAILURE_LIMIT):
                response = self.client.get("/auth/context", headers={"X-API-Key": "wrong-secret"})
                self.assertEqual(response.status_code, 401)
            limited = self.client.get("/auth/context", headers={"X-API-Key": "wrong-secret"})
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Too many failed authentication attempts", limited.text)

    def test_signed_admin_request_is_required_for_mutations(self) -> None:
        admin_key = "admin-secret"
        settings = make_settings(
            api_keys_sha256={"admin": hashlib.sha256(admin_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/integrations/telemetry-fabric/start", headers={"X-API-Key": admin_key})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Signed request headers are required", response.text)

    def test_signed_admin_request_replay_is_blocked(self) -> None:
        admin_key = "admin-secret"
        settings = make_settings(
            api_keys_sha256={"admin": hashlib.sha256(admin_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        timestamp = str(int(time.time()))
        nonce = "nonce-123456"
        payload = "\n".join(["POST", "/integrations/telemetry-fabric/start", timestamp, nonce])
        signature = hmac.new(admin_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {
            "X-API-Key": admin_key,
            "X-ShadowLab-Timestamp": timestamp,
            "X-ShadowLab-Nonce": nonce,
            "X-ShadowLab-Signature": signature,
        }
        with mock.patch.object(security, "security_settings", settings):
            first = self.client.post("/integrations/telemetry-fabric/start", headers=headers)
            second = self.client.post("/integrations/telemetry-fabric/start", headers=headers)
        self.assertNotEqual(first.status_code, 401)
        self.assertEqual(second.status_code, 409)
        self.assertIn("nonce has already been used", second.text)


if __name__ == "__main__":
    unittest.main()
