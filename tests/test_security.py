from __future__ import annotations

import hmac
import hashlib
import os
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException
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

    def test_process_action_rejects_process_name_mismatch(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(security, "security_settings", settings):
            with mock.patch.object(api.main.process_intel_service, "profile_process", return_value={"pid": 321, "name": "lsass.exe", "exe": "C:\\Windows\\System32\\lsass.exe"}):
                response = self.client.post("/processes/321/actions/kill", params={"process_name": "notepad.exe"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Process name mismatch", response.text)

    def test_purple_replay_rejects_paths_outside_artifact_directory(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/enterprise/purple/replay", json={"artifact_path": "C:\\Windows\\win.ini"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("shadowlab_out", response.text)

    def test_threat_hash_lookup_rejects_invalid_sha256(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/threat-intel/hash/lookup", json={"file_hash": "abc"})
        self.assertEqual(response.status_code, 422)

    def test_connector_configuration_rejects_invalid_name(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post(
                "/enterprise/connectors",
                json={"name": "Bad Name", "kind": "siem", "enabled": True, "config": {}},
            )
        self.assertEqual(response.status_code, 422)

    def test_startup_security_validation_rejects_insecure_prod_profile(self) -> None:
        settings = make_settings(
            auth_required=False,
            policy_profile="prod",
            enable_dangerous_actions=True,
            allowed_origins=["*"],
        )
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                with self.assertRaises(RuntimeError):
                    api.main._validate_startup_security_posture()

    def test_approval_is_action_scoped_and_one_time(self) -> None:
        db = __import__("database")
        db.init_db()
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            approval_id = db.create_approval_request(
                conn,
                case_id=1,
                action="process:kill",
                requested_by="analyst",
                approver="admin",
                reason="unit test",
                expires_at=time.time() + 3600,
            )
            db.resolve_approval_request(conn, approval_id, "approved", "admin")
        finally:
            conn.close()

        settings = make_settings(auth_required=True, policy_profile="corp")
        request = SimpleNamespace(
            headers={"X-ShadowLab-Approval-Id": str(approval_id)},
            state=SimpleNamespace(),
        )
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                api.main._require_enterprise_approval(request, "process:kill")
                self.assertEqual(request.state.pending_approval_id, approval_id)
                api.main._consume_pending_approval(request, 200)
                with self.assertRaises(HTTPException):
                    api.main._require_enterprise_approval(request, "process:kill")

    def test_alert_configuration_persists_encrypted_webhook(self) -> None:
        db = __import__("database")
        db.init_db()
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post(
                    "/alerts/configure",
                    json={"webhook_url": "https://hooks.slack.com/services/test", "message": "hello"},
                )
        self.assertEqual(response.status_code, 200)
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            stored = db.get_app_setting(conn, "alert_webhook_url_enc")
        finally:
            conn.close()
        self.assertTrue(stored.startswith("enc:v1:"))


if __name__ == "__main__":
    unittest.main()
