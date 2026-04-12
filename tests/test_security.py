from __future__ import annotations

import asyncio
import hmac
import hashlib
import os
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

import api.main
import api.security as security
from api.security import SecuritySettings
from services.identity_provider import IdentityPrincipal


def make_settings(**overrides) -> SecuritySettings:
    base = SecuritySettings(
        api_key="",
        api_key_sha256="",
        api_key_role="viewer",
        api_keys={},
        api_keys_sha256={},
        auth_required=True,
        require_tls=False,
        enable_dangerous_actions=True,
        enable_network_warfare=False,
        allow_destructive_file_delete=False,
        allowed_origins=["http://127.0.0.1", "http://localhost"],
        protected_process_names=["lsass.exe", "wininit.exe"],
        trusted_proxies=[],
        policy_profile="lab",
        noauth_default_role="viewer",
        oidc_enabled=False,
        signed_request_window_seconds=60,
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

    def test_load_security_settings_rejects_invalid_single_key_role(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SHADOWLAB_REQUIRE_AUTH": "true",
                "SHADOWLAB_API_KEY_SHA256": hashlib.sha256(b"single-secret").hexdigest(),
                "SHADOWLAB_API_KEY_ROLE": "operator",
            },
            clear=True,
        ):
            with self.assertRaises(ValueError):
                security.load_security_settings()

    def test_load_security_settings_requires_explicit_noauth_opt_out(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
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
        security._SIGNATURE_NONCES.clear()
        db = __import__("database")
        db.init_db()
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            conn.execute("DELETE FROM rate_limit_log")
            conn.execute("DELETE FROM request_nonce_log")
            conn.execute("DELETE FROM identity_revocation_log")
            conn.commit()
        finally:
            conn.close()
        self._secret_env = mock.patch.dict(os.environ, {"SHADOWLAB_SECRET_KEY": "unit-test-secret-key"}, clear=False)
        self._secret_env.start()
        self.client = TestClient(api.main.app)

    def tearDown(self) -> None:
        self._secret_env.stop()
        security._RATE_LIMIT_BUCKETS.clear()
        security._SIGNATURE_NONCES.clear()

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
        self.assertEqual(payload["workspace_id"], "default")
        self.assertFalse(payload["capabilities"]["can_manage_process_actions"])
        self.assertFalse(payload["capabilities"]["can_run_monitor"])

    def test_corp_profile_requires_explicit_workspace_header(self) -> None:
        admin_key = "admin-secret"
        settings = make_settings(
            api_keys_sha256={"admin": hashlib.sha256(admin_key.encode("utf-8")).hexdigest()},
            policy_profile="corp",
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context", headers={"X-API-Key": admin_key})
        self.assertEqual(response.status_code, 403)
        self.assertIn("X-ShadowLab-Workspace is required", response.text)

    def test_role_workspace_mapping_limits_requested_workspace(self) -> None:
        analyst_key = "analyst-secret"
        settings = make_settings(
            api_keys_sha256={"analyst": hashlib.sha256(analyst_key.encode("utf-8")).hexdigest()},
            policy_profile="corp",
            enable_dangerous_actions=True,
        )
        with mock.patch.dict(os.environ, {"SHADOWLAB_ROLE_WORKSPACES": "analyst:tenant-a"}, clear=False):
            with mock.patch.object(security, "security_settings", settings):
                denied = self.client.get(
                    "/auth/context",
                    headers={"X-API-Key": analyst_key, "X-ShadowLab-Workspace": "tenant-b"},
                )
                allowed = self.client.get(
                    "/auth/context",
                    headers={"X-API-Key": analyst_key, "X-ShadowLab-Workspace": "tenant-a"},
                )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.json()["workspace_id"], "tenant-a")

    def test_actor_workspace_mapping_overrides_role_workspace_mapping(self) -> None:
        admin_key = "admin-secret"
        settings = make_settings(
            api_keys_sha256={"admin": hashlib.sha256(admin_key.encode("utf-8")).hexdigest()},
            policy_profile="corp",
            enable_dangerous_actions=True,
        )
        with mock.patch.dict(
            os.environ,
            {
                "SHADOWLAB_ROLE_WORKSPACES": "admin:tenant-a",
                "SHADOWLAB_ACTOR_WORKSPACES": "alice@corp:tenant-b",
            },
            clear=False,
        ):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.get(
                    "/auth/context",
                    headers={
                        "X-API-Key": admin_key,
                        "X-ShadowLab-Workspace": "tenant-b",
                        "X-ShadowLab-Actor": "alice@corp",
                    },
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["actor"], "alice@corp")
        self.assertEqual(response.json()["workspace_id"], "tenant-b")

    def test_global_history_endpoints_are_workspace_scoped_in_corp(self) -> None:
        analyst_key = "analyst-secret"
        settings = make_settings(
            api_keys_sha256={"analyst": hashlib.sha256(analyst_key.encode("utf-8")).hexdigest()},
            policy_profile="corp",
            enable_dangerous_actions=True,
        )
        headers = {"X-API-Key": analyst_key, "X-ShadowLab-Workspace": "tenant-a"}
        db = __import__("database")
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.insert_telemetry(conn, [{"ts": time.time(), "cpu": 1.0, "mem_percent": 2.0}], workspace_id="tenant-a")
            db.log_response_action(conn, "suspend", 11, "cmd.exe", "test", workspace_id="tenant-a")
            db.log_quarantine(conn, 11, "cmd.exe", "c:/a.exe", "c:/q/a.exe", workspace_id="tenant-a")
        finally:
            conn.close()
        with mock.patch.object(security, "security_settings", settings):
            telemetry_response = self.client.get("/history/telemetry", headers=headers)
            timeline_response = self.client.get("/timeline", headers=headers)
            quarantine_response = self.client.get("/quarantine", headers=headers)
        for response in (telemetry_response, timeline_response, quarantine_response):
            self.assertEqual(response.status_code, 200)
        self.assertTrue(telemetry_response.json())
        self.assertTrue(quarantine_response.json())

    def test_integrity_history_is_workspace_scoped_in_corp(self) -> None:
        admin_key = "admin-secret"
        settings = make_settings(
            api_keys_sha256={"admin": hashlib.sha256(admin_key.encode("utf-8")).hexdigest()},
            policy_profile="corp",
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            api.main.integrity_service.refresh_manifest(workspace_id="tenant-a")
            response = self.client.get(
                "/integrity/history",
                headers={"X-API-Key": admin_key, "X-ShadowLab-Workspace": "tenant-a"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(str(item.get("workspace_id", "")) == "tenant-a" for item in response.json()))

    def test_global_history_endpoints_are_isolated_between_workspaces(self) -> None:
        analyst_key = "analyst-secret"
        settings = make_settings(
            api_keys_sha256={"analyst": hashlib.sha256(analyst_key.encode("utf-8")).hexdigest()},
            policy_profile="corp",
            enable_dangerous_actions=True,
        )
        db = __import__("database")
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.insert_telemetry(conn, [{"ts": time.time(), "cpu": 3.0, "mem_percent": 3.0}], workspace_id="tenant-a")
            db.insert_telemetry(conn, [{"ts": time.time(), "cpu": 7.0, "mem_percent": 7.0}], workspace_id="tenant-b")
        finally:
            conn.close()
        with mock.patch.object(security, "security_settings", settings):
            tenant_a = self.client.get("/history/telemetry", headers={"X-API-Key": analyst_key, "X-ShadowLab-Workspace": "tenant-a"})
            tenant_b = self.client.get("/history/telemetry", headers={"X-API-Key": analyst_key, "X-ShadowLab-Workspace": "tenant-b"})
        self.assertEqual(tenant_a.status_code, 200)
        self.assertEqual(tenant_b.status_code, 200)
        self.assertNotEqual(tenant_a.json(), tenant_b.json())

    def test_oidc_bearer_token_can_resolve_identity_and_workspace(self) -> None:
        settings = make_settings(
            auth_required=True,
            oidc_enabled=True,
            policy_profile="corp",
        )
        principal = IdentityPrincipal(
            subject="user-123",
            actor="alice@corp",
            role="admin",
            allowed_workspaces=("tenant-a",),
            approval_workspaces=("tenant-a",),
            issuer="https://issuer.example",
            audience="shadowlab",
            token_id="jti-1",
            expires_at=time.time() + 3600,
            issued_at=time.time() - 60,
            claims={"sub": "user-123"},
        )
        with mock.patch.object(security, "security_settings", settings):
            with mock.patch.object(security.identity_provider, "authenticate_token", return_value=principal):
                response = self.client.get(
                    "/auth/context",
                    headers={"Authorization": "Bearer oidc-token", "X-ShadowLab-Workspace": "tenant-a"},
                )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["auth_source"], "oidc")
        self.assertEqual(payload["subject"], "user-123")
        self.assertEqual(payload["workspace_id"], "tenant-a")
        self.assertEqual(payload["approval_workspaces"], ["tenant-a"])

    def test_oidc_workspace_claim_blocks_unlisted_workspace(self) -> None:
        settings = make_settings(
            auth_required=True,
            oidc_enabled=True,
            policy_profile="corp",
        )
        principal = IdentityPrincipal(
            subject="user-123",
            actor="alice@corp",
            role="analyst",
            allowed_workspaces=("tenant-a",),
            approval_workspaces=(),
            issuer="https://issuer.example",
            audience="shadowlab",
            token_id="jti-1",
            expires_at=time.time() + 3600,
            issued_at=time.time() - 60,
            claims={"sub": "user-123"},
        )
        with mock.patch.object(security, "security_settings", settings):
            with mock.patch.object(security.identity_provider, "authenticate_token", return_value=principal):
                response = self.client.get(
                    "/auth/context",
                    headers={"Authorization": "Bearer oidc-token", "X-ShadowLab-Workspace": "tenant-b"},
                )
        self.assertEqual(response.status_code, 403)
        self.assertIn("not allowed", response.text)

    def test_revoked_oidc_token_is_rejected(self) -> None:
        db = __import__("database")
        db.init_db()
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.revoke_identity_token(
                conn,
                issuer="https://issuer.example",
                subject="user-123",
                token_id="jti-1",
                workspace_id="tenant-a",
                actor="admin@corp",
                reason="unit test",
                expires_at=time.time() + 3600,
            )
        finally:
            conn.close()
        settings = make_settings(auth_required=True, oidc_enabled=True, policy_profile="corp")
        principal = IdentityPrincipal(
            subject="user-123",
            actor="alice@corp",
            role="admin",
            allowed_workspaces=("tenant-a",),
            approval_workspaces=("tenant-a",),
            issuer="https://issuer.example",
            audience="shadowlab",
            token_id="jti-1",
            expires_at=time.time() + 3600,
            issued_at=time.time() - 60,
            claims={"sub": "user-123"},
        )
        with mock.patch.object(security, "security_settings", settings):
            with mock.patch.object(security.identity_provider, "authenticate_token", return_value=principal):
                response = self.client.get(
                    "/auth/context",
                    headers={"Authorization": "Bearer oidc-token", "X-ShadowLab-Workspace": "tenant-a"},
                )
        self.assertEqual(response.status_code, 401)

    def test_auth_context_uses_role_key_even_when_auth_disabled(self) -> None:
        analyst_key = "analyst-secret"
        settings = make_settings(
            auth_required=False,
            api_keys_sha256={"analyst": hashlib.sha256(analyst_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context", headers={"X-API-Key": analyst_key})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], "analyst")
        self.assertTrue(payload["capabilities"]["can_run_hunt"])
        self.assertFalse(payload["capabilities"]["can_manage_process_actions"])

    def test_single_key_defaults_to_viewer_role(self) -> None:
        viewer_key = "single-viewer-secret"
        settings = make_settings(
            api_key_sha256=hashlib.sha256(viewer_key.encode("utf-8")).hexdigest(),
            api_key_role="viewer",
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context", headers={"X-API-Key": viewer_key})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], "viewer")
        self.assertFalse(payload["capabilities"]["can_run_hunt"])

    def test_single_key_can_be_explicitly_scoped_to_admin(self) -> None:
        admin_key = "single-admin-secret"
        settings = make_settings(
            api_key_sha256=hashlib.sha256(admin_key.encode("utf-8")).hexdigest(),
            api_key_role="admin",
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context", headers={"X-API-Key": admin_key})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], "admin")
        self.assertTrue(payload["capabilities"]["can_run_hunt"])

    def test_auth_context_returns_viewer_for_invalid_key_when_auth_disabled(self) -> None:
        settings = make_settings(
            auth_required=False,
            api_keys_sha256={"admin": hashlib.sha256(b"admin-secret").hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context", headers={"X-API-Key": "wrong-secret"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], "viewer")
        self.assertFalse(payload["capabilities"]["can_run_hunt"])

    def test_auth_context_defaults_to_viewer_when_auth_disabled_and_no_key_is_provided(self) -> None:
        settings = make_settings(
            auth_required=False,
            api_keys_sha256={"admin": hashlib.sha256(b"admin-secret").hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], "viewer")
        self.assertFalse(payload["capabilities"]["can_manage_process_actions"])

    def test_auth_context_can_use_explicit_noauth_admin_override(self) -> None:
        settings = make_settings(
            auth_required=False,
            noauth_default_role="admin",
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.get("/auth/context")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["role"], "admin")

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

    def test_viewer_is_blocked_from_sensitive_read_sections(self) -> None:
        viewer_key = "viewer-secret"
        settings = make_settings(
            api_keys_sha256={"viewer": hashlib.sha256(viewer_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            process_response = self.client.get("/processes", headers={"X-API-Key": viewer_key})
            artifact_response = self.client.get("/artifacts", headers={"X-API-Key": viewer_key})
            timeline_response = self.client.get("/timeline", headers={"X-API-Key": viewer_key})
        for response in (process_response, artifact_response, timeline_response):
            self.assertEqual(response.status_code, 403)
            self.assertIn("Analyst or admin role required", response.text)

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

    def test_signed_analyst_request_is_required_for_mutations(self) -> None:
        analyst_key = "analyst-secret"
        settings = make_settings(
            api_keys_sha256={"analyst": hashlib.sha256(analyst_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post(
                "/enterprise/investigations/notes",
                headers={"X-API-Key": analyst_key},
                json={
                    "note_text": "Signed analyst request required.",
                    "item_type": "incident",
                    "item_title": "Test note",
                    "author": "tester",
                },
            )
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
        payload = "\n".join(
            [
                "POST",
                "/integrations/telemetry-fabric/start",
                "",
                hashlib.sha256(b"").hexdigest(),
                timestamp,
                nonce,
            ]
        )
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

    def test_signed_admin_request_rejects_query_tampering(self) -> None:
        admin_key = "admin-secret"
        settings = make_settings(
            api_keys_sha256={"admin": hashlib.sha256(admin_key.encode("utf-8")).hexdigest()},
            enable_dangerous_actions=True,
        )
        timestamp = str(int(time.time()))
        nonce = "nonce-query-123456"
        payload = "\n".join(
            [
                "POST",
                "/processes/321/actions/kill",
                "process_name=calc.exe",
                hashlib.sha256(b"").hexdigest(),
                timestamp,
                nonce,
            ]
        )
        signature = hmac.new(admin_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {
            "X-API-Key": admin_key,
            "X-ShadowLab-Timestamp": timestamp,
            "X-ShadowLab-Nonce": nonce,
            "X-ShadowLab-Signature": signature,
        }
        with mock.patch.object(security, "security_settings", settings):
            with mock.patch.object(
                api.main.process_intel_service,
                "profile_process",
                return_value={"pid": 321, "name": "notepad.exe", "exe": "C:\\Temp\\notepad.exe"},
            ):
                response = self.client.post("/processes/321/actions/kill?process_name=evil.exe", headers=headers)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid signed request signature", response.text)

    def test_process_action_rejects_process_name_mismatch(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            with mock.patch.object(api.main.process_intel_service, "profile_process", return_value={"pid": 321, "name": "lsass.exe", "exe": "C:\\Windows\\System32\\lsass.exe"}):
                response = self.client.post("/processes/321/actions/kill", params={"process_name": "notepad.exe"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Process name mismatch", response.text)

    def test_purple_replay_rejects_paths_outside_artifact_directory(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/enterprise/purple/replay", json={"artifact_path": "C:\\Windows\\win.ini"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("shadowlab_out", response.text)

    def test_whids_file_import_rejects_paths_outside_approved_roots(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/integrations/whids/import/file", json={"file_path": "C:\\Windows\\win.ini"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("approved WHIDS import roots", response.text)

    def test_ossec_file_import_rejects_paths_outside_approved_roots(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/integrations/ossec/import/file", json={"file_path": "C:\\Windows\\win.ini"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("approved OSSEC import roots", response.text)

    def test_ossec_live_ingest_rejects_paths_outside_approved_roots(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/integrations/ossec/live/start", json={"file_path": "C:\\Windows\\win.ini"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("approved OSSEC import roots", response.text)

    def test_honeypot_deploy_rejects_path_traversal_filename(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/deception/honeypot/deploy", json={"filename": "..\\..\\evil.txt"})
        self.assertEqual(response.status_code, 422)
        self.assertTrue(
            "path separators" in response.text or "letters, digits, dot, underscore, and dash" in response.text
        )

    def test_whids_file_import_accepts_paths_within_shadowlab_ingest_root(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        approved_path = Path(api.main.WHIDS_IMPORT_ROOT) / "unit-whids.json"
        approved_path.write_text("[]", encoding="utf-8")
        try:
            with mock.patch.object(security, "security_settings", settings):
                with mock.patch.dict(os.environ, {"SHADOWLAB_ALLOWED_WORKSPACES": "tenant-a"}, clear=False):
                    with mock.patch.object(
                        api.main.hids_integration_service,
                        "import_whids_file",
                        return_value={"integration": "whids", "count": 0},
                    ) as import_mock:
                        response = self.client.post(
                            "/integrations/whids/import/file",
                            headers={"X-ShadowLab-Workspace": "tenant-a"},
                            json={"file_path": str(approved_path)},
                        )
            self.assertEqual(response.status_code, 200)
            import_mock.assert_called_once_with(str(approved_path.resolve(strict=False)), limit=200, workspace_id="tenant-a")
        finally:
            approved_path.unlink(missing_ok=True)

    def test_artifact_listing_is_scoped_to_workspace_directory(self) -> None:
        tenant_dir = Path(api.main.OUT_DIR) / "workspaces" / "tenant-a"
        tenant_dir.mkdir(parents=True, exist_ok=True)
        default_artifact = Path(api.main.OUT_DIR) / "score.json"
        tenant_artifact = tenant_dir / "score.json"
        default_artifact.write_text("{}", encoding="utf-8")
        tenant_artifact.write_text("{}", encoding="utf-8")
        try:
            settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
            with mock.patch.object(api.main, "security_settings", settings):
                with mock.patch.object(security, "security_settings", settings):
                    response = self.client.get("/artifacts", headers={"X-ShadowLab-Workspace": "tenant-a"})
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertIn("score.json", payload)
            self.assertIn("workspaces/tenant-a", payload["score.json"].replace("\\", "/").lower())
        finally:
            default_artifact.unlink(missing_ok=True)
            tenant_artifact.unlink(missing_ok=True)

    def test_telemetry_fabric_export_history_is_scoped_to_workspace(self) -> None:
        db = __import__("database")
        db.init_db()
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.log_integration_export(conn, "shadowlab-telemetry-fabric", "incident_log", "tenant-a-target", "success", "ok", workspace_id="tenant-a")
            db.log_integration_export(conn, "shadowlab-telemetry-fabric", "incident_log", "tenant-b-target", "success", "ok", workspace_id="tenant-b")
        finally:
            conn.close()
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.get("/integrations/telemetry-fabric/exports", headers={"X-ShadowLab-Workspace": "tenant-a"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(any(item["target"] == "tenant-a-target" for item in payload))
        self.assertFalse(any(item["target"] == "tenant-b-target" for item in payload))

    def test_security_ops_export_writes_workspace_specific_artifacts(self) -> None:
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post("/enterprise/report/security-ops/export", headers={"X-ShadowLab-Workspace": "tenant-a"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["workspace_id"], "tenant-a")
        self.assertIn("workspaces/tenant-a", payload["json_path"].replace("\\", "/").lower())

    def test_case_report_export_writes_workspace_specific_artifacts(self) -> None:
        case = api.main.enterprise_service.create_case(title="Scoped report case", workspace_id="tenant-a", owner="alice")
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post(
                    f"/enterprise/cases/{int(case['id'])}/investigation-report/export",
                    headers={"X-ShadowLab-Workspace": "tenant-a"},
                )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("workspaces/tenant-a", payload["json_path"].replace("\\", "/").lower())

    def test_agent_registration_rejects_cross_workspace_host_takeover(self) -> None:
        conn = __import__("database").create_connection()
        self.assertIsNotNone(conn)
        try:
            api.main.fleet_service.register_agent(
                conn,
                {
                    "host_id": "agent-shared-1",
                    "host": "agent-shared-1",
                    "platform": "Windows",
                    "role": "agent",
                },
                workspace_id="tenant-a",
            )
        finally:
            conn.close()
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post(
                    "/agents/register",
                    headers={"X-ShadowLab-Workspace": "tenant-b"},
                    json={
                        "host_id": "agent-shared-1",
                        "host": "agent-shared-1",
                        "platform": "Windows",
                        "role": "agent",
                    },
                )
        self.assertEqual(response.status_code, 409)
        self.assertIn("already owned by workspace", response.text)

    def test_threat_hash_lookup_rejects_invalid_sha256(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/threat-intel/hash/lookup", json={"file_hash": "abc"})
        self.assertEqual(response.status_code, 422)

    def test_connector_configuration_rejects_invalid_name(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post(
                "/enterprise/connectors",
                json={"name": "Bad Name", "kind": "siem", "enabled": True, "config": {}},
            )
        self.assertEqual(response.status_code, 422)

    def test_connector_configuration_rejects_insecure_tls_bypass_in_corp_profile(self) -> None:
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.dict(os.environ, {"SHADOWLAB_POLICY_PROFILE": "corp"}, clear=False):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post(
                    "/enterprise/connectors",
                    headers={"X-ShadowLab-Workspace": "tenant-a"},
                    json={
                        "name": "shuffle",
                        "kind": "soar",
                        "enabled": True,
                        "config": {"webhook_url": "https://localhost:8443/hook", "verify_tls": False},
                    },
                )
        self.assertEqual(response.status_code, 400)
        self.assertIn("verify_tls=false", response.text)

    def test_evidence_capture_rejects_invalid_alert_name(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
        with mock.patch.object(security, "security_settings", settings):
            response = self.client.post("/evidence/capture", json={"alert_name": "..\\..\\bad"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("alert_name", response.text)

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

    def test_startup_security_validation_rejects_non_loopback_host_when_auth_disabled(self) -> None:
        settings = make_settings(
            auth_required=False,
            policy_profile="lab",
        )
        with mock.patch.dict(os.environ, {"SHADOWLAB_HOST": "0.0.0.0"}, clear=False):
            with mock.patch.object(api.main, "security_settings", settings):
                with mock.patch.object(security, "security_settings", settings):
                    with self.assertRaises(RuntimeError):
                        api.main._validate_startup_security_posture()

    def test_startup_security_validation_rejects_corp_profile_without_tls(self) -> None:
        settings = make_settings(
            auth_required=True,
            policy_profile="corp",
            require_tls=False,
        )
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                with self.assertRaises(RuntimeError):
                    api.main._validate_startup_security_posture()

    def test_forwarded_proto_is_ignored_without_trusted_proxy(self) -> None:
        settings = make_settings(trusted_proxies=[])
        request = SimpleNamespace(
            url=SimpleNamespace(scheme="http"),
            client=SimpleNamespace(host="203.0.113.10"),
            headers={"x-forwarded-proto": "https"},
        )
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                self.assertFalse(api.main._request_is_secure(request))

    def test_client_ip_uses_forwarded_for_from_trusted_proxy(self) -> None:
        settings = make_settings(trusted_proxies=["10.0.0.10"])
        request = SimpleNamespace(
            client=SimpleNamespace(host="10.0.0.10"),
            headers={"x-forwarded-for": "198.51.100.24, 10.0.0.10"},
        )
        with mock.patch.object(security, "security_settings", settings):
            self.assertEqual(security._client_ip(request), "198.51.100.24")

    def test_startup_security_validation_rejects_credentialed_cors_without_csrf(self) -> None:
        settings = make_settings(auth_required=True, policy_profile="corp", require_tls=True, api_key_sha256="a" * 64)
        with mock.patch.dict(os.environ, {"SHADOWLAB_CORS_ALLOW_CREDENTIALS": "true"}, clear=False):
            with mock.patch.object(api.main, "security_settings", settings):
                with mock.patch.object(security, "security_settings", settings):
                    with self.assertRaises(RuntimeError):
                        api.main._validate_startup_security_posture()

    def test_startup_security_validation_rejects_noauth_admin_override_outside_lab(self) -> None:
        settings = make_settings(
            auth_required=False,
            policy_profile="corp",
            noauth_default_role="admin",
        )
        with mock.patch.dict(os.environ, {"SHADOWLAB_HOST": "127.0.0.1"}, clear=False):
            with mock.patch.object(api.main, "security_settings", settings):
                with mock.patch.object(security, "security_settings", settings):
                    with self.assertRaises(RuntimeError):
                        api.main._validate_startup_security_posture()

    def test_startup_security_validation_allows_noauth_admin_override_in_lab_on_loopback(self) -> None:
        settings = make_settings(
            auth_required=False,
            policy_profile="lab",
            noauth_default_role="admin",
        )
        with mock.patch.dict(os.environ, {"SHADOWLAB_HOST": "127.0.0.1"}, clear=False):
            with mock.patch.object(api.main, "security_settings", settings):
                with mock.patch.object(security, "security_settings", settings):
                    api.main._validate_startup_security_posture()

    def test_html_artifact_download_is_forced_as_attachment(self) -> None:
        artifact_path = Path(api.main.OUT_DIR) / "SecurityOps_Report.html"
        artifact_path.write_text("<html><body>report</body></html>", encoding="utf-8")
        try:
            settings = make_settings(auth_required=False, policy_profile="lab", noauth_default_role="admin")
            with mock.patch.object(api.main, "security_settings", settings):
                with mock.patch.object(security, "security_settings", settings):
                    response = self.client.get("/artifacts/SecurityOps_Report.html")
            self.assertEqual(response.status_code, 200)
            self.assertIn("attachment;", response.headers.get("content-disposition", "").lower())
            self.assertEqual(response.headers.get("x-download-options"), "noopen")
        finally:
            artifact_path.unlink(missing_ok=True)

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
                self.assertTrue(request.state.pending_approval_reserved)
                api.main._consume_pending_approval(request, 200)
                with self.assertRaises(HTTPException):
                    api.main._require_enterprise_approval(request, "process:kill")

    def test_general_request_body_limit_blocks_oversized_payloads(self) -> None:
        class FakeRequest:
            def __init__(self, body: bytes) -> None:
                self.method = "POST"
                self.url = SimpleNamespace(path="/enterprise/connectors/dispatch", scheme="http")
                self.headers = {"content-length": str(len(body))}
                self.client = SimpleNamespace(host="127.0.0.1")
                self._body = body

            async def body(self) -> bytes:
                return self._body

        async def _call() -> None:
            request = FakeRequest(b"A" * (api.main.DEFAULT_MAX_REQUEST_BODY_BYTES + 1))
            with mock.patch.object(api.main, "security_settings", make_settings(auth_required=False, policy_profile="lab")):
                with mock.patch.object(security, "security_settings", make_settings(auth_required=False, policy_profile="lab")):
                    with self.assertRaises(HTTPException) as exc:
                        await api.main.add_security_headers(request, mock.AsyncMock())
            self.assertEqual(exc.exception.status_code, 413)

        asyncio.run(_call())

    def test_import_request_body_limit_allows_larger_import_payload_window(self) -> None:
        request = SimpleNamespace(url=SimpleNamespace(path="/integrations/mitre/import/file"))
        self.assertEqual(api.main._request_body_limit_bytes(request), api.main.IMPORT_MAX_REQUEST_BODY_BYTES)

    def test_failed_mutation_releases_reserved_approval(self) -> None:
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
                api.main._consume_pending_approval(request, 500)
                api.main._require_enterprise_approval(request, "process:kill")

    def test_connector_dispatch_requires_approval_in_corp_profile(self) -> None:
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post(
                    "/enterprise/connectors/dispatch",
                    headers={"X-ShadowLab-Workspace": "tenant-a"},
                    json={"event_type": "unit_test", "payload": {}, "source": "test", "severity": "info"},
                )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Approval", response.text)

    def test_approval_resolution_rejects_actor_spoofing(self) -> None:
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                with mock.patch.object(api.main.enterprise_service, "resolve_approval", return_value={"ok": True}):
                    response = self.client.patch(
                        "/enterprise/approvals/123",
                        headers={"X-ShadowLab-Workspace": "tenant-a", "X-ShadowLab-Actor": "alice@corp"},
                        json={"status": "approved", "approver": "bob@corp"},
                    )
        self.assertEqual(response.status_code, 403)
        self.assertIn("approver must match", response.text)

    def test_whids_scheduler_start_requires_approval_in_corp_profile(self) -> None:
        settings = make_settings(auth_required=False, policy_profile="corp", noauth_default_role="admin")
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                response = self.client.post(
                    "/integrations/whids/scheduler/start",
                    headers={"X-ShadowLab-Workspace": "tenant-a"},
                    json={"manager_url": "https://whids.local:1520", "api_key": "secret-key", "endpoint_uuid": "", "poll_interval": 300, "verify_tls": True},
                )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Approval", response.text)

    def test_alert_configuration_persists_encrypted_webhook(self) -> None:
        db = __import__("database")
        db.init_db()
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, noauth_default_role="admin")
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
        self.assertTrue(stored.startswith("enc:v"))

    def test_triage_respond_executes_policy_plan(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True, policy_profile="lab", noauth_default_role="admin")
        profile = {"pid": 321, "name": "evil.exe", "exe": "C:\\Temp\\evil.exe"}
        intel = {
            "yaraify": {"status": "ok", "matches": []},
            "local_yara": {"matched_rules": ["Inceptor_AMSI_WLDP_ETW_Bypass"], "confidence": "high"},
            "virustotal": {"positives": 12},
            "malwarebazaar": {"query_status": "ok"},
        }
        memory_result = {"memory_yara": {"matched_rules": ["Inceptor_Process_Injection_Syscall_Chain"]}}
        fusion = {"verdict": "malicious", "severity": "critical", "confidence": "high", "score": 96}
        response_plan = {"auto": [{"action": "suspend"}], "manual": [{"action": "analyst-review"}]}
        applied = {"executed": [{"action": "suspend", "status": "success"}], "skipped": [{"action": "analyst-review", "reason": "manual"}]}
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                with mock.patch.object(api.main.process_intel_service, "profile_process", return_value=profile):
                    with mock.patch.object(api.main, "scan_process", return_value=intel):
                        with mock.patch("plugins.memory_forensics.run_analysis", return_value=memory_result):
                            with mock.patch.object(api.main, "fuse_detection_verdict", return_value=fusion):
                                with mock.patch.object(api.main.response_service, "build_triage_response_plan", return_value=response_plan):
                                    with mock.patch.object(api.main.response_service, "apply_triage_response_plan", return_value=applied):
                                        response = self.client.post("/triage/321/respond", json={"process_name": "evil.exe"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["pid"], 321)
        self.assertEqual(payload["process_name"], "evil.exe")
        self.assertEqual(payload["fusion"]["verdict"], "malicious")
        self.assertEqual(payload["response_plan"]["auto"][0]["action"], "suspend")
        self.assertEqual(payload["applied"]["executed"][0]["action"], "suspend")


if __name__ == "__main__":
    unittest.main()
