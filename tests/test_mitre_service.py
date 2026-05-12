from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import api.main
import api.security as security
import database as db
from services.mitre_service import MitreAttackService


def _bundle_fixture() -> dict:
    return {
        "type": "bundle",
        "id": "bundle--unit-test",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--execution",
                "name": "Execution",
                "x_mitre_shortname": "execution",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command interpreters.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_domains": ["enterprise-attack"],
                "x_mitre_detection": "Monitor command interpreter launches.",
                "x_mitre_data_sources": ["Process monitoring"],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--m1038",
                "name": "Execution Prevention",
            },
            {
                "type": "malware",
                "id": "malware--unit",
                "name": "UnitMalware",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--unit",
                "name": "Unit Group",
            },
            {
                "type": "relationship",
                "id": "relationship--mitigates",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1038",
                "target_ref": "attack-pattern--t1059",
            },
            {
                "type": "relationship",
                "id": "relationship--software-uses",
                "relationship_type": "uses",
                "source_ref": "malware--unit",
                "target_ref": "attack-pattern--t1059",
            },
            {
                "type": "relationship",
                "id": "relationship--group-uses",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--unit",
                "target_ref": "attack-pattern--t1059",
            },
        ],
    }


def make_settings() -> security.SecuritySettings:
    return security.SecuritySettings(
        api_key="",
        api_key_sha256="",
        api_key_role="viewer",
        api_keys={},
        api_keys_sha256={},
        auth_required=False,
        require_tls=False,
        enable_dangerous_actions=True,
        enable_network_warfare=False,
        allow_destructive_file_delete=False,
        allowed_origins=["http://127.0.0.1", "http://localhost"],
        protected_process_names=["lsass.exe", "wininit.exe"],
        trusted_proxies=[],
        policy_profile="lab",
        noauth_default_role="admin",
        oidc_enabled=False,
        signed_request_window_seconds=60,
    )


class MitreAttackServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._secret_env = mock.patch.dict(
            os.environ,
            {"SHADOWLAB_SECRET_KEY": "0123456789abcdef0123456789abcdef"},
            clear=False,
        )
        self._secret_env.start()
        db.init_db()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.bundle_path = self.base_dir / "enterprise-attack.json"
        self.bundle_path.write_text(json.dumps(_bundle_fixture()), encoding="utf-8")
        self.service = MitreAttackService(self.base_dir, db)
        self.service.load_bundle(str(self.bundle_path), source="unit-test")
        self.incident_id = f"INC-MITRE-{int(time.time() * 1000)}"
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.upsert_incident(
                conn,
                self.incident_id,
                time.time(),
                "high",
                "Suspicious PowerShell download",
                "Process launched command interpreter after download.",
                attack_chain=json.dumps(["execution"]),
                mitre_mapping=json.dumps(["T1059"]),
            )
            self.case_id = db.create_case_record(
                conn,
                title="MITRE unit test case",
                incident_id=self.incident_id,
                priority="high",
                owner="unit-test",
            )
        finally:
            conn.close()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()
        self._secret_env.stop()

    def test_service_enriches_incident_and_exports_navigator_layer(self) -> None:
        status = self.service.status()
        self.assertTrue(status["loaded"])
        self.assertEqual(status["technique_count"], 1)
        self.assertTrue(status["discovered_bundles"])

        coverage = self.service.incident_coverage(self.incident_id)
        self.assertEqual(coverage["mapped_techniques"], ["T1059"])
        self.assertEqual(coverage["known_techniques"][0]["attack_id"], "T1059")
        self.assertTrue(coverage["known_techniques"][0]["mitigations"])
        self.assertIn("command_execution", coverage["telemetry_cues"])

        case_coverage = self.service.case_coverage(self.case_id)
        self.assertEqual(case_coverage["incident_ids"], [self.incident_id])
        self.assertEqual(case_coverage["coverage_summary"]["technique_count"], 1)
        self.assertIn("tactic_heat", case_coverage["coverage_summary"])

        export = self.service.export_navigator_layer(case_id=self.case_id, layer_name="Unit Layer")
        self.assertTrue(Path(export["saved_path"]).exists())
        self.assertEqual(export["technique_count"], 1)
        self.assertEqual(export["layer"]["techniques"][0]["techniqueID"], "T1059")

        workbench = self.service.workbench_export(case_id=self.case_id)
        self.assertTrue(Path(workbench["saved_path"]).exists())
        self.assertEqual(workbench["technique_count"], 1)

    def test_service_rejects_paths_outside_approved_locations(self) -> None:
        outside = Path(tempfile.gettempdir()) / "outside-mitre.json"
        outside.write_text(json.dumps(_bundle_fixture()), encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                self.service.compare_bundle(str(outside))
        finally:
            if outside.exists():
                outside.unlink()


class MitreApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._secret_env = mock.patch.dict(
            os.environ,
            {"SHADOWLAB_SECRET_KEY": "0123456789abcdef0123456789abcdef"},
            clear=False,
        )
        self._secret_env.start()
        db.init_db()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.bundle_path = self.base_dir / "enterprise-attack.json"
        self.bundle_path.write_text(json.dumps(_bundle_fixture()), encoding="utf-8")
        api_bundle_dir = api.main.MITRE_IMPORT_ROOT
        api_bundle_dir.mkdir(parents=True, exist_ok=True)
        self.api_bundle_path = api_bundle_dir / f"enterprise-attack-api-{int(time.time() * 1000)}.json"
        self.api_bundle_path.write_text(json.dumps(_bundle_fixture()), encoding="utf-8")
        self.mitre_service = MitreAttackService(api.main.BASE_DIR, db)
        self.mitre_service.load_bundle(str(self.api_bundle_path), source="api-test")
        self.incident_id = f"INC-MITRE-API-{int(time.time() * 1000)}"
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.upsert_incident(
                conn,
                self.incident_id,
                time.time(),
                "critical",
                "Encoded script execution",
                "Observed script interpreter execution.",
                attack_chain=json.dumps(["execution"]),
                mitre_mapping=json.dumps(["T1059"]),
            )
            self.case_id = db.create_case_record(
                conn,
                title="MITRE API case",
                incident_id=self.incident_id,
                priority="critical",
                owner="unit-test",
            )
        finally:
            conn.close()
        self.client = TestClient(api.main.app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()
        self.api_bundle_path.unlink(missing_ok=True)
        self._secret_env.stop()

    def test_api_exposes_mitre_summary_and_case_export(self) -> None:
        with mock.patch.object(security, "security_settings", make_settings()):
            with mock.patch.object(api.main, "security_settings", make_settings()):
                with mock.patch.object(api.main, "mitre_service", self.mitre_service):
                    status = self.client.get("/enterprise/mitre/status")
                    self.assertEqual(status.status_code, 200)
                    self.assertTrue(status.json()["loaded"])

                    summary = self.client.get("/enterprise/mitre/summary")
                    self.assertEqual(summary.status_code, 200)
                    self.assertGreaterEqual(summary.json()["technique_count"], 1)
                    self.assertIn("dataset_lifecycle", summary.json())

                    discover = self.client.get("/enterprise/mitre/discover")
                    self.assertEqual(discover.status_code, 200)
                    self.assertTrue(discover.json())

                    compare = self.client.post("/enterprise/mitre/compare", json={"file_path": str(self.api_bundle_path)})
                    self.assertEqual(compare.status_code, 200)
                    self.assertIn("candidate_counts", compare.json())

                    case_coverage = self.client.get(f"/enterprise/cases/{self.case_id}/mitre")
                    self.assertEqual(case_coverage.status_code, 200)
                    self.assertEqual(case_coverage.json()["coverage_summary"]["technique_count"], 1)

                    export = self.client.post(
                        "/enterprise/mitre/navigator/export",
                        json={"case_id": self.case_id, "layer_name": "API Export Layer"},
                    )
                    self.assertEqual(export.status_code, 200)
                    payload = export.json()
                    self.assertTrue(Path(payload["saved_path"]).exists())
                    self.assertEqual(payload["technique_count"], 1)

                    workbench = self.client.post(
                        "/enterprise/mitre/workbench/export",
                        json={"case_id": self.case_id},
                    )
                    self.assertEqual(workbench.status_code, 200)
                    self.assertTrue(Path(workbench.json()["saved_path"]).exists())
