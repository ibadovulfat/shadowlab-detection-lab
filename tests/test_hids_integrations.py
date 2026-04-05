from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import database as db
from services.enterprise_service import EnterpriseService
from services.hids_integration_service import HidsIntegrationService
from services.investigation_service import InvestigationService
from services.response_service import ResponseOrchestrator
from services.timeline_service import TimelineService


class HidsIntegrationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        db.init_db()
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            for table in [
                "incidents",
                "host_inventory",
                "integration_export_log",
                "case_records",
                "investigation_notes",
                "investigation_pins",
                "investigation_stories",
                "case_activity_log",
                "case_tasks",
                "case_assignments",
                "evidence_chain_log",
                "approval_requests",
            ]:
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
        finally:
            conn.close()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        enterprise_service = EnterpriseService(Path(__file__).resolve().parent.parent, mock.Mock(), mock.Mock())
        investigation_service = InvestigationService(TimelineService())
        self.service = HidsIntegrationService(
            db,
            enterprise_service=enterprise_service,
            investigation_service=investigation_service,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_import_whids_file_creates_host_and_incident(self) -> None:
        payload = {
            "Event": {
                "System": {"Computer": "LAB-WS-01", "EventID": 10},
                "EventData": {
                    "SourceImage": "C:\\Windows\\Temp\\evil.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                },
            },
            "EdrData": {
                "Endpoint": {
                    "UUID": "host-whids-1",
                    "IP": "10.10.10.15",
                    "Hostname": "LAB-WS-01",
                },
                "Event": {
                    "Hash": "abc123def4567890abc123def4567890abc123de",
                    "ReceiptTime": "2026-03-21T12:00:00Z",
                },
            },
            "Detection": {
                "Signature": ["SuspiciousLsassAccess"],
                "Criticality": 8,
                "Actions": ["report", "memdump", "kill"],
            },
        }
        source = self.temp_path / "whids-alerts.json"
        source.write_text(json.dumps([payload]), encoding="utf-8")

        result = self.service.import_whids_file(str(source))

        self.assertEqual(result["integration"], "whids")
        self.assertEqual(result["imported"], 1)
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            incident = db.get_incident_by_id(conn, result["incident_ids"][0])
            hosts = db.get_hosts(conn).fillna("").to_dict(orient="records")
            cases = db.get_case_records(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        self.assertIsNotNone(incident)
        self.assertEqual(incident["severity"], "critical")
        self.assertIn("SuspiciousLsassAccess", incident["title"])
        self.assertTrue(any(item["host_id"] == "host-whids-1" for item in hosts))
        self.assertTrue(any(item["incident_id"] == result["incident_ids"][0] for item in cases))

    def test_import_ossec_alert_log_creates_incident(self) -> None:
        source = self.temp_path / "alerts.log"
        source.write_text(
            "\n".join(
                [
                    "** Alert 171102.1: - syscheck,syscheck_entry_modified,",
                    "2026 Mar 21 10:33:01 (web-01) 10.0.0.25->syscheck",
                    "Rule: 550 (level 7) -> 'Integrity checksum changed.'",
                    "Location: /var/www/html/index.php",
                    "Src IP: 10.0.0.25",
                    "File '/var/www/html/index.php' modified.",
                ]
            ),
            encoding="utf-8",
        )

        result = self.service.import_ossec_file(str(source))

        self.assertEqual(result["integration"], "ossec")
        self.assertEqual(result["imported"], 1)
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            incident = db.get_incident_by_id(conn, result["incident_ids"][0])
            cases = db.get_case_records(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        self.assertIsNotNone(incident)
        self.assertEqual(incident["severity"], "medium")
        self.assertIn("Integrity checksum changed", incident["summary"])
        self.assertTrue(incident["incident_id"].startswith("OSSEC-"))
        self.assertTrue(any(item["incident_id"] == result["incident_ids"][0] for item in cases))

    def test_import_ossec_file_scopes_case_and_export_to_workspace(self) -> None:
        source = self.temp_path / "tenant-alerts.log"
        source.write_text(
            "\n".join(
                [
                    "** Alert 171102.1: - syscheck,syscheck_entry_modified,",
                    "2026 Mar 21 10:33:01 (tenant-web-01) 10.0.0.25->syscheck",
                    "Rule: 550 (level 7) -> 'Integrity checksum changed.'",
                    "Location: /var/www/html/index.php",
                    "Src IP: 10.0.0.25",
                    "File '/var/www/html/index.php' modified.",
                ]
            ),
            encoding="utf-8",
        )

        result = self.service.import_ossec_file(str(source), workspace_id="tenant-a")

        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            incident = db.get_incident_by_id(conn, result["incident_ids"][0], workspace_id="tenant-a")
            tenant_cases = db.get_case_records(conn, workspace_id="tenant-a").fillna("").to_dict(orient="records")
            default_cases = db.get_case_records(conn, workspace_id="default").fillna("").to_dict(orient="records")
            exports = db.get_integration_exports(conn, workspace_id="tenant-a").fillna("").to_dict(orient="records")
        finally:
            conn.close()

        self.assertIsNotNone(incident)
        self.assertEqual(incident["workspace_id"], "tenant-a")
        self.assertTrue(any(item["incident_id"] == result["incident_ids"][0] for item in tenant_cases))
        self.assertFalse(any(item["incident_id"] == result["incident_ids"][0] for item in default_cases))
        self.assertTrue(any(item["export_type"] == "import_file" and item["workspace_id"] == "tenant-a" for item in exports))

    def test_orchestrate_incident_response_respects_workspace_scope(self) -> None:
        source = self.temp_path / "scoped-alerts.log"
        source.write_text(
            "\n".join(
                [
                    "** Alert 171102.1: - syscheck,syscheck_entry_modified,",
                    "2026 Mar 21 10:33:01 (tenant-web-01) 10.0.0.25->syscheck",
                    "Rule: 550 (level 7) -> 'Integrity checksum changed.'",
                    "Location: /var/www/html/index.php",
                    "Src IP: 10.0.0.25",
                    "File '/var/www/html/index.php' modified.",
                ]
            ),
            encoding="utf-8",
        )
        result = self.service.import_ossec_file(str(source), workspace_id="tenant-a")

        planned = self.service.orchestrate_incident_response(result["incident_ids"][0], apply_actions=False, workspace_id="tenant-a")
        self.assertEqual(planned["incident_id"], result["incident_ids"][0])

        with self.assertRaises(ValueError):
            self.service.orchestrate_incident_response(result["incident_ids"][0], apply_actions=False, workspace_id="tenant-b")

    def test_import_ossec_json_syslog_shape_preserves_file_context(self) -> None:
        payload = {
            "crit": 11,
            "id": 550,
            "component": "syscheck",
            "classification": "syscheck_entry_modified",
            "description": "Integrity checksum changed.",
            "src_ip": "10.0.0.25",
            "dst_ip": "10.0.0.30",
            "file": "/var/www/html/index.php",
            "sha1_old": "old",
            "sha1_new": "new",
            "message": "File modified.",
            "hostname": "web-02",
        }
        source = self.temp_path / "ossec-alerts.json"
        source.write_text(json.dumps([payload]), encoding="utf-8")

        result = self.service.import_ossec_file(str(source))

        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            incident = db.get_incident_by_id(conn, result["incident_ids"][0])
        finally:
            conn.close()
        self.assertIsNotNone(incident)
        self.assertEqual(incident["severity"], "high")
        self.assertIn("index.php", incident["title"])
        self.assertIn("sha1_new", incident["notes"])

    def test_import_whids_manager_uses_api_key_and_endpoint_api(self) -> None:
        endpoints_response = mock.Mock()
        endpoints_response.json.return_value = {
            "data": [{"uuid": "endpoint-1", "hostname": "LAB-WS-02", "ip": "10.1.1.5", "criticality": 7, "score": 42}]
        }
        endpoints_response.raise_for_status.return_value = None
        detections_response = mock.Mock()
        detections_response.json.return_value = {
            "data": [
                {
                    "Event": {
                        "System": {"Computer": "LAB-WS-02", "EventID": 10},
                        "EventData": {
                            "SourceImage": "C:\\Temp\\credential_tool.exe",
                            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                            "SourceUser": "NT AUTHORITY\\SYSTEM",
                        },
                    },
                    "EdrData": {"Event": {"Hash": "abcdef1234567890abcdef1234567890abcdef12", "ReceiptTime": "2026-03-21T14:00:00Z"}},
                    "Detection": {"Signature": ["SuspiciousLsassAccess"], "Criticality": 8, "Actions": ["report", "memdump"]},
                }
            ]
        }
        detections_response.raise_for_status.return_value = None

        session = mock.Mock()
        session.get.side_effect = [endpoints_response, detections_response]

        with mock.patch("services.hids_integration_service.requests.Session", return_value=session):
            result = self.service.import_whids_manager("https://localhost:1520", "secret-key", limit=50)

        self.assertEqual(result["integration"], "whids")
        self.assertEqual(result["imported"], 1)
        self.assertEqual(result["fetched_endpoints"], 1)
        first_call = session.get.call_args_list[0]
        self.assertIn("endpoints", first_call.args[0])
        self.assertEqual(session.headers.update.call_args.args[0]["X-Api-Key"], "secret-key")

    def test_import_whids_manager_rejects_unsafe_destination(self) -> None:
        with self.assertRaises(ValueError):
            self.service.import_whids_manager("http://169.254.169.254/latest", "secret-key", limit=50)

    def test_import_whids_manager_rejects_tls_bypass_for_remote_host(self) -> None:
        with self.assertRaises(ValueError):
            self.service.import_whids_manager("https://whids.example", "secret-key", limit=50, verify_tls=False)

    def test_sync_whids_reports_writes_report_file(self) -> None:
        reports_response = mock.Mock()
        reports_response.json.return_value = {
            "data": {
                "endpoint-1": {
                    "identifier": "endpoint-1",
                    "alert-count": 5,
                    "score": 77,
                    "signatures": ["SuspiciousService", "NewAutorun"],
                }
            }
        }
        reports_response.raise_for_status.return_value = None
        session = mock.Mock()
        session.get.return_value = reports_response

        with mock.patch("services.hids_integration_service.requests.Session", return_value=session):
            result = self.service.sync_whids_reports("https://localhost:1520", "secret-key")

        self.assertEqual(result["integration"], "whids")
        self.assertEqual(result["report_count"], 1)
        saved_path = Path(result["saved_path"])
        self.assertTrue(saved_path.exists())
        saved_payload = json.loads(saved_path.read_text(encoding="utf-8"))
        self.assertIn("endpoint-1", saved_payload)

    def test_download_whids_artifacts_saves_files_and_manifest(self) -> None:
        artifacts_response = mock.Mock()
        artifacts_response.json.return_value = {
            "data": [
                {
                    "process-guid": "proc-123",
                    "event-hash": "hash-456",
                    "files": [{"name": "trace.json", "size": 12}],
                }
            ]
        }
        artifacts_response.raise_for_status.return_value = None
        file_response = mock.Mock()
        file_response.content = b'{"ok":true}'
        file_response.raise_for_status.return_value = None
        session = mock.Mock()
        session.get.side_effect = [artifacts_response, file_response]

        with mock.patch("services.hids_integration_service.requests.Session", return_value=session):
            result = self.service.download_whids_artifacts(
                "https://localhost:1520",
                "secret-key",
                endpoint_uuid="endpoint-1",
                max_files=5,
            )

        self.assertEqual(result["integration"], "whids")
        self.assertEqual(result["downloaded_count"], 1)
        self.assertTrue(Path(result["manifest_path"]).exists())
        self.assertTrue(Path(result["downloaded_files"][0]["saved_path"]).exists())

    def test_orchestrate_incident_response_builds_plan_for_ossec(self) -> None:
        source = self.temp_path / "suspicious.ps1"
        source.write_text("Write-Host suspicious", encoding="utf-8")
        payload = {
            "crit": 11,
            "id": 550,
            "component": "syscheck",
            "description": "Integrity checksum changed.",
            "src_ip": "10.0.0.25",
            "file": str(source),
            "message": "File modified.",
            "hostname": "web-02",
        }
        alerts = self.temp_path / "ossec-alerts.json"
        alerts.write_text(json.dumps([payload]), encoding="utf-8")
        import_result = self.service.import_ossec_file(str(alerts))

        result = self.service.orchestrate_incident_response(import_result["incident_ids"][0], apply_actions=False)

        self.assertEqual(result["provider"], "ossec")
        actions = {item["action"] for item in result["executed"]}
        self.assertIn("quarantine_file", actions)
        manual_actions = {item["action"] for item in result["manual_required"]}
        self.assertIn("ossec_firewall_drop", manual_actions)

    def test_whids_ioc_and_rule_lifecycle_calls_manager_endpoints(self) -> None:
        get_iocs_response = mock.Mock()
        get_iocs_response.json.return_value = {"data": [{"uuid": "ioc-1", "value": "bad.example", "type": "domain"}]}
        get_iocs_response.raise_for_status.return_value = None
        add_iocs_response = mock.Mock()
        add_iocs_response.json.return_value = {"data": [{"uuid": "ioc-1", "value": "bad.example", "type": "domain"}]}
        add_iocs_response.raise_for_status.return_value = None
        get_rules_response = mock.Mock()
        get_rules_response.json.return_value = {"data": [{"Name": "ShadowLabRule", "Actions": ["kill"]}]}
        get_rules_response.raise_for_status.return_value = None
        add_rules_response = mock.Mock()
        add_rules_response.json.return_value = {"data": [{"Name": "ShadowLabRule", "Actions": ["kill"]}]}
        add_rules_response.raise_for_status.return_value = None
        delete_response = mock.Mock()
        delete_response.raise_for_status.return_value = None

        session = mock.Mock()
        session.get.side_effect = [get_iocs_response, get_rules_response]
        session.post.side_effect = [add_iocs_response, add_rules_response]
        session.delete.side_effect = [delete_response, delete_response]

        with mock.patch("services.hids_integration_service.requests.Session", return_value=session):
            iocs = self.service.list_whids_iocs("https://localhost:1520", "secret-key")
            added_iocs = self.service.add_whids_iocs("https://localhost:1520", "secret-key", [{"value": "bad.example", "type": "domain"}])
            rules = self.service.list_whids_rules("https://localhost:1520", "secret-key")
            added_rules = self.service.add_whids_rules("https://localhost:1520", "secret-key", [{"Name": "ShadowLabRule"}])
            deleted_iocs = self.service.delete_whids_iocs("https://localhost:1520", "secret-key", filters={"value": "bad.example"})
            deleted_rules = self.service.delete_whids_rules("https://localhost:1520", "secret-key", rule_name="ShadowLabRule")

        self.assertEqual(len(iocs["items"]), 1)
        self.assertEqual(len(added_iocs["items"]), 1)
        self.assertEqual(len(rules["items"]), 1)
        self.assertEqual(len(added_rules["items"]), 1)
        self.assertTrue(deleted_iocs["ok"])
        self.assertTrue(deleted_rules["ok"])

    def test_whids_config_and_report_archive_queries_work(self) -> None:
        config_response = mock.Mock()
        config_response.json.return_value = {"data": {"endpoint": True, "rules": {"rules-db": "db"}}}
        config_response.raise_for_status.return_value = None
        archive_response = mock.Mock()
        archive_response.json.return_value = {"data": [{"identifier": "endpoint-1", "archived-time": "2026-03-21T12:00:00Z"}]}
        archive_response.raise_for_status.return_value = None
        session = mock.Mock()
        session.get.side_effect = [config_response, archive_response]

        with mock.patch("services.hids_integration_service.requests.Session", return_value=session):
            config = self.service.get_whids_endpoint_config("https://localhost:1520", "secret-key", endpoint_uuid="endpoint-1")
            archive = self.service.get_whids_report_archive("https://localhost:1520", "secret-key", endpoint_uuid="endpoint-1")

        self.assertTrue(config["config"]["endpoint"])
        self.assertEqual(len(archive["items"]), 1)

    def test_response_policy_auto_applies_collect_artifact(self) -> None:
        source = self.temp_path / "artifact.bin"
        source.write_text("malicious artifact", encoding="utf-8")
        service = HidsIntegrationService(
            db,
            enterprise_service=EnterpriseService(Path(__file__).resolve().parent.parent, mock.Mock(), mock.Mock()),
            investigation_service=InvestigationService(TimelineService()),
            response_service=mock.Mock(),
        )
        service.update_response_policy(
            {
                "providers": {
                    "ossec": {
                        "enabled": True,
                        "severity_actions": {
                            "high": {"auto_apply": True, "actions": ["collect_artifact"]}
                        },
                    }
                }
            }
        )
        payload = {
            "crit": 11,
            "id": 550,
            "component": "syscheck",
            "description": "Integrity checksum changed.",
            "file": str(source),
            "hostname": "web-02",
        }
        alerts = self.temp_path / "auto-ossec.json"
        alerts.write_text(json.dumps([payload]), encoding="utf-8")

        result = service.import_ossec_file(str(alerts))

        collected_dir = Path(__file__).resolve().parent.parent / "shadowlab_out" / "orchestrations" / result["incident_ids"][0]
        self.assertTrue(collected_dir.exists())

    def test_ossec_native_active_response_uses_official_script(self) -> None:
        orchestrator = ResponseOrchestrator()
        completed = mock.Mock(returncode=0, stdout="Adding", stderr="")
        with mock.patch("services.response_service.subprocess.run", return_value=completed) as run_mock:
            result = orchestrator.execute_ossec_active_response("firewall-drop", "1.2.3.4")

        self.assertTrue(result["ok"])
        self.assertIn("firewall-drop.cmd", " ".join(str(item) for item in result["command"]))
        self.assertTrue(run_mock.called)
        self.assertEqual(run_mock.call_args.kwargs.get("shell", False), False)

    def test_ossec_native_active_response_rejects_invalid_subject(self) -> None:
        orchestrator = ResponseOrchestrator()

        with self.assertRaises(ValueError):
            orchestrator.execute_ossec_active_response("firewall-drop", "1.2.3.4 & whoami")

    def test_whids_runtime_state_encrypts_scheduler_api_key(self) -> None:
        with mock.patch.dict("os.environ", {"SHADOWLAB_RESTORE_INTEGRATION_RUNTIME": "false"}):
            service = HidsIntegrationService(
                db,
                enterprise_service=EnterpriseService(Path(__file__).resolve().parent.parent, mock.Mock(), mock.Mock()),
                investigation_service=InvestigationService(TimelineService()),
                response_service=mock.Mock(),
            )
        with mock.patch("services.hids_integration_service.threading.Thread") as thread_cls:
            thread_instance = mock.Mock()
            thread_cls.return_value = thread_instance
            service.start_whids_scheduler("https://localhost:1520", "super-secret-key", endpoint_uuid="endpoint-1")

        runtime_payload = json.loads(service.runtime_path.read_text(encoding="utf-8"))
        saved_key = runtime_payload["whids_scheduler"]["api_key"]
        self.assertNotEqual(saved_key, "super-secret-key")
        self.assertTrue(str(saved_key).startswith("enc:v"))

    def test_whids_runtime_state_persists_scheduler_workspace(self) -> None:
        with mock.patch.dict("os.environ", {"SHADOWLAB_RESTORE_INTEGRATION_RUNTIME": "false"}):
            service = HidsIntegrationService(
                db,
                enterprise_service=EnterpriseService(Path(__file__).resolve().parent.parent, mock.Mock(), mock.Mock()),
                investigation_service=InvestigationService(TimelineService()),
                response_service=mock.Mock(),
            )
        with mock.patch("services.hids_integration_service.threading.Thread") as thread_cls:
            thread_instance = mock.Mock()
            thread_cls.return_value = thread_instance
            state = service.start_whids_scheduler(
                "https://localhost:1520",
                "super-secret-key",
                endpoint_uuid="endpoint-1",
                workspace_id="tenant-a",
            )

        runtime_payload = json.loads(service.runtime_path.read_text(encoding="utf-8"))
        self.assertEqual(state["workspace_id"], "tenant-a")
        self.assertEqual(runtime_payload["whids_scheduler"]["workspace_id"], "tenant-a")

    def test_quarantine_file_keeps_existing_artifact(self) -> None:
        orchestrator = ResponseOrchestrator()
        sample = self.temp_path / "sample.bin"
        sample.write_text("artifact", encoding="utf-8")
        quarantine_dir = Path("shadowlab_quarantine")
        quarantine_dir.mkdir(exist_ok=True)
        existing = quarantine_dir / sample.name
        existing.write_text("older", encoding="utf-8")
        created_path: Path | None = None
        try:
            result = orchestrator.quarantine_file(1234, "sample.bin", str(sample))

            self.assertTrue(result["ok"])
            created_path = Path(result["path"])
            self.assertNotEqual(created_path, existing)
            self.assertEqual(existing.read_text(encoding="utf-8"), "older")
        finally:
            if created_path and created_path.exists():
                created_path.unlink()
            if existing.exists():
                existing.unlink()

    def test_ossec_live_ingest_imports_new_alerts(self) -> None:
        source = self.temp_path / "live-alerts.log"
        source.write_text("", encoding="utf-8")

        self.service.start_ossec_live_ingest(str(source), poll_interval=0.5, limit=50, start_at_end=True)
        source.write_text(
            "\n".join(
                [
                    "** Alert 171102.1: - syscheck,syscheck_entry_modified,",
                    "2026 Mar 21 10:33:01 (web-live-01) 10.0.0.25->syscheck",
                    "Rule: 550 (level 7) -> 'Integrity checksum changed.'",
                    "Location: /var/www/html/index.php",
                    "Src IP: 10.0.0.25",
                    "File '/var/www/html/index.php' modified.",
                ]
            ),
            encoding="utf-8",
        )
        time.sleep(1.2)
        status = self.service.stop_ossec_live_ingest()

        self.assertGreaterEqual(int(status["total_imported"]), 1)
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            incidents = db.get_incidents(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        self.assertTrue(any(str(item.get("incident_id", "")).startswith("OSSEC-") for item in incidents))

    def test_ossec_live_ingest_scopes_to_workspace(self) -> None:
        source = self.temp_path / "tenant-live-alerts.log"
        source.write_text("", encoding="utf-8")

        self.service.start_ossec_live_ingest(str(source), poll_interval=0.5, limit=50, start_at_end=True, workspace_id="tenant-a")
        source.write_text(
            "\n".join(
                [
                    "** Alert 171102.1: - syscheck,syscheck_entry_modified,",
                    "2026 Mar 21 10:33:01 (web-live-tenant) 10.0.0.25->syscheck",
                    "Rule: 550 (level 7) -> 'Integrity checksum changed.'",
                    "Location: /var/www/html/index.php",
                    "Src IP: 10.0.0.25",
                    "File '/var/www/html/index.php' modified.",
                ]
            ),
            encoding="utf-8",
        )
        time.sleep(1.2)
        status = self.service.stop_ossec_live_ingest()

        self.assertEqual(status["workspace_id"], "tenant-a")
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            tenant_incidents = db.get_incidents(conn, workspace_id="tenant-a").fillna("").to_dict(orient="records")
            default_incidents = db.get_incidents(conn, workspace_id="default").fillna("").to_dict(orient="records")
        finally:
            conn.close()
        self.assertTrue(any(str(item.get("incident_id", "")).startswith("OSSEC-") for item in tenant_incidents))
        self.assertFalse(any(str(item.get("incident_id", "")).startswith("OSSEC-") for item in default_incidents))


if __name__ == "__main__":
    unittest.main()
