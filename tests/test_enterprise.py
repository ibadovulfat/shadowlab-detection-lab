from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from unittest import mock

import database as db
from services.connector_delivery_service import ConnectorDeliveryService
from services.enterprise_service import EnterpriseService
from services.graph_service import GraphService
from services.investigation_service import InvestigationService
from services.timeline_service import TimelineService


class DummyProcessService:
    def snapshot_processes(self, include_deep_fields: bool = False):
        return [
            {"pid": 10, "name": "lsass.exe", "memory_percent": 2.0, "cpu_percent": 0.1, "signature_status": "Valid"},
            {"pid": 20, "name": "python.exe", "memory_percent": 8.0, "cpu_percent": 12.0, "signature_status": "unknown"},
        ]


class EnterpriseServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._secret_env = mock.patch.dict(os.environ, {"SHADOWLAB_SECRET_KEY": "unit-test-secret-key"}, clear=False)
        self._secret_env.start()
        db.init_db()
        self.service = EnterpriseService(Path("."), DummyProcessService(), mock.Mock())

    def tearDown(self) -> None:
        self._secret_env.stop()

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

    def test_investigation_service_filters_workspace_and_persists_views(self) -> None:
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.insert_telemetry(
                conn,
                [
                    {
                        "ts": time.time(),
                        "cpu": 96.0,
                        "mem_percent": 40.0,
                        "proc_threads": 14,
                        "proc_handles": 20,
                        "open_files": 2,
                        "tcp_conns": 18,
                        "bytes_sent_rate": 90000.0,
                        "bytes_recv_rate": 1000.0,
                        "remote_ips": "8.8.8.8",
                    }
                ],
            )
            db.upsert_incident(
                conn,
                "INC-UNIT-001",
                time.time(),
                "high",
                "Suspicious powershell behavior",
                "Unit test incident",
            )
            db.log_response_action(conn, "kill", 404, "powershell.exe", "killed during unit test")
        finally:
            conn.close()

        service = InvestigationService(TimelineService())
        workspace = service.workspace(query_text="powershell", severities=["high"], limit=20)
        self.assertTrue(workspace["items"])
        self.assertIn("incident", workspace["summary"]["by_type"])

        saved = service.create_saved_view(
            name="PowerShell Hunt",
            description="Track suspicious PowerShell activity",
            query_text="powershell",
            event_types=["incident", "response"],
            severities=["high"],
            created_by="unit-test",
        )
        self.assertEqual(saved["name"], "PowerShell Hunt")
        note = service.create_note(
            note_text="PowerShell activity aligns with suspicious operator behavior.",
            item_type="incident",
            item_title="Suspicious powershell behavior",
            tags=["powershell", "triage"],
            author="unit-test",
        )
        self.assertEqual(note["author"], "unit-test")
        story = service.create_story(
            title="PowerShell misuse hypothesis",
            hypothesis="A scripted execution chain launched PowerShell for defense evasion.",
            summary="Correlate parent process, outbound traffic, and response actions.",
            confidence="high",
            tags=["powershell"],
            created_by="unit-test",
        )
        self.assertEqual(story["confidence"], "high")
        pin = service.create_pin(
            item_time=time.time(),
            item_type="incident",
            item_title="Suspicious powershell behavior",
            item_severity="high",
            item_payload={"source": "unit-test"},
            rationale="Anchor this event for the board.",
            pinned_by="unit-test",
        )
        self.assertEqual(pin["item_type"], "incident")

        refreshed_workspace = service.workspace(query_text="powershell", severities=["high"], limit=20)
        self.assertGreaterEqual(refreshed_workspace["summary"]["note_count"], 1)
        self.assertGreaterEqual(refreshed_workspace["summary"]["story_count"], 1)
        self.assertGreaterEqual(refreshed_workspace["summary"]["pin_count"], 1)
        self.assertIn("case_board", refreshed_workspace)
        listed = service.list_saved_views()
        self.assertTrue(any(item["name"] == "PowerShell Hunt" for item in listed))
        self.assertTrue(any(item["title"] == "PowerShell misuse hypothesis" for item in service.list_stories()))
        self.assertTrue(any(item["item_title"] == "Suspicious powershell behavior" for item in service.list_pins()))

        case = self.service.create_case(title="Unit Test Investigation Case", owner="unit-test")
        service.assign_analyst(case_id=int(case["id"]), analyst="analyst-1", role="owner", assigned_by="unit-test")
        service.create_task(
            case_id=int(case["id"]),
            title="Review parent process",
            description="Validate suspicious ancestry.",
            assigned_to="analyst-1",
            due_at=time.time() - 60,
            created_by="unit-test",
        )
        first_task = service.list_tasks(case_id=int(case["id"]))[0]
        updated_task = service.update_task(case_id=int(case["id"]), task_id=int(first_task["id"]), status="in_progress")
        self.assertEqual(updated_task["status"], "in_progress")
        case_board = service.case_board(case_id=int(case["id"]))
        self.assertIn("queue", case_board)
        self.assertGreaterEqual(case_board["queue"]["assignments"], 1)
        self.assertGreaterEqual(case_board["queue"]["open_tasks"], 1)
        self.assertGreaterEqual(case_board["queue"]["overdue_tasks"], 1)
        self.assertIn("kpis", case_board)
        self.assertIn("timeline", case_board)
        self.assertIn("entity_links", case_board)
        activity = service.list_activity(case_id=int(case["id"]))
        self.assertTrue(activity)
        self.assertTrue(any(item["event_type"] in {"analyst_assigned", "task_created", "task_updated"} for item in activity))
        export = service.export_case_report(case_id=int(case["id"]), out_dir="shadowlab_out")
        self.assertEqual(export["status"], "exported")
        self.assertTrue(str(export["pdf_path"]).endswith(".pdf"))

    def test_case_graph_scopes_to_case_context(self) -> None:
        graph_service = GraphService(Path("shadowlab_out"))
        case_record = {
            "id": 77,
            "title": "Python outbound investigation",
            "incident_id": "INC-CASE-77",
            "narrative": "Track suspicious python.exe PID 20 beaconing.",
        }
        graph = graph_service.build_case_graph(
            case_record=case_record,
            assignments=[{"analyst": "analyst-1"}],
            tasks=[{"title": "Review python.exe PID 20", "status": "todo"}],
            activity=[{"summary": "Pinned python.exe PID 20 for review"}],
            pins=[{"item_title": "python.exe outbound activity", "item_payload_json": '{"pid": 20, "process_name": "python.exe"}'}],
            notes=[{"note_text": "python.exe reached remote host", "item_title": "python.exe"}],
            stories=[{"title": "python beacon", "summary": "Correlate python.exe with INC-CASE-77"}],
            hosts=[{"host_id": "host-1", "host": "lab-host", "platform": "Windows", "ip_address": "10.0.0.10"}],
            processes=[
                {"pid": 20, "ppid": 4, "name": "python.exe", "exe": "C:\\Python\\python.exe", "cmdline": "python beacon.py", "signature_status": "unknown"},
                {"pid": 99, "ppid": 4, "name": "notepad.exe", "exe": "C:\\Windows\\notepad.exe", "cmdline": "notepad", "signature_status": "Valid"},
            ],
            connections=[
                {"pid": 20, "local_addr": "10.0.0.10:4444", "remote_addr": "8.8.8.8:443"},
                {"pid": 99, "local_addr": "10.0.0.10:5555", "remote_addr": "127.0.0.1:80"},
            ],
            incidents=[
                {"incident_id": "INC-CASE-77", "severity": "high", "title": "python beacon observed", "summary": "python.exe outbound", "attack_chain": '["execution"]', "mitre_mapping": '["T1059"]'},
                {"incident_id": "INC-OTHER", "severity": "low", "title": "benign note", "summary": "notepad"},
            ],
            persistence_items=[{"type": "autorun", "name": "python beacon", "path": "HKCU\\Run\\python"}],
        )
        self.assertEqual(graph["case_context"]["case_id"], 77)
        self.assertGreaterEqual(graph["case_context"]["focus_pid_count"], 1)
        top_processes = graph["summary"].get("top_processes", [])
        self.assertTrue(any(str(item.get("name", "")) == "python.exe" for item in top_processes))
        self.assertTrue(any("incidents matched the selected case context" in str(item).lower() for item in graph["priority_findings"]))


if __name__ == "__main__":
    unittest.main()
