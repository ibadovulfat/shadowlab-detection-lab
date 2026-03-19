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

    def test_investigation_workspace_and_saved_views_endpoints(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                create_view = self.client.post(
                    "/enterprise/investigations/views",
                    json={
                        "name": "High Severity Review",
                        "description": "Filter down to high severity items",
                        "query_text": "incident",
                        "event_types": ["incident"],
                        "severities": ["high"],
                        "created_by": "tester",
                    },
                )
                create_note = self.client.post(
                    "/enterprise/investigations/notes",
                    json={
                        "note_text": "Analyst flagged this as requiring deeper review.",
                        "item_type": "incident",
                        "item_title": "High severity case",
                        "tags": ["review"],
                        "author": "tester",
                    },
                )
                create_story = self.client.post(
                    "/enterprise/investigations/stories",
                    json={
                        "title": "Initial triage hypothesis",
                        "hypothesis": "A high severity event may relate to suspicious process ancestry.",
                        "summary": "Need process tree and network review.",
                        "confidence": "medium",
                        "tags": ["triage"],
                        "created_by": "tester",
                    },
                )
                create_pin = self.client.post(
                    "/enterprise/investigations/pins",
                    json={
                        "item_time": 1234567890,
                        "item_type": "incident",
                        "item_title": "High severity case",
                        "item_severity": "high",
                        "item_payload": {"source": "e2e"},
                        "rationale": "Board anchor",
                        "pinned_by": "tester",
                    },
                )
                create_case = self.client.post(
                    "/enterprise/cases",
                    json={"title": "E2E Investigation Case", "owner": "tester"},
                )
                list_views = self.client.get("/enterprise/investigations/views")
                list_notes = self.client.get("/enterprise/investigations/notes")
                list_stories = self.client.get("/enterprise/investigations/stories")
                list_pins = self.client.get("/enterprise/investigations/pins")
                workspace = self.client.get("/enterprise/investigations/workspace", params={"severities": "high", "limit": 25})
                case_id = create_case.json()["id"]
                seeded_tasks = self.client.get(f"/enterprise/cases/{case_id}/tasks")
                assignment = self.client.post(
                    f"/enterprise/cases/{case_id}/assignments",
                    json={"analyst": "tester-analyst", "role": "owner", "assigned_by": "tester"},
                )
                task = self.client.post(
                    f"/enterprise/cases/{case_id}/tasks",
                    json={"title": "Validate ancestry", "description": "Review parent-child chain", "assigned_to": "tester-analyst", "due_at": 1, "created_by": "tester"},
                )
                assignments = self.client.get(f"/enterprise/cases/{case_id}/assignments")
                tasks = self.client.get(f"/enterprise/cases/{case_id}/tasks")
                task_id = task.json()["id"]
                task_update = self.client.patch(
                    f"/enterprise/cases/{case_id}/tasks/{task_id}",
                    json={"status": "in_progress", "priority": "high"},
                )
                activity = self.client.get(f"/enterprise/cases/{case_id}/activity")
                board = self.client.get(f"/enterprise/cases/{case_id}/board")
                with mock.patch.object(
                    api.main.process_intel_service,
                    "snapshot_processes",
                    return_value=[
                        {
                            "pid": 404,
                            "ppid": 4,
                            "name": "powershell.exe",
                            "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "cmdline": "powershell -enc AAAA",
                            "signature_status": "unknown",
                        }
                    ],
                ):
                    with mock.patch.object(
                        api.main.monitor_core,
                        "get_network_connections",
                        return_value=[{"pid": 404, "local_addr": "10.0.0.10:4444", "remote_addr": "8.8.8.8:443"}],
                    ):
                        case_graph = self.client.get(f"/enterprise/cases/{case_id}/graph")
                export = self.client.post(f"/enterprise/cases/{case_id}/investigation-report/export")
        self.assertEqual(create_view.status_code, 200)
        self.assertEqual(create_note.status_code, 200)
        self.assertEqual(create_story.status_code, 200)
        self.assertEqual(create_pin.status_code, 200)
        self.assertEqual(create_case.status_code, 200)
        self.assertEqual(list_views.status_code, 200)
        self.assertEqual(list_notes.status_code, 200)
        self.assertEqual(list_stories.status_code, 200)
        self.assertEqual(list_pins.status_code, 200)
        self.assertEqual(workspace.status_code, 200)
        self.assertEqual(seeded_tasks.status_code, 200)
        self.assertEqual(assignment.status_code, 200)
        self.assertEqual(task.status_code, 200)
        self.assertEqual(assignments.status_code, 200)
        self.assertEqual(tasks.status_code, 200)
        self.assertEqual(task_update.status_code, 200)
        self.assertEqual(activity.status_code, 200)
        self.assertEqual(board.status_code, 200)
        self.assertEqual(case_graph.status_code, 200)
        self.assertEqual(export.status_code, 200)
        self.assertEqual(create_view.json()["name"], "High Severity Review")
        self.assertTrue(any(item["name"] == "High Severity Review" for item in list_views.json()))
        self.assertTrue(any(item["author"] == "tester" for item in list_notes.json()))
        self.assertTrue(any(item["title"] == "Initial triage hypothesis" for item in list_stories.json()))
        self.assertTrue(any(item["pinned_by"] == "tester" for item in list_pins.json()))
        self.assertTrue(any(item["analyst"] == "tester-analyst" for item in assignments.json()))
        self.assertGreaterEqual(len(seeded_tasks.json()), 4)
        self.assertTrue(any(item["title"] == "Validate ancestry" for item in tasks.json()))
        self.assertEqual(task_update.json()["status"], "in_progress")
        self.assertIn("summary", workspace.json())
        self.assertIn("recent_notes", workspace.json())
        self.assertIn("active_stories", workspace.json())
        self.assertIn("case_board", workspace.json())
        self.assertIn("queue", board.json())
        self.assertIn("kpis", board.json())
        self.assertIn("timeline", board.json())
        self.assertIn("entity_links", board.json())
        self.assertIn("case_context", case_graph.json())
        self.assertEqual(case_graph.json()["case_context"]["case_id"], case_id)
        self.assertGreaterEqual(board.json()["queue"]["overdue_tasks"], 1)
        self.assertTrue(any(item["event_type"] == "task_updated" for item in activity.json()))
        self.assertEqual(export.json()["status"], "exported")
        self.assertIn("pdf_path", export.json())


if __name__ == "__main__":
    unittest.main()
