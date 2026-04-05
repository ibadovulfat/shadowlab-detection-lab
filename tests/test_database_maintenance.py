from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from unittest import mock

import database as db
from services.migration_service import MigrationService


class FakePostgresCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.description = [("id",), ("value",)]
        self.lastrowid = 0

    def execute(self, sql: str, params=None):
        self.executed.append((sql, params))
        return self

    def executemany(self, sql: str, seq_of_params):
        for params in seq_of_params:
            self.executed.append((sql, params))
        return self

    def fetchone(self):
        return (7,)

    def fetchall(self):
        return [(7, "ok")]


class FakePostgresConnection:
    def __init__(self) -> None:
        self.cursor_instance = FakePostgresCursor()
        self.commits = 0

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1

    def rollback(self):
        return None

    def close(self):
        return None


class DatabaseMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        db.init_db()

    def test_retention_cleanup_purges_old_auth_rows(self) -> None:
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            conn.execute(
                """
                INSERT INTO auth_log (created_at, event_type, outcome, role, client_ip, path, detail)
                VALUES (?, 'auth_failure', 'denied', 'viewer', '127.0.0.1', '/auth/context', 'old')
                """,
                (time.time() - (10 * 86400),),
            )
            conn.commit()
            purged = db.purge_old_records(conn, {"auth_log": 1})
        finally:
            conn.close()
        self.assertGreaterEqual(purged.get("auth_log", 0), 1)

    def test_postgres_bootstrap_export_is_generated(self) -> None:
        service = MigrationService(Path("."))
        target = service.export_postgres_bootstrap_sql()
        self.assertTrue(Path(target).exists())

    def test_postgres_runtime_profile_and_query_translation(self) -> None:
        fake_raw = FakePostgresConnection()
        with mock.patch.dict(os.environ, {"SHADOWLAB_DATABASE_URL": "postgresql://shadowlab:secret@db.local/shadowlab"}, clear=False):
            with mock.patch.object(db, "_create_postgres_connection", return_value=fake_raw):
                conn = db.create_connection()
                self.assertIsNotNone(conn)
                self.assertEqual(conn.backend, "postgresql")
                profile = db.database_runtime_profile()
                self.assertEqual(profile["mode"], "shared-runtime")
                db.create_table(conn)
                inserted_id = db.create_case_record(conn, "postgres-case")
                frame = db.get_case_records(conn)
        self.assertEqual(inserted_id, 7)
        self.assertFalse(frame.empty)
        executed_sql = "\n".join(sql for sql, _ in fake_raw.cursor_instance.executed)
        self.assertIn("%s", executed_sql)
        self.assertIn("RETURNING id", executed_sql)
        self.assertIn("EXTRACT(EPOCH FROM NOW())", executed_sql)

    def test_workspace_columns_are_available_on_shared_records(self) -> None:
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.upsert_incident(
                conn,
                "INC-WORKSPACE-001",
                time.time(),
                "medium",
                "Workspace scoped incident",
                "Workspace persistence check",
                workspace_id="tenant-a",
            )
            case_id = db.create_case_record(conn, "Workspace case", workspace_id="tenant-a")
            db.log_case_activity(
                conn,
                case_id=case_id,
                event_type="workspace_check",
                summary="workspace propagation",
                workspace_id="tenant-a",
            )
            db.upsert_connector(conn, "workspace-siem", "siem", True, workspace_id="tenant-a")
            db.insert_telemetry(conn, [{"ts": time.time(), "cpu": 1.0}], workspace_id="tenant-a")
            db.log_response_action(conn, "kill", 12, "cmd.exe", "blocked", workspace_id="tenant-a")
            db.log_alert(conn, "https://localhost/hook", "webhook", "high", "Alert", "sent", "detail", workspace_id="tenant-a")
            db.log_remediation(conn, "registry", "HKCU\\Test", status="applied", workspace_id="tenant-a")
            db.log_quarantine(conn, 12, "cmd.exe", "c:/a.exe", "c:/q/a.exe", workspace_id="tenant-a")
            incidents = db.get_incidents(conn, workspace_id="tenant-a").fillna("")
            cases = db.get_case_records(conn).fillna("")
            activity = db.get_case_activity(conn, case_id).fillna("")
            connectors = db.get_connectors(conn).fillna("")
            telemetry = db.get_historical_data(conn, workspace_id="tenant-a").fillna("")
            responses = db.get_response_logs(conn, workspace_id="tenant-a").fillna("")
            alerts = db.get_alerts(conn, workspace_id="tenant-a").fillna("")
            remediations = db.get_remediations(conn, workspace_id="tenant-a").fillna("")
            quarantine = db.get_quarantine(conn, workspace_id="tenant-a").fillna("")
        finally:
            conn.close()
        self.assertIn("workspace_id", incidents.columns)
        self.assertEqual(str(incidents.iloc[0]["workspace_id"]), "tenant-a")
        self.assertIn("workspace_id", cases.columns)
        self.assertEqual(str(cases[cases["id"] == case_id].iloc[0]["workspace_id"]), "tenant-a")
        self.assertIn("workspace_id", activity.columns)
        self.assertEqual(str(activity.iloc[0]["workspace_id"]), "tenant-a")
        self.assertIn("workspace_id", connectors.columns)
        self.assertEqual(str(connectors[connectors["name"] == "workspace-siem"].iloc[0]["workspace_id"]), "tenant-a")
        for frame in (telemetry, responses, alerts, remediations, quarantine):
            self.assertIn("workspace_id", frame.columns)
            self.assertEqual(str(frame.iloc[0]["workspace_id"]), "tenant-a")

    def test_host_inventory_rejects_cross_workspace_host_id_takeover(self) -> None:
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.upsert_host(
                conn,
                host_id="shared-host-1",
                host="shared-host-1",
                platform="Windows",
                role="agent",
                ip_address="10.0.0.10",
                api_status="online",
                agent_version="1.0",
                boot_time=time.time(),
                last_seen=time.time(),
                workspace_id="tenant-a",
            )
            with self.assertRaises(ValueError):
                db.upsert_host(
                    conn,
                    host_id="shared-host-1",
                    host="shared-host-1",
                    platform="Windows",
                    role="agent",
                    ip_address="10.0.0.11",
                    api_status="online",
                    agent_version="1.0",
                    boot_time=time.time(),
                    last_seen=time.time(),
                    workspace_id="tenant-b",
                )
        finally:
            conn.close()

    def test_connector_registry_allows_same_name_per_workspace(self) -> None:
        conn = db.create_connection()
        self.assertIsNotNone(conn)
        try:
            db.upsert_connector(conn, "splunk", "siem", True, workspace_id="tenant-a")
            db.upsert_connector(conn, "splunk", "siem", True, workspace_id="tenant-b")
            connectors = db.get_connectors(conn).fillna("")
        finally:
            conn.close()
        scoped = connectors[connectors["name"] == "splunk"]
        self.assertTrue(any(str(row["workspace_id"]) == "tenant-a" for _, row in scoped.iterrows()))
        self.assertTrue(any(str(row["workspace_id"]) == "tenant-b" for _, row in scoped.iterrows()))


if __name__ == "__main__":
    unittest.main()
