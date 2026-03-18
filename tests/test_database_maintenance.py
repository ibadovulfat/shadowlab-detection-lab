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


if __name__ == "__main__":
    unittest.main()
