from __future__ import annotations

import os
import sqlite3
import logging
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

import pandas as pd

DEFAULT_DB_FILE = "shadowlab.db"
logger = logging.getLogger(__name__)
_SAFE_SCHEMA_NAMES = {
    "approval_log",
    "approval_requests",
    "action_audit_log",
    "alert_log",
    "auth_log",
    "case_activity_log",
    "case_records",
    "connector_delivery_queue",
    "connector_delivery_log",
    "connector_registry",
    "external_request_log",
    "host_inventory",
    "identity_revocation_log",
    "incidents",
    "integration_export_log",
    "investigation_log",
    "quarantine_log",
    "rate_limit_log",
    "remediation_log",
    "request_nonce_log",
    "response_log",
    "telemetry",
}
_SAFE_COLUMN_NAMES = {
    "actor",
    "attack_chain",
    "allowed_scopes",
    "prev_hash",
    "row_hash",
    "approval_status",
    "approved_at",
    "auth_source",
    "category",
    "connector_type",
    "correlation_story",
    "details",
    "expires_at",
    "metadata",
    "mitre_mapping",
    "notes",
    "owner",
    "policy_profile",
    "reason",
    "remote_ips",
    "resolution",
    "role",
    "source",
    "status",
    "subject",
    "token_id",
    "used_at",
    "workspace_id",
}


def _epoch_now_sql(backend: str) -> str:
    if backend == "postgresql":
        return "EXTRACT(EPOCH FROM NOW())"
    return "strftime('%s', 'now')"


def _read_sql_query(conn, sql: str, params: Any = None) -> pd.DataFrame:
    cursor = conn.execute(sql, params) if params is not None else conn.execute(sql)
    rows = cursor.fetchall()
    columns = [str(column[0]) for column in (cursor.description or [])]
    return pd.DataFrame(rows, columns=columns)


def _insert_ignore_sql(table: str, columns: list[str], backend: str) -> str:
    placeholders = ", ".join(["?"] * len(columns))
    if backend == "postgresql":
        return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
    return f"INSERT OR IGNORE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"


def _insert_returning_id(conn, sql: str, params: Any) -> int:
    if getattr(conn, "backend", "sqlite") == "postgresql":
        cursor = conn.execute(f"{sql} RETURNING id", params)
        row = cursor.fetchone()
        conn.commit()
        return int(row[0])
    cursor = conn.execute(sql, params)
    conn.commit()
    return int(cursor.lastrowid)


class CursorAdapter:
    def __init__(self, backend: str, cursor):
        self.backend = backend
        self._cursor = cursor

    def execute(self, sql: str, params: Any = None):
        translated = _translate_sql(sql, self.backend)
        if params is None:
            self._cursor.execute(translated)
        else:
            self._cursor.execute(translated, params)
        return self

    def executemany(self, sql: str, seq_of_params):
        translated = _translate_sql(sql, self.backend)
        self._cursor.executemany(translated, seq_of_params)
        return self

    def __iter__(self):
        return iter(self._cursor)

    def __getattr__(self, name: str):
        return getattr(self._cursor, name)


class ConnectionAdapter:
    def __init__(self, backend: str, raw_connection):
        self.backend = backend
        self.raw_connection = raw_connection

    def execute(self, sql: str, params: Any = None):
        cursor = self.cursor()
        return cursor.execute(sql, params)

    def executemany(self, sql: str, seq_of_params):
        cursor = self.cursor()
        return cursor.executemany(sql, seq_of_params)

    def cursor(self):
        return CursorAdapter(self.backend, self.raw_connection.cursor())

    def commit(self):
        return self.raw_connection.commit()

    def close(self):
        return self.raw_connection.close()

    def rollback(self):
        return self.raw_connection.rollback()

    def __getattr__(self, name: str):
        return getattr(self.raw_connection, name)


def database_runtime_profile() -> dict[str, str]:
    raw = os.environ.get("SHADOWLAB_DATABASE_URL", "").strip()
    if not raw:
        return {"backend": "sqlite", "database_url": str(Path(DEFAULT_DB_FILE).resolve()), "mode": "embedded"}
    parsed = urlparse(raw)
    if parsed.scheme in {"sqlite", ""}:
        db_path = parsed.path.lstrip("/") if parsed.scheme == "sqlite" else raw
        return {"backend": "sqlite", "database_url": str(Path(db_path or DEFAULT_DB_FILE).resolve()), "mode": "embedded"}
    if parsed.scheme in {"postgres", "postgresql"}:
        return {"backend": "postgresql", "database_url": raw, "mode": "shared-runtime"}
    return {"backend": "unknown", "database_url": raw, "mode": "unsupported"}


def _sqlite_db_file() -> str:
    profile = database_runtime_profile()
    if profile["backend"] != "sqlite":
        raise RuntimeError("Configured database backend is not SQLite.")
    return profile["database_url"]


def _translate_sql(sql: str, backend: str) -> str:
    if backend != "postgresql":
        return sql
    translated = sql
    # `?` → `%s` only OUTSIDE of single-quoted string literals. The naive
    # str.replace also rewrote `?` inside `'foo?bar'` literals and corrupted
    # `LIKE '%?%'`-style filter patterns when they happened to appear.
    translated = _replace_qmark_placeholders(translated)
    translated = translated.replace("(strftime('%s', 'now'))", "EXTRACT(EPOCH FROM NOW())")
    translated = translated.replace("strftime('%s', 'now')", "EXTRACT(EPOCH FROM NOW())")
    translated = translated.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    translated = translated.replace("DATETIME DEFAULT CURRENT_TIMESTAMP", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    translated = translated.replace("REAL DEFAULT (EXTRACT(EPOCH FROM NOW()))", "DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())")
    return translated


def _replace_qmark_placeholders(sql: str) -> str:
    """Convert SQLite `?` placeholders to psycopg `%s` while leaving
    string literals (`'...'`) untouched. SQL only uses single quotes for
    literals; `''` is the standard escape for an embedded quote.
    """
    out: list[str] = []
    in_literal = False
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            # Handle `''` escape: stay inside the literal.
            if in_literal and i + 1 < n and sql[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            in_literal = not in_literal
            out.append(ch)
            i += 1
            continue
        if ch == "?" and not in_literal:
            out.append("%s")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def create_connection():
    conn = None
    profile = database_runtime_profile()
    try:
        if profile["backend"] == "sqlite":
            raw_conn = sqlite3.connect(_sqlite_db_file(), timeout=10)
            raw_conn.execute("PRAGMA journal_mode=WAL;")
            raw_conn.execute("PRAGMA foreign_keys=ON;")
            raw_conn.execute("PRAGMA busy_timeout=10000;")
            conn = ConnectionAdapter("sqlite", raw_conn)
        elif profile["backend"] == "postgresql":
            raw_conn = _create_postgres_connection(profile["database_url"])
            conn = ConnectionAdapter("postgresql", raw_conn)
        else:
            raise RuntimeError(f"Unsupported database backend: {profile['backend']}")
    except Exception as exc:
        logger.exception("Failed to create database connection: %s", exc)
    return conn


def _create_postgres_connection(database_url: str):
    try:
        import psycopg

        return psycopg.connect(database_url)
    except Exception:
        try:
            import psycopg2

            return psycopg2.connect(database_url)
        except Exception as exc:
            raise RuntimeError(
                "PostgreSQL backend requested but no compatible driver is installed. Install psycopg or psycopg2."
            ) from exc


def create_table(conn):
    try:
        if getattr(conn, "backend", "sqlite") == "postgresql":
            _create_table_postgres(conn)
            return
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                ts REAL NOT NULL,
                cpu REAL,
                mem_percent REAL,
                proc_threads INTEGER,
                proc_handles INTEGER,
                open_files INTEGER,
                tcp_conns INTEGER,
                bytes_sent_rate REAL,
                bytes_recv_rate REAL,
                remote_ips TEXT DEFAULT ''
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS response_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT,
                details TEXT
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL UNIQUE,
                workspace_id TEXT DEFAULT 'default',
                created_at REAL,
                severity TEXT,
                title TEXT,
                summary TEXT,
                status TEXT DEFAULT 'open',
                notes TEXT DEFAULT '',
                owner TEXT DEFAULT '',
                recommended_actions TEXT DEFAULT '',
                attack_chain TEXT DEFAULT '',
                mitre_mapping TEXT DEFAULT '',
                correlation_story TEXT DEFAULT ''
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantine_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                pid INTEGER,
                process_name TEXT,
                original_path TEXT,
                quarantine_path TEXT,
                status TEXT DEFAULT 'active'
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT NOT NULL UNIQUE,
                workspace_id TEXT DEFAULT 'default',
                host TEXT NOT NULL,
                platform TEXT,
                role TEXT,
                ip_address TEXT,
                api_status TEXT,
                agent_version TEXT,
                boot_time REAL,
                last_seen REAL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                workspace_id TEXT DEFAULT 'default',
                destination TEXT,
                destination_type TEXT,
                severity TEXT,
                title TEXT,
                status TEXT,
                detail TEXT
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                workspace_id TEXT DEFAULT 'default',
                item_type TEXT,
                target TEXT,
                backup_path TEXT DEFAULT '',
                rollback_data TEXT DEFAULT '',
                status TEXT DEFAULT 'applied'
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_export_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                workspace_id TEXT DEFAULT 'default',
                integration_name TEXT NOT NULL,
                export_type TEXT NOT NULL,
                target TEXT,
                status TEXT,
                detail TEXT
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                workspace_id TEXT DEFAULT 'default',
                event_type TEXT NOT NULL,
                outcome TEXT NOT NULL,
                role TEXT DEFAULT '',
                client_ip TEXT DEFAULT '',
                path TEXT DEFAULT '',
                detail TEXT DEFAULT ''
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL,
                subject TEXT NOT NULL,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS request_nonce_log (
                nonce_key TEXT PRIMARY KEY,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                workspace_id TEXT DEFAULT 'default',
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER,
                role TEXT DEFAULT '',
                client_ip TEXT DEFAULT '',
                detail TEXT DEFAULT '',
                prev_hash TEXT DEFAULT '',
                row_hash TEXT DEFAULT ''
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS external_request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                workspace_id TEXT DEFAULT 'default',
                service TEXT NOT NULL,
                method TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT DEFAULT ''
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS case_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                incident_id TEXT DEFAULT '',
                title TEXT NOT NULL,
                priority TEXT DEFAULT 'medium',
                stage TEXT DEFAULT 'triage',
                owner TEXT DEFAULT '',
                sla_deadline REAL DEFAULT 0,
                asset_criticality REAL DEFAULT 0,
                tags_json TEXT DEFAULT '[]',
                approvers_json TEXT DEFAULT '[]',
                narrative TEXT DEFAULT '',
                status TEXT DEFAULT 'open',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                query_text TEXT DEFAULT '',
                filters_json TEXT DEFAULT '{}',
                case_id INTEGER DEFAULT NULL,
                created_by TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER DEFAULT NULL,
                view_id INTEGER DEFAULT NULL,
                item_time REAL DEFAULT 0,
                item_type TEXT DEFAULT '',
                item_title TEXT DEFAULT '',
                note_text TEXT NOT NULL,
                tags_json TEXT DEFAULT '[]',
                author TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_stories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER DEFAULT NULL,
                title TEXT NOT NULL,
                hypothesis TEXT DEFAULT '',
                summary TEXT DEFAULT '',
                confidence TEXT DEFAULT 'medium',
                tags_json TEXT DEFAULT '[]',
                created_by TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_pins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER DEFAULT NULL,
                view_id INTEGER DEFAULT NULL,
                item_time REAL DEFAULT 0,
                item_type TEXT DEFAULT '',
                item_title TEXT DEFAULT '',
                item_severity TEXT DEFAULT '',
                item_payload_json TEXT DEFAULT '{}',
                rationale TEXT DEFAULT '',
                pinned_by TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS case_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                role TEXT DEFAULT 'owner',
                status TEXT DEFAULT 'active',
                assigned_by TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS case_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT DEFAULT 'todo',
                priority TEXT DEFAULT 'medium',
                assigned_to TEXT DEFAULT '',
                due_at REAL DEFAULT 0,
                created_by TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS case_activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                case_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT DEFAULT '',
                summary TEXT DEFAULT '',
                detail_json TEXT DEFAULT '{}',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_chain_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT DEFAULT '',
                artifact_path TEXT DEFAULT '',
                artifact_hash TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                case_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                requested_by TEXT DEFAULT '',
                approver TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                reason TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                resolved_at REAL DEFAULT 0,
                expires_at REAL DEFAULT 0,
                used_at REAL DEFAULT 0
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_rule_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL UNIQUE,
                version TEXT DEFAULT '1.0.0',
                status TEXT DEFAULT 'active',
                tuning_json TEXT DEFAULT '{}',
                suppression_json TEXT DEFAULT '{}',
                notes TEXT DEFAULT '',
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS false_positive_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                incident_id TEXT DEFAULT '',
                actor TEXT DEFAULT '',
                reason TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS connector_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                workspace_id TEXT DEFAULT 'default',
                kind TEXT NOT NULL,
                enabled INTEGER DEFAULT 0,
                config_json TEXT DEFAULT '{}',
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS connector_delivery_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT DEFAULT 'default',
                connector_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                next_retry_at REAL DEFAULT 0,
                last_error TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT DEFAULT '',
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS identity_revocation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer TEXT DEFAULT '',
                subject TEXT DEFAULT '',
                token_id TEXT DEFAULT '',
                workspace_id TEXT DEFAULT 'default',
                actor TEXT DEFAULT '',
                reason TEXT DEFAULT '',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                expires_at REAL DEFAULT 0
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS yara_scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                target_path TEXT DEFAULT '',
                pack TEXT DEFAULT '',
                scope TEXT DEFAULT 'file',
                status TEXT DEFAULT '',
                match_count INTEGER DEFAULT 0,
                suppressed_count INTEGER DEFAULT 0,
                compile_error_count INTEGER DEFAULT 0,
                source_counts_json TEXT DEFAULT '{}',
                matched_rules_json TEXT DEFAULT '[]',
                errors_json TEXT DEFAULT '[]'
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS yara_rule_hit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                rule_id TEXT NOT NULL,
                source TEXT DEFAULT '',
                source_path TEXT DEFAULT '',
                pack TEXT DEFAULT '',
                scope TEXT DEFAULT 'file',
                severity TEXT DEFAULT 'low',
                confidence TEXT DEFAULT 'low',
                score INTEGER DEFAULT 0,
                suppressed INTEGER DEFAULT 0
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at REAL DEFAULT (strftime('%s', 'now'))
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secret_rotation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                secret_name TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT DEFAULT '',
                detail TEXT DEFAULT ''
            );
            """
        )

        _ensure_column(conn, "incidents", "attack_chain", "TEXT DEFAULT ''")
        _ensure_column(conn, "incidents", "mitre_mapping", "TEXT DEFAULT ''")
        _ensure_column(conn, "incidents", "correlation_story", "TEXT DEFAULT ''")
        _ensure_column(conn, "incidents", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "host_inventory", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "case_records", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "case_activity_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "connector_registry", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "integration_export_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "auth_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "action_audit_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "external_request_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "approval_requests", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "connector_delivery_queue", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "telemetry", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "response_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "quarantine_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "alert_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "remediation_log", "workspace_id", "TEXT DEFAULT 'default'")
        _ensure_column(conn, "telemetry", "remote_ips", "TEXT DEFAULT ''")
        _ensure_column(conn, "approval_requests", "expires_at", "REAL DEFAULT 0")
        _ensure_column(conn, "approval_requests", "used_at", "REAL DEFAULT 0")
        _migrate_connector_registry_workspace_schema(conn)
        _ensure_indexes(conn)
        _record_migration(conn, "2026_03_backend_hardening")
        _record_migration(conn, "2026_04_policy_workspace_foundation")
        _record_migration(conn, "2026_04_tenant_storage_cleanup")
    except sqlite3.Error as exc:
        print(exc)


def _ensure_column(conn, table: str, column: str, definition: str):
    if table not in _SAFE_SCHEMA_NAMES or column not in _SAFE_COLUMN_NAMES:
        raise ValueError("Unsafe schema migration identifier")
    if getattr(conn, "backend", "sqlite") == "postgresql":
        columns = {
            str(row[0])
            for row in conn.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = %s
                """,
                (table,),
            ).fetchall()
        }
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}")
            conn.commit()
        return
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_connector_registry_workspace_schema(conn) -> None:
    backend = getattr(conn, "backend", "sqlite")
    if backend == "postgresql":
        try:
            conn.execute("UPDATE connector_registry SET workspace_id = COALESCE(NULLIF(workspace_id, ''), 'default')")
            rows = conn.execute("SELECT id, name, workspace_id FROM connector_registry").fetchall()
            for row in rows:
                if len(row) < 3:
                    continue
                connector_id = int(row[0])
                raw_name = str(row[1] or "").strip().lower()
                workspace_id = str(row[2] or "default").strip().lower() or "default"
                normalized_workspace = workspace_id
                normalized_name = raw_name
                if "::" in raw_name:
                    prefix, suffix = raw_name.split("::", 1)
                    if prefix:
                        normalized_workspace = prefix.strip().lower() or workspace_id
                    normalized_name = suffix.strip().lower()
                conn.execute(
                    "UPDATE connector_registry SET workspace_id = ?, name = ? WHERE id = ?",
                    (normalized_workspace, normalized_name, connector_id),
                )
        except Exception:
            pass
        conn.execute("DROP INDEX IF EXISTS idx_connector_registry_workspace_name")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_connector_registry_workspace_name ON connector_registry(workspace_id, name)")
        conn.commit()
        return
    index_rows = conn.execute("PRAGMA index_list(connector_registry)").fetchall()
    unique_on_name = False
    for index_row in index_rows:
        index_name = str(index_row[1] or "")
        is_unique = int(index_row[2] or 0) == 1
        if not is_unique:
            continue
        column_rows = conn.execute(f"PRAGMA index_info({index_name})").fetchall()
        columns = [str(item[2] or "") for item in column_rows]
        if columns == ["name"]:
            unique_on_name = True
            break
    if unique_on_name:
        conn.execute("ALTER TABLE connector_registry RENAME TO connector_registry_legacy")
        conn.execute(
            """
            CREATE TABLE connector_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                workspace_id TEXT DEFAULT 'default',
                kind TEXT NOT NULL,
                enabled INTEGER DEFAULT 0,
                config_json TEXT DEFAULT '{}',
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            )
            """
        )
        legacy_rows = conn.execute(
            """
            SELECT id, name, workspace_id, kind, enabled, config_json, updated_at
            FROM connector_registry_legacy
            ORDER BY id ASC
            """
        ).fetchall()
        for row in legacy_rows:
            raw_name = str(row[1] or "").strip().lower()
            workspace_id = str(row[2] or "default").strip().lower() or "default"
            normalized_name = raw_name
            if "::" in raw_name:
                prefix, suffix = raw_name.split("::", 1)
                if prefix:
                    workspace_id = prefix.strip().lower() or workspace_id
                normalized_name = suffix.strip().lower()
            conn.execute(
                """
                INSERT OR IGNORE INTO connector_registry (id, name, workspace_id, kind, enabled, config_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (row[0], normalized_name, workspace_id, row[3], row[4], row[5], row[6]),
            )
        conn.execute("DROP TABLE connector_registry_legacy")
    else:
        rows = conn.execute("SELECT id, name, workspace_id FROM connector_registry").fetchall()
        for row in rows:
            connector_id = int(row[0])
            raw_name = str(row[1] or "").strip().lower()
            workspace_id = str(row[2] or "default").strip().lower() or "default"
            normalized_name = raw_name
            if "::" in raw_name:
                prefix, suffix = raw_name.split("::", 1)
                if prefix:
                    workspace_id = prefix.strip().lower() or workspace_id
                normalized_name = suffix.strip().lower()
            conn.execute(
                "UPDATE connector_registry SET workspace_id = ?, name = ? WHERE id = ?",
                (workspace_id, normalized_name, connector_id),
            )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_connector_registry_workspace_name ON connector_registry(workspace_id, name)")
    conn.commit()


def _create_table_postgres(conn) -> None:
    statements = [
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            ts DOUBLE PRECISION NOT NULL,
            cpu DOUBLE PRECISION,
            mem_percent DOUBLE PRECISION,
            proc_threads INTEGER,
            proc_handles INTEGER,
            open_files INTEGER,
            tcp_conns INTEGER,
            bytes_sent_rate DOUBLE PRECISION,
            bytes_recv_rate DOUBLE PRECISION,
            remote_ips TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS response_log (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            details TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id BIGSERIAL PRIMARY KEY,
            incident_id TEXT NOT NULL UNIQUE,
            workspace_id TEXT DEFAULT 'default',
            created_at DOUBLE PRECISION,
            severity TEXT,
            title TEXT,
            summary TEXT,
            status TEXT DEFAULT 'open',
            notes TEXT DEFAULT '',
            owner TEXT DEFAULT '',
            recommended_actions TEXT DEFAULT '',
            attack_chain TEXT DEFAULT '',
            mitre_mapping TEXT DEFAULT '',
            correlation_story TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS quarantine_log (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pid INTEGER,
            process_name TEXT,
            original_path TEXT,
            quarantine_path TEXT,
            status TEXT DEFAULT 'active'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS host_inventory (
            id BIGSERIAL PRIMARY KEY,
            host_id TEXT NOT NULL UNIQUE,
            workspace_id TEXT DEFAULT 'default',
            host TEXT NOT NULL,
            platform TEXT,
            role TEXT,
            ip_address TEXT,
            api_status TEXT,
            agent_version TEXT,
            boot_time DOUBLE PRECISION,
            last_seen DOUBLE PRECISION
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alert_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            workspace_id TEXT DEFAULT 'default',
            destination TEXT,
            destination_type TEXT,
            severity TEXT,
            title TEXT,
            status TEXT,
            detail TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS remediation_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            workspace_id TEXT DEFAULT 'default',
            item_type TEXT,
            target TEXT,
            backup_path TEXT DEFAULT '',
            rollback_data TEXT DEFAULT '',
            status TEXT DEFAULT 'applied'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS integration_export_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            workspace_id TEXT DEFAULT 'default',
            integration_name TEXT NOT NULL,
            export_type TEXT NOT NULL,
            target TEXT,
            status TEXT,
            detail TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS auth_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            workspace_id TEXT DEFAULT 'default',
            event_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            role TEXT DEFAULT '',
            client_ip TEXT DEFAULT '',
            path TEXT DEFAULT '',
            detail TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS rate_limit_log (
            id BIGSERIAL PRIMARY KEY,
            bucket TEXT NOT NULL,
            subject TEXT NOT NULL,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS request_nonce_log (
            nonce_key TEXT PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS action_audit_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            workspace_id TEXT DEFAULT 'default',
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER,
            role TEXT DEFAULT '',
            client_ip TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            prev_hash TEXT DEFAULT '',
            row_hash TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS external_request_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            workspace_id TEXT DEFAULT 'default',
            service TEXT NOT NULL,
            method TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            detail TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS case_records (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            incident_id TEXT DEFAULT '',
            title TEXT NOT NULL,
            priority TEXT DEFAULT 'medium',
            stage TEXT DEFAULT 'triage',
            owner TEXT DEFAULT '',
            sla_deadline DOUBLE PRECISION DEFAULT 0,
            asset_criticality DOUBLE PRECISION DEFAULT 0,
            tags_json TEXT DEFAULT '[]',
            approvers_json TEXT DEFAULT '[]',
            narrative TEXT DEFAULT '',
            status TEXT DEFAULT 'open',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigation_views (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            query_text TEXT DEFAULT '',
            filters_json TEXT DEFAULT '{}',
            case_id BIGINT DEFAULT NULL,
            created_by TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigation_notes (
            id BIGSERIAL PRIMARY KEY,
            case_id BIGINT DEFAULT NULL,
            view_id BIGINT DEFAULT NULL,
            item_time DOUBLE PRECISION DEFAULT 0,
            item_type TEXT DEFAULT '',
            item_title TEXT DEFAULT '',
            note_text TEXT NOT NULL,
            tags_json TEXT DEFAULT '[]',
            author TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigation_stories (
            id BIGSERIAL PRIMARY KEY,
            case_id BIGINT DEFAULT NULL,
            title TEXT NOT NULL,
            hypothesis TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            confidence TEXT DEFAULT 'medium',
            tags_json TEXT DEFAULT '[]',
            created_by TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigation_pins (
            id BIGSERIAL PRIMARY KEY,
            case_id BIGINT DEFAULT NULL,
            view_id BIGINT DEFAULT NULL,
            item_time DOUBLE PRECISION DEFAULT 0,
            item_type TEXT DEFAULT '',
            item_title TEXT DEFAULT '',
            item_severity TEXT DEFAULT '',
            item_payload_json TEXT DEFAULT '{}',
            rationale TEXT DEFAULT '',
            pinned_by TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS case_assignments (
            id BIGSERIAL PRIMARY KEY,
            case_id BIGINT NOT NULL,
            analyst TEXT NOT NULL,
            role TEXT DEFAULT 'owner',
            status TEXT DEFAULT 'active',
            assigned_by TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS case_tasks (
            id BIGSERIAL PRIMARY KEY,
            case_id BIGINT NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'todo',
            priority TEXT DEFAULT 'medium',
            assigned_to TEXT DEFAULT '',
            due_at DOUBLE PRECISION DEFAULT 0,
            created_by TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS case_activity_log (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            case_id BIGINT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            detail_json TEXT DEFAULT '{}',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS evidence_chain_log (
            id BIGSERIAL PRIMARY KEY,
            case_id BIGINT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT DEFAULT '',
            artifact_path TEXT DEFAULT '',
            artifact_hash TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS approval_requests (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            case_id BIGINT NOT NULL,
            action TEXT NOT NULL,
            requested_by TEXT DEFAULT '',
            approver TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            reason TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            resolved_at DOUBLE PRECISION DEFAULT 0,
            expires_at DOUBLE PRECISION DEFAULT 0,
            used_at DOUBLE PRECISION DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS detection_rule_registry (
            id BIGSERIAL PRIMARY KEY,
            rule_id TEXT NOT NULL UNIQUE,
            version TEXT DEFAULT '1.0.0',
            status TEXT DEFAULT 'active',
            tuning_json TEXT DEFAULT '{}',
            suppression_json TEXT DEFAULT '{}',
            notes TEXT DEFAULT '',
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS false_positive_feedback (
            id BIGSERIAL PRIMARY KEY,
            rule_id TEXT NOT NULL,
            incident_id TEXT DEFAULT '',
            actor TEXT DEFAULT '',
            reason TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS connector_registry (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            workspace_id TEXT DEFAULT 'default',
            kind TEXT NOT NULL,
            enabled INTEGER DEFAULT 0,
            config_json TEXT DEFAULT '{}',
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS connector_delivery_queue (
            id BIGSERIAL PRIMARY KEY,
            workspace_id TEXT DEFAULT 'default',
            connector_name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            attempts INTEGER DEFAULT 0,
            next_retry_at DOUBLE PRECISION DEFAULT 0,
            last_error TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT '',
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS identity_revocation_log (
            id BIGSERIAL PRIMARY KEY,
            issuer TEXT DEFAULT '',
            subject TEXT DEFAULT '',
            token_id TEXT DEFAULT '',
            workspace_id TEXT DEFAULT 'default',
            actor TEXT DEFAULT '',
            reason TEXT DEFAULT '',
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            expires_at DOUBLE PRECISION DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS yara_scan_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            target_path TEXT DEFAULT '',
            pack TEXT DEFAULT '',
            scope TEXT DEFAULT 'file',
            status TEXT DEFAULT '',
            match_count INTEGER DEFAULT 0,
            suppressed_count INTEGER DEFAULT 0,
            compile_error_count INTEGER DEFAULT 0,
            source_counts_json TEXT DEFAULT '{}',
            matched_rules_json TEXT DEFAULT '[]',
            errors_json TEXT DEFAULT '[]'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS yara_rule_hit_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            rule_id TEXT NOT NULL,
            source TEXT DEFAULT '',
            source_path TEXT DEFAULT '',
            pack TEXT DEFAULT '',
            scope TEXT DEFAULT 'file',
            severity TEXT DEFAULT 'low',
            confidence TEXT DEFAULT 'low',
            score INTEGER DEFAULT 0,
            suppressed INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS secret_rotation_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            secret_name TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT DEFAULT '',
            detail TEXT DEFAULT ''
        )
        """,
    ]
    for statement in statements:
        conn.execute(statement)
    conn.commit()
    _ensure_column(conn, "incidents", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "host_inventory", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "case_records", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "case_activity_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "connector_registry", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "integration_export_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "auth_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "action_audit_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "external_request_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "approval_requests", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "connector_delivery_queue", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "telemetry", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "response_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "quarantine_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "alert_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "remediation_log", "workspace_id", "TEXT DEFAULT 'default'")
    _ensure_column(conn, "action_audit_log", "prev_hash", "TEXT DEFAULT ''")
    _ensure_column(conn, "action_audit_log", "row_hash", "TEXT DEFAULT ''")
    _migrate_connector_registry_workspace_schema(conn)
    _ensure_indexes(conn)
    _record_migration(conn, "2026_03_backend_hardening")
    _record_migration(conn, "2026_04_policy_workspace_foundation")
    _record_migration(conn, "2026_04_tenant_storage_cleanup")
    _record_migration(conn, "2026_05_audit_hash_chain")


def _ensure_indexes(conn) -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_auth_log_created_at ON auth_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_subject_created_at ON rate_limit_log(bucket, subject, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_request_nonce_created_at ON request_nonce_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_action_audit_created_at ON action_audit_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_external_request_created_at ON external_request_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alert_log_created_at ON alert_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_telemetry_workspace_ts ON telemetry(workspace_id, ts DESC)",
        "CREATE INDEX IF NOT EXISTS idx_response_workspace_timestamp ON response_log(workspace_id, timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_quarantine_workspace_created_at ON quarantine_log(workspace_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alert_workspace_created_at ON alert_log(workspace_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_remediation_workspace_created_at ON remediation_log(workspace_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_connector_registry_workspace_name ON connector_registry(workspace_id, name)",
        "CREATE INDEX IF NOT EXISTS idx_connector_queue_status_retry ON connector_delivery_queue(status, next_retry_at, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_approval_status_created_at ON approval_requests(status, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_secret_rotation_created_at ON secret_rotation_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_identity_revocation_lookup ON identity_revocation_log(issuer, subject, token_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_yara_scan_created_at ON yara_scan_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_yara_rule_hit_created_at ON yara_rule_hit_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_yara_rule_hit_rule_id ON yara_rule_hit_log(rule_id, created_at DESC)",
    ]
    for statement in statements:
        conn.execute(statement)
    conn.commit()


def _record_migration(conn, version: str) -> None:
    conn.execute(
        _insert_ignore_sql("schema_migrations", ["version"], getattr(conn, "backend", "sqlite")),
        (version,),
    )
    conn.commit()


def insert_telemetry(conn, telemetry_data: list[dict], workspace_id: str = "default"):
    try:
        rows = []
        for row in telemetry_data:
            item = dict(row)
            rows.append(
                (
                    workspace_id,
                    float(item.get("ts", 0)),
                    item.get("cpu"),
                    item.get("mem_percent"),
                    item.get("proc_threads"),
                    item.get("proc_handles"),
                    item.get("open_files"),
                    item.get("tcp_conns"),
                    item.get("bytes_sent_rate"),
                    item.get("bytes_recv_rate"),
                    str(item.get("remote_ips", [])),
                )
            )
        if rows:
            conn.executemany(
                """
                INSERT INTO telemetry (
                    workspace_id, ts, cpu, mem_percent, proc_threads, proc_handles,
                    open_files, tcp_conns, bytes_sent_rate, bytes_recv_rate, remote_ips
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
    except Exception as exc:
        print(exc)


def log_response_action(conn, action, pid, process_name, details="", workspace_id: str = "default"):
    try:
        conn.execute(
            "INSERT INTO response_log (workspace_id, action, pid, process_name, details) VALUES (?, ?, ?, ?, ?)",
            (workspace_id, action, pid, process_name, details),
        )
        conn.commit()
    except Exception as exc:
        print(f"Log Error: {exc}")


def get_response_logs(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM response_log WHERE workspace_id = ? ORDER BY timestamp DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM response_log ORDER BY timestamp DESC")


def get_historical_data(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM telemetry WHERE workspace_id = ? ORDER BY ts DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM telemetry ORDER BY ts DESC")


def upsert_incident(
    conn,
    incident_id,
    created_at,
    severity,
    title,
    summary,
    status="open",
    notes="",
    owner="",
    recommended_actions="",
    attack_chain="",
    mitre_mapping="",
    correlation_story="",
    workspace_id="default",
):
    try:
        conn.execute(
            """
            INSERT INTO incidents (
                incident_id, workspace_id, created_at, severity, title, summary, status, notes, owner,
                recommended_actions, attack_chain, mitre_mapping, correlation_story
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                workspace_id=excluded.workspace_id,
                severity=excluded.severity,
                title=excluded.title,
                summary=excluded.summary,
                status=excluded.status,
                notes=excluded.notes,
                owner=excluded.owner,
                recommended_actions=excluded.recommended_actions,
                attack_chain=excluded.attack_chain,
                mitre_mapping=excluded.mitre_mapping,
                correlation_story=excluded.correlation_story
            """,
            (
                incident_id,
                workspace_id,
                created_at,
                severity,
                title,
                summary,
                status,
                notes,
                owner,
                recommended_actions,
                attack_chain,
                mitre_mapping,
                correlation_story,
            ),
        )
        conn.commit()
    except Exception as exc:
        print(f"Incident upsert error: {exc}")


def update_incident(conn, incident_id, status=None, notes=None, owner=None):
    updates = []
    values = []
    if status is not None:
        updates.append("status = ?")
        values.append(status)
    if notes is not None:
        updates.append("notes = ?")
        values.append(notes)
    if owner is not None:
        updates.append("owner = ?")
        values.append(owner)
    if not updates:
        return
    values.append(incident_id)
    conn.execute(f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ?", values)
    conn.commit()


def get_incidents(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM incidents WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM incidents ORDER BY created_at DESC")


def log_quarantine(conn, pid, process_name, original_path, quarantine_path, status="active", workspace_id: str = "default"):
    conn.execute(
        "INSERT INTO quarantine_log (workspace_id, pid, process_name, original_path, quarantine_path, status) VALUES (?, ?, ?, ?, ?, ?)",
        (workspace_id, pid, process_name, original_path, quarantine_path, status),
    )
    conn.commit()


def update_quarantine(conn, quarantine_id, status, workspace_id: str = ""):
    if workspace_id:
        conn.execute("UPDATE quarantine_log SET status = ? WHERE id = ? AND workspace_id = ?", (status, quarantine_id, workspace_id))
    else:
        conn.execute("UPDATE quarantine_log SET status = ? WHERE id = ?", (status, quarantine_id))
    conn.commit()


def get_quarantine(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM quarantine_log WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM quarantine_log ORDER BY created_at DESC")


def upsert_host(
    conn,
    host_id: str,
    host: str,
    platform: str,
    role: str,
    ip_address: str,
    api_status: str,
    agent_version: str,
    boot_time: float,
    last_seen: float,
    workspace_id: str = "default",
):
    existing = conn.execute("SELECT workspace_id FROM host_inventory WHERE host_id = ?", (host_id,)).fetchone()
    if existing is not None:
        current_workspace = str(existing[0] or "default").strip().lower() or "default"
        requested_workspace = str(workspace_id or "default").strip().lower() or "default"
        if current_workspace != requested_workspace:
            raise ValueError(f"host_id `{host_id}` is already owned by workspace `{current_workspace}`")
    conn.execute(
        """
        INSERT INTO host_inventory (host_id, workspace_id, host, platform, role, ip_address, api_status, agent_version, boot_time, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(host_id) DO UPDATE SET
            workspace_id=excluded.workspace_id,
            host=excluded.host,
            platform=excluded.platform,
            role=excluded.role,
            ip_address=excluded.ip_address,
            api_status=excluded.api_status,
            agent_version=excluded.agent_version,
            boot_time=excluded.boot_time,
            last_seen=excluded.last_seen
        """,
        (host_id, workspace_id, host, platform, role, ip_address, api_status, agent_version, boot_time, last_seen),
    )
    conn.commit()


def get_hosts(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM host_inventory WHERE workspace_id = ? ORDER BY last_seen DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM host_inventory ORDER BY last_seen DESC")


def log_alert(conn, destination: str, destination_type: str, severity: str, title: str, status: str, detail: str, workspace_id: str = "default"):
    conn.execute(
        "INSERT INTO alert_log (workspace_id, destination, destination_type, severity, title, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (workspace_id, destination, destination_type, severity, title, status, detail),
    )
    conn.commit()


def get_alerts(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM alert_log WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM alert_log ORDER BY created_at DESC")


def log_remediation(conn, item_type: str, target: str, backup_path: str = "", rollback_data: str = "", status: str = "applied", workspace_id: str = "default") -> int:
    return _insert_returning_id(
        conn,
        "INSERT INTO remediation_log (workspace_id, item_type, target, backup_path, rollback_data, status) VALUES (?, ?, ?, ?, ?, ?)",
        (workspace_id, item_type, target, backup_path, rollback_data, status),
    )


def update_remediation_status(conn, remediation_id: int, status: str, workspace_id: str = ""):
    if workspace_id:
        conn.execute("UPDATE remediation_log SET status = ? WHERE id = ? AND workspace_id = ?", (status, remediation_id, workspace_id))
    else:
        conn.execute("UPDATE remediation_log SET status = ? WHERE id = ?", (status, remediation_id))
    conn.commit()


def get_remediations(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM remediation_log WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM remediation_log ORDER BY created_at DESC")


def log_integration_export(
    conn,
    integration_name: str,
    export_type: str,
    target: str,
    status: str,
    detail: str,
    workspace_id: str = "default",
):
    conn.execute(
        """
        INSERT INTO integration_export_log (workspace_id, integration_name, export_type, target, status, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, integration_name, export_type, target, status, detail),
    )
    conn.commit()


def get_integration_exports(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(
            conn,
            "SELECT * FROM integration_export_log WHERE workspace_id = ? ORDER BY created_at DESC",
            (workspace_id,),
        )
    return _read_sql_query(conn, "SELECT * FROM integration_export_log ORDER BY created_at DESC")


def log_auth_event(
    conn,
    event_type: str,
    outcome: str,
    role: str = "",
    client_ip: str = "",
    path: str = "",
    detail: str = "",
    workspace_id: str = "default",
):
    conn.execute(
        """
        INSERT INTO auth_log (workspace_id, event_type, outcome, role, client_ip, path, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, event_type, outcome, role, client_ip, path, detail),
    )
    conn.commit()


def get_auth_logs(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM auth_log WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM auth_log ORDER BY created_at DESC")


def record_rate_limit_hit(conn, bucket: str, subject: str, created_at: float) -> None:
    conn.execute(
        """
        INSERT INTO rate_limit_log (bucket, subject, created_at)
        VALUES (?, ?, ?)
        """,
        (bucket, subject, float(created_at)),
    )
    conn.commit()


def prune_rate_limit_hits(conn, bucket: str, subject: str, cutoff: float) -> None:
    conn.execute(
        """
        DELETE FROM rate_limit_log
        WHERE bucket = ? AND subject = ? AND created_at < ?
        """,
        (bucket, subject, float(cutoff)),
    )
    conn.commit()


def count_rate_limit_hits(conn, bucket: str, subject: str, cutoff: float) -> int:
    cursor = conn.execute(
        """
        SELECT COUNT(*)
        FROM rate_limit_log
        WHERE bucket = ? AND subject = ? AND created_at >= ?
        """,
        (bucket, subject, float(cutoff)),
    )
    row = cursor.fetchone()
    return int(row[0]) if row else 0


def reserve_request_nonce(conn, nonce_key: str, created_at: float) -> bool:
    cursor = conn.execute(
        _insert_ignore_sql("request_nonce_log", ["nonce_key", "created_at"], getattr(conn, "backend", "sqlite")),
        (nonce_key, float(created_at)),
    )
    conn.commit()
    rowcount = getattr(cursor, "rowcount", None)
    if rowcount is None:
        return True
    return int(rowcount) > 0


def prune_request_nonces(conn, cutoff: float) -> None:
    conn.execute(
        """
        DELETE FROM request_nonce_log
        WHERE created_at < ?
        """,
        (float(cutoff),),
    )
    conn.commit()


def log_action_audit(
    conn,
    method: str,
    path: str,
    status_code: int,
    role: str = "",
    client_ip: str = "",
    detail: str = "",
    workspace_id: str = "default",
):
    """Append an audit row, chained to the previous row via SHA-256.

    Hash chain (`prev_hash` / `row_hash`) gives tamper-evident audit:
    deleting or mutating a historical row breaks the chain at every row
    after it, which `verify_action_audit_chain()` can detect. This does
    not stop a DB-admin attacker from rewriting *every* subsequent row,
    but combined with periodic chain-tip exports (or the integrity
    manifest history) it makes silent rewriting impractical.
    """
    import hashlib

    cursor = conn.execute(
        "SELECT row_hash FROM action_audit_log ORDER BY id DESC LIMIT 1"
    )
    row = cursor.fetchone()
    prev_hash = str(row[0]) if row and row[0] else ""

    chain_payload = "|".join(
        [
            prev_hash,
            str(workspace_id or ""),
            str(method or ""),
            str(path or ""),
            str(int(status_code)),
            str(role or ""),
            str(client_ip or ""),
            str(detail or ""),
        ]
    )
    row_hash = hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()

    conn.execute(
        """
        INSERT INTO action_audit_log (workspace_id, method, path, status_code, role, client_ip, detail, prev_hash, row_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, method, path, status_code, role, client_ip, detail, prev_hash, row_hash),
    )
    conn.commit()


def verify_action_audit_chain(conn, *, limit: int = 0) -> dict[str, Any]:
    """Walk the audit table and report the first chain break (if any).

    Returns `{"ok": True, "rows_checked": N, "tip": <last row_hash>}` on
    a clean chain. `{"ok": False, "broken_at_id": <id>, "expected_hash":
    ..., "stored_hash": ...}` when a row's recomputed hash disagrees
    with what's stored (tampering or migration glitch).

    `limit` caps how many rows are walked from the head; 0 = all.
    """
    import hashlib

    sql = "SELECT id, workspace_id, method, path, status_code, role, client_ip, detail, prev_hash, row_hash FROM action_audit_log ORDER BY id ASC"
    if limit and limit > 0:
        sql += f" LIMIT {int(limit)}"
    cursor = conn.execute(sql)
    rows_checked = 0
    last_hash = ""
    for row in cursor.fetchall():
        row_id = row[0]
        workspace_id = row[1] or ""
        method = row[2] or ""
        path = row[3] or ""
        status_code = int(row[4] or 0)
        role = row[5] or ""
        client_ip = row[6] or ""
        detail = row[7] or ""
        prev_hash = row[8] or ""
        stored_hash = row[9] or ""
        # Legacy rows (pre-hash-chain) have empty prev_hash/row_hash —
        # the chain starts at the first row with a non-empty row_hash.
        if not stored_hash and not prev_hash:
            rows_checked += 1
            continue
        chain_payload = "|".join(
            [
                last_hash,
                str(workspace_id),
                str(method),
                str(path),
                str(status_code),
                str(role),
                str(client_ip),
                str(detail),
            ]
        )
        expected = hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()
        if prev_hash != last_hash or stored_hash != expected:
            return {
                "ok": False,
                "broken_at_id": int(row_id),
                "rows_checked": rows_checked,
                "expected_hash": expected,
                "stored_hash": stored_hash,
                "expected_prev": last_hash,
                "stored_prev": prev_hash,
            }
        last_hash = stored_hash
        rows_checked += 1
    return {"ok": True, "rows_checked": rows_checked, "tip": last_hash}


def get_action_audits(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM action_audit_log WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM action_audit_log ORDER BY created_at DESC")


def log_external_request(
    conn,
    service: str,
    method: str,
    target: str,
    status: str,
    detail: str = "",
    workspace_id: str = "default",
):
    conn.execute(
        """
        INSERT INTO external_request_log (workspace_id, service, method, target, status, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, service, method, target, status, detail),
    )
    conn.commit()


def get_external_requests(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM external_request_log WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM external_request_log ORDER BY created_at DESC")


def create_case_record(
    conn,
    title: str,
    workspace_id: str = "default",
    incident_id: str = "",
    priority: str = "medium",
    stage: str = "triage",
    owner: str = "",
    sla_deadline: float = 0,
    asset_criticality: float = 0,
    tags_json: str = "[]",
    approvers_json: str = "[]",
    narrative: str = "",
    status: str = "open",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO case_records (
            workspace_id, incident_id, title, priority, stage, owner, sla_deadline, asset_criticality,
            tags_json, approvers_json, narrative, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            workspace_id,
            incident_id,
            title,
            priority,
            stage,
            owner,
            sla_deadline,
            asset_criticality,
            tags_json,
            approvers_json,
            narrative,
            status,
        ),
    )


def update_case_record(conn, case_id: int, **fields) -> None:
    _ALLOWED_CASE_COLUMNS = {
        "incident_id", "title", "priority", "stage", "owner",
        "sla_deadline", "asset_criticality", "tags_json",
        "approvers_json", "narrative", "status",
    }
    updates = []
    values = []
    for key, value in fields.items():
        if key not in _ALLOWED_CASE_COLUMNS:
            raise ValueError(f"Invalid column: {key}")
        updates.append(f"{key} = ?")
        values.append(value)
    updates.append(f"updated_at = ({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})")
    values.append(case_id)
    conn.execute(f"UPDATE case_records SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()


def get_case_records(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(
            conn,
            "SELECT * FROM case_records WHERE workspace_id = ? ORDER BY updated_at DESC, created_at DESC",
            (workspace_id,),
        )
    return _read_sql_query(conn, "SELECT * FROM case_records ORDER BY updated_at DESC, created_at DESC")


def log_evidence_chain(
    conn,
    case_id: int,
    event_type: str,
    actor: str = "",
    artifact_path: str = "",
    artifact_hash: str = "",
    notes: str = "",
):
    conn.execute(
        """
        INSERT INTO evidence_chain_log (case_id, event_type, actor, artifact_path, artifact_hash, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, event_type, actor, artifact_path, artifact_hash, notes),
    )
    conn.commit()


def get_evidence_chain(conn, case_id: int) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM evidence_chain_log WHERE case_id = ? ORDER BY created_at ASC", (case_id,))


def create_investigation_view(
    conn,
    *,
    name: str,
    description: str = "",
    query_text: str = "",
    filters_json: str = "{}",
    case_id: int | None = None,
    created_by: str = "",
) -> int:
    backend = getattr(conn, "backend", "sqlite")
    now_sql = _epoch_now_sql(backend)
    return _insert_returning_id(
        conn,
        f"""
        INSERT INTO investigation_views (
            name, description, query_text, filters_json, case_id, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, {now_sql}, {now_sql})
        """,
        (name, description, query_text, filters_json, case_id, created_by),
    )


def get_investigation_views(conn, case_id: int | None = None) -> pd.DataFrame:
    if case_id is None:
        return _read_sql_query(conn, "SELECT * FROM investigation_views ORDER BY updated_at DESC, created_at DESC")
    return _read_sql_query(
        conn,
        "SELECT * FROM investigation_views WHERE case_id = ? ORDER BY updated_at DESC, created_at DESC",
        (case_id,),
    )


def create_investigation_note(
    conn,
    *,
    note_text: str,
    case_id: int | None = None,
    view_id: int | None = None,
    item_time: float = 0,
    item_type: str = "",
    item_title: str = "",
    tags_json: str = "[]",
    author: str = "",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO investigation_notes (
            case_id, view_id, item_time, item_type, item_title, note_text, tags_json, author
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (case_id, view_id, item_time, item_type, item_title, note_text, tags_json, author),
    )


def get_investigation_notes(conn, case_id: int | None = None, view_id: int | None = None) -> pd.DataFrame:
    sql = "SELECT * FROM investigation_notes"
    clauses: list[str] = []
    params: list[Any] = []
    if case_id is not None:
        clauses.append("case_id = ?")
        params.append(case_id)
    if view_id is not None:
        clauses.append("view_id = ?")
        params.append(view_id)
    if clauses:
        sql = f"{sql} WHERE {' AND '.join(clauses)}"
    sql = f"{sql} ORDER BY created_at DESC"
    return _read_sql_query(conn, sql, tuple(params) if params else None)


def create_investigation_story(
    conn,
    *,
    title: str,
    hypothesis: str = "",
    summary: str = "",
    confidence: str = "medium",
    tags_json: str = "[]",
    case_id: int | None = None,
    created_by: str = "",
) -> int:
    backend = getattr(conn, "backend", "sqlite")
    now_sql = _epoch_now_sql(backend)
    return _insert_returning_id(
        conn,
        f"""
        INSERT INTO investigation_stories (
            case_id, title, hypothesis, summary, confidence, tags_json, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, {now_sql}, {now_sql})
        """,
        (case_id, title, hypothesis, summary, confidence, tags_json, created_by),
    )


def get_investigation_stories(conn, case_id: int | None = None) -> pd.DataFrame:
    if case_id is None:
        return _read_sql_query(conn, "SELECT * FROM investigation_stories ORDER BY updated_at DESC, created_at DESC")
    return _read_sql_query(
        conn,
        "SELECT * FROM investigation_stories WHERE case_id = ? ORDER BY updated_at DESC, created_at DESC",
        (case_id,),
    )


def create_investigation_pin(
    conn,
    *,
    case_id: int | None = None,
    view_id: int | None = None,
    item_time: float = 0,
    item_type: str = "",
    item_title: str = "",
    item_severity: str = "",
    item_payload_json: str = "{}",
    rationale: str = "",
    pinned_by: str = "",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO investigation_pins (
            case_id, view_id, item_time, item_type, item_title, item_severity, item_payload_json, rationale, pinned_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (case_id, view_id, item_time, item_type, item_title, item_severity, item_payload_json, rationale, pinned_by),
    )


def get_investigation_pins(conn, case_id: int | None = None, view_id: int | None = None) -> pd.DataFrame:
    sql = "SELECT * FROM investigation_pins"
    clauses: list[str] = []
    params: list[Any] = []
    if case_id is not None:
        clauses.append("case_id = ?")
        params.append(case_id)
    if view_id is not None:
        clauses.append("view_id = ?")
        params.append(view_id)
    if clauses:
        sql = f"{sql} WHERE {' AND '.join(clauses)}"
    sql = f"{sql} ORDER BY created_at DESC"
    return _read_sql_query(conn, sql, tuple(params) if params else None)


def create_case_assignment(
    conn,
    *,
    case_id: int,
    analyst: str,
    role: str = "owner",
    status: str = "active",
    assigned_by: str = "",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO case_assignments (case_id, analyst, role, status, assigned_by)
        VALUES (?, ?, ?, ?, ?)
        """,
        (case_id, analyst, role, status, assigned_by),
    )


def get_case_assignments(conn, case_id: int) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM case_assignments WHERE case_id = ? ORDER BY created_at DESC", (case_id,))


def create_case_task(
    conn,
    *,
    case_id: int,
    title: str,
    description: str = "",
    status: str = "todo",
    priority: str = "medium",
    assigned_to: str = "",
    due_at: float = 0,
    created_by: str = "",
) -> int:
    backend = getattr(conn, "backend", "sqlite")
    now_sql = _epoch_now_sql(backend)
    return _insert_returning_id(
        conn,
        f"""
        INSERT INTO case_tasks (
            case_id, title, description, status, priority, assigned_to, due_at, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, {now_sql}, {now_sql})
        """,
        (case_id, title, description, status, priority, assigned_to, due_at, created_by),
    )


def get_case_tasks(conn, case_id: int) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM case_tasks WHERE case_id = ? ORDER BY updated_at DESC, created_at DESC", (case_id,))


def update_case_task(
    conn,
    task_id: int,
    *,
    status: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    due_at: float | None = None,
) -> None:
    updates = [f"updated_at = ({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})"]
    values: list[Any] = []
    if status is not None:
        updates.append("status = ?")
        values.append(status)
    if priority is not None:
        updates.append("priority = ?")
        values.append(priority)
    if assigned_to is not None:
        updates.append("assigned_to = ?")
        values.append(assigned_to)
    if due_at is not None:
        updates.append("due_at = ?")
        values.append(float(due_at))
    values.append(int(task_id))
    conn.execute(f"UPDATE case_tasks SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()


def log_case_activity(
    conn,
    *,
    workspace_id: str = "default",
    case_id: int,
    event_type: str,
    actor: str = "",
    summary: str = "",
    detail_json: str = "{}",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO case_activity_log (workspace_id, case_id, event_type, actor, summary, detail_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, case_id, event_type, actor, summary, detail_json),
    )


def get_case_activity(conn, case_id: int, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(
            conn,
            "SELECT * FROM case_activity_log WHERE case_id = ? AND workspace_id = ? ORDER BY created_at DESC",
            (case_id, workspace_id),
        )
    return _read_sql_query(conn, "SELECT * FROM case_activity_log WHERE case_id = ? ORDER BY created_at DESC", (case_id,))


def create_approval_request(
    conn,
    case_id: int,
    action: str,
    requested_by: str = "",
    approver: str = "",
    reason: str = "",
    expires_at: float = 0,
    workspace_id: str = "default",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO approval_requests (workspace_id, case_id, action, requested_by, approver, reason, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, case_id, action, requested_by, approver, reason, float(expires_at)),
    )


def resolve_approval_request(conn, approval_id: int, status: str, approver: str = "") -> None:
    conn.execute(
        f"""
        UPDATE approval_requests
        SET status = ?, approver = ?, resolved_at = ({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})
        WHERE id = ?
        """,
        (status, approver, approval_id),
    )
    conn.commit()


def get_approval_requests(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM approval_requests WHERE workspace_id = ? ORDER BY created_at DESC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM approval_requests ORDER BY created_at DESC")


def mark_approval_used(conn, approval_id: int, used_at: float) -> None:
    conn.execute(
        """
        UPDATE approval_requests
        SET used_at = ?
        WHERE id = ?
        """,
        (float(used_at), int(approval_id)),
    )
    conn.commit()


def reserve_approval_request(conn, approval_id: int, action: str, now_value: float, workspace_id: str = "") -> bool:
    workspace_clause = " AND workspace_id = ?" if workspace_id else ""
    params: list[Any] = [int(approval_id), str(action or ""), float(now_value)]
    if workspace_id:
        params.append(workspace_id)
    cursor = conn.execute(
        f"""
        UPDATE approval_requests
        SET used_at = -1
        WHERE id = ?
          AND LOWER(TRIM(action)) = LOWER(TRIM(?))
          AND LOWER(TRIM(status)) IN ('approved', 'allow', 'granted')
          AND COALESCE(used_at, 0) = 0
          AND (COALESCE(expires_at, 0) = 0 OR expires_at >= ?)
          {workspace_clause}
        """,
        tuple(params),
    )
    conn.commit()
    return bool(getattr(cursor, "rowcount", 0))


def finalize_approval_request(conn, approval_id: int, used_at: float) -> bool:
    cursor = conn.execute(
        """
        UPDATE approval_requests
        SET used_at = ?
        WHERE id = ? AND used_at = -1
        """,
        (float(used_at), int(approval_id)),
    )
    conn.commit()
    return bool(getattr(cursor, "rowcount", 0))


def release_approval_request(conn, approval_id: int) -> bool:
    cursor = conn.execute(
        """
        UPDATE approval_requests
        SET used_at = 0
        WHERE id = ? AND used_at = -1
        """,
        (int(approval_id),),
    )
    conn.commit()
    return bool(getattr(cursor, "rowcount", 0))


def upsert_detection_rule(
    conn,
    rule_id: str,
    version: str = "1.0.0",
    status: str = "active",
    tuning_json: str = "{}",
    suppression_json: str = "{}",
    notes: str = "",
):
    conn.execute(
        f"""
        INSERT INTO detection_rule_registry (rule_id, version, status, tuning_json, suppression_json, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_id) DO UPDATE SET
            version=excluded.version,
            status=excluded.status,
            tuning_json=excluded.tuning_json,
            suppression_json=excluded.suppression_json,
            notes=excluded.notes,
            updated_at=({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})
        """,
        (rule_id, version, status, tuning_json, suppression_json, notes),
    )
    conn.commit()


def get_detection_rules(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM detection_rule_registry ORDER BY rule_id ASC")


def log_false_positive_feedback(conn, rule_id: str, incident_id: str = "", actor: str = "", reason: str = "") -> None:
    conn.execute(
        """
        INSERT INTO false_positive_feedback (rule_id, incident_id, actor, reason)
        VALUES (?, ?, ?, ?)
        """,
        (rule_id, incident_id, actor, reason),
    )
    conn.commit()


def get_false_positive_feedback(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM false_positive_feedback ORDER BY created_at DESC")


def upsert_connector(conn, name: str, kind: str, enabled: bool, config_json: str = "{}", workspace_id: str = "default") -> None:
    normalized_name = str(name or "").strip().lower()
    normalized_workspace = str(workspace_id or "default").strip().lower() or "default"
    existing = conn.execute(
        "SELECT id FROM connector_registry WHERE name = ? AND workspace_id = ?",
        (normalized_name, normalized_workspace),
    ).fetchone()
    if existing is None:
        conn.execute(
            """
            INSERT INTO connector_registry (name, workspace_id, kind, enabled, config_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (normalized_name, normalized_workspace, kind, 1 if enabled else 0, config_json),
        )
    else:
        conn.execute(
            f"""
            UPDATE connector_registry
            SET kind = ?, enabled = ?, config_json = ?, updated_at = ({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})
            WHERE name = ? AND workspace_id = ?
            """,
            (kind, 1 if enabled else 0, config_json, normalized_name, normalized_workspace),
        )
    conn.commit()


def get_connectors(conn, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(conn, "SELECT * FROM connector_registry WHERE workspace_id = ? ORDER BY name ASC", (workspace_id,))
    return _read_sql_query(conn, "SELECT * FROM connector_registry ORDER BY name ASC")


def set_app_setting(conn, key: str, value: str) -> None:
    conn.execute(
        f"""
        INSERT INTO app_settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value=excluded.value,
            updated_at=({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})
        """,
        (key, value),
    )
    conn.commit()


def get_app_setting(conn, key: str) -> str:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return ""
    return str(row[0] or "")


def revoke_identity_token(
    conn,
    *,
    issuer: str,
    subject: str,
    token_id: str = "",
    workspace_id: str = "default",
    actor: str = "",
    reason: str = "",
    expires_at: float = 0,
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO identity_revocation_log (
            issuer, subject, token_id, workspace_id, actor, reason, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (issuer, subject, token_id, workspace_id, actor, reason, float(expires_at or 0)),
    )


def get_identity_revocations(conn, workspace_id: str = "", subject: str = "", issuer: str = "") -> pd.DataFrame:
    clauses: list[str] = []
    params: list[Any] = []
    if workspace_id:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    if subject:
        clauses.append("subject = ?")
        params.append(subject)
    if issuer:
        clauses.append("issuer = ?")
        params.append(issuer)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return _read_sql_query(
        conn,
        f"SELECT * FROM identity_revocation_log {where} ORDER BY created_at DESC",
        tuple(params),
    )


def is_identity_token_revoked(
    conn,
    *,
    issuer: str,
    subject: str,
    token_id: str = "",
    issued_at: float = 0,
) -> bool:
    now_value = float(time.time())
    rows = get_identity_revocations(conn, subject=subject, issuer=issuer).fillna("").to_dict(orient="records")
    token_value = str(token_id or "").strip()
    issued_value = float(issued_at or 0)
    for item in rows:
        expires_at = float(item.get("expires_at", 0) or 0)
        if expires_at and expires_at < now_value:
            continue
        revoked_token = str(item.get("token_id", "") or "").strip()
        if revoked_token and token_value and revoked_token == token_value:
            return True
        if not revoked_token and issued_value and float(item.get("created_at", 0) or 0) >= issued_value:
            return True
    return False


def log_yara_scan(
    conn,
    *,
    target_path: str,
    pack: str,
    scope: str,
    status: str,
    match_count: int,
    suppressed_count: int,
    compile_error_count: int,
    source_counts_json: str = "{}",
    matched_rules_json: str = "[]",
    errors_json: str = "[]",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO yara_scan_log (
            target_path, pack, scope, status, match_count, suppressed_count, compile_error_count,
            source_counts_json, matched_rules_json, errors_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_path,
            pack,
            scope,
            status,
            int(match_count),
            int(suppressed_count),
            int(compile_error_count),
            source_counts_json,
            matched_rules_json,
            errors_json,
        ),
    )


def log_yara_rule_hit(
    conn,
    *,
    rule_id: str,
    source: str,
    source_path: str,
    pack: str,
    scope: str,
    severity: str,
    confidence: str,
    score: int,
    suppressed: bool,
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO yara_rule_hit_log (
            rule_id, source, source_path, pack, scope, severity, confidence, score, suppressed
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rule_id,
            source,
            source_path,
            pack,
            scope,
            severity,
            confidence,
            int(score),
            1 if suppressed else 0,
        ),
    )


def get_yara_scan_log(conn, limit: int = 100) -> pd.DataFrame:
    return _read_sql_query(
        conn,
        "SELECT * FROM yara_scan_log ORDER BY created_at DESC LIMIT ?",
        (int(limit),),
    )


def get_yara_rule_hits(conn, limit: int = 250) -> pd.DataFrame:
    return _read_sql_query(
        conn,
        "SELECT * FROM yara_rule_hit_log ORDER BY created_at DESC LIMIT ?",
        (int(limit),),
    )


def get_schema_migrations(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM schema_migrations ORDER BY applied_at ASC")


def log_secret_rotation(conn, secret_name: str, action: str, actor: str = "", detail: str = "") -> None:
    conn.execute(
        """
        INSERT INTO secret_rotation_log (secret_name, action, actor, detail)
        VALUES (?, ?, ?, ?)
        """,
        (secret_name, action, actor, detail),
    )
    conn.commit()


def get_secret_rotations(conn, limit: int = 100) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM secret_rotation_log ORDER BY created_at DESC LIMIT ?", (int(limit),))


def enqueue_connector_delivery(
    conn,
    connector_name: str,
    event_type: str,
    payload_json: str,
    status: str = "pending",
    attempts: int = 0,
    next_retry_at: float = 0,
    last_error: str = "",
    workspace_id: str = "default",
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO connector_delivery_queue (
            workspace_id, connector_name, event_type, payload_json, status, attempts, next_retry_at, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (workspace_id, connector_name, event_type, payload_json, status, attempts, next_retry_at, last_error),
    )


def get_connector_delivery_queue(conn, status: str = "", limit: int = 200, workspace_id: str = "") -> pd.DataFrame:
    if status:
        if workspace_id:
            return _read_sql_query(
                conn,
                """
                SELECT * FROM connector_delivery_queue
                WHERE status = ? AND workspace_id = ?
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (status, workspace_id, int(limit)),
            )
        return _read_sql_query(
            conn,
            """
            SELECT * FROM connector_delivery_queue
            WHERE status = ?
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (status, int(limit)),
        )
    if workspace_id:
        return _read_sql_query(
            conn,
            """
            SELECT * FROM connector_delivery_queue
            WHERE workspace_id = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (workspace_id, int(limit)),
        )
    return _read_sql_query(
        conn,
        """
        SELECT * FROM connector_delivery_queue
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        (int(limit),),
    )


def get_pending_connector_deliveries(conn, now_ts: float, limit: int = 50, workspace_id: str = "") -> pd.DataFrame:
    if workspace_id:
        return _read_sql_query(
            conn,
            """
            SELECT * FROM connector_delivery_queue
            WHERE status IN ('pending', 'retry')
              AND workspace_id = ?
              AND (next_retry_at IS NULL OR next_retry_at <= ?)
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (workspace_id, float(now_ts), int(limit)),
        )
    return _read_sql_query(
        conn,
        """
        SELECT * FROM connector_delivery_queue
        WHERE status IN ('pending', 'retry')
          AND (next_retry_at IS NULL OR next_retry_at <= ?)
        ORDER BY updated_at ASC
        LIMIT ?
        """,
        (float(now_ts), int(limit)),
    )


def update_connector_delivery(
    conn,
    queue_id: int,
    *,
    status: str,
    attempts: int | None = None,
    next_retry_at: float | None = None,
    last_error: str | None = None,
) -> None:
    updates = ["status = ?", f"updated_at = ({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})"]
    values: list[Any] = [status]
    if attempts is not None:
        updates.append("attempts = ?")
        values.append(int(attempts))
    if next_retry_at is not None:
        updates.append("next_retry_at = ?")
        values.append(float(next_retry_at))
    if last_error is not None:
        updates.append("last_error = ?")
        values.append(last_error)
    values.append(int(queue_id))
    conn.execute(f"UPDATE connector_delivery_queue SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()


def purge_old_records(conn, retention_days: dict[str, int]) -> dict[str, int]:
    purged: dict[str, int] = {}
    table_time_columns = {
        "telemetry": "ts",
        "response_log": "timestamp",
        "incidents": "created_at",
        "alert_log": "created_at",
        "remediation_log": "created_at",
        "integration_export_log": "created_at",
        "auth_log": "created_at",
        "action_audit_log": "created_at",
        "external_request_log": "created_at",
        "case_records": "created_at",
        "evidence_chain_log": "created_at",
        "approval_requests": "created_at",
        "false_positive_feedback": "created_at",
        "connector_delivery_queue": "created_at",
    }
    now = pd.Timestamp.utcnow().timestamp()
    for table, days in retention_days.items():
        column = table_time_columns.get(table)
        if not column or days <= 0:
            continue
        threshold = now - (int(days) * 86400)
        if table == "response_log":
            predicate = (
                f"EXTRACT(EPOCH FROM {column}) < ?"
                if getattr(conn, "backend", "sqlite") == "postgresql"
                else f"strftime('%s', {column}) < ?"
            )
            cursor = conn.execute(
                f"DELETE FROM {table} WHERE {predicate}",
                (float(threshold),),
            )
        else:
            cursor = conn.execute(
                f"DELETE FROM {table} WHERE {column} > 0 AND {column} < ?",
                (float(threshold),),
            )
        purged[table] = int(cursor.rowcount or 0)
    conn.commit()
    return purged


def get_incident_by_id(conn, incident_id: str, workspace_id: str = "") -> dict[str, Any] | None:
    if workspace_id:
        row = conn.execute(
            """
            SELECT incident_id, workspace_id, created_at, severity, title, summary, status, notes, owner,
                   recommended_actions, attack_chain, mitre_mapping, correlation_story
            FROM incidents
            WHERE incident_id = ? AND workspace_id = ?
            """,
            (incident_id, workspace_id),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT incident_id, workspace_id, created_at, severity, title, summary, status, notes, owner,
                   recommended_actions, attack_chain, mitre_mapping, correlation_story
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()
    if row is None:
        return None

    columns = [
        "incident_id",
        "workspace_id",
        "created_at",
        "severity",
        "title",
        "summary",
        "status",
        "notes",
        "owner",
        "recommended_actions",
        "attack_chain",
        "mitre_mapping",
        "correlation_story",
    ]
    return dict(zip(columns, row))


def init_db():
    conn = create_connection()
    if conn:
        create_table(conn)
        conn.close()
