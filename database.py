from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

import pandas as pd

DEFAULT_DB_FILE = "shadowlab.db"


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
    translated = translated.replace("?", "%s")
    translated = translated.replace("(strftime('%s', 'now'))", "EXTRACT(EPOCH FROM NOW())")
    translated = translated.replace("strftime('%s', 'now')", "EXTRACT(EPOCH FROM NOW())")
    translated = translated.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    translated = translated.replace("DATETIME DEFAULT CURRENT_TIMESTAMP", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    translated = translated.replace("REAL DEFAULT (EXTRACT(EPOCH FROM NOW()))", "DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())")
    return translated


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
        print(exc)
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
            CREATE TABLE IF NOT EXISTS action_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER,
                role TEXT DEFAULT '',
                client_ip TEXT DEFAULT '',
                detail TEXT DEFAULT ''
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS external_request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL DEFAULT (strftime('%s', 'now')),
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
                name TEXT NOT NULL UNIQUE,
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
        _ensure_column(conn, "telemetry", "remote_ips", "TEXT DEFAULT ''")
        _ensure_column(conn, "approval_requests", "expires_at", "REAL DEFAULT 0")
        _ensure_column(conn, "approval_requests", "used_at", "REAL DEFAULT 0")
        _ensure_indexes(conn)
        _record_migration(conn, "2026_03_backend_hardening")
    except sqlite3.Error as exc:
        print(exc)


def _ensure_column(conn, table: str, column: str, definition: str):
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


def _create_table_postgres(conn) -> None:
    statements = [
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id BIGSERIAL PRIMARY KEY,
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
            event_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            role TEXT DEFAULT '',
            client_ip TEXT DEFAULT '',
            path TEXT DEFAULT '',
            detail TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS action_audit_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER,
            role TEXT DEFAULT '',
            client_ip TEXT DEFAULT '',
            detail TEXT DEFAULT ''
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS external_request_log (
            id BIGSERIAL PRIMARY KEY,
            created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
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
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            enabled INTEGER DEFAULT 0,
            config_json TEXT DEFAULT '{}',
            updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS connector_delivery_queue (
            id BIGSERIAL PRIMARY KEY,
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
    _ensure_indexes(conn)
    _record_migration(conn, "2026_03_backend_hardening")


def _ensure_indexes(conn) -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_auth_log_created_at ON auth_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_action_audit_created_at ON action_audit_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_external_request_created_at ON external_request_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alert_log_created_at ON alert_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_connector_queue_status_retry ON connector_delivery_queue(status, next_retry_at, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_approval_status_created_at ON approval_requests(status, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_secret_rotation_created_at ON secret_rotation_log(created_at DESC)",
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


def insert_telemetry(conn, telemetry_data: list[dict]):
    try:
        rows = []
        for row in telemetry_data:
            item = dict(row)
            rows.append(
                (
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
                    ts, cpu, mem_percent, proc_threads, proc_handles,
                    open_files, tcp_conns, bytes_sent_rate, bytes_recv_rate, remote_ips
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
    except Exception as exc:
        print(exc)


def log_response_action(conn, action, pid, process_name, details=""):
    try:
        conn.execute(
            "INSERT INTO response_log (action, pid, process_name, details) VALUES (?, ?, ?, ?)",
            (action, pid, process_name, details),
        )
        conn.commit()
    except Exception as exc:
        print(f"Log Error: {exc}")


def get_response_logs(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM response_log ORDER BY timestamp DESC")


def get_historical_data(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM telemetry")


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
):
    try:
        conn.execute(
            """
            INSERT INTO incidents (
                incident_id, created_at, severity, title, summary, status, notes, owner,
                recommended_actions, attack_chain, mitre_mapping, correlation_story
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
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


def get_incidents(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM incidents ORDER BY created_at DESC")


def log_quarantine(conn, pid, process_name, original_path, quarantine_path, status="active"):
    conn.execute(
        "INSERT INTO quarantine_log (pid, process_name, original_path, quarantine_path, status) VALUES (?, ?, ?, ?, ?)",
        (pid, process_name, original_path, quarantine_path, status),
    )
    conn.commit()


def update_quarantine(conn, quarantine_id, status):
    conn.execute("UPDATE quarantine_log SET status = ? WHERE id = ?", (status, quarantine_id))
    conn.commit()


def get_quarantine(conn) -> pd.DataFrame:
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
):
    conn.execute(
        """
        INSERT INTO host_inventory (host_id, host, platform, role, ip_address, api_status, agent_version, boot_time, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(host_id) DO UPDATE SET
            host=excluded.host,
            platform=excluded.platform,
            role=excluded.role,
            ip_address=excluded.ip_address,
            api_status=excluded.api_status,
            agent_version=excluded.agent_version,
            boot_time=excluded.boot_time,
            last_seen=excluded.last_seen
        """,
        (host_id, host, platform, role, ip_address, api_status, agent_version, boot_time, last_seen),
    )
    conn.commit()


def get_hosts(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM host_inventory ORDER BY last_seen DESC")


def log_alert(conn, destination: str, destination_type: str, severity: str, title: str, status: str, detail: str):
    conn.execute(
        "INSERT INTO alert_log (destination, destination_type, severity, title, status, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (destination, destination_type, severity, title, status, detail),
    )
    conn.commit()


def get_alerts(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM alert_log ORDER BY created_at DESC")


def log_remediation(conn, item_type: str, target: str, backup_path: str = "", rollback_data: str = "", status: str = "applied") -> int:
    return _insert_returning_id(
        conn,
        "INSERT INTO remediation_log (item_type, target, backup_path, rollback_data, status) VALUES (?, ?, ?, ?, ?)",
        (item_type, target, backup_path, rollback_data, status),
    )


def update_remediation_status(conn, remediation_id: int, status: str):
    conn.execute("UPDATE remediation_log SET status = ? WHERE id = ?", (status, remediation_id))
    conn.commit()


def get_remediations(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM remediation_log ORDER BY created_at DESC")


def log_integration_export(
    conn,
    integration_name: str,
    export_type: str,
    target: str,
    status: str,
    detail: str,
):
    conn.execute(
        """
        INSERT INTO integration_export_log (integration_name, export_type, target, status, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (integration_name, export_type, target, status, detail),
    )
    conn.commit()


def get_integration_exports(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM integration_export_log ORDER BY created_at DESC")


def log_auth_event(
    conn,
    event_type: str,
    outcome: str,
    role: str = "",
    client_ip: str = "",
    path: str = "",
    detail: str = "",
):
    conn.execute(
        """
        INSERT INTO auth_log (event_type, outcome, role, client_ip, path, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (event_type, outcome, role, client_ip, path, detail),
    )
    conn.commit()


def get_auth_logs(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM auth_log ORDER BY created_at DESC")


def log_action_audit(
    conn,
    method: str,
    path: str,
    status_code: int,
    role: str = "",
    client_ip: str = "",
    detail: str = "",
):
    conn.execute(
        """
        INSERT INTO action_audit_log (method, path, status_code, role, client_ip, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (method, path, status_code, role, client_ip, detail),
    )
    conn.commit()


def get_action_audits(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM action_audit_log ORDER BY created_at DESC")


def log_external_request(
    conn,
    service: str,
    method: str,
    target: str,
    status: str,
    detail: str = "",
):
    conn.execute(
        """
        INSERT INTO external_request_log (service, method, target, status, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (service, method, target, status, detail),
    )
    conn.commit()


def get_external_requests(conn) -> pd.DataFrame:
    return _read_sql_query(conn, "SELECT * FROM external_request_log ORDER BY created_at DESC")


def create_case_record(
    conn,
    title: str,
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
            incident_id, title, priority, stage, owner, sla_deadline, asset_criticality,
            tags_json, approvers_json, narrative, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
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


def get_case_records(conn) -> pd.DataFrame:
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


def create_approval_request(
    conn,
    case_id: int,
    action: str,
    requested_by: str = "",
    approver: str = "",
    reason: str = "",
    expires_at: float = 0,
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO approval_requests (case_id, action, requested_by, approver, reason, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, action, requested_by, approver, reason, float(expires_at)),
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


def get_approval_requests(conn) -> pd.DataFrame:
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


def upsert_connector(conn, name: str, kind: str, enabled: bool, config_json: str = "{}") -> None:
    conn.execute(
        f"""
        INSERT INTO connector_registry (name, kind, enabled, config_json)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            kind=excluded.kind,
            enabled=excluded.enabled,
            config_json=excluded.config_json,
            updated_at=({_epoch_now_sql(getattr(conn, 'backend', 'sqlite'))})
        """,
        (name, kind, 1 if enabled else 0, config_json),
    )
    conn.commit()


def get_connectors(conn) -> pd.DataFrame:
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
) -> int:
    return _insert_returning_id(
        conn,
        """
        INSERT INTO connector_delivery_queue (
            connector_name, event_type, payload_json, status, attempts, next_retry_at, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (connector_name, event_type, payload_json, status, attempts, next_retry_at, last_error),
    )


def get_connector_delivery_queue(conn, status: str = "", limit: int = 200) -> pd.DataFrame:
    if status:
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
    return _read_sql_query(
        conn,
        """
        SELECT * FROM connector_delivery_queue
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        (int(limit),),
    )


def get_pending_connector_deliveries(conn, now_ts: float, limit: int = 50) -> pd.DataFrame:
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


def get_incident_by_id(conn, incident_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT incident_id, created_at, severity, title, summary, status, notes, owner,
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
