import sqlite3
from typing import Any

import pandas as pd

DB_FILE = "shadowlab.db"


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
    except sqlite3.Error as exc:
        print(exc)
    return conn


def create_table(conn):
    try:
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

        _ensure_column(conn, "incidents", "attack_chain", "TEXT DEFAULT ''")
        _ensure_column(conn, "incidents", "mitre_mapping", "TEXT DEFAULT ''")
        _ensure_column(conn, "incidents", "correlation_story", "TEXT DEFAULT ''")
        _ensure_column(conn, "telemetry", "remote_ips", "TEXT DEFAULT ''")
    except sqlite3.Error as exc:
        print(exc)


def _ensure_column(conn, table: str, column: str, definition: str):
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def insert_telemetry(conn, telemetry_data: list[dict]):
    try:
        normalized = []
        for row in telemetry_data:
            item = dict(row)
            item["remote_ips"] = str(item.get("remote_ips", []))
            normalized.append(item)
        df = pd.DataFrame(normalized)
        df.to_sql("telemetry", conn, if_exists="append", index=False)
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
    return pd.read_sql_query("SELECT * FROM response_log ORDER BY timestamp DESC", conn)


def get_historical_data(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM telemetry", conn)


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
    return pd.read_sql_query("SELECT * FROM incidents ORDER BY created_at DESC", conn)


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
    return pd.read_sql_query("SELECT * FROM quarantine_log ORDER BY created_at DESC", conn)


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
    return pd.read_sql_query("SELECT * FROM host_inventory ORDER BY last_seen DESC", conn)


def log_alert(conn, destination: str, destination_type: str, severity: str, title: str, status: str, detail: str):
    conn.execute(
        "INSERT INTO alert_log (destination, destination_type, severity, title, status, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (destination, destination_type, severity, title, status, detail),
    )
    conn.commit()


def get_alerts(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM alert_log ORDER BY created_at DESC", conn)


def log_remediation(conn, item_type: str, target: str, backup_path: str = "", rollback_data: str = "", status: str = "applied") -> int:
    cursor = conn.execute(
        "INSERT INTO remediation_log (item_type, target, backup_path, rollback_data, status) VALUES (?, ?, ?, ?, ?)",
        (item_type, target, backup_path, rollback_data, status),
    )
    conn.commit()
    return int(cursor.lastrowid)


def update_remediation_status(conn, remediation_id: int, status: str):
    conn.execute("UPDATE remediation_log SET status = ? WHERE id = ?", (status, remediation_id))
    conn.commit()


def get_remediations(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM remediation_log ORDER BY created_at DESC", conn)


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
    return pd.read_sql_query("SELECT * FROM integration_export_log ORDER BY created_at DESC", conn)


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
