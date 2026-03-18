import sqlite3
from typing import Any

import pandas as pd

DB_FILE = "shadowlab.db"


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
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
                resolved_at REAL DEFAULT 0
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
    return pd.read_sql_query("SELECT * FROM auth_log ORDER BY created_at DESC", conn)


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
    return pd.read_sql_query("SELECT * FROM action_audit_log ORDER BY created_at DESC", conn)


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
    return pd.read_sql_query("SELECT * FROM external_request_log ORDER BY created_at DESC", conn)


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
    cursor = conn.execute(
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
    conn.commit()
    return int(cursor.lastrowid)


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
    updates.append("updated_at = (strftime('%s', 'now'))")
    values.append(case_id)
    conn.execute(f"UPDATE case_records SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()


def get_case_records(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM case_records ORDER BY updated_at DESC, created_at DESC", conn)


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
    return pd.read_sql_query(
        "SELECT * FROM evidence_chain_log WHERE case_id = ? ORDER BY created_at ASC",
        conn,
        params=(case_id,),
    )


def create_approval_request(conn, case_id: int, action: str, requested_by: str = "", approver: str = "", reason: str = "") -> int:
    cursor = conn.execute(
        """
        INSERT INTO approval_requests (case_id, action, requested_by, approver, reason)
        VALUES (?, ?, ?, ?, ?)
        """,
        (case_id, action, requested_by, approver, reason),
    )
    conn.commit()
    return int(cursor.lastrowid)


def resolve_approval_request(conn, approval_id: int, status: str, approver: str = "") -> None:
    conn.execute(
        """
        UPDATE approval_requests
        SET status = ?, approver = ?, resolved_at = (strftime('%s', 'now'))
        WHERE id = ?
        """,
        (status, approver, approval_id),
    )
    conn.commit()


def get_approval_requests(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM approval_requests ORDER BY created_at DESC", conn)


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
        """
        INSERT INTO detection_rule_registry (rule_id, version, status, tuning_json, suppression_json, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_id) DO UPDATE SET
            version=excluded.version,
            status=excluded.status,
            tuning_json=excluded.tuning_json,
            suppression_json=excluded.suppression_json,
            notes=excluded.notes,
            updated_at=(strftime('%s', 'now'))
        """,
        (rule_id, version, status, tuning_json, suppression_json, notes),
    )
    conn.commit()


def get_detection_rules(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM detection_rule_registry ORDER BY rule_id ASC", conn)


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
    return pd.read_sql_query("SELECT * FROM false_positive_feedback ORDER BY created_at DESC", conn)


def upsert_connector(conn, name: str, kind: str, enabled: bool, config_json: str = "{}") -> None:
    conn.execute(
        """
        INSERT INTO connector_registry (name, kind, enabled, config_json)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            kind=excluded.kind,
            enabled=excluded.enabled,
            config_json=excluded.config_json,
            updated_at=(strftime('%s', 'now'))
        """,
        (name, kind, 1 if enabled else 0, config_json),
    )
    conn.commit()


def get_connectors(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM connector_registry ORDER BY name ASC", conn)


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
    cursor = conn.execute(
        """
        INSERT INTO connector_delivery_queue (
            connector_name, event_type, payload_json, status, attempts, next_retry_at, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (connector_name, event_type, payload_json, status, attempts, next_retry_at, last_error),
    )
    conn.commit()
    return int(cursor.lastrowid)


def get_connector_delivery_queue(conn, status: str = "", limit: int = 200) -> pd.DataFrame:
    if status:
        return pd.read_sql_query(
            """
            SELECT * FROM connector_delivery_queue
            WHERE status = ?
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            conn,
            params=(status, int(limit)),
        )
    return pd.read_sql_query(
        """
        SELECT * FROM connector_delivery_queue
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        conn,
        params=(int(limit),),
    )


def get_pending_connector_deliveries(conn, now_ts: float, limit: int = 50) -> pd.DataFrame:
    return pd.read_sql_query(
        """
        SELECT * FROM connector_delivery_queue
        WHERE status IN ('pending', 'retry')
          AND (next_retry_at IS NULL OR next_retry_at <= ?)
        ORDER BY updated_at ASC
        LIMIT ?
        """,
        conn,
        params=(float(now_ts), int(limit)),
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
    updates = ["status = ?", "updated_at = (strftime('%s', 'now'))"]
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
