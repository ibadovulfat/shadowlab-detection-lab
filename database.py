
import sqlite3
import pandas as pd

DB_FILE = "shadowlab.db"

def create_connection():
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
    except sqlite3.Error as e:
        print(e)
    return conn

def create_table(conn):
    """Create the telemetry table."""
    try:
        sql = """
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
            bytes_recv_rate REAL
        );
        """
        conn.execute(sql)
        
        # New table for response logging
        sql_log = """
        CREATE TABLE IF NOT EXISTS response_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            details TEXT
        );
        """
        conn.execute(sql_log)

        sql_cases = """
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
            recommended_actions TEXT DEFAULT ''
        );
        """
        conn.execute(sql_cases)

        sql_quarantine = """
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
        conn.execute(sql_quarantine)
        
    except sqlite3.Error as e:
        print(e)

def insert_telemetry(conn, telemetry_data: list[dict]):
    """Insert telemetry data into the telemetry table."""
    try:
        df = pd.DataFrame(telemetry_data)
        df.to_sql("telemetry", conn, if_exists="append", index=False)
    except Exception as e:
        print(e)
        
def log_response_action(conn, action, pid, process_name, details=""):
    """Log a remediation action."""
    try:
        sql = "INSERT INTO response_log (action, pid, process_name, details) VALUES (?, ?, ?, ?)"
        conn.execute(sql, (action, pid, process_name, details))
        conn.commit()
    except Exception as e:
        print(f"Log Error: {e}")

def get_response_logs(conn) -> pd.DataFrame:
    """Query response logs."""
    return pd.read_sql_query("SELECT * FROM response_log ORDER BY timestamp DESC", conn)

def get_historical_data(conn) -> pd.DataFrame:
    """Query all rows in the telemetry table."""
    return pd.read_sql_query("SELECT * FROM telemetry", conn)

def upsert_incident(conn, incident_id, created_at, severity, title, summary, status="open", notes="", owner="", recommended_actions=""):
    try:
        sql = """
        INSERT INTO incidents (incident_id, created_at, severity, title, summary, status, notes, owner, recommended_actions)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(incident_id) DO UPDATE SET
            severity=excluded.severity,
            title=excluded.title,
            summary=excluded.summary,
            status=excluded.status,
            notes=excluded.notes,
            owner=excluded.owner,
            recommended_actions=excluded.recommended_actions
        """
        conn.execute(sql, (incident_id, created_at, severity, title, summary, status, notes, owner, recommended_actions))
        conn.commit()
    except Exception as e:
        print(f"Incident upsert error: {e}")

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

def init_db():
    """Initialize the database."""
    conn = create_connection()
    if conn:
        create_table(conn) # Creates both tables now

        conn.close()
