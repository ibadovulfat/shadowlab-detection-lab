
import sqlite3
import pandas as pd

DB_FILE = "shadowlab.db"

def create_connection():
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        print(f"SQLite version: {sqlite3.sqlite_version}")
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

def init_db():
    """Initialize the database."""
    conn = create_connection()
    if conn:
        create_table(conn) # Creates both tables now

        conn.close()
