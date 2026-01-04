
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
    except sqlite3.Error as e:
        print(e)

def insert_telemetry(conn, telemetry_data: list[dict]):
    """Insert telemetry data into the telemetry table."""
    try:
        df = pd.DataFrame(telemetry_data)
        df.to_sql("telemetry", conn, if_exists="append", index=False)
    except Exception as e:
        print(e)

def get_historical_data(conn) -> pd.DataFrame:
    """Query all rows in the telemetry table."""
    return pd.read_sql_query("SELECT * FROM telemetry", conn)

def init_db():
    """Initialize the database."""
    conn = create_connection()
    if conn:
        create_table(conn)
        conn.close()
