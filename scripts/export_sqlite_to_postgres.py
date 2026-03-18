from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path


def export_table(conn: sqlite3.Connection, table: str, out_dir: Path) -> None:
    cursor = conn.execute(f"SELECT * FROM {table}")
    columns = [item[0] for item in cursor.description]
    target = out_dir / f"{table}.csv"
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        writer.writerows(cursor.fetchall())


def main() -> None:
    parser = argparse.ArgumentParser(description="Export SQLite tables to CSV for PostgreSQL import")
    parser.add_argument("--db", default="shadowlab.db")
    parser.add_argument("--out", default="shadowlab_out/postgres_export")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(args.db)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name ASC"
            ).fetchall()
        ]
        for table in tables:
            export_table(conn, table, out_dir)
    finally:
        conn.close()
    print(f"Exported {len(tables)} tables to {out_dir}")


if __name__ == "__main__":
    main()
