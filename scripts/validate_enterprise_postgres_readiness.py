from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database as db


REQUIRED_TABLES = {
    "auth_log",
    "action_audit_log",
    "external_request_log",
    "schema_migrations",
    "connector_delivery_queue",
    "secret_rotation_log",
}


def main() -> int:
    profile = db.database_runtime_profile()
    if profile["backend"] != "postgresql":
        print("ERROR: enterprise PostgreSQL readiness validation requires SHADOWLAB_DATABASE_URL to use PostgreSQL.")
        print(json.dumps(profile, indent=2))
        return 1

    conn = db.create_connection()
    if conn is None:
        print("ERROR: unable to connect to configured PostgreSQL backend.")
        return 1

    try:
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            ).fetchall()
        }
        missing = sorted(REQUIRED_TABLES - tables)
        migrations = db.get_schema_migrations(conn).fillna("").to_dict(orient="records")
        auth_count = int(conn.execute("SELECT COUNT(*) FROM auth_log").fetchone()[0])
        action_count = int(conn.execute("SELECT COUNT(*) FROM action_audit_log").fetchone()[0])
        external_count = int(conn.execute("SELECT COUNT(*) FROM external_request_log").fetchone()[0])
    finally:
        conn.close()

    if missing:
        print("ERROR: missing required PostgreSQL tables:")
        for name in missing:
            print(f"- {name}")
        return 2

    payload = {
        "status": "ok",
        "backend": profile["backend"],
        "database_url": profile["database_url"],
        "tables_checked": sorted(REQUIRED_TABLES),
        "migration_count": len(migrations),
        "latest_migration": migrations[-1]["version"] if migrations else "",
        "auth_log_rows": auth_count,
        "action_audit_rows": action_count,
        "external_request_rows": external_count,
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
