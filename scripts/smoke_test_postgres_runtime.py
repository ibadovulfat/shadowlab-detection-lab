import sys
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse, urlunparse

# Ensure root is in sys.path for database import
sys.path.append(str(Path(__file__).resolve().parent.parent))

import database as db


def redact_profile(profile: dict[str, str]) -> dict[str, str]:
    sanitized = dict(profile)
    raw_url = str(sanitized.get("database_url", "")).strip()
    parsed = urlparse(raw_url)
    if parsed.scheme in {"postgres", "postgresql"} and parsed.hostname:
        auth = parsed.username or ""
        if auth:
            auth = f"{auth}:***@"
        netloc = f"{auth}{parsed.hostname}"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        sanitized["database_url"] = urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )
    return sanitized


def main() -> None:
    profile = db.database_runtime_profile()
    if profile["backend"] != "postgresql":
        raise SystemExit("SHADOWLAB_DATABASE_URL must point to a PostgreSQL database for this smoke test.")

    temp_dir = Path(tempfile.mkdtemp(prefix="shadowlab_pg_smoke_"))
    previous_out = os.environ.get("SHADOWLAB_OUT_DIR")
    os.environ["SHADOWLAB_OUT_DIR"] = str(temp_dir)

    conn = db.create_connection()
    if conn is None:
        raise SystemExit("Unable to connect to PostgreSQL runtime.")

    try:
        db.create_table(conn)
        db.insert_telemetry(
            conn,
            [
                {
                    "ts": 1710000000.0,
                    "cpu": 5.5,
                    "mem_percent": 12.0,
                    "proc_threads": 9,
                    "proc_handles": 40,
                    "open_files": 2,
                    "tcp_conns": 3,
                    "bytes_sent_rate": 1.2,
                    "bytes_recv_rate": 2.4,
                    "remote_ips": ["127.0.0.1"],
                }
            ],
        )
        case_id = db.create_case_record(conn, title="postgres-smoke-case", narrative="runtime validation")
        approval_id = db.create_approval_request(conn, case_id=case_id, action="smoke_test", requested_by="ci")
        db.resolve_approval_request(conn, approval_id, "approved", approver="ci")
        connectors = db.get_connectors(conn)
        telemetry = db.get_historical_data(conn)
        approvals = db.get_approval_requests(conn)
        summary = {
            "profile": redact_profile(profile),
            "telemetry_rows": int(len(telemetry.index)),
            "connector_rows": int(len(connectors.index)),
            "approval_rows": int(len(approvals.index)),
            "case_id": int(case_id),
            "approval_id": int(approval_id),
        }
        print(json.dumps(summary, indent=2))
    finally:
        conn.close()
        if previous_out is None:
            os.environ.pop("SHADOWLAB_OUT_DIR", None)
        else:
            os.environ["SHADOWLAB_OUT_DIR"] = previous_out


if __name__ == "__main__":
    main()
