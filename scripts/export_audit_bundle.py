from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database as db


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    conn = db.create_connection()
    if conn is None:
        print("ERROR: database unavailable")
        return 1

    try:
        export_root = ROOT / "shadowlab_out" / "audit_exports"
        export_root.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        bundle_dir = export_root / f"audit_bundle_{timestamp}"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        payloads = {
            "auth_log.json": db.get_auth_logs(conn).fillna("").to_dict(orient="records"),
            "action_audit_log.json": db.get_action_audits(conn).fillna("").to_dict(orient="records"),
            "external_request_log.json": db.get_external_requests(conn).fillna("").to_dict(orient="records"),
            "secret_rotation_log.json": db.get_secret_rotations(conn, limit=500).fillna("").to_dict(orient="records"),
            "connector_delivery_queue.json": db.get_connector_delivery_queue(conn, status="", limit=500).fillna("").to_dict(orient="records"),
            "schema_migrations.json": db.get_schema_migrations(conn).fillna("").to_dict(orient="records"),
        }
    finally:
        conn.close()

    manifest: list[dict[str, object]] = []
    for filename, payload in payloads.items():
        target = bundle_dir / filename
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        manifest.append(
            {
                "filename": filename,
                "sha256": _sha256(target),
                "records": len(payload) if isinstance(payload, list) else 0,
            }
        )

    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_text(json.dumps({"generated_at": timestamp, "files": manifest}, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "status": "ok",
                "bundle_dir": str(bundle_dir),
                "manifest_path": str(manifest_path),
                "files": manifest,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
