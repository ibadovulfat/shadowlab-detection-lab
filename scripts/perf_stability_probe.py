from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import hashlib
from pathlib import Path


def _make_ossec_record(index: int, *, duplicate_anchor: int | None = None) -> dict[str, object]:
    anchor = duplicate_anchor if duplicate_anchor is not None else index
    return {
        "crit": 11 if anchor % 5 == 0 else 7,
        "id": 550 + (anchor % 10),
        "component": "syscheck",
        "classification": "syscheck_entry_modified",
        "description": "Integrity checksum changed.",
        "src_ip": f"10.0.{anchor % 255}.{(anchor * 3) % 255}",
        "dst_ip": f"10.1.{anchor % 255}.{(anchor * 7) % 255}",
        "file": f"C:/lab/samples/file-{anchor % 250}.bin",
        "sha1_old": f"old-{anchor % 100}",
        "sha1_new": f"new-{anchor % 100}",
        "message": f"File modified #{anchor}",
        "hostname": f"host-{anchor % 40}",
    }


def _make_whids_record(index: int) -> dict[str, object]:
    return {
        "Event": {
            "System": {"Computer": f"LAB-WS-{index % 25:02d}", "EventID": 10},
            "EventData": {
                "SourceImage": f"C:\\Temp\\tool-{index % 200}.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "SourceUser": "NT AUTHORITY\\SYSTEM",
            },
        },
        "EdrData": {
            "Endpoint": {
                "UUID": f"whids-host-{index % 25}",
                "IP": f"10.20.{index % 255}.{(index * 11) % 255}",
                "Hostname": f"LAB-WS-{index % 25:02d}",
            },
            "Event": {
                "Hash": hashlib.sha1(f"whids-{index}".encode("utf-8")).hexdigest(),
                "ReceiptTime": "2026-03-21T12:00:00Z",
            },
        },
        "Detection": {
            "Signature": [f"SuspiciousSignature{index % 20}"],
            "Criticality": 8 if index % 4 == 0 else 6,
            "Actions": ["report", "memdump"] if index % 4 == 0 else ["report"],
        },
    }


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    temp_path = Path(tempfile.mkdtemp(prefix="shadowlab-perf-"))
    try:
        db_path = temp_path / "perf_shadowlab.db"
        os.environ["SHADOWLAB_DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"

        import database as db
        from services.enterprise_service import EnterpriseService
        from services.hids_integration_service import HidsIntegrationService
        from services.investigation_service import InvestigationService
        from services.response_service import ResponseOrchestrator
        from services.timeline_service import TimelineService
        from unittest import mock

        db.init_db()
        enterprise_service = EnterpriseService(repo_root, mock.Mock(), mock.Mock())
        investigation_service = InvestigationService(TimelineService())
        service = HidsIntegrationService(
            db,
            enterprise_service=enterprise_service,
            investigation_service=investigation_service,
            response_service=ResponseOrchestrator(),
        )

        ossec_path = temp_path / "ossec-large.json"
        whids_path = temp_path / "whids-large.json"
        live_path = temp_path / "ossec-live.jsonl"

        ossec_records = [_make_ossec_record(i) for i in range(1000)]
        whids_records = [_make_whids_record(i) for i in range(1000)]
        ossec_path.write_text(json.dumps(ossec_records), encoding="utf-8")
        whids_path.write_text(json.dumps(whids_records), encoding="utf-8")
        live_path.write_text("", encoding="utf-8")

        results: list[tuple[str, bool, str]] = []

        started = time.perf_counter()
        ossec_result = service.import_ossec_file(str(ossec_path), limit=1000)
        ossec_seconds = time.perf_counter() - started
        results.append(("import_ossec_1000", ossec_result.get("imported") == 1000, f"{ossec_seconds:.2f}s imported={ossec_result.get('imported')}"))

        started = time.perf_counter()
        whids_result = service.import_whids_file(str(whids_path), limit=1000)
        whids_seconds = time.perf_counter() - started
        results.append(("import_whids_1000", whids_result.get("imported") == 1000, f"{whids_seconds:.2f}s imported={whids_result.get('imported')}"))

        seed_records = [_make_ossec_record(i) for i in range(60)]
        live_path.write_text("", encoding="utf-8")
        service.start_ossec_live_ingest(str(live_path), poll_interval=0.5, limit=500, start_at_end=True)
        time.sleep(1.0)
        duplicate_batch = [_make_ossec_record(i, duplicate_anchor=i % 20) for i in range(240)]
        unique_batch = [_make_ossec_record(5000 + i) for i in range(80)]
        started = time.perf_counter()
        with live_path.open("a", encoding="utf-8") as handle:
            for record in seed_records + duplicate_batch + unique_batch:
                handle.write(json.dumps(record) + "\n")
        deadline = time.time() + 10
        live_state = {}
        while time.time() < deadline:
            live_state = service.ossec_live_status()
            if int(live_state.get("total_imported", 0)) >= 80:
                break
            time.sleep(0.5)
        live_elapsed = time.perf_counter() - started
        final_state = service.stop_ossec_live_ingest()
        imported_live = int(final_state.get("total_imported", 0))
        results.append(("live_ingest_unique_batch", imported_live >= 80, f"{live_elapsed:.2f}s imported={imported_live}"))

        second_ossec_result = service.import_ossec_file(str(ossec_path), limit=1000)
        results.append(("duplicate_import_skipped", second_ossec_result.get("imported") == 0, f"imported={second_ossec_result.get('imported')}"))

        with sqlite3.connect(db_path) as conn:
            incident_count = int(conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
            dedupe_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM integration_export_log WHERE integration_name='ossec' AND export_type='dedupe_skip'"
                ).fetchone()[0]
            )
        results.append(("db_incident_volume", incident_count >= 2080, f"incidents={incident_count}"))
        results.append(("dedupe_logging_present", dedupe_count > 0, f"dedupe_skips={dedupe_count}"))

        print("ShadowLab performance and stability probe")
        failures = [item for item in results if not item[1]]
        for name, ok, detail in results:
            state = "PASS" if ok else "FAIL"
            print(f"[{state}] {name}: {detail}")
        print(f"\nSummary: {len(results) - len(failures)} passed / {len(failures)} failed")
        return 1 if failures else 0
    finally:
        os.environ.pop("SHADOWLAB_DATABASE_URL", None)
        shutil.rmtree(temp_path, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
