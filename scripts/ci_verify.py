from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> None:
    print(f"Executing: {' '.join(command)}")
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if completed.returncode != 0:
        print(f"Error executing command: {' '.join(command)}")
        print("STDOUT:")
        print(completed.stdout)
        print("STDERR:")
        print(completed.stderr)
        raise SystemExit(completed.returncode)
    else:
        print("SUCCESS")
        print(completed.stdout)


def main() -> None:
    run(
        [
            sys.executable,
            "-m",
            "py_compile",
            "database.py",
            "api/main.py",
            "desktop/main.py",
            "services/malware_analyst_service.py",
            "services/static_pe_service.py",
            "scripts/backup_shadowlab_data.py",
            "scripts/export_audit_bundle.py",
            "scripts/restore_shadowlab_data.py",
            "scripts/smoke_test_postgres_runtime.py",
            "scripts/validate_enterprise_postgres_readiness.py",
            "scripts/validate_detection_corpus.py",
        ]
    )
    run(
        [
            sys.executable,
            "-m",
            "unittest",
            "tests.test_security",
            "tests.test_enterprise",
            "tests.test_triage_error_handling",
            "tests.test_integrity",
            "tests.test_telemetry_bridge",
            "tests.test_database_maintenance",
            "tests.test_api_e2e",
        ]
    )
    run(
        [
            sys.executable,
            "-m",
            "unittest",
            "tests.test_api_load",
            "tests.test_detection_service",
            "tests.test_malware_analyst",
            "tests.test_detection_validation_corpus",
        ]
    )
    run(
        [
            sys.executable,
            "-m",
            "unittest",
            "tests.test_static_pe_service",
            "tests.test_sandbox",
            "tests.test_threat_intelligence",
            "tests.test_ops_scripts",
            "tests.test_graph_service",
        ]
    )


if __name__ == "__main__":
    main()
