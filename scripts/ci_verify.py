from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> None:
    run(
        [
            sys.executable,
            "-m",
            "py_compile",
            "database.py",
            "api/main.py",
            "desktop/main.py",
            "scripts/backup_shadowlab_data.py",
            "scripts/restore_shadowlab_data.py",
            "scripts/smoke_test_postgres_runtime.py",
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
            "tests.test_api_load",
            "tests.test_ops_scripts",
            "tests.test_graph_service",
        ]
    )


if __name__ == "__main__":
    main()
