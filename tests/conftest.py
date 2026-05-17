"""Pytest session bootstrap — DATABASE ISOLATION.

Production-hygiene fix: the suite imports `database` and calls
`create_connection()` directly. With no isolation, every `pytest` run
read and WROTE the real production `shadowlab.db` — seeding it with
fixture incidents and placeholder response-log rows (sample.bin/1234,
1.2.3.4, powershell.exe/404) that then showed up in the live UI and made
the product look like a simulation. Conversely, real operator data could
leak into and flake the tests.

`database.database_runtime_profile()` resolves the DB path from
`SHADOWLAB_DATABASE_URL` on EVERY `create_connection()` call (it is not
cached at import), so redirecting that env var to a throwaway temp file
isolates the entire suite. This is set at conftest *import time* —
before any test module is imported — so a connection opened during
collection/import also lands in the sandbox, never in `shadowlab.db`.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# --- Hard isolation, applied at collection start ---------------------- #
# Only override when the operator hasn't already pointed the suite at an
# explicit (e.g. CI Postgres) database, so `SHADOWLAB_DATABASE_URL=...
# pytest` keeps working.
if not os.environ.get("SHADOWLAB_DATABASE_URL", "").strip():
    _tmp_dir = tempfile.mkdtemp(prefix="shadowlab-test-db-")
    _tmp_db = Path(_tmp_dir) / "shadowlab_test.db"
    # `sqlite:///<forward-slash-abs-path>` so urlparse yields
    # scheme="sqlite" on Windows too (a bare `C:\..` path parses with
    # scheme="c" and would be rejected by database_runtime_profile).
    os.environ["SHADOWLAB_DATABASE_URL"] = "sqlite:///" + _tmp_db.as_posix()
    os.environ.setdefault("SHADOWLAB_TEST_DB_DIR", _tmp_dir)


@pytest.fixture(scope="session", autouse=True)
def _ensure_isolated_schema():
    """Create the schema in the isolated DB once per session.

    Guarantees the sandbox DB exists with tables before the first test
    touches it, regardless of import order.
    """
    import database as db

    conn = db.create_connection()
    if conn is not None:
        try:
            db.create_table(conn)
        except Exception:
            # Individual tests that need richer fixtures create their
            # own rows; a partial schema here must not abort the run.
            pass
        finally:
            conn.close()
    yield
