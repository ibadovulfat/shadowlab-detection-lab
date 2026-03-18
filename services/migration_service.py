from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import database as db


@dataclass(frozen=True)
class MigrationStep:
    version: str
    description: str
    apply: Callable


class MigrationService:
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.export_dir = self.base_dir / "shadowlab_out"
        self.steps = [
            MigrationStep("2026_03_backend_hardening", "Core backend hardening schema extensions", self._noop),
            MigrationStep("2026_03_ops_foundation", "Ops foundation indexes and app settings", self._noop),
        ]

    def ensure_applied(self) -> dict[str, object]:
        conn = db.create_connection()
        if conn is None:
            return {"status": "database_unavailable", "applied": [], "pending": [step.version for step in self.steps]}
        try:
            applied_df = db.get_schema_migrations(conn)
            applied = {str(item.get("version", "")) for item in applied_df.fillna("").to_dict(orient="records")}
            newly_applied: list[str] = []
            for step in self.steps:
                if step.version in applied:
                    continue
                step.apply(conn)
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)",
                    (step.version,),
                )
                conn.commit()
                newly_applied.append(step.version)
            final_df = db.get_schema_migrations(conn)
            return {
                "status": "ok",
                "applied": final_df.fillna("").to_dict(orient="records"),
                "newly_applied": newly_applied,
            }
        finally:
            conn.close()

    def export_postgres_bootstrap_sql(self) -> str:
        target = self.export_dir / "postgres_bootstrap.sql"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self._postgres_schema_sql(), encoding="utf-8")
        return str(target)

    def _postgres_schema_sql(self) -> str:
        return """-- ShadowLab PostgreSQL bootstrap foundation
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT '',
    updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE TABLE IF NOT EXISTS auth_log (
    id BIGSERIAL PRIMARY KEY,
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    role TEXT DEFAULT '',
    client_ip TEXT DEFAULT '',
    path TEXT DEFAULT '',
    detail TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS action_audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    role TEXT DEFAULT '',
    client_ip TEXT DEFAULT '',
    detail TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_pg_auth_log_created_at ON auth_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_action_audit_created_at ON action_audit_log(created_at DESC);
"""

    def _noop(self, conn) -> None:  # pragma: no cover - intentionally empty migration placeholder
        return
