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
            MigrationStep("2026_04_av_foundation", "Antivirus foundation: verdict cache, scan audit, signature update history, vault index", self._apply_av_foundation),
            MigrationStep("2026_05_av_wave3_ops", "Wave-3 ops: async scan jobs, signed webhooks (deliveries/DLQ/secrets), folder watcher state", self._apply_av_wave3_ops),
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

CREATE TABLE IF NOT EXISTS av_verdict_cache (
    sha256 TEXT NOT NULL,
    providers_fp TEXT NOT NULL,
    fused_verdict TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'low',
    score INTEGER NOT NULL DEFAULT 0,
    confidence TEXT NOT NULL DEFAULT 'low',
    payload_json TEXT NOT NULL DEFAULT '',
    expires_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    PRIMARY KEY (sha256, providers_fp)
);
CREATE INDEX IF NOT EXISTS idx_av_verdict_cache_expires ON av_verdict_cache(expires_at);

CREATE TABLE IF NOT EXISTS av_scans (
    id BIGSERIAL PRIMARY KEY,
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    workspace_id TEXT NOT NULL DEFAULT 'default',
    actor TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT 'file',
    target_path TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    fused_verdict TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'low',
    score INTEGER NOT NULL DEFAULT 0,
    confidence TEXT NOT NULL DEFAULT 'low',
    providers_set TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'live',
    duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_av_scans_created ON av_scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_av_scans_sha256 ON av_scans(sha256);
CREATE INDEX IF NOT EXISTS idx_av_scans_workspace ON av_scans(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS av_signature_updates (
    id BIGSERIAL PRIMARY KEY,
    provider_key TEXT NOT NULL,
    started_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    finished_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    message TEXT NOT NULL DEFAULT '',
    files_changed INTEGER NOT NULL DEFAULT 0,
    trigger TEXT NOT NULL DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_av_signature_updates_provider ON av_signature_updates(provider_key, started_at DESC);

CREATE TABLE IF NOT EXISTS av_vault_entries (
    file_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'default',
    original_path TEXT NOT NULL DEFAULT '',
    ciphertext_path TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT '',
    fused_verdict TEXT NOT NULL DEFAULT '',
    process_name TEXT NOT NULL DEFAULT '',
    pid INTEGER NOT NULL DEFAULT -1,
    actor TEXT NOT NULL DEFAULT '',
    hmac_tag TEXT NOT NULL DEFAULT '',
    nonce_b64 TEXT NOT NULL DEFAULT '',
    manifest_json TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'sealed',
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE INDEX IF NOT EXISTS idx_av_vault_workspace ON av_vault_entries(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_av_vault_sha ON av_vault_entries(sha256);

-- Wave-3 ops: async scan jobs + signed webhook deliveries.
CREATE TABLE IF NOT EXISTS av_scan_jobs (
    job_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'default',
    actor TEXT NOT NULL DEFAULT '',
    target_path TEXT NOT NULL DEFAULT '',
    policy_overrides_json TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    submitted_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    started_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    finished_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    result_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_av_scan_jobs_state ON av_scan_jobs(state, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_av_scan_jobs_workspace ON av_scan_jobs(workspace_id, submitted_at DESC);

CREATE TABLE IF NOT EXISTS webhook_secrets (
    secret_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    secret TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE INDEX IF NOT EXISTS idx_webhook_secrets_workspace ON webhook_secrets(workspace_id, active);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    delivery_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'default',
    target_url TEXT NOT NULL,
    event_type TEXT NOT NULL DEFAULT 'generic',
    payload_json TEXT NOT NULL DEFAULT '{}',
    secret_id TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_status INTEGER NOT NULL DEFAULT 0,
    last_response_excerpt TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending',
    history_json TEXT NOT NULL DEFAULT '[]',
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    delivered_at DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_state ON webhook_deliveries(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_workspace ON webhook_deliveries(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS webhook_dlq (
    delivery_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'default',
    target_url TEXT NOT NULL,
    event_type TEXT NOT NULL DEFAULT 'generic',
    payload_json TEXT NOT NULL DEFAULT '{}',
    last_status INTEGER NOT NULL DEFAULT 0,
    last_response_excerpt TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW()),
    delivered_at DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_webhook_dlq_workspace ON webhook_dlq(workspace_id, created_at DESC);
"""

    def _noop(self, conn) -> None:  # pragma: no cover - intentionally empty migration placeholder
        return

    def _apply_av_foundation(self, conn) -> None:
        """Create the four foundational tables that back the antivirus
        Wave-1 capability set. SQLite-flavoured DDL — the Postgres
        bootstrap below mirrors the same shape."""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS av_verdict_cache (
                sha256 TEXT NOT NULL,
                providers_fp TEXT NOT NULL,
                fused_verdict TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'low',
                score INTEGER NOT NULL DEFAULT 0,
                confidence TEXT NOT NULL DEFAULT 'low',
                payload_json TEXT NOT NULL DEFAULT '',
                expires_at REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (sha256, providers_fp)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_verdict_cache_expires ON av_verdict_cache(expires_at)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS av_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                workspace_id TEXT NOT NULL DEFAULT 'default',
                actor TEXT NOT NULL DEFAULT '',
                scope TEXT NOT NULL DEFAULT 'file',
                target_path TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                fused_verdict TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'low',
                score INTEGER NOT NULL DEFAULT 0,
                confidence TEXT NOT NULL DEFAULT 'low',
                providers_set TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'live',
                duration_ms INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_scans_created ON av_scans(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_scans_sha256 ON av_scans(sha256)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_scans_workspace ON av_scans(workspace_id, created_at DESC)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS av_signature_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_key TEXT NOT NULL,
                started_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                finished_at REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                message TEXT NOT NULL DEFAULT '',
                files_changed INTEGER NOT NULL DEFAULT 0,
                trigger TEXT NOT NULL DEFAULT 'manual'
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_av_signature_updates_provider ON av_signature_updates(provider_key, started_at DESC)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS av_vault_entries (
                file_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                original_path TEXT NOT NULL DEFAULT '',
                ciphertext_path TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT '',
                fused_verdict TEXT NOT NULL DEFAULT '',
                process_name TEXT NOT NULL DEFAULT '',
                pid INTEGER NOT NULL DEFAULT -1,
                actor TEXT NOT NULL DEFAULT '',
                hmac_tag TEXT NOT NULL DEFAULT '',
                nonce_b64 TEXT NOT NULL DEFAULT '',
                manifest_json TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'sealed',
                created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                updated_at REAL NOT NULL DEFAULT (strftime('%s','now'))
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_vault_workspace ON av_vault_entries(workspace_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_vault_sha ON av_vault_entries(sha256)")
        conn.commit()

    def _apply_av_wave3_ops(self, conn) -> None:
        """Wave-3 ops tables: async scan jobs + signed webhook deliveries
        (queue, DLQ, per-workspace secrets). SQLite-flavoured DDL."""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS av_scan_jobs (
                job_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                actor TEXT NOT NULL DEFAULT '',
                target_path TEXT NOT NULL DEFAULT '',
                policy_overrides_json TEXT NOT NULL DEFAULT '{}',
                state TEXT NOT NULL DEFAULT 'queued',
                progress INTEGER NOT NULL DEFAULT 0,
                submitted_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                started_at REAL NOT NULL DEFAULT 0,
                finished_at REAL NOT NULL DEFAULT 0,
                error TEXT NOT NULL DEFAULT '',
                result_json TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_scan_jobs_state ON av_scan_jobs(state, submitted_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_av_scan_jobs_workspace ON av_scan_jobs(workspace_id, submitted_at DESC)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_secrets (
                secret_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                secret TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_secrets_workspace ON webhook_secrets(workspace_id, active)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                target_url TEXT NOT NULL,
                event_type TEXT NOT NULL DEFAULT 'generic',
                payload_json TEXT NOT NULL DEFAULT '{}',
                secret_id TEXT NOT NULL DEFAULT '',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                last_status INTEGER NOT NULL DEFAULT 0,
                last_response_excerpt TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'pending',
                history_json TEXT NOT NULL DEFAULT '[]',
                created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                delivered_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_state ON webhook_deliveries(state, next_attempt_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_workspace ON webhook_deliveries(workspace_id, created_at DESC)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_dlq (
                delivery_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                target_url TEXT NOT NULL,
                event_type TEXT NOT NULL DEFAULT 'generic',
                payload_json TEXT NOT NULL DEFAULT '{}',
                last_status INTEGER NOT NULL DEFAULT 0,
                last_response_excerpt TEXT NOT NULL DEFAULT '',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                delivered_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_dlq_workspace ON webhook_dlq(workspace_id, created_at DESC)")

        conn.commit()
