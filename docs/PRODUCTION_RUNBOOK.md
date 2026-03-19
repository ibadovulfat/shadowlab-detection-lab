# ShadowLab Production Runbook

This runbook covers the current hardened runtime path, with emphasis on auth, database readiness, integrity, observability, secrets, and enterprise operations.

## Scope

Covered areas:

- auth-enabled local and service startup
- integrity manifests and history
- observability summaries
- secret rotation and stored secret state
- retention cleanup
- SQLite-to-PostgreSQL migration preparation
- CI verification and smoke checks
- backup and restore helpers

## Startup Modes

### Standard local startup

```powershell
python app.py
```

### Auth-enabled local startup

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
```

### Windows service-oriented startup

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_api.ps1
```

Related service helper:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_shadowlab_windows_service.ps1 -NssmPath C:\tools\nssm.exe
```

Linux helper:

```bash
sh scripts/start_shadowlab_api.sh
```

## Authentication And Role Operations

Relevant environment variables:

- `SHADOWLAB_REQUIRE_AUTH`
- `SHADOWLAB_API_KEYS`
- `SHADOWLAB_API_KEYS_SHA256`
- `SHADOWLAB_ALLOWED_ORIGINS`
- `SHADOWLAB_POLICY_PROFILE`

Recommended practice:

1. generate new role keys with `scripts/generate_api_keys.py`
2. store only SHA-256 digests in environment variables
3. validate role behavior through `GET /auth/context`
4. keep desktop users on least-privilege keys when possible

Auth audit routes:

- `GET /auth/context`
- `GET /history/auth`
- `GET /history/auth/anomalies`

## Database Path

- default local database: SQLite
- readiness route: `GET /enterprise/database/readiness`
- PostgreSQL bootstrap artifact: `shadowlab_out/postgres_bootstrap.sql`
- SQLite export helper: `scripts/export_sqlite_to_postgres.py`
- PostgreSQL smoke helper: `scripts/smoke_test_postgres_runtime.py`

Suggested migration sequence:

1. run `python scripts/export_sqlite_to_postgres.py`
2. apply `shadowlab_out/postgres_bootstrap.sql` to the target PostgreSQL cluster
3. import exported CSV data
4. set `SHADOWLAB_DATABASE_URL=postgresql://...`
5. validate `GET /enterprise/database/readiness`
6. run `python scripts/smoke_test_postgres_runtime.py`

## Integrity Operations

Routes:

- `GET /integrity`
- `GET /integrity/history`
- `POST /integrity/refresh`

Notes:

- integrity signing uses `SHADOWLAB_INTEGRITY_SIGNING_KEY` or a rotated stored key
- use refresh after planned baseline changes, not as a reflex during unexplained drift

## Secret Operations

Routes:

- `GET /enterprise/secrets/status`
- `POST /enterprise/secrets/rotate`

Use these to rotate or clear stored secrets for connectors, alerting, and integrity-related materials.

## Observability And Reporting

Routes:

- `GET /observability/summary`
- `GET /enterprise/report/security-ops`
- `POST /enterprise/report/security-ops/export`
- `GET /enterprise/abuse/summary`

## Retention And Maintenance

Routes:

- `POST /enterprise/maintenance/retention`
- `GET /enterprise/connectors/queue`
- `POST /enterprise/connectors/queue/process`

Use retention cleanup to control table growth and queue processing to flush connector backlogs.

## Backup And Restore

Backup:

```powershell
python scripts/backup_shadowlab_data.py --output-dir backups
```

Restore:

```powershell
python scripts/restore_shadowlab_data.py backups/shadowlab_backup_YYYYMMDD_HHMMSS/manifest.json
```

## Verification

Local CI-style verification:

```powershell
python scripts/ci_verify.py
```

Useful extra checks:

- `python scripts/load_test_api.py --base-url http://127.0.0.1:8000 --path /health --requests 200 --concurrency 20`
- `python scripts/smoke_test_postgres_runtime.py`

## Operator Notes

- the desktop `Security Ops` tab is the safest place to review integrity, observability, readiness, and report exports without manually calling endpoints
- approval-gated behavior depends on policy profile and enabled dangerous-action settings
- keep raw role keys out of the repository and shell history where possible
