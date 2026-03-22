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
- WHIDS and OSSEC live integration validation
- deployment runtime restore and scheduler persistence
- local YARA pack health, policy, and validation

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
powershell -ExecutionPolicy Bypass -File scripts\install_shadowlab_windows_service.ps1 -NssmPath C:\tools\nssm.exe -RequireAuth -EnableDangerousActions -RestoreIntegrationRuntime -ApiKeysSha256 "viewer:<sha256>,analyst:<sha256>,admin:<sha256>" -OssecHome C:\Users\ulfat\Documents\ossec-hids-main -RunPreflight
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
- `SHADOWLAB_RESTORE_INTEGRATION_RUNTIME`
- `SHADOWLAB_OSSEC_HOME`
- `SHADOWLAB_WHIDS_MANAGER_URL`
- `SHADOWLAB_WHIDS_API_KEY`
- `SHADOWLAB_WHIDS_ENDPOINT_UUID`

Recommended practice:

1. generate new role keys with `scripts/generate_api_keys.py`
2. store only SHA-256 digests in environment variables
3. validate role behavior through `GET /auth/context`
4. keep desktop users on least-privilege keys when possible
5. use a raw admin key only for signed-request smoke tests, then rotate it out

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

Local YARA observability routes:

- `GET /yara/local/health`
- `GET /yara/local/errors`
- `GET /yara/local/analytics`
- `GET /yara/local/update-workflow`

## Retention And Maintenance

Routes:

- `POST /enterprise/maintenance/retention`
- `GET /enterprise/connectors/queue`
- `POST /enterprise/connectors/queue/process`

Use retention cleanup to control table growth and queue processing to flush connector backlogs.

## Deployment Preflight

Use this before starting a service or handing the node to another operator:

```powershell
python scripts/validate_deployment_runtime.py
```

This checks:

- auth and policy environment consistency
- OSSEC active-response script presence
- runtime restore files for scheduler and live ingest
- admin-session readiness for native Windows active-response validation
- optional WHIDS manager environment readiness when set

## Live Integration Validation

### OSSEC active-response on a real Windows host

Run this from an elevated PowerShell session:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome C:\Users\ulfat\Documents\ossec-hids-main
```

What it does:

- verifies the shell is running as Administrator
- executes `firewall-drop.cmd add/delete`
- executes `route-null.cmd add/delete`
- automatically cleans up the temporary test rule and route
- prints the latest `active-responses.log` entries

### ShadowLab live API and WHIDS manager smoke test

With ShadowLab already running and an admin API key available:

```powershell
python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key>
```

To include live WHIDS manager checks:

```powershell
python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key> --manager-url https://whids-manager.example --manager-api-key <whids_key> --endpoint-uuid <uuid>
```

This verifies:

- `GET /auth/context`
- `GET /integrations/ossec/live/status`
- `GET /integrations/whids/scheduler/status`
- signed `POST /integrations/response-policy`
- signed `POST /integrations/whids/config`
- signed `POST /integrations/whids/report-archive`

## MITRE ATT&CK Validation

Recommended ATT&CK checks before handing the system to another operator:

1. load the approved ATT&CK bundle with `POST /enterprise/mitre/load-bundle`
2. verify `GET /enterprise/mitre/status`
3. review `GET /enterprise/mitre/discover`
4. compare the selected bundle with `POST /enterprise/mitre/compare`
5. if a changelog JSON is available, review it with `POST /enterprise/mitre/changelog`
6. open the desktop `Enterprise` view and confirm ATT&CK coverage panels render
7. export one Navigator layer and one Workbench bundle

Operational notes:

- ATT&CK file access is intentionally restricted to approved ATT&CK locations
- bundle discovery is cached to avoid repeated recursive scans during enterprise refresh
- large ATT&CK JSON files are bounded to reduce avoidable memory pressure

## Restart Behavior

When `SHADOWLAB_RESTORE_INTEGRATION_RUNTIME=true`, ShadowLab restores:

- last `OSSEC` live ingest file and interval
- last `WHIDS` scheduler target and interval

These values are stored in `shadowlab_out/integration_runtime.json`. Validate them with:

```powershell
python scripts/validate_deployment_runtime.py
```

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

Recommended YARA validation checkpoints:

1. confirm `GET /yara/local/health` reports `compile_error_count = 0`
2. confirm enterprise pack inventory remains stable after community updates
3. validate at least one known `Inceptor` payload sample through the local enterprise pack
4. review `/yara/local/analytics` for noisy or newly dominant rules before promoting pack changes

## Operator Notes

- the desktop `Security Ops` tab is the safest place to review integrity, observability, readiness, and report exports without manually calling endpoints
- approval-gated behavior depends on policy profile and enabled dangerous-action settings
- keep raw role keys out of the repository and shell history where possible
