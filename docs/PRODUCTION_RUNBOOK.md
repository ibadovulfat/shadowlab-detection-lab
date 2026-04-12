# ShadowLab Production Runbook

This runbook covers the hardened runtime path for ShadowLab, with emphasis on auth, integrity, observability, secret handling, integrations, and recovery.

## Startup Modes

Standard local startup:

```powershell
python app.py
```

Auth-enabled local startup:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
```

Windows service-oriented startup:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_api.ps1
```

## Authentication And Policy

Relevant environment variables:

- `SHADOWLAB_REQUIRE_AUTH`
- `SHADOWLAB_API_KEYS`
- `SHADOWLAB_API_KEYS_SHA256`
- `SHADOWLAB_ALLOWED_ORIGINS`
- `SHADOWLAB_POLICY_PROFILE`
- `SHADOWLAB_NOAUTH_DEFAULT_ROLE`
- `SHADOWLAB_RESTORE_INTEGRATION_RUNTIME`
- `SHADOWLAB_OSSEC_HOME`

Recommended practice:

1. generate fresh role keys with `scripts/generate_api_keys.py`
2. store digests instead of raw keys where possible
3. keep `prod` and `corp` profiles fully authenticated
4. use no-auth elevated defaults only for local lab work on loopback
5. treat approval IDs as part of change control
6. in corp/prod, start from `deploy/shadowlab.prod.env.example`

## Signed Requests

Authenticated write operations are signed. If you call the API outside the desktop client, the signature must cover:

- HTTP method
- request path
- canonical query string
- request body hash
- timestamp
- nonce

Replay protection and rate-limit counters are persisted in the database.

## Database Readiness

- default local database: SQLite
- readiness route: `GET /enterprise/database/readiness`
- PostgreSQL bootstrap artifact: `shadowlab_out/postgres_bootstrap.sql`
- export helper: `scripts/export_sqlite_to_postgres.py`
- smoke helper: `scripts/smoke_test_postgres_runtime.py`
- enterprise readiness helper: `scripts/validate_enterprise_postgres_readiness.py`

## Integrity And Secrets

Routes:

- `GET /integrity`
- `GET /integrity/history`
- `POST /integrity/refresh`
- `GET /enterprise/secrets/status`
- `POST /enterprise/secrets/rotate`

Refresh integrity after known-good baseline changes. Rotate secrets when credentials, webhook settings, or signing material changes.

## Observability And Reporting

Routes:

- `GET /observability/summary`
- `GET /enterprise/report/security-ops`
- `POST /enterprise/report/security-ops/export`
- `GET /enterprise/abuse/summary`

Offline audit export helper:

- `python scripts/export_audit_bundle.py`

The audit bundle contains auth logs, action audit logs, external request logs, secret rotation history, connector queue state, and schema migrations with a local SHA-256 manifest.

Generated incident reports now include:

- executive summary and correlation narrative
- prioritized findings and ATT&CK coverage notes
- response guidance and analyst note rollup
- telemetry snapshot and security-event highlights
- artifact inventory from `shadowlab_out`

If the desktop `Artifacts` view and the exported report disagree, regenerate the monitor artifacts first and then refresh integrity.

YARA operations:

- `GET /yara/local/health`
- `GET /yara/local/errors`
- `GET /yara/local/analytics`
- `GET /yara/local/update-workflow`

## Deployment Preflight

Run before handing the node to another operator:

```powershell
python scripts/validate_deployment_runtime.py
```

Production env template:

- `deploy/shadowlab.prod.env.example`

History cleanup and rotation guide:

- `docs/SECURITY_REMEDIATION_RUNBOOK.md`

## Live Integration Validation

OSSEC active-response validation:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome C:\Users\ulfat\Documents\ossec-hids-main
```

ShadowLab live API and `WHIDS` smoke test:

```powershell
python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key>
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

Useful checks:

- `python scripts/ci_verify.py`
- `python scripts/load_test_api.py --base-url http://127.0.0.1:8000 --path /health --requests 200 --concurrency 20`
- `python scripts/smoke_test_postgres_runtime.py`
- `python scripts/validate_enterprise_postgres_readiness.py`
- `python scripts/export_audit_bundle.py`

## Operator Notes

- the desktop `Security Ops` tab is the safest place to review posture
- approval requirements depend on both profile and feature flags
- keep raw keys out of shell history and repository files

updated

