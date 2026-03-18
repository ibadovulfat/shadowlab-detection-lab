# ShadowLab Production Runbook

## Scope
This runbook covers the production-ready database/runtime path added to the current lab build:
- signed integrity manifests
- observability JSONL stream
- secret rotation workflows
- SQLite-to-PostgreSQL migration preparation
- retention cleanup and abuse analytics
- CI verification and PostgreSQL smoke testing
- backup and restore automation
- service startup templates for Windows and Linux

## Database Path
- Default local runtime backend: SQLite
- Readiness endpoint: `GET /enterprise/database/readiness`
- PostgreSQL bootstrap schema artifact: `shadowlab_out/postgres_bootstrap.sql`
- SQLite export helper: `scripts/export_sqlite_to_postgres.py`
- PostgreSQL smoke helper: `scripts/smoke_test_postgres_runtime.py`

Suggested migration sequence:
1. Run `python scripts/export_sqlite_to_postgres.py`
2. Apply `shadowlab_out/postgres_bootstrap.sql` to the target PostgreSQL cluster
3. Import exported CSV data
4. Set `SHADOWLAB_DATABASE_URL=postgresql://...`
5. Validate `/enterprise/database/readiness`
6. Run `python scripts/smoke_test_postgres_runtime.py`

## CI/CD Gates
- Workflow: `.github/workflows/backend-hardening.yml`
- Local verify: `python scripts/ci_verify.py`
- The workflow runs compile checks, the backend regression suite, and a live PostgreSQL 16 smoke validation

## Integrity Operations
- Verify current state: `GET /integrity`
- Review integrity history: `GET /integrity/history`
- Refresh baseline: `POST /integrity/refresh`
- Rotate signing key: `POST /enterprise/secrets/rotate`

## Secret Operations
- View rotation state: `GET /enterprise/secrets/status`
- Rotate all stored secrets: `POST /enterprise/secrets/rotate`
- Clear stored alert webhook: `POST /enterprise/secrets/rotate` with `clear_alert_webhook=true`

## Reporting
- Security Ops summary: `GET /enterprise/report/security-ops`
- Export report bundle: `POST /enterprise/report/security-ops/export`
- Observability summary: `GET /observability/summary`
- Abuse analytics: `GET /enterprise/abuse/summary`

## Retention
- Run cleanup: `POST /enterprise/maintenance/retention`
- Tune per-table day ranges in the request payload

## Load Test
- Simple parallel test:
  `python scripts/load_test_api.py --base-url http://127.0.0.1:8000 --path /health --requests 200 --concurrency 20`

## Backup And Restore
- Backup bundle:
  `python scripts/backup_shadowlab_data.py --output-dir backups`
- Restore bundle:
  `python scripts/restore_shadowlab_data.py backups/shadowlab_backup_YYYYMMDD_HHMMSS/manifest.json`

## Service Wrappers
- Windows startup:
  `powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_api.ps1`
- Windows service install:
  `powershell -ExecutionPolicy Bypass -File scripts\install_shadowlab_windows_service.ps1 -NssmPath C:\tools\nssm.exe`
- Linux startup:
  `sh scripts/start_shadowlab_api.sh`
- Linux systemd template:
  `deploy/systemd/shadowlab-api.service`

## Operator Notes
- Signed integrity depends on either `SHADOWLAB_INTEGRITY_SIGNING_KEY` or a rotated stored signing key.
- SQLite remains the default local mode, but PostgreSQL can be used as the active shared runtime when `SHADOWLAB_DATABASE_URL` is configured and a supported driver is installed.
- Use the desktop `Security Ops` tab for non-breaking UI access to the new controls.
