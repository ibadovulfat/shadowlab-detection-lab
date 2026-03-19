# ShadowLab Usage Guide

This guide covers the current operator workflow for backend, desktop, auth, enterprise investigation, and security-ops usage.

## Start Modes

### Basic local mode

```powershell
python app.py
python desktop\main.py
```

### Auth-enabled local mode

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

Use auth-enabled mode when you want to test:

- role-based access
- capability gating
- enterprise/admin-only actions
- approval-dependent workflows

## Desktop Workflow

Typical desktop flow:

1. confirm backend health
2. enter an API key when auth is enabled
3. inspect overview and dashboards
4. investigate suspicious processes
5. triage, enrich, and review graph or timeline context
6. open or work an enterprise case if needed
7. export findings or reports

## Process Investigation

Primary routes:

- `GET /processes`
- `GET /processes/{pid}`
- `GET /processes/{pid}/tree`
- `GET /processes/{pid}/internals`
- `POST /processes/{pid}/strings`
- `POST /processes/{pid}/yara`
- `POST /processes/{pid}/sandbox-trace`
- `GET /processes/{pid}/ai-analysis`
- `POST /processes/{pid}/scan`
- `GET /processes/{pid}/memory-analysis`
- `POST /triage/{pid}`

Recommended flow:

1. load the process list
2. inspect the selected process profile
3. review process tree and internals
4. run strings and YARAify lookup when relevant
5. run sandbox trace for short-lived behavior capture
6. use one-click triage for a bundled view
7. take response action only after review

## Threat Intelligence

Routes:

- `GET /threat-intel/ip/{ip}`
- `GET /threat-intel/hash/{file_hash}`
- `POST /threat-intel/hash/lookup`
- `POST /processes/{pid}/scan`

Supported providers in code:

- VirusTotal
- MalwareBazaar
- AbuseIPDB
- YARAify

YARAify desktop note:

- paste only the abuse.ch `Auth Key` value
- do not paste `curl`, quotes, or header labels

## Persistence, Quarantine, And Evidence

Routes:

- `GET /persistence`
- `POST /persistence/remediate`
- `POST /persistence/rollback/{remediation_id}`
- `GET /quarantine`
- `POST /quarantine/{quarantine_id}/restore`
- `DELETE /quarantine/{quarantine_id}`
- `POST /evidence/capture`
- `GET /evidence`
- `DELETE /evidence/{filename}`

Use these only in systems you own and control. Dangerous or destructive actions remain role- and policy-gated.

## Enterprise Case Workflow

Main case routes:

- `POST /enterprise/cases`
- `GET /enterprise/cases`
- `GET /enterprise/cases/{case_id}/board`
- `GET /enterprise/cases/{case_id}/activity`
- `GET /enterprise/cases/{case_id}/graph`
- `POST /enterprise/cases/{case_id}/assignments`
- `GET /enterprise/cases/{case_id}/assignments`
- `POST /enterprise/cases/{case_id}/tasks`
- `GET /enterprise/cases/{case_id}/tasks`
- `PATCH /enterprise/cases/{case_id}/tasks/{task_id}`
- `POST /enterprise/cases/{case_id}/investigation-report/export`

Investigation routes:

- `GET /enterprise/investigations/workspace`
- `POST /enterprise/investigations/views`
- `GET /enterprise/investigations/views`
- `POST /enterprise/investigations/notes`
- `GET /enterprise/investigations/notes`
- `POST /enterprise/investigations/stories`
- `GET /enterprise/investigations/stories`
- `POST /enterprise/investigations/pins`
- `GET /enterprise/investigations/pins`

Typical enterprise workflow:

1. create or select a case
2. review the case board
3. assign an analyst
4. use checklist tasks to track work
5. add notes and stories
6. pin important evidence
7. review activity, notifications, entity links, and scoped graph context
8. export an investigation report when ready

## Security Ops

Security-ops routes:

- `GET /integrity`
- `GET /integrity/history`
- `POST /integrity/refresh`
- `GET /observability/summary`
- `GET /enterprise/database/readiness`
- `GET /enterprise/report/security-ops`
- `POST /enterprise/report/security-ops/export`
- `POST /enterprise/secrets/rotate`
- `GET /enterprise/secrets/status`
- `POST /enterprise/maintenance/retention`

Use the `Security Ops` desktop tab for a safer operational entry point to these features.

## Telemetry Fabric

Routes:

- `GET /integrations/telemetry-fabric/status`
- `POST /integrations/telemetry-fabric/start`
- `POST /integrations/telemetry-fabric/stop`
- `POST /integrations/telemetry-fabric/export/incidents/{incident_id}`
- `GET /integrations/telemetry-fabric/exports`

Relevant files:

- `config/telemetry-fabric-runtime.yaml`
- `config/telemetry-fabric-builder.yaml`
- `scripts/build_telemetry_fabric.ps1`

## Packaging

Desktop packaging files:

- `desktop/build_exe.ps1`
- `desktop/shadowlab.spec`
- `desktop/shadowlab.iss`
- `desktop/version_info.txt`

## Safety

ShadowLab contains lab-only capabilities such as response actions, deception controls, packet sniffing, and network warfare helpers. Use only in environments you own and control.
