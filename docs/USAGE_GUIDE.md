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
3. inspect dashboards, `WHIDS`, `HIDS`, and overview
4. investigate suspicious processes
5. use `Static Analysis` when file-oriented malware review is needed
6. triage, enrich, and review graph or timeline context
7. open or work an enterprise case if needed
8. export findings or reports

Current desktop screenshots and section descriptions are documented in [PLATFORM_GUIDE.md](PLATFORM_GUIDE.md).

## WHIDS And HIDS Workflow

Key integration routes:

- `POST /integrations/whids/import/file`
- `POST /integrations/whids/import/manager`
- `POST /integrations/whids/reports`
- `POST /integrations/whids/artifacts`
- `POST /integrations/whids/config`
- `POST /integrations/whids/report-archive`
- `POST /integrations/whids/iocs/query`
- `POST /integrations/whids/iocs/add`
- `POST /integrations/whids/iocs/delete`
- `POST /integrations/whids/rules/query`
- `POST /integrations/whids/rules/add`
- `POST /integrations/whids/rules/delete`
- `POST /integrations/whids/scheduler/start`
- `POST /integrations/whids/scheduler/stop`
- `GET /integrations/whids/scheduler/status`
- `POST /integrations/ossec/import/file`
- `POST /integrations/ossec/live/start`
- `POST /integrations/ossec/live/stop`
- `GET /integrations/ossec/live/status`
- `POST /integrations/incidents/{incident_id}/response`

Recommended `WHIDS` workflow:

1. verify manager URL, API key, and endpoint UUID
2. import manager detections or file exports
3. sync reports and archive data
4. pull artifacts only when needed
5. use scheduler for repeated polling
6. manage rules and IoCs from the dedicated workspace

Recommended `HIDS/OSSEC` workflow:

1. import alert exports or `alerts.log`
2. enable live ingest when monitoring an active stream
3. review normalized incidents and enterprise linkage
4. plan response first
5. apply response only after review or explicit policy decision

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
5. let ShadowLab fall back to local YARA and memory YARA when external results are weak or unavailable
6. run sandbox trace for short-lived behavior capture
7. use one-click triage for a bundled view
8. take response action only after review

Current local YARA packs:

- `fast`
- `balanced`
- `enterprise`
- `memory`

Current validated enterprise-pack state:

- `rules_master = 434`
- `signature_base = 726`
- `enterprise = 1163`
- `compile_error_count = 0`

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

## MITRE ATT&CK

MITRE routes:

- `GET /enterprise/mitre/status`
- `GET /enterprise/mitre/discover`
- `POST /enterprise/mitre/load-bundle`
- `POST /enterprise/mitre/compare`
- `POST /enterprise/mitre/changelog`
- `GET /enterprise/mitre/summary`
- `GET /enterprise/mitre/techniques/{attack_id}`
- `GET /enterprise/mitre/incidents/{incident_id}/coverage`
- `GET /enterprise/cases/{case_id}/mitre`
- `POST /enterprise/mitre/navigator/export`
- `POST /enterprise/mitre/workbench/export`

Typical ATT&CK workflow:

1. load a STIX bundle from the desktop `Load ATT&CK` action or the load-bundle API
2. review discovered bundles and compare the currently selected bundle
3. inspect enterprise ATT&CK coverage and case ATT&CK rollup
4. review tactic heat, sub-technique counts, parent rollup, and telemetry cues
5. export Navigator coverage
6. export Workbench coverage when annotation or relationship work should continue outside ShadowLab

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

Local YARA operational routes:

- `GET /yara/local/health`
- `GET /yara/local/policy`
- `PUT /yara/local/policy`
- `GET /yara/local/errors`
- `GET /yara/local/analytics`
- `POST /yara/local/tuning/rule`
- `GET /yara/local/update-workflow`
- `POST /yara/local/update-workflow/snapshot`

## Verification Helpers

Useful validation commands:

- `python scripts/validate_deployment_runtime.py`
- `python scripts/rbac_smoke_matrix.py`
- `python scripts/perf_stability_probe.py`
- `python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key>`

Native `OSSEC` validation still requires an elevated shell:

- `powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome C:\Users\ulfat\Documents\ossec-hids-main`

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
