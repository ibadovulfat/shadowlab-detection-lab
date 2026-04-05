# ShadowLab Usage Guide

This guide walks through the normal operator flow for the backend, desktop client, integrations, casework, and security-operations features.

## Starting ShadowLab

Basic local mode:

```powershell
python app.py
python desktop\main.py
```

Auth-enabled local mode:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

Use the auth-enabled path when you want to validate role-based access, signed writes, approval-gated workflows, and admin-only controls.

## Typical Desktop Flow

1. confirm backend health
2. enter a key if auth is enabled
3. review `Dashboards`, `Overview`, `WHIDS`, or `HIDS`
4. pivot into `Processes` or `Advanced Hunt`
5. use `Threat Intel`, `Graph`, `Timeline`, and `Static Analysis` for context
6. create a case under `Enterprise` if the activity needs structured handling
7. export evidence or reports when the work is ready for handoff

The visual walkthrough is in [PLATFORM_GUIDE.md](PLATFORM_GUIDE.md).

## Auth And Signed Requests

Authenticated `POST`, `PATCH`, and `DELETE` operations are signed by the desktop client automatically. Direct API callers must sign:

- method
- path
- canonical query string
- request body hash
- timestamp
- nonce

Approval-gated operations also require `X-ShadowLab-Approval-Id` when policy says so.

## WHIDS And HIDS Workflow

Recommended `WHIDS` flow:

1. confirm manager URL, API key, and endpoint UUID
2. import manager detections or a known export file
3. review exports and normalized incidents
4. pull artifacts only when needed
5. manage scheduler, IoCs, and rules from the same workspace

Recommended `OSSEC/HIDS` flow:

1. import an approved alert file or point live ingest at a valid log path
2. review the normalized incidents first
3. plan response before applying it
4. use enterprise case creation when the alert becomes an investigation

Integration file imports are restricted to approved roots. Keep sample files under the expected ShadowLab or OSSEC directories instead of pointing the API at arbitrary paths.

## Process Investigation

Recommended flow:

1. load the process list
2. inspect the selected process profile and tree
3. review strings, internals, and network context
4. run YARA and memory analysis when the process deserves deeper review
5. use triage for a bundled summary
6. move into response only after confirming the process and policy context

## Threat Intelligence

Providers currently used in code:

- VirusTotal
- MalwareBazaar
- AbuseIPDB
- YARAify

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

These actions are policy-gated for a reason. Treat them like response actions, not convenience buttons.

## Enterprise Workflow

Typical enterprise flow:

1. create or select a case
2. review the board
3. assign ownership
4. track work through tasks
5. add notes and stories as the hypothesis sharpens
6. pin evidence that matters
7. review graph and timeline context
8. export the report when the case is ready to leave the workstation

Exported monitor and case handoff material is richer than before. Expect the generated report set to include:

- executive summary and incident narrative
- prioritized findings and ATT&CK references
- response guidance and analyst notes
- telemetry snapshot and event highlights
- artifact inventory for the current `shadowlab_out` workspace

The `Artifacts` tab is the fastest way to confirm what was generated before handing the case to another analyst or team.

## MITRE ATT&CK Workflow

Recommended flow:

1. load an approved STIX bundle
2. verify bundle status and compare it to the current dataset
3. review incident and case coverage
4. check tactic heat and rollups
5. export a Navigator layer or Workbench bundle if needed

## Security Ops

Use the desktop `Security Ops` tab unless you are debugging directly against the API. It is the safest operator entry point for integrity, observability, YARA health, readiness, and reporting.

## Verification Helpers

Useful commands:

- `python scripts/validate_deployment_runtime.py`
- `python scripts/rbac_smoke_matrix.py`
- `python scripts/perf_stability_probe.py`
- `python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key>`
- `powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome C:\Users\ulfat\Documents\ossec-hids-main`

## Safety

ShadowLab includes containment, deception, packet inspection, and network-assessment features. Keep it in controlled environments and assume every destructive action needs a second look before you run it.

updated

