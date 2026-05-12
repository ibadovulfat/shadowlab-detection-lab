# ShadowLab Usage Guide

This guide walks through the normal operator flow for the backend, desktop client, integrations, casework, containment, and security-operations features.

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

Lab-only mode for destructive and network-warfare controls:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1 -EnableDangerousActions -EnableNetworkWarfare
python desktop\main.py
```

Use the auth-enabled path when you want to validate role-based access, signed writes, approval-gated workflows, and admin-only controls.

## Typical Desktop Flow

1. confirm backend health
2. enter a key if auth is enabled
3. review `Dashboards`, `Overview`, `WHIDS`, or `HIDS`
4. pivot into `Processes`
5. use `Persistence`, `File Analysis`, `Network`, `Graph`, and `Timeline` for context
6. use `Antivirus` when verdict, quarantine, or containment workflow is needed
7. create a case under `Enterprise` if the activity needs structured handling
8. export evidence or reports when the work is ready for handoff

The visual walkthrough is in [PLATFORM_GUIDE.md](PLATFORM_GUIDE.md).

## Auth And Signed Requests

Authenticated `POST`, `PUT`, `PATCH`, and `DELETE` operations are signed
by the desktop client automatically. Direct API callers must sign:

- HTTP method
- request path
- canonical query string (RFC 3986 percent-encoded, key-sorted)
- SHA-256 of the request body
- timestamp (Unix epoch seconds)
- per-request nonce

Approval-gated operations also require `X-ShadowLab-Approval-Id` when the
active policy demands it.

Note: `PUT` was added to the signed-mutation set in `v0.0.8`. Earlier
clients that only signed `POST` / `PATCH` / `DELETE` must be updated
before upgrading the backend to `v0.0.8` or later.

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
6. move into response only after confirming process identity and policy context

## File Analysis

Recommended flow:

1. choose a file or use the selected process executable
2. confirm `File Analysis` runtime status
3. run static PE and Detect It Easy analysis
4. review packer/compiler/cryptor hints, imports, sections, and high-signal highlights
5. connect the result back to process triage, antivirus verdicts, or enterprise case notes

## Network, Graph, And Timeline

Network workflows are privilege-aware:

- packet capture is analyst/admin and limited to the backend-accepted duration range
- ARP discovery is a discovery workflow for analyst/admin users
- blocker start/stop is admin-only and requires dangerous actions plus network-warfare enablement

Use `Graph` to explain relationships and `Timeline` to reconstruct order of events. These views are most useful after process or antivirus evidence has already narrowed the investigation.

## Antivirus And Containment

Use `Antivirus` for:

- provider readiness
- scan jobs
- verdict history
- quarantine and restore workflow
- response actions
- watcher state
- webhooks
- rules and lists

Containment and destructive actions are policy-gated and audited. Treat them as response actions, not convenience buttons.

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

These actions are policy-gated for a reason. Confirm scope, actor, approval ID, and workspace before changing host state.

## Enterprise Workflow

Typical enterprise flow:

1. create or select a case
2. review the board
3. assign ownership
4. track work through tasks
5. add notes and stories as the hypothesis sharpens
6. pin evidence that matters
7. review graph, timeline, and ATT&CK context
8. export the report when the case is ready to leave the workstation

Exported monitor and case handoff material includes:

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

Use the desktop `Security Ops` tab unless you are debugging directly against the API. It is the safest operator entry point for integrity, observability, YARA health, readiness, secrets, audit export, and reporting.

## Verification Helpers

Useful commands:

- `python scripts/validate_deployment_runtime.py`
- `python scripts/rbac_smoke_matrix.py`
- `python scripts/perf_stability_probe.py`
- `python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key>`
- `powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome <ossec_home>`
- `python scripts/validate_detection_corpus.py`

## Safety

ShadowLab includes containment, packet inspection, ARP discovery, network blocker, and assessment features. Keep it in controlled environments and assume every destructive action needs a second look before you run it.
