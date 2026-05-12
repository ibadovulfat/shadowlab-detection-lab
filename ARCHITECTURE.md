# ShadowLab Architecture

ShadowLab is built as a local security operations platform rather than a single-script lab utility. The backend owns policy, authorization, persistence, orchestration, and security gates. The desktop client is the operator surface on top of that backend.

## Runtime Shape

```text
desktop/main.py  -> PySide6 operator console
app.py           -> uvicorn entrypoint for api.main:app
api/             -> REST API, auth, RBAC, signing, middleware, route modules, workers
services/        -> investigation, antivirus, response, graph, enterprise, telemetry, security logic
database.py      -> SQLite/PostgreSQL-backed persistence helpers
plugins/         -> host-native collection, YARA, sandbox, forensic, sniffer, and network helpers
shadowlab_out/   -> reports, artifacts, exports, audit mirrors, and runtime outputs
```

## Layer Breakdown

### API Layer

`api/main.py` assembles the platform surface for auth, process investigation, persistence, evidence, network, graph, timeline, antivirus, integrations, enterprise workflow, ATT&CK operations, artifacts, audit, observability, and security-operations controls. It is also the final authority for RBAC, policy gates, signed mutations, rate limits, replay protection, and approval checks.

### Service Layer

The service layer keeps backend behavior out of the UI. Key services cover telemetry, process intelligence, malware analysis, static PE inspection, antivirus verdicts, incident handling, response orchestration, enterprise case handling, graph and timeline correlation, ATT&CK lifecycle, WHIDS/OSSEC integration logic, integrity, secrets, observability, and outbound request safety.

### Persistence Layer

`database.py` stores platform state for incidents, host inventory, response and quarantine logs, auth and action audit logs, integration history, enterprise workflow data, approvals, YARA analytics, request nonces, rate-limit counters, connector queue state, migrations, and settings.

SQLite is the default local runtime. PostgreSQL is supported when a shared or enterprise runtime is needed.

### Desktop Layer

The desktop client provides the operator workflow for dashboards, WHIDS/HIDS integrations, overview, process investigation, persistence, file analysis, network, graph, timeline, antivirus containment, history, artifacts, enterprise casework, security operations, and About / FAQ.

The desktop reads capabilities from `/auth/context` and signs authenticated write requests so the backend can enforce policy consistently.

## Detection Model

ShadowLab uses a layered detection model:

- telemetry and event summarization
- heuristic process scoring
- rule-based behavioral correlation
- local and memory YARA
- external enrichment when configured
- fused verdict generation for triage, antivirus workflow, and response planning

Recent hardening added stricter request signing, DB-backed nonce and rate-limit tracking, import-path allowlists, audit mirrors, network-action capability separation, and anti-evasion metrics for bursty traffic, low-and-slow beaconing, remote IP churn, and CPU or thread spikes.

## Network And Containment Model

Network visibility and containment are intentionally split by privilege:

- packet capture is an analyst/admin workflow through `can_run_sniffer`
- ARP discovery is an analyst/admin discovery workflow
- network blocker start/stop remains admin-only and requires dangerous actions plus network-warfare enablement
- antivirus containment actions are policy-gated and audited

This keeps read/discovery workflows available for investigation while preserving strict gates around host- or network-impacting actions.

## ATT&CK Layer

The ATT&CK layer is centralized in the backend so mapping and export behavior stays consistent. It handles approved bundle loading, bundle discovery, version comparison, incident and case enrichment, tactic heat calculation, Navigator export, and Workbench-oriented export.

## Enterprise Investigation Model

The enterprise side is case-first:

1. create or select a case
2. review the board
3. assign analysts and tasks
4. add notes, stories, and pinned evidence
5. review graph, timeline, and ATT&CK context
6. export the investigation package

That model is intentionally compact and operator-driven.

## Security Model

ShadowLab currently relies on:

- `viewer`, `analyst`, and `admin` roles
- policy profiles: `lab`, `corp`, and `prod`
- feature flags for dangerous actions and network warfare
- signed authenticated mutations
- approval workflows for higher-risk actions
- server-side gating for destructive operations
- import allowlists for integration files
- secret storage and rotation posture checks
- security headers, origin controls, trusted proxy handling, and body-size limits

Auth-disabled mode is intentionally constrained. Elevated no-auth defaults should only be used in explicit lab conditions and loopback-bound setups.

## Strategic Direction

The platform is strongest as a Windows-first local workstation for host visibility, suspicious-process investigation, controlled response actions, case-driven investigation, malware triage, network context, and operator-ready reporting.
