# ShadowLab Architecture

ShadowLab is built as a local security platform rather than a single-script lab utility. The backend owns policy, authorization, and orchestration. The desktop client is the operator surface on top of that backend.

## Runtime Shape

```text
desktop/main.py  -> operator console
api/main.py      -> REST API, auth, RBAC, policy checks
services/        -> investigation, response, graph, enterprise, and telemetry logic
database.py      -> SQLite/PostgreSQL-backed persistence helpers
plugins/         -> host-native collection, response, YARA, and forensic modules
shadowlab_out/   -> generated reports, artifacts, exports, and runtime outputs
```

## Layer Breakdown

### API Layer

`api/main.py` exposes the platform surface for investigation, response, integrations, enterprise workflow, ATT&CK operations, and security-operations controls. It is also the final authority for RBAC, policy gates, signed mutations, and approval checks.

### Service Layer

The service layer keeps backend behavior out of the UI. Key services cover telemetry, process intelligence, incidents, response orchestration, enterprise case handling, graph and timeline correlation, ATT&CK lifecycle, and `WHIDS` or `OSSEC` integration logic.

### Persistence Layer

`database.py` stores platform state for incidents, host inventory, response and quarantine logs, auth and action audit logs, integration history, enterprise workflow data, approvals, YARA analytics, request nonces, and rate-limit counters.

SQLite is the default local runtime. PostgreSQL is supported when a shared runtime is needed.

### Desktop Layer

The desktop client provides the operator workflow for dashboards, integrations, process and hunt workflows, persistence, threat intel, static analysis, deception, graph, timeline, enterprise casework, and security-operations reporting.

The desktop reads capabilities from `/auth/context` and signs authenticated write requests so the backend can enforce policy consistently.

## Detection Model

ShadowLab uses a layered detection model:

- telemetry and event summarization
- heuristic scoring
- rule-based behavioral correlation
- local and memory YARA
- fused verdict generation for triage and response planning

Recent hardening added stricter request signing, DB-backed nonce and rate-limit tracking, import-path allowlists, and anti-evasion metrics for bursty traffic, low-and-slow beaconing, remote IP churn, and CPU or thread spikes.

## ATT&CK Layer

The ATT&CK layer is centralized in the backend so mapping and export behavior stays consistent. It handles approved bundle loading, bundle discovery, version comparison, incident and case enrichment, tactic heat calculation, Navigator export, and Workbench-oriented export.

## Enterprise Investigation Model

The enterprise side is case-first:

1. create or select a case
2. review the board
3. assign analysts and tasks
4. add notes, stories, and pinned evidence
5. review graph and timeline context
6. export the investigation package

That model is intentionally compact and operator-driven.

## Security Model

ShadowLab currently relies on:

- `viewer`, `analyst`, and `admin` roles
- policy profiles such as `lab`, `corp`, and `prod`
- feature flags for dangerous actions, deception, and network warfare
- signed authenticated mutations
- approval workflows for higher-risk actions
- server-side gating for destructive operations
- import allowlists for integration files

Auth-disabled mode is intentionally constrained. Elevated no-auth defaults are only valid in explicit lab conditions and loopback-bound setups.

## Strategic Direction

The platform is strongest as a Windows-first local workstation for host visibility, suspicious-process investigation, controlled response actions, case-driven investigation, and operator-ready reporting.
