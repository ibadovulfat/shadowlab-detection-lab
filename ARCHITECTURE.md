# ShadowLab Architecture

ShadowLab is no longer a single-surface lab app. The current shape is a local platform with a FastAPI backend, a PySide6 desktop client, shared services, and enterprise investigation flows on top of the same data model.

## Runtime Shape

```text
desktop/main.py  ->  local operator console
api/main.py      ->  REST API, auth, RBAC, feature gating
services/        ->  orchestration and domain logic
database.py      ->  SQLite/PostgreSQL-backed persistence helpers
plugins/         ->  host-native collection and response modules
shadowlab_out/   ->  generated artifacts, reports, and runtime outputs
```

## Major Layers

### API layer

`api/main.py` exposes:

- process investigation endpoints
- incident and history endpoints
- WHIDS and HIDS integration endpoints
- MITRE ATT&CK lifecycle, coverage, and export endpoints
- enterprise case and investigation endpoints
- integrity, observability, secrets, and retention controls
- auth context and RBAC enforcement

The API is the source of truth for authorization. The desktop reads capability flags from `/auth/context` and adapts the UI, but permission enforcement remains server-side.

### Service layer

Key services include:

- telemetry and incident orchestration
- response and persistence handling
- process intelligence
- WHIDS and HIDS integration orchestration
- MITRE ATT&CK dataset lifecycle, inference, and export orchestration
- graph correlation
- enterprise case management
- investigation workspace assembly
- reporting and export logic

This layer keeps desktop concerns separate from backend behavior so the same API can serve future clients or automation.

### Local YARA layer

ShadowLab now includes a dedicated local YARA layer that sits between external threat-intel lookups and operator response.

That layer currently provides:

- `YARAify` first-pass external lookup
- curated local YARA fallback and deep scan packs
- community pack ingestion from `rules-master` and `signature-base-master`
- ShadowLab-specific `Inceptor_*` and `Memory_*` tradecraft rules
- pack strategies such as `fast`, `balanced`, `enterprise`, and `memory`
- rule suppression, allowlist, registry tuning, telemetry, and compile-health reporting

The current enterprise pack excludes broad, low-value noise sources such as `domain.yar` and `RAT_PoetRATPython.yar` so fused verdicts stay readable.

### Persistence layer

`database.py` backs:

- incidents
- integration export history
- case workflow
- approvals
- tasks and assignments
- investigation notes, stories, pins, and saved views
- integrity history
- observability logs
- connector and secret state

SQLite remains the default local mode. PostgreSQL is supported as a shared runtime target through environment configuration and migration scripts.

### Desktop layer

The desktop is the operator-facing control plane. It exposes:

- telemetry and process workflows
- threat-intel and persistence review
- graph, timeline, and artifacts
- enterprise investigation workflows
- ATT&CK lifecycle, coverage, Navigator export, and Workbench export flows
- security-ops controls

Recent UI design choices:

- large workspaces are local-scroll surfaces instead of forcing full-window growth
- `Enterprise` is split into `Enterprise Ops` and `Enterprise Intel`
- heavy enterprise refresh behavior is deferred to avoid UI freezes
- role-aware controls respect server capability flags

## MITRE ATT&CK Layer

The current architecture now includes a dedicated ATT&CK intelligence layer.

That layer is responsible for:

- loading STIX ATT&CK bundles from approved local paths
- caching and discovering known ATT&CK bundle candidates
- comparing current and candidate bundles
- parsing ATT&CK tactic, technique, mitigation, software, and relationship data
- enriching incidents and cases with explicit and inferred ATT&CK mappings
- calculating tactic heat, progression, sub-technique counts, and parent rollups
- exporting ATT&CK Navigator layers
- exporting Workbench-oriented coverage bundles
- feeding mapped techniques into response-policy decisions

This keeps ATT&CK logic centralized in the backend instead of scattering mapping and export logic across the UI.

## Enterprise Investigation Model

The enterprise workspace is built around a case-first flow:

1. create or load a case
2. review the case board
3. assign analysts
4. work checklist tasks
5. pin evidence and add notes
6. capture stories and hypotheses
7. review activity, timeline, notifications, and linked entities
8. export investigation reports

Key backend objects:

- cases
- case chain entries
- assignments
- tasks
- activity entries
- notes
- stories
- pins
- saved views
- scoped case graphs

## Security Model

ShadowLab uses:

- `viewer`, `analyst`, and `admin` roles
- feature flags for dangerous actions, deception, and network warfare
- policy profiles such as `lab`, `corp`, and `prod`
- approval workflows for higher-risk operations in stricter policy modes

Notable hardening points:

- auth-disabled mode no longer causes the desktop to present fake admin state
- approval one-time use is reserved and finalized atomically to avoid duplicate use races
- dangerous endpoints remain gated server-side even if a client is modified
- signed mutations are enforced for authenticated write operations
- WHIDS scheduler runtime secrets are stored encrypted instead of plaintext
- OSSEC native response execution validates IP input and avoids shell-style command composition
- MITRE bundle access is limited to approved ATT&CK roots instead of arbitrary local JSON paths
- ATT&CK bundle discovery uses caching to avoid repeated recursive scans during enterprise refresh

## Strategic Direction

The strongest direction remains a Windows-first security workstation with:

- local host visibility
- rich process investigation
- operator-led response
- case-driven investigation
- desktop-first workflows

Fleet or remote management can be layered later, but the current product is intentionally optimized for local or lab-controlled operations first.

## Integration Runtime Layer

The current platform also includes a provider-oriented runtime layer above the core API:

- `WHIDS` manager and file ingest
- `WHIDS` reports, report archive, artifacts, rules, IoCs, and scheduler
- `OSSEC/HIDS` file ingest and live ingest
- normalized incident storage and dedupe logging
- enterprise auto-case, note, pin, and chain-of-custody correlation
- orchestration planning and policy-driven response execution

This is the layer that turns ShadowLab from a purely local telemetry console into a unifying investigation surface for multiple detection sources.
