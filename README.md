# ShadowLab

> Use only in owned, isolated, lab environments.

**Created by [Ulfat Ibadov](https://www.linkedin.com/in/ibadovulfat/)**

ShadowLab is an API-first Windows security operations and research platform. It combines host telemetry, process investigation, response controls, persistence review, threat-intelligence enrichment, deception tooling, and an enterprise investigation workspace in one local stack.

## What It Does

- collects local telemetry and incident artifacts
- investigates suspicious processes with deeper host context
- tracks persistence, quarantine, history, evidence, and timeline data
- supports role-based access with viewer, analyst, and admin scopes
- provides a PySide6 desktop client for day-to-day operator workflows
- adds enterprise case handling, assignments, tasks, notes, stories, approvals, reporting, graph correlation, and security-ops controls

## Current Desktop Surface

Main desktop tabs:

- `Dashboards`
- `Overview`
- `Processes`
- `Advanced Hunt`
- `Persistence`
- `Threat Intel`
- `Deception`
- `Network`
- `Hosts`
- `Graph`
- `Timeline`
- `Quarantine`
- `History`
- `Artifacts`
- `Enterprise`
- `Security Ops`
- `Scenarios`
- `About / FAQ`

Inside `Enterprise`, the workspace is split into:

- `Enterprise Ops`
- `Enterprise Intel`

## Images

### Overview Telemetry Dashboard

![Overview Telemetry Dashboard](images/overview-telemetry-dashboard.png)

### Process Intelligence Workspace

![Process Intelligence Workspace](images/process-intelligence-workspace.png)

### Graph Workspace

![Graph Workspace](images/graph-workspace.png)

### About Creator Profile

![About Creator Profile](images/about-creator-profile.png)

## Key Capabilities

- telemetry monitoring with CPU, memory, thread, handle, file, TCP, and bandwidth metrics
- Windows Defender and Sysmon event summarization
- rule-based and scored behavioral detections
- incident bundle generation and incident status updates
- process profile, tree, memory-analysis metadata, strings, internals, YARAify enrichment, sandbox trace, AI analysis, and one-click triage
- persistence discovery, remediation, and rollback workflows
- threat-intel lookups for hashes and IPs
- quarantine center, artifacts, HTML reporting, and evidence capture
- deception workflows for honeypots and canaries
- graph and timeline correlation views
- enterprise case workflow with boards, activity feed, assignments, tasks, notes, stories, saved views, pinning, scoped case graphs, executive investigation exports, and notification center
- security-ops controls for integrity, observability, secrets, database readiness, retention, and telemetry-fabric operations

## Architecture

```text
api/         FastAPI routes and auth/authorization enforcement
core/        Shared models and normalization helpers
services/    Investigation, graph, response, telemetry, incident, and enterprise logic
detections/  YAML rule packs and detection engine
plugins/     Host-native forensic, network, deception, and persistence modules
desktop/     PySide6 desktop client
docs/        Usage and production operation guides
scripts/     Startup, auth, packaging, migration, and verification helpers
```

## Quick Start

### 1. Create a virtual environment

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the API

Basic local start:

```powershell
python app.py
```

Auth-enabled local start:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
```

This starts the API with:

- `SHADOWLAB_REQUIRE_AUTH=true`
- role-based API keys
- lab policy flags suitable for local controlled testing

### 3. Start the desktop client

```powershell
python desktop\main.py
```

The desktop expects the backend at `http://127.0.0.1:8000` by default.

## Role-Based Auth

ShadowLab supports three roles:

- `viewer`
- `analyst`
- `admin`

Runtime auth environment variables:

- `SHADOWLAB_REQUIRE_AUTH`
- `SHADOWLAB_API_KEYS`
- `SHADOWLAB_API_KEYS_SHA256`
- `SHADOWLAB_ALLOWED_ORIGINS`

Recommended approach:

1. Generate fresh keys with `scripts\generate_api_keys.py`
2. Store only SHA-256 hashes in environment variables
3. Start the backend with auth enabled
4. Paste the raw key into the desktop `API Key` field

Desktop behavior:

- role and capabilities are pulled from `GET /auth/context`
- actions are hidden or disabled based on capability flags
- if backend auth is disabled, the desktop does not fake privileged access

## Enterprise Investigation Workflow

`Enterprise Ops` includes:

- case controls
- case board
- assignments
- tasks and checklist state
- activity feed
- notifications
- report export

`Enterprise Intel` includes:

- critical assets
- detection lifecycle view
- notes and stories
- case timeline
- entity links
- graph correlation

Current investigation APIs include:

```text
GET  /enterprise/investigations/workspace
POST /enterprise/investigations/views
GET  /enterprise/investigations/views
POST /enterprise/investigations/notes
GET  /enterprise/investigations/notes
POST /enterprise/investigations/stories
GET  /enterprise/investigations/stories
POST /enterprise/investigations/pins
GET  /enterprise/investigations/pins
GET  /enterprise/cases/{case_id}/board
GET  /enterprise/cases/{case_id}/graph
POST /enterprise/cases/{case_id}/assignments
GET  /enterprise/cases/{case_id}/assignments
POST /enterprise/cases/{case_id}/tasks
GET  /enterprise/cases/{case_id}/tasks
PATCH /enterprise/cases/{case_id}/tasks/{task_id}
GET  /enterprise/cases/{case_id}/activity
POST /enterprise/cases/{case_id}/investigation-report/export
```

## Main API Areas

Core endpoints:

```text
GET  /health
GET  /auth/context
POST /monitor/run
GET  /processes
GET  /processes/{pid}
GET  /processes/{pid}/tree
GET  /processes/{pid}/internals
POST /processes/{pid}/strings
POST /processes/{pid}/yara
POST /processes/{pid}/sandbox-trace
GET  /processes/{pid}/ai-analysis
POST /processes/{pid}/scan
GET  /processes/{pid}/memory-analysis
POST /processes/{pid}/actions/{action}
GET  /persistence
POST /persistence/remediate
POST /persistence/rollback/{remediation_id}
GET  /threat-intel/ip/{ip}
GET  /threat-intel/hash/{file_hash}
POST /threat-intel/hash/lookup
GET  /incidents
PATCH /incidents/{incident_id}
GET  /timeline
GET  /timeline/graph
GET  /hosts
GET  /graph/entity-map
GET  /graph/entity-map/html
POST /triage/{pid}
GET  /artifacts
GET  /artifacts/{filename}
GET  /reports/html
```

Enterprise and security-ops endpoints:

```text
GET  /enterprise/policy
GET  /enterprise/assets
GET  /enterprise/triage
POST /enterprise/cases
GET  /enterprise/cases
POST /enterprise/cases/{case_id}/chain
GET  /enterprise/cases/{case_id}/chain
POST /enterprise/approvals
PATCH /enterprise/approvals/{approval_id}
GET  /enterprise/approvals
GET  /enterprise/detections/lifecycle
POST /enterprise/detections/lifecycle
POST /enterprise/detections/false-positive
GET  /enterprise/connectors
POST /enterprise/connectors
POST /enterprise/connectors/dispatch
POST /enterprise/connectors/queue/process
GET  /enterprise/connectors/queue
GET  /enterprise/abuse/summary
POST /enterprise/maintenance/retention
GET  /enterprise/database/readiness
GET  /enterprise/report/security-ops
POST /enterprise/report/security-ops/export
POST /enterprise/secrets/rotate
GET  /enterprise/secrets/status
GET  /enterprise/adversary/profiles
POST /enterprise/purple/replay
GET  /enterprise/canary/bypass
GET  /enterprise/telemetry/gaps
GET  /enterprise/web/inspection
POST /enterprise/network/assessment
GET  /integrity
GET  /integrity/history
POST /integrity/refresh
GET  /observability/summary
GET  /integrations/telemetry-fabric/status
POST /integrations/telemetry-fabric/start
POST /integrations/telemetry-fabric/stop
POST /integrations/telemetry-fabric/export/incidents/{incident_id}
GET  /integrations/telemetry-fabric/exports
```

## Security Notes

- `viewer` is read-heavy and cannot run dangerous actions
- `analyst` can investigate, triage, capture evidence, and work cases
- `admin` can perform protected operational actions when policy flags allow it
- dangerous and destructive operations are additionally gated by feature flags and, in stricter policy modes, approvals
- approval consumption is handled with a reserve/finalize flow to avoid one-time-use races

## Desktop Packaging

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

Related assets:

- `desktop\shadowlab.spec`
- `desktop\shadowlab.iss`
- `desktop\version_info.txt`

## Operations And Runbooks

- [docs/PLATFORM_GUIDE.md](docs/PLATFORM_GUIDE.md)
- [docs/USAGE_GUIDE.md](docs/USAGE_GUIDE.md)
- [docs/PRODUCTION_RUNBOOK.md](docs/PRODUCTION_RUNBOOK.md)
- [desktop/README.md](desktop/README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [TOP10_ROADMAP.md](TOP10_ROADMAP.md)

## Safety

This repository includes lab-only capabilities including process action workflows, deception controls, packet inspection, and network assessment helpers. Use only on systems and networks you own and control.
