# ShadowLab

> Use only in systems and networks you own or explicitly control.

**Created by [Ulfat Ibadov](https://www.linkedin.com/in/ibadovulfat/)**

ShadowLab is a Windows-focused security operations and research platform built around a local FastAPI backend and a PySide6 desktop client. It brings host telemetry, process investigation, persistence review, threat enrichment, response controls, graph and timeline context, deception tooling, and enterprise casework into one stack.

The platform is built for detection engineers, threat hunters, and security researchers who want one environment for studying how Windows tradecraft unfolds, where telemetry breaks down, and how case-driven response should look once detections become real investigations.

## What It Covers

- local telemetry collection and incident artifact generation
- process profiling, tree review, strings, internals, sandbox trace, YARA, and memory analysis
- persistence discovery, remediation, rollback, quarantine, and evidence capture
- threat-intelligence lookups for hashes and IPs
- `WHIDS` and `OSSEC/HIDS` ingest, live validation, and response orchestration
- case-driven enterprise workflow with assignments, tasks, notes, stories, pins, and exports
- `MITRE ATT&CK` lifecycle, coverage, Navigator export, and Workbench export
- security-operations controls for integrity, observability, secrets, readiness, and retention
- workspace-aware enterprise workflow, approval scoping, tenant-aware exports, and identity-backed RBAC groundwork

## Desktop Sections

The current desktop client includes:

- `Dashboards`
- `WHIDS`
- `HIDS`
- `Overview`
- `Processes`
- `Advanced Hunt`
- `Persistence`
- `Threat Intel`
- `Static Analysis`
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

Inside `Enterprise`, the workspace is split into `Enterprise Ops` and `Enterprise Intel`.

## Architecture

```text
api/         FastAPI routes, RBAC, policy enforcement, and request signing
core/        shared models and normalization helpers
services/    investigation, response, telemetry, enterprise, and graph logic
detections/  behavioral rules and scoring support
plugins/     host-native collection, response, YARA, and forensic modules
desktop/     PySide6 operator client
docs/        platform, usage, and operational guides
scripts/     startup, packaging, migration, and validation helpers
```

## Local YARA Layer

ShadowLab uses a layered YARA workflow tuned for Windows tradecraft:

- `YARAify` as the first external lookup
- local fallback and deep scan using ShadowLab rules plus curated community packs
- dedicated `Inceptor_*` and `Memory_*` rules for AMSI, ETW, manual map, APC, syscall, and unhooking tradecraft
- policy, tuning, telemetry, and compile-health reporting through the `Security Ops` workspace

Latest validated state:

- `enterprise_rules_requested = 1163`
- `enterprise_rules_loaded = 1163`
- `compile_error_count = 0`

Detailed notes are in [plugins/rules/YARA_VALIDATION.md](plugins/rules/YARA_VALIDATION.md).

## Static Analysis

The `Static Analysis` workspace can use Detect It Easy through the native `die-python` binding or an optional external binary:

- preferred backend: native `die-python`
- optional subprocess backend: `diec.exe` or `die.exe` via `SHADOWLAB_DIEC_PATH` or `PATH`
- fallback path: `pefile`-based structural PE analysis
- native DiE execution is isolated in a worker process to reduce crash impact
- the desktop now reports native runtime readiness correctly even when no external `diec.exe` path is configured

## Reporting And Artifacts

Monitor and case exports now produce fuller report output instead of a thin summary page.

- `ShadowLab_Report.pdf` includes executive summary, detection breakdown, analyst findings, response guidance, telemetry snapshot, security-event highlights, and artifact inventory
- `ShadowLab_Report.html` mirrors the same structure in a handoff-friendly format
- `Artifacts` is the quickest place to pull the current report set, telemetry exports, and investigation output

More detail is in [docs/DIE_INTEGRATION.md](docs/DIE_INTEGRATION.md).

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

That path enables role-aware auth, generates fresh keys when needed, and keeps dangerous actions off unless you opt in.

### 3. Start the desktop client

```powershell
python desktop\main.py
```

The desktop expects the backend at `http://127.0.0.1:8000` by default.

## Auth Model

ShadowLab supports three roles:

- `viewer`
- `analyst`
- `admin`

Relevant environment variables:

- `SHADOWLAB_REQUIRE_AUTH`
- `SHADOWLAB_API_KEYS`
- `SHADOWLAB_API_KEYS_SHA256`
- `SHADOWLAB_ALLOWED_ORIGINS`
- `SHADOWLAB_POLICY_PROFILE`
- `SHADOWLAB_NOAUTH_DEFAULT_ROLE`
- `SHADOWLAB_OIDC_ENABLED`
- `SHADOWLAB_OIDC_ISSUER`
- `SHADOWLAB_OIDC_AUDIENCE`
- `SHADOWLAB_ROLE_WORKSPACES`
- `SHADOWLAB_ACTOR_WORKSPACES`

Recommended practice:

1. generate fresh keys with `scripts\generate_api_keys.py`
2. store SHA-256 digests instead of raw keys where possible
3. keep `viewer` and `analyst` keys separate from admin workflows
4. use approval IDs for higher-risk actions in stricter policy profiles
5. in `corp` and `prod`, pass explicit workspace context and prefer OIDC-backed identity over shared API keys

Authenticated write operations now require signed requests. The desktop client handles that automatically.

Current enterprise hardening highlights:

- OIDC scaffold and identity revocation support exist alongside API key auth
- `lab`, `corp`, and `prod` policy profiles now share one matrix
- enterprise records, approvals, connector queue state, artifacts, and audit exports are workspace-aware
- connector storage now uses tenant-aware `workspace_id + name` persistence rather than a prefixed storage key workaround

## Validation

Useful checks shipped with the repository:

- `python scripts/validate_deployment_runtime.py`
- `python scripts/rbac_smoke_matrix.py`
- `python scripts/perf_stability_probe.py`
- `python scripts/smoke_test_live_integrations.py --base-url http://127.0.0.1:8000 --api-key <raw_admin_key>`
- `powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome C:\Users\ulfat\Documents\ossec-hids-main`

## Packaging

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

Related files:

- `desktop\shadowlab.spec`
- `desktop\shadowlab.iss`
- `desktop\version_info.txt`

## Documentation

- [docs/PLATFORM_GUIDE.md](docs/PLATFORM_GUIDE.md)
- [docs/USAGE_GUIDE.md](docs/USAGE_GUIDE.md)
- [docs/PRODUCTION_RUNBOOK.md](docs/PRODUCTION_RUNBOOK.md)
- [docs/ENTERPRISE_ROADMAP.md](docs/ENTERPRISE_ROADMAP.md)
- [docs/POLICY_MATRIX.md](docs/POLICY_MATRIX.md)
- [docs/ShadowLab.pdf](docs/ShadowLab.pdf)
- [desktop/README.md](desktop/README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [TOP10_ROADMAP.md](TOP10_ROADMAP.md)

## Licensing

The repository's primary licensing and usage restrictions are defined in [LICENSE](LICENSE).
An Apache 2.0 text copy is also included in [LICENSE-APACHE](LICENSE-APACHE) for future dual-licensing or component-specific use, but it does not override the repository-wide terms in [LICENSE](LICENSE) unless explicitly stated for a specific file, component, or release.

## Screenshots

![Dashboards Workspace](images/shadowlab-dashboard-wall.png)
Quick SOC wall for platform health, threat posture, and workflow entry points.

![WHIDS Workspace](images/shadowlab-whids-integration.png)
WHIDS manager sync, report ingest, artifact pull, and scheduler controls.

![HIDS Workspace](images/shadowlab-hids-integration.png)
OSSEC/HIDS alert ingestion, live status, and response-oriented operations.

![Overview Workspace](images/shadowlab-monitor-overview.png)
High-signal incident brief with triage context and operator summary.

![Advanced Hunt Workspace](images/shadowlab-advanced-hunt.png)
Deep-dive investigation area for process internals, strings, and hunt output.

![Persistence Workspace](images/shadowlab-persistence-remediatio.png)
Persistence discovery and remediation workflow for long-lived footholds.

![Threat Intel Workspace](images/shadowlab-threat-intel-enrichmen.png)
Hash/IP enrichment and provider-backed threat correlation workflow.

![Static Analysis Workspace](images/shadowlab-static-pe-analysis.png)
Detect It Easy and PE-focused static malware analysis panel.

![Deception Workspace](images/shadowlab-deception-evidence-ops.png)
Deception and evidence capture workspace for controlled detection tests.

![Network Workspace](images/shadowlab-network-telemetry-bloc.png)
Network telemetry and device visibility for lateral context.

![Graph Workspace](images/shadowlab-attack-surface-graph.png)
Relationship graph for entities, incidents, and attack-surface correlation.

![Timeline Workspace](images/shadowlab-timeline-story.png)
Chronological event story for incident reconstruction.

![Quarantine Workspace](images/shadowlab-quarantine-alert-workf.png)
Containment, restore, and quarantine tracking operations.

![History Workspace](images/shadowlab-incident-history-audit.png)
Incident, action, and audit history for retrospective investigation.

![Artifacts Workspace](images/shadowlab-artifact-evidence-stor.png)
Central store for reports, evidence, and exported investigation artifacts.

![Enterprise Workspace](images/shadowlab-enterprise-case-ops.png)
Case-centric enterprise workflow with assignments, tasks, and approvals.

![Security Ops Workspace](images/shadowlab-security-ops-readiness.png)
Operational readiness view for integrity, secrets, and security controls.

![Scenarios Workspace](images/shadowlab-attack-scenario-simula.png)
Adversary simulation runner for repeatable telemetry generation.

![About FAQ Workspace](images/shadowlab-about-faq-profile.png)
Product overview and creator profile with quick project links.

## Safety

This repository includes lab-only features such as response actions, deception controls, packet inspection, and network assessment helpers. Keep it in isolated environments and treat it like a security tool, not a general-purpose desktop app.

updated

