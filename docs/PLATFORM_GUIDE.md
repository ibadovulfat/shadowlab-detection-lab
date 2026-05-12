# ShadowLab Platform Guide

ShadowLab is a locally operated, API-first cybersecurity operations platform centered on a PySide6 desktop console and a FastAPI backend. It is designed for Windows-focused investigation, detection engineering, incident response practice, malware triage, enterprise casework, and security-operations readiness.

The goal of this guide is to describe the current product shape: what exists now, how the major workspaces fit together, and how an operator should move through the platform.

## What ShadowLab Is Today

At the center of the platform is a FastAPI backend. It owns authentication, RBAC, policy checks, signed mutations, approval handling, route orchestration, background workers, persistence, and security posture validation. The desktop client is the operator-facing layer that turns those capabilities into a practical investigation workflow.

The current product combines multiple layers:

- live and collected host telemetry
- process investigation and risk scoring
- persistence discovery and remediation
- file and malware analysis
- WHIDS and OSSEC/HIDS integration workflows
- network telemetry, packet capture, ARP discovery, graph correlation, and timeline reconstruction
- antivirus-style verdict, quarantine, and containment operations
- enterprise case management and ATT&CK coverage
- artifacts, reports, audit history, integrity, observability, and secret posture

## What Has Already Been Built

The repository has moved beyond a prototype. The main layers are already in place.

The backend layer has route modules for auth, processes, persistence, evidence, quarantine, network, network-warfare, hosts, graph, timeline, antivirus, artifacts, audit, integrations, enterprise, MITRE, observability, security operations, and related utility workflows.

The desktop layer now exposes a role-aware operator console with tabs for `Dashboards`, `WHIDS`, `HIDS`, `Overview`, `Processes`, `Persistence`, `File Analysis`, `Network`, `Graph`, `Timeline`, `Antivirus`, `History`, `Artifacts`, `Enterprise`, `Security Ops`, and `About / FAQ`.

The enterprise investigation layer is case-first. It includes case boards, assignments, checklist-style tasks, notes, stories, pins, saved views, activity, scoped graph correlation, ATT&CK rollups, timeline support, notifications, and report export.

Important security improvements are already present:

- role-aware API key auth with `viewer`, `analyst`, and `admin`
- signed authenticated `POST`, `PATCH`, and `DELETE` requests
- structured approval handling for higher-risk actions
- policy profiles for `lab`, `corp`, and `prod`
- feature flags for dangerous actions and network warfare
- replay protection and rate limiting
- trusted-proxy and origin controls
- encrypted secret storage and rotation posture checks
- audit mirroring from desktop consoles

## How The Architecture Is Organized

The `api/` directory contains route modules, middleware, schemas, observability helpers, bootstrap wiring, and background workers. The `services/` directory holds investigation, antivirus, graph, response, telemetry, enterprise, identity, MITRE, malware analysis, static PE, secret, webhook, and integrity logic. `database.py` manages SQLite and PostgreSQL-ready persistence. `desktop/` contains the operator UI. `docs/` stores operational documentation. `scripts/` contains startup, packaging, migration, backup, audit, and validation helpers.

The strength of this design is separation: the UI is an operator surface, while the backend remains the policy and orchestration authority.

## Desktop Sections

`Dashboards` and `Overview` give the operator a broad picture of current platform state, auth mode, incident posture, telemetry pressure, and investigation summaries.

`WHIDS` and `HIDS` expose provider-oriented workflows for import, live status, artifact pull, scheduler state, IoC/rule lifecycle, and enterprise jump-off. `WHIDS` focuses on manager and export-based EDR ingestion. `HIDS` focuses on OSSEC-style alert ingestion and response planning.

`Processes` is one of the main investigation entry points. It allows the operator to inspect process profiles, process trees, extracted strings, internals, YARAify enrichment, sandbox traces, AI analysis, and triage context.

That process workflow includes local YARA fallback, memory YARA enrichment, and fused verdict scoring built from curated community and ShadowLab tradecraft rules. Broad community noise is intentionally filtered out of the enterprise pack so verdicts remain readable.

`Persistence` is used to review autoruns, scheduled tasks, services, and other persistence artifacts, and to trigger rollback-aware remediation when policy allows it.

`File Analysis` is the file-focused malware-analysis section. It presents Detect It Easy readiness, file/process submission, PE structure, extracted highlights, and raw output in a way that complements live process triage.

`Network`, `Graph`, and `Timeline` help the operator understand events in a wider context. Network gives connection and discovery context, packet capture, ARP discovery, and blocker controls. Graph visualizes entity relationships. Timeline reconstructs the story chronologically.

`Antivirus` provides provider health, scan jobs, verdict history, quarantine, signatures, response, watcher, webhooks, rules, lists, and containment operations. It is the main surface for antivirus-style workflow in the current UI.

`History` and `Artifacts` store the outcome of investigation and response work. History centralizes incident/action/auth audit views. Artifacts stores generated reports, exported evidence, and investigation material.

`Enterprise` behaves as a compact investigation suite. `Enterprise Ops` manages case-centric workflow, while `Enterprise Intel` focuses on intelligence, correlation, and ATT&CK context.

`Security Ops` holds operational security controls such as integrity, observability, readiness, secret rotation, YARA health, audit export, and security reporting.

`About / FAQ` presents product identity, project links, and creator profile information.

## What The Enterprise Layer Adds

Inside `Enterprise Ops`, the operator selects or creates a case and then sees board state, assignments, tasks, approvals, notes, activity, and export actions. It becomes easy to understand who is working on a case, what remains open, and what is ready for handoff.

`Enterprise Intel` provides a more analytical view. It brings together critical asset visibility, detection lifecycle data, ATT&CK coverage, tactic heat, bundle lifecycle diff, case ATT&CK rollup, notes, stories, case timeline, entity links, and scoped graph correlation.

This moves ShadowLab closer to a compact SOC-style investigation platform rather than only a defensive lab utility.

## How It Is Used In Practice

The simplest path is to start the backend first. For local testing, `python app.py` is enough. For role-based behavior, use:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
```

If you are testing lab-only containment and network-warfare controls in an isolated network, start with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1 -EnableDangerousActions -EnableNetworkWarfare
```

Then start the desktop:

```powershell
python desktop\main.py
```

If auth is enabled, enter the correct API key in the desktop and activate the role. From there, a typical operator reviews `Dashboards` and `Overview`, pivots into `Processes`, checks `Persistence`, runs `File Analysis` when a binary matters, expands context through `Network`, `Graph`, and `Timeline`, and uses `Enterprise` if the activity becomes a case.

If the focus is platform hardening or health, the operator moves into `Security Ops`. If the focus is external detection tooling, the operator usually enters through `WHIDS` or `HIDS`, normalizes detections into ShadowLab incidents, and then moves into `Enterprise`.

## MITRE ATT&CK Layer

ShadowLab has a dedicated ATT&CK layer inside the enterprise workflow.

The backend keeps bundle lifecycle state such as bundle version, modified date, object counts, discovered candidate bundles, and diff results against the currently loaded dataset. This helps the operator understand whether the ATT&CK dataset is current and what changed between versions.

Incident and case coverage are not limited to stored `mitre_mapping`. ShadowLab also performs lightweight ATT&CK inference from incident title, summary, notes, process-execution language, download behavior, credential-access hints, persistence hints, lateral-movement cues, and exfiltration patterns.

Case-level ATT&CK views include tactic heat, tactic progression, sub-technique counts, parent-technique rollups, top mitigations, and top software overlap. Navigator export and Workbench-oriented coverage JSON are supported.

## Recommended Operator Flow

The most practical flow starts with `Dashboards` and `Overview` for awareness. The second stage is process investigation. The third stage expands context using persistence review, file analysis, network, graph, and timeline. The fourth stage opens a case and starts enterprise workflow. The fifth stage exports reports and artifacts. The sixth stage uses `Security Ops` to verify platform health and evidence integrity.

This flow shows one of ShadowLab's main strengths: it does not only display data, it gives the operator a structured way to work through that data.

## Validation And Readiness

Current validation coverage includes:

- deployment preflight and runtime-restore checks
- RBAC smoke tests for `viewer`, `analyst`, and `admin`
- live ShadowLab and WHIDS integration smoke tests
- performance and dedupe probes for large ingest paths
- OSSEC active-response validation on elevated Windows hosts
- local YARA compile-health and detection-corpus validation
- focused tests for API load, security, network operations, enterprise operations, observability, and desktop controllers

## Visual Tour

The screenshots below map directly to the current desktop image set in `images/`. The sequence follows the current top-level desktop navigation from left to right.

### Dashboards Workspace

![Dashboards Workspace](../images/shadowlab-dashboard-wall.png)

The dashboards surface is the quickest status board in the product. It condenses platform health, threat posture, auth state, and short investigation summaries into one operator-facing wall.

### WHIDS Workspace

![WHIDS Workspace](../images/shadowlab-whids-integration.png)

The WHIDS workspace brings manager sync, reports, artifacts, scheduler state, IoC/rule lifecycle, and enterprise jump-off into one control area.

### HIDS Workspace

![HIDS Workspace](../images/shadowlab-hids-integration.png)

The HIDS workspace is centered on OSSEC-style ingest and response planning.

### Overview Incident Brief

![Overview Incident Brief](../images/shadowlab-monitor-overview.png)

Overview highlights incident posture, monitor results, telemetry summary, and operator-facing recommendations.

### Processes Workspace

![Processes Workspace](../images/shadowlab-processes-investigation.png)

Processes is the main suspicious-process analysis surface. The process list, selected-process detail, triage output, and action strip work together here.

### Persistence Workspace

![Persistence Workspace](../images/shadowlab-persistence-remediation.png)

Persistence gives the operator a dedicated post-compromise review area for autoruns, tasks, services, and rollback-aware remediation.

### File Analysis Workspace

![File Analysis Workspace](../images/shadowlab-file-analysis-static-pe.png)

File Analysis presents Detect It Easy readiness, file/process submission, PE structure, highlights, and raw analysis output.

### Network Workspace

![Network Workspace](../images/shadowlab-network-telemetry-blocker.png)

Network gives connection, capture, discovery, host inventory, and blocker context that process views alone cannot provide.

### Graph Interactive Browser

![Graph Interactive Browser](../images/shadowlab-entity-graph.png)

Graph visualizes relationships across entities, incidents, persistence items, processes, and remote endpoints.

### Timeline Event Story Workspace

![Timeline Event Story Workspace](../images/shadowlab-timeline-story.png)

Timeline reconstructs the incident story chronologically.

### Antivirus And Containment Workspace

![Antivirus And Containment Workspace](../images/shadowlab-antivirus-containment.png)

Antivirus combines provider health, scans, verdict history, quarantine, response controls, rules, lists, and containment operations.

### History And Incident Log

![History And Incident Log](../images/shadowlab-incident-history-audit.png)

History centralizes incident, action, auth, telemetry, and audit traces.

### Artifacts And Evidence Store

![Artifacts And Evidence Store](../images/shadowlab-artifacts-evidence-store.png)

Artifacts stores reports, exports, and collected evidence in an operator-friendly repository.

### Enterprise Case Ops Workspace

![Enterprise Case Ops Workspace](../images/shadowlab-enterprise-case-ops.png)

Enterprise is the structured investigation suite for tasks, approvals, assignments, notes, export actions, and case workflow.

### Security Ops Workspace

![Security Ops Workspace](../images/shadowlab-security-ops-readiness.png)

Security Ops groups integrity, observability, local YARA health, secret handling, audit export, readiness, and report controls.

### About Creator Profile

![About Creator Profile](../images/shadowlab-about-faq-profile.png)

The About / FAQ area separates product identity from creator identity and keeps quick project links visible.

## What This Guide Is Useful For

This guide is useful for product presentation, onboarding, security review, and explaining what ShadowLab does today. The README remains the shorter project entry point; this guide is the broader operator and product overview.
