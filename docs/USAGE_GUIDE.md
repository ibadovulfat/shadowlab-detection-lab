# ShadowLab Usage Guide

This guide expands on the main project README and focuses on the operational parts of ShadowLab that go beyond a basic API startup.

## What This Covers

- backend and desktop runtime usage
- telemetry fabric lifecycle
- process investigation and triage
- persistence hunting and remediation
- timeline, graph, and host inventory workflows
- deception controls
- artifacts and reporting
- packaging notes

## Backend and Desktop

Start the API:

```powershell
python app.py
```

Start the desktop client:

```powershell
python desktop\main.py
```

The desktop client expects the local API to be reachable at `http://127.0.0.1:8000` unless changed in the UI settings.

## Telemetry Fabric

ShadowLab can forward monitor session metrics, logs, and traces to its telemetry fabric over OTLP.

Key files:

- `config/telemetry-fabric-runtime.yaml`
- `config/telemetry-fabric-builder.yaml`
- `scripts/build_telemetry_fabric.ps1`

Main API routes:

- `GET /integrations/telemetry-fabric/status`
- `POST /integrations/telemetry-fabric/start`
- `POST /integrations/telemetry-fabric/stop`
- `POST /integrations/telemetry-fabric/export/incidents/{incident_id}`
- `GET /integrations/telemetry-fabric/exports`

Typical flow:

1. Start the API.
2. Start the telemetry fabric.
3. Run `POST /monitor/run`.
4. Inspect export audit history.

Build a custom Windows telemetry binary:

```powershell
scripts\build_telemetry_fabric.ps1
```

## Monitor and Detection Workflow

Core monitor route:

- `POST /monitor/run`

This route:

- collects local telemetry samples
- summarizes Defender and Sysmon context
- computes blended likelihood
- creates an incident record
- writes artifacts
- optionally exports to telemetry fabric

Returned fields of interest:

- `telemetry_rows`
- `final_score`
- `incident`
- `collector_export`
- `artifacts`

## Process Investigation

Useful routes:

- `GET /processes`
- `GET /processes/{pid}`
- `POST /processes/{pid}/scan`
- `GET /processes/{pid}/internals`
- `POST /processes/{pid}/strings`
- `POST /processes/{pid}/yara`
- `POST /processes/{pid}/sandbox-trace`
- `GET /processes/{pid}/tree`
- `GET /processes/{pid}/ai-analysis`
- `POST /triage/{pid}`

Recommended operator sequence:

1. List processes.
2. Inspect a suspicious PID profile.
3. Run strings, YARA, and sandbox trace.
4. Use one-click triage for a correlated view.
5. Contain with response actions only after review.

## Persistence Hunting and Remediation

Routes:

- `GET /persistence`
- `POST /persistence/remediate`
- `POST /persistence/rollback/{remediation_id}`
- `GET /history/remediations`

Current implementation focus:

- Windows Run keys
- Startup folder items
- Scheduled tasks
- Windows services
- Winlogon autorun values

Remediation backups are stored under:

```text
shadowlab_out/remediation_backups/
```

## Threat Intelligence

Routes:

- `GET /threat-intel/ip/{ip}`
- `GET /threat-intel/hash/{file_hash}`
- `POST /threat-intel/hash/lookup`
- `POST /processes/{pid}/scan`

Supported providers in the codebase:

- VirusTotal
- MalwareBazaar
- YARAify
- AbuseIPDB

## History, Timeline, and Graph Views

Routes:

- `GET /history/telemetry`
- `GET /history/responses`
- `GET /history/alerts`
- `GET /history/remediations`
- `GET /timeline`
- `GET /timeline/graph`
- `GET /hosts`
- `GET /graph/entity-map`
- `GET /graph/entity-map/html`

These views help correlate:

- telemetry spikes
- response actions
- incident creation
- remediation history
- host/process/network relationships

## Deception and Evidence

Routes:

- `POST /deception/honeypot/deploy`
- `GET /deception/honeypot/status`
- `DELETE /deception/honeypot`
- `POST /deception/canary/deploy`
- `GET /deception/canary/status`
- `DELETE /deception/canary`
- `POST /evidence/capture`
- `GET /evidence`
- `DELETE /evidence/{filename}`

These features are intended for owned lab systems only.

## Artifacts and Reports

Routes:

- `GET /artifacts`
- `GET /artifacts/{filename}`
- `GET /reports/html`

Generated outputs commonly include:

- telemetry CSV
- Defender and Sysmon summaries
- final score JSON
- incident bundle JSON
- HTML/PDF reports
- entity graph HTML/JSON

## Desktop Packaging

Desktop packaging assets:

- `desktop/build_exe.ps1`
- `desktop/shadowlab.spec`
- `desktop/shadowlab.iss`
- `desktop/version_info.txt`

Use these when packaging the PySide6 desktop client as a Windows executable.

## Safety Notes

Some modules are explicitly lab-only:

- ARP blocking
- packet sniffing
- deception features
- process kill and quarantine workflows

Use only in systems and networks you own and control.
