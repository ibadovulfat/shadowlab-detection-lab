# ShadowLab Desktop Client

This folder contains the PySide6 desktop client for the local ShadowLab API.

## What The Desktop Covers

The desktop is the main operator console and currently exposes:

- dashboards and overview telemetry views
- WHIDS and HIDS integration workspaces
- process investigation, deep hunt, and response workflows
- persistence review and remediation controls
- threat-intel lookups
- network, hosts, graph, timeline, quarantine, history, and artifact views
- deception and scenario workflows
- enterprise case operations and investigation intelligence views
- enterprise ATT&CK lifecycle, ATT&CK coverage, Navigator export, and Workbench export views
- security-ops posture and reporting controls
- local YARA policy, health, analytics, and error review from `Security Ops`

## Enterprise Layout

The `Enterprise` tab is split into:

- `Enterprise Ops`
  - case controls
  - case board
  - assignments
  - tasks
  - activity feed
  - notifications
  - report export
- `Enterprise Intel`
  - critical assets
  - detection lifecycle
  - ATT&CK coverage and bundle lifecycle
  - case ATT&CK rollup
  - notes
  - stories
  - timeline
  - entity links
  - graph correlation

ATT&CK-specific desktop actions now include:

- `Load ATT&CK`
- `ATT&CK Layer`
- `Workbench`

The enterprise ATT&CK panels show:

- discovered bundle candidates
- loaded bundle metadata
- bundle diff summary
- tactic heat and tactic progression
- parent and sub-technique rollup
- telemetry cue hotspots
- case-level ATT&CK enrichment

Large tabs use local scrolling instead of forcing the full window to grow beyond the screen.

## Auth And Roles

The desktop reads role and capability state from `GET /auth/context`.

Supported roles:

- `viewer`
- `analyst`
- `admin`

The client:

- shows role-aware actions
- hides or disables unavailable controls
- does not treat auth-disabled backends as implicit admin anymore
- keeps `WHIDS` and `HIDS` controls locked for non-admin roles
- still allows analysts to move into enterprise case work where capability policy permits it

Current YARA-related desktop usage:

- inspect triage summaries that merge `YARAify`, local YARA, memory YARA, and fused confidence
- use `Security Ops` to review YARA health, policy, analytics, and compile errors
- use `Triage Respond` for policy-aware response planning after high-confidence hits

For local role-based testing, use:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

## Run Locally

```powershell
python app.py
python desktop\main.py
```

Auth-enabled local start:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

## Build EXE

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

Packaging assets:

- `desktop\shadowlab.spec`
- `desktop\shadowlab.iss`
- `desktop\version_info.txt`

## Related Docs

- [README.md](../README.md)
- [docs/USAGE_GUIDE.md](../docs/USAGE_GUIDE.md)
- [docs/PRODUCTION_RUNBOOK.md](../docs/PRODUCTION_RUNBOOK.md)
- [docs/PLATFORM_GUIDE.md](../docs/PLATFORM_GUIDE.md)
