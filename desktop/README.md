# ShadowLab Desktop Client

This folder contains the PySide6 desktop client for ShadowLab.

## What The Desktop Does

The desktop is the main operator console. It covers:

- `Dashboards` and `Overview`
- `WHIDS` and `HIDS` integration workspaces
- `Processes` investigation and triage
- `Persistence` review and remediation
- `File Analysis` with Detect It Easy and PE fallback
- `Network`, `Graph`, and `Timeline`
- `Antivirus` provider health, scans, verdicts, quarantine, response, rules, lists, webhooks, and containment
- `History`, `Artifacts`, and evidence/report handling
- `Enterprise` case operations and investigation intelligence
- ATT&CK coverage, Navigator export, and Workbench export
- `Security Ops` posture, YARA health, integrity, observability, secrets, and reporting
- `About / FAQ`

## Enterprise Layout

The `Enterprise` tab is split into:

- `Enterprise Ops`
- `Enterprise Intel`

## Auth And Roles

The desktop reads role and capability state from `GET /auth/context`.

Supported roles:

- `viewer`
- `analyst`
- `admin`

The client:

- enables or disables controls based on backend capabilities
- signs authenticated write requests automatically
- attaches approval IDs when needed
- does not assume admin access just because backend auth is disabled
- activates role-aware API access from a valid key without requiring manual header setup

Important capability examples:

- packet capture: `can_run_sniffer`
- ARP discovery and investigation workflows: analyst/admin capabilities
- network blocker: `can_manage_network_warfare`
- dangerous response actions: admin plus explicit feature flags

## Local Run

```powershell
python app.py
python desktop\main.py
```

Auth-enabled local run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

Lab-only network and destructive controls:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1 -EnableDangerousActions -EnableNetworkWarfare
python desktop\main.py
```

## Build

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

Packaging files:

- `desktop\shadowlab.spec`
- `desktop\shadowlab.iss`
- `desktop\version_info.txt`

## Detect It Easy Notes

The preferred backend for `File Analysis` is `die-python`. If you still want the external CLI path, provide `diec.exe` or `die.exe` through `SHADOWLAB_DIEC_PATH` or `PATH`.

The runtime badge in the desktop reflects native and subprocess backends separately. A healthy native binding appears as `Runtime: ready (native)` even if no external `diec.exe` path exists.

## Reporting Notes

The desktop `Artifacts`, `Antivirus`, `Enterprise`, and export flows surface richer monitor and case reports. Generated PDF and HTML reports include analyst findings, telemetry context, event highlights, ATT&CK context, and an artifact manifest suitable for handoff.

## Related Documentation

- [README.md](../README.md)
- [docs/PLATFORM_GUIDE.md](../docs/PLATFORM_GUIDE.md)
- [docs/USAGE_GUIDE.md](../docs/USAGE_GUIDE.md)
- [docs/PRODUCTION_RUNBOOK.md](../docs/PRODUCTION_RUNBOOK.md)
