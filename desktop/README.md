# ShadowLab Desktop Client

This folder contains the PySide6 desktop client for ShadowLab.

## What The Desktop Does

The desktop is the main operator console. It covers:

- dashboards and overview views
- `WHIDS` and `HIDS` integration workspaces
- process investigation and advanced hunt
- persistence, threat-intel, and static-analysis workflows
- deception, network, hosts, graph, and timeline views
- quarantine, history, artifacts, and evidence handling
- enterprise case operations and investigation intelligence
- ATT&CK coverage, Navigator export, and Workbench export
- security-operations posture, YARA health, and reporting

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

- shows or hides controls based on capabilities
- signs authenticated write requests automatically
- attaches approval IDs when needed
- does not assume admin access just because backend auth is disabled
- activates role-aware API access from a valid key without requiring separate manual header setup

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

The preferred backend for `Static Analysis` is `die-python`. If you still want the external CLI path, provide `diec.exe` or `die.exe` through `SHADOWLAB_DIEC_PATH` or `PATH`.

The runtime badge in the desktop reflects native and subprocess backends separately. A healthy native binding appears as `Runtime: ready (native)` even if no external `diec.exe` path exists.

## Reporting Notes

The desktop `Artifacts` and export flows now surface fuller monitor reports. Generated PDF and HTML reports include analyst findings, telemetry context, event highlights, and an artifact manifest suitable for handoff.

## Related Documentation

- [README.md](../README.md)
- [docs/PLATFORM_GUIDE.md](../docs/PLATFORM_GUIDE.md)
- [docs/USAGE_GUIDE.md](../docs/USAGE_GUIDE.md)
- [docs/PRODUCTION_RUNBOOK.md](../docs/PRODUCTION_RUNBOOK.md)
