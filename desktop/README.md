# ShadowLab Desktop Client

This folder contains the PySide6 desktop client for the local ShadowLab FastAPI backend.

Current features:

- backend health check
- process table loading
- selected process detail view
- monitor-session trigger
- advanced response actions (`suspend`, `resume`, `kill`, `kill-tree`, `quarantine`)
- case and incident visibility in History
- incident owner/status update workflow
- richer threat-intel workflow with lookup history and process auto-fill
- deeper hunt workflow with strings, YARA, sandbox trace, process tree, and AI analyst
- one-click auto triage workflow for selected processes
- hosts, timeline, and quarantine tabs
- persistence remediation workflow
- webhook alert configuration and test path
- memory analysis metadata with Volatility availability tracking
- persistence, threat intel, network, history, artifacts, and scenario tabs
- overview chart and severity highlighting

Run locally:

```powershell
python app.py
python desktop\main.py
```

Build EXE:

```powershell
pip install pyinstaller
desktop\build_exe.ps1
```

Spec file:

- [shadowlab.spec](C:\Users\ulfat\Downloads\shadowlab-detection-lab\desktop\shadowlab.spec)
