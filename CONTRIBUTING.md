# Contributing

Thanks for taking the time to contribute to ShadowLab.

## Before You Start

- use the project only in owned, isolated lab environments
- keep changes focused
- avoid mixing unrelated refactors into the same change
- prefer fixes that are easy to review and easy to re-test
- update docs when routes, screenshots, UI tabs, policy behavior, or workflows change

## Local Setup

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Run locally:

```powershell
python app.py
python desktop\main.py
```

Auth-enabled workflow:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

Lab-only destructive and network-warfare workflow:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1 -EnableDangerousActions -EnableNetworkWarfare
python desktop\main.py
```

## Pull Requests

Please include:

- what changed
- why it changed
- how you tested it
- screenshots for UI work when useful
- config, migration, or rollout notes if behavior changed
- security impact if the change touches auth, signing, secrets, file access, network actions, antivirus response, or destructive controls

## Testing

Run the checks that match your change. Common examples:

```powershell
venv\Scripts\python.exe -m pytest tests\test_security.py
venv\Scripts\python.exe -m pytest tests\test_api_e2e.py
venv\Scripts\python.exe -m pytest tests\test_network_ops.py
venv\Scripts\python.exe -m py_compile api\main.py desktop\main.py
```

If you touch detections, integrations, antivirus, network actions, or security-sensitive code, include the validation steps in the PR description.

## Security

- never commit raw secrets or tokens
- prefer hashed API keys in configuration
- keep screenshots free of usable keys and real customer data
- use [SECURITY.md](SECURITY.md) for vulnerability reporting

## Documentation

If routes, screenshots, workflows, or UI behavior change, update the relevant docs:

- `README.md`
- `docs/PLATFORM_GUIDE.md`
- `docs/USAGE_GUIDE.md`
- `docs/PRODUCTION_RUNBOOK.md`
- `desktop/README.md`
- `docs/ARCHITECTURE.md`
- `docs/POLICY_MATRIX.md`
