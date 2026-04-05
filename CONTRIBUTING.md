# Contributing

Thanks for taking the time to contribute to ShadowLab.

## Before You Start

- use the project only in owned, isolated lab environments
- keep changes focused
- avoid mixing unrelated refactors into the same change
- prefer fixes that are easy to review and easy to re-test

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

## Pull Requests

Please include:

- what changed
- why it changed
- how you tested it
- screenshots for UI work when useful
- config, migration, or rollout notes if behavior changed

## Testing

Run the checks that match your change. Common examples:

```powershell
venv\Scripts\python.exe -m unittest tests.test_security -v
venv\Scripts\python.exe -m unittest tests.test_api_e2e -v
venv\Scripts\python.exe -m py_compile api\main.py desktop\main.py
```

If you touch detections, integrations, or security-sensitive code, include the validation steps in the PR description.

## Security

- never commit raw secrets or tokens
- prefer hashed API keys in configuration
- use [SECURITY.md](SECURITY.md) for vulnerability reporting

## Documentation

If routes, screenshots, workflows, or UI behavior change, update the relevant docs:

- `README.md`
- `docs/PLATFORM_GUIDE.md`
- `docs/USAGE_GUIDE.md`
- `docs/PRODUCTION_RUNBOOK.md`
- `desktop/README.md`

updated

