# Contributing

Thanks for contributing to ShadowLab.

## Before You Start

- use this project only in owned, isolated, lab environments
- keep changes focused and easy to review
- avoid unrelated refactors in the same change
- prefer reproducible bug reports and testable fixes

## Development Setup

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

Auth-enabled local workflow:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_shadowlab_auth.ps1
python desktop\main.py
```

## Branching

- create a focused branch from `main`
- use clear commit messages
- keep PRs small enough to review safely

## Pull Request Expectations

Please include:

- what changed
- why it changed
- how it was tested
- screenshots for UI work when relevant
- migration or config notes if behavior changed

## Testing

Run the checks relevant to your change. Common examples:

```powershell
venv\Scripts\python.exe -m unittest tests.test_security -v
venv\Scripts\python.exe -m unittest tests.test_api_e2e -v
venv\Scripts\python.exe -m py_compile api\main.py desktop\main.py
```

If you add or change detection, analysis, or integration workflows, include the most relevant validation steps in the PR description.

## Security

- do not commit secrets, raw tokens, or production credentials
- prefer hashed API keys in configuration
- follow [SECURITY.md](SECURITY.md) for vulnerability reporting

## Documentation

If UI, screenshots, flows, or routes change, update the relevant docs, especially:

- `README.md`
- `docs/PLATFORM_GUIDE.md`
- `docs/USAGE_GUIDE.md`
- `desktop/README.md`
