# ShadowLab Security Remediation Runbook

This runbook covers the remaining operational remediation work after the backend hardening changes.

## Part 1: Git History Cleanup And Secret Rotation

### 1. Inventory sensitive history

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\prepare_git_history_cleanup.ps1
```

This helper:

- verifies `git` and `git-filter-repo`
- lists configured sensitive paths
- shows current tracked matches
- summarizes history hits
- prints the exact rewrite commands without executing them

### 2. Rewrite repository history

Create a backup branch first, then run the printed `git filter-repo` command.

Minimum cleanup target:

- `shadowlab.db`
- `.env`
- `honey/passwords.txt`

After the rewrite:

```powershell
git push --force --all
git push --force --tags
```

Every collaborator must remove stale local clones or hard-reset to the new rewritten history.

### 3. Rotate exposed secrets

Treat the following as compromised if they were ever stored in the repository, database, shell history, screenshots, or exported artifacts:

- `SHADOWLAB_API_KEY`
- `SHADOWLAB_API_KEYS`
- `SHADOWLAB_API_KEY_SHA256` source secrets
- integration webhook URLs
- malware intelligence API keys
- OIDC client secrets
- any connector secrets stored in the database

Rotation checklist:

1. revoke old credentials at the upstream provider
2. generate new role keys with `python scripts/generate_api_keys.py`
3. update runtime env vars or secret manager values
4. re-enter any encrypted connector secrets through the application flow
5. verify `/enterprise/secrets/status` and integration health
6. document the rotation timestamp and owner

## Part 2: Deployment Configuration And Handoff

### 1. Start from the hardened env template

Use:

- [deploy/shadowlab.prod.env.example](/Users/ulfat/Documents/shadowlab-detection-lab/deploy/shadowlab.prod.env.example)

Required production settings:

- `SHADOWLAB_REQUIRE_AUTH=true`
- `SHADOWLAB_REQUIRE_TLS=true`
- `SHADOWLAB_POLICY_PROFILE=corp` or `prod`
- `SHADOWLAB_API_KEYS_SHA256=...`
- `SHADOWLAB_TRUSTED_PROXIES=...` only when a trusted reverse proxy exists

### 2. Reverse proxy expectations

The proxy must:

- terminate TLS
- forward only trusted `X-Forwarded-Proto: https`
- restrict backend access to proxy/internal addresses
- preserve request bodies within the configured app limits

Recommended pattern:

- reverse proxy listens on `443`
- ShadowLab binds to `127.0.0.1:8000`
- firewall blocks direct remote access to the backend port

### 3. Deployment validation

Run before handoff:

```powershell
python scripts/validate_deployment_runtime.py
python scripts/rbac_smoke_matrix.py
python scripts/smoke_test_postgres_runtime.py
```

If OSSEC is enabled:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome <path>
```

## Long-Term Hardening Backlog

### Desktop modularization

Break `desktop/main.py` into:

- `desktop/auth.py`
- `desktop/api_client.py`
- `desktop/settings.py`
- `desktop/views/`
- `desktop/widgets/`

### API versioning

Introduce `/api/v1` while preserving a migration window for current routes.

Suggested rollout:

1. add versioned routers
2. mirror critical current endpoints under `/api/v1`
3. update the desktop client to prefer versioned paths
4. deprecate unversioned paths after verification

### Centralized log shipping

Current app logging is JSON-formatted locally. Next step is forwarding logs to a collector such as:

- Windows Event Forwarding
- Splunk HEC
- Elastic Agent
- OpenTelemetry collector

Ship at least:

- auth events
- approval actions
- response actions
- startup posture validation
- external request audit events
