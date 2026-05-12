# ShadowLab Security Remediation Runbook

This runbook covers operational remediation work after backend hardening, desktop role enforcement, and secret-handling improvements.

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
- accidental screenshots containing raw API keys
- exported artifacts containing secrets or real customer data

After the rewrite:

```powershell
git push --force --all
git push --force --tags
```

Every collaborator must remove stale local clones or hard-reset to the rewritten history.

### 3. Rotate exposed secrets

Treat the following as compromised if they were ever stored in the repository, database, shell history, screenshots, or exported artifacts:

- `SHADOWLAB_API_KEY`
- `SHADOWLAB_API_KEYS`
- `SHADOWLAB_API_KEY_SHA256` source secrets
- `SHADOWLAB_API_KEYS_SHA256` source raw keys
- integration webhook URLs
- malware intelligence API keys
- WHIDS manager API keys
- OIDC client secrets
- connector secrets stored in the database
- signing material, client certificates, or mTLS private keys

Rotation checklist:

1. revoke old credentials at the upstream provider
2. generate new role keys with `python scripts/generate_api_keys.py`
3. update runtime environment variables or secret manager values
4. re-enter encrypted connector secrets through the application flow
5. verify `/enterprise/secrets/status` and integration health
6. export or archive a clean audit bundle
7. document the rotation timestamp and owner

## Part 2: Deployment Configuration And Handoff

### 1. Start from the hardened env template

Use:

- [deploy/shadowlab.prod.env.example](../deploy/shadowlab.prod.env.example)

Required production settings:

- `SHADOWLAB_REQUIRE_AUTH=true`
- `SHADOWLAB_REQUIRE_TLS=true`
- `SHADOWLAB_POLICY_PROFILE=corp` or `prod`
- `SHADOWLAB_API_KEYS_SHA256=...` or OIDC-backed identity
- `SHADOWLAB_TRUSTED_PROXIES=...` only when a trusted reverse proxy exists
- `SHADOWLAB_ENABLE_DANGEROUS_ACTIONS=false`
- `SHADOWLAB_ENABLE_NETWORK_WARFARE=false`

### 2. Reverse proxy expectations

The proxy must:

- terminate TLS
- forward only trusted `X-Forwarded-Proto: https`
- restrict backend access to proxy/internal addresses
- preserve request bodies within configured app limits
- set explicit origin policy for any browser-facing surface

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
python scripts/validate_enterprise_postgres_readiness.py
```

If OSSEC is enabled:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate_ossec_active_response.ps1 -OssecHome <path>
```

## Long-Term Hardening Backlog

### Desktop modularization

Continue reducing `desktop/main.py` into focused controllers and shared UI primitives. Several controllers already exist under `desktop/`, including auth, dashboard, network, timeline, history, enterprise, antivirus, integrations, monitor, process hunt, intel, security ops, and artifact operations.

Future split targets:

- `desktop/auth.py`
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

Current app logging can emit JSON locally. Next step is forwarding logs to a collector such as:

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
- secret rotation events
- antivirus and containment actions
