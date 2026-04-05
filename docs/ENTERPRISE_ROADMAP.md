# ShadowLab Enterprise Roadmap

This roadmap turns ShadowLab from a strong lab-grade platform into an enterprise-ready security operations platform. It is grouped into three delivery blocks so we can implement the foundation first, then production operations, then governance and scale.

## Phase 1: Core Platform Security Foundation

This phase covers:

- `1. SSO / OIDC / user-based auth`
- `2. Central secret management`
- `3. Shared runtime controls`

### Goals

- move from shared API keys toward user and service identity
- remove long-lived secrets from local config and ad hoc environment usage
- make security controls consistent across multi-process and multi-node deployments

### Deliverables

#### 1. SSO / OIDC / user-based auth

- add OIDC configuration support for issuer, audience, client ID, and JWKS
- support interactive operator auth and service-to-service auth separately
- map identity claims to ShadowLab roles and capabilities
- add per-user audit logging instead of only token/role attribution
- support token expiry, revocation posture, and session timeout handling
- keep API key mode only as a lab fallback, not the enterprise default

#### 2. Central secret management

- define a secret provider abstraction in services
- support environment, local encrypted storage, and enterprise secret backends
- move connector secrets, webhook secrets, and signing keys behind the provider
- prevent plaintext secret material from being persisted outside approved storage
- add secret rotation workflows with audit records

#### 3. Shared runtime controls

- move rate-limit buckets, nonce tracking, and approval reservation state to Redis
- add shared request replay protection for multi-worker deployments
- support distributed lock semantics for queue workers and scheduler tasks
- add failure-mode rules for Redis unavailability on security-critical paths

### Suggested implementation order

1. introduce auth and secret provider interfaces
2. add Redis-backed nonce and rate-limit storage
3. add OIDC validation and claim-to-role mapping
4. migrate existing admin-only workflows to user identity context

### Exit criteria

- enterprise profile can run without raw API keys
- mutating request signing and replay checks work across workers
- connector and platform secrets can be rotated without manual file edits
- audit logs clearly identify the acting user or service principal

## Phase 2: Enterprise Operations And Reliability

This phase covers:

- `4. Database maturity`
- `5. Immutable audit / compliance posture`
- `6. Deployment hardening`

### Goals

- replace single-node assumptions with operationally reliable building blocks
- improve recoverability, observability, and audit defensibility
- make deployment safer and more repeatable

### Deliverables

#### 4. Database maturity

- make PostgreSQL the primary enterprise backend
- define migration discipline and startup safety checks for schema drift
- add backup, restore, and recovery validation scripts
- document HA and connection-pool expectations
- add retention jobs and operational readiness checks for large datasets

#### 5. Immutable audit / compliance posture

- stream audit events to SIEM or message pipeline
- define append-only export or signed audit package workflow
- add retention controls for auth, action, evidence, and connector logs
- document compliance mappings for SOC 2, ISO 27001, and NIST-oriented environments
- add audit integrity verification for exported records

#### 6. Deployment hardening

- standardize reverse proxy deployment with trusted forwarded-header handling
- enforce TLS, secure headers, and approved origins in enterprise profiles
- add SBOM generation and dependency vulnerability checks in CI
- add signed release artifacts and build provenance
- define container and host hardening baselines

### Suggested implementation order

1. make PostgreSQL the validated production backend
2. add audit export and retention controls
3. harden CI, packaging, reverse proxy, and release workflows

### Exit criteria

- enterprise runtime is validated on PostgreSQL
- audit events can be exported and verified externally
- deployment artifacts are scanned, versioned, and operationally documented

## Phase 3: Governance And Scale

This phase covers:

- `7. Policy formalization`
- `8. Multi-user / tenant isolation`

### Goals

- move from implicit policy checks to formal, reviewable policy logic
- support multiple teams, environments, or customers without cross-exposure

### Deliverables

#### 7. Policy formalization

- define a policy matrix for feature availability by profile and environment
- move approval requirements, connector restrictions, and dangerous-action rules into declarative policy
- add policy validation tests and startup posture validation against the matrix
- make policy exceptions explicit and auditable

#### 8. Multi-user / tenant isolation

- define workspace or tenant boundaries for cases, incidents, evidence, connectors, and logs
- add tenant-aware authorization and query filtering
- separate secrets, exports, and audit streams by tenant or workspace
- document isolation expectations for shared deployments

### Suggested implementation order

1. formalize the policy matrix and enforcement model
2. add workspace or tenant identifiers to enterprise records
3. enforce tenant-aware filtering across API and reporting surfaces

### Exit criteria

- policy behavior is deterministic, testable, and reviewable
- data and connector actions can be scoped per workspace or tenant
- enterprise deployments can support multiple operators or teams safely

## Practical Next Step

The next implementation block should be `Phase 1`.

Why:

- it reduces the biggest enterprise risk fastest
- it creates the identity and secret foundations needed for later work
- it prevents us from scaling insecure patterns into PostgreSQL, HA, or multi-tenant design

## Initial Task Breakdown

### Phase 1 backlog

- add `auth/providers` module for API key and OIDC backends
- add `secrets/providers` module for environment and enterprise secret stores
- add Redis-backed nonce and rate-limit adapters
- define claim-to-role mapping rules
- add tests for mixed API key and OIDC deployments

### Phase 2 backlog

- add PostgreSQL-only readiness validator for enterprise mode
- add audit export command and retention job
- add SBOM and dependency scan CI jobs
- document reverse proxy reference deployment

### Phase 3 backlog

- create policy matrix document and validation tests
- add workspace ID to enterprise records
- prototype tenant-aware case and artifact filtering

updated

