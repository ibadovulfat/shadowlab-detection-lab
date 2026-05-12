# ShadowLab Backend Architecture

This document describes the runtime shape of the `api/` package after the 2026-Q2 refactor. It is intended for engineers adding endpoints, middleware, background workers, or backend services. Operators should start with `PRODUCTION_RUNBOOK.md`; first-time users should start with `USAGE_GUIDE.md`.

## 1. High-Level Layout

```text
api/
  main.py                    # App assembly, lifespan, route registration
  bootstrap/
    ctx.py                   # build_shared_ctx(...): dependency container
    services.py              # build_services(...): service singletons
  middleware/
    security_headers.py      # TLS, body limit, CSP, approval finalization
  routes/                    # Route modules, one per domain
    auth.py                  # /health, /metrics, /auth/*
    enterprise.py            # /enterprise/*
    integrations.py          # /integrations/*, /whids/*, /ossec/*
    processes.py             # /yara/*, /process/*
    network.py               # /network/connections, /network/sniff
    network_warfare.py       # /network/warfare/*
    antivirus.py             # /antivirus/*
    ...
  schemas/                   # Pydantic request/response models
  security.py                # Auth, RBAC, signing, rate-limit primitives
  utils/                     # Paths, validators, audit, approval, webhooks
  observability/
    metrics.py               # MetricsRegistry + Prometheus exposition
    logging.py               # JsonLogFormatter + configure_json_logging
  workers/
    connector_worker.py      # ConnectorQueueWorker background thread
```

Golden rule: every file under `api/` should be either pure helpers, service glue, or one layer of FastAPI wiring. Avoid files that both define HTTP routes and own long-running state.

## 2. Request Flow

```text
Client
  -> security_headers middleware
     -> route handler in api/routes/*.py
        -> services/* or plugins/*
           -> database.py / external approved provider / runtime artifact
```

Key properties enforced in `api/middleware/security_headers.py`:

- body-limit streaming: the middleware reads `request.stream()` chunk by chunk and aborts once the configured limit is crossed
- approval finalization: approval reservations are consumed and audited even when a route raises
- conditional HSTS: only added when the request arrived over TLS directly or through a trusted proxy
- security headers: response hardening is centralized instead of duplicated per route

## 3. App Assembly

`api/main.py` is intentionally thin. Its job is to:

1. build settings, security context, and service singletons through `api.bootstrap.services.build_services(...)`
2. create the FastAPI app with a lifespan handler
3. install security middleware
4. build one `_shared_ctx` dict through `api.bootstrap.ctx.build_shared_ctx(...)`
5. call each route module's `register_routes(app, ctx)`
6. start and stop background workers in lifespan startup/shutdown

## 4. Route Design

Route modules take one `ctx` dict and pull only the dependencies they need. This keeps route registration readable without forcing every module to accept a very large signature.

When adding schemas, prefer module-top imports from `api.schemas`. Avoid hidden local schema classes in route function annotations because FastAPI resolves annotations against module globals.

## 5. Capability And Policy Model

`api/security.py` builds the capability payload returned by `/auth/context`. The desktop uses that payload to enable or disable controls, but the backend remains authoritative.

Important examples:

- `can_run_sniffer`: analyst/admin packet capture
- `can_run_hunt`: analyst/admin investigation and discovery
- `can_manage_network_warfare`: admin plus dangerous actions plus network-warfare enablement
- `can_manage_process_actions`: admin plus dangerous actions
- `can_manage_integrations`: admin integration management

Do not rely on UI gating alone. Every mutating or sensitive route must also enforce the correct backend dependency.

## 6. Background Workers

Workers are daemon threads launched from lifespan startup. Each worker is a class with `start()` and `stop()` methods and receives dependencies through constructor arguments.

Current worker:

| File | Class | Purpose |
|------|-------|---------|
| `api/workers/connector_worker.py` | `ConnectorQueueWorker` | Drain the enterprise connector queue on an interval. |

Rules for adding a worker:

1. one class per file
2. no module-level thread startup
3. inject services explicitly
4. expose metrics for iterations, failures, and timing

## 7. Observability

`api/observability/metrics.py` provides a Prometheus-compatible registry with minimal dependencies. `/metrics` is admin-only.

`api/observability/logging.py` provides JSON logging behind the `SHADOWLAB_JSON_LOGGING` environment variable. Local dev and CI can keep text logging; production or container deployments can opt into JSON.

Avoid unbounded metric labels such as hashes, usernames, URLs, or case titles.

## 8. Threat Intelligence And Outbound Safety

`threat_intelligence.py` exposes `ThreatIntelClient` and module-level helper functions. The client owns API keys, allowlist behavior, and optional session injection.

Outbound request safety is enforced before sockets open. Requests to unapproved hosts are blocked and logged to external request audit storage.

## 9. Antivirus And File Analysis

Antivirus workflow is implemented through route modules and services under `services/antivirus/`. It covers provider health, scan jobs, verdict cache, quarantine, live response, watcher behavior, credentials, rules, lists, webhooks, sandbox provider integration, and MITRE mapping.

File analysis uses `services/die_binding_service.py`, `services/static_pe_service.py`, and malware analyst helpers. The desktop presents this as `File Analysis`.

## 10. Testing Conventions

- `tests/test_api_load.py` exercises the FastAPI app through `TestClient`
- `tests/test_security.py` focuses on auth, RBAC, signing, policy, and capabilities
- `tests/test_network_ops.py` covers desktop network action policy and safety assumptions
- `tests/test_observability.py` covers metrics and logging
- `tests/test_connector_worker.py` covers connector queue worker behavior
- `tests/test_threat_intel_client.py` covers threat-intelligence client safety and behavior

When tests mutate global state, restore the prior state in `finally` or fixtures. Prefer focused tests around route modules and services over broad UI-dependent tests unless the behavior is truly desktop-specific.

## 11. Recent Refactors At A Glance

| Refactor | Status |
|----------|--------|
| schemas moved to `api/schemas/` | Done |
| route modules moved under `api/routes/` | Done |
| `ConnectorQueueWorker` moved to `api/workers/` | Done |
| `ThreatIntelClient` introduced | Done |
| `/metrics` endpoint and JSON logging support | Done |
| lifespan startup/shutdown migration | Done |
| body-limit streaming fix | Done |
| approval finalization hardening | Done |
| network action capability split | Done |
| antivirus service layer expansion | Done |
