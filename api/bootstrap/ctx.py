"""Shared route-registration context builder.

Every `register_routes(app, ctx)` helper takes a dict of dependencies
plucked from the FastAPI app namespace. Without a shared builder each of
the 21 registrations had to list 10–40 keys explicitly — ~500 lines of
boilerplate in `api/main.py`, mostly duplicated.

`build_shared_ctx()` returns a single master dict. Route modules read
what they need from it via `ctx["key"]`; extra keys are harmless. Routes
that need schema classes or ad-hoc wiring still merge a small overlay on
top (e.g. `shared_ctx | {"MitreBundleLoadRequest": MitreBundleLoadRequest}`).

Late-binding callables (YARA/VT/malwarebazaar, detection fusion, process
scanning) are wrapped in lambdas that look the attribute up on the main
module at call time — this preserves `mock.patch.object(api.main, ...)`
semantics used throughout the test suite.
"""
from __future__ import annotations

from typing import Any


class _LateBoundModuleAttr:
    """Attribute proxy that resolves a module attribute on every access.

    Routes bound at startup capture service objects by value via ctx. A test
    that does `mock.patch.object(api.main, "mitre_service", fake)` swaps the
    module attribute, but anything that already pulled `ctx["mitre_service"]`
    still points at the original — so the mock is ignored. Wrapping the ctx
    value in this proxy means every `mitre_service.status()` call looks up
    `api.main.mitre_service` fresh, honoring `mock.patch.object` transparently.
    Kept minimal (just `__getattr__` / `__call__`) because only a handful of
    services are patched whole and the normal attribute-access pattern
    covers all of them.
    """

    __slots__ = ("_mod", "_attr")

    def __init__(self, module: Any, attr: str) -> None:
        object.__setattr__(self, "_mod", module)
        object.__setattr__(self, "_attr", attr)

    def _resolve(self) -> Any:
        return getattr(self._mod, self._attr)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolve(), name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._resolve()(*args, **kwargs)

    def __repr__(self) -> str:
        return f"<_LateBoundModuleAttr {self._attr!r}>"


def build_shared_ctx(
    main_module: Any,
    *,
    # Top-level modules and config
    db: Any,
    config: dict[str, Any],
    base_dir: Any,
    out_dir: Any,
    monitor_core: Any,
    yara_scanner: Any,
    requests: Any,
    html: Any,
    json: Any,
    secret_store: Any,
    identity_provider: Any,
    # Auth / policy helpers (api.security)
    SecurityContext: Any,
    build_auth_context_payload: Any,
    current_actor: Any,
    current_subject: Any,
    can_approve_workspace: Any,
    require_admin: Any,
    require_analyst_or_admin: Any,
    require_api_key: Any,
    safe_child_path: Any,
    ensure_dangerous_actions_enabled: Any,
    ensure_delete_enabled: Any,
    ensure_network_warfare_enabled: Any,
    enforce_process_action_policy: Any,
    # Service singletons
    alert_service: Any,
    antivirus_service: Any,
    collector_bridge: Any,
    detection_service: Any,
    enterprise_service: Any,
    fleet_service: Any,
    graph_service: Any,
    hids_integration_service: Any,
    integrity_service: Any,
    investigation_service: Any,
    malware_analyst_service: Any,
    migration_service: Any,
    mitre_service: Any,
    observability_service: Any,
    process_intel_service: Any,
    response_service: Any,
    timeline_service: Any,
    TelemetryMonitoringService: Any,
    # Wave-3 ops
    metrics_registry: Any = None,
    scan_job_queue: Any = None,
    webhook_dispatcher: Any = None,
    folder_watcher: Any = None,
    rotation_worker: Any = None,
    # Shims (thin wrappers around api/utils modules)
    request_workspace_id: Any,
    require_default_workspace_for_global_scope: Any,
    apply_rate_limit: Any,
    require_enterprise_approval: Any,
    alert_destination_type: Any,
    set_alert_webhook_url: Any,
    get_alert_webhook_url: Any,
    get_network_warfare_instance: Any,
    set_network_warfare_instance: Any,
    workspace_artifact_dir: Any,
    artifact_manifest: Any,
    load_scenario_runner: Any,
    normalize_incident_row: Any,
    validate_persistence_target: Any,
    write_monitor_artifacts: Any,
    log_collector_exports: Any,
    log_single_collector_export: Any,
    # Validators
    validated_incident_id: Any,
    validated_ip_address: Any,
    validated_sha256: Any,
    parse_csv_query_values: Any,
    # Wrapped helpers (existing call sites used thin lambdas — keep that
    # so signatures stay stable even if the underlying impl changes)
    safe_file_response: Any,
    validate_webhook_url: Any,
    validate_replay_artifact_path: Any,
    validate_quarantine_file_path: Any,
    validate_quarantine_restore_paths: Any,
    build_auth_anomalies: Any,
) -> dict[str, Any]:
    """Return the master ctx dict shared across all route registrations."""
    return {
        # --- top-level modules / config
        "db": db,
        "config": config,
        "BASE_DIR": base_dir,
        "OUT_DIR": out_dir,
        "monitor_core": monitor_core,
        "yara_scanner": yara_scanner,
        "requests": requests,
        "html": html,
        "json": json,
        "secret_store": secret_store,
        "identity_provider": identity_provider,
        # --- auth / policy helpers
        "SecurityContext": SecurityContext,
        "build_auth_context_payload": build_auth_context_payload,
        "current_actor": current_actor,
        "current_subject": current_subject,
        "can_approve_workspace": can_approve_workspace,
        "require_admin": require_admin,
        "require_analyst_or_admin": require_analyst_or_admin,
        "require_api_key": require_api_key,
        "safe_child_path": safe_child_path,
        "ensure_dangerous_actions_enabled": ensure_dangerous_actions_enabled,
        "ensure_delete_enabled": ensure_delete_enabled,
        "ensure_network_warfare_enabled": ensure_network_warfare_enabled,
        "enforce_process_action_policy": enforce_process_action_policy,
        # --- service singletons
        "alert_service": alert_service,
        "antivirus_service": antivirus_service,
        # Wave-3 ops singletons (None when bootstrap is built in legacy
        # call sites that haven't started passing them yet — routes that
        # need them check for None before using).
        "metrics_registry": metrics_registry,
        "scan_job_queue": scan_job_queue,
        "webhook_dispatcher": webhook_dispatcher,
        "folder_watcher": folder_watcher,
        "rotation_worker": rotation_worker,
        "collector_bridge": collector_bridge,
        "detection_service": detection_service,
        "enterprise_service": enterprise_service,
        "fleet_service": fleet_service,
        "graph_service": graph_service,
        "hids_integration_service": hids_integration_service,
        "integrity_service": integrity_service,
        "investigation_service": investigation_service,
        "malware_analyst_service": malware_analyst_service,
        "migration_service": migration_service,
        # Late-binding proxy: test_mitre_service patches api.main.mitre_service
        # wholesale via mock.patch.object — a captured reference would ignore it.
        "mitre_service": _LateBoundModuleAttr(main_module, "mitre_service"),
        "observability_service": observability_service,
        "process_intel_service": process_intel_service,
        "response_service": response_service,
        "timeline_service": timeline_service,
        "TelemetryMonitoringService": TelemetryMonitoringService,
        # --- shims (api/main.py underscore-prefixed aliases preserved)
        "_request_workspace_id": request_workspace_id,
        "_require_default_workspace_for_global_scope": require_default_workspace_for_global_scope,
        "_apply_rate_limit": apply_rate_limit,
        "_require_enterprise_approval": require_enterprise_approval,
        "_alert_destination_type": alert_destination_type,
        "_set_alert_webhook_url": set_alert_webhook_url,
        "_get_alert_webhook_url": get_alert_webhook_url,
        "_get_network_warfare_instance": get_network_warfare_instance,
        "_set_network_warfare_instance": set_network_warfare_instance,
        "_workspace_artifact_dir": workspace_artifact_dir,
        "_artifact_manifest": artifact_manifest,
        "_load_scenario_runner": load_scenario_runner,
        "_normalize_incident_row": normalize_incident_row,
        "_validate_persistence_target": validate_persistence_target,
        "_write_monitor_artifacts": write_monitor_artifacts,
        "_log_collector_exports": log_collector_exports,
        "_log_single_collector_export": log_single_collector_export,
        # --- validators
        "_validated_incident_id": validated_incident_id,
        "_validated_ip_address": validated_ip_address,
        "_validated_sha256": validated_sha256,
        "_parse_csv_query_values": parse_csv_query_values,
        # --- wrapped helpers (thin lambdas kept for signature stability)
        "_safe_file_response": lambda target, filename=None: safe_file_response(target, filename=filename),
        "_validate_webhook_url": lambda url: validate_webhook_url(url),
        "_validate_replay_artifact_path": validate_replay_artifact_path,
        "_validate_quarantine_file_path": lambda q: validate_quarantine_file_path(q),
        "_validate_quarantine_restore_paths": lambda q, o: validate_quarantine_restore_paths(q, o),
        "_build_auth_anomalies": lambda auth_rows, action_rows: build_auth_anomalies(auth_rows, action_rows),
        # --- late-binding callables (test patches mock.patch.object(api.main, ...))
        "check_ip": lambda *a, **kw: main_module.check_ip(*a, **kw),
        "check_file_malwarebazaar": lambda *a, **kw: main_module.check_file_malwarebazaar(*a, **kw),
        "check_file_yaraify": lambda *a, **kw: main_module.check_file_yaraify(*a, **kw),
        "check_file_vt": lambda *a, **kw: main_module.check_file_vt(*a, **kw),
        "fuse_detection_verdict": lambda *a, **kw: main_module.fuse_detection_verdict(*a, **kw),
        "run_local_yara_scan": lambda *a, **kw: main_module.run_local_yara_scan(*a, **kw),
        "scan_process": lambda *a, **kw: main_module.scan_process(*a, **kw),
    }
