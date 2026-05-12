from __future__ import annotations

from typing import Any

from fastapi import Body, Depends, HTTPException, Request
from pydantic import ValidationError


def register_routes(app, ctx: dict[str, Any]) -> None:
    # Schemas stay in ctx (rather than module-top imports like
    # integrations.py) to avoid a pydantic-core TypeAdapter cache
    # interaction that surfaces as "Circular reference detected" during
    # unrelated response serialization. The routes below use the
    # `payload: dict[str, Any] = Body(...)` + manual `model_validate()`
    # pattern, so no `payload: Model` annotation is at risk of the
    # Query-param fall-through that bit integrations.py.
    MitreBundleLoadRequest = ctx["MitreBundleLoadRequest"]
    MitrePathRequest = ctx["MitrePathRequest"]
    NavigatorExportRequest = ctx["NavigatorExportRequest"]
    CaseCreateRequest = ctx["CaseCreateRequest"]
    ChainOfCustodyRequest = ctx["ChainOfCustodyRequest"]
    InvestigationViewRequest = ctx["InvestigationViewRequest"]
    InvestigationNoteRequest = ctx["InvestigationNoteRequest"]
    InvestigationStoryRequest = ctx["InvestigationStoryRequest"]
    InvestigationPinRequest = ctx["InvestigationPinRequest"]
    CaseAssignmentRequest = ctx["CaseAssignmentRequest"]
    CaseTaskRequest = ctx["CaseTaskRequest"]
    CaseTaskUpdateRequest = ctx["CaseTaskUpdateRequest"]
    ApprovalRequestModel = ctx["ApprovalRequestModel"]
    ApprovalResolveRequest = ctx["ApprovalResolveRequest"]
    DetectionLifecycleRequest = ctx["DetectionLifecycleRequest"]
    FalsePositiveRequest = ctx["FalsePositiveRequest"]
    ConnectorConfigRequest = ctx["ConnectorConfigRequest"]
    ConnectorDispatchRequest = ctx["ConnectorDispatchRequest"]
    ConnectorQueueProcessRequest = ctx["ConnectorQueueProcessRequest"]
    RetentionCleanupRequest = ctx["RetentionCleanupRequest"]
    SecretRotationRequest = ctx["SecretRotationRequest"]
    ReplayRequest = ctx["ReplayRequest"]
    NetworkAssessmentRequest = ctx["NetworkAssessmentRequest"]
    EventSeverity = ctx["EventSeverity"]
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    enterprise_service = ctx["enterprise_service"]
    mitre_service = ctx["mitre_service"]
    investigation_service = ctx["investigation_service"]
    db = ctx["db"]
    request_workspace_id = ctx["_request_workspace_id"]
    validated_incident_id = ctx["_validated_incident_id"]
    parse_csv_query_values = ctx["_parse_csv_query_values"]
    graph_service = ctx["graph_service"]
    fleet_service = ctx["fleet_service"]
    process_intel_service = ctx["process_intel_service"]
    monitor_core = ctx["monitor_core"]
    workspace_artifact_dir = ctx["_workspace_artifact_dir"]
    observability_service = ctx["observability_service"]
    integrity_service = ctx["integrity_service"]
    current_actor = ctx["current_actor"]
    can_approve_workspace = ctx["can_approve_workspace"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    migration_service = ctx["migration_service"]
    artifact_manifest = ctx["_artifact_manifest"]
    html = ctx["html"]
    json = ctx["json"]
    secret_store = ctx["secret_store"]
    get_alert_webhook_url = ctx["_get_alert_webhook_url"]
    set_alert_webhook_url = ctx["_set_alert_webhook_url"]
    validate_replay_artifact_path = ctx["_validate_replay_artifact_path"]

    @app.get("/enterprise/policy", dependencies=[Depends(require_admin)])
    def enterprise_policy() -> dict[str, Any]:
        return enterprise_service.get_policy_profiles()

    @app.get("/enterprise/assets", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_assets() -> dict[str, Any]:
        return enterprise_service.assess_asset_criticality()

    @app.get("/enterprise/mitre/status", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_status() -> dict[str, Any]:
        return mitre_service.status()

    @app.post("/enterprise/mitre/load-bundle", dependencies=[Depends(require_admin)])
    def enterprise_mitre_load_bundle(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = MitreBundleLoadRequest.model_validate(payload)
        try:
            return mitre_service.load_bundle(payload_model.file_path, source=payload_model.source)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/enterprise/mitre/summary", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_summary(request: Request, limit: int = 50) -> dict[str, Any]:
        try:
            return mitre_service.enterprise_summary(limit=max(1, min(limit, 500)), workspace_id=request_workspace_id(request))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/enterprise/mitre/discover", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_discover() -> list[dict[str, Any]]:
        return mitre_service.discover_bundle_sources()

    @app.post("/enterprise/mitre/compare", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_compare(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = MitrePathRequest.model_validate(payload)
        try:
            return mitre_service.compare_bundle(payload_model.file_path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/enterprise/mitre/changelog", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_changelog(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = MitrePathRequest.model_validate(payload)
        try:
            return mitre_service.changelog_summary(payload_model.file_path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/enterprise/mitre/techniques/{attack_id}", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_technique(attack_id: str) -> dict[str, Any]:
        try:
            return mitre_service.technique_details(attack_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/enterprise/mitre/incidents/{incident_id}/coverage", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_incident_coverage(request: Request, incident_id: str) -> dict[str, Any]:
        try:
            return mitre_service.incident_coverage(validated_incident_id(incident_id), workspace_id=request_workspace_id(request))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/enterprise/cases/{case_id}/mitre", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_case_coverage(request: Request, case_id: int) -> dict[str, Any]:
        try:
            return mitre_service.case_coverage(case_id, workspace_id=request_workspace_id(request))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/enterprise/mitre/navigator/export", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_export_navigator(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = NavigatorExportRequest.model_validate(payload)
        try:
            return mitre_service.export_navigator_layer(
                incident_ids=payload_model.incident_ids,
                case_id=payload_model.case_id,
                layer_name=payload_model.layer_name,
                description=payload_model.description,
                include_subtechniques=payload_model.include_subtechniques,
                workspace_id=request_workspace_id(request),
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/enterprise/mitre/workbench/export", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_mitre_export_workbench(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = NavigatorExportRequest.model_validate(payload)
        try:
            return mitre_service.workbench_export(incident_ids=payload_model.incident_ids, case_id=payload_model.case_id, workspace_id=request_workspace_id(request))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/enterprise/triage", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_triage(request: Request) -> dict[str, Any]:
        return enterprise_service.triage_dashboard(workspace_id=request_workspace_id(request))

    @app.post("/enterprise/cases", dependencies=[Depends(require_analyst_or_admin)])
    def create_enterprise_case(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = CaseCreateRequest.model_validate(payload)
        return enterprise_service.create_case(workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/cases", dependencies=[Depends(require_analyst_or_admin)])
    def list_enterprise_cases(request: Request) -> list[dict[str, Any]]:
        return enterprise_service.list_cases(workspace_id=request_workspace_id(request))

    @app.post("/enterprise/cases/{case_id}/chain", dependencies=[Depends(require_analyst_or_admin)])
    def add_case_chain_event(request: Request, case_id: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = ChainOfCustodyRequest.model_validate(payload)
        return enterprise_service.add_chain_of_custody_event(case_id, payload_model.event_type, payload_model.actor, payload_model.artifact_path, payload_model.notes, workspace_id=request_workspace_id(request))

    @app.get("/enterprise/cases/{case_id}/chain", dependencies=[Depends(require_analyst_or_admin)])
    def case_chain(request: Request, case_id: int) -> list[dict[str, Any]]:
        return enterprise_service.get_chain_of_custody(case_id, workspace_id=request_workspace_id(request))

    @app.get("/enterprise/investigations/workspace", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_investigation_workspace(
        request: Request,
        query_text: str = "",
        event_types: str = "",
        severities: str = "",
        start_time: float | None = None,
        end_time: float | None = None,
        limit: int = 150,
        case_id: int | None = None,
    ) -> dict[str, Any]:
        return investigation_service.workspace(
            workspace_id=request_workspace_id(request),
            query_text=query_text,
            event_types=parse_csv_query_values(event_types),
            severities=parse_csv_query_values(severities),
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            case_id=case_id,
        )

    @app.post("/enterprise/investigations/views", dependencies=[Depends(require_analyst_or_admin)])
    def create_investigation_view(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = InvestigationViewRequest.model_validate(payload)
        return investigation_service.create_saved_view(
            workspace_id=request_workspace_id(request),
            name=payload_model.name,
            description=payload_model.description,
            query_text=payload_model.query_text,
            event_types=payload_model.event_types,
            severities=[severity.value if isinstance(severity, EventSeverity) else str(severity) for severity in payload_model.severities],
            start_time=payload_model.start_time,
            end_time=payload_model.end_time,
            case_id=payload_model.case_id,
            created_by=payload_model.created_by,
        )

    @app.get("/enterprise/investigations/views", dependencies=[Depends(require_analyst_or_admin)])
    def list_investigation_views(request: Request, case_id: int | None = None) -> list[dict[str, Any]]:
        return investigation_service.list_saved_views(case_id=case_id, workspace_id=request_workspace_id(request))

    @app.post("/enterprise/investigations/notes", dependencies=[Depends(require_analyst_or_admin)])
    def create_investigation_note(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = InvestigationNoteRequest.model_validate(payload)
        return investigation_service.create_note(workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/investigations/notes", dependencies=[Depends(require_analyst_or_admin)])
    def list_investigation_notes(request: Request, case_id: int | None = None, view_id: int | None = None) -> list[dict[str, Any]]:
        return investigation_service.list_notes(case_id=case_id, view_id=view_id, workspace_id=request_workspace_id(request))

    @app.post("/enterprise/investigations/stories", dependencies=[Depends(require_analyst_or_admin)])
    def create_investigation_story(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = InvestigationStoryRequest.model_validate(payload)
        return investigation_service.create_story(workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/investigations/stories", dependencies=[Depends(require_analyst_or_admin)])
    def list_investigation_stories(request: Request, case_id: int | None = None) -> list[dict[str, Any]]:
        return investigation_service.list_stories(case_id=case_id, workspace_id=request_workspace_id(request))

    @app.post("/enterprise/investigations/pins", dependencies=[Depends(require_analyst_or_admin)])
    def create_investigation_pin(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = InvestigationPinRequest.model_validate(payload)
        return investigation_service.create_pin(workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/investigations/pins", dependencies=[Depends(require_analyst_or_admin)])
    def list_investigation_pins(request: Request, case_id: int | None = None, view_id: int | None = None) -> list[dict[str, Any]]:
        return investigation_service.list_pins(case_id=case_id, view_id=view_id, workspace_id=request_workspace_id(request))

    @app.get("/enterprise/cases/{case_id}/board", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_case_board(request: Request, case_id: int) -> dict[str, Any]:
        return investigation_service.case_board(case_id=case_id, workspace_id=request_workspace_id(request))

    @app.get("/enterprise/cases/{case_id}/graph", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_case_graph(request: Request, case_id: int) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        try:
            workspace_id = request_workspace_id(request)
            cases = db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            case_record = next((item for item in cases if int(item.get("id", 0) or 0) == case_id), None)
            if case_record is None:
                raise HTTPException(status_code=404, detail="Case not found")
            assignments = db.get_case_assignments(conn, case_id).fillna("").to_dict(orient="records")
            tasks = db.get_case_tasks(conn, case_id).fillna("").to_dict(orient="records")
            activity = db.get_case_activity(conn, case_id, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            pins = db.get_investigation_pins(conn, case_id=case_id).fillna("").to_dict(orient="records")
            notes = db.get_investigation_notes(conn, case_id=case_id).fillna("").to_dict(orient="records")
            stories = db.get_investigation_stories(conn, case_id=case_id).fillna("").to_dict(orient="records")
            incidents = db.get_incidents(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            hosts_data = fleet_service.list_hosts(conn, workspace_id=workspace_id)
        finally:
            conn.close()
        processes = process_intel_service.snapshot_processes(include_deep_fields=False)
        connections = monitor_core.get_network_connections()
        try:
            import plugins.persistence as persistence_scanner

            persistence_items = persistence_scanner.get_persistence_items_fast()
        except Exception:
            persistence_items = []
        return graph_service.build_case_graph(
            case_record=case_record,
            assignments=assignments,
            tasks=tasks,
            activity=activity,
            pins=pins,
            notes=notes,
            stories=stories,
            hosts=hosts_data,
            processes=processes,
            connections=connections,
            incidents=incidents,
            persistence_items=persistence_items,
        )

    @app.post("/enterprise/cases/{case_id}/assignments", dependencies=[Depends(require_analyst_or_admin)])
    def create_case_assignment(request: Request, case_id: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = CaseAssignmentRequest.model_validate(payload)
        return investigation_service.assign_analyst(case_id=case_id, workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/cases/{case_id}/assignments", dependencies=[Depends(require_analyst_or_admin)])
    def list_case_assignments(request: Request, case_id: int) -> list[dict[str, Any]]:
        return investigation_service.list_assignments(case_id=case_id, workspace_id=request_workspace_id(request))

    @app.post("/enterprise/cases/{case_id}/tasks", dependencies=[Depends(require_analyst_or_admin)])
    def create_case_task(request: Request, case_id: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = CaseTaskRequest.model_validate(payload)
        return investigation_service.create_task(case_id=case_id, workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/cases/{case_id}/tasks", dependencies=[Depends(require_analyst_or_admin)])
    def list_case_tasks(request: Request, case_id: int) -> list[dict[str, Any]]:
        return investigation_service.list_tasks(case_id=case_id, workspace_id=request_workspace_id(request))

    @app.patch("/enterprise/cases/{case_id}/tasks/{task_id}", dependencies=[Depends(require_analyst_or_admin)])
    def update_case_task(request: Request, case_id: int, task_id: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = CaseTaskUpdateRequest.model_validate(payload)
        return investigation_service.update_task(case_id=case_id, task_id=task_id, workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.get("/enterprise/cases/{case_id}/activity", dependencies=[Depends(require_analyst_or_admin)])
    def list_case_activity(request: Request, case_id: int) -> list[dict[str, Any]]:
        return investigation_service.list_activity(case_id=case_id, workspace_id=request_workspace_id(request))

    @app.post("/enterprise/cases/{case_id}/investigation-report/export", dependencies=[Depends(require_admin)])
    def export_case_investigation_report(request: Request, case_id: int) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        result = investigation_service.export_case_report(case_id=case_id, out_dir=str(workspace_artifact_dir(workspace_id)), workspace_id=workspace_id)
        observability_service.log_event(
            "investigation_report_exported",
            case_id=case_id,
            json_path=result.get("json_path", ""),
            html_path=result.get("html_path", ""),
            workspace_id=workspace_id,
        )
        integrity_service.refresh_manifest()
        return result

    @app.post("/enterprise/approvals", dependencies=[Depends(require_analyst_or_admin)])
    def request_enterprise_approval(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = ApprovalRequestModel.model_validate(payload)
        actor = current_actor(request)
        if actor and payload_model.requested_by and payload_model.requested_by.strip().lower() != actor:
            raise HTTPException(status_code=403, detail="requested_by must match the authenticated actor")
        return enterprise_service.request_approval(workspace_id=request_workspace_id(request), **payload_model.model_dump())

    @app.patch("/enterprise/approvals/{approval_id}", dependencies=[Depends(require_admin)])
    def resolve_enterprise_approval(request: Request, approval_id: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = ApprovalResolveRequest.model_validate(payload)
        actor = current_actor(request)
        workspace_id = request_workspace_id(request)
        if actor and payload_model.approver and payload_model.approver.strip().lower() != actor:
            raise HTTPException(status_code=403, detail="approver must match the authenticated actor")
        if actor and not can_approve_workspace(request, workspace_id):
            raise HTTPException(status_code=403, detail="Current identity may not approve actions for this workspace")
        effective_approver = payload_model.approver or actor
        return enterprise_service.resolve_approval(approval_id, payload_model.status, effective_approver, workspace_id=workspace_id)

    @app.get("/enterprise/approvals", dependencies=[Depends(require_analyst_or_admin)])
    def list_enterprise_approvals(request: Request) -> list[dict[str, Any]]:
        return enterprise_service.list_approvals(workspace_id=request_workspace_id(request))

    @app.get("/enterprise/detections/lifecycle", dependencies=[Depends(require_analyst_or_admin)])
    def detection_lifecycle() -> dict[str, Any]:
        return enterprise_service.detection_lifecycle()

    @app.post("/enterprise/detections/lifecycle", dependencies=[Depends(require_analyst_or_admin)])
    def tune_detection_lifecycle(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = DetectionLifecycleRequest.model_validate(payload)
        return enterprise_service.tune_detection_rule(payload_model.rule_id, payload_model.version, payload_model.tuning, payload_model.suppressions, payload_model.notes)

    @app.post("/enterprise/detections/false-positive", dependencies=[Depends(require_analyst_or_admin)])
    def submit_false_positive(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = FalsePositiveRequest.model_validate(payload)
        return enterprise_service.log_false_positive(payload_model.rule_id, payload_model.incident_id, payload_model.actor, payload_model.reason)

    @app.get("/enterprise/connectors", dependencies=[Depends(require_admin)])
    def list_enterprise_connectors(request: Request) -> list[dict[str, Any]]:
        return enterprise_service.list_connectors(workspace_id=request_workspace_id(request))

    @app.post("/enterprise/connectors", dependencies=[Depends(require_admin)])
    def configure_enterprise_connector(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        # Route takes a raw dict (not the model directly) because
        # `from __future__ import annotations` makes the annotation a string
        # that FastAPI's get_type_hints() cannot resolve against this function's
        # local scope — binding via ctx would silently fall back to query.
        # We do the model validation manually here; convert Pydantic errors to
        # 422 (same status FastAPI would emit for a native body annotation).
        try:
            payload_model = ConnectorConfigRequest.model_validate(payload)
        except ValidationError as exc:
            # include_context=False strips ValueError objects (non JSON-serializable)
            raise HTTPException(status_code=422, detail=exc.errors(include_url=False, include_context=False)) from exc
        try:
            return enterprise_service.configure_connector(payload_model.name, payload_model.kind, payload_model.enabled, payload_model.config, workspace_id=request_workspace_id(request))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/enterprise/connectors/dispatch", dependencies=[Depends(require_admin)])
    def dispatch_enterprise_connector_event(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        try:
            payload_model = ConnectorDispatchRequest.model_validate(payload)
        except ValidationError as exc:
            # include_context=False strips ValueError objects (non JSON-serializable)
            raise HTTPException(status_code=422, detail=exc.errors(include_url=False, include_context=False)) from exc
        apply_rate_limit(request, bucket="connector_dispatch", detail="Too many connector dispatch attempts. Wait briefly and retry.")
        require_enterprise_approval(request, action_name="connector:dispatch")
        return enterprise_service.dispatch_connector_event(
            event_type=payload_model.event_type,
            payload=payload_model.payload,
            source=payload_model.source,
            severity=payload_model.severity,
            workspace_id=request_workspace_id(request),
        )

    @app.post("/enterprise/connectors/queue/process", dependencies=[Depends(require_admin)])
    def process_enterprise_connector_queue(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        try:
            payload_model = ConnectorQueueProcessRequest.model_validate(payload)
        except ValidationError as exc:
            # include_context=False strips ValueError objects (non JSON-serializable)
            raise HTTPException(status_code=422, detail=exc.errors(include_url=False, include_context=False)) from exc
        require_enterprise_approval(request, action_name="connector:queue:process")
        return enterprise_service.process_connector_queue(payload_model.limit, workspace_id=request_workspace_id(request))

    @app.get("/enterprise/connectors/queue", dependencies=[Depends(require_admin)])
    def enterprise_connector_queue(request: Request, status: str = "", limit: int = 100) -> list[dict[str, Any]]:
        return enterprise_service.connector_queue_status(status=status, limit=limit, workspace_id=request_workspace_id(request))

    @app.get("/enterprise/abuse/summary", dependencies=[Depends(require_admin)])
    def enterprise_abuse_summary(request: Request) -> dict[str, Any]:
        return enterprise_service.abuse_summary(workspace_id=request_workspace_id(request))

    @app.post("/enterprise/maintenance/retention", dependencies=[Depends(require_admin)])
    def enterprise_retention_cleanup(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = RetentionCleanupRequest.model_validate(payload)
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            purged = db.purge_old_records(
                conn,
                {
                    "telemetry": payload_model.telemetry_days,
                    "alert_log": payload_model.alerts_days,
                    "auth_log": payload_model.auth_days,
                    "action_audit_log": payload_model.action_audit_days,
                    "external_request_log": payload_model.external_days,
                    "connector_delivery_queue": payload_model.queue_days,
                },
            )
            observability_service.log_event("retention_cleanup_completed", purged=purged)
            return {"status": "completed", "purged": purged}
        finally:
            conn.close()

    @app.get("/enterprise/database/readiness", dependencies=[Depends(require_admin)])
    def enterprise_database_readiness() -> dict[str, Any]:
        migrations = migration_service.ensure_applied()
        bootstrap_path = migration_service.export_postgres_bootstrap_sql()
        profile = db.database_runtime_profile()
        return {
            "database": profile,
            "migrations": migrations,
            "postgres_bootstrap_sql": bootstrap_path,
            "production_notes": [
                "SQLite stays the default embedded mode for local lab use.",
                "PostgreSQL can now run as the shared backend when SHADOWLAB_DATABASE_URL is configured with a supported driver.",
                "Bootstrap SQL is still exported so multi-node deployments can provision the shared database deterministically.",
            ],
        }

    @app.get("/enterprise/report/security-ops", dependencies=[Depends(require_admin)])
    def enterprise_security_ops_report(request: Request) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        return {
            "integrity": integrity_service.verify_manifest(workspace_id=workspace_id),
            "abuse": enterprise_service.abuse_summary(workspace_id=workspace_id),
            "observability": observability_service.summary(),
            "database": enterprise_database_readiness(),
            "artifacts": artifact_manifest(workspace_id),
            "workspace_id": workspace_id,
        }

    @app.post("/enterprise/report/security-ops/export", dependencies=[Depends(require_admin)])
    def enterprise_security_ops_report_export(request: Request) -> dict[str, Any]:
        report = enterprise_security_ops_report(request)
        workspace_id = request_workspace_id(request)
        target_dir = workspace_artifact_dir(workspace_id)
        report_json = target_dir / "SecurityOps_Report.json"
        report_html = target_dir / "SecurityOps_Report.html"
        report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        html_body = (
            "<html><body style='font-family:Segoe UI,Arial,sans-serif;background:#10151d;color:#eef4fb;padding:24px;'>"
            "<h1>ShadowLab Security Ops Report</h1>"
            f"<pre style='white-space:pre-wrap;background:#16202c;border:1px solid #243446;padding:16px;border-radius:10px;'>{html.escape(json.dumps(report, indent=2))}</pre>"
            "</body></html>"
        )
        report_html.write_text(html_body, encoding="utf-8")
        observability_service.log_event("security_ops_report_exported", json_path=str(report_json), html_path=str(report_html), workspace_id=workspace_id)
        integrity_service.refresh_manifest()
        return {"status": "exported", "json_path": str(report_json), "html_path": str(report_html), "workspace_id": workspace_id}

    @app.post("/enterprise/secrets/rotate", dependencies=[Depends(require_admin)])
    def enterprise_rotate_secrets(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = SecretRotationRequest.model_validate(payload)
        rotated: list[str] = []
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            if payload_model.reencrypt_connector_secrets:
                connectors = db.get_connectors(conn, workspace_id=request_workspace_id(request)).fillna("").to_dict(orient="records")
                for item in connectors:
                    name = str(item.get("name", "")).strip().lower()
                    raw_config = item.get("config_json", "{}")
                    parsed = json.loads(raw_config or "{}") if isinstance(raw_config, str) else (raw_config or {})
                    revealed = secret_store.reveal_config(parsed)
                    protected = secret_store.protect_config(revealed)
                    db.upsert_connector(
                        conn,
                        name,
                        str(item.get("kind", "")),
                        bool(item.get("enabled")),
                        json.dumps(protected),
                        workspace_id=str(item.get("workspace_id", request_workspace_id(request)) or request_workspace_id(request)),
                    )
                rotated.append("connector_secrets")
                db.log_secret_rotation(conn, "connector_secrets", "rotate", detail="Connector secrets were re-encrypted")
            if payload_model.clear_alert_webhook:
                set_alert_webhook_url("")
                db.set_app_setting(conn, "alert_webhook_url_enc", "")
                rotated.append("alert_webhook_cleared")
                db.log_secret_rotation(conn, "alert_webhook", "clear", detail="Stored alert webhook secret cleared")
            elif payload_model.reencrypt_webhook_secret and get_alert_webhook_url():
                encrypted = secret_store.encrypt_text(get_alert_webhook_url())
                db.set_app_setting(conn, "alert_webhook_url_enc", encrypted)
                rotated.append("alert_webhook")
                db.log_secret_rotation(conn, "alert_webhook", "rotate", detail="Alert webhook secret was re-encrypted")
        finally:
            conn.close()
        if payload_model.rotate_integrity_signing_key:
            integrity_service.rotate_signing_key()
            conn = db.create_connection()
            if conn:
                try:
                    db.log_secret_rotation(conn, "integrity_signing_key", "rotate", detail="Integrity signing key rotated and manifest refreshed")
                finally:
                    conn.close()
            rotated.append("integrity_signing_key")
        observability_service.log_event("secrets_rotated", rotated=rotated)
        return {"status": "completed", "rotated": rotated}

    @app.get("/enterprise/secrets/status", dependencies=[Depends(require_admin)])
    def enterprise_secret_status(request: Request) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            history = db.get_secret_rotations(conn, limit=100).fillna("").to_dict(orient="records")
            stored_webhook = bool(db.get_app_setting(conn, "alert_webhook_url_enc"))
        finally:
            conn.close()
        return {
            "stored_alert_webhook": stored_webhook,
            "rotation_history": history,
            "integrity_history": integrity_service.history(limit=20, workspace_id=request_workspace_id(request)),
        }

    @app.get("/enterprise/adversary/profiles", dependencies=[Depends(require_analyst_or_admin)])
    def adversary_profiles() -> dict[str, Any]:
        return enterprise_service.adversary_emulation()

    @app.post("/enterprise/purple/replay", dependencies=[Depends(require_analyst_or_admin)])
    def purple_replay(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = ReplayRequest.model_validate(payload)
        target = validate_replay_artifact_path(payload_model.artifact_path)
        return enterprise_service.replay_incident(str(target))

    @app.get("/enterprise/telemetry/gaps", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_telemetry_gaps() -> dict[str, Any]:
        return enterprise_service.telemetry_gap_analysis()

    @app.get("/enterprise/web/inspection", dependencies=[Depends(require_analyst_or_admin)])
    def web_inspection() -> dict[str, Any]:
        return enterprise_service.inspect_web_surface()

    @app.post("/enterprise/network/assessment", dependencies=[Depends(require_analyst_or_admin)])
    def enterprise_network_assessment(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        payload_model = NetworkAssessmentRequest.model_validate(payload)
        return enterprise_service.network_pentest_overview(payload_model.ip_range)
