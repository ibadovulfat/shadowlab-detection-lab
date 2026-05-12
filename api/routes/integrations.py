from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, Request

# NOTE: Pydantic schemas are imported at module scope — NOT pulled from `ctx`.
# `from __future__ import annotations` turns function annotations into strings;
# FastAPI's `get_type_hints()` resolves them against the MODULE globals, not the
# local scope of `register_routes()`. If these models only lived in `ctx` the
# `payload: IntegrationFileImportRequest` annotation on every route below would
# silently fall back to a Query parameter (422 "Field required: query.payload"),
# bypassing the path-traversal validators on the models. Four security tests
# caught this regression — hence the explicit module-level import.
from api.schemas.requests import (
    IncidentResponseOrchestrationRequest,
    IntegrationFileImportRequest,
    IntegrationResponsePolicyRequest,
    OssecFileImportRequest,
    OssecLiveIngestRequest,
    WhidsArtifactsRequest,
    WhidsConfigRequest,
    WhidsIoCRequest,
    WhidsManagerImportRequest,
    WhidsRulesRequest,
    WhidsSchedulerRequest,
)


def register_routes(app, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    collector_bridge = ctx["collector_bridge"]
    log_single_collector_export = ctx["_log_single_collector_export"]
    request_workspace_id = ctx["_request_workspace_id"]
    db = ctx["db"]
    normalize_incident_row = ctx["_normalize_incident_row"]
    hids_integration_service = ctx["hids_integration_service"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    requests = ctx["requests"]

    @app.get("/integrations/telemetry-fabric/status", dependencies=[Depends(require_admin)])
    def telemetry_fabric_status() -> dict[str, Any]:
        return collector_bridge.collector_status()

    @app.post("/integrations/telemetry-fabric/start", dependencies=[Depends(require_admin)])
    def start_telemetry_fabric(request: Request) -> dict[str, Any]:
        result = collector_bridge.start_collector()
        log_single_collector_export("collector_start", result, workspace_id=request_workspace_id(request))
        return result

    @app.post("/integrations/telemetry-fabric/stop", dependencies=[Depends(require_admin)])
    def stop_telemetry_fabric(request: Request) -> dict[str, Any]:
        result = collector_bridge.stop_collector()
        log_single_collector_export("collector_stop", result, workspace_id=request_workspace_id(request))
        return result

    @app.post("/integrations/telemetry-fabric/export/incidents/{incident_id}", dependencies=[Depends(require_admin)])
    def resend_incident_to_telemetry_fabric(request: Request, incident_id: str) -> dict[str, Any]:
        workspace_id = request_workspace_id(request)
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            incident = db.get_incident_by_id(conn, incident_id, workspace_id=workspace_id)
        finally:
            conn.close()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        result = collector_bridge.export_incident_record(normalize_incident_row(incident))
        log_single_collector_export("incident_log", result, incident_id=incident_id, workspace_id=workspace_id)
        return result

    @app.get("/integrations/telemetry-fabric/exports", dependencies=[Depends(require_admin)])
    def list_telemetry_fabric_exports(request: Request) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
        try:
            frame = db.get_integration_exports(conn, workspace_id=request_workspace_id(request))
        finally:
            conn.close()
        return frame.fillna("").to_dict(orient="records")

    @app.post("/integrations/whids/import/file", dependencies=[Depends(require_admin)])
    def import_whids_file(request: Request, payload: IntegrationFileImportRequest) -> dict[str, Any]:
        try:
            return hids_integration_service.import_whids_file(payload.file_path, limit=payload.limit, workspace_id=request_workspace_id(request))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/whids/import/manager", dependencies=[Depends(require_admin)])
    def import_whids_manager(request: Request, payload: WhidsManagerImportRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:import_manager")
        try:
            return hids_integration_service.import_whids_manager(
                payload.manager_url,
                payload.api_key,
                limit=payload.limit,
                endpoint_uuid=payload.endpoint_uuid,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS manager request failed: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/whids/reports", dependencies=[Depends(require_admin)])
    def sync_whids_reports(request: Request, payload: WhidsManagerImportRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:reports")
        try:
            return hids_integration_service.sync_whids_reports(
                payload.manager_url,
                payload.api_key,
                endpoint_uuid=payload.endpoint_uuid,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS reports request failed: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/whids/artifacts", dependencies=[Depends(require_admin)])
    def download_whids_artifacts(request: Request, payload: WhidsArtifactsRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:artifacts")
        try:
            return hids_integration_service.download_whids_artifacts(
                payload.manager_url,
                payload.api_key,
                endpoint_uuid=payload.endpoint_uuid,
                since=payload.since,
                max_files=payload.max_files,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS artifacts request failed: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/ossec/import/file", dependencies=[Depends(require_admin)])
    def import_ossec_file(request: Request, payload: OssecFileImportRequest) -> dict[str, Any]:
        try:
            return hids_integration_service.import_ossec_file(payload.file_path, limit=payload.limit, workspace_id=request_workspace_id(request))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/ossec/live/start", dependencies=[Depends(require_admin)])
    def start_ossec_live_ingest(request: Request, payload: OssecLiveIngestRequest) -> dict[str, Any]:
        try:
            return hids_integration_service.start_ossec_live_ingest(
                payload.file_path,
                poll_interval=payload.poll_interval,
                limit=payload.limit,
                start_at_end=payload.start_at_end,
                workspace_id=request_workspace_id(request),
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/ossec/live/stop", dependencies=[Depends(require_admin)])
    def stop_ossec_live_ingest() -> dict[str, Any]:
        return hids_integration_service.stop_ossec_live_ingest()

    @app.get("/integrations/ossec/live/status", dependencies=[Depends(require_admin)])
    def ossec_live_status() -> dict[str, Any]:
        return hids_integration_service.ossec_live_status()

    @app.get("/integrations/response-policy", dependencies=[Depends(require_admin)])
    def get_integration_response_policy() -> dict[str, Any]:
        return hids_integration_service.get_response_policy()

    @app.post("/integrations/response-policy", dependencies=[Depends(require_admin)])
    def update_integration_response_policy(payload: IntegrationResponsePolicyRequest) -> dict[str, Any]:
        return hids_integration_service.update_response_policy(payload.policy)

    @app.post("/integrations/incidents/{incident_id}/response", dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)])
    def orchestrate_integration_incident_response(request: Request, incident_id: str, payload: IncidentResponseOrchestrationRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:incident:response")
        try:
            return hids_integration_service.orchestrate_incident_response(
                incident_id,
                apply_actions=payload.apply_actions,
                workspace_id=request_workspace_id(request),
            )
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/integrations/whids/iocs/query", dependencies=[Depends(require_admin)])
    def query_whids_iocs(request: Request, payload: WhidsIoCRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:iocs:query")
        try:
            return hids_integration_service.list_whids_iocs(
                payload.manager_url,
                payload.api_key,
                filters=payload.filters,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS IoC query failed: {exc}") from exc

    @app.post("/integrations/whids/iocs/add", dependencies=[Depends(require_admin)])
    def add_whids_iocs(request: Request, payload: WhidsIoCRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:iocs:add")
        try:
            return hids_integration_service.add_whids_iocs(
                payload.manager_url,
                payload.api_key,
                payload.items,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS IoC add failed: {exc}") from exc

    @app.post("/integrations/whids/iocs/delete", dependencies=[Depends(require_admin)])
    def delete_whids_iocs(request: Request, payload: WhidsIoCRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:iocs:delete")
        try:
            return hids_integration_service.delete_whids_iocs(
                payload.manager_url,
                payload.api_key,
                filters=payload.filters,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS IoC delete failed: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/whids/rules/query", dependencies=[Depends(require_admin)])
    def query_whids_rules(request: Request, payload: WhidsRulesRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:rules:query")
        try:
            return hids_integration_service.list_whids_rules(
                payload.manager_url,
                payload.api_key,
                name=payload.name_filter,
                filters_only=payload.filters_only,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS rules query failed: {exc}") from exc

    @app.post("/integrations/whids/rules/add", dependencies=[Depends(require_admin)])
    def add_whids_rules(request: Request, payload: WhidsRulesRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:rules:add")
        try:
            return hids_integration_service.add_whids_rules(
                payload.manager_url,
                payload.api_key,
                payload.rules,
                update_existing=payload.update_existing,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS rules add failed: {exc}") from exc

    @app.post("/integrations/whids/rules/delete", dependencies=[Depends(require_admin)])
    def delete_whids_rules(request: Request, payload: WhidsRulesRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:rules:delete")
        try:
            return hids_integration_service.delete_whids_rules(
                payload.manager_url,
                payload.api_key,
                rule_name=payload.rule_name,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS rules delete failed: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/integrations/whids/config", dependencies=[Depends(require_admin)])
    def get_whids_config(request: Request, payload: WhidsConfigRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:config")
        try:
            return hids_integration_service.get_whids_endpoint_config(
                payload.manager_url,
                payload.api_key,
                endpoint_uuid=payload.endpoint_uuid,
                config_format=payload.config_format,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS config query failed: {exc}") from exc

    @app.post("/integrations/whids/report-archive", dependencies=[Depends(require_admin)])
    def get_whids_report_archive(request: Request, payload: WhidsConfigRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:report_archive")
        try:
            return hids_integration_service.get_whids_report_archive(
                payload.manager_url,
                payload.api_key,
                endpoint_uuid=payload.endpoint_uuid,
                since=payload.since,
                until=payload.until,
                verify_tls=payload.verify_tls,
                workspace_id=request_workspace_id(request),
            )
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"WHIDS report archive query failed: {exc}") from exc

    @app.post("/integrations/whids/scheduler/start", dependencies=[Depends(require_admin)])
    def start_whids_scheduler(request: Request, payload: WhidsSchedulerRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:scheduler:start")
        return hids_integration_service.start_whids_scheduler(
            payload.manager_url,
            payload.api_key,
            endpoint_uuid=payload.endpoint_uuid,
            poll_interval=payload.poll_interval,
            verify_tls=payload.verify_tls,
            workspace_id=request_workspace_id(request),
        )

    @app.post("/integrations/whids/scheduler/stop", dependencies=[Depends(require_admin)])
    def stop_whids_scheduler(request: Request) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="integration:whids:scheduler:stop")
        return hids_integration_service.stop_whids_scheduler()

    @app.get("/integrations/whids/scheduler/status", dependencies=[Depends(require_admin)])
    def whids_scheduler_status() -> dict[str, Any]:
        return hids_integration_service.whids_scheduler_status()

