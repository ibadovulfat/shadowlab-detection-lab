from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
import time
from pathlib import Path
import re
import threading
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import psutil
from services.outbound_security import normalize_outbound_url
from services.secret_store import is_encrypted_secret, secret_store


class HidsIntegrationService:
    def __init__(self, db_module, enterprise_service=None, investigation_service=None, response_service=None, mitre_service=None):
        self.db = db_module
        self.enterprise_service = enterprise_service
        self.investigation_service = investigation_service
        self.response_service = response_service
        self.mitre_service = mitre_service
        self.base_dir = Path(__file__).resolve().parent.parent
        self.out_dir = self.base_dir / "shadowlab_out" / "whids"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.orchestration_dir = self.base_dir / "shadowlab_out" / "orchestrations"
        self.orchestration_dir.mkdir(parents=True, exist_ok=True)
        self.policy_path = self.base_dir / "shadowlab_out" / "integration_response_policy.json"
        self.runtime_path = self.base_dir / "shadowlab_out" / "integration_runtime.json"
        self.whids_scheduler_stop = threading.Event()
        self.whids_scheduler_thread: threading.Thread | None = None
        self.whids_scheduler_state: dict[str, Any] = {
            "running": False,
            "manager_url": "",
            "poll_interval": 0.0,
            "endpoint_uuid": "",
            "workspace_id": "default",
            "last_run_at": 0.0,
            "last_error": "",
            "total_cycles": 0,
        }
        self._write_default_policy_if_missing()
        self._ossec_live_lock = threading.Lock()
        self._ossec_live_stop = threading.Event()
        self._ossec_live_thread: threading.Thread | None = None
        self._ossec_live_state: dict[str, Any] = {
            "running": False,
            "file_path": "",
            "poll_interval": 0.0,
            "limit": 0,
            "start_at_end": True,
            "workspace_id": "default",
            "last_run_at": 0.0,
            "last_imported_at": 0.0,
            "last_error": "",
            "total_imported": 0,
            "seen_count": 0,
        }
        self._restore_runtime_if_enabled()

    def _workspace_output_dir(self, workspace_id: str) -> Path:
        current = str(workspace_id or "default").strip().lower() or "default"
        if current == "default":
            self.out_dir.mkdir(parents=True, exist_ok=True)
            return self.out_dir
        target = self.out_dir / "workspaces" / self._slugify(current)
        target.mkdir(parents=True, exist_ok=True)
        return target

    def import_whids_file(self, file_path: str, limit: int = 200, workspace_id: str = "default") -> dict[str, Any]:
        path = Path(file_path).expanduser()
        records = self._load_json_records(path, limit=limit)
        return self._store_incidents(
            integration_name="whids",
            export_type="import_file",
            target=str(path),
            detail_template="Imported {count} WHIDS detections from file",
            records=records,
            normalizer=self._normalize_whids_record,
            workspace_id=workspace_id,
        )

    def import_whids_manager(
        self,
        manager_url: str,
        api_key: str,
        *,
        limit: int = 200,
        endpoint_uuid: str = "",
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)

        endpoints = []
        if endpoint_uuid.strip():
            endpoints = [{"uuid": endpoint_uuid.strip()}]
        else:
            response = session.get(urljoin(base_url, "endpoints"), timeout=25)
            response.raise_for_status()
            payload = self._safe_json(response)
            endpoint_items = payload.get("data", [])
            endpoints = endpoint_items if isinstance(endpoint_items, list) else []

        records: list[dict[str, Any]] = []
        fetched_endpoints = 0
        for endpoint in endpoints[: max(1, limit)]:
            uuid = str(endpoint.get("uuid", "")).strip()
            if not uuid:
                continue
            detections_response = session.get(
                urljoin(base_url, f"endpoints/{uuid}/detections"),
                params={"limit": min(limit, 500)},
                timeout=30,
            )
            detections_response.raise_for_status()
            detections_payload = self._safe_json(detections_response)
            detection_items = detections_payload.get("data", [])
            if isinstance(detection_items, list):
                for item in detection_items:
                    if isinstance(item, dict):
                        enriched = dict(item)
                        enriched.setdefault("EdrData", {})
                        edr_data = enriched["EdrData"] if isinstance(enriched["EdrData"], dict) else {}
                        endpoint_meta = edr_data.get("Endpoint", {}) if isinstance(edr_data.get("Endpoint"), dict) else {}
                        endpoint_meta.setdefault("UUID", uuid)
                        endpoint_meta.setdefault("Hostname", endpoint.get("hostname", ""))
                        endpoint_meta.setdefault("IP", endpoint.get("ip", ""))
                        edr_data["Endpoint"] = endpoint_meta
                        enriched["EdrData"] = edr_data
                        records.append(enriched)
            fetched_endpoints += 1

        result = self._store_incidents(
            integration_name="whids",
            export_type="import_manager",
            target=manager_url,
            detail_template="Imported {count} WHIDS detections from manager API",
            records=records[:limit],
            normalizer=self._normalize_whids_record,
            workspace_id=workspace_id,
        )
        result["fetched_endpoints"] = fetched_endpoints
        result["source"] = manager_url
        return result

    def import_ossec_file(self, file_path: str, limit: int = 200, workspace_id: str = "default") -> dict[str, Any]:
        path = Path(file_path).expanduser()
        records = self._load_ossec_records(path, limit=limit)
        return self._store_incidents(
            integration_name="ossec",
            export_type="import_file",
            target=str(path),
            detail_template="Imported {count} OSSEC alerts from file",
            records=records,
            normalizer=self._normalize_ossec_record,
            workspace_id=workspace_id,
        )

    def start_ossec_live_ingest(
        self,
        file_path: str,
        *,
        poll_interval: float = 2.0,
        limit: int = 200,
        start_at_end: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        path = Path(file_path).expanduser()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Integration source not found: {path}")
        interval = max(0.5, float(poll_interval))
        max_records = max(1, min(int(limit), 2000))
        initial_seen = self._load_existing_ossec_incident_ids(workspace_id=workspace_id)
        if start_at_end:
            current_records = self._load_ossec_records(path, limit=max_records)
            initial_seen.update(self._normalized_incident_ids(current_records, self._normalize_ossec_record))

        with self._ossec_live_lock:
            if self._ossec_live_thread and self._ossec_live_thread.is_alive():
                self._ossec_live_state.update(
                    {
                        "file_path": str(path),
                        "poll_interval": interval,
                        "limit": max_records,
                        "start_at_end": bool(start_at_end),
                        "workspace_id": workspace_id,
                        "seen_count": len(initial_seen),
                    }
                )
                return dict(self._ossec_live_state)
            self._ossec_live_stop.clear()
            self._ossec_live_state.update(
                {
                    "running": True,
                    "file_path": str(path),
                    "poll_interval": interval,
                    "limit": max_records,
                    "start_at_end": bool(start_at_end),
                    "workspace_id": workspace_id,
                    "last_run_at": 0.0,
                    "last_imported_at": 0.0,
                    "last_error": "",
                    "total_imported": 0,
                    "seen_count": len(initial_seen),
                }
            )
            self._ossec_live_thread = threading.Thread(
                target=self._ossec_live_worker,
                args=(str(path), interval, max_records, initial_seen, workspace_id),
                daemon=True,
                name="shadowlab-ossec-live-ingest",
            )
            self._ossec_live_thread.start()
        self._log_export(
            integration_name="ossec",
            export_type="live_start",
            target=str(path),
            status="success",
            detail=f"Started OSSEC live ingest from {path}",
        )
        self._save_runtime_state(
            {
                "ossec_live": {
                    "enabled": True,
                    "file_path": str(path),
                    "poll_interval": interval,
                    "limit": max_records,
                    "start_at_end": bool(start_at_end),
                    "workspace_id": workspace_id,
                }
            }
        )
        return dict(self._ossec_live_state)

    def stop_ossec_live_ingest(self) -> dict[str, Any]:
        thread = None
        with self._ossec_live_lock:
            thread = self._ossec_live_thread
            self._ossec_live_stop.set()
        if thread and thread.is_alive():
            thread.join(timeout=3)
        with self._ossec_live_lock:
            self._ossec_live_state["running"] = False
            self._ossec_live_thread = None
            state = dict(self._ossec_live_state)
        if state.get("file_path"):
            self._log_export(
                integration_name="ossec",
                export_type="live_stop",
                target=str(state.get("file_path", "")),
                status="success",
                detail=f"Stopped OSSEC live ingest after importing {state.get('total_imported', 0)} alerts",
            )
        self._save_runtime_state({"ossec_live": {"enabled": False}})
        return state

    def ossec_live_status(self) -> dict[str, Any]:
        with self._ossec_live_lock:
            if self._ossec_live_thread and not self._ossec_live_thread.is_alive():
                self._ossec_live_state["running"] = False
                self._ossec_live_thread = None
            return dict(self._ossec_live_state)

    def get_response_policy(self) -> dict[str, Any]:
        if not self.policy_path.exists():
            self._write_default_policy_if_missing()
        try:
            loaded = json.loads(self.policy_path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else self._default_policy()
        except Exception:
            return self._default_policy()

    def update_response_policy(self, patch: dict[str, Any]) -> dict[str, Any]:
        current = self.get_response_policy()
        merged = self._deep_merge(current, patch)
        self.policy_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
        return merged

    def start_whids_scheduler(
        self,
        manager_url: str,
        api_key: str,
        *,
        endpoint_uuid: str = "",
        poll_interval: float = 300.0,
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        interval = max(30.0, float(poll_interval))
        if self.whids_scheduler_thread and self.whids_scheduler_thread.is_alive():
            self.whids_scheduler_state.update(
                {
                    "manager_url": manager_url,
                    "poll_interval": interval,
                    "endpoint_uuid": endpoint_uuid,
                    "workspace_id": workspace_id,
                    "last_error": "",
                }
            )
            return dict(self.whids_scheduler_state)
        self.whids_scheduler_stop.clear()
        self.whids_scheduler_state.update(
            {
                "running": True,
                "manager_url": manager_url,
                "poll_interval": interval,
                "endpoint_uuid": endpoint_uuid,
                "workspace_id": workspace_id,
                "last_run_at": 0.0,
                "last_error": "",
                "total_cycles": 0,
            }
        )
        self.whids_scheduler_thread = threading.Thread(
            target=self._whids_scheduler_worker,
            args=(manager_url, api_key, endpoint_uuid, interval, verify_tls, workspace_id),
            daemon=True,
            name="shadowlab-whids-scheduler",
        )
        self.whids_scheduler_thread.start()
        self._save_runtime_state(
            {
                "whids_scheduler": {
                    "enabled": True,
                    "manager_url": manager_url,
                    "api_key": secret_store.encrypt_text(api_key),
                    "endpoint_uuid": endpoint_uuid,
                    "poll_interval": interval,
                    "verify_tls": bool(verify_tls),
                    "workspace_id": workspace_id,
                }
            }
        )
        return dict(self.whids_scheduler_state)

    def stop_whids_scheduler(self) -> dict[str, Any]:
        self.whids_scheduler_stop.set()
        if self.whids_scheduler_thread and self.whids_scheduler_thread.is_alive():
            self.whids_scheduler_thread.join(timeout=3)
        self.whids_scheduler_state["running"] = False
        self.whids_scheduler_thread = None
        self._save_runtime_state({"whids_scheduler": {"enabled": False}})
        return dict(self.whids_scheduler_state)

    def whids_scheduler_status(self) -> dict[str, Any]:
        if self.whids_scheduler_thread and not self.whids_scheduler_thread.is_alive():
            self.whids_scheduler_state["running"] = False
            self.whids_scheduler_thread = None
        return dict(self.whids_scheduler_state)

    def orchestrate_incident_response(
        self,
        incident_id: str,
        *,
        apply_actions: bool = False,
        allowed_actions: list[str] | None = None,
        source: str = "manual",
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        conn = self.db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            incident = self.db.get_incident_by_id(conn, incident_id, workspace_id=workspace_id)
        finally:
            conn.close()
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")

        provider = self._provider_from_incident(incident)
        context = self._incident_context(incident, provider)
        plan = self._build_response_plan(provider, incident, context)
        if allowed_actions is not None:
            allowed = {str(item).strip() for item in allowed_actions if str(item).strip()}
            plan = [item for item in plan if str(item.get("action", "")) in allowed]
        executed: list[dict[str, Any]] = []
        manual_required: list[dict[str, Any]] = []
        for action in plan:
            if action.get("supported"):
                if apply_actions:
                    executed.append(self._execute_orchestration_action(incident_id, action, context))
                else:
                    executed.append({**action, "status": "planned"})
            else:
                manual_required.append({**action, "status": "manual_required"})
        summary = {
            "incident_id": incident_id,
            "provider": provider,
            "apply_actions": apply_actions,
            "context": context,
            "executed": executed,
            "manual_required": manual_required,
        }
        self._log_export(
            integration_name=provider,
            export_type="response_orchestration_apply" if apply_actions else "response_orchestration_plan",
            target=incident_id,
            status="success",
            detail=f"{'Applied' if apply_actions else 'Planned'} {len(executed)} supported response actions for {incident_id} via {source}",
            workspace_id=workspace_id,
        )
        return summary

    def list_whids_iocs(self, manager_url: str, api_key: str, *, filters: dict[str, str] | None = None, verify_tls: bool = True, workspace_id: str = "default") -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.get(urljoin(base_url, "iocs"), params=filters or None, timeout=30)
        response.raise_for_status()
        payload = self._safe_json(response)
        items = payload.get("data", [])
        return {"integration": "whids", "resource": "iocs", "items": items if isinstance(items, list) else []}

    def add_whids_iocs(self, manager_url: str, api_key: str, items: list[dict[str, Any]], *, verify_tls: bool = True, workspace_id: str = "default") -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.post(urljoin(base_url, "iocs"), json=items, timeout=30)
        response.raise_for_status()
        payload = self._safe_json(response)
        data = payload.get("data", [])
        self._log_export(
            integration_name="whids",
            export_type="ioc_add",
            target=manager_url,
            status="success",
            detail=f"Added {len(data) if isinstance(data, list) else len(items)} WHIDS IoCs",
            workspace_id=workspace_id,
        )
        return {"integration": "whids", "resource": "iocs", "items": data if isinstance(data, list) else []}

    def delete_whids_iocs(self, manager_url: str, api_key: str, *, filters: dict[str, str], verify_tls: bool = True, workspace_id: str = "default") -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.delete(urljoin(base_url, "iocs"), params=filters, timeout=30)
        response.raise_for_status()
        self._log_export(
            integration_name="whids",
            export_type="ioc_delete",
            target=manager_url,
            status="success",
            detail=f"Deleted WHIDS IoCs with filters {json.dumps(filters, ensure_ascii=False)}",
            workspace_id=workspace_id,
        )
        return {"integration": "whids", "resource": "iocs", "deleted_filters": filters, "ok": True}

    def list_whids_rules(self, manager_url: str, api_key: str, *, name: str = "", filters_only: bool = False, verify_tls: bool = True, workspace_id: str = "default") -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        params: dict[str, Any] = {}
        if name.strip():
            params["name"] = name.strip()
        if filters_only:
            params["filters"] = "true"
        response = session.get(urljoin(base_url, "rules"), params=params or None, timeout=30)
        response.raise_for_status()
        payload = self._safe_json(response)
        data = payload.get("data", [])
        return {"integration": "whids", "resource": "rules", "items": data if isinstance(data, list) else []}

    def add_whids_rules(
        self,
        manager_url: str,
        api_key: str,
        rules: list[dict[str, Any]],
        *,
        update_existing: bool = True,
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.post(
            urljoin(base_url, "rules"),
            params={"update": str(update_existing).lower()},
            json=rules,
            timeout=30,
        )
        response.raise_for_status()
        payload = self._safe_json(response)
        data = payload.get("data", [])
        self._log_export(
            integration_name="whids",
            export_type="rules_add",
            target=manager_url,
            status="success",
            detail=f"Added or updated {len(data) if isinstance(data, list) else len(rules)} WHIDS rules",
            workspace_id=workspace_id,
        )
        return {"integration": "whids", "resource": "rules", "items": data if isinstance(data, list) else []}

    def delete_whids_rules(self, manager_url: str, api_key: str, *, rule_name: str, verify_tls: bool = True, workspace_id: str = "default") -> dict[str, Any]:
        if not rule_name.strip():
            raise ValueError("rule_name is required")
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.delete(urljoin(base_url, "rules"), params={"name": rule_name.strip()}, timeout=30)
        response.raise_for_status()
        self._log_export(
            integration_name="whids",
            export_type="rules_delete",
            target=manager_url,
            status="success",
            detail=f"Deleted WHIDS rule {rule_name.strip()}",
            workspace_id=workspace_id,
        )
        return {"integration": "whids", "resource": "rules", "deleted_rule": rule_name.strip(), "ok": True}

    def get_whids_endpoint_config(
        self,
        manager_url: str,
        api_key: str,
        *,
        endpoint_uuid: str,
        config_format: str = "json",
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.get(
            urljoin(base_url, f"endpoints/{endpoint_uuid.strip()}/config"),
            params={"format": config_format},
            timeout=30,
        )
        response.raise_for_status()
        payload = self._safe_json(response)
        return {
            "integration": "whids",
            "resource": "endpoint_config",
            "endpoint_uuid": endpoint_uuid.strip(),
            "format": config_format,
            "config": payload.get("data", {}),
        }

    def get_whids_report_archive(
        self,
        manager_url: str,
        api_key: str,
        *,
        endpoint_uuid: str,
        since: str = "",
        until: str = "",
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        params = {}
        if since.strip():
            params["since"] = since.strip()
        if until.strip():
            params["until"] = until.strip()
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        response = session.get(
            urljoin(base_url, f"endpoints/{endpoint_uuid.strip()}/report/archive"),
            params=params or None,
            timeout=30,
        )
        response.raise_for_status()
        payload = self._safe_json(response)
        data = payload.get("data", [])
        return {
            "integration": "whids",
            "resource": "report_archive",
            "endpoint_uuid": endpoint_uuid.strip(),
            "items": data if isinstance(data, list) else [],
        }

    def sync_whids_reports(
        self,
        manager_url: str,
        api_key: str,
        *,
        endpoint_uuid: str = "",
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        target_uuid = endpoint_uuid.strip()
        if target_uuid:
            response = session.get(urljoin(base_url, f"endpoints/{target_uuid}/report"), timeout=30)
            response.raise_for_status()
            payload = self._safe_json(response)
            report_data = payload.get("data", {})
            reports = {target_uuid: report_data} if isinstance(report_data, dict) and report_data else {}
        else:
            response = session.get(urljoin(base_url, "endpoints/reports"), timeout=30)
            response.raise_for_status()
            payload = self._safe_json(response)
            report_data = payload.get("data", {})
            reports = report_data if isinstance(report_data, dict) else {}

        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target_name = f"whids-report-{self._slugify(target_uuid or 'all-endpoints')}-{stamp}.json"
        output_path = self._workspace_output_dir(workspace_id) / target_name
        output_path.write_text(json.dumps(reports, indent=2, ensure_ascii=False), encoding="utf-8")

        summary = {
            "integration": "whids",
            "source": manager_url,
            "endpoint_uuid": target_uuid,
            "report_count": len(reports),
            "saved_path": str(output_path),
            "reports": reports,
        }
        self._log_export(
            integration_name="whids",
            export_type="sync_reports",
            target=manager_url if not target_uuid else f"{manager_url.rstrip('/')}/endpoints/{target_uuid}/report",
            status="success" if reports else "no_data",
            detail=f"Synced {len(reports)} WHIDS report entries to {output_path.name}",
            workspace_id=workspace_id,
        )
        return summary

    def download_whids_artifacts(
        self,
        manager_url: str,
        api_key: str,
        *,
        endpoint_uuid: str,
        since: str = "",
        max_files: int = 25,
        verify_tls: bool = True,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        target_uuid = endpoint_uuid.strip()
        if not target_uuid:
            raise ValueError("endpoint_uuid is required for WHIDS artifact download")

        session, base_url = self._build_whids_session(manager_url, api_key, verify_tls=verify_tls)
        params = {"since": since.strip()} if since.strip() else None
        response = session.get(urljoin(base_url, f"endpoints/{target_uuid}/artifacts"), params=params, timeout=45)
        response.raise_for_status()
        payload = self._safe_json(response)
        artifact_entries = payload.get("data", [])
        entries = artifact_entries if isinstance(artifact_entries, list) else []

        artifact_dir = self._workspace_output_dir(workspace_id) / "artifacts" / self._slugify(target_uuid)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        downloaded_files: list[dict[str, Any]] = []
        files_seen = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            pguid = str(entry.get("process-guid", "")).strip()
            ehash = str(entry.get("event-hash", "")).strip()
            files = entry.get("files", [])
            if not pguid or not ehash or not isinstance(files, list):
                continue
            entry_dir = artifact_dir / self._slugify(pguid) / self._slugify(ehash)
            entry_dir.mkdir(parents=True, exist_ok=True)
            for file_meta in files:
                if files_seen >= max_files:
                    break
                if not isinstance(file_meta, dict):
                    continue
                filename = str(file_meta.get("name", "")).strip()
                if not filename:
                    continue
                artifact_response = session.get(
                    urljoin(base_url, f"endpoints/{target_uuid}/artifacts/{pguid}/{ehash}/{filename}"),
                    params={"raw": "true", "gunzip": "true"},
                    timeout=60,
                )
                artifact_response.raise_for_status()
                safe_name = self._safe_filename(filename)
                destination = entry_dir / safe_name
                destination.write_bytes(artifact_response.content)
                downloaded_files.append(
                    {
                        "endpoint_uuid": target_uuid,
                        "process_guid": pguid,
                        "event_hash": ehash,
                        "filename": filename,
                        "saved_path": str(destination),
                        "size": len(artifact_response.content),
                    }
                )
                files_seen += 1
            if files_seen >= max_files:
                break

        metadata_path = artifact_dir / f"artifact-manifest-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
        metadata_path.write_text(json.dumps(downloaded_files, indent=2, ensure_ascii=False), encoding="utf-8")
        self._log_export(
            integration_name="whids",
            export_type="sync_artifacts",
            target=f"{manager_url.rstrip('/')}/endpoints/{target_uuid}/artifacts",
            status="success" if downloaded_files else "no_data",
            detail=f"Downloaded {len(downloaded_files)} WHIDS artifacts for endpoint {target_uuid}",
            workspace_id=workspace_id,
        )
        return {
            "integration": "whids",
            "source": manager_url,
            "endpoint_uuid": target_uuid,
            "artifact_entries": len(entries),
            "downloaded_files": downloaded_files,
            "downloaded_count": len(downloaded_files),
            "saved_dir": str(artifact_dir),
            "manifest_path": str(metadata_path),
        }

    def _store_incidents(
        self,
        *,
        integration_name: str,
        export_type: str,
        target: str,
        detail_template: str,
        records: list[dict[str, Any]],
        normalizer,
        workspace_id: str = "default",
    ) -> dict[str, Any]:
        imported = 0
        incidents: list[str] = []
        conn = self.db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            for record in records:
                normalized = normalizer(record)
                if not normalized:
                    continue
                if self._store_normalized_incident(
                    conn,
                    normalized,
                    integration_name=integration_name,
                    source_target=target,
                    workspace_id=workspace_id,
                ):
                    imported += 1
                    incidents.append(normalized["incident"]["incident_id"])
            self.db.log_integration_export(
                conn,
                integration_name,
                export_type,
                str(target),
                "success" if imported else "no_data",
                detail_template.format(count=imported),
                workspace_id=workspace_id,
            )
        finally:
            conn.close()
        return {
            "integration": integration_name,
            "source": str(target),
            "imported": imported,
            "incident_ids": incidents,
        }

    def _store_normalized_incident(
        self,
        conn,
        normalized: dict[str, Any],
        *,
        integration_name: str,
        source_target: str,
        seen_ids: set[str] | None = None,
        workspace_id: str = "default",
    ) -> bool:
        incident_id = str(normalized["incident"]["incident_id"])
        if seen_ids is not None and incident_id in seen_ids:
            return False
        existing = self.db.get_incident_by_id(conn, incident_id, workspace_id=workspace_id)
        host_payload = dict(normalized["host"])
        incident_payload = dict(normalized["incident"])
        host_payload["workspace_id"] = workspace_id
        incident_payload["workspace_id"] = workspace_id
        self.db.upsert_host(conn, **host_payload)
        self.db.upsert_incident(conn, **incident_payload)
        if seen_ids is not None:
            seen_ids.add(incident_id)
        if existing is None:
            self._correlate_enterprise_incident(
                normalized,
                integration_name=integration_name,
                source_target=source_target,
                workspace_id=workspace_id,
            )
            self._auto_respond_if_needed(incident_id, normalized, integration_name=integration_name)
            return True
        self._log_export(
            integration_name=integration_name,
            export_type="dedupe_skip",
            target=incident_id,
            status="success",
            detail=f"Skipped duplicate incident import for {incident_id}",
            workspace_id=workspace_id,
        )
        return False

    def _log_export(
        self,
        *,
        integration_name: str,
        export_type: str,
        target: str,
        status: str,
        detail: str,
        workspace_id: str = "default",
    ) -> None:
        conn = self.db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            self.db.log_integration_export(conn, integration_name, export_type, str(target), status, detail, workspace_id=workspace_id)
        finally:
            conn.close()

    def _build_whids_session(self, manager_url: str, api_key: str, *, verify_tls: bool) -> tuple[requests.Session, str]:
        base_url = self._normalize_whids_manager_url(manager_url, verify_tls=verify_tls)
        headers = {"X-Api-Key": api_key.strip()}
        session = requests.Session()
        session.headers.update(headers)
        session.verify = verify_tls
        return session, base_url

    def _normalize_whids_manager_url(self, manager_url: str, *, verify_tls: bool) -> str:
        normalized = normalize_outbound_url(manager_url)
        if not normalized:
            raise ValueError("WHIDS manager URL must be a safe http(s) destination")
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").strip().lower()
        if not verify_tls and hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("TLS verification may only be disabled for loopback WHIDS managers")
        return normalized.rstrip("/") + "/"

    def _load_existing_ossec_incident_ids(self, workspace_id: str = "default") -> set[str]:
        conn = self.db.create_connection()
        if conn is None:
            return set()
        try:
            incidents = self.db.get_incidents(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        return {str(item.get("incident_id", "")) for item in incidents if str(item.get("incident_id", "")).startswith("OSSEC-")}

    def _normalized_incident_ids(self, records: list[dict[str, Any]], normalizer) -> set[str]:
        incident_ids: set[str] = set()
        for record in records:
            normalized = normalizer(record)
            if normalized:
                incident_ids.add(str(normalized["incident"]["incident_id"]))
        return incident_ids

    def _ossec_live_worker(self, file_path: str, interval: float, limit: int, seen_ids: set[str], workspace_id: str) -> None:
        path = Path(file_path)
        while not self._ossec_live_stop.wait(interval):
            try:
                records = self._load_ossec_records(path, limit=limit)
                imported_now = 0
                conn = self.db.create_connection()
                if conn is None:
                    raise RuntimeError("Database unavailable")
                try:
                    for record in records:
                        normalized = self._normalize_ossec_record(record)
                        if not normalized:
                            continue
                        if self._store_normalized_incident(
                            conn,
                            normalized,
                            integration_name="ossec",
                            source_target=file_path,
                            seen_ids=seen_ids,
                            workspace_id=workspace_id,
                        ):
                            imported_now += 1
                finally:
                    conn.close()
                with self._ossec_live_lock:
                    self._ossec_live_state["last_run_at"] = time.time()
                    self._ossec_live_state["seen_count"] = len(seen_ids)
                    if imported_now:
                        self._ossec_live_state["last_imported_at"] = time.time()
                        self._ossec_live_state["total_imported"] = int(self._ossec_live_state.get("total_imported", 0)) + imported_now
                        self._ossec_live_state["last_error"] = ""
                        self._log_export(
                            integration_name="ossec",
                            export_type="live_ingest",
                            target=file_path,
                            status="success",
                            detail=f"Imported {imported_now} new OSSEC alerts from live ingest",
                            workspace_id=workspace_id,
                        )
            except Exception as exc:
                with self._ossec_live_lock:
                    self._ossec_live_state["last_run_at"] = time.time()
                    self._ossec_live_state["last_error"] = str(exc)
        with self._ossec_live_lock:
            self._ossec_live_state["running"] = False

    def _whids_scheduler_worker(
        self,
        manager_url: str,
        api_key: str,
        endpoint_uuid: str,
        interval: float,
        verify_tls: bool,
        workspace_id: str,
    ) -> None:
        while not self.whids_scheduler_stop.wait(interval):
            try:
                self.import_whids_manager(
                    manager_url,
                    api_key,
                    limit=200,
                    endpoint_uuid=endpoint_uuid,
                    verify_tls=verify_tls,
                    workspace_id=workspace_id,
                )
                self.sync_whids_reports(manager_url, api_key, endpoint_uuid=endpoint_uuid, verify_tls=verify_tls)
                self.whids_scheduler_state["last_run_at"] = time.time()
                self.whids_scheduler_state["last_error"] = ""
                self.whids_scheduler_state["total_cycles"] = int(self.whids_scheduler_state.get("total_cycles", 0)) + 1
            except Exception as exc:
                self.whids_scheduler_state["last_run_at"] = time.time()
                self.whids_scheduler_state["last_error"] = str(exc)
        self.whids_scheduler_state["running"] = False

    def _correlate_enterprise_incident(
        self,
        normalized: dict[str, Any],
        *,
        integration_name: str,
        source_target: str,
        workspace_id: str = "default",
    ) -> None:
        if self.enterprise_service is None or self.investigation_service is None:
            return
        incident = normalized.get("incident", {})
        host = normalized.get("host", {})
        incident_id = str(incident.get("incident_id", "")).strip()
        if not incident_id:
            return
        conn = self.db.create_connection()
        if conn is None:
            return
        try:
            case_rows = self.db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        existing_case = next((item for item in case_rows if str(item.get("incident_id", "")).strip() == incident_id), None)
        severity = str(incident.get("severity", "medium")).lower()
        if existing_case:
            case_id = int(existing_case.get("id", 0) or 0)
        else:
            case = self.enterprise_service.create_case(
                title=str(incident.get("title", f"{integration_name.upper()} incident")),
                incident_id=incident_id,
                owner="hids-auto",
                priority=self._case_priority_from_severity(severity),
                stage="triage",
                asset_criticality=self._asset_criticality_from_severity(severity),
                tags=[integration_name, "auto-ingested", str(host.get("host", ""))],
                narrative=str(incident.get("summary", "")),
                workspace_id=workspace_id,
            )
            case_id = int(case.get("id", 0) or 0)
        if not case_id:
            return
        payload = {
            "integration": integration_name,
            "host": host,
            "incident": incident,
            "source_target": source_target,
        }
        self.investigation_service.create_pin(
            case_id=case_id,
            item_time=float(incident.get("created_at", time.time()) or time.time()),
            item_type=f"{integration_name}_incident",
            item_title=str(incident.get("title", incident_id)),
            item_severity=severity,
            item_payload=payload,
            rationale=f"Auto-correlated from {integration_name.upper()} ingest.",
            pinned_by="hids-auto",
            workspace_id=workspace_id,
        )
        self.investigation_service.create_note(
            case_id=case_id,
            item_time=float(incident.get("created_at", time.time()) or time.time()),
            item_type=f"{integration_name}_incident",
            item_title=str(incident.get("title", incident_id)),
            note_text=f"Imported from {integration_name.upper()} source {source_target}.",
            tags=[integration_name, severity, "auto-ingested"],
            author="hids-auto",
            workspace_id=workspace_id,
        )
        if source_target and Path(source_target).exists():
            self.enterprise_service.add_chain_of_custody_event(
                case_id,
                f"{integration_name}_source_ingested",
                actor="hids-auto",
                artifact_path=source_target,
                notes=f"Source ingested for incident {incident_id}",
                workspace_id=workspace_id,
            )

    def _provider_from_incident(self, incident: dict[str, Any]) -> str:
        incident_key = str(incident.get("incident_id", "")).upper()
        if incident_key.startswith("WHIDS-"):
            return "whids"
        if incident_key.startswith("OSSEC-"):
            return "ossec"
        notes = self._json_loads_safe(str(incident.get("notes", "")))
        provider = str(notes.get("provider", "")).strip().lower()
        return provider or "unknown"

    def _incident_context(self, incident: dict[str, Any], provider: str) -> dict[str, Any]:
        notes = self._json_loads_safe(str(incident.get("notes", "")))
        context = {
            "provider": provider,
            "severity": str(incident.get("severity", "")),
            "title": str(incident.get("title", "")),
            "summary": str(incident.get("summary", "")),
            "notes": notes,
            "mitre_mapping": self._json_list(str(incident.get("mitre_mapping", ""))),
            "attack_chain": self._json_list(str(incident.get("attack_chain", ""))),
            "file_path": "",
            "src_ip": "",
            "process_name": "",
            "pid": None,
        }
        if provider == "whids":
            file_path = str(notes.get("source_image", "") or notes.get("target_image", "") or "")
            context["file_path"] = file_path
            context["process_name"] = Path(file_path).name if file_path else ""
            pid = self._find_pid_by_path_or_name(file_path, context["process_name"])
            context["pid"] = pid
        elif provider == "ossec":
            file_path = str(notes.get("file", "") or "")
            context["file_path"] = file_path
            context["src_ip"] = str(notes.get("src_ip", "") or "")
            context["process_name"] = Path(file_path).name if file_path else ""
            context["pid"] = self._find_pid_by_path_or_name(file_path, context["process_name"]) if file_path else None
        if self.mitre_service is not None:
            try:
                coverage = self.mitre_service.incident_coverage(
                    str(incident.get("incident_id", "") or ""),
                    workspace_id=str(incident.get("workspace_id", "default") or "default"),
                )
                context["mitre_mapping"] = coverage.get("mapped_techniques", context["mitre_mapping"])
                context["mitre_inferred"] = coverage.get("inferred_techniques", [])
                context["telemetry_cues"] = coverage.get("telemetry_cues", [])
            except Exception:
                context.setdefault("mitre_inferred", [])
                context.setdefault("telemetry_cues", [])
        return context

    def _build_response_plan(self, provider: str, incident: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        severity = str(incident.get("severity", "medium")).lower()
        notes = context.get("notes", {}) if isinstance(context.get("notes"), dict) else {}
        plan: list[dict[str, Any]] = []
        if provider == "whids":
            raw_detection = notes.get("raw_detection", {}) if isinstance(notes.get("raw_detection"), dict) else {}
            provider_actions = raw_detection.get("Actions", []) if isinstance(raw_detection.get("Actions"), list) else []
            for action in provider_actions:
                token = str(action).strip().lower()
                if token == "kill":
                    plan.append(self._action_spec("kill_process", "Kill matching suspicious process", supported=context.get("pid") is not None))
                elif token == "memdump":
                    plan.append(self._action_spec("collect_artifact", "Collect source artifact copy", supported=bool(context.get("file_path"))))
                elif token == "report":
                    plan.append(self._action_spec("case_note", "Record response note in enterprise case", supported=True))
            if context.get("file_path"):
                plan.append(self._action_spec("quarantine_file", "Copy source executable to quarantine", supported=True))
        elif provider == "ossec":
            file_path = str(context.get("file_path", "") or "")
            src_ip = str(context.get("src_ip", "") or "")
            if file_path:
                plan.append(self._action_spec("quarantine_file", "Quarantine modified or suspicious file copy", supported=True))
                plan.append(self._action_spec("collect_artifact", "Collect monitored file as evidence", supported=True))
            if src_ip:
                plan.append(self._action_spec("ossec_firewall_drop", "Execute OSSEC firewall-drop active response", supported=self.response_service is not None, details={"src_ip": src_ip}))
                plan.append(self._action_spec("ossec_route_null", "Execute OSSEC route-null active response", supported=self.response_service is not None, details={"src_ip": src_ip}))
                host_deny_supported = self.response_service is not None and (self.response_service._ossec_script_for_action("host-deny") is not None)
                plan.append(self._action_spec("ossec_host_deny", "Execute OSSEC host-deny active response", supported=host_deny_supported, details={"src_ip": src_ip}))
        if severity in {"high", "critical"} and context.get("pid") is not None:
            plan.append(self._action_spec("kill_process", "Kill running process tied to incident", supported=True))
        for action_id in self._technique_priority_actions(provider, context):
            if any(str(item.get("action", "")) == action_id for item in plan):
                continue
            supported = action_id not in {"kill_process"} or context.get("pid") is not None
            if action_id == "quarantine_file":
                supported = bool(context.get("file_path"))
            elif action_id in {"ossec_firewall_drop", "ossec_route_null", "ossec_host_deny"}:
                supported = bool(context.get("src_ip")) and self.response_service is not None
            elif action_id == "collect_artifact":
                supported = bool(context.get("file_path"))
            plan.insert(0, self._action_spec(action_id, f"Technique-aware action for {', '.join(context.get('mitre_mapping', [])[:2])}", supported=supported))
        if not plan:
            plan.append(self._action_spec("case_note", "No direct endpoint action available; add analyst response note", supported=True))
        return plan

    def _action_spec(self, action_id: str, description: str, *, supported: bool, details: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"action": action_id, "description": description, "supported": supported, "details": details or {}}

    def _execute_orchestration_action(self, incident_id: str, action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        action_id = str(action.get("action", ""))
        result: dict[str, Any]
        if action_id == "quarantine_file":
            result = self._quarantine_path(context)
        elif action_id == "collect_artifact":
            result = self._collect_artifact_copy(incident_id, context)
        elif action_id == "kill_process":
            result = self._kill_context_process(context)
        elif action_id == "ossec_firewall_drop":
            result = self._execute_ossec_native("firewall-drop", context)
        elif action_id == "ossec_route_null":
            result = self._execute_ossec_native("route-null", context)
        elif action_id == "ossec_host_deny":
            result = self._execute_ossec_native("host-deny", context)
        else:
            result = {"ok": True, "message": f"Recorded orchestration action {action_id}"}
        if action_id == "case_note":
            result = {"ok": True, "message": "Enterprise response note recorded"}
        result["action"] = action_id
        result["status"] = "applied" if result.get("ok") else "failed"
        return result

    def _quarantine_path(self, context: dict[str, Any]) -> dict[str, Any]:
        path = str(context.get("file_path", "") or "")
        process_name = str(context.get("process_name", "") or Path(path).name)
        pid = int(context.get("pid") or -1)
        if self.response_service is not None:
            return self.response_service.quarantine_file(pid, process_name or "artifact", path)
        if not path or not Path(path).exists():
            return {"ok": False, "message": "File path unavailable for quarantine"}
        quarantine_dir = self.base_dir / "shadowlab_quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        src = Path(path)
        dest = quarantine_dir / src.name
        dest.write_bytes(src.read_bytes())
        return {"ok": True, "message": f"Quarantined copy created at {dest}", "path": str(dest)}

    def _collect_artifact_copy(self, incident_id: str, context: dict[str, Any]) -> dict[str, Any]:
        path = str(context.get("file_path", "") or "")
        if not path or not Path(path).exists():
            return {"ok": False, "message": "No local file available for artifact collection"}
        src = Path(path)
        dest_dir = self.orchestration_dir / self._slugify(incident_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        dest.write_bytes(src.read_bytes())
        return {"ok": True, "message": f"Collected artifact copy at {dest}", "path": str(dest)}

    def _kill_context_process(self, context: dict[str, Any]) -> dict[str, Any]:
        pid = context.get("pid")
        process_name = str(context.get("process_name", "") or "process")
        if pid is None:
            return {"ok": False, "message": "No matching process found for incident"}
        if self.response_service is not None:
            return self.response_service.kill(int(pid), process_name)
        try:
            proc = psutil.Process(int(pid))
            proc.kill()
            return {"ok": True, "message": f"Killed PID {pid}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def _find_pid_by_path_or_name(self, file_path: str, process_name: str) -> int | None:
        wanted_path = str(Path(file_path)) if file_path else ""
        wanted_name = process_name.lower().strip()
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = str(proc.info.get("exe") or "")
                name = str(proc.info.get("name") or "").lower()
                if wanted_path and exe and os.path.normcase(exe) == os.path.normcase(wanted_path):
                    return int(proc.info["pid"])
                if wanted_name and name == wanted_name:
                    return int(proc.info["pid"])
            except Exception:
                continue
        return None

    def _execute_ossec_native(self, action_name: str, context: dict[str, Any]) -> dict[str, Any]:
        if self.response_service is None:
            return {"ok": False, "message": f"Response service unavailable for {action_name}"}
        subject = str(context.get("src_ip", "") or "")
        if not subject:
            return {"ok": False, "message": f"No src_ip available for {action_name}"}
        return self.response_service.execute_ossec_active_response(action_name.replace("ossec_", "").replace("_", "-"), subject)

    def _auto_respond_if_needed(self, incident_id: str, normalized: dict[str, Any], *, integration_name: str) -> None:
        policy = self.get_response_policy()
        provider_policy = policy.get("providers", {}).get(integration_name, {}) if isinstance(policy.get("providers"), dict) else {}
        if not provider_policy or not provider_policy.get("enabled", False):
            return
        severity = str((normalized.get("incident", {}) or {}).get("severity", "")).lower()
        severity_actions = provider_policy.get("severity_actions", {}).get(severity, {})
        actions: list[str] = []
        if isinstance(severity_actions, dict) and severity_actions.get("auto_apply", False):
            actions.extend(str(item).strip() for item in severity_actions.get("actions", []) if str(item).strip())
        incident_context = normalized.get("incident", {}) if isinstance(normalized.get("incident"), dict) else {}
        actions.extend(self._policy_actions_for_techniques(provider_policy, incident_context.get("mitre_mapping", "")))
        actions = list(dict.fromkeys(item for item in actions if item))
        if not actions:
            return
        self.orchestrate_incident_response(
            incident_id,
            apply_actions=True,
            allowed_actions=actions,
            source="policy",
            workspace_id=str(incident_context.get("workspace_id", "default") or "default"),
        )

    def _policy_actions_for_techniques(self, provider_policy: dict[str, Any], mitre_mapping: Any) -> list[str]:
        mappings = self._json_list(mitre_mapping) if isinstance(mitre_mapping, str) else [str(item).strip() for item in mitre_mapping or [] if str(item).strip()]
        technique_policy = provider_policy.get("technique_actions", {}) if isinstance(provider_policy.get("technique_actions"), dict) else {}
        actions: list[str] = []
        for technique_id in mappings:
            rule = technique_policy.get(technique_id, {})
            if not isinstance(rule, dict) or not rule.get("auto_apply", False):
                continue
            actions.extend(str(item).strip() for item in rule.get("actions", []) if str(item).strip())
        return list(dict.fromkeys(actions))

    def _technique_priority_actions(self, provider: str, context: dict[str, Any]) -> list[str]:
        policy = self.get_response_policy()
        provider_policy = policy.get("providers", {}).get(provider, {}) if isinstance(policy.get("providers"), dict) else {}
        return self._policy_actions_for_techniques(provider_policy, context.get("mitre_mapping", []))

    def _default_policy(self) -> dict[str, Any]:
        return {
            "providers": {
                "whids": {
                    "enabled": True,
                    "severity_actions": {
                        "critical": {"auto_apply": True, "actions": ["quarantine_file", "collect_artifact", "kill_process"]},
                        "high": {"auto_apply": True, "actions": ["quarantine_file", "collect_artifact"]},
                        "medium": {"auto_apply": False, "actions": ["collect_artifact"]},
                    },
                    "technique_actions": {
                        "T1059": {"auto_apply": True, "actions": ["kill_process", "quarantine_file"]},
                        "T1105": {"auto_apply": True, "actions": ["quarantine_file", "collect_artifact"]},
                        "T1003": {"auto_apply": True, "actions": ["kill_process", "collect_artifact"]},
                    },
                },
                "ossec": {
                    "enabled": True,
                    "severity_actions": {
                        "critical": {"auto_apply": True, "actions": ["quarantine_file", "collect_artifact", "ossec_firewall_drop", "ossec_route_null"]},
                        "high": {"auto_apply": True, "actions": ["quarantine_file", "collect_artifact", "ossec_firewall_drop"]},
                        "medium": {"auto_apply": False, "actions": ["collect_artifact"]},
                    },
                    "technique_actions": {
                        "T1021": {"auto_apply": True, "actions": ["ossec_firewall_drop", "ossec_route_null"]},
                        "T1071": {"auto_apply": True, "actions": ["ossec_firewall_drop", "collect_artifact"]},
                        "T1547": {"auto_apply": True, "actions": ["quarantine_file", "collect_artifact"]},
                    },
                },
            }
        }

    def _write_default_policy_if_missing(self) -> None:
        if self.policy_path.exists():
            return
        self.policy_path.write_text(json.dumps(self._default_policy(), indent=2, ensure_ascii=False), encoding="utf-8")

    def _deep_merge(self, base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for key, value in patch.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = self._deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _load_runtime_state(self) -> dict[str, Any]:
        if not self.runtime_path.exists():
            return {}
        try:
            loaded = json.loads(self.runtime_path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}

    def _save_runtime_state(self, patch: dict[str, Any]) -> dict[str, Any]:
        current = self._load_runtime_state()
        merged = self._deep_merge(current, patch)
        self.runtime_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
        return merged

    def _restore_runtime_if_enabled(self) -> None:
        restore_enabled = os.environ.get("SHADOWLAB_RESTORE_INTEGRATION_RUNTIME", "true").strip().lower() in {"1", "true", "yes", "on"}
        if not restore_enabled:
            return
        runtime = self._load_runtime_state()
        whids = runtime.get("whids_scheduler", {}) if isinstance(runtime.get("whids_scheduler"), dict) else {}
        ossec = runtime.get("ossec_live", {}) if isinstance(runtime.get("ossec_live"), dict) else {}
        try:
            if whids.get("enabled") and whids.get("manager_url") and whids.get("api_key"):
                runtime_api_key = str(whids.get("api_key", ""))
                if is_encrypted_secret(runtime_api_key):
                    runtime_api_key = secret_store.decrypt_text(runtime_api_key)
                self.start_whids_scheduler(
                    str(whids.get("manager_url", "")),
                    runtime_api_key,
                    endpoint_uuid=str(whids.get("endpoint_uuid", "")),
                    poll_interval=float(whids.get("poll_interval", 300.0) or 300.0),
                    verify_tls=bool(whids.get("verify_tls", True)),
                    workspace_id=str(whids.get("workspace_id", "default") or "default"),
                )
        except Exception as exc:
            self.whids_scheduler_state["last_error"] = f"restore_failed: {exc}"
        try:
            if ossec.get("enabled") and ossec.get("file_path"):
                file_path = str(ossec.get("file_path", ""))
                if Path(file_path).exists():
                    self.start_ossec_live_ingest(
                        file_path,
                        poll_interval=float(ossec.get("poll_interval", 2.0) or 2.0),
                        limit=int(ossec.get("limit", 200) or 200),
                        start_at_end=bool(ossec.get("start_at_end", True)),
                        workspace_id=str(ossec.get("workspace_id", "default") or "default"),
                    )
        except Exception as exc:
            self._ossec_live_state["last_error"] = f"restore_failed: {exc}"

    def _json_loads_safe(self, value: str) -> dict[str, Any]:
        try:
            loaded = json.loads(value)
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}

    def _json_list(self, value: str) -> list[str]:
        try:
            loaded = json.loads(value)
            return [str(item).strip() for item in loaded if str(item).strip()] if isinstance(loaded, list) else []
        except Exception:
            return []

    def _safe_json(self, response: requests.Response) -> dict[str, Any]:
        try:
            payload = response.json()
            return payload if isinstance(payload, dict) else {}
        except ValueError:
            return {}

    def _slugify(self, value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
        return cleaned.strip("-._") or "item"

    def _safe_filename(self, value: str) -> str:
        candidate = Path(value).name
        return self._slugify(candidate)

    def _case_priority_from_severity(self, severity: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
        return mapping.get(severity.lower(), "medium")

    def _asset_criticality_from_severity(self, severity: str) -> float:
        mapping = {"critical": 95.0, "high": 80.0, "medium": 60.0, "low": 35.0, "info": 20.0}
        return mapping.get(severity.lower(), 50.0)

    def _load_json_records(self, path: Path, limit: int) -> list[dict[str, Any]]:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Integration source not found: {path}")
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return []
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError:
            loaded = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    loaded.append(item)
        if isinstance(loaded, dict):
            for key in ("alerts", "events", "items", "data"):
                value = loaded.get(key)
                if isinstance(value, list):
                    loaded = value
                    break
            else:
                loaded = [loaded]
        if not isinstance(loaded, list):
            return []
        return [item for item in loaded[:limit] if isinstance(item, dict)]

    def _load_ossec_records(self, path: Path, limit: int) -> list[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix in {".json", ".jsonl", ".ndjson"}:
            return self._load_json_records(path, limit=limit)
        return self._parse_ossec_alert_log(path, limit=limit)

    def _parse_ossec_alert_log(self, path: Path, limit: int) -> list[dict[str, Any]]:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Integration source not found: {path}")
        content = path.read_text(encoding="utf-8", errors="replace")
        blocks: list[list[str]] = []
        current: list[str] = []
        for raw_line in content.splitlines():
            line = raw_line.rstrip()
            if line.startswith("** Alert"):
                if current:
                    blocks.append(current)
                current = [line]
                continue
            if current:
                current.append(line)
        if current:
            blocks.append(current)

        records: list[dict[str, Any]] = []
        for block in blocks[:limit]:
            joined = "\n".join(block)
            meta_line = block[1] if len(block) > 1 else ""
            rule_line = next((line for line in block if "Rule:" in line), "")
            location_line = next((line for line in block if line.strip().startswith("Location:")), "")
            src_line = next((line for line in block if "Src IP:" in line), "")
            host = ""
            component = ""
            if "(" in meta_line and ")" in meta_line:
                host = meta_line.split("(", 1)[1].split(")", 1)[0].strip()
            if "->" in meta_line:
                component = meta_line.split("->", 1)[1].strip()
            rule_id = ""
            level = 0
            description = ""
            if rule_line:
                try:
                    prefix, description = rule_line.split("->", 1)
                    description = description.strip().strip("'\"")
                except ValueError:
                    prefix = rule_line
                if "(" in prefix and ")" in prefix:
                    level_token = prefix.split("(level", 1)[-1].split(")", 1)[0].strip()
                    if level_token.isdigit():
                        level = int(level_token)
                if "Rule:" in prefix:
                    rule_id = prefix.split("Rule:", 1)[-1].split("(", 1)[0].strip()
            location = location_line.split("Location:", 1)[-1].strip() if location_line else ""
            src_ip = src_line.split("Src IP:", 1)[-1].strip() if src_line else ""
            message_lines = [
                line for line in block[2:]
                if line and "Rule:" not in line and not line.strip().startswith("Location:") and "Src IP:" not in line
            ]
            records.append(
                {
                    "alert_id": self._stable_id(joined),
                    "hostname": host,
                    "component": component,
                    "rule_id": rule_id,
                    "level": level,
                    "description": description or "OSSEC alert imported from text log",
                    "location": location,
                    "src_ip": src_ip,
                    "message": "\n".join(message_lines).strip(),
                    "full_log": joined,
                }
            )
        return records

    def _normalize_whids_record(self, record: dict[str, Any]) -> dict[str, Any] | None:
        if not record:
            return None
        # WHIDS manager endpoints wrap payloads under {"data": [...]} or provide direct event objects.
        if isinstance(record.get("Event"), list):
            return None
        edr_data = record.get("EdrData", {}) if isinstance(record.get("EdrData"), dict) else {}
        endpoint = edr_data.get("Endpoint", {}) if isinstance(edr_data.get("Endpoint"), dict) else {}
        detection = record.get("Detection", {}) if isinstance(record.get("Detection"), dict) else {}
        event = record.get("Event", {}) if isinstance(record.get("Event"), dict) else {}
        system = event.get("System", {}) if isinstance(event.get("System"), dict) else {}
        event_data = event.get("EventData", {}) if isinstance(event.get("EventData"), dict) else {}
        endpoint_candidates = record.get("Endpoint", {}) if isinstance(record.get("Endpoint"), dict) else {}
        if endpoint_candidates and not endpoint:
            endpoint = endpoint_candidates

        signatures = detection.get("Signature", [])
        signature_list = [str(item) for item in signatures if str(item).strip()] if isinstance(signatures, list) else []
        actions = detection.get("Actions", []) if isinstance(detection.get("Actions"), list) else []
        if not endpoint and not signature_list and not event_data:
            return None

        hostname = str(endpoint.get("Hostname") or endpoint.get("hostname") or system.get("Computer") or "unknown-host")
        host_id = str(endpoint.get("UUID") or endpoint.get("uuid") or hostname)
        ip_address = str(endpoint.get("IP") or endpoint.get("ip") or "")
        system_info = endpoint.get("system-info", {}) if isinstance(endpoint.get("system-info"), dict) else {}
        os_info = system_info.get("os", {}) if isinstance(system_info.get("os"), dict) else {}
        edr_info = system_info.get("edr", {}) if isinstance(system_info.get("edr"), dict) else {}
        receipt_time = str((edr_data.get("Event") or {}).get("ReceiptTime") or system.get("TimeCreated", {}).get("SystemTime", ""))
        created_at = self._coerce_timestamp(receipt_time) or time.time()
        event_hash = str((edr_data.get("Event") or {}).get("Hash") or self._stable_id(json.dumps(record, sort_keys=True)))
        incident_id = f"WHIDS-{event_hash[:24].upper()}"
        criticality = int(detection.get("Criticality") or endpoint.get("criticality") or 0)
        score = endpoint.get("score")
        source_image = str(event_data.get("SourceImage", ""))
        target_image = str(event_data.get("TargetImage", ""))
        event_id = str(system.get("EventID", "unknown"))
        title = ", ".join(signature_list[:3]) or f"WHIDS detection on {hostname}"
        summary_bits = [f"WHIDS detected suspicious activity on {hostname}"]
        summary_bits.append(f"event_id={event_id}")
        if criticality:
            summary_bits.append(f"criticality={criticality}")
        if score not in {None, ""}:
            summary_bits.append(f"score={score}")
        if source_image:
            summary_bits.append(f"source={Path(source_image).name}")
        if target_image:
            summary_bits.append(f"target={Path(target_image).name}")
        summary = " (" + ", ".join(summary_bits[1:]) + ")" if len(summary_bits) > 1 else ""
        notes = json.dumps(
            {
                "provider": "WHIDS",
                "host": hostname,
                "endpoint_uuid": host_id,
                "source_image": source_image,
                "target_image": target_image,
                "source_hashes": event_data.get("SourceHashes", ""),
                "target_hashes": event_data.get("TargetHashes", ""),
                "source_user": event_data.get("SourceUser", ""),
                "raw_signatures": signature_list,
                "raw_detection": detection,
            }
        )
        mitre_mapping = []
        for item in signature_list:
            if ":" in item and item.split(":", 1)[0].strip().upper().startswith("T"):
                mitre_mapping.append(item.split(":", 1)[0].strip())
        platform_name = "Windows (WHIDS)"
        if os_info:
            platform_name = f"{os_info.get('product', 'Windows')} (WHIDS)"
        agent_version = str(edr_info.get("version") or "whids")
        return {
            "host": {
                "host_id": host_id,
                "host": hostname,
                "platform": platform_name,
                "role": "whids-agent",
                "ip_address": ip_address,
                "api_status": "imported",
                "agent_version": agent_version,
                "boot_time": created_at,
                "last_seen": time.time(),
            },
            "incident": {
                "incident_id": incident_id,
                "created_at": created_at,
                "severity": self._severity_from_score(criticality, scale="whids"),
                "title": title[:200],
                "summary": f"{summary_bits[0]}{summary}"[:500],
                "status": "open",
                "notes": notes[:4000],
                "owner": "",
                "recommended_actions": json.dumps([str(item) for item in actions[:10]]),
                "attack_chain": json.dumps(self._deduce_attack_chain(signature_list, source_image, target_image)),
                "mitre_mapping": json.dumps(sorted(set(mitre_mapping))),
                "correlation_story": f"Imported from WHIDS endpoint {host_id} via event hash {event_hash[:12]}.",
            },
        }

    def _normalize_ossec_record(self, record: dict[str, Any]) -> dict[str, Any] | None:
        if not record:
            return None
        host = str(
            record.get("hostname")
            or (record.get("agent", {}) or {}).get("name", "")
            or record.get("location")
            or record.get("component")
            or "unknown-host"
        )
        if host.startswith("(") and ")" in host:
            host = host.split(")", 1)[-1].strip() or host

        level = self._safe_int(record.get("level") or record.get("crit")) or 0
        rule_id = str(record.get("rule_id") or record.get("id") or record.get("rule") or "")
        description = str(record.get("description") or record.get("comment") or "OSSEC alert")
        full_log = str(record.get("full_log") or record.get("message") or "")
        src_ip = str(record.get("src_ip") or "")
        dst_ip = str(record.get("dst_ip") or "")
        file_path = str(record.get("file") or record.get("location") or "")
        component = str(record.get("component") or "")
        classification = str(record.get("classification") or "")
        incident_seed = str(record.get("alert_id") or self._stable_id(json.dumps(record, sort_keys=True)))
        incident_id = f"OSSEC-{incident_seed[:24].upper()}"
        created_at = self._coerce_timestamp(str(record.get("timestamp") or "")) or time.time()
        title = self._ossec_title(rule_id, description, component, classification, file_path, full_log)
        if file_path:
            title = f"{title}: {Path(file_path).name}"
        summary = self._ossec_summary(description, component, classification, src_ip, dst_ip, file_path, full_log)
        notes = json.dumps(
            {
                "provider": "OSSEC",
                "rule_id": rule_id,
                "component": component,
                "classification": classification,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "file": file_path,
                "sha1_old": record.get("sha1_old", ""),
                "sha1_new": record.get("sha1_new", ""),
                "md5_old": record.get("md5_old", ""),
                "md5_new": record.get("md5_new", ""),
                "full_log": full_log[:2000],
            }
        )
        attack_chain = self._deduce_ossec_attack_chain(record)
        return {
            "host": {
                "host_id": host,
                "host": host,
                "platform": "OSSEC",
                "role": "ossec-agent",
                "ip_address": src_ip if self._looks_like_ip(src_ip) else "",
                "api_status": "imported",
                "agent_version": "ossec",
                "boot_time": created_at,
                "last_seen": time.time(),
            },
            "incident": {
                "incident_id": incident_id,
                "created_at": created_at,
                "severity": self._severity_from_score(level, scale="ossec"),
                "title": title[:200],
                "summary": summary[:500],
                "status": "open",
                "notes": notes[:4000],
                "owner": "",
                "recommended_actions": json.dumps(
                    [
                        "Review original OSSEC alert context and correlated logs.",
                        "Validate impacted asset or file path.",
                        "Confirm whether active response should be triggered in ShadowLab.",
                    ]
                ),
                "attack_chain": json.dumps(attack_chain),
                "mitre_mapping": json.dumps([]),
                "correlation_story": f"Imported from OSSEC alert stream for host {host}.",
            },
        }

    def _ossec_title(self, rule_id: str, description: str, component: str, classification: str, file_path: str, full_log: str) -> str:
        lower_component = component.lower()
        lower_class = classification.lower()
        lower_desc = description.lower()
        lower_log = full_log.lower()
        if "rootcheck" in lower_component or "rootcheck" in lower_class or "rootkit" in lower_desc:
            return f"OSSEC rootcheck {rule_id or 'alert'}"
        if "syscheck" in lower_component or "syscheck" in lower_class or "checksum" in lower_desc or file_path:
            return f"OSSEC syscheck {rule_id or 'alert'}"
        if "firewall" in lower_component or "firewall" in lower_desc or "firewall" in lower_log:
            return f"OSSEC firewall {rule_id or 'event'}"
        if "ids" in lower_component or "ids" in lower_class or "snort" in lower_log:
            return f"OSSEC ids {rule_id or 'event'}"
        if "windows" in lower_component or "windows" in lower_class or "win_" in lower_class:
            return f"OSSEC windows {rule_id or 'event'}"
        return f"OSSEC rule {rule_id or 'unknown'}"

    def _ossec_summary(
        self,
        description: str,
        component: str,
        classification: str,
        src_ip: str,
        dst_ip: str,
        file_path: str,
        full_log: str,
    ) -> str:
        parts = [f"OSSEC detected {description or 'alert activity'}"]
        if component:
            parts.append(f"component={component}")
        if classification:
            parts.append(f"classification={classification}")
        if file_path:
            parts.append(f"file={file_path}")
        if src_ip:
            parts.append(f"src_ip={src_ip}")
        if dst_ip:
            parts.append(f"dst_ip={dst_ip}")
        if not file_path and full_log:
            snippet = full_log.replace("\n", " ").strip()
            if snippet:
                parts.append(f"log={snippet[:160]}")
        return " | ".join(parts)

    def _deduce_attack_chain(self, signatures: list[str], source_image: str, target_image: str) -> list[str]:
        chain = ["Detection"]
        joined = " ".join(signatures).lower()
        if "lsass" in joined or "lsass" in source_image.lower() or "lsass" in target_image.lower():
            chain.insert(0, "Credential Access")
        if "powershell" in joined or "cmd" in joined:
            chain.insert(0, "Execution")
        if "remote" in joined or "inject" in joined:
            chain.append("Defense Evasion")
        deduped: list[str] = []
        for item in chain:
            if item not in deduped:
                deduped.append(item)
        return deduped

    def _deduce_ossec_attack_chain(self, record: dict[str, Any]) -> list[str]:
        chain = ["Detection"]
        lowered = json.dumps(record).lower()
        if any(token in lowered for token in ["syscheck", "checksum", "file", "sha1_new", "md5_new"]):
            chain.insert(0, "Persistence")
        if any(token in lowered for token in ["rootcheck", "rootkit"]):
            chain.insert(0, "Defense Evasion")
        if any(token in lowered for token in ["src_ip", "dst_ip", "firewall", "ssh"]):
            chain.append("Lateral Movement")
        deduped: list[str] = []
        for item in chain:
            if item not in deduped:
                deduped.append(item)
        return deduped

    def _severity_from_score(self, value: int, scale: str) -> str:
        if scale == "whids":
            if value >= 8:
                return "critical"
            if value >= 6:
                return "high"
            if value >= 3:
                return "medium"
            return "low"
        if value >= 12:
            return "critical"
        if value >= 8:
            return "high"
        if value >= 4:
            return "medium"
        return "low"

    def _coerce_timestamp(self, value: str) -> float:
        if not value:
            return 0.0
        normalized = value.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            return 0.0

    def _stable_id(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    def _looks_like_ip(self, value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def _safe_int(self, value: Any) -> int | None:
        try:
            if value in {None, ""}:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None
