from __future__ import annotations

import json
import os
import random
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

import database as db
from core.policy_matrix import build_policy_matrix
from core.workspace_context import DEFAULT_WORKSPACE_ID, filter_rows_by_workspace, workspace_matches_row
from services.connector_delivery_service import ConnectorDeliveryService
from services.outbound_security import normalize_outbound_url
from services.secret_store import secret_store


class EnterpriseService:
    def __init__(self, base_dir: Path, process_service, fleet_service):
        self.base_dir = Path(base_dir)
        self.process_service = process_service
        self.fleet_service = fleet_service
        self.policy_profiles = build_policy_matrix()["profiles"]
        self.connector_delivery = ConnectorDeliveryService(timeout=10)

    def get_policy_profiles(self) -> dict[str, Any]:
        active_profile = os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab").strip().lower() or "lab"
        if active_profile not in self.policy_profiles:
            active_profile = "lab"
        matrix = build_policy_matrix()
        matrix["active_profile_hint"] = active_profile
        return matrix

    def assess_asset_criticality(self) -> dict[str, Any]:
        processes = self.process_service.snapshot_processes(include_deep_fields=True)
        critical_tokens = {
            "lsass": 95,
            "wininit": 90,
            "services": 88,
            "svchost": 75,
            "sqlservr": 85,
            "httpd": 65,
            "nginx": 65,
            "python": 40,
        }
        ranked = []
        for proc in processes[:250]:
            name = str(proc.get("name", "") or "").lower()
            score = max(float(proc.get("memory_percent", 0) or 0) * 2.5, float(proc.get("cpu_percent", 0) or 0))
            for token, base_score in critical_tokens.items():
                if token in name:
                    score = max(score, float(base_score))
            if proc.get("signature_status") == "Valid":
                score = max(0.0, score - 5.0)
            ranked.append(
                {
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "asset_type": "process",
                    "criticality_score": min(100.0, round(score, 2)),
                    "rationale": self._criticality_rationale(name, score),
                }
            )
        ranked.sort(key=lambda item: float(item["criticality_score"]), reverse=True)
        host_score = max((float(item["criticality_score"]) for item in ranked[:10]), default=0.0)
        return {
            "host": socket.gethostname(),
            "host_criticality_score": min(100.0, round(host_score, 2)),
            "top_assets": ranked[:30],
        }

    def create_case(
        self,
        *,
        workspace_id: str = DEFAULT_WORKSPACE_ID,
        title: str,
        incident_id: str = "",
        owner: str = "",
        priority: str = "medium",
        stage: str = "triage",
        sla_hours: int = 24,
        asset_criticality: float = 0,
        tags: list[str] | None = None,
        approvers: list[str] | None = None,
        narrative: str = "",
    ) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            if incident_id:
                incidents = db.get_incidents(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
                incident = next((item for item in incidents if str(item.get("incident_id", "")) == incident_id), None)
                if incident is None:
                    raise KeyError(f"Incident `{incident_id}` not found")
                if not workspace_matches_row(incident, workspace_id):
                    raise ValueError("Incident belongs to a different workspace")
            case_id = db.create_case_record(
                conn,
                workspace_id=workspace_id,
                title=title,
                incident_id=incident_id,
                priority=priority,
                stage=stage,
                owner=owner,
                sla_deadline=time.time() + (int(sla_hours) * 3600),
                asset_criticality=float(asset_criticality),
                tags_json=json.dumps(tags or []),
                approvers_json=json.dumps(approvers or []),
                narrative=narrative,
            )
            db.log_evidence_chain(conn, case_id, "case_created", actor=owner, notes="Enterprise case opened")
            frame = db.get_case_records(conn, workspace_id=workspace_id)
            self._seed_case_checklist(conn, case_id, owner=owner or "unassigned", created_by=owner or "system")
            db.log_case_activity(
                conn,
                workspace_id=workspace_id,
                case_id=case_id,
                event_type="case_created",
                actor=owner,
                summary=f"Case '{title}' created",
                detail_json=json.dumps({"priority": priority, "stage": stage}),
            )
            return frame[(frame["id"] == case_id) & (frame["workspace_id"] == workspace_id)].fillna("").to_dict(orient="records")[0]
        finally:
            conn.close()

    def list_cases(self, workspace_id: str = DEFAULT_WORKSPACE_ID) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            return filter_rows_by_workspace(db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
        finally:
            conn.close()

    def add_chain_of_custody_event(self, case_id: int, event_type: str, actor: str, artifact_path: str = "", notes: str = "", workspace_id: str = DEFAULT_WORKSPACE_ID) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            case_rows = filter_rows_by_workspace(db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
            if not any(int(item.get("id", 0) or 0) == case_id for item in case_rows):
                raise KeyError("Case not found")
            artifact_hash = ""
            path = Path(artifact_path)
            if artifact_path and path.exists() and path.is_file():
                artifact_hash = self._sha256(path)
            db.log_evidence_chain(conn, case_id, event_type, actor=actor, artifact_path=artifact_path, artifact_hash=artifact_hash, notes=notes)
            db.log_case_activity(
                conn,
                workspace_id=workspace_id,
                case_id=case_id,
                event_type="chain_of_custody",
                actor=actor,
                summary=f"Chain of custody event recorded: {event_type}",
                detail_json=json.dumps({"artifact_path": artifact_path, "artifact_hash": artifact_hash, "notes": notes}),
            )
            return {"case_id": case_id, "event_type": event_type, "actor": actor, "artifact_hash": artifact_hash, "notes": notes}
        finally:
            conn.close()

    def get_chain_of_custody(self, case_id: int, workspace_id: str = DEFAULT_WORKSPACE_ID) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            case_rows = filter_rows_by_workspace(db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
            if not any(int(item.get("id", 0) or 0) == case_id for item in case_rows):
                return []
            return db.get_evidence_chain(conn, case_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()

    def request_approval(self, case_id: int, action: str, requested_by: str, approver: str, reason: str, workspace_id: str = DEFAULT_WORKSPACE_ID) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            case_rows = filter_rows_by_workspace(db.get_case_records(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
            if not any(int(item.get("id", 0) or 0) == case_id for item in case_rows):
                raise KeyError("Case not found")
            expires_at = time.time() + (8 * 3600)
            approval_id = db.create_approval_request(
                conn,
                case_id,
                action,
                requested_by=requested_by,
                approver=approver,
                reason=reason,
                expires_at=expires_at,
                workspace_id=workspace_id,
            )
            db.log_case_activity(
                conn,
                workspace_id=workspace_id,
                case_id=case_id,
                event_type="approval_requested",
                actor=requested_by,
                summary=f"Approval requested for {action}",
                detail_json=json.dumps({"approver": approver, "reason": reason}),
            )
            return {"approval_id": approval_id, "case_id": case_id, "status": "pending", "action": action, "expires_at": expires_at}
        finally:
            conn.close()

    def resolve_approval(self, approval_id: int, status: str, approver: str, workspace_id: str = DEFAULT_WORKSPACE_ID) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            approvals = db.get_approval_requests(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            approval = next((item for item in approvals if int(item.get("id", 0) or 0) == approval_id), None)
            if approval is None:
                raise KeyError("Approval not found")
            db.resolve_approval_request(conn, approval_id, status, approver)
            if approval:
                db.log_case_activity(
                    conn,
                    workspace_id=workspace_id,
                    case_id=int(approval.get("case_id", 0) or 0),
                    event_type="approval_resolved",
                    actor=approver,
                    summary=f"Approval {status}",
                    detail_json=json.dumps({"approval_id": approval_id, "action": approval.get("action", "")}),
                )
            return {"approval_id": approval_id, "status": status, "approver": approver}
        finally:
            conn.close()

    def _seed_case_checklist(self, conn, case_id: int, *, owner: str, created_by: str) -> None:
        default_tasks = [
            ("Validate triggering evidence", "Review the initial alert, telemetry, or incident summary."),
            ("Confirm process ancestry", "Inspect parent-child relationships and execution context."),
            ("Review network activity", "Check outbound connections, DNS, and suspicious egress."),
            ("Capture analyst narrative", "Document the working hypothesis and next steps."),
        ]
        for title, description in default_tasks:
            db.create_case_task(
                conn,
                case_id=case_id,
                title=title,
                description=description,
                assigned_to=owner,
                created_by=created_by,
            )

    def list_approvals(self, workspace_id: str = DEFAULT_WORKSPACE_ID) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            return db.get_approval_requests(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()

    def detection_lifecycle(self) -> dict[str, Any]:
        rules_path = self.base_dir / "detections" / "default_rules.yaml"
        yaml_rules = []
        try:
            import yaml

            loaded = yaml.safe_load(rules_path.read_text(encoding="utf-8")) if rules_path.exists() else {}
            if isinstance(loaded, dict):
                yaml_rules = loaded.get("rules", []) or []
            elif isinstance(loaded, list):
                yaml_rules = loaded
        except Exception:
            yaml_rules = []
        conn = db.create_connection()
        registry: list[dict[str, Any]] = []
        feedback: list[dict[str, Any]] = []
        if conn:
            try:
                for rule in yaml_rules:
                    rule_id = str(rule.get("id") or rule.get("rule_id") or rule.get("name") or "unnamed-rule")
                    db.upsert_detection_rule(conn, rule_id=rule_id, version=str(rule.get("version", "1.0.0")), notes=str(rule.get("description", "")))
                registry = db.get_detection_rules(conn).fillna("").to_dict(orient="records")
                feedback = db.get_false_positive_feedback(conn).fillna("").to_dict(orient="records")
            finally:
                conn.close()
        return {"rules": registry, "false_positive_feedback": feedback, "suppression_guidance": "Tune and suppress only after case review."}

    def tune_detection_rule(self, rule_id: str, version: str, tuning: dict[str, Any], suppressions: dict[str, Any], notes: str) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            db.upsert_detection_rule(
                conn,
                rule_id=rule_id,
                version=version,
                tuning_json=json.dumps(tuning or {}),
                suppression_json=json.dumps(suppressions or {}),
                notes=notes,
            )
            return {"rule_id": rule_id, "version": version, "status": "updated"}
        finally:
            conn.close()

    def log_false_positive(self, rule_id: str, incident_id: str, actor: str, reason: str) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            db.log_false_positive_feedback(conn, rule_id, incident_id=incident_id, actor=actor, reason=reason)
            return {"rule_id": rule_id, "incident_id": incident_id, "status": "logged"}
        finally:
            conn.close()

    def list_connectors(self, workspace_id: str = DEFAULT_WORKSPACE_ID) -> list[dict[str, Any]]:
        defaults = [
            {"name": "splunk", "kind": "siem", "enabled": False, "config_json": "{}"},
            {"name": "sentinel", "kind": "siem", "enabled": False, "config_json": "{}"},
            {"name": "elastic", "kind": "siem", "enabled": False, "config_json": "{}"},
            {"name": "thehive", "kind": "soar", "enabled": False, "config_json": "{}"},
            {"name": "shuffle", "kind": "soar", "enabled": False, "config_json": "{}"},
        ]
        conn = db.create_connection()
        if conn is None:
            return defaults
        try:
            existing = {
                str(item.get("name", "")).strip().lower()
                for item in filter_rows_by_workspace(db.get_connectors(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
            }
            for item in defaults:
                normalized_name = str(item["name"]).strip().lower()
                if normalized_name not in existing:
                    db.upsert_connector(conn, normalized_name, item["kind"], item["enabled"], item["config_json"], workspace_id=workspace_id)
            rows = filter_rows_by_workspace(db.get_connectors(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
            return [self._serialize_connector(item) for item in rows]
        finally:
            conn.close()

    def configure_connector(self, name: str, kind: str, enabled: bool, config: dict[str, Any], workspace_id: str = DEFAULT_WORKSPACE_ID) -> dict[str, Any]:
        sanitized = self._validate_connector_config(name, config or {})
        normalized_name = str(name or "").strip().lower()
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            protected_config = secret_store.protect_config(sanitized)
            db.upsert_connector(conn, normalized_name, kind, enabled, json.dumps(protected_config), workspace_id=workspace_id)
            return {"name": normalized_name, "kind": kind, "enabled": enabled, "workspace_id": workspace_id, "config": secret_store.redact_config(sanitized)}
        finally:
            conn.close()

    def _validate_connector_config(self, name: str, config: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(config or {})
        connector_name = str(name or "").strip().lower()
        profile = os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab").strip().lower() or "lab"
        url_fields = {
            "splunk": ["hec_url"],
            "elastic": ["endpoint"],
            "thehive": ["url"],
            "shuffle": ["webhook_url"],
        }
        for field_name in url_fields.get(connector_name, []):
            raw_value = normalized.get(field_name, "")
            if raw_value:
                safe_url = normalize_outbound_url(raw_value)
                if not safe_url:
                    raise ValueError(f"{connector_name}.{field_name} must be a safe http(s) destination")
                normalized[field_name] = safe_url
        verify_tls = bool(normalized.get("verify_tls", True))
        if profile in {"corp", "prod"} and not verify_tls:
            raise ValueError("verify_tls=false is not allowed outside the lab profile")
        if connector_name == "sentinel":
            workspace_id = str(normalized.get("workspace_id", "")).strip()
            if not workspace_id:
                raise ValueError("sentinel.workspace_id is required")
            if not re.fullmatch(r"[A-Za-z0-9-]{3,120}", workspace_id):
                raise ValueError("sentinel.workspace_id contains unsupported characters")
        return normalized

    def dispatch_connector_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        source: str = "shadowlab",
        severity: str = "info",
        workspace_id: str = DEFAULT_WORKSPACE_ID,
    ) -> dict[str, Any]:
        event = {
            "event_type": event_type,
            "source": source,
            "severity": severity,
            "host": socket.gethostname(),
            "ts": time.time(),
            "payload": payload,
            "title": payload.get("title") if isinstance(payload, dict) else event_type,
            "workspace_id": workspace_id,
        }
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            connectors = filter_rows_by_workspace(db.get_connectors(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records"), workspace_id)
            enabled = [item for item in connectors if bool(item.get("enabled"))]
            delivered = []
            queued = []
            failed = []
            for item in enabled:
                result = self.connector_delivery.deliver(item, event)
                name = str(item.get("name", "unknown"))
                display_name = self._connector_display_name(name)
                if result.get("ok"):
                    delivered.append({"name": display_name, "status": result.get("status", "ok")})
                    db.log_integration_export(
                        conn,
                        display_name,
                        export_type=event_type,
                        target=display_name,
                        status="delivered",
                        detail=str(result.get("detail", ""))[:500],
                        workspace_id=workspace_id,
                    )
                    continue
                failed.append({"name": display_name, "status": result.get("status", "failed"), "detail": result.get("detail", "")})
                next_retry = time.time() + 30
                queue_id = db.enqueue_connector_delivery(
                    conn,
                    connector_name=name,
                    event_type=event_type,
                    payload_json=json.dumps(event),
                    status="retry",
                    attempts=1,
                    next_retry_at=next_retry,
                    last_error=str(result.get("detail", ""))[:600],
                    workspace_id=workspace_id,
                )
                queued.append({"name": display_name, "queue_id": queue_id})
                db.log_integration_export(
                    conn,
                    display_name,
                    export_type=event_type,
                    target=display_name,
                    status="queued",
                    detail=str(result.get("detail", ""))[:500],
                    workspace_id=workspace_id,
                )
            return {
                "event_type": event_type,
                "enabled_connectors": len(enabled),
                "delivered": delivered,
                "queued": queued,
                "failed": failed,
            }
        finally:
            conn.close()

    def process_connector_queue(self, limit: int = 50, workspace_id: str = "") -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            connector_rows = db.get_connectors(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records") if workspace_id else db.get_connectors(conn).fillna("").to_dict(orient="records")
            if workspace_id:
                connector_rows = filter_rows_by_workspace(connector_rows, workspace_id)
            connectors = {str(item.get("name", "")): item for item in connector_rows}
            pending = db.get_pending_connector_deliveries(conn, now_ts=time.time(), limit=limit, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            processed = []
            for item in pending:
                queue_id = int(item.get("id", 0) or 0)
                connector_name = str(item.get("connector_name", ""))
                attempts = int(item.get("attempts", 0) or 0)
                connector = connectors.get(connector_name)
                if not connector or not bool(connector.get("enabled")):
                    db.update_connector_delivery(conn, queue_id, status="failed", attempts=attempts + 1, last_error="Connector disabled or missing")
                    processed.append({"id": queue_id, "connector": self._connector_display_name(connector_name), "status": "failed"})
                    continue
                try:
                    event = json.loads(str(item.get("payload_json", "{}")))
                except Exception:
                    event = {}
                result = self.connector_delivery.deliver(connector, event)
                if result.get("ok"):
                    db.update_connector_delivery(conn, queue_id, status="delivered", attempts=attempts + 1, last_error="")
                    db.log_integration_export(
                        conn,
                        self._connector_display_name(connector_name),
                        export_type=str(item.get("event_type", "queued_event")),
                        target=self._connector_display_name(connector_name),
                        status="delivered",
                        detail=str(result.get("detail", ""))[:500],
                        workspace_id=str(item.get("workspace_id", workspace_id or DEFAULT_WORKSPACE_ID) or DEFAULT_WORKSPACE_ID),
                    )
                    processed.append({"id": queue_id, "connector": self._connector_display_name(connector_name), "status": "delivered"})
                    continue
                next_retry = time.time() + min(300, 30 * (attempts + 1)) + random.randint(0, 10)
                status = "retry" if attempts < 5 else "dead_letter"
                db.update_connector_delivery(
                    conn,
                    queue_id,
                    status=status,
                    attempts=attempts + 1,
                    next_retry_at=next_retry,
                    last_error=str(result.get("detail", ""))[:600],
                )
                processed.append({"id": queue_id, "connector": self._connector_display_name(connector_name), "status": status})
            return {"processed": processed, "count": len(processed)}
        finally:
            conn.close()

    def connector_queue_status(self, status: str = "", limit: int = 100, workspace_id: str = DEFAULT_WORKSPACE_ID) -> list[dict[str, Any]]:
        conn = db.create_connection()
        if conn is None:
            return []
        try:
            rows = db.get_connector_delivery_queue(conn, status=status, limit=limit, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            for item in rows:
                item["connector_name"] = self._connector_display_name(str(item.get("connector_name", "")))
            return rows
        finally:
            conn.close()

    def adversary_emulation(self) -> dict[str, Any]:
        profiles = [
            {"profile": "lolbin-staging", "mitre": ["T1218", "T1059"], "backing_scenario": "balanced", "safety": "lab-only"},
            {"profile": "dns-beacon", "mitre": ["T1071.004"], "backing_scenario": "network-heavy", "safety": "lab-only"},
            {"profile": "collection-burst", "mitre": ["T1005", "T1119"], "backing_scenario": "file-heavy", "safety": "lab-only"},
        ]
        return {"profiles": profiles, "guidance": "Map safe emulation runs to detections and compare ATT&CK coverage."}

    def replay_incident(self, artifact_path: str) -> dict[str, Any]:
        target = self._safe_replay_artifact(artifact_path)
        if not target.exists():
            return {"status": "missing", "path": artifact_path}
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        mitre = payload.get("mitre_techniques", []) if isinstance(payload, dict) else []
        return {
            "status": "replayed",
            "artifact": artifact_path,
            "detection_count": len(findings),
            "coverage_map": {"mitre_techniques": mitre, "finding_titles": [item.get("title", "") for item in findings if isinstance(item, dict)]},
        }

    def assess_canary_bypass(self) -> dict[str, Any]:
        return {
            "status": "ready",
            "tests": [
                {"name": "rename-then-touch", "goal": "Detect bypass attempts against filename-based canaries"},
                {"name": "read-only-open", "goal": "Validate alerting on stealthy reconnaissance against honeypot files"},
                {"name": "rapid-delete-recreate", "goal": "Measure watcher resilience to race-condition style bypasses"},
            ],
        }

    def telemetry_gap_analysis(self) -> dict[str, Any]:
        processes = self.process_service.snapshot_processes(include_deep_fields=False)
        suspicious = [proc for proc in processes if any(token in str(proc.get("name", "")).lower() for token in ["powershell", "cmd", "rundll32", "mshta", "wmic"])]
        gaps = []
        if suspicious:
            gaps.append("LOLBin lineage is visible, but code-injection telemetry is still inferred rather than natively instrumented.")
        gaps.append("Process injection, AMSI bypass, and token theft need deeper ETW/Sysmon or EDR-grade telemetry for stronger confidence.")
        gaps.append("Staged execution over web and DNS is partially visible through connections, but content-layer telemetry is limited.")
        return {"suspicious_processes": suspicious[:20], "gaps": gaps}

    def inspect_web_surface(self) -> dict[str, Any]:
        services = []
        findings = []
        listening = self._local_http_candidates()
        for item in listening[:20]:
            inspection = self._inspect_http_service(item["host"], item["port"])
            services.append(inspection)
            findings.extend(inspection.get("findings", []))
        trace = self.web_attack_trace()
        return {"services": services, "findings": findings, "trace": trace}

    def network_pentest_overview(self, ip_range: str = "") -> dict[str, Any]:
        connections = self._network_connections()
        return {
            "nmap": self._run_nmap(ip_range),
            "lateral_movement": self._lateral_map(connections),
            "segmentation": self._segmentation_validation(connections),
            "dns_arp_anomalies": self._dns_arp_anomalies(),
        }

    def triage_dashboard(self, workspace_id: str = DEFAULT_WORKSPACE_ID) -> dict[str, Any]:
        asset_view = self.assess_asset_criticality()
        cases = self.list_cases(workspace_id=workspace_id)
        auth_anomalies = []
        conn = db.create_connection()
        if conn:
            try:
                from api.main import _build_auth_anomalies

                auth_rows = db.get_auth_logs(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
                action_rows = db.get_action_audits(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
                auth_anomalies = _build_auth_anomalies(auth_rows, action_rows)
            finally:
                conn.close()
        return {
            "what_needs_attention_now": [
                "Review high-criticality assets with unsigned or unusual process ancestry.",
                "Check pending approval requests before containment actions.",
                "Triaging auth anomalies and connector export failures prevents blind spots.",
            ],
            "top_assets": asset_view.get("top_assets", [])[:5],
            "open_cases": cases[:5],
            "auth_anomalies": auth_anomalies[:5],
        }

    def abuse_summary(self, workspace_id: str = DEFAULT_WORKSPACE_ID) -> dict[str, Any]:
        conn = db.create_connection()
        if conn is None:
            return {"status": "database_unavailable"}
        try:
            auth_rows = db.get_auth_logs(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            action_rows = db.get_action_audits(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            external_rows = db.get_external_requests(conn, workspace_id=workspace_id).fillna("").to_dict(orient="records")
            queue_rows = db.get_connector_delivery_queue(conn, status="", limit=500, workspace_id=workspace_id).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        anomalies = []
        try:
            from api.main import _build_auth_anomalies

            anomalies = _build_auth_anomalies(auth_rows, action_rows)
        except Exception:
            anomalies = []
        return {
            "auth_failures": sum(1 for row in auth_rows if str(row.get("event_type", "")) == "auth_failure"),
            "authorization_denials": sum(1 for row in auth_rows if str(row.get("event_type", "")) in {"authz_denied", "policy_denied"}),
            "signature_failures": sum(1 for row in auth_rows if str(row.get("event_type", "")) in {"signature_failure", "signature_replay"}),
            "dangerous_mutations": sum(
                1 for row in action_rows
                if str(row.get("method", "")).upper() in {"POST", "PATCH", "DELETE"}
                and any(token in str(row.get("path", "")) for token in ["/actions/", "/network/warfare/", "/quarantine/", "/deception/"])
            ),
            "external_failures": sum(1 for row in external_rows if str(row.get("status", "")).lower() not in {"ok", "sent", "delivered", "success"}),
            "dead_letters": sum(1 for row in queue_rows if str(row.get("status", "")).lower() == "dead_letter"),
            "anomalies": anomalies[:10],
        }

    def incident_timeline_story(self, incident: dict[str, Any]) -> dict[str, Any]:
        attack_chain = incident.get("attack_chain", []) if isinstance(incident, dict) else []
        severity = incident.get("severity", "unknown") if isinstance(incident, dict) else "unknown"
        title = incident.get("title", "Incident") if isinstance(incident, dict) else "Incident"
        story = (
            f"{title} progressed as a {severity} severity storyline. "
            f"The observed phases were: {' -> '.join(attack_chain) if attack_chain else 'telemetry collection, enrichment, and analyst review'}. "
            "Recommended handling starts with evidence preservation, continues with scoped validation, and ends with controlled containment."
        )
        return {"story": story, "progressive_disclosure": ["summary", "evidence", "raw telemetry"]}

    def _criticality_rationale(self, name: str, score: float) -> str:
        if score >= 85:
            return f"{name or 'process'} appears mission or OS critical and should require approval before containment."
        if score >= 60:
            return f"{name or 'process'} has elevated business or service impact."
        return f"{name or 'process'} appears lower criticality and is suitable for standard triage."

    def _sha256(self, path: Path) -> str:
        import hashlib

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _local_http_candidates(self) -> list[dict[str, Any]]:
        candidates = []
        try:
            import psutil

            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr and conn.laddr.port in {80, 443, 3000, 5000, 8000, 8080, 8443}:
                    candidates.append({"host": conn.laddr.ip, "port": conn.laddr.port, "pid": conn.pid})
        except Exception:
            return []
        return candidates

    def _inspect_http_service(self, host: str, port: int) -> dict[str, Any]:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}"
        result = {"url": url, "reachable": False, "headers": {}, "cookies": [], "findings": [], "auth_review": {}}
        try:
            safe_url = normalize_outbound_url(url)
            if not safe_url:
                result["findings"].append({"severity": "info", "title": "Service skipped", "detail": "Outbound SSRF guard blocked inspection target."})
                return result
            response = requests.get(safe_url, timeout=5)
            result["reachable"] = True
            result["headers"] = dict(response.headers)
            result["cookies"] = [cookie.name for cookie in response.cookies]
            result["auth_review"] = self._auth_review(url, response.headers)
            findings = result["findings"]
            if "Access-Control-Allow-Origin" in response.headers and response.headers.get("Access-Control-Allow-Origin") == "*":
                findings.append({"severity": "medium", "title": "Permissive CORS", "detail": "Wildcard CORS header observed."})
            if "swagger" in response.text.lower():
                findings.append({"severity": "low", "title": "Swagger exposure", "detail": "Swagger/OpenAPI content discovered on the root path."})
            if ".git" in response.text.lower():
                findings.append({"severity": "high", "title": "Potential .git exposure", "detail": "Response content references .git artifacts."})
        except Exception as exc:
            result["findings"].append({"severity": "info", "title": "Service unavailable", "detail": str(exc)})
        return result

    def _auth_review(self, url: str, headers: dict[str, Any]) -> dict[str, Any]:
        cookies = str(headers.get("Set-Cookie", ""))
        return {
            "url": url,
            "jwt_like": "jwt" in str(headers).lower() or "bearer" in str(headers).lower(),
            "session_cookie_flags": {
                "http_only": "httponly" in cookies.lower(),
                "secure": "secure" in cookies.lower(),
                "same_site": "samesite" in cookies.lower(),
            },
            "csrf_posture": "origin" in str(headers).lower() or "csrf" in str(headers).lower(),
            "idor_checklist": [
                "Review object identifiers for direct reference exposure.",
                "Verify authorization on read, write, and export paths.",
            ],
        }

    def web_attack_trace(self) -> dict[str, Any]:
        browsers = {"chrome.exe", "msedge.exe", "firefox.exe", "safari", "chrome", "msedge"}
        processes = self.process_service.snapshot_processes(include_deep_fields=False)
        web_processes = [proc for proc in processes if str(proc.get("name", "")).lower() in browsers]
        connections = self._network_connections()
        correlated = [conn for conn in connections if int(conn.get("pid", -1) or -1) in {int(proc.get("pid", -1) or -1) for proc in web_processes}]
        return {"browser_processes": web_processes[:20], "network_flows": correlated[:60]}

    def _network_connections(self) -> list[dict[str, Any]]:
        try:
            import monitor_core

            return monitor_core.get_network_connections()
        except Exception:
            return []

    def _run_nmap(self, ip_range: str) -> dict[str, Any]:
        target = ip_range.strip() or "127.0.0.1"
        if not shutil.which("nmap"):
            return {"status": "unavailable", "target": target, "detail": "nmap not installed"}
        try:
            completed = subprocess.run(
                ["nmap", "-sV", "-oX", "-", target],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            root = ET.fromstring(completed.stdout or "<nmaprun/>")
            hosts = []
            for host in root.findall("host"):
                address = ""
                addr = host.find("address")
                if addr is not None:
                    address = str(addr.attrib.get("addr", ""))
                services = []
                for port in host.findall(".//port"):
                    service = port.find("service")
                    services.append(
                        {
                            "port": port.attrib.get("portid", ""),
                            "protocol": port.attrib.get("protocol", ""),
                            "service": service.attrib.get("name", "") if service is not None else "",
                            "product": service.attrib.get("product", "") if service is not None else "",
                        }
                    )
                hosts.append({"address": address, "services": services})
            return {"status": "ok", "target": target, "hosts": hosts}
        except Exception as exc:
            return {"status": "error", "target": target, "detail": str(exc)}

    def _lateral_map(self, connections: list[dict[str, Any]]) -> dict[str, Any]:
        protocols = []
        interesting = {53: "DNS", 88: "Kerberos", 135: "RPC", 389: "LDAP", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}
        for conn in connections:
            remote = str(conn.get("remote_addr", ""))
            if ":" not in remote:
                continue
            try:
                port = int(remote.rsplit(":", 1)[1])
            except ValueError:
                continue
            if port in interesting:
                protocols.append({"protocol": interesting[port], "remote_addr": remote, "pid": conn.get("pid")})
        return {"movements": protocols[:80]}

    def _segmentation_validation(self, connections: list[dict[str, Any]]) -> dict[str, Any]:
        violations = []
        for conn in connections:
            remote = str(conn.get("remote_addr", ""))
            if not remote:
                continue
            ip = remote.split(":")[0]
            if ip.startswith("169.254.169.254"):
                violations.append({"severity": "high", "title": "Metadata reachability", "ip": ip})
        return {"violations": violations, "zones": ["localhost", "private-rfc1918", "external"]}

    def _dns_arp_anomalies(self) -> dict[str, Any]:
        anomalies = []
        try:
            arp_output = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8", errors="ignore", timeout=10)
            if arp_output.lower().count("dynamic") > 40:
                anomalies.append({"severity": "medium", "title": "Large ARP surface", "detail": "High number of dynamic ARP entries observed."})
        except Exception:
            pass
        try:
            dns_output = subprocess.check_output(["ipconfig", "/all"], text=True, encoding="utf-8", errors="ignore", timeout=10)
            if "8.8.8.8" in dns_output and "corp" in socket.gethostname().lower():
                anomalies.append({"severity": "medium", "title": "Unexpected resolver", "detail": "Public resolver present on a corp-named host."})
        except Exception:
            pass
        return {"anomalies": anomalies}

    def _safe_replay_artifact(self, artifact_path: str) -> Path:
        candidate = Path(artifact_path or "").expanduser()
        if not str(candidate).strip():
            raise ValueError("artifact_path is required")
        resolved = candidate.resolve(strict=False)
        allowed_root = (self.base_dir / "shadowlab_out").resolve()
        if allowed_root not in resolved.parents:
            raise ValueError("Replay artifacts must stay within shadowlab_out")
        if resolved.suffix.lower() != ".json":
            raise ValueError("Replay artifacts must be JSON files")
        parsed = urlparse(resolved.as_uri())
        if parsed.scheme != "file":
            raise ValueError("Replay artifacts must be local files")
        return resolved

    def _serialize_connector(self, connector: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(connector)
        normalized["name"] = self._connector_display_name(str(normalized.get("name", "")))
        raw_config = normalized.get("config_json", "{}")
        if isinstance(raw_config, str):
            try:
                parsed = json.loads(raw_config or "{}")
            except json.JSONDecodeError:
                parsed = {}
        elif isinstance(raw_config, dict):
            parsed = raw_config
        else:
            parsed = {}
        normalized["config"] = secret_store.redact_config(secret_store.reveal_config(parsed))
        normalized["config_json"] = json.dumps(normalized["config"])
        return normalized

    def _connector_display_name(self, storage_name: str) -> str:
        return str(storage_name or "").strip().lower()
