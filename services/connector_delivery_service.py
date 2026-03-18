from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import requests


class ConnectorDeliveryService:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def deliver(self, connector: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        name = str(connector.get("name", "")).strip().lower()
        config = self._parse_config(connector.get("config_json", "{}"))
        if name == "splunk":
            return self._deliver_splunk(config, event)
        if name == "sentinel":
            return self._deliver_sentinel(config, event)
        if name == "elastic":
            return self._deliver_elastic(config, event)
        if name == "thehive":
            return self._deliver_thehive(config, event)
        if name == "shuffle":
            return self._deliver_shuffle(config, event)
        return {"ok": False, "status": "unsupported", "detail": f"Unsupported connector: {name}"}

    def _deliver_splunk(self, config: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        hec_url = str(config.get("hec_url", "")).strip()
        token = str(config.get("token", "")).strip()
        if not hec_url or not token:
            return {"ok": False, "status": "invalid_config", "detail": "splunk.hec_url and splunk.token are required"}
        payload = {
            "event": event,
            "index": str(config.get("index", "main")),
            "sourcetype": str(config.get("sourcetype", "shadowlab:event")),
            "host": str(event.get("host", "")),
        }
        headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
        return self._post_json(hec_url, headers, payload, verify=bool(config.get("verify_tls", True)))

    def _deliver_sentinel(self, config: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        workspace_id = str(config.get("workspace_id", "")).strip()
        shared_key = str(config.get("shared_key", "")).strip()
        log_type = str(config.get("log_type", "ShadowLabEvents")).strip()
        if not workspace_id or not shared_key:
            return {"ok": False, "status": "invalid_config", "detail": "sentinel.workspace_id and sentinel.shared_key are required"}
        body = json.dumps([event], separators=(",", ":"))
        rfc1123 = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        try:
            signature = self._build_sentinel_signature(workspace_id, shared_key, len(body), rfc1123)
        except Exception as exc:
            return {"ok": False, "status": "invalid_config", "detail": f"Invalid Sentinel shared key format: {exc}"}
        url = (
            f"https://{workspace_id}.ods.opinsights.azure.com/api/logs"
            "?api-version=2016-04-01"
        )
        headers = {
            "Content-Type": "application/json",
            "Log-Type": log_type,
            "x-ms-date": rfc1123,
            "Authorization": signature,
        }
        return self._post_json(url, headers, [event], verify=bool(config.get("verify_tls", True)))

    def _deliver_elastic(self, config: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(config.get("endpoint", "")).strip().rstrip("/")
        index = str(config.get("index", "shadowlab-events")).strip()
        api_key = str(config.get("api_key", "")).strip()
        if not endpoint:
            return {"ok": False, "status": "invalid_config", "detail": "elastic.endpoint is required"}
        url = f"{endpoint}/{index}/_doc"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        return self._post_json(url, headers, event, verify=bool(config.get("verify_tls", True)))

    def _deliver_thehive(self, config: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        url = str(config.get("url", "")).strip().rstrip("/")
        api_key = str(config.get("api_key", "")).strip()
        if not url or not api_key:
            return {"ok": False, "status": "invalid_config", "detail": "thehive.url and thehive.api_key are required"}
        alert_payload = {
            "title": str(event.get("title", event.get("event_type", "shadowlab-event"))),
            "description": json.dumps(event, indent=2),
            "severity": int(event.get("severity_level", 2) or 2),
            "type": "external",
            "source": "shadowlab",
            "sourceRef": str(event.get("event_id", event.get("event_type", "shadowlab"))),
            "tags": ["shadowlab", str(event.get("event_type", "event"))],
        }
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        return self._post_json(f"{url}/api/v1/alert", headers, alert_payload, verify=bool(config.get("verify_tls", True)))

    def _deliver_shuffle(self, config: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        webhook_url = str(config.get("webhook_url", "")).strip()
        token = str(config.get("token", "")).strip()
        if not webhook_url:
            return {"ok": False, "status": "invalid_config", "detail": "shuffle.webhook_url is required"}
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self._post_json(webhook_url, headers, event, verify=bool(config.get("verify_tls", True)))

    def _post_json(self, url: str, headers: dict[str, str], payload: Any, *, verify: bool) -> dict[str, Any]:
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=self.timeout, verify=verify)
            snippet = (response.text or "").strip()[:400]
            if response.ok:
                return {"ok": True, "status": str(response.status_code), "detail": snippet or "ok"}
            return {"ok": False, "status": str(response.status_code), "detail": snippet or "request failed"}
        except Exception as exc:
            return {"ok": False, "status": "exception", "detail": str(exc)}

    def _parse_config(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            stripped = raw.strip()
            if not stripped:
                return {}
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}

    def _build_sentinel_signature(self, workspace_id: str, shared_key: str, content_length: int, rfc1123date: str) -> str:
        x_headers = f"x-ms-date:{rfc1123date}"
        string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {workspace_id}:{encoded_hash}"
