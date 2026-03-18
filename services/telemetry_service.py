from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import monitor_core
import requests

from core.normalization import normalize_telemetry_row


class TelemetryMonitoringService:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.sampler = monitor_core.TelemetrySampler()

    def sample_once(self) -> dict[str, Any]:
        sample = normalize_telemetry_row(self.sampler.sample())
        return sample.to_dict()

    def collect_event_context(self) -> tuple[dict[str, Any], dict[str, Any]]:
        raw_defender, raw_sysmon = monitor_core.read_windows_events()
        defender_summary = monitor_core.summarize_events(
            raw_defender, self.config.get("defender_ids")
        ) if raw_defender else {"total": 0, "by_id": {}}
        sysmon_summary = monitor_core.summarize_events(
            raw_sysmon, self.config.get("sysmon_ids")
        ) if raw_sysmon else {"total": 0, "by_id": {}}
        return defender_summary, sysmon_summary


class CollectorTelemetryBridge:
    def __init__(self, config: dict[str, Any] | None = None, out_dir: Path | None = None):
        self.config = config or {}
        self.out_dir = out_dir or Path("shadowlab_out")
        self._collector_process: subprocess.Popen[str] | None = None
        self._collector_log_handle = None
        self._lock = threading.Lock()

    def is_enabled(self) -> bool:
        return bool(self._collector_config_root().get("enabled", False))

    def export_monitor_session(
        self,
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
        final_score: dict[str, Any],
        incident: dict[str, Any],
    ) -> dict[str, Any]:
        endpoint = self._collector_ingest_endpoint()
        headers = self._request_headers()
        timeout = self._timeout()
        resource = self._resource_payload(self._resource_attributes())

        payloads = {
            "metrics": self._build_metrics_payload(resource, telemetry_rows, defender_summary, sysmon_summary, final_score),
            "logs": self._build_logs_payload(resource, incident, final_score, defender_summary, sysmon_summary),
            "traces": self._build_traces_payload(resource, telemetry_rows, incident),
        }

        exports: dict[str, Any] = {}
        for signal_type, payload in payloads.items():
            url = f"{endpoint}/v1/{signal_type}"
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=timeout)
                exports[signal_type] = {
                    "status": "sent" if response.ok else "failed",
                    "http_status": response.status_code,
                    "detail": response.text[:300] if response.text else "",
                    "target": url,
                }
            except requests.RequestException as exc:
                exports[signal_type] = {
                    "status": "failed",
                    "detail": str(exc),
                    "target": url,
                }
        return {
            "enabled": True,
            "collector_endpoint": endpoint,
            "exports": exports,
        }

    def export_incident_record(self, incident: dict[str, Any]) -> dict[str, Any]:
        endpoint = self._collector_ingest_endpoint()
        payload = self._build_logs_payload(
            self._resource_payload(self._resource_attributes()),
            incident,
            {},
            {},
            {},
        )
        url = f"{endpoint}/v1/logs"
        try:
            response = requests.post(url, json=payload, headers=self._request_headers(), timeout=self._timeout())
            return {
                "enabled": True,
                "status": "sent" if response.ok else "failed",
                "http_status": response.status_code,
                "detail": response.text[:300] if response.text else "",
                "target": url,
            }
        except requests.RequestException as exc:
            return {
                "enabled": True,
                "status": "failed",
                "detail": str(exc),
                "target": url,
            }

    def collector_status(self) -> dict[str, Any]:
        process_running = False
        pid = None
        with self._lock:
            self._cleanup_collector_handle_locked()
            if self._collector_process is not None and self._collector_process.poll() is None:
                process_running = True
                pid = self._collector_process.pid
        zpages_url = self._collector_zpages_url()
        return {
            "enabled": self.is_enabled(),
            "distribution_manifest": str(self._collector_builder_manifest_path()),
            "config_path": str(self._collector_runtime_config_path()),
            "binary_path": self._collector_binary_path(),
            "otlp_http_endpoint": self._collector_ingest_endpoint(),
            "zpages_url": zpages_url,
            "zpages_probe": self._probe_zpages(zpages_url),
            "fabric_name": "shadowlab-telemetry-fabric",
            "process_running": process_running,
            "pid": pid,
        }

    def start_collector(self) -> dict[str, Any]:
        binary_path = self._collector_binary_path()
        config_path = self._collector_runtime_config_path()
        if not binary_path:
            return {"status": "failed", "detail": "Collector binary path is not configured."}
        binary = Path(binary_path)
        if not binary.exists():
            return {"status": "failed", "detail": f"Collector binary not found: {binary}"}
        if not config_path.exists():
            return {"status": "failed", "detail": f"Collector config not found: {config_path}"}

        with self._lock:
            self._cleanup_collector_handle_locked()
            if self._collector_process is not None and self._collector_process.poll() is None:
                return {"status": "already_running", "pid": self._collector_process.pid}
            log_path = self.out_dir / "telemetry-fabric.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = log_path.open("a", encoding="utf-8")
            self._collector_log_handle = log_handle
            self._collector_process = subprocess.Popen(
                [str(binary), "--config", str(config_path)],
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
            pid = self._collector_process.pid
        return {"status": "started", "pid": pid, "target": str(log_path)}

    def stop_collector(self) -> dict[str, Any]:
        with self._lock:
            if self._collector_process is None or self._collector_process.poll() is not None:
                self._collector_process = None
                self._cleanup_collector_handle_locked(force=True)
                return {"status": "not_running"}
            self._collector_process.terminate()
            try:
                self._collector_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._collector_process.kill()
                self._collector_process.wait(timeout=5)
            pid = self._collector_process.pid
            self._collector_process = None
            self._cleanup_collector_handle_locked(force=True)
        return {"status": "stopped", "pid": pid}

    def _cleanup_collector_handle_locked(self, *, force: bool = False) -> None:
        process_finished = self._collector_process is None or self._collector_process.poll() is not None
        if not force and not process_finished:
            return
        if self._collector_log_handle is not None:
            try:
                self._collector_log_handle.flush()
                self._collector_log_handle.close()
            except Exception:
                pass
            self._collector_log_handle = None

    def _collector_config_root(self) -> dict[str, Any]:
        return (
            self.config.get("telemetry_fabric")
            or {}
        )

    def _collector_runtime(self) -> dict[str, Any]:
        return self._collector_config_root().get("runtime", {}) or self._collector_config_root().get("collector", {}) or {}

    def _collector_build(self) -> dict[str, Any]:
        return self._collector_config_root().get("build", {}) or {}

    def _collector_ingest_endpoint(self) -> str:
        endpoint = os.environ.get("SHADOWLAB_OTLP_HTTP_ENDPOINT") or self._collector_config_root().get(
            "otlp_http_endpoint",
            "http://127.0.0.1:4318",
        )
        return str(endpoint).rstrip("/")

    def _collector_binary_path(self) -> str:
        return str(os.environ.get("SHADOWLAB_OTELCOL_BIN") or self._collector_runtime().get("binary_path", "")).strip()

    def _collector_runtime_config_path(self) -> Path:
        configured = os.environ.get("SHADOWLAB_OTELCOL_CONFIG") or self._collector_runtime().get(
            "config_path",
            str(Path("config") / "telemetry-fabric-runtime.yaml"),
        )
        return Path(configured)

    def _collector_builder_manifest_path(self) -> Path:
        configured = self._collector_build().get("manifest_path", str(Path("config") / "telemetry-fabric-builder.yaml"))
        return Path(configured)

    def _collector_zpages_url(self) -> str:
        return str(
            os.environ.get("SHADOWLAB_OTEL_ZPAGES_URL")
            or self._collector_runtime().get("zpages_url", "http://127.0.0.1:55679/debug/servicez")
        )

    def _request_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        for key, value in (self._collector_config_root().get("headers", {}) or {}).items():
            headers[str(key)] = str(value)
        return headers

    def _timeout(self) -> float:
        return float(self._collector_config_root().get("timeout_seconds", 5.0))

    def _probe_zpages(self, zpages_url: str) -> dict[str, Any]:
        try:
            response = requests.get(zpages_url, timeout=self._timeout())
            return {
                "reachable": response.ok,
                "http_status": response.status_code,
                "detail": response.text[:200] if response.text else "",
            }
        except requests.RequestException as exc:
            return {
                "reachable": False,
                "detail": str(exc),
            }

    def _resource_attributes(self) -> list[dict[str, Any]]:
        root = self._collector_config_root()
        return [
            self._attribute("service.name", root.get("service_name", "shadowlab")),
            self._attribute("service.namespace", root.get("service_namespace", "shadowlab")),
            self._attribute("service.version", root.get("service_version", "2.1.0")),
            self._attribute("deployment.environment", root.get("environment", "lab")),
            self._attribute("host.name", socket.gethostname()),
            self._attribute("shadowlab.collector.mode", "telemetry-fabric"),
        ]

    def _resource_payload(self, attributes: list[dict[str, Any]]) -> dict[str, Any]:
        return {"resource": {"attributes": attributes}}

    def _build_metrics_payload(
        self,
        resource: dict[str, Any],
        telemetry_rows: list[dict[str, Any]],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
        final_score: dict[str, Any],
    ) -> dict[str, Any]:
        now = self._now_nanos()
        metrics = [
            self._gauge_metric("shadowlab.telemetry.cpu.average", self._average(telemetry_rows, "cpu"), now, "percent"),
            self._gauge_metric("shadowlab.telemetry.memory.average", self._average(telemetry_rows, "mem_percent"), now, "percent"),
            self._gauge_metric("shadowlab.telemetry.threads.average", self._average(telemetry_rows, "proc_threads"), now, "{threads}"),
            self._gauge_metric("shadowlab.telemetry.connections.average", self._average(telemetry_rows, "tcp_conns"), now, "{connections}"),
            self._gauge_metric("shadowlab.detection.likelihood", float(final_score.get("likelihood", 0.0)), now, "1"),
            self._sum_metric("shadowlab.events.defender.total", float(defender_summary.get("total", 0)), now, "{events}"),
            self._sum_metric("shadowlab.events.sysmon.total", float(sysmon_summary.get("total", 0)), now, "{events}"),
            self._sum_metric("shadowlab.telemetry.samples", float(len(telemetry_rows)), now, "{samples}"),
        ]
        return {
            "resourceMetrics": [
                {
                    **resource,
                    "scopeMetrics": [
                        {
                            "scope": {"name": "shadowlab.telemetry.bridge", "version": "1.0.0"},
                            "metrics": metrics,
                        }
                    ],
                }
            ]
        }

    def _build_logs_payload(
        self,
        resource: dict[str, Any],
        incident: dict[str, Any],
        final_score: dict[str, Any],
        defender_summary: dict[str, Any],
        sysmon_summary: dict[str, Any],
    ) -> dict[str, Any]:
        now = self._now_nanos()
        body = {
            "incident_id": incident.get("incident_id", "unknown"),
            "title": incident.get("title", "ShadowLab incident"),
            "summary": incident.get("summary", ""),
            "severity": incident.get("severity", "unknown"),
            "likelihood": float(final_score.get("likelihood", incident.get("likelihood", 0.0) or 0.0)),
            "attack_chain": incident.get("attack_chain", []),
            "mitre_techniques": incident.get("mitre_techniques", incident.get("mitre_mapping", [])),
            "defender_total": defender_summary.get("total", 0),
            "sysmon_total": sysmon_summary.get("total", 0),
        }
        return {
            "resourceLogs": [
                {
                    **resource,
                    "scopeLogs": [
                        {
                            "scope": {"name": "shadowlab.telemetry.bridge", "version": "1.0.0"},
                            "logRecords": [
                                {
                                    "timeUnixNano": now,
                                    "severityText": str(incident.get("severity", "info")).upper(),
                                    "body": {"stringValue": json.dumps(body, ensure_ascii=True)},
                                    "attributes": [
                                        self._attribute("shadowlab.incident_id", incident.get("incident_id", "unknown")),
                                        self._attribute("shadowlab.status", incident.get("status", "open")),
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    def _build_traces_payload(
        self,
        resource: dict[str, Any],
        telemetry_rows: list[dict[str, Any]],
        incident: dict[str, Any],
    ) -> dict[str, Any]:
        earliest = min((float(row.get("ts", time.time())) for row in telemetry_rows), default=time.time())
        return {
            "resourceSpans": [
                {
                    **resource,
                    "scopeSpans": [
                        {
                            "scope": {"name": "shadowlab.telemetry.bridge", "version": "1.0.0"},
                            "spans": [
                                {
                                    "traceId": secrets.token_hex(16),
                                    "spanId": secrets.token_hex(8),
                                    "name": "shadowlab.monitor.run",
                                    "kind": 1,
                                    "startTimeUnixNano": str(int(earliest * 1_000_000_000)),
                                    "endTimeUnixNano": self._now_nanos(),
                                    "attributes": [
                                        self._attribute("shadowlab.incident_id", incident.get("incident_id", "unknown")),
                                        self._attribute("shadowlab.telemetry_count", len(telemetry_rows)),
                                    ],
                                    "status": {"code": 1},
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    def _average(self, telemetry_rows: list[dict[str, Any]], key: str) -> float:
        if not telemetry_rows:
            return 0.0
        return sum(float(row.get(key, 0.0) or 0.0) for row in telemetry_rows) / float(len(telemetry_rows))

    def _gauge_metric(self, name: str, value: float, now: str, unit: str) -> dict[str, Any]:
        return {
            "name": name,
            "unit": unit,
            "gauge": {"dataPoints": [{"timeUnixNano": now, "asDouble": float(value)}]},
        }

    def _sum_metric(self, name: str, value: float, now: str, unit: str) -> dict[str, Any]:
        return {
            "name": name,
            "unit": unit,
            "sum": {
                "aggregationTemporality": 2,
                "isMonotonic": False,
                "dataPoints": [{"timeUnixNano": now, "asDouble": float(value)}],
            },
        }

    def _attribute(self, key: str, value: Any) -> dict[str, Any]:
        if isinstance(value, bool):
            encoded = {"boolValue": value}
        elif isinstance(value, int):
            encoded = {"intValue": str(value)}
        elif isinstance(value, float):
            encoded = {"doubleValue": value}
        else:
            encoded = {"stringValue": str(value)}
        return {"key": key, "value": encoded}

    def _now_nanos(self) -> str:
        return str(time.time_ns())

