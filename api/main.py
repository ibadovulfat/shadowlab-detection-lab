from __future__ import annotations

import csv
import importlib.util
import json
import os
import platform
import socket
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import database as db
import monitor_core
from report_export import generate_pdf
from services.detection_service import DetectionOrchestrator
from services.incident_service import IncidentArtifactService
from services.process_intelligence_service import ProcessIntelligenceService
from services.response_service import ResponseOrchestrator
from services.telemetry_service import TelemetryMonitoringService
from threat_intelligence import check_file_malwarebazaar, check_ip, scan_process
import yaml


BASE_DIR = Path(__file__).resolve().parent.parent
OUT_DIR = BASE_DIR / "shadowlab_out"
OUT_DIR.mkdir(exist_ok=True, parents=True)


def load_config() -> dict[str, Any]:
    with (BASE_DIR / "config.yaml").open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


config = load_config()
db.init_db()

app = FastAPI(
    title="ShadowLab API",
    version="2.0.0",
    description="Streamlit-free backend for the ShadowLab defensive operations platform.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

process_intel_service = ProcessIntelligenceService()
response_service = ResponseOrchestrator()
detection_service = DetectionOrchestrator()
artifact_service = IncidentArtifactService(OUT_DIR)
honeypot_instance = None
canary_instance = None
canary_alerts: list[str] = []
network_warfare_instance = None
alert_webhook_url = os.environ.get("SHADOWLAB_ALERT_WEBHOOK", "")


class MonitorRequest(BaseModel):
    duration: int = Field(default=60, ge=5, le=600)
    interval: float = Field(default=1.0, ge=0.1, le=10.0)
    report_sections: list[str] = Field(default_factory=lambda: ["Telemetry", "Events Summary", "Detection Score"])


class ScenarioRequest(BaseModel):
    profile: str = Field(default="balanced")
    duration: int = Field(default=30, ge=5, le=300)


class ProcessScanRequest(BaseModel):
    api_key: str


class SnifferRequest(BaseModel):
    duration: int = Field(default=10, ge=5, le=60)


class StringScanRequest(BaseModel):
    min_length: int = Field(default=4, ge=3, le=20)
    patterns: list[str] = Field(default_factory=lambda: ["http", "powershell", "cmd", "token", "password", "api"])


class SandboxTraceRequest(BaseModel):
    duration: int = Field(default=5, ge=2, le=60)
    interval: float = Field(default=0.5, ge=0.1, le=5.0)


class HoneypotRequest(BaseModel):
    filename: str = Field(default="passwords.txt")


class EvidenceRequest(BaseModel):
    alert_name: str = Field(default="incident")


class NetworkScanRequest(BaseModel):
    ip_range: str = Field(default="192.168.1.0/24")


class BlockerRequest(BaseModel):
    target_ip: str
    gateway_ip: str


class IncidentUpdateRequest(BaseModel):
    status: str | None = None
    notes: str | None = None
    owner: str | None = None


class PersistenceRemediationRequest(BaseModel):
    item_type: str
    path: str
    name: str = ""


class AlertWebhookRequest(BaseModel):
    webhook_url: str
    message: str = "ShadowLab test alert"


class TriageRequest(BaseModel):
    virustotal_api_key: str | None = None
    yara_pack: str = "hybrid"
    trace_duration: int = Field(default=3, ge=1, le=20)
    strings_min_length: int = Field(default=4, ge=3, le=20)
    strings_patterns: list[str] = Field(default_factory=lambda: ["http", "powershell", "cmd", "password"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def get_config() -> dict[str, Any]:
    return config


@app.post("/monitor/run")
def run_monitor(payload: MonitorRequest) -> dict[str, Any]:
    telemetry_service = TelemetryMonitoringService(config)
    telemetry_rows: list[dict[str, Any]] = []
    timeline_scores: list[float] = []

    defender_summary, sysmon_summary = telemetry_service.collect_event_context()
    start = time.time()
    while time.time() - start < payload.duration:
        row = telemetry_service.sample_once()
        telemetry_rows.append(row)
        score = detection_service.incremental_score(telemetry_rows, defender_summary, sysmon_summary)
        timeline_scores.append(float(score["likelihood"]))
        time.sleep(max(0.1, float(payload.interval)))

    final = detection_service.final_score(telemetry_rows, defender_summary, sysmon_summary)
    incident = detection_service.build_incident(telemetry_rows, defender_summary, sysmon_summary)

    _write_monitor_artifacts(telemetry_rows, defender_summary, sysmon_summary, final, payload.report_sections, incident)

    conn = db.create_connection()
    if conn:
        db.insert_telemetry(conn, telemetry_rows)
        db.upsert_incident(
            conn,
            incident.incident_id,
            incident.created_at,
            incident.severity,
            incident.title,
            incident.summary,
            status="open",
            notes="\n".join(incident.notes),
            recommended_actions=json.dumps(incident.recommended_actions),
        )
        conn.close()

    if alert_webhook_url and incident.severity.lower() in {"high", "critical"}:
        _send_webhook_alert(
            alert_webhook_url,
            {
                "product": "ShadowLab",
                "incident_id": incident.incident_id,
                "severity": incident.severity,
                "title": incident.title,
                "summary": incident.summary,
            },
        )

    return {
        "telemetry_count": len(telemetry_rows),
        "timeline_scores": timeline_scores,
        "event_summaries": {
            "defender": defender_summary,
            "sysmon": sysmon_summary,
        },
        "final_score": final,
        "incident": incident.to_dict(),
        "artifacts": _artifact_manifest(),
    }


@app.get("/processes")
def list_processes() -> list[dict[str, Any]]:
    return process_intel_service.snapshot_processes()


@app.get("/processes/{pid}")
def get_process(pid: int) -> dict[str, Any]:
    try:
        return process_intel_service.profile_process(pid)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/processes/{pid}/tree")
def process_tree(pid: int) -> dict[str, Any]:
    snapshot = process_intel_service.snapshot_processes(include_deep_fields=False)
    indexed = {int(row["pid"]): row for row in snapshot if row.get("pid") is not None}
    if pid not in indexed:
        raise HTTPException(status_code=404, detail="Process not found")

    def build_node(current_pid: int, depth: int = 0) -> dict[str, Any]:
        current = indexed.get(current_pid, {})
        children = [
            build_node(int(row["pid"]), depth + 1)
            for row in snapshot
            if int(row.get("ppid", -1) or -1) == current_pid and depth < 3
        ]
        return {
            "pid": current_pid,
            "ppid": current.get("ppid"),
            "name": current.get("name"),
            "cmdline": current.get("cmdline"),
            "children": children,
        }

    lineage: list[dict[str, Any]] = []
    cursor = indexed[pid]
    seen: set[int] = set()
    while cursor and int(cursor.get("pid", -1)) not in seen:
        seen.add(int(cursor.get("pid", -1)))
        lineage.append(
            {
                "pid": cursor.get("pid"),
                "ppid": cursor.get("ppid"),
                "name": cursor.get("name"),
                "cmdline": cursor.get("cmdline"),
            }
        )
        parent_pid = int(cursor.get("ppid", -1) or -1)
        cursor = indexed.get(parent_pid)
    return {"root": build_node(pid), "lineage": lineage}


@app.get("/processes/{pid}/internals")
def process_internals(pid: int) -> dict[str, Any]:
    import plugins.internals as internals

    return {
        "pid": pid,
        "handles": internals.get_process_handles(pid),
        "modules": internals.get_process_libs(pid),
    }


@app.post("/processes/{pid}/strings")
def process_strings(pid: int, payload: StringScanRequest) -> dict[str, Any]:
    import plugins.strings_analyser as strings_analyser

    profile = process_intel_service.profile_process(pid)
    exe_path = profile.get("exe")
    strings = strings_analyser.extract_strings(exe_path, payload.min_length)
    hits = strings_analyser.search_patterns(strings, payload.patterns)
    return {
        "pid": pid,
        "exe": exe_path,
        "min_length": payload.min_length,
        "patterns": payload.patterns,
        "total_strings": len(strings),
        "sample": strings[:100],
        "pattern_hits": hits[:100],
    }


@app.get("/processes/{pid}/yara")
def process_yara(pid: int, pack: str = "hybrid") -> dict[str, Any]:
    import plugins.yara_scanner as yara_scanner

    profile = process_intel_service.profile_process(pid)
    exe_path = profile.get("exe")
    rules = yara_scanner.compile_rules(pack=pack)
    matches = yara_scanner.scan_file(exe_path, rules) if exe_path else []
    return {
        "pid": pid,
        "exe": exe_path,
        "pack": pack,
        "yara_available": bool(yara_scanner.YARA_AVAILABLE),
        "available_packs": yara_scanner.available_packs(),
        "rules_loaded": bool(rules),
        "matches": matches,
    }


@app.post("/processes/{pid}/sandbox-trace")
def process_sandbox_trace(pid: int, payload: SandboxTraceRequest) -> dict[str, Any]:
    import plugins.sandbox as sandbox

    tracer = sandbox.ProcessTracer(pid)
    return tracer.trace(duration=payload.duration, interval=payload.interval)


@app.get("/processes/{pid}/ai-analysis")
def process_ai_analysis(pid: int) -> dict[str, Any]:
    import plugins.ai_analyst as ai_analyst

    profile = process_intel_service.profile_process(pid)
    analyst = ai_analyst.AIAnalyst()
    return analyst.analyze_process(profile)


@app.post("/processes/{pid}/scan")
def scan_single_process(pid: int, payload: ProcessScanRequest) -> dict[str, Any]:
    process_rows = process_intel_service.snapshot_processes()
    target = next((row for row in process_rows if int(row.get("pid", -1)) == pid), None)
    if not target:
        raise HTTPException(status_code=404, detail="Process not found")
    return scan_process(target, payload.api_key)


@app.get("/processes/{pid}/memory-analysis")
def memory_analysis(pid: int, process_name: str) -> dict[str, Any]:
    import plugins.memory_forensics as memory_forensics

    return memory_forensics.run_analysis(pid, process_name)


@app.post("/processes/{pid}/actions/{action}")
def process_action(pid: int, action: str, process_name: str) -> dict[str, Any]:
    action_name = action.lower()
    profile = process_intel_service.profile_process(pid)
    if action_name == "suspend":
        result = response_service.suspend(pid, process_name)
    elif action_name == "resume":
        result = response_service.resume(pid, process_name)
    elif action_name == "kill":
        result = response_service.kill(pid, process_name)
    elif action_name == "kill-tree":
        result = response_service.kill_tree(pid, process_name)
    elif action_name == "quarantine":
        result = response_service.quarantine_file(pid, process_name, profile.get("exe"))
    else:
        raise HTTPException(status_code=400, detail="Unsupported action")
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    if action_name == "quarantine":
        conn = db.create_connection()
        if conn:
            try:
                db.log_quarantine(conn, pid, process_name, profile.get("exe"), result.get("path", ""), "active")
            finally:
                conn.close()
    return result


@app.get("/persistence")
def persistence_items() -> list[dict[str, Any]]:
    import plugins.persistence as persistence_scanner

    return persistence_scanner.get_persistence_items()


@app.post("/persistence/remediate")
def remediate_persistence(payload: PersistenceRemediationRequest) -> dict[str, Any]:
    import plugins.persistence as persistence_scanner

    result = persistence_scanner.remediate_persistence_item(payload.item_type, payload.path, payload.name)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("message", "Remediation failed"))
    return result


@app.get("/threat-intel/ip/{ip}")
def threat_intel_lookup(ip: str) -> dict[str, Any]:
    result = check_ip(ip)
    return {"ip": ip, "result": result}


@app.get("/threat-intel/hash/{file_hash}")
def threat_hash_lookup(file_hash: str) -> dict[str, Any]:
    return {
        "hash": file_hash,
        "malwarebazaar": check_file_malwarebazaar(file_hash),
    }


@app.get("/history/telemetry")
def telemetry_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        history_df = db.get_historical_data(conn)
    finally:
        conn.close()
    return history_df.to_dict(orient="records")


@app.get("/history/responses")
def response_history() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        response_df = db.get_response_logs(conn)
    finally:
        conn.close()
    return response_df.to_dict(orient="records")


@app.get("/incidents")
def incidents() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_incidents(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.patch("/incidents/{incident_id}")
def update_incident(incident_id: str, payload: IncidentUpdateRequest) -> dict[str, str]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        db.update_incident(conn, incident_id, status=payload.status, notes=payload.notes, owner=payload.owner)
    finally:
        conn.close()
    return {"status": "updated", "incident_id": incident_id}


@app.get("/quarantine")
def quarantine_items() -> list[dict[str, Any]]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_quarantine(conn)
    finally:
        conn.close()
    return frame.to_dict(orient="records")


@app.post("/quarantine/{quarantine_id}/restore")
def restore_quarantine(quarantine_id: int) -> dict[str, Any]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_quarantine(conn)
        row = frame[frame["id"] == quarantine_id]
        if row.empty:
            raise HTTPException(status_code=404, detail="Quarantine record not found")
        item = row.iloc[0].to_dict()
        source = Path(item["quarantine_path"])
        target = Path(item["original_path"])
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            source.replace(target)
        db.update_quarantine(conn, quarantine_id, "restored")
        return {"status": "restored", "path": str(target)}
    finally:
        conn.close()


@app.delete("/quarantine/{quarantine_id}")
def delete_quarantine(quarantine_id: int) -> dict[str, Any]:
    conn = db.create_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")
    try:
        frame = db.get_quarantine(conn)
        row = frame[frame["id"] == quarantine_id]
        if row.empty:
            raise HTTPException(status_code=404, detail="Quarantine record not found")
        item = row.iloc[0].to_dict()
        target = Path(item["quarantine_path"])
        if target.exists():
            target.unlink()
        db.update_quarantine(conn, quarantine_id, "deleted")
        return {"status": "deleted", "path": str(target)}
    finally:
        conn.close()


@app.get("/timeline")
def timeline() -> list[dict[str, Any]]:
    timeline_items: list[dict[str, Any]] = []
    conn = db.create_connection()
    if conn:
        try:
            for row in db.get_response_logs(conn).to_dict(orient="records")[:50]:
                timeline_items.append({"time": row.get("timestamp"), "type": "response", "severity": "high" if row.get("action") == "KILL" else "medium", "title": row.get("action"), "details": row})
            for row in db.get_incidents(conn).to_dict(orient="records")[:30]:
                timeline_items.append({"time": row.get("created_at"), "type": "incident", "severity": row.get("severity"), "title": row.get("title"), "details": row})
            for row in db.get_historical_data(conn).to_dict(orient="records")[-40:]:
                timeline_items.append({"time": row.get("ts"), "type": "telemetry", "severity": "low", "title": f"CPU {row.get('cpu')}%", "details": row})
        finally:
            conn.close()
    timeline_items.sort(key=lambda item: str(item.get("time")), reverse=True)
    return timeline_items


@app.get("/hosts")
def hosts() -> list[dict[str, Any]]:
    boot_time = None
    try:
        import psutil
        boot_time = psutil.boot_time()
    except Exception:
        boot_time = None
    return [{"host": socket.gethostname(), "platform": platform.platform(), "boot_time": boot_time, "api_status": "online", "role": "local"}]


@app.post("/alerts/test")
def test_alert_webhook(payload: AlertWebhookRequest) -> dict[str, Any]:
    _send_webhook_alert(payload.webhook_url, {"product": "ShadowLab", "message": payload.message, "severity": "info"})
    return {"status": "sent", "webhook_url": payload.webhook_url}


@app.post("/alerts/configure")
def configure_alert_webhook(payload: AlertWebhookRequest) -> dict[str, Any]:
    global alert_webhook_url
    alert_webhook_url = payload.webhook_url
    return {"status": "configured", "webhook_url": alert_webhook_url}


@app.post("/triage/{pid}")
def auto_triage(pid: int, payload: TriageRequest) -> dict[str, Any]:
    import plugins.ai_analyst as ai_analyst
    import plugins.internals as internals
    import plugins.memory_forensics as memory_forensics
    import plugins.sandbox as sandbox
    import plugins.strings_analyser as strings_analyser
    import plugins.yara_scanner as yara_scanner

    profile = process_intel_service.profile_process(pid)
    exe_path = profile.get("exe")
    strings = strings_analyser.extract_strings(exe_path, payload.strings_min_length)
    hits = strings_analyser.search_patterns(strings, payload.strings_patterns)
    yara_rules = yara_scanner.compile_rules(payload.yara_pack)
    yara_matches = yara_scanner.scan_file(exe_path, yara_rules) if exe_path else []
    trace = sandbox.ProcessTracer(pid).trace(duration=payload.trace_duration, interval=0.5)
    analyst = ai_analyst.AIAnalyst().analyze_process(profile)
    intel = None
    if payload.virustotal_api_key:
        intel = scan_process({"exe": exe_path, "pid": pid, "name": profile.get("name")}, payload.virustotal_api_key)
    return {
        "profile": profile,
        "internals_summary": {"handles": len(internals.get_process_handles(pid)), "modules": len(internals.get_process_libs(pid))},
        "strings": {"total": len(strings), "hits": hits[:25]},
        "yara": {"pack": payload.yara_pack, "matches": yara_matches},
        "sandbox": trace,
        "memory": memory_forensics.run_analysis(pid, profile.get("name", "process")),
        "ai_analyst": analyst,
        "threat_intel": intel,
    }


@app.post("/scenario/run")
def run_scenario(payload: ScenarioRequest) -> dict[str, Any]:
    runner = _load_scenario_runner()
    if runner is None:
        raise HTTPException(status_code=500, detail="Scenario runner unavailable")
    runner.start(payload.profile, int(payload.duration))
    return {"status": "started", "profile": payload.profile, "duration": payload.duration}


@app.get("/network/connections")
def network_connections() -> list[dict[str, Any]]:
    return monitor_core.get_network_connections()


@app.post("/network/sniff")
def network_sniff(payload: SnifferRequest) -> dict[str, Any]:
    import plugins.sniffer as net_sniffer

    if not net_sniffer.SCAPY_AVAILABLE:
        raise HTTPException(status_code=500, detail="Scapy not available for packet capture")
    result = net_sniffer.run_sniffer_session(duration=payload.duration)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@app.get("/artifacts")
def list_artifacts() -> dict[str, str]:
    return _artifact_manifest()


@app.get("/artifacts/{filename}")
def download_artifact(filename: str):
    target = OUT_DIR / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(target)


@app.post("/deception/honeypot/deploy")
def deploy_honeypot(payload: HoneypotRequest) -> dict[str, Any]:
    import plugins.honeypot as honeypot

    global honeypot_instance
    honeypot_instance = honeypot.FileHoneypot(filename=payload.filename)
    ok, message = honeypot_instance.deploy()
    if not ok:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "deployed", "message": message, "filepath": str(honeypot_instance.filepath)}


@app.get("/deception/honeypot/status")
def honeypot_status() -> dict[str, Any]:
    if honeypot_instance is None:
        return {"status": "inactive"}
    return {
        "status": honeypot_instance.check(),
        "filepath": str(honeypot_instance.filepath),
        "active": honeypot_instance.is_active,
    }


@app.delete("/deception/honeypot")
def cleanup_honeypot() -> dict[str, str]:
    global honeypot_instance
    if honeypot_instance is not None:
        honeypot_instance.cleanup()
        honeypot_instance = None
    return {"status": "cleaned"}


@app.post("/deception/canary/deploy")
def deploy_canary() -> dict[str, Any]:
    import plugins.canary as canary

    global canary_instance, canary_alerts
    canary_alerts = []

    def on_alert(message: str) -> None:
        canary_alerts.append(message)

    canary_instance = canary.RansomwareCanary(on_alert)
    created = canary_instance.deploy()
    return {"status": "deployed", "files": created}


@app.get("/deception/canary/status")
def canary_status() -> dict[str, Any]:
    active = canary_instance is not None
    canary_dir = getattr(canary_instance, "canary_dir", None)
    return {
        "active": active,
        "directory": str(canary_dir) if canary_dir else None,
        "alerts": canary_alerts[-20:],
    }


@app.delete("/deception/canary")
def cleanup_canary() -> dict[str, str]:
    global canary_instance, canary_alerts
    if canary_instance is not None:
        canary_instance.cleanup()
        canary_instance = None
    canary_alerts = []
    return {"status": "cleaned"}


@app.post("/evidence/capture")
def capture_evidence(payload: EvidenceRequest) -> dict[str, Any]:
    import plugins.evidence as evidence

    collector = evidence.EvidenceCollector()
    path = collector.capture_screenshot(payload.alert_name)
    if str(path).startswith("Error"):
        raise HTTPException(status_code=500, detail=str(path))
    return {"status": "captured", "path": path}


@app.get("/evidence")
def list_evidence() -> dict[str, Any]:
    import plugins.evidence as evidence

    collector = evidence.EvidenceCollector()
    return {"items": collector.list_evidence()}


@app.delete("/evidence/{filename}")
def delete_evidence(filename: str) -> dict[str, str]:
    target = BASE_DIR / "evidence_locker" / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    target.unlink()
    return {"status": "deleted", "path": str(target)}


@app.post("/network/warfare/scan")
def network_warfare_scan(payload: NetworkScanRequest) -> dict[str, Any]:
    import plugins.net_warfare as net_warfare

    global network_warfare_instance
    network_warfare_instance = network_warfare_instance or net_warfare.NetworkWarfare()
    return {"devices": network_warfare_instance.scan_network(payload.ip_range), "ip_range": payload.ip_range}


@app.post("/network/warfare/block")
def network_warfare_block(payload: BlockerRequest) -> dict[str, Any]:
    import plugins.net_warfare as net_warfare

    global network_warfare_instance
    network_warfare_instance = network_warfare_instance or net_warfare.NetworkWarfare()
    network_warfare_instance.start_blocker(payload.target_ip, payload.gateway_ip)
    return {"status": "started", "target_ip": payload.target_ip, "gateway_ip": payload.gateway_ip}


@app.delete("/network/warfare/block")
def network_warfare_stop() -> dict[str, str]:
    if network_warfare_instance is not None:
        network_warfare_instance.stop_blocker()
    return {"status": "stopped"}


def _write_monitor_artifacts(
    telemetry_rows: list[dict[str, Any]],
    defender_summary: dict[str, Any],
    sysmon_summary: dict[str, Any],
    final: dict[str, Any],
    report_sections: list[str],
    incident,
) -> None:
    with (OUT_DIR / "telemetry.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "ts",
                "cpu",
                "mem_percent",
                "proc_threads",
                "proc_handles",
                "open_files",
                "tcp_conns",
                "bytes_sent_rate",
                "bytes_recv_rate",
                "remote_ips",
            ]
        )
        for row in telemetry_rows:
            writer.writerow(
                [
                    row["ts"],
                    row["cpu"],
                    row["mem_percent"],
                    row["proc_threads"],
                    row["proc_handles"] or "",
                    row["open_files"],
                    row["tcp_conns"],
                    row["bytes_sent_rate"],
                    row["bytes_recv_rate"],
                    row.get("remote_ips", []),
                ]
            )

    (OUT_DIR / "events_defender.json").write_text(json.dumps({"summary": defender_summary}, indent=2), encoding="utf-8")
    (OUT_DIR / "events_sysmon.json").write_text(json.dumps({"summary": sysmon_summary}, indent=2), encoding="utf-8")
    (OUT_DIR / "score.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    artifact_service.write_incident_bundle(incident, final, telemetry_rows)
    generate_pdf(OUT_DIR, author="Ulfat Ibadov", sections=report_sections)


def _artifact_manifest() -> dict[str, str]:
    files = [
        "telemetry.csv",
        "events_defender.json",
        "events_sysmon.json",
        "score.json",
        "incident_bundle.json",
        "ShadowLab_Report.pdf",
    ]
    return {
        name: str(OUT_DIR / name)
        for name in files
        if (OUT_DIR / name).exists()
    }


def _load_scenario_runner():
    try:
        spec = importlib.util.spec_from_file_location("scenario_profiles", BASE_DIR / "plugins" / "scenario_profiles.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module.ScenarioRunner()
    except Exception:
        return None


def _send_webhook_alert(webhook_url: str, payload: dict[str, Any]) -> None:
    import requests

    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass
