"""Threat intelligence + malware analyst routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request

from api.schemas import MalwareAnalystFileRequest, ThreatHashLookupRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    validated_ip_address = ctx["_validated_ip_address"]
    validated_sha256 = ctx["_validated_sha256"]
    check_ip = ctx["check_ip"]
    check_file_malwarebazaar = ctx["check_file_malwarebazaar"]
    check_file_yaraify = ctx["check_file_yaraify"]
    check_file_vt = ctx["check_file_vt"]
    malware_analyst_service = ctx["malware_analyst_service"]

    # Role gate: every other intel route in the codebase (malware
    # analyst, persistence, hunt) requires analyst-or-admin. Without
    # the same `Depends(require_analyst_or_admin)` here, a viewer (or
    # any unauthenticated principal in `SHADOWLAB_REQUIRE_AUTH=false`
    # mode) can drive arbitrary outbound lookups to VirusTotal /
    # MalwareBazaar / YARAify — burning quota, scanning the operator's
    # network from inside, and on the POST variant supplying
    # attacker-controlled API keys whose responses are echoed back.
    @app.get("/threat-intel/ip/{ip}", dependencies=[Depends(require_analyst_or_admin)])
    def threat_intel_lookup(request: Request, ip: str) -> dict[str, Any]:
        apply_rate_limit(request, bucket="threat_intel", detail="Too many threat-intelligence lookups. Wait briefly and retry.")
        ip = validated_ip_address(ip)
        result = check_ip(ip)
        return {"ip": ip, "result": result}

    @app.get("/threat-intel/hash/{file_hash}", dependencies=[Depends(require_analyst_or_admin)])
    def threat_hash_lookup(request: Request, file_hash: str) -> dict[str, Any]:
        apply_rate_limit(request, bucket="threat_intel", detail="Too many threat-intelligence lookups. Wait briefly and retry.")
        file_hash = validated_sha256(file_hash)
        return {
            "hash": file_hash,
            "malwarebazaar": check_file_malwarebazaar(file_hash),
            "yaraify": check_file_yaraify(file_hash),
        }

    @app.post("/threat-intel/hash/lookup", dependencies=[Depends(require_analyst_or_admin)])
    def threat_hash_lookup_with_auth(request: Request, payload: ThreatHashLookupRequest) -> dict[str, Any]:
        apply_rate_limit(request, bucket="threat_intel", detail="Too many threat-intelligence lookups. Wait briefly and retry.")
        return {
            "hash": payload.file_hash,
            "malwarebazaar": check_file_malwarebazaar(payload.file_hash, payload.malwarebazaar_auth_key),
            "yaraify": check_file_yaraify(payload.file_hash, payload.yaraify_auth_key),
            "virustotal": check_file_vt(payload.file_hash, payload.virustotal_api_key),
        }

    @app.get("/malware-analyst/status", dependencies=[Depends(require_analyst_or_admin)])
    def malware_analyst_status() -> dict[str, Any]:
        return malware_analyst_service.status()

    @app.post("/malware-analyst/file", dependencies=[Depends(require_analyst_or_admin)])
    def malware_analyst_file(payload: MalwareAnalystFileRequest) -> dict[str, Any]:
        return malware_analyst_service.analyze_file(payload.file_path)

    @app.get("/malware-analyst/processes/{pid}", dependencies=[Depends(require_analyst_or_admin)])
    def malware_analyst_process(pid: int) -> dict[str, Any]:
        return malware_analyst_service.analyze_process(pid)
