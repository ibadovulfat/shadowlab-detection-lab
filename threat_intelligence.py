from __future__ import annotations

import hashlib
import logging
import os
from typing import Any
from urllib.parse import urlparse

import requests
from plugins import yara_scanner

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
MALWAREBAZAAR_AUTH_KEY = os.environ.get("MALWAREBAZAAR_AUTH_KEY")
YARAIFY_AUTH_KEY = os.environ.get("YARAIFY_AUTH_KEY")
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
YARAIFY_API_URL = "https://yaraify-api.abuse.ch/api/v1/"
logger = logging.getLogger(__name__)
ALLOWED_OUTBOUND_HOSTS = {
    "api.abuseipdb.com",
    "mb-api.abuse.ch",
    "yaraify-api.abuse.ch",
    "www.virustotal.com",
}


def _safe_json(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
        return payload if isinstance(payload, dict) else {}
    except ValueError:
        return {}


def _log_external_request(service: str, method: str, target: str, status: str, detail: str = "") -> None:
    try:
        import database as db

        conn = db.create_connection()
        if conn is None:
            return
        try:
            db.log_external_request(conn, service, method, target, status, detail[:300])
        finally:
            conn.close()
    except Exception:
        return


def _safe_request(
    service: str,
    method: str,
    url: str,
    *,
    allowed_hosts: set[str] | None = None,
    timeout: int = 25,
    **kwargs,
) -> requests.Response:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    approved = allowed_hosts or ALLOWED_OUTBOUND_HOSTS
    if hostname not in approved:
        detail = f"Blocked outbound target: {hostname or 'unknown-host'}"
        _log_external_request(service, method.upper(), url, "blocked", detail)
        raise ValueError(detail)
    try:
        response = requests.request(method.upper(), url, timeout=timeout, **kwargs)
        _log_external_request(service, method.upper(), url, "ok" if response.ok else "http_error", str(response.status_code))
        return response
    except requests.RequestException as exc:
        _log_external_request(service, method.upper(), url, "error", str(exc))
        raise


def check_ip(ip: str) -> dict | None:
    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set. Skipping threat intelligence check.")
        return None

    try:
        response = _safe_request(
            "abuseipdb",
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=20,
        )
        response.raise_for_status()
        return response.json().get("data")
    except requests.exceptions.RequestException as exc:
        logger.error("Error checking IP %s: %s", ip, exc)
        return None


def calculate_file_hash(filepath: str) -> str | None:
    if not filepath:
        return None
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as handle:
            for byte_block in iter(lambda: handle.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def check_file_vt(file_hash: str, api_key: str | None) -> dict[str, Any] | None:
    if not api_key:
        return {"status": "skipped", "reason": "No VirusTotal API key provided"}
    try:
        response = _safe_request(
            "virustotal",
            "GET",
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=25,
        )
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {})
        if response.status_code == 404:
            return {"status": "not_found", "message": "Hash not found in VirusTotal"}
        if response.status_code == 429:
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded"}
        return {"status": "error", "message": f"VirusTotal API Error: {response.status_code}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _abuse_headers(auth_key: str | None, env_value: str | None) -> dict[str, str]:
    key = (auth_key or env_value or "").strip()
    return {"Auth-Key": key} if key else {}


def check_file_malwarebazaar(file_hash: str, auth_key: str | None = None) -> dict[str, Any]:
    headers = _abuse_headers(auth_key, MALWAREBAZAAR_AUTH_KEY)
    if "Auth-Key" not in headers:
        return {"status": "skipped", "reason": "No MalwareBazaar Auth-Key provided"}

    payload = {"query": "get_info", "hash": file_hash}
    try:
        response = _safe_request("malwarebazaar", "POST", MALWAREBAZAAR_API_URL, data=payload, headers=headers, timeout=25)
        result = _safe_json(response)
        if response.status_code == 403:
            return {
                "status": result.get("query_status", "forbidden"),
                "message": result.get("message") or "MalwareBazaar rejected the provided Auth-Key",
            }
        response.raise_for_status()
        if result.get("query_status") == "ok":
            data = result.get("data", [])
            if not data:
                return {"status": "ok", "data": []}
            first_hit = data[0]
            return {
                "status": "ok",
                "sha256_hash": first_hit.get("sha256_hash"),
                "sha3_384_hash": first_hit.get("sha3_384_hash"),
                "file_name": first_hit.get("file_name"),
                "file_type": first_hit.get("file_type"),
                "signature": first_hit.get("signature"),
                "delivery_method": first_hit.get("delivery_method"),
                "tags": first_hit.get("tags", []),
                "first_seen": first_hit.get("first_seen"),
                "reporter": first_hit.get("reporter"),
            }
        return {"status": result.get("query_status", "unknown"), "message": result.get("message")}
    except Exception as exc:
        logger.error("Error querying MalwareBazaar for %s: %s", file_hash, exc)
        return {"status": "error", "message": str(exc)}


def check_file_yaraify(file_hash: str, auth_key: str | None = None) -> dict[str, Any]:
    headers = _abuse_headers(auth_key, YARAIFY_AUTH_KEY)
    if "Auth-Key" not in headers:
        return {"status": "skipped", "reason": "No YARAify Auth-Key provided"}

    headers["Content-Type"] = "application/json"
    payload = {"query": "lookup_hash", "search_term": file_hash}
    try:
        response = _safe_request("yaraify", "POST", YARAIFY_API_URL, json=payload, headers=headers, timeout=25)
        result = _safe_json(response)
        if response.status_code == 403:
            return {
                "status": result.get("query_status", "forbidden"),
                "message": result.get("message") or "YARAify rejected the provided Auth-Key",
            }
        response.raise_for_status()
        if result.get("query_status") == "ok":
            data = result.get("data", {})
            if not data:
                return {"status": "ok", "data": []}
            metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
            yara_results = data.get("yara_rules", []) or data.get("yara_results", []) if isinstance(data, dict) else []
            matched_rules = []
            for item in yara_results[:15]:
                if isinstance(item, dict):
                    rule_name = item.get("rule_name") or item.get("rule") or item.get("name")
                    if rule_name:
                        matched_rules.append(rule_name)
            return {
                "status": "ok",
                "sha256": metadata.get("sha256_hash"),
                "md5": metadata.get("md5_hash"),
                "sha1": metadata.get("sha1_hash"),
                "tlsh": metadata.get("tlsh"),
                "file_type": metadata.get("file_type_mime"),
                "first_seen": metadata.get("first_seen"),
                "last_seen": metadata.get("last_seen"),
                "sightings": metadata.get("sightings"),
                "clamav": data.get("clamav"),
                "yara_rule_count": len(yara_results),
                "matched_rules": matched_rules,
                "yara_results": yara_results[:20],
            }
        return {"status": result.get("query_status", "unknown"), "message": result.get("message")}
    except Exception as exc:
        logger.error("Error querying YARAify for %s: %s", file_hash, exc)
        return {"status": "error", "message": str(exc)}


def run_local_yara_scan(filepath: str, pack: str = "enterprise", context: dict[str, Any] | None = None) -> dict[str, Any]:
    return yara_scanner.scan_file(filepath, pack=pack, context=context)


def _should_run_local_yara(yaraify_result: dict[str, Any] | None) -> bool:
    if not isinstance(yaraify_result, dict):
        return True
    status = str(yaraify_result.get("status", "")).lower()
    if status in {"error", "skipped", "forbidden", "not_found", "unknown", "missing", "unavailable"}:
        return True
    if status != "ok":
        return True
    return int(yaraify_result.get("yara_rule_count", 0) or 0) <= 0 and not yaraify_result.get("matched_rules")


def _normalized_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def fuse_detection_verdict(
    *,
    yaraify_result: dict[str, Any] | None = None,
    local_yara_result: dict[str, Any] | None = None,
    virustotal_result: dict[str, Any] | None = None,
    malwarebazaar_result: dict[str, Any] | None = None,
    memory_result: dict[str, Any] | None = None,
    behavior_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    if isinstance(yaraify_result, dict) and _normalized_status(yaraify_result.get("status")) == "ok":
        yaraify_hits = len(yaraify_result.get("matched_rules", []) or [])
        if yaraify_hits:
            addition = min(35, 15 + (yaraify_hits * 3))
            score += addition
            reasons.append(f"YARAify matched {yaraify_hits} rule(s).")

    if isinstance(local_yara_result, dict):
        local_score = int(local_yara_result.get("score", 0) or 0)
        local_hits = int(local_yara_result.get("active_match_count", local_yara_result.get("match_count", 0)) or 0)
        suppressed_hits = int(local_yara_result.get("suppressed_match_count", 0) or 0)
        if local_hits:
            addition = min(40, 10 + int(local_score * 0.45))
            score += addition
            reasons.append(f"Local YARA matched {local_hits} rule(s) with {local_yara_result.get('confidence', 'low')} confidence.")
        if suppressed_hits:
            reasons.append(f"Suppressed {suppressed_hits} lower-confidence local YARA match(es) via allowlist.")

    if isinstance(malwarebazaar_result, dict) and _normalized_status(malwarebazaar_result.get("status")) == "ok":
        score += 20
        signature = malwarebazaar_result.get("signature")
        reasons.append(f"MalwareBazaar returned a known sample{' (' + str(signature) + ')' if signature else ''}.")

    if isinstance(virustotal_result, dict):
        stats = (virustotal_result.get("last_analysis_stats") or {}) if isinstance(virustotal_result, dict) else {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious or suspicious:
            vt_score = min(25, malicious * 3 + suspicious * 2)
            score += vt_score
            reasons.append(f"VirusTotal reported malicious={malicious}, suspicious={suspicious}.")

    if isinstance(memory_result, dict):
        analysis = memory_result.get("analysis", {}) if isinstance(memory_result.get("analysis"), dict) else memory_result
        memory_yara = analysis.get("memory_yara", {}) if isinstance(analysis.get("memory_yara"), dict) else {}
        if memory_yara.get("match_count"):
            score += min(30, 12 + int(memory_yara.get("score", 0) * 0.3))
            reasons.append(f"Memory YARA matched {memory_yara.get('match_count', 0)} rule(s).")
        severity = _normalized_status(analysis.get("severity"))
        if severity == "critical":
            score += 25
            reasons.append("Memory analysis found critical stealth or injection artefacts.")
        elif severity == "high":
            score += 15
            reasons.append("Memory analysis found high-severity injection artefacts.")

    if isinstance(behavior_result, dict):
        likelihood = float(behavior_result.get("likelihood", 0.0) or 0.0)
        if likelihood > 0:
            addition = min(30, int(likelihood * 25))
            score += addition
            reasons.append(f"Behavioral engine likelihood={likelihood:.2f}.")

    final_score = max(0, min(100, score))
    return {
        "score": final_score,
        "severity": _severity_from_score(final_score),
        "confidence": "high" if final_score >= 75 else "medium" if final_score >= 45 else "low",
        "reasons": reasons,
    }


def scan_process(
    proc_info: dict[str, Any],
    virustotal_api_key: str | None = None,
    malwarebazaar_auth_key: str | None = None,
    yaraify_auth_key: str | None = None,
) -> dict[str, Any]:
    exe_path = proc_info.get("exe")
    if not exe_path:
        return {"status": "skipped", "reason": "No executable path"}

    file_hash = calculate_file_hash(exe_path)
    if not file_hash:
        return {"status": "skipped", "reason": "Could not hash file"}

    vt_result = check_file_vt(file_hash, virustotal_api_key)
    malwarebazaar_result = check_file_malwarebazaar(file_hash, malwarebazaar_auth_key)
    yaraify_result = check_file_yaraify(file_hash, yaraify_auth_key)
    if _should_run_local_yara(yaraify_result):
        local_yara_result = run_local_yara_scan(
            exe_path,
            context={
                "sha256": file_hash,
                "signature_status": proc_info.get("signature_status", ""),
                "filepath": exe_path,
            },
        )
    else:
        local_yara_result = {
            "status": "skipped",
            "reason": "YARAify already returned matches",
            "matches": [],
        }
    fusion = fuse_detection_verdict(
        yaraify_result=yaraify_result,
        local_yara_result=local_yara_result,
        virustotal_result=vt_result,
        malwarebazaar_result=malwarebazaar_result,
    )
    return {
        "process": proc_info.get("name"),
        "pid": proc_info.get("pid"),
        "path": exe_path,
        "hash": file_hash,
        "virustotal": vt_result,
        "malwarebazaar": malwarebazaar_result,
        "yaraify": yaraify_result,
        "local_yara": local_yara_result,
        "fusion": fusion,
    }
