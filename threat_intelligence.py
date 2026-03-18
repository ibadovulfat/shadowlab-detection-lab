from __future__ import annotations

import hashlib
import logging
import os
from typing import Any
from urllib.parse import urlparse

import requests

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
    return {
        "process": proc_info.get("name"),
        "pid": proc_info.get("pid"),
        "hash": file_hash,
        "virustotal": vt_result,
        "malwarebazaar": malwarebazaar_result,
        "yaraify": yaraify_result,
    }
