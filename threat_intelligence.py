"""Threat-intelligence client + free-function compat layer.

Historically every check was a free function reading keys directly from
`os.environ` at module import time. That made the keys impossible to
override per-request, impossible to rotate without a process restart, and
impossible to unit-test without monkey-patching module globals.

This module now exposes:

* `ThreatIntelClient` — a class that owns the API keys, the outbound host
  allowlist, and a `requests.Session` (reused across calls to amortize
  TLS). Callers who need custom keys (e.g. a tenant-specific VirusTotal
  tier) instantiate their own client.
* Module-level `check_ip`, `check_file_vt`, ... — thin wrappers that
  delegate to a process-wide default client built from environment
  variables. Preserved verbatim so existing call sites (and the test
  suite's `mock.patch.object(threat_intelligence, "check_file_vt", ...)`
  pattern) keep working without churn.

Adding a new provider now means adding one method on the class, not a
new module-level function that has to re-derive keys from `os.environ`.
"""
from __future__ import annotations

from functools import lru_cache
from copy import deepcopy
import hashlib
import logging
import os
import random
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from plugins import yara_scanner
from services.malware_analyst_service import MalwareAnalystService

# Environment-sourced defaults. Read once at import time for backward
# compatibility — module-level functions still honour these. The class
# constructor accepts overrides, so runtime rotation is possible via a
# fresh client.
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
    "www.hybrid-analysis.com",
}
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _safe_json(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
        return payload if isinstance(payload, dict) else {}
    except ValueError:
        return {}


def _log_external_request(service: str, method: str, target: str, status: str, detail: str = "") -> None:
    """Best-effort audit trail for every outbound TI request.

    Silent on failure by design — the call sites treat intelligence as
    optional enrichment, and an audit-log blip must not break detection.
    """
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


def calculate_file_hash(filepath: str) -> str | None:
    """Stream-hash a file to SHA-256. Returns None on any error."""
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


def _abuse_headers(auth_key: str | None, env_value: str | None) -> dict[str, str]:
    key = (auth_key or env_value or "").strip()
    return {"Auth-Key": key} if key else {}


@lru_cache(maxsize=1)
def _malware_analyst_service() -> MalwareAnalystService:
    return MalwareAnalystService(Path(__file__).resolve().parent)


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


def _should_run_local_yara(yaraify_result: dict[str, Any] | None) -> bool:
    if not isinstance(yaraify_result, dict):
        return True
    status = str(yaraify_result.get("status", "")).lower()
    if status in {"error", "skipped", "forbidden", "not_found", "unknown", "missing", "unavailable"}:
        return True
    if status != "ok":
        return True
    return int(yaraify_result.get("yara_rule_count", 0) or 0) <= 0 and not yaraify_result.get("matched_rules")


class ThreatIntelClient:
    """Stateful client for external threat-intelligence services.

    Instance attributes:
        abuseipdb_api_key, malwarebazaar_auth_key, yaraify_auth_key —
            provider credentials. Fall back to env vars when unset.
        allowed_outbound_hosts — SSRF allowlist. Any outbound host not in
            this set is rejected BEFORE the socket is opened, and the
            attempt is audited so operators can spot misconfigured
            integrations.
        session — a `requests.Session` for connection reuse. Swap in a
            MagicMock for offline tests.
    """

    def __init__(
        self,
        *,
        abuseipdb_api_key: str | None = None,
        malwarebazaar_auth_key: str | None = None,
        yaraify_auth_key: str | None = None,
        allowed_outbound_hosts: set[str] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.abuseipdb_api_key = abuseipdb_api_key if abuseipdb_api_key is not None else ABUSEIPDB_API_KEY
        self.malwarebazaar_auth_key = malwarebazaar_auth_key if malwarebazaar_auth_key is not None else MALWAREBAZAAR_AUTH_KEY
        self.yaraify_auth_key = yaraify_auth_key if yaraify_auth_key is not None else YARAIFY_AUTH_KEY
        self.allowed_outbound_hosts = set(allowed_outbound_hosts) if allowed_outbound_hosts is not None else set(ALLOWED_OUTBOUND_HOSTS)
        self._session = session
        self._cache_lock = threading.Lock()
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._circuit_lock = threading.Lock()
        self._circuit_failures: dict[str, list[float]] = {}
        self._circuit_open_until: dict[str, float] = {}
        self._cache_ttl_seconds = max(0, int(os.environ.get("SHADOWLAB_TI_CACHE_TTL_SECONDS", "900") or 900))
        self._max_retries = max(0, min(int(os.environ.get("SHADOWLAB_TI_MAX_RETRIES", "2") or 2), 6))
        self._retry_backoff_seconds = max(0.05, float(os.environ.get("SHADOWLAB_TI_RETRY_BACKOFF_SECONDS", "0.4") or 0.4))
        self._retry_jitter_seconds = max(0.0, float(os.environ.get("SHADOWLAB_TI_RETRY_JITTER_SECONDS", "0.25") or 0.25))
        self._circuit_threshold = max(1, int(os.environ.get("SHADOWLAB_TI_CIRCUIT_THRESHOLD", "5") or 5))
        self._circuit_window_seconds = max(5, int(os.environ.get("SHADOWLAB_TI_CIRCUIT_WINDOW_SECONDS", "60") or 60))
        self._circuit_open_seconds = max(5, int(os.environ.get("SHADOWLAB_TI_CIRCUIT_OPEN_SECONDS", "60") or 60))

    # ------------------------------------------------------------------
    # Networking primitive
    # ------------------------------------------------------------------

    def _safe_request(
        self,
        service: str,
        method: str,
        url: str,
        *,
        allowed_hosts: set[str] | None = None,
        timeout: int = 25,
        **kwargs,
    ) -> requests.Response:
        """Enforce the outbound-host allowlist, then log+issue the request."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        approved = allowed_hosts or self.allowed_outbound_hosts
        if hostname not in approved:
            detail = f"Blocked outbound target: {hostname or 'unknown-host'}"
            _log_external_request(service, method.upper(), url, "blocked", detail)
            raise ValueError(detail)
        if self._is_circuit_open(service):
            detail = f"{service} circuit breaker is open"
            _log_external_request(service, method.upper(), url, "circuit_open", detail)
            raise RuntimeError(detail)
        requester = self._session.request if self._session is not None else requests.request
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = requester(method.upper(), url, timeout=timeout, **kwargs)
                code = int(response.status_code or 0)
                if code in RETRYABLE_STATUS_CODES and attempt < self._max_retries:
                    _log_external_request(
                        service,
                        method.upper(),
                        url,
                        "retry",
                        f"http_{code} attempt={attempt + 1}",
                    )
                    self._sleep_before_retry(attempt)
                    continue
                if response.ok:
                    self._record_success(service)
                    _log_external_request(service, method.upper(), url, "ok", str(code))
                else:
                    if code in RETRYABLE_STATUS_CODES:
                        self._record_failure(service)
                    _log_external_request(service, method.upper(), url, "http_error", str(code))
                return response
            except requests.RequestException as exc:
                last_error = exc
                if attempt < self._max_retries:
                    _log_external_request(
                        service,
                        method.upper(),
                        url,
                        "retry",
                        f"exception attempt={attempt + 1} detail={exc}",
                    )
                    self._sleep_before_retry(attempt)
                    continue
                self._record_failure(service)
                _log_external_request(service, method.upper(), url, "error", str(exc))
                raise
        if last_error is not None:
            raise last_error
        raise RuntimeError("Threat-intelligence request failed unexpectedly")

    def _sleep_before_retry(self, attempt: int) -> None:
        base = self._retry_backoff_seconds * (2 ** attempt)
        jitter = random.uniform(0.0, self._retry_jitter_seconds)
        time.sleep(base + jitter)

    def _is_circuit_open(self, service: str) -> bool:
        now = time.time()
        with self._circuit_lock:
            open_until = float(self._circuit_open_until.get(service, 0.0) or 0.0)
            if open_until and now < open_until:
                return True
            if open_until and now >= open_until:
                self._circuit_open_until[service] = 0.0
        return False

    def _record_failure(self, service: str) -> None:
        now = time.time()
        cutoff = now - float(self._circuit_window_seconds)
        with self._circuit_lock:
            failures = [ts for ts in self._circuit_failures.get(service, []) if ts >= cutoff]
            failures.append(now)
            self._circuit_failures[service] = failures
            if len(failures) >= self._circuit_threshold:
                self._circuit_open_until[service] = now + float(self._circuit_open_seconds)
                self._circuit_failures[service] = []

    def _record_success(self, service: str) -> None:
        with self._circuit_lock:
            self._circuit_failures[service] = []
            self._circuit_open_until[service] = 0.0

    def _cache_get(self, cache_key: str) -> dict[str, Any] | None:
        if self._cache_ttl_seconds <= 0:
            return None
        now = time.time()
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if not cached:
                return None
            expires_at, payload = cached
            if now >= float(expires_at):
                self._cache.pop(cache_key, None)
                return None
            return deepcopy(payload)

    def _cache_set(self, cache_key: str, payload: dict[str, Any]) -> None:
        if self._cache_ttl_seconds <= 0:
            return
        with self._cache_lock:
            self._cache[cache_key] = (time.time() + float(self._cache_ttl_seconds), deepcopy(payload))

    def _credential_marker(self, value: str | None) -> str:
        token = str(value or "").strip()
        if not token:
            return "none"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]

    # ------------------------------------------------------------------
    # Providers
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> dict | None:
        """Query AbuseIPDB. Returns None if the API key is missing or the call fails."""
        if not self.abuseipdb_api_key:
            logger.warning("ABUSEIPDB_API_KEY not set. Skipping threat intelligence check.")
            return None
        try:
            response = self._safe_request(
                "abuseipdb",
                "GET",
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Accept": "application/json", "Key": self.abuseipdb_api_key},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=20,
            )
            response.raise_for_status()
            return response.json().get("data")
        except requests.exceptions.RequestException as exc:
            logger.error("Error checking IP %s: %s", ip, exc)
            return None

    def check_file_vt(self, file_hash: str, api_key: str | None = None) -> dict[str, Any] | None:
        """VirusTotal hash lookup. `api_key` is passed explicitly because VT keys
        are often per-request (different analyst tiers) rather than per-client."""
        if not api_key:
            return {"status": "skipped", "reason": "No VirusTotal API key provided"}
        cache_key = f"vt:{str(file_hash).lower()}:{self._credential_marker(api_key)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            response = self._safe_request(
                "virustotal",
                "GET",
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": api_key},
                timeout=25,
            )
            if response.status_code == 200:
                result = response.json().get("data", {}).get("attributes", {})
                if isinstance(result, dict):
                    self._cache_set(cache_key, result)
                return result
            if response.status_code == 404:
                result = {"status": "not_found", "message": "Hash not found in VirusTotal"}
                self._cache_set(cache_key, result)
                return result
            if response.status_code == 429:
                return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded"}
            return {"status": "error", "message": f"VirusTotal API Error: {response.status_code}"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def check_file_malwarebazaar(self, file_hash: str, auth_key: str | None = None) -> dict[str, Any]:
        headers = _abuse_headers(auth_key, self.malwarebazaar_auth_key)
        if "Auth-Key" not in headers:
            return {"status": "skipped", "reason": "No MalwareBazaar Auth-Key provided"}
        effective_key = auth_key or self.malwarebazaar_auth_key
        cache_key = f"mb:{str(file_hash).lower()}:{self._credential_marker(effective_key)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        payload = {"query": "get_info", "hash": file_hash}
        try:
            response = self._safe_request(
                "malwarebazaar", "POST", MALWAREBAZAAR_API_URL, data=payload, headers=headers, timeout=25
            )
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
                    empty = {"status": "ok", "data": []}
                    self._cache_set(cache_key, empty)
                    return empty
                first_hit = data[0]
                normalized = {
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
                self._cache_set(cache_key, normalized)
                return normalized
            fallback = {"status": result.get("query_status", "unknown"), "message": result.get("message")}
            if _normalized_status(fallback.get("status")) in {"hash_not_found", "not_found", "no_results", "ok"}:
                self._cache_set(cache_key, fallback)
            return fallback
        except Exception as exc:
            logger.error("Error querying MalwareBazaar for %s: %s", file_hash, exc)
            return {"status": "error", "message": str(exc)}

    def check_file_yaraify(self, file_hash: str, auth_key: str | None = None) -> dict[str, Any]:
        headers = _abuse_headers(auth_key, self.yaraify_auth_key)
        if "Auth-Key" not in headers:
            return {"status": "skipped", "reason": "No YARAify Auth-Key provided"}
        effective_key = auth_key or self.yaraify_auth_key
        cache_key = f"yaraify:{str(file_hash).lower()}:{self._credential_marker(effective_key)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        headers["Content-Type"] = "application/json"
        payload = {"query": "lookup_hash", "search_term": file_hash}
        try:
            response = self._safe_request(
                "yaraify", "POST", YARAIFY_API_URL, json=payload, headers=headers, timeout=25
            )
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
                    empty = {"status": "ok", "data": []}
                    self._cache_set(cache_key, empty)
                    return empty
                metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
                yara_results = data.get("yara_rules", []) or data.get("yara_results", []) if isinstance(data, dict) else []
                matched_rules = []
                for item in yara_results[:15]:
                    if isinstance(item, dict):
                        rule_name = item.get("rule_name") or item.get("rule") or item.get("name")
                        if rule_name:
                            matched_rules.append(rule_name)
                normalized = {
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
                self._cache_set(cache_key, normalized)
                return normalized
            fallback = {"status": result.get("query_status", "unknown"), "message": result.get("message")}
            if _normalized_status(fallback.get("status")) in {"hash_not_found", "not_found", "no_results", "ok"}:
                self._cache_set(cache_key, fallback)
            return fallback
        except Exception as exc:
            logger.error("Error querying YARAify for %s: %s", file_hash, exc)
            return {"status": "error", "message": str(exc)}

    def check_file_hybrid_analysis(self, file_hash: str, api_key: str | None = None) -> dict[str, Any]:
        """Hybrid-Analysis cloud sandbox hash lookup.

        Endpoint: POST https://www.hybrid-analysis.com/api/v2/search/hash
        Auth: api-key header (free tier at hybrid-analysis.com).
        Submits only the hash — no file body — and surfaces verdict,
        threat-score, MITRE-ATT&CK techniques, and submission name.
        """
        effective_key = (api_key or os.environ.get("HYBRID_ANALYSIS_API_KEY", "") or "").strip()
        if not effective_key:
            return {"status": "skipped", "reason": "No Hybrid-Analysis API key provided"}
        cache_key = f"hybridanalysis:{str(file_hash).lower()}:{self._credential_marker(effective_key)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        headers = {
            "api-key": effective_key,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = self._safe_request(
                "hybrid_analysis",
                "POST",
                "https://www.hybrid-analysis.com/api/v2/search/hash",
                headers=headers,
                data={"hash": file_hash},
                timeout=30,
            )
            if response.status_code == 401 or response.status_code == 403:
                return {"status": "forbidden", "message": "Hybrid-Analysis rejected the API key"}
            if response.status_code == 429:
                return {"status": "rate_limited", "message": "Hybrid-Analysis rate limit exceeded"}
            if response.status_code == 404:
                empty = {"status": "not_found", "message": "Hash unknown to Hybrid-Analysis"}
                self._cache_set(cache_key, empty)
                return empty
            response.raise_for_status()
            payload = response.json() if response.content else []
            entries = payload if isinstance(payload, list) else []
            if not entries:
                empty = {"status": "no_results", "reports": []}
                self._cache_set(cache_key, empty)
                return empty
            entries.sort(key=lambda item: int((item or {}).get("threat_score") or 0), reverse=True)
            top = entries[0]
            normalized = {
                "status": "ok",
                "verdict": top.get("verdict") or top.get("threat_level_human") or "",
                "threat_score": int(top.get("threat_score") or 0),
                "threat_level": int(top.get("threat_level") or 0),
                "av_detect": int(top.get("av_detect") or 0),
                "vx_family": top.get("vx_family") or top.get("classification_tags", []),
                "submission_name": top.get("submit_name") or top.get("submitname") or "",
                "environment_description": top.get("environment_description", ""),
                "analysis_start_time": top.get("analysis_start_time") or top.get("analysis_started_at"),
                "mitre_attcks": top.get("mitre_attcks") or top.get("mitre_attck") or [],
                "compromised_hosts": top.get("compromised_hosts", []),
                "domains": top.get("domains", []),
                "hosts": top.get("hosts", []),
                "report_count": len(entries),
                "reports": entries[:5],
            }
            self._cache_set(cache_key, normalized)
            return normalized
        except Exception as exc:
            logger.error("Error querying Hybrid-Analysis for %s: %s", file_hash, exc)
            return {"status": "error", "message": str(exc)}

    # ------------------------------------------------------------------
    # Local (non-network) analyzers — delegate to plugins/services
    # ------------------------------------------------------------------

    def run_local_yara_scan(
        self,
        filepath: str,
        pack: str = "enterprise",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return yara_scanner.scan_file(filepath, pack=pack, context=context)

    def run_static_pe_analysis(self, filepath: str) -> dict[str, Any]:
        if not filepath:
            return {"status": "skipped", "summary": "No executable path provided for static PE analysis."}
        result = _malware_analyst_service().analyze_file(filepath)
        die_static = result.get("static_analysis", {}) if isinstance(result.get("static_analysis"), dict) else {}
        pe_structure = result.get("pe_structure", {}) if isinstance(result.get("pe_structure"), dict) else {}
        pe_risk = pe_structure.get("risk", {}) if isinstance(pe_structure.get("risk"), dict) else {}
        combined_score = min(100, int(die_static.get("score", 0) or 0) + int(pe_risk.get("score", 0) or 0))
        result["combined_static"] = {
            "score": combined_score,
            "confidence": "high" if combined_score >= 55 else "medium" if combined_score >= 25 else "low",
            "severity": "critical" if combined_score >= 75 else "high" if combined_score >= 50 else "medium" if combined_score >= 25 else "low",
            "verdict": "suspicious" if combined_score >= 25 else "informational",
            "suspicious_indicators": list(die_static.get("suspicious_indicators", []) or []) + list(pe_risk.get("reasons", []) or []),
        }
        return result

    # ------------------------------------------------------------------
    # Verdict fusion + process scan
    # ------------------------------------------------------------------

    def fuse_detection_verdict(
        self,
        *,
        yaraify_result: dict[str, Any] | None = None,
        local_yara_result: dict[str, Any] | None = None,
        virustotal_result: dict[str, Any] | None = None,
        malwarebazaar_result: dict[str, Any] | None = None,
        static_result: dict[str, Any] | None = None,
        memory_result: dict[str, Any] | None = None,
        behavior_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Combine signals from the various providers into a single verdict."""
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
                reasons.append(
                    f"Local YARA matched {local_hits} rule(s) with {local_yara_result.get('confidence', 'low')} confidence."
                )
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

        if isinstance(static_result, dict):
            static_analysis = static_result.get("combined_static", {}) if isinstance(static_result.get("combined_static"), dict) else {}
            if not static_analysis:
                static_analysis = static_result.get("static_analysis", {}) if isinstance(static_result.get("static_analysis"), dict) else {}
            static_score = int(static_analysis.get("score", 0) or 0)
            static_indicators = static_analysis.get("suspicious_indicators", []) if isinstance(static_analysis.get("suspicious_indicators"), list) else []
            if static_score > 0 and static_indicators:
                addition = min(30, 8 + int(static_score * 0.4))
                score += addition
                reasons.append(
                    f"Static PE analysis found {len(static_indicators)} suspicious indicator(s) with {static_analysis.get('confidence', 'low')} confidence."
                )

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
        self,
        proc_info: dict[str, Any],
        virustotal_api_key: str | None = None,
        malwarebazaar_auth_key: str | None = None,
        yaraify_auth_key: str | None = None,
    ) -> dict[str, Any]:
        """End-to-end scan: hash the executable, fan out to providers, fuse.

        Uses module-level provider functions (`check_file_vt`, etc.) rather
        than the bound methods so that tests which patch
        `threat_intelligence.check_file_vt` at module level still intercept
        the call — `mock.patch.object(threat_intelligence, "check_file_vt",
        ...)` is the dominant patch pattern in the existing test suite.
        """
        exe_path = proc_info.get("exe")
        if not exe_path:
            return {"status": "skipped", "reason": "No executable path"}

        file_hash = calculate_file_hash(exe_path)
        if not file_hash:
            return {"status": "skipped", "reason": "Could not hash file"}

        vt_result = check_file_vt(file_hash, virustotal_api_key)
        malwarebazaar_result = check_file_malwarebazaar(file_hash, malwarebazaar_auth_key)
        yaraify_result = check_file_yaraify(file_hash, yaraify_auth_key)
        static_result = run_static_pe_analysis(exe_path)
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
            static_result=static_result,
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
            "static_pe": static_result,
            "fusion": fusion,
        }


# ---------------------------------------------------------------------------
# Process-wide default client + module-level compat wrappers
# ---------------------------------------------------------------------------
#
# Every existing caller (api/main.py, desktop/*, tests/*) imports names like
# `threat_intelligence.check_file_vt` directly. Keep those as free functions
# that delegate to a shared default client so the refactor lands without
# touching any call site. Tests can still `mock.patch.object(threat_intelligence,
# "check_file_vt", ...)` and the class's `scan_process` will pick it up
# because the class also calls the module-level function.

default_client = ThreatIntelClient()


def _safe_request(
    service: str,
    method: str,
    url: str,
    *,
    allowed_hosts: set[str] | None = None,
    timeout: int = 25,
    **kwargs,
) -> requests.Response:
    return default_client._safe_request(
        service, method, url, allowed_hosts=allowed_hosts, timeout=timeout, **kwargs
    )


def check_ip(ip: str) -> dict | None:
    return default_client.check_ip(ip)


def check_file_vt(file_hash: str, api_key: str | None) -> dict[str, Any] | None:
    return default_client.check_file_vt(file_hash, api_key)


def check_file_malwarebazaar(file_hash: str, auth_key: str | None = None) -> dict[str, Any]:
    return default_client.check_file_malwarebazaar(file_hash, auth_key)


def check_file_yaraify(file_hash: str, auth_key: str | None = None) -> dict[str, Any]:
    return default_client.check_file_yaraify(file_hash, auth_key)


def run_local_yara_scan(
    filepath: str, pack: str = "enterprise", context: dict[str, Any] | None = None
) -> dict[str, Any]:
    return default_client.run_local_yara_scan(filepath, pack=pack, context=context)


def run_static_pe_analysis(filepath: str) -> dict[str, Any]:
    return default_client.run_static_pe_analysis(filepath)


def fuse_detection_verdict(
    *,
    yaraify_result: dict[str, Any] | None = None,
    local_yara_result: dict[str, Any] | None = None,
    virustotal_result: dict[str, Any] | None = None,
    malwarebazaar_result: dict[str, Any] | None = None,
    static_result: dict[str, Any] | None = None,
    memory_result: dict[str, Any] | None = None,
    behavior_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return default_client.fuse_detection_verdict(
        yaraify_result=yaraify_result,
        local_yara_result=local_yara_result,
        virustotal_result=virustotal_result,
        malwarebazaar_result=malwarebazaar_result,
        static_result=static_result,
        memory_result=memory_result,
        behavior_result=behavior_result,
    )


def scan_process(
    proc_info: dict[str, Any],
    virustotal_api_key: str | None = None,
    malwarebazaar_auth_key: str | None = None,
    yaraify_auth_key: str | None = None,
) -> dict[str, Any]:
    return default_client.scan_process(
        proc_info,
        virustotal_api_key=virustotal_api_key,
        malwarebazaar_auth_key=malwarebazaar_auth_key,
        yaraify_auth_key=yaraify_auth_key,
    )
