"""Cloud threat-intelligence provider for the antivirus pipeline.

Real commercial antivirus products never rely on local signatures
alone; they pivot every scan against cloud reputation feeds. This
provider plugs three production feeds into the ShadowLab fused verdict:

  * MalwareBazaar — abuse.ch's malware-sample feed. Returns structured
    hit records (signature family, first-seen, reporter, delivery
    method) when a SHA-256 is known malware.
    Endpoint: POST https://mb-api.abuse.ch/api/v1/
    Auth: Auth-Key header (free registration at auth.abuse.ch)

  * YARAify — abuse.ch's YARA-hit feed. For any hash, returns which
    community / commercial YARA rules matched, plus ClamAV signature
    matches and file metadata.
    Endpoint: POST https://yaraify-api.abuse.ch/api/v1/
    Auth: Auth-Key header (free at auth.abuse.ch)

  * VirusTotal v3 — the industry-standard multi-vendor aggregator.
    Returns per-vendor votes (malicious / suspicious / undetected).
    Endpoint: GET https://www.virustotal.com/api/v3/files/{sha256}
    Auth: x-apikey header (free tier at virustotal.com)

None of these are mocked. The `ThreatIntelClient` this provider wraps
enforces the outbound-host allowlist, caches verdicts by hash, and has
a circuit breaker so provider outages degrade gracefully. Missing API
keys return `status: skipped` with a plain-text reason — the provider
stays online, it just contributes nothing to the fused verdict that
scan.
"""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Any

from .base import AntivirusProvider


class CloudIntelProvider(AntivirusProvider):
    provider_key = "cloud_intel"
    display_name = "Cloud Intel"

    def __init__(self, base_dir: Path, *, client_factory=None):
        self.base_dir = Path(base_dir)
        self._client_factory = client_factory
        self._client_lock = threading.Lock()
        self._client = None

    def _get_client(self):
        with self._client_lock:
            if self._client is not None:
                return self._client
            if self._client_factory is not None:
                self._client = self._client_factory()
                return self._client
            # Lazy import avoids pulling the heavy threat_intelligence
            # module at provider construction time in lab / offline
            # test runs.
            from threat_intelligence import ThreatIntelClient  # local import by design
            self._client = ThreatIntelClient()
            return self._client

    def status(self) -> dict[str, Any]:
        """Surface which cloud feeds are wired without talking to the network."""
        from .credentials import resolve_credential
        mb_key = resolve_credential("malwarebazaar")
        yaraify_key = resolve_credential("yaraify")
        vt_key = resolve_credential("virustotal")
        feeds_configured = sum(1 for value in [mb_key, yaraify_key, vt_key] if value)
        return {
            "display_name": self.display_name,
            "available": feeds_configured > 0,
            "version": "cloud-v1",
            "feeds": {
                "malwarebazaar": bool(mb_key),
                "yaraify": bool(yaraify_key),
                "virustotal": bool(vt_key),
            },
            "feeds_configured": feeds_configured,
            "latest_signature_update": 0.0,
            "mode": "cloud-reputation",
            "endpoints": {
                "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
                "yaraify": "https://yaraify-api.abuse.ch/api/v1/",
                "virustotal": "https://www.virustotal.com/api/v3/files/{sha256}",
            },
            "notes": [
                "Queries are keyed by SHA-256; no file body is uploaded.",
                "Missing API keys produce skipped sub-feeds, not errors.",
                "Outbound hosts are pinned by ThreatIntelClient's allowlist.",
            ],
        }

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        timeout_seconds = max(10, int(policy.get("scan_timeout_seconds", 90) or 90))
        sha256 = self._hash_file(Path(path))
        if not sha256:
            return {
                "status": "error",
                "engine": self.display_name,
                "error": "Failed to hash file for cloud lookup",
            }
        if self.status().get("feeds_configured", 0) == 0:
            return {
                "status": "skipped",
                "engine": self.display_name,
                "error": "No cloud feed API keys configured. Paste them in Advanced Hunt → VirusTotal / MalwareBazaar / YARAify, or export the matching env vars before launch.",
            }
        from .credentials import resolve_credential
        client = self._get_client()
        hits: dict[str, Any] = {}
        errors: list[str] = []
        # Pull every key fresh on each scan so the desktop's
        # "paste-then-rescan" workflow takes effect immediately —
        # otherwise the ThreatIntelClient instance would keep using the
        # snapshot it captured at module import time.
        mb_key = resolve_credential("malwarebazaar")
        yaraify_key = resolve_credential("yaraify")
        vt_key = resolve_credential("virustotal")
        score = 0
        findings: list[str] = []

        # MalwareBazaar — escalate ONLY when MB returns a real malware-
        # family attribution (the `signature` field). A bare hash match
        # without a family is metadata, not a verdict: legitimate
        # samples occasionally get submitted to MB by analysts mid-
        # investigation. Without the family gate, any signed Microsoft
        # binary that happened to share a hash with an MB record would
        # be classified as malicious. The gate keeps MB's signal-to-
        # noise high enough to count as a HARD provider in the fusion
        # layer (see services/antivirus/service.py:_HARD_PROVIDERS).
        try:
            mb = client.check_file_malwarebazaar(sha256, auth_key=mb_key or None)
            hits["malwarebazaar"] = mb
            if isinstance(mb, dict) and str(mb.get("status", "")).lower() == "ok" and mb.get("sha256_hash"):
                family = str(mb.get("signature") or "").strip()
                if family:
                    score += 50
                    findings.append(f"MalwareBazaar: {family}")
                else:
                    # Bare hash match → low-confidence metadata signal.
                    # Worth surfacing but never enough alone to fuse to
                    # malicious. Caller's threshold is 40, so 10 stays
                    # firmly below it.
                    score += 10
                    file_type = str(mb.get("file_type") or "").strip()
                    findings.append(
                        f"MalwareBazaar metadata match (no family attribution); file_type={file_type or 'unknown'}"
                    )
        except Exception as exc:
            errors.append(f"malwarebazaar: {exc}")
            hits["malwarebazaar"] = {"status": "error", "message": str(exc)}

        # YARAify
        try:
            yf = client.check_file_yaraify(sha256, auth_key=yaraify_key or None)
            hits["yaraify"] = yf
            if isinstance(yf, dict) and str(yf.get("status", "")).lower() == "ok":
                matched = yf.get("matched_rules") or []
                if matched:
                    score += min(35, 10 + 3 * len(matched))
                    findings.append(f"YARAify matched {len(matched)} rule(s): {', '.join(str(item) for item in matched[:3])}")
                clamav_hit = yf.get("clamav")
                if isinstance(clamav_hit, list) and clamav_hit:
                    score += 15
                    findings.append(f"YARAify ClamAV signature: {clamav_hit[0]}")
                elif isinstance(clamav_hit, str) and clamav_hit:
                    score += 15
                    findings.append(f"YARAify ClamAV signature: {clamav_hit}")
        except Exception as exc:
            errors.append(f"yaraify: {exc}")
            hits["yaraify"] = {"status": "error", "message": str(exc)}

        # VirusTotal — smart threshold replacing the legacy
        # "3 * malicious" formula. Real EDR products require BOTH:
        #   (a) a minimum absolute count of detections (so one heuristic
        #       FP from a single noisy vendor doesn't fire), AND
        #   (b) a minimum DETECTION RATIO across the active scanner set
        #       (so a binary scanned by 75 engines where 5 fire is
        #       treated very differently from one scanned by 10 where
        #       5 fire).
        # Defaults are 5 / 10% — operator-overridable via env vars for
        # the rare deployment that wants a stricter or looser bar.
        if vt_key:
            try:
                vt = client.check_file_vt(sha256, api_key=vt_key)
                hits["virustotal"] = vt
                if isinstance(vt, dict):
                    stats = vt.get("last_analysis_stats") if isinstance(vt.get("last_analysis_stats"), dict) else {}
                    malicious = int(stats.get("malicious", 0) or 0)
                    suspicious_v = int(stats.get("suspicious", 0) or 0)
                    undetected = int(stats.get("undetected", 0) or 0)
                    harmless = int(stats.get("harmless", 0) or 0)
                    timeout = int(stats.get("timeout", 0) or 0)
                    total_scanners = max(0, malicious + suspicious_v + undetected + harmless + timeout)
                    ratio = (malicious / total_scanners) if total_scanners > 0 else 0.0
                    min_count = _vt_min_malicious_count()
                    min_ratio = _vt_min_detection_ratio()
                    if malicious or suspicious_v:
                        if malicious >= min_count and ratio >= min_ratio:
                            # Strong VT verdict — full weight + a guaranteed
                            # bonus so a passing-threshold result always
                            # crosses the 40-point provider-level infected
                            # gate. Without this, a "7 of 20 vendors call
                            # this malicious" (35% — a clearly strong signal)
                            # could net score=21 and the provider would still
                            # report `clean`. The bonus reflects that the
                            # signal already CLEARED the count + ratio gates.
                            # Bonus is calibrated to push even the edge
                            # case (malicious == min_count, ratio == min_ratio)
                            # past the 40-point provider-infected gate:
                            # 3*5 + 25 = 40. Strong signals (12+ vendors)
                            # just hit the +45 cap regardless.
                            score += min(45, 3 * malicious + 2 * suspicious_v) + 25
                            findings.append(
                                f"VirusTotal: {malicious}/{total_scanners} malicious "
                                f"({ratio:.0%} ratio, threshold {min_count}+/{min_ratio:.0%}), "
                                f"suspicious={suspicious_v}"
                            )
                        else:
                            # Below threshold — surface as informational
                            # only. The fused score gets at most 8 points
                            # so a borderline VT signal can't tip a clean
                            # binary into malicious territory by itself.
                            score += min(8, malicious + suspicious_v)
                            findings.append(
                                f"VirusTotal: low-confidence signal "
                                f"({malicious}/{total_scanners} malicious, {ratio:.0%} ratio "
                                f"below {min_count}+ / {min_ratio:.0%} threshold)"
                            )
            except Exception as exc:
                errors.append(f"virustotal: {exc}")
                hits["virustotal"] = {"status": "error", "message": str(exc)}
        else:
            hits["virustotal"] = {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY not configured"}

        if score >= 40 or any(
            isinstance(hits.get(key), dict) and str(hits[key].get("status", "")).lower() == "ok"
            and _has_positive_signal(hits[key])
            for key in ("malwarebazaar", "yaraify")
        ):
            status = "infected"
            malware_name = findings[0] if findings else "Cloud intel match"
        elif all(
            isinstance(hits.get(key), dict) and str(hits[key].get("status", "")).lower() in {"ok", "hash_not_found", "not_found", "no_results"}
            for key in hits
        ) and not errors:
            status = "clean"
            malware_name = ""
        elif errors:
            status = "error"
            malware_name = ""
        else:
            status = "clean"
            malware_name = ""

        return {
            "status": status,
            "engine": self.display_name,
            "malware_name": malware_name,
            "score": min(100, score),
            "findings": findings,
            "providers": hits,
            "errors": errors,
            "sha256": sha256,
            "timeout_budget_seconds": timeout_seconds,
        }

    def _hash_file(self, path: Path) -> str:
        try:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return ""


def _vt_min_malicious_count() -> int:
    """Minimum VT vendors that must call a file malicious before it counts."""
    raw = str(os.environ.get("SHADOWLAB_VT_MIN_MALICIOUS", "") or "").strip()
    try:
        value = int(raw) if raw else 5
    except ValueError:
        value = 5
    return max(1, min(value, 50))


def _vt_min_detection_ratio() -> float:
    """Minimum (malicious / total_scanners) ratio before VT counts as a hard hit."""
    raw = str(os.environ.get("SHADOWLAB_VT_MIN_RATIO", "") or "").strip()
    try:
        value = float(raw) if raw else 0.10
    except ValueError:
        value = 0.10
    return max(0.01, min(value, 1.0))


def _has_positive_signal(payload: dict[str, Any]) -> bool:
    """True for MB/YARAify when the response carries a family / rule attribution.

    Bare hash matches no longer count — see the gate in `scan_file`.
    """
    if not isinstance(payload, dict):
        return False
    # MalwareBazaar: only positive when a malware family (`signature`)
    # is attributed. Hash-only match (sha256_hash without signature) is
    # metadata and intentionally NOT a positive signal anymore.
    if str(payload.get("signature") or "").strip():
        return True
    # YARAify: positive when a YARA rule actually matched.
    matched = payload.get("matched_rules")
    if isinstance(matched, list) and matched:
        return True
    return False
