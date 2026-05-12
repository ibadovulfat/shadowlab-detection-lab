"""Cloud sandbox provider for the antivirus pipeline.

Real commercial AV stacks fan suspicious samples out to a cloud
sandbox (CrowdStrike Falcon Sandbox, Joe Sandbox, VMRay, ANY.RUN,
Hybrid-Analysis) which detonates the file in instrumented VMs and
returns dynamic-execution evidence: dropped files, network IOCs,
process tree, registry writes, and — most usefully for fusion —
MITRE ATT&CK technique IDs the sample exhibited.

ShadowLab integrates with **Hybrid-Analysis** (CrowdStrike Falcon
Sandbox public cloud). It is the most accessible production sandbox
with a free tier that returns full reports for known hashes via the
public API at `https://www.hybrid-analysis.com/api/v2/`.

Scope:
  * Hash-only query (`/api/v2/search/hash`) by default — no file body
    is uploaded. This matches the privacy posture of the Wave-1 cloud
    intel provider and also avoids the ToS friction around uploading
    third-party files to a public sandbox.
  * The provider returns a verdict, a numeric `threat_score`, the AV
    detection ratio, the MITRE technique list, and the inferred
    malware family — all of which the fusion layer in
    `AntivirusService._fuse` consumes.
  * Missing API key → `status: skipped`, never an error. That's the
    contract every Wave-1 / Wave-2 cloud provider follows so a missing
    integration degrades the verdict gracefully.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any

from .base import AntivirusProvider


HYBRID_ANALYSIS_KEY_ENV = "HYBRID_ANALYSIS_API_KEY"


class CloudSandboxProvider(AntivirusProvider):
    provider_key = "cloud_sandbox"
    display_name = "Cloud Sandbox"

    # Backpressure — Hybrid-Analysis free tier caps at 200 lookups/day
    # per key. We track a rolling 24-hour window in-process and refuse
    # the call (returning `skipped` with a clear reason) once the quota
    # is gone. Keeps the analyst from getting opaque 429s and protects
    # paid-tier keys from accidentally burning a month's budget on a
    # runaway folder-watcher loop.
    DAILY_QUOTA_DEFAULT = 200
    QUOTA_WINDOW_SECONDS = 24 * 3600

    def __init__(self, base_dir: Path, *, client_factory=None, daily_quota: int | None = None):
        self.base_dir = Path(base_dir)
        self._client_factory = client_factory
        self._client_lock = threading.Lock()
        self._client = None
        self._quota_max = int(daily_quota or self.DAILY_QUOTA_DEFAULT)
        self._quota_lock = threading.Lock()
        self._quota_calls: list[float] = []  # timestamps of recent successful calls

    def _quota_consume(self) -> tuple[bool, int]:
        """Returns (allowed, calls_in_window). Drops timestamps that
        have aged out of the rolling window before checking."""
        now = time.time()
        cutoff = now - self.QUOTA_WINDOW_SECONDS
        with self._quota_lock:
            self._quota_calls = [t for t in self._quota_calls if t >= cutoff]
            if len(self._quota_calls) >= self._quota_max:
                return False, len(self._quota_calls)
            self._quota_calls.append(now)
            return True, len(self._quota_calls)

    def _get_client(self):
        with self._client_lock:
            if self._client is not None:
                return self._client
            if self._client_factory is not None:
                self._client = self._client_factory()
                return self._client
            from threat_intelligence import ThreatIntelClient  # local import by design
            self._client = ThreatIntelClient()
            return self._client

    def status(self) -> dict[str, Any]:
        from .credentials import resolve_credential
        api_key = resolve_credential("hybrid_analysis")
        return {
            "display_name": self.display_name,
            "available": bool(api_key),
            "version": "sandbox-v1",
            "feeds": {"hybrid_analysis": bool(api_key)},
            "feeds_configured": 1 if api_key else 0,
            "definitions_loaded": bool(api_key),
            "latest_signature_update": 0.0,
            "mode": "cloud-sandbox",
            "endpoints": {
                "hybrid_analysis": "https://www.hybrid-analysis.com/api/v2/search/hash",
            },
            "notes": [
                "Hash-only queries — no file body is uploaded.",
                "MITRE ATT&CK techniques are surfaced into fused verdict.",
                "Missing API key produces a skipped status, not an error.",
            ],
        }

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        from .credentials import resolve_credential
        api_key = resolve_credential("hybrid_analysis")
        if not api_key:
            return {
                "status": "skipped",
                "engine": self.display_name,
                "error": "No cloud sandbox API key configured. Paste it in Advanced Hunt → Hybrid-Analysis Auth-Key.",
            }
        # Quota check — refuse fast when the rolling 24h window is full.
        allowed, calls_used = self._quota_consume()
        if not allowed:
            return {
                "status": "skipped",
                "engine": self.display_name,
                "error": f"Daily Hybrid-Analysis quota exhausted ({calls_used}/{self._quota_max} in 24h)",
                "quota_used": calls_used,
                "quota_max": self._quota_max,
            }
        sha256 = self._hash_file(Path(path))
        if not sha256:
            return {
                "status": "error",
                "engine": self.display_name,
                "error": "Failed to hash file for cloud sandbox lookup",
            }
        client = self._get_client()
        try:
            report = client.check_file_hybrid_analysis(sha256, api_key=api_key)
        except Exception as exc:
            return {"status": "error", "engine": self.display_name, "error": str(exc)}
        if not isinstance(report, dict):
            return {"status": "error", "engine": self.display_name, "error": "Sandbox returned non-dict payload"}
        raw_status = str(report.get("status", "")).lower()
        if raw_status in {"forbidden", "rate_limited", "error"}:
            return {
                "status": "error",
                "engine": self.display_name,
                "error": str(report.get("message", raw_status)),
                "sha256": sha256,
            }
        if raw_status in {"not_found", "no_results"}:
            return {
                "status": "clean",
                "engine": self.display_name,
                "sha256": sha256,
                "score": 0,
                "reason": "Hash unknown to cloud sandbox",
            }
        threat_score = int(report.get("threat_score", 0) or 0)
        threat_level = int(report.get("threat_level", 0) or 0)
        verdict = str(report.get("verdict", "")).lower()
        family = report.get("vx_family") or ""
        if isinstance(family, list):
            family = ", ".join(str(item) for item in family[:3])
        techniques_raw = report.get("mitre_attcks") or []
        techniques: list[dict[str, Any]] = []
        for item in techniques_raw if isinstance(techniques_raw, list) else []:
            if not isinstance(item, dict):
                continue
            techniques.append(
                {
                    "id": str(item.get("technique") or item.get("attck_id") or item.get("id") or ""),
                    "tactic": str(item.get("tactic") or ""),
                    "name": str(item.get("name") or item.get("technique_name") or ""),
                }
            )
        # Score normalisation: Hybrid-Analysis reports 0–100 already.
        score = max(0, min(100, threat_score))
        is_malicious = (
            verdict in {"malicious", "suspicious"}
            or threat_level >= 1
            or score >= 40
        )
        if is_malicious:
            status = "infected"
            malware_name = str(family or report.get("submission_name") or "Sandbox.Detected")
        else:
            status = "clean"
            malware_name = ""
        return {
            "status": status,
            "engine": self.display_name,
            "malware_name": malware_name,
            "score": score,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "verdict": verdict,
            "av_detect": int(report.get("av_detect", 0) or 0),
            "submission_name": report.get("submission_name", ""),
            "environment": report.get("environment_description", ""),
            "techniques": techniques[:25],
            "compromised_hosts": (report.get("compromised_hosts") or [])[:10],
            "domains": (report.get("domains") or [])[:10],
            "hosts": (report.get("hosts") or [])[:10],
            "report_count": int(report.get("report_count", 0) or 0),
            "sha256": sha256,
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
