from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .aegis_provider import AegisProvider
from .behavioural_analyzer import BehaviouralAnalyzer
from .cloud_provider import CloudIntelProvider
from .mitre_mapper import MitreMapper
from .sandbox_provider import CloudSandboxProvider
from .sentinel_provider import SentinelProvider
from .signature_updater import SignatureUpdater
from .vault import QuarantineVault
from .verdict_cache import VerdictCache
from .worker_pool import ScanWorkerPool
from .yara_x_provider import YaraXProvider


# Classification of providers for fusion purposes.
#
# HARD providers return SIGNATURE-based verdicts: KicomAV (aegis_core),
# ClamAV (sentinel_cli), and cloud reputation feeds (cloud_intel /
# VirusTotal / MalwareBazaar / YARAify) — each one carries a real
# malware-family attribution when it fires. A single HARD hit is
# enough to escalate the fused verdict to malicious.
#
# SOFT providers return HEURISTIC / BEHAVIOURAL verdicts: the static
# behavioural analyzer (capability / imports / entropy scoring) and the
# local YARA engine (community + bespoke packs). These flag suspect
# CAPABILITIES, not known-bad signatures. A single soft hit is
# `suspicious` (visible to analyst, but NOT auto-quarantine); two
# independent soft hits corroborate each other and escalate to
# malicious. This matches every commercial EDR's fusion model and
# stops a single noisy heuristic hit on a Microsoft-signed binary
# (msedgewebview2.exe, V8 JIT) from dominating the verdict.
_HARD_PROVIDERS = frozenset({"aegis_core", "sentinel_cli", "cloud_intel"})
_SOFT_PROVIDERS = frozenset({"behavioural", "yara_x", "cloud_sandbox"})


class AntivirusService:
    PROVIDER_ALIASES = {
        "aegis_core": "aegis_core",
        "sentinel_cli": "sentinel_cli",
        "cloud_intel": "cloud_intel",
        "yara_x": "yara_x",
        "behavioural": "behavioural",
        "cloud_sandbox": "cloud_sandbox",
        "kicomav": "aegis_core",
        "clamav": "sentinel_cli",
        "virustotal": "cloud_intel",
        "malwarebazaar": "cloud_intel",
        "yaraify": "cloud_intel",
        "yara": "yara_x",
        "yara-x": "yara_x",
        "static_pe": "behavioural",
        "behaviour": "behavioural",
        "behavior": "behavioural",
        "hybrid_analysis": "cloud_sandbox",
        "sandbox": "cloud_sandbox",
    }

    DEFAULT_POLICY: dict[str, Any] = {
        "enabled": True,
        "providers": [
            "aegis_core",
            "sentinel_cli",
            "cloud_intel",
            "yara_x",
            "behavioural",
            "cloud_sandbox",
        ],
        "max_file_size_mb": 128,
        "scan_profile": "balanced",
        "quarantine_on_infected": False,
        "auto_quarantine_threshold": "disabled",
        "require_admin_for_quarantine": True,
        "scan_timeout_seconds": 120,
        "scheduled_validation_minutes": 240,
        "signature_grace_hours": 48,
        "cache_ttl_seconds": 24 * 3600,
        "yara_pack": "enterprise",
        "mitre_mapping_enabled": True,
    }

    def __init__(self, base_dir: Path, *, base_dir_alias=None, db: Any = None, worker_pool: ScanWorkerPool | None = None):
        self.base_dir = Path(base_dir)
        self._db = db
        self._metrics = None
        # Per-provider rolling health stats (in-memory ring buffer of
        # (timestamp, status, scan_time_ms, error_excerpt) tuples). Sized
        # to the most recent 200 calls per provider — enough for p95
        # latency + last-N error reasons without a schema change.
        self._provider_health: dict[str, list[dict[str, Any]]] = {}
        self._provider_health_max = 200
        import threading as _threading
        self._provider_health_lock = _threading.Lock()
        self.providers = {
            "aegis_core": AegisProvider(self.base_dir),
            "sentinel_cli": SentinelProvider(self.base_dir),
            "cloud_intel": CloudIntelProvider(self.base_dir),
            "yara_x": YaraXProvider(self.base_dir),
            "behavioural": BehaviouralAnalyzer(self.base_dir),
            "cloud_sandbox": CloudSandboxProvider(self.base_dir),
        }
        self._mitre_mapper = MitreMapper()
        self._worker_pool = worker_pool or ScanWorkerPool()
        self._cache = VerdictCache(db=db)
        self._vault = QuarantineVault(self.base_dir, db=db)
        self._signature_updater = SignatureUpdater(
            self.base_dir,
            sentinel=self.providers["sentinel_cli"] if isinstance(self.providers.get("sentinel_cli"), SentinelProvider) else None,
            db=db,
        )

    @property
    def vault(self) -> QuarantineVault:
        return self._vault

    @property
    def cache(self) -> VerdictCache:
        return self._cache

    @property
    def worker_pool(self) -> ScanWorkerPool:
        return self._worker_pool

    @property
    def signature_updater(self) -> SignatureUpdater:
        return self._signature_updater

    def attach_metrics(self, metrics_registry: Any) -> None:
        """Wire a Prometheus-style metrics registry into the scan path.

        Called once during bootstrap. After this, every fused scan
        increments `shadowlab_av_scans_total`, observes
        `shadowlab_av_scan_duration_seconds`, bumps per-provider error
        counters, and refreshes engine-status / signature-age gauges
        on each `provider_status()` call."""
        self._metrics = metrics_registry

    def default_policy(self) -> dict[str, Any]:
        return dict(self.DEFAULT_POLICY)

    def normalize_policy(self, value: dict[str, Any] | None) -> dict[str, Any]:
        merged = dict(self.DEFAULT_POLICY)
        if isinstance(value, dict):
            merged.update(value)
        providers = merged.get("providers", self.DEFAULT_POLICY["providers"])
        if not isinstance(providers, list):
            providers = list(self.DEFAULT_POLICY["providers"])
        normalized_providers: list[str] = []
        for item in providers:
            alias = self.PROVIDER_ALIASES.get(str(item).strip().lower())
            if alias and alias in self.providers and alias not in normalized_providers:
                normalized_providers.append(alias)
        merged["providers"] = normalized_providers
        merged["enabled"] = bool(merged.get("enabled", True))
        merged["quarantine_on_infected"] = bool(merged.get("quarantine_on_infected", False))
        merged["require_admin_for_quarantine"] = bool(merged.get("require_admin_for_quarantine", True))
        merged["max_file_size_mb"] = max(1, min(int(merged.get("max_file_size_mb", 128) or 128), 2048))
        merged["scan_timeout_seconds"] = max(10, min(int(merged.get("scan_timeout_seconds", 90) or 90), 900))
        merged["scheduled_validation_minutes"] = max(15, min(int(merged.get("scheduled_validation_minutes", 240) or 240), 10080))
        merged["signature_grace_hours"] = max(6, min(int(merged.get("signature_grace_hours", 48) or 48), 720))
        merged["cache_ttl_seconds"] = max(60, min(int(merged.get("cache_ttl_seconds", 24 * 3600) or 24 * 3600), 14 * 24 * 3600))
        merged["mitre_mapping_enabled"] = bool(merged.get("mitre_mapping_enabled", True))
        yara_pack = str(merged.get("yara_pack", "enterprise") or "enterprise").strip().lower()
        if yara_pack not in {"enterprise", "hybrid", "memory", "shadowlab", "rules_master", "signature_base"}:
            yara_pack = "enterprise"
        merged["yara_pack"] = yara_pack
        scan_profile = str(merged.get("scan_profile", "balanced") or "balanced").strip().lower()
        if scan_profile not in {"conservative", "balanced", "aggressive"}:
            scan_profile = "balanced"
        merged["scan_profile"] = scan_profile
        threshold = str(merged.get("auto_quarantine_threshold", "disabled") or "disabled").strip().lower()
        if threshold not in {"disabled", "critical", "high"}:
            threshold = "disabled"
        merged["auto_quarantine_threshold"] = threshold
        if not merged["providers"]:
            merged["providers"] = [item for item in self.DEFAULT_POLICY["providers"] if item in self.providers]
        return merged

    def provider_status(self) -> dict[str, Any]:
        statuses = {key: provider.status() for key, provider in self.providers.items()}
        if self._metrics is not None:
            try:
                self._metrics.update_engine_posture(statuses)
            except Exception:
                pass
        return statuses

    def signature_health(self, *, provider_status: dict[str, Any] | None = None, policy: dict[str, Any] | None = None) -> dict[str, Any]:
        statuses = provider_status or self.provider_status()
        normalized_policy = self.normalize_policy(policy)
        grace_seconds = int(normalized_policy.get("signature_grace_hours", 48) or 48) * 3600
        now_value = float(time.time())
        provider_rows: list[dict[str, Any]] = []
        worst_rank = 0
        latest_update = 0.0
        for provider_key in normalized_policy["providers"]:
            provider = statuses.get(provider_key, {}) if isinstance(statuses.get(provider_key, {}), dict) else {}
            available = bool(provider.get("available"))
            definitions_loaded = bool(provider.get("definitions_loaded", provider.get("system_rule_files", 0) or provider.get("user_rule_files", 0) or provider.get("feeds_configured", 0)))
            updated_at = float(provider.get("latest_signature_update", 0) or 0)
            latest_update = max(latest_update, updated_at)
            age_seconds = max(0.0, now_value - updated_at) if updated_at else 0.0
            if not available or not definitions_loaded:
                state = "degraded"
                worst_rank = max(worst_rank, 3)
            elif updated_at and age_seconds > grace_seconds:
                state = "stale"
                worst_rank = max(worst_rank, 2)
            else:
                state = "healthy"
                worst_rank = max(worst_rank, 1)
            provider_rows.append(
                {
                    "provider_key": provider_key,
                    "display_name": str(provider.get("display_name", provider_key)),
                    "state": state,
                    "available": available,
                    "definitions_loaded": definitions_loaded,
                    "latest_signature_update": updated_at,
                    "age_seconds": age_seconds,
                }
            )
        overall = "degraded" if worst_rank >= 3 else "stale" if worst_rank == 2 else "healthy"
        return {
            "overall": overall,
            "grace_hours": normalized_policy["signature_grace_hours"],
            "latest_update": latest_update,
            "providers": provider_rows,
        }

    def scan_file(
        self,
        file_path: str | Path,
        *,
        policy: dict[str, Any] | None = None,
        workspace_id: str = "default",
        actor: str = "",
        use_cache: bool = True,
    ) -> dict[str, Any]:
        normalized_policy = self.normalize_policy(policy)
        # Refuse `~` expansion outright (same hardening we applied to the
        # path-traversal guards). Caller is expected to pass an absolute
        # path that already lives inside an approved root; a leading `~`
        # is a developer mistake or an attacker probing for tilde-aware
        # shell semantics.
        raw_path = str(file_path or "").strip()
        if raw_path.startswith("~"):
            return {
                "status": "error",
                "path": raw_path,
                "error": "Home-directory expansion is not allowed for scan targets",
                "policy": normalized_policy,
                "providers": {},
                "summary": {},
            }
        target = Path(raw_path)
        if not normalized_policy["enabled"]:
            return {"status": "disabled", "path": str(target), "policy": normalized_policy, "providers": {}, "summary": {}}
        if not target.exists() or not target.is_file():
            return {"status": "error", "path": str(target), "error": "File not found", "policy": normalized_policy, "providers": {}, "summary": {}}
        try:
            stat = target.stat()
        except OSError as exc:
            return {"status": "error", "path": str(target), "error": str(exc), "policy": normalized_policy, "providers": {}, "summary": {}}
        if stat.st_size > normalized_policy["max_file_size_mb"] * 1024 * 1024:
            return {
                "status": "skipped",
                "path": str(target),
                "error": f"File exceeds max scan size of {normalized_policy['max_file_size_mb']} MB",
                "policy": normalized_policy,
                "providers": {},
                "summary": {},
            }

        scan_started = time.time()
        sha256 = ""
        hash_error = ""
        try:
            sha256 = self._sha256_file(target)
        except OSError as exc:
            hash_error = str(exc)

        providers_fp = VerdictCache.fingerprint(normalized_policy["providers"])
        cached = self._cache.lookup(sha256, providers_fp) if (use_cache and sha256) else None
        if cached is not None:
            cached = dict(cached)
            cached["path"] = str(target)
            cached["source"] = "cache"
            cached["policy"] = normalized_policy
            return cached

        timeout_seconds = int(normalized_policy["scan_timeout_seconds"])
        thunks = {
            provider_key: self._make_thunk(provider_key, target, normalized_policy)
            for provider_key in normalized_policy["providers"]
        }
        provider_results, pool_telemetry = self._worker_pool.run_providers(
            thunks, timeout_seconds=timeout_seconds
        )

        result = self._fuse(
            target=target,
            stat=stat,
            sha256=sha256,
            hash_error=hash_error,
            provider_results=provider_results,
            normalized_policy=normalized_policy,
        )
        result["source"] = "live"
        result["worker_pool"] = pool_telemetry
        duration_ms = int((time.time() - scan_started) * 1000)
        result["duration_ms"] = duration_ms

        summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
        auto_quarantined = None
        if (
            normalized_policy.get("quarantine_on_infected")
            and summary.get("auto_quarantine_ready")
            and result.get("status") == "infected"
            and sha256
        ):
            try:
                entry = self._vault.seal(
                    target,
                    workspace_id=workspace_id,
                    actor=actor,
                    severity=str(summary.get("severity", "")),
                    fused_verdict=str(summary.get("fused_verdict", "")),
                    sha256=sha256,
                    extra={"detections": summary.get("detections", [])},
                )
                auto_quarantined = entry.to_record()
            except Exception as exc:
                auto_quarantined = {"ok": False, "reason": str(exc)}
        if auto_quarantined is not None:
            result["auto_quarantined"] = auto_quarantined

        if sha256 and result.get("status") not in {"error", "degraded", "skipped", "disabled"}:
            self._cache.store(
                sha256,
                providers_fp,
                result,
                ttl_seconds=int(normalized_policy.get("cache_ttl_seconds", 24 * 3600)),
            )

        self._audit(
            workspace_id=workspace_id,
            actor=actor,
            target=target,
            sha256=sha256,
            size_bytes=int(stat.st_size),
            normalized_policy=normalized_policy,
            result=result,
            duration_ms=duration_ms,
        )
        # Prometheus instrumentation — every fused scan emits scan_total
        # + duration histogram (labelled by scope) and bumps the
        # engine_errors counter for each provider that returned an error.
        if self._metrics is not None:
            try:
                summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
                self._metrics.record_scan(
                    verdict=str(summary.get("fused_verdict", result.get("status", "unknown"))),
                    scope="file",
                    source=str(result.get("source", "live")),
                    duration_seconds=duration_ms / 1000.0,
                )
                for provider_name, provider_result in (provider_results or {}).items():
                    if not isinstance(provider_result, dict):
                        continue
                    if str(provider_result.get("status", "")).lower() == "error":
                        self._metrics.record_engine_error(
                            provider=provider_name,
                            reason=str(provider_result.get("error", "error"))[:64],
                        )
            except Exception:
                pass
        # Per-provider rolling health record — drives the Provider Matrix
        # latency p95 + success-rate columns and the inline "Last error"
        # diagnostic the analyst sees when an engine flips offline.
        self._record_provider_health(provider_results)
        return result

    def _record_provider_health(self, provider_results: dict[str, Any]) -> None:
        if not isinstance(provider_results, dict):
            return
        now = time.time()
        with self._provider_health_lock:
            for provider_name, provider_result in provider_results.items():
                if not isinstance(provider_result, dict):
                    continue
                bucket = self._provider_health.setdefault(provider_name, [])
                bucket.append({
                    "ts": now,
                    "status": str(provider_result.get("status", "") or "").lower(),
                    "scan_time_ms": int(provider_result.get("scan_time_ms", 0) or 0),
                    "error": str(provider_result.get("error", "") or "")[:200],
                })
                if len(bucket) > self._provider_health_max:
                    del bucket[: len(bucket) - self._provider_health_max]

    def provider_health(self, *, window_seconds: int = 24 * 3600) -> dict[str, dict[str, Any]]:
        """Aggregate per-provider rolling health stats.

        Returns `{provider_key: {calls, success_rate, p50_ms, p95_ms,
        last_status, last_error, last_seen_at}}` aggregated from the
        in-memory ring buffer over the past `window_seconds`."""
        cutoff = time.time() - max(60, int(window_seconds))
        out: dict[str, dict[str, Any]] = {}
        with self._provider_health_lock:
            snapshot = {k: list(v) for k, v in self._provider_health.items()}
        for key, calls in snapshot.items():
            recent = [c for c in calls if float(c.get("ts", 0)) >= cutoff]
            if not recent:
                # Surface the last-known call even if outside the window
                # so the matrix shows *something* before the first scan.
                recent = calls[-1:] if calls else []
            n = len(recent)
            if n == 0:
                out[key] = {
                    "calls": 0, "success_rate": None, "p50_ms": 0, "p95_ms": 0,
                    "last_status": "", "last_error": "", "last_seen_at": 0.0,
                }
                continue
            successes = sum(1 for c in recent if c.get("status") in {"clean", "infected", "suspicious"})
            timings = sorted(int(c.get("scan_time_ms", 0) or 0) for c in recent if int(c.get("scan_time_ms", 0) or 0) > 0)
            def _pct(p: float) -> int:
                if not timings:
                    return 0
                idx = max(0, min(len(timings) - 1, int(round(p * (len(timings) - 1)))))
                return int(timings[idx])
            last = recent[-1]
            out[key] = {
                "calls": n,
                "success_rate": round(successes / n, 4),
                "p50_ms": _pct(0.50),
                "p95_ms": _pct(0.95),
                "last_status": str(last.get("status", "")),
                "last_error": str(last.get("error", "")),
                "last_seen_at": float(last.get("ts", 0)),
            }
        return out

    def scan_process(self, process_profile: dict[str, Any], *, policy: dict[str, Any] | None = None) -> dict[str, Any]:
        exe_path = str(process_profile.get("exe") or "").strip()
        if not exe_path:
            return {"status": "skipped", "error": "Executable path unavailable", "summary": {}, "providers": {}}
        result = self.scan_file(exe_path, policy=policy)
        result["process"] = {
            "pid": int(process_profile.get("pid", 0) or 0),
            "name": str(process_profile.get("name", "") or ""),
            "exe": exe_path,
            "signature_status": str(process_profile.get("signature_status", "") or ""),
        }
        return result

    def stats(self) -> dict[str, Any]:
        return {
            "worker_pool": self._worker_pool.snapshot(),
            "cache": self._cache.stats(),
            "vault": self._vault.status(),
            "signature_updater": self._signature_updater.status(),
        }

    def recent_mitre_coverage(self, *, limit: int = 50) -> dict[str, Any]:
        """Aggregate ATT&CK techniques across the last `limit` cached scans.

        Used by the analyst dashboard's coverage heat-map. Reads the
        verdict cache (DB-backed when available, else process LRU),
        unions every `summary.mitre_techniques` row, and returns both
        the raw deduplicated technique list and a tactic-grouped
        summary suitable for direct UI rendering."""
        limit = max(1, min(int(limit or 50), 500))
        rows: list[dict[str, Any]] = []
        # DB path — the cache table holds full payload_json, ordered by
        # most-recent expiry as a proxy for most-recently-stored.
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    cursor = conn.execute(
                        """
                        SELECT payload_json FROM av_verdict_cache
                        WHERE expires_at > ?
                        ORDER BY expires_at DESC
                        LIMIT ?
                        """,
                        (time.time(), limit),
                    )
                    for row in cursor.fetchall():
                        try:
                            rows.append(json.loads(row[0]))
                        except Exception:
                            continue
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        # Memory fallback — pull straight from the in-process LRU.
        if not rows:
            with self._cache._lock:  # noqa: SLF001 — intra-package access by design
                for _expires, payload in list(self._cache._memory.values())[:limit]:  # noqa: SLF001
                    if isinstance(payload, dict):
                        rows.append(payload)
        # Re-aggregate via the mapper so dedupe + sources tracking are
        # consistent with the per-scan output.
        synthetic_provider_results: dict[str, Any] = {}
        scan_count = 0
        for scan in rows:
            summary = scan.get("summary") if isinstance(scan, dict) else None
            if not isinstance(summary, dict):
                continue
            techniques = summary.get("mitre_techniques") or []
            if not isinstance(techniques, list) or not techniques:
                continue
            scan_count += 1
            sha = str(scan.get("sha256", "") or f"scan_{scan_count}")[:16] or f"scan_{scan_count}"
            synthetic_provider_results[f"scan:{sha}"] = {"techniques": techniques}
        techniques = self._mitre_mapper.map_provider_results(synthetic_provider_results)
        coverage = self._mitre_mapper.coverage_summary(techniques)
        return {
            "scans_considered": scan_count,
            "techniques": techniques,
            "coverage": coverage,
        }

    def _make_thunk(self, provider_key: str, target: Path, policy: dict[str, Any]):
        provider = self.providers[provider_key]

        def _run() -> dict[str, Any]:
            return provider.scan_file(target, policy=policy)

        return _run

    def _fuse(
        self,
        *,
        target: Path,
        stat,
        sha256: str,
        hash_error: str,
        provider_results: dict[str, Any],
        normalized_policy: dict[str, Any],
    ) -> dict[str, Any]:
        infected_hits = [name for name, result in provider_results.items() if str(result.get("status", "")).lower() == "infected"]
        suspicious_hits = [name for name, result in provider_results.items() if str(result.get("status", "")).lower() == "suspicious"]
        errors = [name for name, result in provider_results.items() if str(result.get("status", "")).lower() == "error"]
        warnings = [name for name, result in provider_results.items() if str(result.get("status", "")).lower() in {"unavailable", "skipped"}]
        clean_hits = [name for name, result in provider_results.items() if str(result.get("status", "")).lower() == "clean"]
        # Partition infected hits by provider class — see `_HARD_PROVIDERS`
        # / `_SOFT_PROVIDERS` at module scope for the rationale. Hard
        # providers (signature / cloud reputation) carry a malware-family
        # attribution; one hard hit is sufficient to escalate. Soft
        # providers (heuristic) need corroboration: two distinct soft
        # hits OR one soft + one hard for the verdict to flip malicious.
        hard_infected = [name for name in infected_hits if name in _HARD_PROVIDERS]
        soft_infected = [name for name in infected_hits if name in _SOFT_PROVIDERS]
        # Trusted-publisher signal: if ANY provider observed a trusted
        # Authenticode signature, soft hits cannot quorum a malicious
        # verdict on their own. A real signature engine still can, but
        # in that case it's not a heuristic false positive.
        trusted_publisher = any(
            isinstance(result, dict) and bool(result.get("trusted_publisher"))
            for result in provider_results.values()
        )
        score = 0
        reasons: list[str] = []
        detections: list[str] = []
        provider_cards: list[dict[str, Any]] = []
        for provider_name, result in provider_results.items():
            provider_display = str(result.get("engine", provider_name))
            provider_status = str(result.get("status", "")).lower()
            if provider_status == "infected":
                per_engine_score = int(result.get("score", 0) or 0)
                # Floor lowered from 40 → 20: the previous floor pushed
                # one infected provider's score into the "high" severity
                # band even when the provider itself reported a low
                # internal confidence. 20 keeps a clear signal in the
                # fused score without auto-tripping severity bands.
                score += max(20, per_engine_score)
                malware_name = str(result.get("malware_name", "")).strip()
                detections.append(f"{provider_display}:{malware_name or 'detected'}")
                reasons.append(f"{provider_display} detected {malware_name or 'a suspicious sample'}.")
            elif provider_status == "suspicious":
                per_engine_score = int(result.get("score", 0) or 0)
                # Suspicious contributes a softer signal — half-weight,
                # capped at 25 — so a single behavioural maybe doesn't
                # ship a clean sample to quarantine, but two of them do.
                score += max(10, min(25, per_engine_score // 2))
                malware_name = str(result.get("malware_name", "")).strip() or "Behavioural risk"
                reasons.append(f"{provider_display} flagged {malware_name} (behavioural).")
            elif provider_status == "clean":
                reasons.append(f"{provider_display} returned clean.")
            elif provider_status == "error":
                reasons.append(f"{provider_display} error: {result.get('error', 'scan failed')}.")
            elif provider_status in {"unavailable", "skipped"}:
                reasons.append(f"{provider_display} returned {provider_status}.")
            provider_cards.append(
                {
                    "provider": provider_name,
                    "engine": provider_display,
                    "status": provider_status or "unknown",
                    "malware_name": str(result.get("malware_name", "") or ""),
                    "scan_time_ms": int(result.get("scan_time_ms", 0) or 0),
                    "error": str(result.get("error", "") or ""),
                    "score": int(result.get("score", 0) or 0),
                }
            )
        # Quorum logic — replaces the legacy "any infected → malicious"
        # short-circuit. Three escalation paths:
        #   1. Any HARD-provider infected hit → malicious (signature
        #      attribution is high confidence).
        #   2. ≥1 SOFT-provider infected AND ≥1 corroborating SOFT
        #      `suspicious`/`infected` → malicious. Lone soft infected
        #      stays as `suspicious` so a single noisy YARA rule
        #      can't override the rest.
        #   3. ≥2 SOFT-provider suspicious → suspicious (was the legacy
        #      `escalated_by_suspicious`); only escalates to malicious
        #      when we have a HARD hit too.
        # Trusted-publisher binaries can NEVER reach malicious via the
        # soft path alone.
        soft_corroborated_count = sum(
            1 for name in suspicious_hits if name in _SOFT_PROVIDERS
        ) + len(soft_infected)
        if hard_infected:
            escalated_to_malicious = True
            escalation_reason = "hard_provider_infected"
        elif soft_infected and soft_corroborated_count >= 2 and not trusted_publisher:
            escalated_to_malicious = True
            escalation_reason = "soft_corroborated"
        else:
            escalated_to_malicious = False
            escalation_reason = ""
        # Backwards-compat alias for callers that still read the old flag.
        escalated_by_suspicious = (escalation_reason == "soft_corroborated")
        final_score = min(100, score)
        # When a trusted publisher is detected and we don't have a hard
        # provider hit, cap severity at "medium" so the analyst still
        # sees the heuristic noise but the binary doesn't get a
        # quarantine recommendation. Real EDR products do exactly this
        # for first-party platform binaries.
        if trusted_publisher and not hard_infected:
            final_score = min(final_score, 35)
        severity = "critical" if final_score >= 80 else "high" if final_score >= 55 else "medium" if final_score >= 30 else "low"
        if escalated_to_malicious:
            fused_verdict = "malicious"
        elif soft_infected or suspicious_hits:
            fused_verdict = "suspicious"
        elif errors or warnings:
            fused_verdict = "degraded"
        else:
            fused_verdict = "clean"
        confidence = (
            "high" if len(hard_infected) >= 2 or (hard_infected and (soft_infected or suspicious_hits))
            else "medium" if escalated_to_malicious
            else "low"
        )
        if escalated_to_malicious:
            status = "infected"
        elif not provider_results:
            status = "error"
        elif soft_infected or suspicious_hits:
            status = "suspicious"
        elif errors or warnings:
            status = "degraded"
        else:
            status = "clean"
        if escalated_to_malicious:
            recommended_actions = ["quarantine", "investigate_parent_process", "review_network_exposure"]
        elif soft_infected or suspicious_hits:
            recommended_actions = ["detonate_in_sandbox", "collect_telemetry", "review_parent_chain"]
        elif errors or warnings:
            recommended_actions = ["validate_antivirus_stack", "refresh_signatures", "retest_sample"]
        else:
            recommended_actions = ["no_action"]
        auto_quarantine_ready = False
        threshold = str(normalized_policy.get("auto_quarantine_threshold", "disabled") or "disabled").lower()
        # Auto-quarantine never fires for soft-only verdicts. A real
        # quarantine action against a Microsoft-signed binary would brick
        # the operator's machine; gating on `hard_infected` makes that
        # impossible by construction.
        if threshold == "critical":
            auto_quarantine_ready = severity == "critical" and bool(hard_infected)
        elif threshold == "high":
            auto_quarantine_ready = severity in {"critical", "high"} and bool(hard_infected)
        if hash_error:
            reasons.append(f"File hash unavailable after scan: {hash_error}.")
        # MITRE ATT&CK technique aggregation across providers — sandbox
        # contributes its native technique list, behavioural+yara contribute
        # via indicator-string lookup. Off-by-policy flag means an empty
        # list (so the schema stays stable for the UI).
        mitre_techniques: list[dict[str, Any]] = []
        mitre_coverage: dict[str, Any] = {"total_techniques": 0, "tactics_covered": [], "by_tactic": {}}
        if normalized_policy.get("mitre_mapping_enabled", True):
            mitre_techniques = self._mitre_mapper.map_provider_results(provider_results)
            mitre_coverage = self._mitre_mapper.coverage_summary(mitre_techniques)
        return {
            "status": status,
            "path": str(target),
            "sha256": sha256,
            "hash_error": hash_error,
            "size_bytes": int(stat.st_size),
            "providers": provider_results,
            "summary": {
                "infected": escalated_to_malicious,
                "detections": detections,
                "provider_hits": infected_hits,
                "provider_hard_hits": hard_infected,
                "provider_soft_hits": soft_infected,
                "provider_suspicious": suspicious_hits,
                "provider_errors": errors,
                "provider_warnings": warnings,
                "provider_clean": clean_hits,
                "provider_cards": provider_cards,
                "score": final_score,
                "severity": severity,
                "fused_verdict": fused_verdict,
                "confidence": confidence,
                "reasons": reasons,
                "recommended_actions": recommended_actions,
                "auto_quarantine_ready": auto_quarantine_ready,
                "mitre_techniques": mitre_techniques,
                "mitre_coverage": mitre_coverage,
                "escalated_by_suspicious": escalated_by_suspicious,
                "escalation_reason": escalation_reason,
                "trusted_publisher": trusted_publisher,
            },
            "policy": normalized_policy,
        }

    def _audit(
        self,
        *,
        workspace_id: str,
        actor: str,
        target: Path,
        sha256: str,
        size_bytes: int,
        normalized_policy: dict[str, Any],
        result: dict[str, Any],
        duration_ms: int,
    ) -> None:
        if self._db is None:
            return
        try:
            conn = self._db.create_connection()
        except Exception:
            return
        try:
            summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
            conn.execute(
                """
                INSERT INTO av_scans (
                    workspace_id, actor, scope, target_path, sha256, size_bytes,
                    fused_verdict, severity, score, confidence,
                    providers_set, source, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace_id,
                    actor,
                    "file",
                    str(target),
                    sha256,
                    int(size_bytes),
                    str(summary.get("fused_verdict", result.get("status", ""))),
                    str(summary.get("severity", "low")),
                    int(summary.get("score", 0) or 0),
                    str(summary.get("confidence", "low")),
                    json.dumps(normalized_policy.get("providers", []), ensure_ascii=False),
                    str(result.get("source", "live")),
                    int(duration_ms),
                ),
            )
            conn.commit()
        except Exception:
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
