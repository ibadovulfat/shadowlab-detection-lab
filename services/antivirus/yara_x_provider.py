"""Independent YARA scanning provider for the antivirus pipeline.

KicomAV (the Aegis provider) ships its own YARA-style heuristics tied
to the vendored rule tree. Real production AV stacks always run a
*second* YARA engine on top, fed from community rule packs (Florian
Roth's signature-base, Neo23x0/Inceptor, Yara-Rules, and the
operator's own bespoke rules). When a sample lights up across two
independent engines you have a real second opinion; when the in-house
engine is silent but YARA fires on a Florian Roth rule, you've caught
something KicomAV's vendored tree didn't ship a signature for.

This provider wraps `plugins.yara_scanner.scan_file()` — which already
owns rule discovery, compilation cache, severity weighting, and
allowlist/suppression policy — and adapts it to the
`AntivirusProvider` interface so the worker pool can run it
concurrently with the other engines.

Design notes:
  * Pack selection comes from policy (`yara_pack`, defaults to
    "enterprise"). The plugin already falls back to "enterprise" or
    "hybrid" if the requested pack is missing.
  * `status: ok` with no active matches → `clean`. Active matches →
    `infected` (the plugin already applies suppression so suppressed
    matches don't count).
  * Compile errors / missing yara-python / no packs → `unavailable`,
    not `error`, so the fused verdict treats it as a degraded engine
    rather than a hard failure.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .base import AntivirusProvider


class YaraXProvider(AntivirusProvider):
    provider_key = "yara_x"
    display_name = "YARA-X"

    def __init__(self, base_dir: Path, *, scanner_module=None):
        self.base_dir = Path(base_dir)
        self._scanner = scanner_module

    def _get_scanner(self):
        if self._scanner is not None:
            return self._scanner
        # Local import keeps the heavy YARA compile machinery off the
        # provider construction path for unit tests / offline runs.
        from plugins import yara_scanner  # local import by design
        self._scanner = yara_scanner
        return self._scanner

    def status(self) -> dict[str, Any]:
        scanner = self._get_scanner()
        available_packs: dict[str, list[Path]] = {}
        try:
            available_packs = scanner.available_packs()
        except Exception:
            available_packs = {}
        rule_files: list[str] = []
        latest_update = 0.0
        for pack_paths in available_packs.values():
            for path in pack_paths or []:
                rule_files.append(str(path))
                try:
                    latest_update = max(latest_update, float(Path(path).stat().st_mtime))
                except OSError:
                    continue
        return {
            "display_name": self.display_name,
            "available": bool(getattr(scanner, "YARA_AVAILABLE", False)) and bool(rule_files),
            "yara_python_loaded": bool(getattr(scanner, "YARA_AVAILABLE", False)),
            "packs": {name: len(paths) for name, paths in available_packs.items()},
            "system_rule_files": len(rule_files),
            "rule_files_sample": rule_files[:10],
            "definitions_loaded": bool(rule_files),
            "latest_signature_update": latest_update,
            "mode": "yara-engine",
            "notes": [
                "Independent YARA engine fed by community + bespoke packs.",
                "Suppression and allowlists are honoured via plugins/yara_scanner policy.",
            ],
        }

    # Minimum aggregate score / max-severity gate before YARA escalates a
    # match to `infected`. Community YARA packs are inherently noisy —
    # `gen_packer.yar` hits every packed installer, `expl_*` rules fire
    # on shellcode-shaped legitimate buffers, etc. Without a gate we
    # treated every match as gospel and steamrolled the fusion layer
    # into "malicious" on signed Microsoft binaries.
    _INFECTED_MIN_SCORE = 30
    _INFECTED_MIN_SEVERITY = "high"

    @staticmethod
    def _severity_at_least(observed: str, threshold: str) -> bool:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order.get(str(observed or "").lower(), 0) >= order.get(threshold, 3)

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        scanner = self._get_scanner()
        if not getattr(scanner, "YARA_AVAILABLE", False):
            return {"status": "unavailable", "engine": self.display_name, "error": "yara-python not installed"}
        pack = str(policy.get("yara_pack", "enterprise") or "enterprise").strip().lower() or "enterprise"
        started = time.time()
        # Hand the scanner the authenticode + sha256 context up-front.
        # `plugins/yara_scanner._suppression_reasons` already owns the
        # "valid signature + trusted path + safe Windows subfolder"
        # suppression path — without `signature_status` populated, that
        # path was dead code and signed Microsoft binaries got hit by
        # every "process injection capability" YARA rule. Compute the
        # signature once (cached) and pass it through `context=`.
        sig_status = ""
        sig_signer = ""
        sig_trusted = False
        try:
            from .authenticode import signature_status as _sig_lookup
            sig_info = _sig_lookup(path)
            sig_status = str(sig_info.get("status", "") or "").strip()
            sig_signer = str(sig_info.get("signer_subject", "") or "")
            sig_trusted = bool(sig_info.get("trusted_publisher", False))
        except Exception:
            # Signature lookup is best-effort; never fail YARA scanning
            # because the Authenticode helper had a bad day.
            pass
        scan_context = {
            "filepath": str(path),
            "filename": Path(path).name,
            "extension": Path(path).suffix.lstrip("."),
            "filetype": Path(path).suffix.lower(),
            "signature_status": sig_status.lower() if sig_status else "",
            "signer_subject": sig_signer,
            "trusted_publisher": sig_trusted,
            "scope": "file",
        }
        try:
            result = scanner.scan_file(str(path), pack=pack, context=scan_context)
        except TypeError:
            # Older scanners pre-context kwarg — degrade gracefully.
            try:
                result = scanner.scan_file(str(path), pack=pack)
            except Exception as exc:
                return {"status": "error", "engine": self.display_name, "error": str(exc)}
        except Exception as exc:
            return {"status": "error", "engine": self.display_name, "error": str(exc)}
        duration_ms = int((time.time() - started) * 1000)
        raw_status = str(result.get("status", "")).lower()
        if raw_status in {"missing", "unavailable", "skipped"}:
            return {
                "status": "unavailable" if raw_status != "missing" else "error",
                "engine": self.display_name,
                "error": result.get("reason", raw_status),
                "scan_time_ms": duration_ms,
            }
        if raw_status == "error":
            return {
                "status": "error",
                "engine": self.display_name,
                "error": result.get("reason", "yara scan failed"),
                "scan_time_ms": duration_ms,
            }
        active_matches = int(result.get("active_match_count", 0) or 0)
        matched_rules = list(result.get("matched_rules", []) or [])
        score = int(result.get("score", 0) or 0)
        agg_severity = str(result.get("severity", "low"))

        if active_matches > 0 and matched_rules:
            # Gate: only escalate to `infected` when BOTH the aggregate
            # score AND the highest single-rule severity cross their
            # thresholds. Signed binaries with a trusted publisher
            # cannot reach `infected` unless we see a critical-severity
            # rule firing — single noisy "capability" matches stay
            # `suspicious` for the fusion layer to weigh against other
            # engines.
            severe_enough = self._severity_at_least(agg_severity, self._INFECTED_MIN_SEVERITY)
            score_high_enough = score >= self._INFECTED_MIN_SCORE
            if sig_trusted and not self._severity_at_least(agg_severity, "critical"):
                # Trusted publisher → never escalate beyond `suspicious`
                # without a critical-severity match. This is what every
                # commercial AV does for Microsoft-signed binaries.
                escalated = False
            else:
                escalated = severe_enough and score_high_enough
            status = "infected" if escalated else "suspicious"
            return {
                "status": status,
                "engine": self.display_name,
                "malware_name": matched_rules[0],
                "score": score,
                "matched_rules": matched_rules[:25],
                "match_count": active_matches,
                "severity": agg_severity,
                "confidence": str(result.get("confidence", "low")),
                "pack": result.get("pack", pack),
                "scan_time_ms": duration_ms,
                "signature_status": sig_status,
                "trusted_publisher": sig_trusted,
                "gate": {
                    "min_score": self._INFECTED_MIN_SCORE,
                    "min_severity": self._INFECTED_MIN_SEVERITY,
                    "escalated_to_infected": escalated,
                },
            }
        return {
            "status": "clean",
            "engine": self.display_name,
            "score": score,
            "match_count": 0,
            "pack": result.get("pack", pack),
            "scan_time_ms": duration_ms,
            "signature_status": sig_status,
            "trusted_publisher": sig_trusted,
        }
