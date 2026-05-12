"""Behavioural / structural analysis provider for the antivirus pipeline.

The Wave-1 engines (KicomAV, ClamAV, cloud reputation, YARA) all
return *signature* verdicts — they say "yes, this matches a known bad
pattern". A behavioural engine says something different: "this binary
has the *capabilities* of a malicious actor even if no signature has
been written for it yet". That's the pre-zero-day layer real
commercial AV products run on top of signatures.

This provider runs the existing `StaticPEAnalysisService`
(pefile-backed PE structural inspection: imports, sections, entropy,
overlays, TLS callbacks, .NET stub, signature status) and adapts the
output to the `AntivirusProvider` shape. The existing service already
weights findings into a numeric risk score; we map that score onto
ShadowLab's `clean / suspicious / infected` status taxonomy so the
fusion layer can aggregate it with signature engines.

Non-PE samples (scripts, archives, ELF, Mach-O) get `status: skipped`
with a reason — the analyzer doesn't pretend to cover formats it
wasn't built for. That's how a real AV pipeline routes file types to
the right engine.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .base import AntivirusProvider


PE_MAGIC = b"MZ"


class BehaviouralAnalyzer(AntivirusProvider):
    provider_key = "behavioural"
    display_name = "Behavioural Static Analyzer"

    def __init__(self, base_dir: Path, *, analyzer=None):
        self.base_dir = Path(base_dir)
        self._analyzer = analyzer

    def _get_analyzer(self):
        if self._analyzer is not None:
            return self._analyzer
        from services.static_pe_service import StaticPEAnalysisService  # local import by design
        self._analyzer = StaticPEAnalysisService()
        return self._analyzer

    def status(self) -> dict[str, Any]:
        try:
            from services import static_pe_service
            pefile_loaded = bool(getattr(static_pe_service, "PEFILE_AVAILABLE", False))
        except Exception:
            pefile_loaded = False
        return {
            "display_name": self.display_name,
            "available": pefile_loaded,
            "pefile_loaded": pefile_loaded,
            "definitions_loaded": pefile_loaded,
            "latest_signature_update": 0.0,
            "mode": "behavioural-static",
            "scope": "PE32 / PE32+ / .NET",
            "notes": [
                "Capability-driven scoring (RWX sections, injection chain, TLS, entropy).",
                "Skips non-PE samples — feed them to format-specific engines.",
            ],
        }

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        target = Path(path)
        magic = self._read_magic(target)
        if magic != PE_MAGIC:
            return {
                "status": "skipped",
                "engine": self.display_name,
                "error": "Behavioural analyzer only inspects PE binaries (MZ header expected)",
            }
        analyzer = self._get_analyzer()
        started = time.time()
        try:
            report = analyzer.analyze_file(str(target))
        except Exception as exc:
            return {"status": "error", "engine": self.display_name, "error": str(exc)}
        duration_ms = int((time.time() - started) * 1000)
        raw_status = str(report.get("status", "")).lower()
        if raw_status == "missing":
            return {"status": "error", "engine": self.display_name, "error": "Target missing", "scan_time_ms": duration_ms}
        if raw_status == "unavailable":
            return {
                "status": "unavailable",
                "engine": self.display_name,
                "error": report.get("summary", "pefile not available"),
                "scan_time_ms": duration_ms,
            }
        if raw_status == "error":
            return {
                "status": "error",
                "engine": self.display_name,
                "error": report.get("summary", "PE analysis failed"),
                "scan_time_ms": duration_ms,
            }
        risk = report.get("risk", {}) if isinstance(report.get("risk"), dict) else {}
        score = int(risk.get("score", 0) or 0)
        severity = str(risk.get("severity", "low")).lower()
        verdict = str(risk.get("verdict", "informational")).lower()
        confidence = str(risk.get("confidence", "low")).lower()
        reasons = list(risk.get("reasons", []) or [])

        # Translate behavioural verdict → AV status taxonomy.
        #
        # IMPORTANT: a heuristic engine MUST NOT unilaterally return
        # `infected`. Doing so historically let one noisy behavioural
        # hit on a signed Microsoft binary (msedgewebview2.exe, V8 JIT
        # patterns) override every signature engine and quarantine
        # the file. The new contract: behavioural can ONLY contribute
        # `suspicious` — the fusion layer in `service._fuse` combines
        # it with other engines and decides whether to escalate.
        #
        # We still differentiate the malware-name label by severity so
        # the analyst sees how confidently the heuristic fired, but the
        # status is capped at `suspicious`. This matches how Defender's
        # behavioural monitoring contributes to a multi-engine verdict.
        if verdict == "suspicious" and severity in {"high", "critical"}:
            status = "suspicious"
            malware_name = f"Heuristic.Behavioural.{severity.title()}"
        elif verdict == "suspicious":
            status = "suspicious"
            malware_name = "Heuristic.Behavioural.Medium"
        else:
            status = "clean"
            malware_name = ""

        return {
            "status": status,
            "engine": self.display_name,
            "malware_name": malware_name,
            "score": score,
            "severity": severity,
            "confidence": confidence,
            "verdict": verdict,
            "reasons": reasons[:12],
            "imphash": report.get("headers", {}).get("imphash", "") if isinstance(report.get("headers"), dict) else "",
            "is_dotnet": bool(report.get("headers", {}).get("is_dotnet")) if isinstance(report.get("headers"), dict) else False,
            "scan_time_ms": duration_ms,
            "behavioural_report": {
                "summary": report.get("summary", ""),
                "sections_count": len(report.get("sections", []) or []),
                "imports_count": int((report.get("imports", {}) or {}).get("function_count", 0) or 0),
                "tls_callbacks": report.get("tls_callbacks", []),
                "overlay": report.get("overlay", {}),
                "entry_point_section": report.get("entry_point_section", ""),
            },
        }

    @staticmethod
    def _read_magic(path: Path) -> bytes:
        try:
            with path.open("rb") as handle:
                return handle.read(2)
        except OSError:
            return b""
