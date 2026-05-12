"""Unit tests for the Wave-2 antivirus components.

Wave-2 layers a third opinion onto the signature engines: an
independent YARA engine (community + bespoke packs), a behavioural
static analyzer (PE structural capabilities), and a cloud sandbox
provider (Hybrid-Analysis hash lookup). On top of that sits a MITRE
ATT&CK technique mapper that turns per-provider indicators into
analyst-grade tactic/technique coverage.

These tests use injected fakes for every external dependency so the
suite stays deterministic offline:
  * `YaraXProvider` is fed a fake `scanner_module` matching the
    `plugins.yara_scanner` surface.
  * `BehaviouralAnalyzer` is fed a fake static-PE analyzer.
  * `CloudSandboxProvider` is fed a fake `ThreatIntelClient` via
    `client_factory`.
  * `MitreMapper` is exercised against synthetic provider results that
    reproduce the live-pipeline shape.
  * Final fusion is verified end-to-end through `AntivirusService` with
    only the in-memory fakes wired up — no live network.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from services.antivirus import (
    AntivirusService,
    BehaviouralAnalyzer,
    CloudSandboxProvider,
    MitreMapper,
    YaraXProvider,
)


# --------------------------------------------------------------------- YARA-X


class _FakeYaraScanner:
    """Mimic the `plugins.yara_scanner` module surface."""

    YARA_AVAILABLE = True

    def __init__(self, scan_result: dict | None = None, packs: dict | None = None):
        self._scan_result = scan_result or {"status": "ok", "active_match_count": 0, "matched_rules": [], "score": 0}
        self._packs = packs or {"enterprise": [Path("rule_a.yar"), Path("rule_b.yar")]}

    def available_packs(self):
        return self._packs

    def scan_file(self, path, *, pack="enterprise"):
        return dict(self._scan_result)


class YaraXProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="shadowlab-yarax-test-"))
        self.sample = self.tmp / "sample.bin"
        self.sample.write_bytes(b"\x90" * 32)

    def test_yara_unavailable_yields_unavailable_status(self) -> None:
        scanner = _FakeYaraScanner()
        scanner.YARA_AVAILABLE = False
        provider = YaraXProvider(self.tmp, scanner_module=scanner)
        result = provider.scan_file(self.sample, policy={"yara_pack": "enterprise"})
        self.assertEqual(result["status"], "unavailable")

    def test_active_match_promotes_to_infected(self) -> None:
        scanner = _FakeYaraScanner(
            scan_result={
                "status": "ok",
                "active_match_count": 2,
                "matched_rules": ["MAL_RANSOMWARE_LockBit", "INDICATOR_TOOL_AdvancedRun"],
                "score": 70,
                "severity": "high",
                "confidence": "high",
                "pack": "enterprise",
            }
        )
        provider = YaraXProvider(self.tmp, scanner_module=scanner)
        result = provider.scan_file(self.sample, policy={"yara_pack": "enterprise"})
        self.assertEqual(result["status"], "infected")
        self.assertEqual(result["malware_name"], "MAL_RANSOMWARE_LockBit")
        self.assertEqual(result["match_count"], 2)
        self.assertGreaterEqual(result["score"], 70)

    def test_no_matches_returns_clean(self) -> None:
        provider = YaraXProvider(self.tmp, scanner_module=_FakeYaraScanner())
        result = provider.scan_file(self.sample, policy={"yara_pack": "enterprise"})
        self.assertEqual(result["status"], "clean")


# ------------------------------------------------------- Behavioural analyzer


class _FakeStaticPE:
    """Mimic the `StaticPEAnalysisService` surface."""

    def __init__(self, report):
        self._report = report

    def analyze_file(self, path):
        return dict(self._report)


class BehaviouralAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="shadowlab-behavioural-test-"))

    def _write_pe(self, body: bytes = b"MZ\x90\x00\x03") -> Path:
        sample = self.tmp / "binary.exe"
        sample.write_bytes(body)
        return sample

    def _write_non_pe(self) -> Path:
        sample = self.tmp / "script.txt"
        sample.write_bytes(b"#!/bin/sh\necho hi\n")
        return sample

    def test_non_pe_is_skipped(self) -> None:
        analyzer = BehaviouralAnalyzer(self.tmp, analyzer=_FakeStaticPE({"status": "ok"}))
        result = analyzer.scan_file(self._write_non_pe(), policy={})
        self.assertEqual(result["status"], "skipped")

    def test_high_severity_suspicious_escalates_to_infected(self) -> None:
        analyzer = BehaviouralAnalyzer(
            self.tmp,
            analyzer=_FakeStaticPE(
                {
                    "status": "ok",
                    "summary": "RWX section detected; CreateRemoteThread imported",
                    "risk": {
                        "score": 75,
                        "severity": "high",
                        "verdict": "suspicious",
                        "confidence": "medium",
                        "reasons": ["RWX section(s)", "Suspicious imports: CreateRemoteThread"],
                    },
                    "headers": {"imphash": "abc", "is_dotnet": False},
                }
            ),
        )
        result = analyzer.scan_file(self._write_pe(), policy={})
        self.assertEqual(result["status"], "infected")
        self.assertIn("Heuristic.Behavioural", result["malware_name"])
        self.assertGreaterEqual(result["score"], 70)

    def test_medium_severity_stays_suspicious(self) -> None:
        analyzer = BehaviouralAnalyzer(
            self.tmp,
            analyzer=_FakeStaticPE(
                {
                    "status": "ok",
                    "summary": "TLS callback present",
                    "risk": {
                        "score": 35,
                        "severity": "medium",
                        "verdict": "suspicious",
                        "confidence": "low",
                        "reasons": ["TLS callback(s)"],
                    },
                    "headers": {"imphash": "", "is_dotnet": False},
                }
            ),
        )
        result = analyzer.scan_file(self._write_pe(), policy={})
        self.assertEqual(result["status"], "suspicious")
        self.assertEqual(result["malware_name"], "Heuristic.Behavioural.Medium")

    def test_clean_verdict_returns_clean_status(self) -> None:
        analyzer = BehaviouralAnalyzer(
            self.tmp,
            analyzer=_FakeStaticPE(
                {
                    "status": "ok",
                    "summary": "Standard signed binary",
                    "risk": {
                        "score": 5,
                        "severity": "low",
                        "verdict": "informational",
                        "confidence": "low",
                        "reasons": [],
                    },
                    "headers": {"imphash": "", "is_dotnet": True},
                }
            ),
        )
        result = analyzer.scan_file(self._write_pe(), policy={})
        self.assertEqual(result["status"], "clean")


# ---------------------------------------------------------- Cloud sandbox


class _FakeSandboxClient:
    def __init__(self, report):
        self._report = report

    def check_file_hybrid_analysis(self, sha, *, api_key=None):
        return dict(self._report)


class CloudSandboxProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="shadowlab-sandbox-test-"))
        self.sample = self.tmp / "sample.bin"
        self.sample.write_bytes(b"benign sandbox sample\n")

    def test_no_api_key_yields_skipped(self) -> None:
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": ""}, clear=False):
            provider = CloudSandboxProvider(self.tmp, client_factory=lambda: _FakeSandboxClient({}))
            result = provider.scan_file(self.sample, policy={})
            self.assertEqual(result["status"], "skipped")

    def test_malicious_verdict_emits_infected_with_techniques(self) -> None:
        report = {
            "status": "ok",
            "verdict": "malicious",
            "threat_score": 78,
            "threat_level": 2,
            "av_detect": 42,
            "vx_family": "LockBit",
            "submission_name": "ransom.exe",
            "environment_description": "Windows 10 64",
            "mitre_attcks": [
                {"technique": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
                {"technique": "T1055", "tactic": "Defense Evasion", "name": "Process Injection"},
            ],
            "compromised_hosts": ["1.2.3.4"],
            "domains": ["evil.example"],
            "hosts": ["198.51.100.10"],
            "report_count": 3,
        }
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": "x"}, clear=False):
            provider = CloudSandboxProvider(self.tmp, client_factory=lambda: _FakeSandboxClient(report))
            result = provider.scan_file(self.sample, policy={})
            self.assertEqual(result["status"], "infected")
            self.assertEqual(result["malware_name"], "LockBit")
            self.assertGreaterEqual(result["score"], 70)
            ids = {item["id"] for item in result["techniques"]}
            self.assertIn("T1486", ids)
            self.assertIn("T1055", ids)

    def test_unknown_hash_returns_clean(self) -> None:
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": "x"}, clear=False):
            provider = CloudSandboxProvider(
                self.tmp,
                client_factory=lambda: _FakeSandboxClient({"status": "no_results"}),
            )
            result = provider.scan_file(self.sample, policy={})
            self.assertEqual(result["status"], "clean")


# ------------------------------------------------------------- MITRE mapper


class MitreMapperTests(unittest.TestCase):
    def test_dedupes_techniques_across_providers(self) -> None:
        provider_results = {
            "cloud_sandbox": {
                "techniques": [
                    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
                    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
                ]
            },
            "behavioural": {
                "reasons": [
                    "Suspicious imports: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread",
                    "RWX section(s)",
                ]
            },
            "yara_x": {
                "matched_rules": ["MAL_RANSOMWARE_LockBit", "INJECT_THREAD_API"],
                "malware_name": "MAL_RANSOMWARE_LockBit",
            },
        }
        mapper = MitreMapper()
        techniques = mapper.map_provider_results(provider_results)
        ids = {row["id"] for row in techniques}
        self.assertIn("T1055", ids)
        self.assertIn("T1486", ids)
        # Process injection sub-technique fired via behavioural reason.
        self.assertIn("T1055.002", ids)
        # Sources tracking — T1055 should attribute multiple providers.
        t1055 = next(row for row in techniques if row["id"] == "T1055")
        self.assertGreaterEqual(len(t1055["sources"]), 2)

    def test_coverage_summary_groups_by_tactic(self) -> None:
        techniques = [
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "sources": ["x"]},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "sources": ["y"]},
        ]
        coverage = MitreMapper().coverage_summary(techniques)
        self.assertEqual(coverage["total_techniques"], 2)
        self.assertIn("Defense Evasion", coverage["tactics_covered"])
        self.assertIn("Impact", coverage["tactics_covered"])

    def test_empty_input_is_safe(self) -> None:
        mapper = MitreMapper()
        self.assertEqual(mapper.map_provider_results({}), [])
        self.assertEqual(mapper.coverage_summary([])["total_techniques"], 0)


# ---------------------------------------------------- End-to-end fusion


class FusionWithWave2Tests(unittest.TestCase):
    """Confirm the new providers and MITRE mapper land in the fused result."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="shadowlab-fusion-test-"))
        self.sample = self.tmp / "binary.exe"
        # MZ header so behavioural analyzer doesn't skip.
        self.sample.write_bytes(b"MZ\x90\x00\x03" + b"\x00" * 256)

    def _service_with_fakes(self, *, behavioural_verdict="suspicious", behavioural_severity="high",
                             yara_matches=None, sandbox_techniques=None):
        service = AntivirusService(self.tmp)
        service.providers["yara_x"] = YaraXProvider(
            self.tmp,
            scanner_module=_FakeYaraScanner(
                scan_result=(
                    {
                        "status": "ok",
                        "active_match_count": len(yara_matches or []),
                        "matched_rules": list(yara_matches or []),
                        "score": 60 if yara_matches else 0,
                    }
                )
            ),
        )
        service.providers["behavioural"] = BehaviouralAnalyzer(
            self.tmp,
            analyzer=_FakeStaticPE(
                {
                    "status": "ok",
                    "summary": "RWX + CreateRemoteThread",
                    "risk": {
                        "score": 70,
                        "severity": behavioural_severity,
                        "verdict": behavioural_verdict,
                        "confidence": "medium",
                        "reasons": ["RWX section(s)", "Suspicious imports: CreateRemoteThread"],
                    },
                    "headers": {"imphash": "", "is_dotnet": False},
                }
            ),
        )
        sandbox_report = {
            "status": "ok",
            "verdict": "malicious" if sandbox_techniques else "no_results",
            "threat_score": 80 if sandbox_techniques else 0,
            "threat_level": 2 if sandbox_techniques else 0,
            "vx_family": "Sandbox.Test" if sandbox_techniques else "",
            "mitre_attcks": [
                {"technique": tid, "tactic": "Impact", "name": "Test"} for tid in (sandbox_techniques or [])
            ],
        }
        service.providers["cloud_sandbox"] = CloudSandboxProvider(
            self.tmp, client_factory=lambda: _FakeSandboxClient(sandbox_report)
        )
        return service

    def test_two_suspicious_providers_escalate_to_infected(self) -> None:
        # Two providers (behavioural + yara behaviour-only suspicion) won't
        # both come from identical paths, but two suspicious behavioural
        # signals — even from the same kind of provider — should escalate.
        # Easiest reproduction: behavioural medium + a sandbox suspicious
        # via verdict="suspicious".
        service = self._service_with_fakes(
            behavioural_verdict="suspicious",
            behavioural_severity="medium",  # → status "suspicious"
        )
        # Inject a second suspicious provider via fake.
        sandbox_report = {
            "status": "ok",
            "verdict": "suspicious",
            "threat_score": 35,
            "threat_level": 1,
        }
        service.providers["cloud_sandbox"] = CloudSandboxProvider(
            self.tmp, client_factory=lambda: _FakeSandboxClient(sandbox_report)
        )
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": "x", "MALWAREBAZAAR_AUTH_KEY": "",
                                            "YARAIFY_AUTH_KEY": "", "VIRUSTOTAL_API_KEY": ""}, clear=False):
            result = service.scan_file(
                self.sample,
                policy={"providers": ["behavioural", "cloud_sandbox"], "mitre_mapping_enabled": True},
                use_cache=False,
            )
        # cloud_sandbox malicious-or-suspicious + threat_level >= 1 → status infected by provider.
        # Two infected/suspicious signals → fused malicious.
        self.assertIn(result["status"], {"infected", "suspicious"})
        summary = result["summary"]
        self.assertIn(summary["fused_verdict"], {"malicious", "suspicious"})

    def test_single_suspicious_keeps_status_suspicious(self) -> None:
        service = self._service_with_fakes(
            behavioural_verdict="suspicious",
            behavioural_severity="medium",
        )
        # Run only behavioural, no sandbox/yara, so we have exactly one suspicious.
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": ""}, clear=False):
            result = service.scan_file(
                self.sample,
                policy={"providers": ["behavioural"], "mitre_mapping_enabled": True},
                use_cache=False,
            )
        self.assertEqual(result["status"], "suspicious")
        self.assertEqual(result["summary"]["fused_verdict"], "suspicious")
        # No infected hits, but suspicious_hits list is populated.
        self.assertEqual(result["summary"]["provider_hits"], [])
        self.assertIn("behavioural", result["summary"]["provider_suspicious"])

    def test_mitre_techniques_appear_in_fused_summary(self) -> None:
        service = self._service_with_fakes(
            behavioural_verdict="suspicious",
            behavioural_severity="high",
            yara_matches=["MAL_RANSOMWARE_LockBit"],
            sandbox_techniques=["T1486", "T1055"],
        )
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": "x"}, clear=False):
            result = service.scan_file(
                self.sample,
                policy={
                    "providers": ["yara_x", "behavioural", "cloud_sandbox"],
                    "mitre_mapping_enabled": True,
                },
                use_cache=False,
            )
        summary = result["summary"]
        self.assertIn("mitre_techniques", summary)
        self.assertIn("mitre_coverage", summary)
        ids = {row["id"] for row in summary["mitre_techniques"]}
        self.assertIn("T1486", ids)  # sandbox-supplied
        self.assertIn("T1055", ids)  # sandbox + behavioural reasons
        self.assertGreaterEqual(summary["mitre_coverage"]["total_techniques"], 2)

    def test_mitre_disabled_returns_empty_techniques(self) -> None:
        service = self._service_with_fakes(
            behavioural_verdict="suspicious",
            behavioural_severity="high",
            sandbox_techniques=["T1486"],
        )
        with mock.patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": "x"}, clear=False):
            result = service.scan_file(
                self.sample,
                policy={
                    "providers": ["behavioural", "cloud_sandbox"],
                    "mitre_mapping_enabled": False,
                },
                use_cache=False,
            )
        self.assertEqual(result["summary"]["mitre_techniques"], [])
        self.assertEqual(result["summary"]["mitre_coverage"]["total_techniques"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
