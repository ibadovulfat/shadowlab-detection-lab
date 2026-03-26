import tempfile
import unittest
from pathlib import Path
from unittest import mock
import json

import plugins.memory_forensics as memory_forensics
import plugins.yara_scanner as yara_scanner
import threat_intelligence
from services.response_service import ResponseOrchestrator


class ThreatIntelligenceTests(unittest.TestCase):
    def setUp(self) -> None:
        yara_scanner._load_policy.cache_clear()
        yara_scanner.clear_registry_rule_override_cache()

    def test_local_yara_scan_matches_basic_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.bin"
            sample.write_text("powershell -enc AAAA", encoding="utf-8")

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="basic")

            self.assertEqual(result["status"], "ok")
            self.assertGreaterEqual(result["match_count"], 1)
            self.assertIn("Suspicious_Strings", result["matched_rules"])

    def test_scan_process_falls_back_to_local_yara_when_yaraify_misses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.bin"
            sample.write_text("powershell -enc BBBB", encoding="utf-8")

            with mock.patch.object(threat_intelligence, "check_file_vt", return_value={"status": "skipped"}), \
                 mock.patch.object(threat_intelligence, "check_file_malwarebazaar", return_value={"status": "skipped"}), \
                 mock.patch.object(threat_intelligence, "check_file_yaraify", return_value={"status": "ok", "matched_rules": [], "yara_rule_count": 0}):
                result = threat_intelligence.scan_process({"exe": str(sample), "pid": 42, "name": "sample.exe"})

            self.assertEqual(result["local_yara"]["status"], "ok")
            self.assertIn("Suspicious_Strings", result["local_yara"]["matched_rules"])

    def test_inceptor_pack_detects_tradecraft_strings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.cs"
            sample.write_text(
                "AmsiScanBuffer WldpQueryDynamicCodeTrust EtwEventWrite VirtualProtect RtlMoveMemory",
                encoding="utf-8",
            )

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="inceptor")

            self.assertEqual(result["status"], "ok")
            self.assertIn("Inceptor_AMSI_WLDP_ETW_Bypass", result["matched_rules"])

    def test_scan_process_returns_fusion_verdict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.bin"
            sample.write_text("powershell -enc BBBB", encoding="utf-8")

            with mock.patch.object(threat_intelligence, "check_file_vt", return_value={"last_analysis_stats": {"malicious": 2, "suspicious": 1}}), \
                 mock.patch.object(threat_intelligence, "check_file_malwarebazaar", return_value={"status": "ok", "signature": "TestFam"}), \
                 mock.patch.object(threat_intelligence, "check_file_yaraify", return_value={"status": "ok", "matched_rules": [], "yara_rule_count": 0}), \
                 mock.patch.object(threat_intelligence, "run_static_pe_analysis", return_value={"status": "ok", "static_analysis": {"score": 32, "confidence": "medium", "suspicious_indicators": ["VirtualProtect"], "verdict": "suspicious"}}):
                result = threat_intelligence.scan_process({"exe": str(sample), "pid": 42, "name": "sample.exe"})

            self.assertIn("fusion", result)
            self.assertGreater(result["fusion"]["score"], 0)
            self.assertIn("static_pe", result)

    def test_fusion_verdict_includes_static_pe_signals(self):
        fusion = threat_intelligence.fuse_detection_verdict(
            static_result={
                "status": "ok",
                "static_analysis": {
                    "score": 58,
                    "confidence": "high",
                    "suspicious_indicators": ["VirtualProtect", "NtCreateThreadEx"],
                    "verdict": "suspicious",
                },
            }
        )

        self.assertGreaterEqual(fusion["score"], 20)
        self.assertTrue(any("Static PE analysis" in item for item in fusion["reasons"]))

    def test_allowlist_suppresses_low_signal_community_match(self):
        match = {
            "rule": "GenericPacker",
            "source": "signature_base",
            "severity": "medium",
            "score": 24,
            "confidence": "medium",
            "tags": ["packer"],
            "meta": {"description": "generic packer hit"},
        }
        context = {
            "filepath": "C:\\Windows\\System32\\trusted.exe",
            "signature_status": "Valid",
            "sha256": "",
        }

        result = yara_scanner._apply_suppression(match, context)

        self.assertTrue(result["suppressed"])
        self.assertIn("trusted path with valid signature", result["suppression_reasons"])
        self.assertEqual(result["confidence"], "low")
        self.assertLess(result["score"], 24)

    def test_pack_strategy_exposes_fast_and_balanced_profiles(self):
        packs = yara_scanner.available_packs()

        self.assertIn("fast", packs)
        self.assertIn("balanced", packs)
        self.assertIn("deep", packs)
        self.assertLessEqual(len(packs["fast"]), len(packs["balanced"]))
        self.assertLessEqual(len(packs["balanced"]), len(packs["enterprise"]))

    def test_memory_analysis_runs_enterprise_yara_on_dump(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dump_path = Path(temp_dir) / "memdump_test_1.raw"
            dump_path.write_text("AmsiScanBuffer WldpQueryDynamicCodeTrust EtwEventWrite VirtualProtect RtlMoveMemory", encoding="utf-8")

            with mock.patch.object(memory_forensics, "acquire_memory_dump", return_value={"path": str(dump_path), "status": "completed"}), \
                 mock.patch.object(memory_forensics, "run_volatility_analysis", return_value={"severity": "low", "verdict": "clean", "summary": "ok", "findings": [], "transcript": []}):
                result = memory_forensics.run_analysis(1, "testproc")

            self.assertEqual(result["analysis"]["memory_yara"]["status"], "ok")
            self.assertIn("Inceptor_AMSI_WLDP_ETW_Bypass", result["analysis"]["memory_yara"]["matched_rules"])
            self.assertIn("fusion", result["analysis"])

    def test_inceptor_pack_detects_unhook_tradecraft(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.cs"
            sample.write_text(
                "UnhookNtdll NtOpenSection NtMapViewOfSection NtUnmapViewOfSection ntdll.dll .text",
                encoding="utf-8",
            )

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="inceptor")

            self.assertEqual(result["status"], "ok")
            self.assertIn("Inceptor_Unhook_NTDLL_Tradecraft", result["matched_rules"])

    def test_inceptor_pack_detects_pe_load_template(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "pe_load_template.cs"
            sample.write_text(
                "PELoader pe = new PELoader(decoded); Preferred Load Address BaseRelocationTable "
                "LoadModuleFromDisk GetLibraryAddress CreateThread WaitForSingleObject",
                encoding="utf-8",
            )

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="inceptor")

            self.assertEqual(result["status"], "ok")
            self.assertIn("Inceptor_PE_Load_Loader_Template", result["matched_rules"])

    def test_inceptor_pack_detects_installutil_injection_template(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "installutil_template.cs"
            sample.write_text(
                "[System.ComponentModel.RunInstaller(true)] "
                "public override void Uninstall(System.Collections.IDictionary savedState) "
                "VirtualAllocEx WriteProcessMemory CreateRemoteThread ProcessAccessFlags.All CommandLineToArgvW",
                encoding="utf-8",
            )

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="inceptor")

            self.assertEqual(result["status"], "ok")
            self.assertIn("Inceptor_InstallUtil_Remote_Injection_Template", result["matched_rules"])

    def test_inceptor_pack_detects_nodebug_template(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "nodebug_template.cs"
            sample.write_text(
                "CheckRemoteDebuggerPresent IsDebuggerPresent NtQueryInformationProcess "
                "NtRemoveProcessDebug NtSetInformationDebugObject ProcessDebugPort ProcessDebugObjectHandle",
                encoding="utf-8",
            )

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="inceptor")

            self.assertEqual(result["status"], "ok")
            self.assertIn("Inceptor_Nodebug_AntiAnalysis_Template", result["matched_rules"])

    def test_health_report_includes_policy_and_pack_counts(self):
        report = yara_scanner.build_health_report()

        self.assertEqual(report["status"], "ok")
        self.assertTrue(report["policy_path"].endswith("local_yara_policy.json"))
        self.assertIn("enterprise", report["pack_counts"])

    def test_registry_rule_tuning_boosts_match_score(self):
        with mock.patch.object(yara_scanner, "_registry_rule_overrides", return_value={
            "inceptor_amsi_wldp_etw_bypass": {"tuning": {"score_delta": 9}, "suppressions": {}, "status": "active"}
        }):
            match = {
                "rule": "Inceptor_AMSI_WLDP_ETW_Bypass",
                "source_path": "plugins/rules/inceptor_tradecraft.yar",
                "score": 20,
                "severity": "high",
                "confidence": "medium",
                "suppressed": False,
                "scope": "file",
            }
            boosted = yara_scanner._apply_boost(match)

        self.assertTrue(boosted["boosted"])
        self.assertEqual(boosted["boost_delta"], 9)
        self.assertEqual(boosted["score"], 29)
        self.assertEqual(boosted["confidence"], "medium")

    def test_policy_save_sanitizes_invalid_entries(self):
        original_policy = yara_scanner.POLICY_PATH.read_text(encoding="utf-8")
        try:
            saved = yara_scanner.save_policy(
                {
                    "allowlist_rule_patterns": ["  RuleOne  ", "", "ruleone"],
                    "boost_rule_patterns": {"inceptor": "9", "bad": "not-a-number", "huge": 999},
                    "unexpected_key": ["ignored"],
                }
            )
        finally:
            yara_scanner.POLICY_PATH.write_text(original_policy, encoding="utf-8")
            yara_scanner._load_policy.cache_clear()

        self.assertEqual(saved["allowlist_rule_patterns"], ["RuleOne"])
        self.assertEqual(saved["boost_rule_patterns"]["inceptor"], 9)
        self.assertEqual(saved["boost_rule_patterns"]["huge"], 20)
        self.assertNotIn("unexpected_key", saved)

    def test_memory_pack_detects_apc_injection_tradecraft(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "memdump.raw"
            sample.write_text(
                "NtQueueApcThread QueueUserAPC CreateRemoteThread RtlCreateUserThread NtWriteVirtualMemory OpenProcess",
                encoding="utf-8",
            )

            result = threat_intelligence.run_local_yara_scan(str(sample), pack="memory")

            self.assertEqual(result["status"], "ok")
            self.assertIn("Memory_Syscall_Apc_Injection", result["matched_rules"])

    def test_memory_analysis_adds_dump_heuristic_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dump_path = Path(temp_dir) / "memdump_test_2.raw"
            dump_path.write_text(
                "amsi.dll AmsiScanBuffer EtwEventWrite VirtualProtect ntdll.dll .text NtMapViewOfSection NtUnmapViewOfSection PAGE_EXECUTE_READWRITE",
                encoding="utf-8",
            )

            with mock.patch.object(memory_forensics, "acquire_memory_dump", return_value={"path": str(dump_path), "status": "completed"}), \
                 mock.patch.object(memory_forensics, "run_volatility_analysis", return_value={"severity": "low", "verdict": "clean", "summary": "ok", "findings": [], "transcript": []}):
                result = memory_forensics.run_analysis(2, "memoryproc")

            findings = result["analysis"]["findings"]
            titles = [item["title"] for item in findings]
            self.assertIn("Patched AMSI or ETW sequence", titles)
            self.assertIn("NTDLL remap or unhook sequence", titles)
            self.assertEqual(result["analysis"]["memory_yara"]["pack"], "memory")

    def test_memory_analysis_detects_unbacked_and_manual_map_markers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dump_path = Path(temp_dir) / "memdump_test_3.raw"
            dump_path.write_text(
                "manual map DInvoke MapModuleToMemory PAGE_EXECUTE_READWRITE private shellcode "
                "This program cannot be run in DOS mode ntdll.dll .text patched integrity mismatch",
                encoding="utf-8",
            )

            with mock.patch.object(memory_forensics, "acquire_memory_dump", return_value={"path": str(dump_path), "status": "completed"}), \
                 mock.patch.object(memory_forensics, "run_volatility_analysis", return_value={"severity": "low", "verdict": "clean", "summary": "ok", "findings": [], "transcript": []}):
                result = memory_forensics.run_analysis(3, "mapproc")

            titles = [item["title"] for item in result["analysis"]["findings"]]
            self.assertIn("Unbacked executable private region", titles)
            self.assertIn("Manual mapped module indicators", titles)
            self.assertIn("NTDLL text integrity mismatch", titles)

    def test_memory_analysis_parses_handle_and_module_findings(self):
        dlllist_findings = memory_forensics._parse_volatility_output(
            "windows.dlllist",
            "amsi.dll C:\\Users\\ulfat\\AppData\\Local\\Temp\\amsi.dll\nntdll.dll",
            41,
            "loader.exe",
        )
        handle_findings = memory_forensics._parse_volatility_output(
            "windows.handles",
            "Process Handle -> lsass.exe",
            41,
            "loader.exe",
        )

        self.assertTrue(any(item["title"] == "Sensitive module load from suspicious path" for item in dlllist_findings))
        self.assertTrue(any(item["title"] == "Cross-process handle access" for item in handle_findings))

    def test_memory_scope_policy_can_suppress_rule_pattern(self):
        original_policy = yara_scanner.POLICY_PATH.read_text(encoding="utf-8")
        try:
            policy = json.loads(original_policy)
            policy["memory_suppressed_rule_patterns"] = ["generic_memory_rule"]
            yara_scanner.save_policy(policy)
            match = {
                "rule": "Generic_Memory_Rule",
                "source": "signature_base",
                "source_path": "vendor/yara/generic_memory_rule.yar",
                "severity": "medium",
                "score": 20,
                "confidence": "medium",
                "tags": [],
                "meta": {},
            }
            suppressed = yara_scanner._apply_suppression(match, {"filepath": "dump.raw", "scope": "memory"})
        finally:
            yara_scanner.POLICY_PATH.write_text(original_policy, encoding="utf-8")
            yara_scanner._load_policy.cache_clear()

        self.assertTrue(suppressed["suppressed"])
        self.assertIn("memory rule pattern suppressed by local policy", suppressed["suppression_reasons"])


class ResponsePlanTests(unittest.TestCase):
    def test_build_triage_response_plan_high_confidence(self):
        orchestrator = ResponseOrchestrator()
        profile = {
            "name": "evil.exe",
            "exe": "C:\\Temp\\evil.exe",
            "network_connections": ["10.0.0.5:4444->1.2.3.4:443"],
            "execution_context": {
                "suspicious": True,
                "reasons": ["Parent process is a browser."],
                "suspicious_chain_matches": ["Browser-to-PowerShell execution chain"],
            },
            "child_processes": [{"pid": 500, "name": "cmd.exe"}],
        }
        fusion = {"confidence": "high", "severity": "critical", "reasons": ["high score"]}
        local_yara = {"matched_rules": ["Inceptor_Process_Injection_Syscall_Chain"]}

        plan = orchestrator.build_triage_response_plan(profile=profile, fusion=fusion, local_yara=local_yara, memory={})

        actions = [item["action"] for item in plan["actions"]]
        self.assertIn("suspend", actions)
        self.assertIn("quarantine", actions)
        self.assertIn("firewall-drop", actions)
        self.assertTrue(any(item["action"] == "inceptor-hunt" for item in plan["manual_required"]))
        self.assertTrue(any(item["action"] == "execution-context-review" for item in plan["manual_required"]))
        self.assertTrue(any(item["action"] == "suspicious-chain-review" for item in plan["manual_required"]))
        self.assertTrue(any(item["action"] == "lineage-review" for item in plan["manual_required"]))


if __name__ == "__main__":
    unittest.main()
