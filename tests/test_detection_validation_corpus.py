from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.validate_detection_corpus import evaluate_sample, run_validation


class DetectionValidationCorpusTests(unittest.TestCase):
    def test_evaluate_sample_passes_when_rule_and_static_threshold_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_path = Path(temp_dir) / "sample.bin"
            sample_path.write_text("dummy", encoding="utf-8")
            sample = {
                "id": "sample1",
                "path": str(sample_path),
                "yara_pack": "memory",
                "expected_rules_any": ["Memory_Syscall_Apc_Injection"],
                "expected_static_min_score": 10,
            }
            static_service = mock.Mock()
            static_service.analyze_file.return_value = {"status": "ok", "risk": {"score": 12}}
            with mock.patch("scripts.validate_detection_corpus.threat_intelligence.run_local_yara_scan", return_value={"status": "ok", "matched_rules": ["Memory_Syscall_Apc_Injection"]}):
                result = evaluate_sample(sample, static_service)
        self.assertEqual(result["status"], "passed")

    def test_run_validation_reports_invalid_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text('{"samples":[{"id":"x"}]}', encoding="utf-8")
            result = run_validation(manifest_path)
        self.assertEqual(result["status"], "invalid")
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
