from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from services.integrity_service import IntegrityService


class IntegrityServiceTests(unittest.TestCase):
    def test_manifest_detects_modified_missing_and_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            out_dir = base_dir / "shadowlab_out"
            evidence_dir = base_dir / "evidence_locker"
            quarantine_dir = base_dir / "shadowlab_quarantine"
            out_dir.mkdir(parents=True, exist_ok=True)
            evidence_dir.mkdir(parents=True, exist_ok=True)
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            artifact = out_dir / "score.json"
            evidence = evidence_dir / "sample.png"
            quarantined = quarantine_dir / "binary.exe"
            artifact.write_text(json.dumps({"ok": True}), encoding="utf-8")
            evidence.write_bytes(b"png")
            quarantined.write_bytes(b"quarantine")

            service = IntegrityService(base_dir, out_dir)
            manifest = service.refresh_manifest()
            self.assertEqual(len(manifest["files"]), 3)

            artifact.write_text(json.dumps({"ok": False}), encoding="utf-8")
            evidence.unlink()
            (quarantine_dir / "new.exe").write_bytes(b"new")

            result = service.verify_manifest()
            self.assertEqual(result["status"], "drift_detected")
            self.assertEqual(result["counts"]["modified"], 1)
            self.assertEqual(result["counts"]["missing"], 1)
            self.assertEqual(result["counts"]["untracked"], 1)

    def test_manifest_can_be_signed_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            out_dir = base_dir / "shadowlab_out"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "score.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
            service = IntegrityService(base_dir, out_dir)
            with mock.patch.dict(os.environ, {"SHADOWLAB_INTEGRITY_SIGNING_KEY": "unit-test-signing-key"}, clear=False):
                manifest = service.refresh_manifest()
                self.assertEqual(manifest["signature_status"], "signed")
                result = service.verify_manifest()
            self.assertTrue(result["signature_valid"])
            self.assertTrue(service.history(limit=5))


if __name__ == "__main__":
    unittest.main()
