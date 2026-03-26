from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from services.die_binding_service import DieBindingService


class DieBindingAvailabilityTests(unittest.TestCase):
    """Tests for import-guard and availability check."""

    def test_is_available_returns_bool(self) -> None:
        result = DieBindingService.is_available()
        self.assertIsInstance(result, bool)

    def test_database_path_returns_path_or_none(self) -> None:
        result = DieBindingService.database_path()
        self.assertTrue(result is None or isinstance(result, Path))


class DieBindingScanTests(unittest.TestCase):
    """Tests for scan_file behaviour using mocked die module."""

    def test_scan_file_missing_target(self) -> None:
        service = DieBindingService()
        result = service.scan_file("/nonexistent/path/sample.exe")
        self.assertEqual(result["status"], "missing")

    def test_scan_file_returns_unavailable_when_die_not_installed(self) -> None:
        service = DieBindingService()
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "test.exe"
            sample.write_bytes(b"MZ")
            with mock.patch("services.die_binding_service._DIE_AVAILABLE", False):
                result = service.scan_file(str(sample))
        self.assertEqual(result["status"], "unavailable")

    def test_scan_file_parses_json_result(self) -> None:
        service = DieBindingService()
        die_json = json.dumps({
            "detects": [
                {
                    "filetype": "PE64",
                    "parentfilepart": "Header",
                    "values": [
                        {
                            "type": "Compiler",
                            "name": "MSVC",
                            "version": "19.36",
                            "string": "Compiler: MSVC(19.36)",
                            "info": "",
                        },
                        {
                            "type": "Packer",
                            "name": "UPX",
                            "version": "4.24",
                            "string": "Packer: UPX(4.24)[NRV,brute]",
                            "info": "NRV,brute",
                        },
                    ],
                }
            ]
        })
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "test.exe"
            sample.write_bytes(b"MZ")
            with mock.patch("services.die_binding_service._DIE_AVAILABLE", True):
                with mock.patch("services.die_binding_service._die") as mock_die:
                    mock_die.ScanFlags.RESULT_AS_JSON = 1
                    mock_die.ScanFlags.DEEP_SCAN = 2
                    mock_die.scan_file.return_value = die_json
                    with mock.patch.object(service, "database_path", return_value=Path("/fake/db")):
                        result = service.scan_file(str(sample))

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["filetype"], "PE64")
        self.assertEqual(len(result["detects"]), 2)
        self.assertTrue(any(item["category"] == "packing" for item in result["highlights"]))
        self.assertTrue(any(item["category"] == "toolchain" for item in result["highlights"]))

    def test_scan_file_handles_exception_gracefully(self) -> None:
        service = DieBindingService()
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "test.exe"
            sample.write_bytes(b"MZ")
            with mock.patch("services.die_binding_service._DIE_AVAILABLE", True):
                with mock.patch("services.die_binding_service._die") as mock_die:
                    mock_die.ScanFlags.RESULT_AS_JSON = 1
                    mock_die.ScanFlags.DEEP_SCAN = 2
                    mock_die.scan_file.side_effect = RuntimeError("crash")
                    with mock.patch.object(service, "database_path", return_value=None):
                        result = service.scan_file(str(sample))
        self.assertEqual(result["status"], "error")
        self.assertIn("crash", result["summary"])


class DieBindingClassifyTests(unittest.TestCase):
    """Tests for _classify_value highlight categorisation."""

    def test_packer_classified(self) -> None:
        entry = {"type": "Packer", "name": "UPX", "version": "", "string": "Packer: UPX", "info": ""}
        result = DieBindingService._classify_value(entry)
        self.assertEqual(result["category"], "packing")

    def test_compiler_classified(self) -> None:
        entry = {"type": "Compiler", "name": "MSVC", "version": "", "string": "Compiler: MSVC", "info": ""}
        result = DieBindingService._classify_value(entry)
        self.assertEqual(result["category"], "toolchain")

    def test_library_classified(self) -> None:
        entry = {"type": "Library", "name": "OpenSSL", "version": "", "string": "Library: OpenSSL", "info": ""}
        result = DieBindingService._classify_value(entry)
        self.assertEqual(result["category"], "framework")


if __name__ == "__main__":
    unittest.main()
