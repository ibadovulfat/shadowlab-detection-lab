from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import services.static_pe_service as static_pe_service


class _FakeSection:
    def __init__(self, name: str, data: bytes, characteristics: int, virtual_size: int = 512, raw_size: int = 512):
        self.Name = name.encode() + b"\x00"
        self._data = data
        self.Characteristics = characteristics
        self.Misc_VirtualSize = virtual_size
        self.SizeOfRawData = raw_size

    def get_data(self) -> bytes:
        return self._data


class _FakeImportEntry:
    def __init__(self, dll: str, functions: list[str]):
        self.dll = dll.encode()
        self.imports = [SimpleNamespace(name=name.encode()) for name in functions]


class _FakePE:
    def __init__(self) -> None:
        self.sections = [
            _FakeSection(".text", b"\x90" * 200, 0x60000020),
            _FakeSection(".x", bytes(range(256)), 0xE0000020),
        ]
        self.DIRECTORY_ENTRY_IMPORT = [
            _FakeImportEntry("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
        ]
        self.FILE_HEADER = SimpleNamespace(Machine=0x8664, TimeDateStamp=123456, Characteristics=0x0002)
        self.OPTIONAL_HEADER = SimpleNamespace(
            AddressOfEntryPoint=0x2000,
            ImageBase=0x140000000,
            Subsystem=2,
            DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=0) for _ in range(15)],
        )
        self.OPTIONAL_HEADER.DATA_DIRECTORY[14] = SimpleNamespace(VirtualAddress=0x3000)
        self.DIRECTORY_ENTRY_TLS = SimpleNamespace(struct=SimpleNamespace(AddressOfCallBacks=0x180003000))
        self.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(entries=[SimpleNamespace(id=16), SimpleNamespace(id=3)])
        self.FileInfo = [
            SimpleNamespace(
                Key=b"StringFileInfo",
                StringTable=[SimpleNamespace(entries={"CompanyName": "ShadowLab", "FileDescription": "Test PE"})],
            )
        ]

    def parse_data_directories(self) -> None:
        return None

    def get_imphash(self) -> str:
        return "fake-imphash"

    def get_overlay_data_start_offset(self) -> int:
        return 256

    def get_section_by_rva(self, _rva: int):
        return self.sections[-1]


class StaticPEAnalysisServiceTests(unittest.TestCase):
    def test_reports_unavailable_when_pefile_missing(self) -> None:
        service = static_pe_service.StaticPEAnalysisService()
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.exe"
            sample.write_bytes(b"MZ")
            with mock.patch.object(static_pe_service, "PEFILE_AVAILABLE", False):
                result = service.analyze_file(str(sample))
        self.assertEqual(result["status"], "unavailable")

    def test_analyze_file_extracts_structural_risk(self) -> None:
        service = static_pe_service.StaticPEAnalysisService()
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.exe"
            sample.write_bytes(b"MZ" + (b"A" * 1024))
            fake_pe = _FakePE()
            fake_module = SimpleNamespace(PE=mock.Mock(return_value=fake_pe))
            with mock.patch.object(static_pe_service, "PEFILE_AVAILABLE", True):
                with mock.patch.object(static_pe_service, "pefile", fake_module):
                    with mock.patch.object(
                        service,
                        "_signature_status",
                        return_value={"status": "NotSigned", "signer_subject": "", "status_message": ""},
                    ):
                        result = service.analyze_file(str(sample))
        self.assertEqual(result["status"], "ok")
        self.assertGreater(result["risk"]["score"], 45)
        self.assertTrue(any("RWX" in reason for reason in result["risk"]["reasons"]))
        self.assertTrue(any("TLS callback" in reason for reason in result["risk"]["reasons"]))
        self.assertTrue(any("Authenticode status" in reason for reason in result["risk"]["reasons"]))
        self.assertTrue(any(".NET high-risk imports" in reason for reason in result["risk"]["reasons"]))
        self.assertIn("VirtualAllocEx", result["imports"]["functions"])
        self.assertEqual(result["entry_point_section"], ".x")
        self.assertTrue(result["headers"]["is_dotnet"])
        self.assertEqual(result["resources"]["count"], 2)
        self.assertEqual(result["version_info"]["CompanyName"], "ShadowLab")


if __name__ == "__main__":
    unittest.main()
