from __future__ import annotations

import math
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

try:
    import pefile  # type: ignore
except Exception:
    pefile = None


PEFILE_AVAILABLE = pefile is not None
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc": 6,
    "VirtualAllocEx": 8,
    "VirtualProtect": 6,
    "VirtualProtectEx": 8,
    "WriteProcessMemory": 10,
    "ReadProcessMemory": 6,
    "CreateRemoteThread": 12,
    "NtAllocateVirtualMemory": 12,
    "NtWriteVirtualMemory": 12,
    "NtProtectVirtualMemory": 12,
    "NtCreateThreadEx": 14,
    "QueueUserAPC": 8,
    "SetWindowsHookEx": 8,
    "AmsiScanBuffer": 10,
    "EtwEventWrite": 10,
    "WldpQueryDynamicCodeTrust": 10,
    "WinExec": 6,
    "ShellExecuteA": 6,
    "ShellExecuteW": 6,
    "URLDownloadToFileA": 8,
    "URLDownloadToFileW": 8,
}
SUSPICIOUS_SECTION_NAMES = {".x", ".packed", ".aspack", ".upx0", ".upx1", ".vmp0", ".vmp1", ".stub"}
HIGH_RISK_DOTNET_IMPORTS = {"VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "AmsiScanBuffer"}


class StaticPEAnalysisService:
    def analyze_file(self, file_path: str) -> dict[str, Any]:
        target = Path(file_path).expanduser()
        if not target.exists() or not target.is_file():
            return {"status": "missing", "summary": "Target file not found.", "file_path": str(target)}
        if not PEFILE_AVAILABLE:
            return {
                "status": "unavailable",
                "summary": "pefile is not installed, so structural PE analysis is unavailable.",
                "file_path": str(target),
            }

        try:
            pe = pefile.PE(str(target), fast_load=False)
            pe.parse_data_directories()
        except Exception as exc:
            return {
                "status": "error",
                "summary": f"PE parsing failed: {exc}",
                "file_path": str(target),
            }

        sections = self._sections(pe)
        imports = self._imports(pe)
        suspicious_imports = [name for name in imports["functions"] if name in SUSPICIOUS_IMPORTS]
        overlay_size = self._overlay_size(pe, target)
        entry_section = self._entry_point_section(pe)
        entry_in_last_section = bool(entry_section and sections and entry_section == sections[-1]["name"])
        dotnet_info = self._dotnet_info(pe)
        tls_callbacks = self._tls_callbacks(pe)
        resource_info = self._resource_info(pe)
        version_info = self._version_info(pe)
        signature = self._signature_status(target)
        score = 0
        reasons: list[str] = []

        rwx_sections = [section["name"] for section in sections if section["rwx"]]
        if rwx_sections:
            score += min(24, 10 + len(rwx_sections) * 4)
            reasons.append(f"RWX section(s): {', '.join(rwx_sections[:4])}")

        high_entropy_sections = [section for section in sections if float(section["entropy"]) >= 7.2]
        if high_entropy_sections:
            score += min(20, 6 + len(high_entropy_sections) * 4)
            reasons.append(
                "High-entropy section(s): " + ", ".join(f"{item['name']}={item['entropy']}" for item in high_entropy_sections[:4])
            )

        if suspicious_imports:
            score += min(35, sum(SUSPICIOUS_IMPORTS[name] for name in suspicious_imports[:8]))
            reasons.append(f"Suspicious imports: {', '.join(suspicious_imports[:8])}")

        if self._has_injection_chain(suspicious_imports):
            score += 12
            reasons.append("Suspicious import chain supports remote memory/thread injection")

        odd_sections = [section["name"] for section in sections if section["name"].lower() in SUSPICIOUS_SECTION_NAMES]
        if odd_sections:
            score += min(14, 6 + len(odd_sections) * 2)
            reasons.append(f"Suspicious section name(s): {', '.join(odd_sections[:4])}")

        if overlay_size >= 8192:
            score += 6
            reasons.append(f"Overlay detected ({overlay_size} bytes)")
        elif overlay_size > 0:
            score += 2
            reasons.append(f"Small overlay detected ({overlay_size} bytes)")

        if entry_in_last_section:
            score += 8
            reasons.append(f"Entry point located in last section ({entry_section})")

        if tls_callbacks:
            score += min(12, 4 + len(tls_callbacks) * 2)
            reasons.append(f"TLS callback(s) present: {len(tls_callbacks)}")

        if dotnet_info["is_dotnet"] and suspicious_imports:
            score += 6
            reasons.append(".NET image also exposes suspicious Win32/native API imports")

        if dotnet_info["is_dotnet"] and dotnet_info["has_native_entry_stub"]:
            score += 6
            reasons.append(".NET image has a native entry stub")

        if dotnet_info["is_dotnet"] and dotnet_info["high_risk_imports"]:
            score += min(14, 4 + len(dotnet_info["high_risk_imports"]) * 2)
            reasons.append(f".NET high-risk imports: {', '.join(dotnet_info['high_risk_imports'][:5])}")

        if resource_info["count"] == 0 and not resource_info["has_version"] and not str(signature.get("status", "")).startswith("Valid"):
            score += 3
            reasons.append("No version/resource metadata present")

        signature_score, signature_reason = self._signature_risk(signature, target, version_info)
        if signature_score:
            score += signature_score
            reasons.append(signature_reason)

        score = min(100, score)
        confidence = "high" if score >= 55 else "medium" if score >= 25 else "low"
        severity = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
        verdict = "suspicious" if score >= 35 else "informational"

        return {
            "status": "ok",
            "file_path": str(target),
            "summary": self._summary(sections, suspicious_imports, overlay_size, score),
            "risk": {
                "score": score,
                "severity": severity,
                "confidence": confidence,
                "verdict": verdict,
                "reasons": reasons,
            },
            "headers": {
                "machine": hex(int(getattr(pe.FILE_HEADER, "Machine", 0) or 0)),
                "timestamp": int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0),
                "subsystem": int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0) or 0),
                "entry_point": hex(int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0)),
                "image_base": hex(int(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0) or 0)),
                "imphash": pe.get_imphash() if hasattr(pe, "get_imphash") else "",
                "is_dll": bool(getattr(pe.FILE_HEADER, "Characteristics", 0) & 0x2000),
                "is_dotnet": dotnet_info["is_dotnet"],
            },
            "sections": sections,
            "imports": imports,
            "overlay": {"size": overlay_size, "present": overlay_size > 0},
            "entry_point_section": entry_section,
            "tls_callbacks": tls_callbacks,
            "resources": resource_info,
            "version_info": version_info,
            "signature": signature,
            "dotnet": dotnet_info,
        }

    def _sections(self, pe: Any) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for section in getattr(pe, "sections", []):
            raw_name = section.Name.decode(errors="ignore").strip("\x00 ").strip() or "<unnamed>"
            entropy = round(self._entropy(section.get_data()), 4)
            characteristics = int(getattr(section, "Characteristics", 0) or 0)
            result.append(
                {
                    "name": raw_name,
                    "virtual_size": int(getattr(section, "Misc_VirtualSize", 0) or 0),
                    "raw_size": int(getattr(section, "SizeOfRawData", 0) or 0),
                    "entropy": entropy,
                    "readable": bool(characteristics & 0x40000000),
                    "writable": bool(characteristics & 0x80000000),
                    "executable": bool(characteristics & 0x20000000),
                    "rwx": bool(characteristics & 0xE0000000 == 0xE0000000),
                }
            )
        return result

    def _imports(self, pe: Any) -> dict[str, Any]:
        libraries: list[str] = []
        functions: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll_name = (entry.dll or b"").decode(errors="ignore").strip()
            if dll_name:
                libraries.append(dll_name)
            for imp in getattr(entry, "imports", []) or []:
                if imp.name:
                    functions.append(imp.name.decode(errors="ignore").strip())
        deduped_functions = sorted({item for item in functions if item})
        return {
            "library_count": len(libraries),
            "function_count": len(deduped_functions),
            "libraries": libraries[:40],
            "functions": deduped_functions[:120],
        }

    def _overlay_size(self, pe: Any, target: Path) -> int:
        try:
            offset = pe.get_overlay_data_start_offset()
        except Exception:
            offset = None
        if offset is None:
            return 0
        try:
            return max(0, target.stat().st_size - int(offset))
        except Exception:
            return 0

    def _entry_point_section(self, pe: Any) -> str:
        try:
            entry_rva = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0)
            section = pe.get_section_by_rva(entry_rva)
            if section is None:
                return ""
            return section.Name.decode(errors="ignore").strip("\x00 ").strip()
        except Exception:
            return ""

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        total = len(data)
        for count in counts:
            if not count:
                continue
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    def _has_injection_chain(self, suspicious_imports: list[str]) -> bool:
        lowered = {item.lower() for item in suspicious_imports}
        alloc = {"virtualallocex", "ntallocatevirtualmemory"} & lowered
        write = {"writeprocessmemory", "ntwritevirtualmemory"} & lowered
        thread = {"createremotethread", "ntcreatethreadex", "queueuserapc"} & lowered
        return bool(alloc and write and thread)

    def _tls_callbacks(self, pe: Any) -> list[str]:
        callbacks: list[str] = []
        try:
            tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
            if tls and getattr(tls.struct, "AddressOfCallBacks", 0):
                callbacks.append(hex(int(tls.struct.AddressOfCallBacks)))
        except Exception:
            return []
        return callbacks

    def _resource_info(self, pe: Any) -> dict[str, Any]:
        count = 0
        has_version = False
        try:
            root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
            if root:
                entries = getattr(root, "entries", []) or []
                count = len(entries)
                has_version = any(getattr(entry, "id", None) == 16 for entry in entries)
        except Exception:
            return {"count": 0, "has_version": False}
        return {"count": count, "has_version": has_version}

    def _version_info(self, pe: Any) -> dict[str, Any]:
        data: dict[str, Any] = {}
        try:
            for file_info in getattr(pe, "FileInfo", []) or []:
                if getattr(file_info, "Key", b"") == b"StringFileInfo":
                    for table in getattr(file_info, "StringTable", []) or []:
                        for key, value in getattr(table, "entries", {}).items():
                            data[str(key)] = str(value)
        except Exception:
            return {}
        return data

    def _dotnet_info(self, pe: Any) -> dict[str, Any]:
        try:
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            is_dotnet = bool(getattr(directory, "VirtualAddress", 0))
        except Exception:
            is_dotnet = False
        imports = self._imports(pe)
        high_risk_imports = [name for name in imports["functions"] if name in HIGH_RISK_DOTNET_IMPORTS]
        entry_point = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0)
        return {
            "is_dotnet": is_dotnet,
            "high_risk_imports": high_risk_imports[:12],
            "has_native_entry_stub": bool(is_dotnet and entry_point),
        }

    def _signature_status(self, target: Path) -> dict[str, str]:
        if platform.system() != "Windows" or not os.path.exists(target):
            return {"status": "unknown"}
        try:
            escaped_path = str(target).replace("'", "''")
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "$sig=Get-AuthenticodeSignature -FilePath "
                    f"'{escaped_path}'; "
                    "[pscustomobject]@{Status=$sig.Status;StatusMessage=$sig.StatusMessage;Signer=$sig.SignerCertificate.Subject} | ConvertTo-Json -Compress"
                ),
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="ignore", timeout=10)
            stripped = output.strip()
            if stripped.startswith("{"):
                import json

                payload = json.loads(stripped)
                return {
                    "status": str(payload.get("Status", "unknown") or "unknown"),
                    "status_message": str(payload.get("StatusMessage", "") or ""),
                    "signer_subject": str(payload.get("Signer", "") or ""),
                }
            return {"status": stripped or "unknown"}
        except Exception:
            return {"status": "unknown"}

    def _signature_risk(self, signature: dict[str, str], target: Path, version_info: dict[str, Any]) -> tuple[int, str]:
        status = str(signature.get("status", "unknown") or "unknown")
        signer = str(signature.get("signer_subject", "") or "")
        company_name = str(version_info.get("CompanyName", "") or "")
        filename = target.name.lower()

        if status in {"Valid", "ValidCatalogSigned"}:
            if any(token in filename for token in ("payload", "helper", "dropper", "stub")):
                return 6, "Signed binary uses a suspicious filename pattern"
            if company_name and signer and company_name.lower() not in signer.lower():
                return 4, "Signer subject does not match embedded company metadata"
            return 0, ""
        if status in {"NotSigned", "UnknownError", "HashMismatch", "NotTrusted"}:
            return 6, f"Authenticode status: {status}"
        return 4, f"Authenticode status: {status}"

    def _summary(self, sections: list[dict[str, Any]], suspicious_imports: list[str], overlay_size: int, score: int) -> str:
        parts: list[str] = [f"Sections={len(sections)}", f"Score={score}"]
        if suspicious_imports:
            parts.append(f"Suspicious imports={len(suspicious_imports)}")
        if overlay_size:
            parts.append(f"Overlay={overlay_size} bytes")
        if sections:
            highest = max(sections, key=lambda item: float(item["entropy"]))
            parts.append(f"Top entropy={highest['name']}:{highest['entropy']}")
        return " | ".join(parts)
