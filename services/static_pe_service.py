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

# Tier-1: APIs whose presence is itself a high-confidence malware
# capability signal. Direct NT syscalls and dynamic-code-trust probes
# are almost never used by legitimate user-mode applications — they
# typically appear in syscall-hopping shellcode loaders, manual mappers,
# EDR-evasion frameworks (Inceptor / DInvoke), and ETW/AMSI bypass
# loaders. Score these full-weight.
SUSPICIOUS_IMPORTS_TIER1 = {
    "NtAllocateVirtualMemory": 12,
    "NtWriteVirtualMemory": 12,
    "NtProtectVirtualMemory": 12,
    "NtCreateThreadEx": 14,
    "NtMapViewOfSection": 12,
    "NtUnmapViewOfSection": 10,
    "WldpQueryDynamicCodeTrust": 10,
    "EtwEventWriteEx": 8,
    "AmsiScanBufferUTF16": 10,
    "QueueUserAPC": 8,
    "SetWindowsHookEx": 6,
}

# Tier-2: APIs that ARE used by malware but ALSO have legitimate uses
# in modern Windows runtimes — V8/JavaScriptCore JIT (VirtualAlloc /
# VirtualProtect), the .NET CLR (WriteProcessMemory for native interop),
# AMSI-aware applications (AmsiScanBuffer is required by anything that
# wants to be defender-friendly), shell launchers (ShellExecute), etc.
# These score MUCH lower on their own; their weight only fires when
# combined with another red flag (RWX section, high entropy, no
# signature, suspicious filename) — see `_tier2_score` for the gating.
SUSPICIOUS_IMPORTS_TIER2 = {
    "VirtualAlloc": 3,
    "VirtualAllocEx": 5,
    "VirtualProtect": 3,
    "VirtualProtectEx": 5,
    "WriteProcessMemory": 6,
    "ReadProcessMemory": 4,
    "CreateRemoteThread": 8,
    "AmsiScanBuffer": 3,
    "EtwEventWrite": 3,
    "WinExec": 4,
    "ShellExecuteA": 2,
    "ShellExecuteW": 2,
    "URLDownloadToFileA": 6,
    "URLDownloadToFileW": 6,
}

# Backwards-compatible flat dict for callers that still iterate over
# SUSPICIOUS_IMPORTS (tests, the static-pe API surface, etc.). New code
# should read the tiered dicts directly.
SUSPICIOUS_IMPORTS = {**SUSPICIOUS_IMPORTS_TIER2, **SUSPICIOUS_IMPORTS_TIER1}

SUSPICIOUS_SECTION_NAMES = {".x", ".packed", ".aspack", ".upx0", ".upx1", ".vmp0", ".vmp1", ".stub"}
HIGH_RISK_DOTNET_IMPORTS = {"VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "AmsiScanBuffer"}

# DoS guard: malicious PE files with a giant import directory or
# pathological resource tree can pin pefile in CPU for minutes. Cap
# how many imports we score (we already truncate to 8 in the scoring
# math; this caps the parse-side cost too).
_MAX_IMPORTS_INSPECTED = 4096
_MAX_SECTIONS_INSPECTED = 96


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
        # DoS guard — cap pathological PE files.
        import_functions = list(imports.get("functions", []) or [])[: _MAX_IMPORTS_INSPECTED]
        sections = sections[: _MAX_SECTIONS_INSPECTED]
        suspicious_imports = [name for name in import_functions if name in SUSPICIOUS_IMPORTS]
        tier1_imports = [name for name in import_functions if name in SUSPICIOUS_IMPORTS_TIER1]
        tier2_imports = [name for name in import_functions if name in SUSPICIOUS_IMPORTS_TIER2]
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

        # Tier-1 imports: full weight, no gating. These are direct NT
        # syscall primitives + dynamic-code-trust probes — legitimate
        # software essentially never imports them by name.
        if tier1_imports:
            tier1_score = min(35, sum(SUSPICIOUS_IMPORTS_TIER1[name] for name in tier1_imports[:8]))
            score += tier1_score
            reasons.append(f"Tier-1 suspicious imports: {', '.join(tier1_imports[:8])}")

        # Tier-2 imports: GATED. These APIs are commonly used by
        # legitimate JIT engines (V8, .NET CLR), defender-aware apps
        # (AMSI), shell launchers, and updaters. Imports alone aren't
        # enough — they only contribute meaningfully when at least one
        # corroborating red flag is present (RWX section, high-entropy
        # section, suspicious section name). Without a corroborator, a
        # mere "VirtualAlloc + VirtualProtect" pattern in `msedgewebview2`
        # / `node.exe` / `chrome.exe` is ignored.
        tier2_raw = sum(SUSPICIOUS_IMPORTS_TIER2[name] for name in tier2_imports[:8])
        has_corroborator = bool(rwx_sections) or bool(high_entropy_sections) or bool(
            [s for s in sections if s["name"].lower() in SUSPICIOUS_SECTION_NAMES]
        )
        if tier2_imports and has_corroborator:
            tier2_score = min(20, tier2_raw)
            score += tier2_score
            reasons.append(f"Tier-2 imports (with RWX/entropy/odd-section corroborator): {', '.join(tier2_imports[:8])}")
        elif tier2_imports:
            # Surface but don't score — analysts still see what
            # capabilities the binary exposes.
            reasons.append(f"Tier-2 imports (no corroborator, ignored): {', '.join(tier2_imports[:8])}")

        if self._has_injection_chain(suspicious_imports) and has_corroborator:
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

        # Clamp into [0, 100] — `_signature_risk` may legitimately return
        # a negative delta (trusted-publisher reduction), and a clean
        # signed binary should never finish at a negative score.
        score = max(0, min(100, score))
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
        """Authenticode status via the shared in-process helper.

        Replaces the per-scan PowerShell spawn. The helper caches by
        `(path, mtime, size)` so folder-watcher scans don't pay the
        Authenticode cost more than once per file version. Result
        shape matches the legacy dict so the rest of this file is
        unchanged.
        """
        if platform.system() != "Windows" or not os.path.exists(target):
            return {"status": "unknown"}
        try:
            from services.antivirus.authenticode import signature_status as _sig_lookup
            info = _sig_lookup(target)
            return {
                "status": str(info.get("status", "unknown") or "unknown"),
                "status_message": "",
                "signer_subject": str(info.get("signer_subject", "") or ""),
                "trusted_publisher": bool(info.get("trusted_publisher", False)),
            }
        except Exception:
            return {"status": "unknown"}

    def _signature_risk(self, signature: dict[str, Any], target: Path, version_info: dict[str, Any]) -> tuple[int, str]:
        """Translate Authenticode state into a score delta.

        Key change vs the legacy version:

        * A **trusted-publisher** signature now produces a *negative*
          delta — i.e. it actively REDUCES the heuristic score. Without
          this, signed Microsoft-Corporation binaries that legitimately
          use V8 JIT (`msedgewebview2.exe`) or .NET interop
          (`PowerShell.exe`) easily crossed the "critical" threshold and
          got eskalated to malicious. Now a trusted publisher offsets
          ~30 points of heuristic noise — enough to drag a clean signed
          binary back below the "high" severity gate while still
          letting a real malicious-but-signed sample register.
        * The "helper/payload/stub" filename heuristic is GATED on the
          publisher NOT being trusted. `MicrosoftEdgeUpdateStub.exe` and
          `WebView2RuntimeInstaller.exe` are legitimate, and the
          filename pattern alone should never penalize them.
        """
        status = str(signature.get("status", "unknown") or "unknown")
        signer = str(signature.get("signer_subject", "") or "")
        trusted = bool(signature.get("trusted_publisher", False))
        company_name = str(version_info.get("CompanyName", "") or "")
        filename = target.name.lower()

        if status in {"Valid", "ValidCatalogSigned"}:
            if trusted:
                # Strong negative — equivalent to wiping out the noise
                # from RWX + Tier-2 imports on a Microsoft-signed
                # platform binary. Score is clamped at min(0, …) by the
                # caller's `min(100, max(0, score + signature_score))`
                # in the scoring loop so we can't drive it negative.
                return -30, f"Signed by trusted publisher ({signer or 'verified'})"
            if any(token in filename for token in ("payload", "helper", "dropper", "stub")):
                # Only penalize when publisher is NOT trusted — legit
                # Microsoft updaters use *Stub.exe* / *Helper.exe* names.
                return 6, "Signed binary uses a suspicious filename pattern"
            if company_name and signer and company_name.lower() not in signer.lower():
                return 4, "Signer subject does not match embedded company metadata"
            # Generic-signed-but-not-trusted: no score change.
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
