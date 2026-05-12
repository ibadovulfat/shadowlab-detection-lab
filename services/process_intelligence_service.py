from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

import psutil
import yaml


class ProcessIntelligenceService:
    def __init__(self, max_history: int = 500):
        self.max_history = max_history
        self.snapshot_history: deque[list[dict[str, Any]]] = deque(maxlen=max_history)
        self.browser_parents = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe"}
        self.office_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "visio.exe"}
        self.proxy_execution_names = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "installutil.exe",
            "regasm.exe",
            "mssqltoolsservice.exe",
        }
        self.sigmaeye_behavior = self._load_sigmaeye_behavior()
        self.lolbins = {str(item).lower() for item in self.sigmaeye_behavior.get("lolbins", [])}
        self.suspicious_patterns = list(self.sigmaeye_behavior.get("suspicious_patterns", []))

    def snapshot_processes(self, include_deep_fields: bool = False) -> list[dict[str, Any]]:
        snapshot: list[dict[str, Any]] = []
        for proc in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "username",
                "cpu_percent",
                "memory_percent",
                "exe",
                "cmdline",
                "create_time",
                "status",
            ]
        ):
            info = proc.info
            exe_path = info.get("exe")
            entry = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "cpu_percent": info.get("cpu_percent"),
                "memory_percent": info.get("memory_percent"),
                "exe": exe_path,
                "cmdline": " ".join(info.get("cmdline") or []),
                "create_time": info.get("create_time"),
                "status": info.get("status"),
            }
            if include_deep_fields:
                entry["sha256"] = self._safe_sha256(exe_path)
                entry["signature_status"] = self._signature_status(exe_path)
            snapshot.append(entry)
        self.snapshot_history.append(snapshot)
        return snapshot

    def profile_process(self, pid: int) -> dict[str, Any]:
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Process {pid} not found")

        try:
            with process.oneshot():
                exe_path = self._safe_call(process.exe)
                cmdline_list = self._safe_call(process.cmdline, [])
                cmdline = " ".join(cmdline_list)
                connections = []
                try:
                    connections = [
                        f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port}" if c.raddr else f"{c.laddr.ip}:{c.laddr.port}"
                        for c in process.net_connections(kind="inet")
                    ]
                except Exception:
                    connections = []
                parent = self._safe_call(process.parent)
                parent_name = ""
                parent_pid = None
                parent_cmdline = ""
                parent_exe = ""
                parent_signature: dict[str, str] = {"status": "unknown", "signer": "", "issuer": "", "thumbprint": ""}
                if parent is not None:
                    parent_pid = self._safe_call(parent.pid)
                    parent_name = self._safe_call(parent.name, "")
                    parent_cmdline = " ".join(self._safe_call(parent.cmdline, []) or [])
                    parent_exe = self._safe_call(parent.exe, "") or ""
                    parent_signature = self._signature_info(parent_exe)
                children_summary = self._safe_children(process)
                open_files = self._safe_call(process.open_files, [])
                module_paths = self._safe_module_paths(process)
                execution_context = self._execution_context(
                    process_name=self._safe_call(process.name, "") or "",
                    exe_path=exe_path or "",
                    cmdline=cmdline,
                    parent_name=parent_name or "",
                )
                partial_telemetry = any(
                    [
                        not exe_path,
                        not parent_name and pid not in {0, 4},
                        not cmdline and str(self._safe_call(process.name, "") or "").lower() not in {"system idle process", "system"},
                        self._safe_session_id(pid) == "unknown",
                    ]
                )
                return {
                    "pid": pid,
                    "ppid": parent_pid,
                    "name": self._safe_call(process.name, ""),
                    "parent_name": parent_name,
                    "parent_cmdline": parent_cmdline,
                    "parent_exe": parent_exe,
                    "parent_signature": parent_signature,
                    "cmdline": cmdline,
                    "exe": exe_path,
                    "cwd": self._safe_call(process.cwd, "") if hasattr(process, "cwd") else "",
                    "username": self._safe_call(process.username, ""),
                    "status": self._safe_call(process.status, ""),
                    "session_id": self._safe_session_id(pid),
                    "integrity_level": self._safe_integrity_level(pid),
                    "partial_telemetry": partial_telemetry,
                    "create_time": self._safe_call(process.create_time, 0.0),
                    "sha256": self._safe_sha256(exe_path),
                    "signature_status": self._signature_status(exe_path),
                    "signature": self._signature_info(exe_path),
                    "network_connections": connections[:25],
                    "child_processes": children_summary[:12],
                    "open_file_count": len(open_files or []),
                    "loaded_module_count": len(module_paths),
                    "loaded_modules": module_paths[:25],
                    "execution_context": execution_context,
                }
        except psutil.NoSuchProcess:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Process {pid} terminated during profiling")

    def _safe_sha256(self, path: str | None) -> str | None:
        if not path or not os.path.exists(path):
            return None
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(8192), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None

    def _safe_call(self, func, default=None):
        try:
            return func()
        except Exception:
            return default

    def _safe_session_id(self, pid: int) -> str:
        if platform.system() != "Windows":
            return "unknown"
        try:
            cmd = ["powershell", "-NoProfile", "-Command", f"(Get-Process -Id {int(pid)} -ErrorAction Stop).SessionId"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="ignore", timeout=5)
            return output.strip() or "unknown"
        except Exception:
            return "unknown"

    def _safe_integrity_level(self, pid: int) -> str:
        if platform.system() != "Windows":
            return "unknown"
        try:
            import ctypes
            from ctypes import wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            TOKEN_QUERY = 0x0008
            TOKEN_INTEGRITY_LEVEL = 25

            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            process_handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not process_handle:
                return "unknown"
            token_handle = wintypes.HANDLE()
            try:
                if not advapi32.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token_handle)):
                    return "unknown"
                needed = wintypes.DWORD(0)
                advapi32.GetTokenInformation(token_handle, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(needed))
                if needed.value <= 0:
                    return "unknown"
                buffer = ctypes.create_string_buffer(needed.value)
                if not advapi32.GetTokenInformation(token_handle, TOKEN_INTEGRITY_LEVEL, buffer, needed, ctypes.byref(needed)):
                    return "unknown"

                class SID_AND_ATTRIBUTES(ctypes.Structure):
                    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

                label = ctypes.cast(buffer, ctypes.POINTER(SID_AND_ATTRIBUTES)).contents
                advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
                advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
                count_ptr = advapi32.GetSidSubAuthorityCount(label.Sid)
                if not count_ptr:
                    return "unknown"
                count = int(count_ptr.contents.value)
                if count <= 0:
                    return "unknown"
                rid_ptr = advapi32.GetSidSubAuthority(label.Sid, count - 1)
                if not rid_ptr:
                    return "unknown"
                rid = int(rid_ptr.contents.value)
                if rid >= 0x5000:
                    return "Protected"
                if rid >= 0x4000:
                    return "System"
                if rid >= 0x3000:
                    return "High"
                if rid >= 0x2000:
                    return "Medium"
                if rid >= 0x1000:
                    return "Low"
                return "Untrusted"
            finally:
                if token_handle:
                    kernel32.CloseHandle(token_handle)
                kernel32.CloseHandle(process_handle)
        except Exception:
            return "unknown"

    def _signature_status(self, path: str | None) -> str:
        return str(self._signature_info(path).get("status", "unknown") or "unknown")

    def _signature_info(self, path: str | None) -> dict[str, str]:
        if platform.system() != "Windows" or not path or not os.path.exists(path):
            return {"status": "unknown", "signer": "", "issuer": "", "thumbprint": "", "not_before": "", "not_after": "", "trust_state": "unknown"}
        try:
            # Pass the target path through an environment variable rather
            # than interpolating it into the PowerShell command string.
            # Single-quote escaping (`'` → `''`) is correct in isolation
            # but couples brittle quoting rules to a path that may carry
            # NUL bytes, line breaks, or future shell metachars we don't
            # anticipate. `$env:SHADOWLAB_SIG_TARGET` is read as a literal
            # string regardless of content.
            script = (
                "$p=$env:SHADOWLAB_SIG_TARGET;"
                "$sig=Get-AuthenticodeSignature -LiteralPath $p;"
                "[pscustomobject]@{"
                "Status=$sig.Status;"
                "StatusMessage=$sig.StatusMessage;"
                "Signer=$(if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{''});"
                "Issuer=$(if($sig.SignerCertificate){$sig.SignerCertificate.Issuer}else{''});"
                "Thumbprint=$(if($sig.SignerCertificate){$sig.SignerCertificate.Thumbprint}else{''});"
                "NotBefore=$(if($sig.SignerCertificate){$sig.SignerCertificate.NotBefore.ToString('o')}else{''});"
                "NotAfter=$(if($sig.SignerCertificate){$sig.SignerCertificate.NotAfter.ToString('o')}else{''});"
                "Revocation=$(if($env:SHADOWLAB_CERT_REVOCATION_CHECK -eq 'true' -and $sig.SignerCertificate){"
                "$chain=New-Object System.Security.Cryptography.X509Certificates.X509Chain;"
                "$chain.ChainPolicy.RevocationMode=[System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online;"
                "$chain.ChainPolicy.RevocationFlag=[System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot;"
                "$chain.ChainPolicy.UrlRetrievalTimeout=New-TimeSpan -Seconds 3;"
                "$ok=$chain.Build($sig.SignerCertificate);"
                "if($ok){'ok'}else{($chain.ChainStatus | ForEach-Object {$_.Status}) -join ','}"
                "}else{'offline_skipped'})"
                "} | ConvertTo-Json -Compress"
            )
            cmd = ["powershell", "-NoProfile", "-Command", script]
            child_env = os.environ.copy()
            child_env["SHADOWLAB_SIG_TARGET"] = path
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="ignore", timeout=10, env=child_env)
            parsed = json.loads(output.strip() or "{}")
            status_value = str(parsed.get("Status") or "unknown")
            not_after = str(parsed.get("NotAfter") or "")
            trust_state = "trusted" if status_value.lower() == "valid" else status_value.lower()
            if not_after:
                try:
                    from datetime import datetime, timezone
                    expires = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=timezone.utc)
                    if expires < datetime.now(timezone.utc):
                        trust_state = "expired"
                except Exception:
                    pass
            revocation = str(parsed.get("Revocation") or "offline_skipped")
            if revocation and revocation not in {"ok", "offline_skipped"} and trust_state == "trusted":
                trust_state = "revocation_warning"
            return {
                "status": status_value,
                "status_message": str(parsed.get("StatusMessage") or ""),
                "signer": str(parsed.get("Signer") or ""),
                "issuer": str(parsed.get("Issuer") or ""),
                "thumbprint": str(parsed.get("Thumbprint") or ""),
                "not_before": str(parsed.get("NotBefore") or ""),
                "not_after": not_after,
                "revocation": revocation,
                "trust_state": trust_state,
            }
        except Exception:
            return {"status": "unknown", "signer": "", "issuer": "", "thumbprint": "", "not_before": "", "not_after": "", "trust_state": "unknown"}

    def _safe_children(self, process: psutil.Process) -> list[dict[str, Any]]:
        try:
            children = process.children(recursive=False)
        except Exception:
            return []
        summarized: list[dict[str, Any]] = []
        for child in children:
            try:
                summarized.append({"pid": child.pid, "name": child.name()})
            except Exception:
                continue
        return summarized

    def _safe_module_paths(self, process: psutil.Process) -> list[str]:
        try:
            maps = process.memory_maps(grouped=False)
        except Exception:
            return []
        seen: set[str] = set()
        module_paths: list[str] = []
        for item in maps:
            path = str(getattr(item, "path", "") or "")
            lowered = path.lower()
            if not path:
                continue
            if not lowered.endswith((".dll", ".exe", ".ocx", ".drv")):
                continue
            if lowered in seen:
                continue
            seen.add(lowered)
            module_paths.append(path)
        return module_paths

    def _execution_context(self, *, process_name: str, exe_path: str, cmdline: str, parent_name: str) -> dict[str, Any]:
        lowered_path = str(exe_path or "").lower()
        lowered_parent = str(parent_name or "").lower()
        lowered_name = str(process_name or "").lower()
        lowered_cmd = str(cmdline or "").lower()

        user_writable_path = any(token in lowered_path for token in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\startup\\"))
        browser_parent = lowered_parent in self.browser_parents
        office_parent = lowered_parent in self.office_parents
        proxy_execution = lowered_name in self.proxy_execution_names
        lolbin = lowered_name in self.lolbins
        script_like = any(token in lowered_cmd for token in ("-enc", "frombase64string", "downloadstring", "iex ", "invoke-expression"))
        suspicious_chain_matches = self._match_suspicious_patterns(lowered_parent, lowered_name)
        browser_assisted_execution = browser_parent and any(
            [
                user_writable_path,
                proxy_execution,
                lolbin,
                script_like,
                bool(suspicious_chain_matches),
            ]
        )
        suspicious = (
            user_writable_path
            or office_parent
            or proxy_execution
            or lolbin
            or script_like
            or bool(suspicious_chain_matches)
            or browser_assisted_execution
        )

        reasons: list[str] = []
        if user_writable_path:
            reasons.append("Executable path is user-writable or launch-prone.")
        if browser_assisted_execution:
            reasons.append("Browser-spawned process also matches additional execution-risk signals.")
        if office_parent:
            reasons.append("Parent process is an Office application.")
        if proxy_execution:
            reasons.append("Process name matches a known proxy-execution binary.")
        if lolbin:
            reasons.append("Process matches a known LOLBin.")
        if script_like:
            reasons.append("Command line contains encoded or in-memory execution markers.")
        reasons.extend(suspicious_chain_matches[:3])

        return {
            "suspicious": suspicious,
            "user_writable_path": user_writable_path,
            "browser_parent": browser_parent,
            "office_parent": office_parent,
            "proxy_execution": proxy_execution,
            "lolbin": lolbin,
            "script_like": script_like,
            "suspicious_chain_matches": suspicious_chain_matches,
            "reasons": reasons,
        }

    def _load_sigmaeye_behavior(self) -> dict[str, Any]:
        config_path = Path(__file__).resolve().parent.parent / "config" / "sigmaeye_behavior.yaml"
        if not config_path.exists():
            return {}
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or {}
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}

    def _match_suspicious_patterns(self, parent_name: str, process_name: str) -> list[str]:
        matches: list[str] = []
        for pattern in self.suspicious_patterns:
            if not isinstance(pattern, dict):
                continue
            parent = str(pattern.get("parent", "")).lower()
            child = str(pattern.get("child", "")).lower()
            if parent == parent_name and child == process_name:
                description = str(pattern.get("description", "")).strip()
                if description:
                    matches.append(description)
        return matches
