from __future__ import annotations

import hashlib
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
                if parent is not None:
                    parent_pid = self._safe_call(parent.pid)
                    parent_name = self._safe_call(parent.name, "")
                children_summary = self._safe_children(process)
                open_files = self._safe_call(process.open_files, [])
                module_paths = self._safe_module_paths(process)
                execution_context = self._execution_context(
                    process_name=self._safe_call(process.name, "") or "",
                    exe_path=exe_path or "",
                    cmdline=cmdline,
                    parent_name=parent_name or "",
                )
                return {
                    "pid": pid,
                    "ppid": parent_pid,
                    "name": self._safe_call(process.name, ""),
                    "parent_name": parent_name,
                    "cmdline": cmdline,
                    "exe": exe_path,
                    "cwd": self._safe_call(process.cwd, "") if hasattr(process, "cwd") else "",
                    "username": self._safe_call(process.username, ""),
                    "status": self._safe_call(process.status, ""),
                    "create_time": self._safe_call(process.create_time, 0.0),
                    "sha256": self._safe_sha256(exe_path),
                    "signature_status": self._signature_status(exe_path),
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

    def _signature_status(self, path: str | None) -> str:
        if platform.system() != "Windows" or not path or not os.path.exists(path):
            return "unknown"
        try:
            escaped_path = path.replace("'", "''")
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-AuthenticodeSignature -FilePath '{escaped_path}').Status",
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="ignore", timeout=10)
            return output.strip() or "unknown"
        except Exception:
            return "unknown"

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
