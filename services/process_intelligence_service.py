from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from collections import deque
from typing import Any

import psutil


class ProcessIntelligenceService:
    def __init__(self, max_history: int = 500):
        self.max_history = max_history
        self.snapshot_history: deque[list[dict[str, Any]]] = deque(maxlen=max_history)

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
                connections = []
                try:
                    connections = [
                        f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port}" if c.raddr else f"{c.laddr.ip}:{c.laddr.port}"
                        for c in process.net_connections(kind="inet")
                    ]
                except Exception:
                    connections = []
                return {
                    "pid": pid,
                    "name": self._safe_call(process.name, ""),
                    "cmdline": " ".join(self._safe_call(process.cmdline, [])),
                    "exe": exe_path,
                    "cwd": self._safe_call(process.cwd, "") if hasattr(process, "cwd") else "",
                    "username": self._safe_call(process.username, ""),
                    "status": self._safe_call(process.status, ""),
                    "create_time": self._safe_call(process.create_time, 0.0),
                    "sha256": self._safe_sha256(exe_path),
                    "signature_status": self._signature_status(exe_path),
                    "network_connections": connections[:25],
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
