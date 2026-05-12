from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .base import AntivirusProvider
from .trust import (
    is_trusted_path,
    strict_binary_trust_enabled,
    trusted_binary_roots,
)


class SentinelProvider(AntivirusProvider):
    provider_key = "sentinel_cli"
    display_name = "Sentinel CLI"

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.runtime_root = self.base_dir / "shadowlab_out" / "antivirus" / "sentinel"
        self.database_dir = self.runtime_root / "database"
        self.database_dir.mkdir(parents=True, exist_ok=True)
        self._strict_binary_trust = strict_binary_trust_enabled()
        self._trusted_binary_roots = trusted_binary_roots(self.base_dir)
        self.binary_path = self._discover_binary()
        self.freshclam_path = self._discover_freshclam()

    def _discover_binary(self) -> Path | None:
        env_binary = os.environ.get("SHADOWLAB_SENTINEL_PATH", "").strip() or os.environ.get("SHADOWLAB_CLAMSCAN_PATH", "").strip()
        if env_binary:
            path = Path(env_binary).expanduser()
            if path.exists() and self._trusted_binary(path):
                return path
        for resolved in [shutil.which("clamscan"), shutil.which("clamscan.exe"), shutil.which("clamdscan"), shutil.which("clamdscan.exe")]:
            if resolved:
                path = Path(resolved)
                if self._trusted_binary(path):
                    return path
        common_paths = [
            Path(r"C:\Program Files\ClamAV\clamscan.exe"),
            Path(r"C:\Program Files\ClamAV\clamdscan.exe"),
            Path(r"C:\Program Files (x86)\ClamAV\clamscan.exe"),
            Path(r"C:\Program Files (x86)\ClamAV\clamdscan.exe"),
        ]
        for path in common_paths:
            if path.exists() and self._trusted_binary(path):
                return path
        return None

    def _discover_freshclam(self) -> Path | None:
        env_binary = os.environ.get("SHADOWLAB_SENTINEL_FRESHCLAM", "").strip()
        if env_binary:
            path = Path(env_binary).expanduser()
            if path.exists() and self._trusted_binary(path):
                return path
        for resolved in [shutil.which("freshclam"), shutil.which("freshclam.exe")]:
            if resolved:
                path = Path(resolved)
                if self._trusted_binary(path):
                    return path
        common_paths = [
            Path(r"C:\Program Files\ClamAV\freshclam.exe"),
            Path(r"C:\Program Files (x86)\ClamAV\freshclam.exe"),
        ]
        for path in common_paths:
            if path.exists() and self._trusted_binary(path):
                return path
        return None

    def _database_files(self) -> list[Path]:
        patterns = ("*.cvd", "*.cld", "*.cud", "*.ndb", "*.ldb", "*.hdb")
        files: list[Path] = []
        for pattern in patterns:
            files.extend(self.database_dir.glob(pattern))
        return sorted(set(files))

    def status(self) -> dict[str, Any]:
        database_files = self._database_files()
        latest_definition_update = 0.0
        for path in database_files:
            try:
                latest_definition_update = max(latest_definition_update, float(path.stat().st_mtime))
            except OSError:
                continue
        return {
            "display_name": self.display_name,
            "available": bool(self.binary_path),
            "binary": str(self.binary_path) if self.binary_path else "",
            "freshclam": str(self.freshclam_path) if self.freshclam_path else "",
            "database_dir": str(self.database_dir),
            "database_files": [path.name for path in database_files],
            "definitions_loaded": bool(database_files),
            "latest_signature_update": latest_definition_update,
            "mode": "command-gateway",
            "strict_binary_trust": self._strict_binary_trust,
            "trusted_binary_roots": [str(item) for item in self._trusted_binary_roots],
            "notes": [
                "ShadowLab owns the provider wrapper locally.",
                "Runtime uses an installed command-line scanner through a local gateway adapter.",
            ],
        }

    def _trusted_binary(self, candidate: Path) -> bool:
        if not self._strict_binary_trust:
            return True
        return is_trusted_path(candidate, self._trusted_binary_roots)

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        if not self.binary_path:
            return {"status": "unavailable", "engine": self.display_name, "error": "Sentinel scanner binary not found"}
        command = [
            str(self.binary_path),
            "--stdout",
            "--infected",
            "--no-summary",
            f"--database={self.database_dir}",
            str(path),
        ]
        started = time.time()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=int(policy["scan_timeout_seconds"]),
            )
        except Exception as exc:
            return {"status": "error", "engine": self.display_name, "error": str(exc)}
        duration_ms = int((time.time() - started) * 1000)
        output = (completed.stdout or completed.stderr or "").strip()
        if completed.returncode == 0:
            return {"status": "clean", "engine": self.display_name, "scan_time_ms": duration_ms}
        if completed.returncode == 1:
            malware_name = self._parse_detection(output, path)
            return {
                "status": "infected",
                "engine": self.display_name,
                "malware_name": malware_name,
                "scan_time_ms": duration_ms,
                "raw_output": output[:500],
            }
        return {
            "status": "error",
            "engine": self.display_name,
            "error": output or f"Sentinel scanner exited with code {completed.returncode}",
            "scan_time_ms": duration_ms,
        }

    def _parse_detection(self, output: str, path: Path) -> str:
        for line in output.splitlines():
            if "FOUND" in line:
                normalized = line.replace(str(path), "").strip()
                normalized = normalized.replace(": ", "").replace(" FOUND", "").strip(": ")
                return normalized or f"Detected by {self.display_name}"
        return f"Detected by {self.display_name}"
