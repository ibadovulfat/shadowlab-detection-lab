from __future__ import annotations

import ipaddress
import os
import subprocess
from pathlib import Path
import shutil
from typing import Any

import psutil

import database as db


class ResponseOrchestrator:
    def __init__(self):
        self.protected_names = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}
        configured_home = os.environ.get("SHADOWLAB_OSSEC_HOME", "").strip()
        candidates = [
            Path(configured_home) if configured_home else None,
            Path.home() / "Documents" / "ossec-hids-main",
            Path("C:/Users/ulfat/Documents/ossec-hids-main"),
            Path(__file__).resolve().parent.parent.parent / "ossec-hids-main",
        ]
        self.ossec_home = next((candidate for candidate in candidates if candidate and candidate.exists()), Path.home() / "Documents" / "ossec-hids-main")

    def suspend(self, pid: int, process_name: str) -> dict[str, Any]:
        return self._execute("SUSPEND", pid, process_name, lambda proc: proc.suspend())

    def resume(self, pid: int, process_name: str) -> dict[str, Any]:
        return self._execute("RESUME", pid, process_name, lambda proc: proc.resume())

    def kill(self, pid: int, process_name: str) -> dict[str, Any]:
        return self._execute("KILL", pid, process_name, lambda proc: proc.kill())

    def kill_tree(self, pid: int, process_name: str) -> dict[str, Any]:
        if process_name.lower() in self.protected_names:
            return {"ok": False, "message": f"Protected process blocked: {process_name}"}
        try:
            proc = psutil.Process(pid)
            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except Exception:
                    continue
            proc.kill()
            self._audit("KILL_TREE", pid, process_name, f"Killed process and {len(children)} children")
            return {"ok": True, "message": f"KILL_TREE succeeded for PID {pid}", "children_killed": len(children)}
        except Exception as exc:
            self._audit("KILL_TREE", pid, process_name, f"Failed: {exc}")
            return {"ok": False, "message": str(exc)}

    def quarantine_file(self, pid: int, process_name: str, path: str | None) -> dict[str, Any]:
        if not path or not Path(path).exists():
            return {"ok": False, "message": "Executable path unavailable for quarantine"}
        try:
            quarantine_dir = Path("shadowlab_quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            src = Path(path)
            dest = quarantine_dir / self._unique_quarantine_name(src.name)
            shutil.copy2(src, dest)
            self._audit("QUARANTINE", pid, process_name, f"Copied to quarantine: {dest}")
            return {"ok": True, "message": f"Quarantined copy created at {dest}", "path": str(dest)}
        except Exception as exc:
            self._audit("QUARANTINE", pid, process_name, f"Failed: {exc}")
            return {"ok": False, "message": str(exc)}

    def execute_ossec_active_response(self, action: str, subject: str, *, mode: str = "add", user: str = "-") -> dict[str, Any]:
        normalized_action = action.strip().lower()
        normalized_subject = self._validated_ossec_subject(subject)
        normalized_mode = self._validated_ossec_mode(mode)
        normalized_user = self._validated_ossec_user(user)
        script = self._ossec_script_for_action(normalized_action)
        if script is None:
            return {"ok": False, "message": f"OSSEC active-response script unavailable for {normalized_action}"}
        command = self._ossec_command(script, mode=normalized_mode, user=normalized_user, subject=normalized_subject)
        env = os.environ.copy()
        env.setdefault("OSSECPATH", str(self.ossec_home) + os.sep)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
                env=env,
            )
        except Exception as exc:
            self._audit(f"OSSEC_{normalized_action.upper()}", -1, normalized_subject, f"Failed: {exc}")
            return {"ok": False, "message": str(exc), "command": command}
        ok = completed.returncode == 0
        detail = (completed.stdout or completed.stderr or "").strip()
        self._audit(f"OSSEC_{normalized_action.upper()}", -1, normalized_subject, detail or f"exit={completed.returncode}")
        return {
            "ok": ok,
            "message": detail or f"OSSEC {normalized_action} exit code {completed.returncode}",
            "command": command,
            "returncode": completed.returncode,
        }

    def _execute(self, action: str, pid: int, process_name: str, operation) -> dict[str, Any]:
        if process_name.lower() in self.protected_names:
            return {"ok": False, "message": f"Protected process blocked: {process_name}"}
        try:
            proc = psutil.Process(pid)
            operation(proc)
            self._audit(action, pid, process_name, "User initiated action")
            return {"ok": True, "message": f"{action} succeeded for PID {pid}"}
        except Exception as exc:
            self._audit(action, pid, process_name, f"Failed: {exc}")
            return {"ok": False, "message": str(exc)}

    def _audit(self, action: str, pid: int, process_name: str, details: str) -> None:
        conn = db.create_connection()
        if not conn:
            return
        try:
            db.log_response_action(conn, action, pid, process_name, details)
        finally:
            conn.close()

    def _ossec_script_for_action(self, action: str) -> Path | None:
        normalized = action.strip().lower()
        if normalized == "firewall-drop":
            return self.ossec_home / "active-response" / "win" / "firewall-drop.cmd"
        if normalized == "route-null":
            return self.ossec_home / "active-response" / "win" / "route-null.cmd"
        if normalized == "host-deny":
            unix_script = self.ossec_home / "active-response" / "host-deny.sh"
            return unix_script if unix_script.exists() else None
        return None

    def _ossec_command(self, script: Path, *, mode: str, user: str, subject: str) -> list[str] | str:
        if script.suffix.lower() == ".cmd":
            return ["cmd.exe", "/c", str(script), mode, user, subject]
        return ["sh", str(script), mode, user, subject]

    def _validated_ossec_subject(self, subject: str) -> str:
        candidate = str(subject or "").strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ValueError(f"OSSEC active-response subject must be a valid IP address: {candidate}") from exc

    def _validated_ossec_mode(self, mode: str) -> str:
        candidate = str(mode or "").strip().lower()
        if candidate not in {"add", "delete"}:
            raise ValueError(f"Unsupported OSSEC active-response mode: {mode}")
        return candidate

    def _validated_ossec_user(self, user: str) -> str:
        candidate = str(user or "-").strip()
        if not candidate or any(ch.isspace() for ch in candidate):
            raise ValueError("OSSEC active-response user must be a single token")
        return candidate

    def _unique_quarantine_name(self, filename: str) -> str:
        candidate = Path(filename).name or "artifact.bin"
        stem = Path(candidate).stem or "artifact"
        suffix = Path(candidate).suffix
        quarantine_dir = Path("shadowlab_quarantine")
        target = quarantine_dir / candidate
        if not target.exists():
            return candidate
        counter = 1
        while True:
            sibling = quarantine_dir / f"{stem}_{counter}{suffix}"
            if not sibling.exists():
                return sibling.name
            counter += 1
