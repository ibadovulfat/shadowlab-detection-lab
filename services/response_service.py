from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import psutil

import database as db


class ResponseOrchestrator:
    def __init__(self):
        self.protected_names = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}

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
            dest = quarantine_dir / src.name
            shutil.copy2(src, dest)
            self._audit("QUARANTINE", pid, process_name, f"Copied to quarantine: {dest}")
            return {"ok": True, "message": f"Quarantined copy created at {dest}", "path": str(dest)}
        except Exception as exc:
            self._audit("QUARANTINE", pid, process_name, f"Failed: {exc}")
            return {"ok": False, "message": str(exc)}

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
