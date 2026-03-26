from __future__ import annotations

import ipaddress
import os
import subprocess
from pathlib import Path
import shutil
import re
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

    def build_triage_response_plan(
        self,
        *,
        profile: dict[str, Any],
        fusion: dict[str, Any],
        local_yara: dict[str, Any] | None = None,
        memory: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        confidence = str(fusion.get("confidence", "low")).lower()
        severity = str(fusion.get("severity", "low")).lower()
        process_name = str(profile.get("name") or "process")
        remote_ips = self.extract_remote_ips(profile)
        actions: list[dict[str, Any]] = []
        manual_required: list[dict[str, Any]] = []
        execution_context = profile.get("execution_context", {}) if isinstance(profile.get("execution_context"), dict) else {}

        if confidence == "high":
            actions.append({"action": "suspend", "mode": "auto", "reason": f"High-confidence fused verdict for {process_name}."})
            if profile.get("exe"):
                actions.append({"action": "quarantine", "mode": "auto", "reason": "Executable path is available for containment copy."})
            for ip in remote_ips[:3]:
                actions.append({"action": "firewall-drop", "mode": "auto", "target": ip, "reason": "Active remote IP observed during high-confidence triage."})
        elif confidence == "medium":
            actions.append({"action": "memory-review", "mode": "auto", "reason": "Medium-confidence verdict requires deeper memory review."})
            manual_required.append({"action": "analyst-review", "mode": "manual", "reason": "Containment should be analyst-approved for medium-confidence findings."})
            if remote_ips:
                manual_required.append({"action": "firewall-drop", "mode": "manual", "targets": remote_ips[:3], "reason": "Remote IP blocking is suggested if analyst confirms malicious traffic."})
        else:
            manual_required.append({"action": "analyst-review", "mode": "manual", "reason": "Low-confidence verdict should remain in triage."})

        inceptor_hits = []
        if isinstance(local_yara, dict):
            inceptor_hits = [rule for rule in local_yara.get("matched_rules", []) if str(rule).startswith("Inceptor_")]
        if inceptor_hits:
            manual_required.append(
                {
                    "action": "inceptor-hunt",
                    "mode": "manual",
                    "reason": f"Inceptor tradecraft markers matched: {', '.join(inceptor_hits[:5])}.",
                }
            )

        memory_fusion = {}
        if isinstance(memory, dict):
            analysis = memory.get("analysis", {}) if isinstance(memory.get("analysis"), dict) else {}
            memory_fusion = analysis.get("fusion", {}) if isinstance(analysis.get("fusion"), dict) else {}
        if execution_context.get("suspicious"):
            manual_required.append(
                {
                    "action": "execution-context-review",
                    "mode": "manual",
                    "reason": "Execution context looks suspicious: " + "; ".join(execution_context.get("reasons", [])[:3]),
                }
            )
        if execution_context.get("suspicious_chain_matches"):
            manual_required.append(
                {
                    "action": "suspicious-chain-review",
                    "mode": "manual",
                    "reason": "Sigma-style suspicious chain matched: " + "; ".join(execution_context.get("suspicious_chain_matches", [])[:3]),
                }
            )
        if profile.get("child_processes"):
            manual_required.append(
                {
                    "action": "lineage-review",
                    "mode": "manual",
                    "reason": f"Process spawned {len(profile.get('child_processes', []) or [])} direct child process(es).",
                }
            )
        if memory_fusion.get("confidence") == "high" and confidence != "high":
            manual_required.append(
                {
                    "action": "priority-memory-review",
                    "mode": "manual",
                    "reason": "Memory analysis produced high-confidence indicators even though fused verdict is not high-confidence.",
                }
            )
        return {
            "confidence": confidence,
            "severity": severity,
            "remote_ips": remote_ips,
            "actions": actions,
            "manual_required": manual_required,
            "memory_confidence": memory_fusion.get("confidence", "low") if memory_fusion else "low",
        }

    def apply_triage_response_plan(
        self,
        *,
        pid: int,
        process_name: str,
        executable_path: str | None,
        plan: dict[str, Any],
    ) -> dict[str, Any]:
        executed: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        for item in plan.get("actions", []):
            action = str(item.get("action", "")).lower()
            try:
                if action == "suspend":
                    result = self.suspend(pid, process_name)
                elif action == "quarantine":
                    result = self.quarantine_file(pid, process_name, executable_path)
                elif action == "firewall-drop":
                    result = self.execute_ossec_active_response("firewall-drop", str(item.get("target", "")))
                else:
                    continue
            except Exception as exc:
                result = {"ok": False, "message": str(exc)}
            if result.get("ok"):
                executed.append({"action": action, "result": result})
            else:
                failed.append({"action": action, "result": result})
        return {"executed": executed, "failed": failed, "manual_required": plan.get("manual_required", [])}

    def extract_remote_ips(self, profile: dict[str, Any]) -> list[str]:
        remote_ips: list[str] = []
        for item in profile.get("network_connections", []) or []:
            candidate = str(item)
            matches = re.findall(r"->([0-9a-fA-F:.]+):\d+", candidate)
            for ip_text in matches:
                try:
                    normalized = str(ipaddress.ip_address(ip_text))
                except ValueError:
                    continue
                if normalized not in remote_ips:
                    remote_ips.append(normalized)
        return remote_ips

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
