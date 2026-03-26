
from __future__ import annotations

import time
from collections import Counter
from pathlib import PureWindowsPath

import psutil

class ProcessTracer:
    def __init__(self, pid):
        self.pid = pid
        self.process = None
        self.running = False
        self.events = []
        self._suspicious_indicators = []

        try:
            self.process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            pass

    def _safe_process_name(self, proc):
        try:
            return proc.name()
        except Exception:
            return ""

    def _safe_process_path(self, proc):
        try:
            return proc.exe()
        except Exception:
            return ""

    def _safe_cmdline(self, proc):
        try:
            cmdline = proc.cmdline()
        except Exception:
            return []
        return [str(item) for item in cmdline if item]

    def _safe_ppid(self, proc):
        try:
            return proc.ppid()
        except Exception:
            return None

    def _safe_status(self, proc):
        try:
            return proc.status()
        except Exception:
            return ""

    def _safe_create_time(self, proc):
        try:
            return proc.create_time()
        except Exception:
            return None

    def _safe_open_files(self):
        try:
            return list(self.process.open_files())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []

    def _safe_connections(self):
        try:
            if hasattr(self.process, "net_connections"):
                return list(self.process.net_connections())
            return list(self.process.connections())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []

    def _safe_children(self):
        try:
            return list(self.process.children(recursive=False))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []

    def _safe_memory_maps(self):
        try:
            return list(self.process.memory_maps(grouped=False))
        except (psutil.AccessDenied, psutil.NoSuchProcess, ValueError):
            return []

    def _path_flags(self, raw_path):
        path = str(raw_path or "").lower()
        flags = []
        if not path:
            return flags
        markers = {
            "temp": ["\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\"],
            "downloads": ["\\downloads\\"],
            "startup": ["\\start menu\\programs\\startup\\", "\\startup\\"],
            "user_profile": ["\\users\\"],
            "programdata": ["\\programdata\\"],
        }
        for label, patterns in markers.items():
            if any(pattern in path for pattern in patterns):
                flags.append(label)
        return flags

    def _cmdline_flags(self, cmdline):
        joined = " ".join(cmdline).lower()
        markers = [
            ("encoded-command", [" -enc ", " -encodedcommand ", " /enc "]),
            ("download-cradle", ["downloadstring(", "downloadfile(", "invoke-webrequest", "curl ", "bitsadmin"]),
            ("script-execution", [".ps1", ".js", ".vbs", "mshta", "rundll32", "regsvr32"]),
        ]
        return [label for label, patterns in markers if any(pattern in joined for pattern in patterns)]

    def _record_suspicious_indicator(self, category, value):
        if not value:
            return
        indicator = f"{category}:{value}"
        if indicator not in self._suspicious_indicators:
            self._suspicious_indicators.append(indicator)

    def _process_snapshot(self):
        exe = self._safe_process_path(self.process)
        cmdline = self._safe_cmdline(self.process)
        path_flags = self._path_flags(exe)
        cmdline_flags = self._cmdline_flags(cmdline)
        for flag in path_flags:
            self._record_suspicious_indicator("process_path", flag)
        for flag in cmdline_flags:
            self._record_suspicious_indicator("command_line", flag)
        return {
            "pid": self.pid,
            "name": self._safe_process_name(self.process),
            "ppid": self._safe_ppid(self.process),
            "exe": exe,
            "cmdline": cmdline,
            "status": self._safe_status(self.process),
            "create_time": self._safe_create_time(self.process),
            "path_flags": path_flags,
            "cmdline_flags": cmdline_flags,
        }

    def _append_event(self, event_type, detail, **extra):
        event = {
            "time": time.strftime("%H:%M:%S"),
            "type": event_type,
            "detail": detail,
        }
        event.update(extra)
        self.events.append(event)

    def _connection_repr(self, conn):
        laddr = getattr(conn, "laddr", "")
        raddr = getattr(conn, "raddr", "")
        status = getattr(conn, "status", "")
        return f"{laddr} -> {raddr} ({status})"

    def _module_event_payload(self, mmap):
        detail = str(getattr(mmap, "path", "") or "")
        perms = str(getattr(mmap, "perms", "") or "")
        flags = self._path_flags(detail)
        if "w" in perms.lower() and "x" in perms.lower():
            flags.append("rwx-perms")
        for flag in flags:
            self._record_suspicious_indicator("module", flag)
        return detail, perms, sorted(set(flags))

    def _build_summary(self):
        counts = Counter(event.get("type", "UNKNOWN") for event in self.events)
        suspicious_events = [event for event in self.events if event.get("flags")]
        return {
            "event_count": len(self.events),
            "event_type_counts": dict(counts),
            "suspicious_event_count": len(suspicious_events),
            "suspicious_indicators": self._suspicious_indicators[:20],
        }

    def trace(self, duration=5, interval=0.5):
        if not self.process:
            return {"error": "Process not found"}

        self.events = []
        self._suspicious_indicators = []
        end_time = time.time() + duration

        seen_files = set()
        seen_conns = set()
        seen_children = set()
        seen_modules = set()
        snapshot = self._process_snapshot()

        if snapshot["path_flags"] or snapshot["cmdline_flags"]:
            self._append_event(
                "EXECUTION_CONTEXT",
                snapshot["exe"] or snapshot["name"] or str(self.pid),
                path_flags=snapshot["path_flags"],
                cmdline_flags=snapshot["cmdline_flags"],
                ppid=snapshot["ppid"],
            )

        while time.time() < end_time:
            try:
                for open_file in self._safe_open_files():
                    path = str(getattr(open_file, "path", "") or "")
                    if path and path not in seen_files:
                        flags = self._path_flags(path)
                        for flag in flags:
                            self._record_suspicious_indicator("file", flag)
                        self._append_event(
                            "FILE_OPEN",
                            path,
                            mode=str(getattr(open_file, "mode", "") or ""),
                            flags=flags,
                        )
                        seen_files.add(path)

                for connection in self._safe_connections():
                    conn_str = self._connection_repr(connection)
                    if conn_str not in seen_conns and str(getattr(connection, "status", "")).upper() == "ESTABLISHED":
                        self._append_event(
                            "NET_CONN",
                            conn_str,
                            mode=getattr(connection, "type", ""),
                        )
                        seen_conns.add(conn_str)

                for child in self._safe_children():
                    child_pid = getattr(child, "pid", None)
                    if child_pid is None or child_pid in seen_children:
                        continue
                    child_name = self._safe_process_name(child)
                    child_path = self._safe_process_path(child)
                    flags = self._path_flags(child_path)
                    for flag in flags:
                        self._record_suspicious_indicator("child", flag)
                    self._append_event(
                        "CHILD_PROCESS",
                        f"{child_name or 'process'} ({child_pid})",
                        path=child_path,
                        flags=flags,
                    )
                    seen_children.add(child_pid)

                for mmap in self._safe_memory_maps():
                    detail, perms, flags = self._module_event_payload(mmap)
                    if not detail or detail in seen_modules:
                        continue
                    self._append_event(
                        "MODULE_LOAD",
                        detail,
                        perms=perms,
                        flags=flags,
                    )
                    seen_modules.add(detail)

                if not self.process.is_running():
                    self._append_event("PROCESS_EXIT", f"Process {self.pid} exited")
                    break

                time.sleep(interval)
            except Exception:
                break

        return {
            "status": "ok",
            "process_snapshot": snapshot,
            "events": self.events,
            "summary": self._build_summary(),
        }
