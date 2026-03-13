from __future__ import annotations

import platform
import socket
import time
from typing import Any

try:
    import psutil
except Exception:
    psutil = None


class FleetService:
    def __init__(self, db_module):
        self.db = db_module

    def register_local_host(self, conn) -> dict[str, Any]:
        snapshot = self._snapshot(role="local")
        self.db.upsert_host(conn, **snapshot)
        return snapshot

    def register_agent(self, conn, payload: dict[str, Any]) -> dict[str, Any]:
        host_record = {
            "host_id": payload.get("host_id") or payload.get("host") or socket.gethostname(),
            "host": payload.get("host") or socket.gethostname(),
            "platform": payload.get("platform") or platform.platform(),
            "role": payload.get("role") or "agent",
            "ip_address": payload.get("ip_address") or self._resolve_ip(),
            "api_status": payload.get("api_status") or "online",
            "agent_version": payload.get("agent_version") or "2.1.0",
            "boot_time": float(payload.get("boot_time") or time.time()),
            "last_seen": time.time(),
        }
        self.db.upsert_host(conn, **host_record)
        return host_record

    def list_hosts(self, conn) -> list[dict[str, Any]]:
        self.register_local_host(conn)
        data = self.db.get_hosts(conn)
        return data.to_dict("records")

    def _snapshot(self, role: str = "local") -> dict[str, Any]:
        return {
            "host_id": socket.gethostname(),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "role": role,
            "ip_address": self._resolve_ip(),
            "api_status": "online",
            "agent_version": "2.1.0",
            "boot_time": self._boot_time(),
            "last_seen": time.time(),
        }

    def _resolve_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _boot_time(self) -> float:
        if psutil is not None:
            try:
                return float(psutil.boot_time())
            except Exception:
                pass
        return time.time()
