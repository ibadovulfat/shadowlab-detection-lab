"""Network connections + sniffer routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from api.schemas import SnifferRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    monitor_core = ctx["monitor_core"]

    @app.get("/network/connections", dependencies=[Depends(require_analyst_or_admin)])
    def network_connections() -> list[dict[str, Any]]:
        return monitor_core.get_network_connections()

    @app.post("/network/sniff", dependencies=[Depends(require_analyst_or_admin)])
    def network_sniff(payload: SnifferRequest) -> dict[str, Any]:
        import plugins.sniffer as net_sniffer

        if not net_sniffer.SCAPY_AVAILABLE:
            raise HTTPException(status_code=500, detail="Scapy not available for packet capture")
        result = net_sniffer.run_sniffer_session(duration=payload.duration)
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        return result
