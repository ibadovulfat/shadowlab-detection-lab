"""Network warfare (active-response) routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request

from api.schemas import BlockerRequest, NetworkScanRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    ensure_network_warfare_enabled = ctx["ensure_network_warfare_enabled"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    get_warfare_instance = ctx["_get_network_warfare_instance"]
    set_warfare_instance = ctx["_set_network_warfare_instance"]

    @app.post(
        "/network/warfare/scan",
        dependencies=[
            Depends(require_analyst_or_admin),
            Depends(ensure_network_warfare_enabled),
        ],
    )
    def network_warfare_scan(payload: NetworkScanRequest) -> dict[str, Any]:
        import plugins.net_warfare as net_warfare

        instance = get_warfare_instance() or net_warfare.NetworkWarfare()
        set_warfare_instance(instance)
        return {"devices": instance.scan_network(payload.ip_range), "ip_range": payload.ip_range}

    @app.post(
        "/network/warfare/block",
        dependencies=[
            Depends(require_admin),
            Depends(ensure_network_warfare_enabled),
            Depends(ensure_dangerous_actions_enabled),
        ],
    )
    def network_warfare_block(request: Request, payload: BlockerRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="network:warfare:block")
        import plugins.net_warfare as net_warfare

        instance = get_warfare_instance() or net_warfare.NetworkWarfare()
        set_warfare_instance(instance)
        instance.start_blocker(payload.target_ip, payload.gateway_ip)
        return {"status": "started", "target_ip": payload.target_ip, "gateway_ip": payload.gateway_ip}

    @app.delete(
        "/network/warfare/block",
        dependencies=[
            Depends(require_admin),
            Depends(ensure_network_warfare_enabled),
            Depends(ensure_dangerous_actions_enabled),
        ],
    )
    def network_warfare_stop() -> dict[str, str]:
        instance = get_warfare_instance()
        if instance is not None:
            instance.stop_blocker()
        return {"status": "stopped"}
