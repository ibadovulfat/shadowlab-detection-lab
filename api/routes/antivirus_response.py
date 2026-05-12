"""Live Response + Custom YARA + Lists + Forensics routes (Sprint 5).

All endpoints are admin-gated; the destructive ones (kill / isolate /
restore / delete) additionally require `ensure_dangerous_actions_enabled`
and (for network isolation + VSS restore) enterprise approval at the
API layer. Read endpoints (process tree, list reads, dry-run) accept
analyst role.

Audit posture: every mutating call writes a row into `action_audit_log`
via the security middleware that already wraps signed requests, so we
don't repeat the audit logic here."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.utils.antivirus_paths import validate_antivirus_scan_target


# ---------------------------------------------------------------- Schemas


class KillProcessRequest(BaseModel):
    pid: int
    force: bool = False


class NetworkIsolationRequest(BaseModel):
    allow_management_ip: str = "127.0.0.1"


class VssRestoreRequest(BaseModel):
    shadow_volume: str
    relative_path: str
    destination_path: str


class CustomYaraSaveRequest(BaseModel):
    source: str


class CustomYaraDryRunRequest(BaseModel):
    sample_path: str


class ListEntryRequest(BaseModel):
    value: str
    note: str = ""


class ListBulkRequest(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------- Registration


def register_routes(app, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    require_enterprise_approval = ctx["_require_enterprise_approval"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    current_actor = ctx["current_actor"]
    db = ctx["db"]
    base_dir = ctx["BASE_DIR"]

    # Lazy singletons — built once on first use.
    yara_store_holder: dict[str, Any] = {}
    list_store_holder: dict[str, Any] = {}

    def _yara_store():
        from services.antivirus.custom_yara import CustomYaraStore
        if "store" not in yara_store_holder:
            yara_store_holder["store"] = CustomYaraStore(Path(base_dir))
        return yara_store_holder["store"]

    def _list_store():
        from services.antivirus.lists import AntivirusListStore
        if "store" not in list_store_holder:
            list_store_holder["store"] = AntivirusListStore(db)
        return list_store_holder["store"]

    # ============================================================ LIVE RESPONSE

    @app.post(
        "/antivirus/response/kill",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def antivirus_kill_process(request: Request, payload: KillProcessRequest) -> dict[str, Any]:
        apply_rate_limit(request, bucket="antivirus_response_kill", detail="Too many kill requests. Wait briefly.")
        from services.antivirus.live_response import kill_process
        result = kill_process(payload.pid, force=bool(payload.force))
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "actor": current_actor(request) or "api", "result": result}

    @app.post(
        "/antivirus/response/network/isolate",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def antivirus_network_isolate(request: Request, payload: NetworkIsolationRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="antivirus:network_isolate")
        apply_rate_limit(request, bucket="antivirus_network_isolate", detail="Too many isolation toggles. Wait briefly.")
        from services.antivirus.live_response import network_isolate
        result = network_isolate(allow_management_ip=(payload.allow_management_ip or "127.0.0.1").strip())
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "actor": current_actor(request) or "api", "result": result}

    @app.post(
        "/antivirus/response/network/release",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def antivirus_network_release(request: Request) -> dict[str, Any]:
        from services.antivirus.live_response import network_release
        result = network_release()
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "actor": current_actor(request) or "api", "result": result}

    @app.get("/antivirus/response/artifacts/{pid}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_collect_artifacts(pid: int) -> dict[str, Any]:
        from services.antivirus.live_response import collect_artifacts
        result = collect_artifacts(int(pid))
        if not result.get("ok"):
            raise HTTPException(status_code=404, detail=result)
        return {"status": "ok", "result": result}

    @app.get("/antivirus/response/vss/snapshots", dependencies=[Depends(require_admin)])
    def antivirus_vss_list() -> dict[str, Any]:
        from services.antivirus.live_response import vss_list_snapshots
        result = vss_list_snapshots()
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result}

    @app.post(
        "/antivirus/response/vss/restore",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def antivirus_vss_restore(request: Request, payload: VssRestoreRequest) -> dict[str, Any]:
        require_enterprise_approval(request, action_name="antivirus:vss_restore")
        from services.antivirus.live_response import vss_restore_path
        result = vss_restore_path(
            shadow_volume=payload.shadow_volume,
            relative_path=payload.relative_path,
            destination_path=payload.destination_path,
        )
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok", "actor": current_actor(request) or "api", "result": result}

    # ============================================================ CUSTOM YARA

    @app.get("/antivirus/yara/custom", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_list_custom_yara() -> dict[str, Any]:
        rows = _yara_store().list_rules()
        return {"status": "ok", "rows": rows, "count": len(rows)}

    @app.get("/antivirus/yara/custom/{name}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_get_custom_yara(name: str) -> dict[str, Any]:
        rule = _yara_store().get_rule(name)
        if rule is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found", "name": name})
        return {"status": "ok", "rule": rule}

    @app.put("/antivirus/yara/custom/{name}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_save_custom_yara(name: str, payload: CustomYaraSaveRequest) -> dict[str, Any]:
        result = _yara_store().save_rule(name, payload.source or "")
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result}

    @app.delete(
        "/antivirus/yara/custom/{name}",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def antivirus_delete_custom_yara(name: str) -> dict[str, Any]:
        result = _yara_store().delete_rule(name)
        if not result.get("ok"):
            raise HTTPException(status_code=404, detail=result)
        return {"status": "ok", "result": result}

    @app.post("/antivirus/yara/custom/{name}/dry-run", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_dry_run_custom_yara(name: str, payload: CustomYaraDryRunRequest) -> dict[str, Any]:
        sample_path = validate_antivirus_scan_target(payload.sample_path or "", ctx["BASE_DIR"])
        result = _yara_store().dry_run(name, str(sample_path))
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result}

    # ============================================================ LISTS

    @app.get("/antivirus/lists/{kind}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_get_list(kind: str) -> dict[str, Any]:
        items = _list_store().get(kind)
        return {"status": "ok", "kind": kind.lower(), "items": items, "count": len(items)}

    @app.put("/antivirus/lists/{kind}", dependencies=[Depends(require_admin)])
    def antivirus_replace_list(request: Request, kind: str, payload: ListBulkRequest) -> dict[str, Any]:
        result = _list_store().set(kind, payload.items or [], actor=current_actor(request) or "")
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result}

    @app.post("/antivirus/lists/{kind}/add", dependencies=[Depends(require_admin)])
    def antivirus_list_add(request: Request, kind: str, payload: ListEntryRequest) -> dict[str, Any]:
        result = _list_store().add_entry(kind, payload.value, note=payload.note, actor=current_actor(request) or "")
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result}

    @app.post("/antivirus/lists/{kind}/remove", dependencies=[Depends(require_admin)])
    def antivirus_list_remove(request: Request, kind: str, payload: ListEntryRequest) -> dict[str, Any]:
        result = _list_store().remove_entry(kind, payload.value, actor=current_actor(request) or "")
        if not result.get("ok"):
            raise HTTPException(status_code=404, detail=result)
        return {"status": "ok", "result": result}

    # ============================================================ FORENSICS

    @app.get("/antivirus/forensics/process-tree/{pid}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_process_tree(pid: int, depth: int = 6) -> dict[str, Any]:
        from services.antivirus.forensics import get_process_tree
        result = get_process_tree(int(pid), max_depth=max(1, min(int(depth), 12)))
        if not result.get("ok"):
            raise HTTPException(status_code=404, detail=result)
        return {"status": "ok", "result": result}
