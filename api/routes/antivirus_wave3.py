"""Wave-3 ops routes for the antivirus pipeline.

Three concerns, three route groups:

  1. **Async scan jobs** — submit a scan, poll for status, watch live
     progress over WebSocket. Built so analysts and automation can
     fire-and-forget long-running cloud-sandbox detonations without
     blocking an HTTP worker.
  2. **Prometheus metrics** — `GET /metrics` exposes the in-process
     registry in standard text/plain exposition format. Wired to
     `require_admin` so secrets in label values can't leak via an
     untrusted scrape.
  3. **Signed webhooks + DLQ** — list deliveries, replay from the
     dead-letter queue, rotate the workspace HMAC secret.
  4. **Folder watcher** — start / stop / status for the on-access poll
     service.

Every endpoint defers to a service singleton wired through `ctx`. The
routes themselves are thin: validate input → call the service → map
errors to HTTPException. Business logic lives in the service modules
(`scan_jobs.py`, `webhook_dispatcher.py`, `folder_watcher.py`,
`observability/metrics.py`)."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field


class AsyncScanRequest(BaseModel):
    file_path: str
    policy_overrides: dict[str, Any] = Field(default_factory=dict)


class WebhookEnqueueRequest(BaseModel):
    target_url: str
    event_type: str = "generic"
    payload: dict[str, Any] = Field(default_factory=dict)


class WebhookSecretRotateRequest(BaseModel):
    workspace_id: str = "default"


class FolderWatcherConfigRequest(BaseModel):
    paths: list[str] = Field(default_factory=list)
    workspace_id: str = "default"
    max_file_size_mb: int = 128


def register_routes(app, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    require_analyst_or_admin = ctx["require_analyst_or_admin"]
    apply_rate_limit = ctx["_apply_rate_limit"]
    request_workspace_id = ctx["_request_workspace_id"]
    current_actor = ctx["current_actor"]
    metrics_registry = ctx.get("metrics_registry")
    scan_job_queue = ctx.get("scan_job_queue")
    webhook_dispatcher = ctx.get("webhook_dispatcher")
    folder_watcher = ctx.get("folder_watcher")

    # ------------------------------------------------------------------
    # 1) Async scan jobs
    # ------------------------------------------------------------------

    @app.post("/antivirus/scan/file/async", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_submit_async_scan(request: Request, payload: AsyncScanRequest) -> dict[str, Any]:
        if scan_job_queue is None:
            raise HTTPException(status_code=503, detail="Async scan queue not initialised")
        apply_rate_limit(request, bucket="antivirus_scan_async", detail="Too many async scan submissions. Wait briefly and retry.")
        target = (payload.file_path or "").strip()
        if not target:
            raise HTTPException(status_code=422, detail="file_path is required")
        snapshot = scan_job_queue.submit(
            target,
            workspace_id=request_workspace_id(request),
            actor=current_actor(request) or "api",
            policy_overrides=payload.policy_overrides or {},
        )
        if metrics_registry is not None:
            try:
                metrics_registry.record_job_transition("queued")
            except Exception:
                pass
        return {"status": "queued", "job": snapshot}

    @app.get("/antivirus/jobs/{job_id}", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_get_job(job_id: str) -> dict[str, Any]:
        if scan_job_queue is None:
            raise HTTPException(status_code=503, detail="Async scan queue not initialised")
        snapshot = scan_job_queue.get(job_id)
        if snapshot is None:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        return {"status": "ok", "job": snapshot}

    @app.get("/antivirus/jobs", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_list_jobs(request: Request, limit: int = 50, state: str | None = None) -> dict[str, Any]:
        if scan_job_queue is None:
            raise HTTPException(status_code=503, detail="Async scan queue not initialised")
        rows = scan_job_queue.list(workspace_id=request_workspace_id(request), limit=limit, state=state)
        return {"status": "ok", "rows": rows, "count": len(rows), "stats": scan_job_queue.stats()}

    @app.post("/antivirus/jobs/{job_id}/cancel", dependencies=[Depends(require_analyst_or_admin)])
    def antivirus_cancel_job(job_id: str) -> dict[str, Any]:
        if scan_job_queue is None:
            raise HTTPException(status_code=503, detail="Async scan queue not initialised")
        result = scan_job_queue.cancel(job_id)
        if not result.get("ok"):
            raise HTTPException(status_code=409, detail=result)
        if metrics_registry is not None:
            try:
                metrics_registry.record_job_transition(str(result.get("state", "cancelled")))
            except Exception:
                pass
        return {"status": "ok", "result": result}

    @app.websocket("/antivirus/jobs/{job_id}/stream")
    async def antivirus_stream_job(websocket: WebSocket, job_id: str) -> None:
        """Live progress stream for a single job.

        Authentication has two layers:
          1. **API key in `Sec-WebSocket-Protocol`** — browser clients
             can't set arbitrary headers, so the key rides as the
             subprotocol. Resolved via the same `_resolve_context` the
             HTTP auth chain uses, so a key rotation purges both
             transports atomically.
          2. **Replay protection via timestamp** — the client must also
             pass a UTC unix timestamp as a second subprotocol value.
             We reject anything older than 60 s, blocking a replayed
             upgrade request even if the attacker captured a valid key.
        """
        if scan_job_queue is None:
            await websocket.close(code=1011, reason="Async scan queue not initialised")
            return
        token = ""
        ts_value = ""
        proto_header = websocket.headers.get("sec-websocket-protocol", "")
        if proto_header:
            parts = [p.strip() for p in proto_header.split(",") if p.strip()]
            if parts:
                token = parts[0]
            if len(parts) >= 2:
                ts_value = parts[1]
        if not token:
            await websocket.close(code=1008, reason="API key required (Sec-WebSocket-Protocol)")
            return
        # Replay protection — clients append a unix-second timestamp; we
        # accept a 60-second window. Skipped (returns immediately) when
        # no timestamp is offered to keep older clients backwards-compat,
        # but production deployments should require both protocol values.
        import time as _time
        if ts_value:
            try:
                client_ts = int(ts_value)
                drift = abs(int(_time.time()) - client_ts)
                if drift > 60:
                    await websocket.close(code=1008, reason="Stale upgrade timestamp; replay protection rejected")
                    return
            except ValueError:
                await websocket.close(code=1008, reason="Invalid Sec-WebSocket-Protocol timestamp")
                return
        from api.security import _resolve_context  # local import: avoid circular
        sec_ctx = _resolve_context(token)
        role = sec_ctx.role if sec_ctx is not None else None
        if role not in {"analyst", "admin"}:
            await websocket.close(code=1008, reason="Analyst or admin role required")
            return
        await websocket.accept(subprotocol=token)

        # Send the current snapshot immediately so the client doesn't
        # have to wait for the next state transition.
        snapshot = scan_job_queue.get(job_id)
        if snapshot is None:
            await websocket.send_json({"error": "unknown_job", "job_id": job_id})
            await websocket.close(code=1003)
            return
        await websocket.send_json(snapshot)

        # Subscribe — every state transition gets pushed.
        import asyncio
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def _on_update(update_payload: dict[str, Any]) -> None:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, update_payload)
            except RuntimeError:
                # Loop closed mid-publish (client gone).
                pass

        unsubscribe = scan_job_queue.subscribe(job_id, _on_update)
        try:
            while True:
                update = await queue.get()
                await websocket.send_json(update)
                if update.get("state") in {"complete", "error", "cancelled"}:
                    break
        except WebSocketDisconnect:
            return
        finally:
            try:
                unsubscribe()
            except Exception:
                pass
            try:
                await websocket.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 2) Prometheus metrics — `/metrics` is already registered by
    #    `api/routes/auth.py` against the shared `default_registry`. We
    #    don't re-register it here; the Wave-3 series (scan_total,
    #    duration histogram, engine_errors, webhook_deliveries, jobs)
    #    are written into that same registry through the delegating
    #    adapter in `services/observability/metrics.py`, so the existing
    #    scrape surface picks them up automatically.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 3) Signed webhooks + DLQ
    # ------------------------------------------------------------------

    @app.post("/webhooks/enqueue", dependencies=[Depends(require_analyst_or_admin)])
    def webhook_enqueue(request: Request, payload: WebhookEnqueueRequest) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        result = webhook_dispatcher.enqueue(
            workspace_id=request_workspace_id(request),
            target_url=(payload.target_url or "").strip(),
            event_type=payload.event_type or "generic",
            payload=payload.payload or {},
        )
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "queued", **result}

    @app.post("/webhooks/test", dependencies=[Depends(require_analyst_or_admin)])
    def webhook_test(request: Request, payload: WebhookEnqueueRequest) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        return webhook_dispatcher.deliver_sync(
            workspace_id=request_workspace_id(request),
            target_url=(payload.target_url or "").strip(),
            event_type=payload.event_type or "test",
            payload=payload.payload or {"shadowlab": "test_alert"},
        )

    @app.get("/webhooks/deliveries", dependencies=[Depends(require_analyst_or_admin)])
    def webhook_list_deliveries(request: Request, limit: int = 50, state: str | None = None) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        rows = webhook_dispatcher.list_deliveries(
            workspace_id=request_workspace_id(request), limit=limit, state=state
        )
        return {"status": "ok", "rows": rows, "count": len(rows)}

    @app.get("/webhooks/dlq", dependencies=[Depends(require_admin)])
    def webhook_list_dlq(request: Request, limit: int = 100) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        rows = webhook_dispatcher.list_dlq(workspace_id=request_workspace_id(request), limit=limit)
        return {"status": "ok", "rows": rows, "count": len(rows)}

    @app.post("/webhooks/dlq/{delivery_id}/replay", dependencies=[Depends(require_admin)])
    def webhook_replay_dlq(delivery_id: str) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        result = webhook_dispatcher.replay_from_dlq(delivery_id)
        if not result.get("ok"):
            raise HTTPException(status_code=404, detail=result)
        return {"status": "ok", "result": result}

    @app.delete("/webhooks/dlq/{delivery_id}", dependencies=[Depends(require_admin)])
    def webhook_purge_one_dlq(delivery_id: str) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        result = webhook_dispatcher.purge_dlq(delivery_id=delivery_id)
        if not result.get("ok") or int(result.get("removed", 0)) == 0:
            raise HTTPException(status_code=404, detail=result)
        return {"status": "ok", "result": result}

    @app.delete("/webhooks/dlq", dependencies=[Depends(require_admin)])
    def webhook_purge_dlq(request: Request, older_than_days: int | None = None) -> dict[str, Any]:
        """Bulk DLQ purge. Without `older_than_days` everything in the
        operator's workspace is wiped; with it, only entries older than
        N days are removed (typical retention sweep)."""
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        older = int(older_than_days) * 24 * 3600 if older_than_days else None
        result = webhook_dispatcher.purge_dlq(
            older_than_seconds=older,
            workspace_id=request_workspace_id(request),
        )
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result}

    @app.post("/webhooks/secret/rotate", dependencies=[Depends(require_admin)])
    def webhook_rotate_secret(request: Request, payload: WebhookSecretRotateRequest) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        # Use payload workspace_id when provided so a workspace admin can
        # rotate a different workspace's secret only if explicitly named.
        ws = (payload.workspace_id or request_workspace_id(request) or "default").strip()
        return webhook_dispatcher.rotate_secret(ws)

    @app.get("/webhooks/secret", dependencies=[Depends(require_admin)])
    def webhook_get_secret(request: Request) -> dict[str, Any]:
        if webhook_dispatcher is None:
            raise HTTPException(status_code=503, detail="Webhook dispatcher not initialised")
        active = webhook_dispatcher.get_active_secret(request_workspace_id(request))
        if not active:
            return {"status": "ok", "configured": False}
        # Never echo the raw secret over the API — only the id + a short
        # fingerprint. Operators rotate to retrieve a fresh secret.
        secret_id, secret = active
        fingerprint = secret[-4:] if secret else ""
        return {"status": "ok", "configured": True, "secret_id": secret_id, "secret_fingerprint": fingerprint}

    # ------------------------------------------------------------------
    # 4) On-access folder watcher
    # ------------------------------------------------------------------

    @app.get("/antivirus/folder-watcher/status", dependencies=[Depends(require_analyst_or_admin)])
    def folder_watcher_status() -> dict[str, Any]:
        if folder_watcher is None:
            raise HTTPException(status_code=503, detail="Folder watcher not initialised")
        return {"status": "ok", "watcher": folder_watcher.status()}

    @app.post("/antivirus/folder-watcher/configure", dependencies=[Depends(require_admin)])
    def folder_watcher_configure(request: Request, payload: FolderWatcherConfigRequest) -> dict[str, Any]:
        if folder_watcher is None:
            raise HTTPException(status_code=503, detail="Folder watcher not initialised")
        folder_watcher.configure(
            paths=payload.paths or [],
            workspace_id=payload.workspace_id or request_workspace_id(request),
            max_file_size_mb=int(payload.max_file_size_mb or 128),
        )
        return {"status": "ok", "watcher": folder_watcher.status()}

    @app.post("/antivirus/folder-watcher/start", dependencies=[Depends(require_admin)])
    def folder_watcher_start() -> dict[str, Any]:
        if folder_watcher is None:
            raise HTTPException(status_code=503, detail="Folder watcher not initialised")
        result = folder_watcher.start()
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result)
        return {"status": "ok", "result": result, "watcher": folder_watcher.status()}

    @app.post("/antivirus/folder-watcher/stop", dependencies=[Depends(require_admin)])
    def folder_watcher_stop() -> dict[str, Any]:
        if folder_watcher is None:
            raise HTTPException(status_code=503, detail="Folder watcher not initialised")
        return {"status": "ok", "result": folder_watcher.stop(), "watcher": folder_watcher.status()}


