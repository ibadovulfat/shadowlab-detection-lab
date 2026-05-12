"""Alert webhook test + configure routes."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request

from api.schemas import AlertWebhookRequest


def register_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    require_admin = ctx["require_admin"]
    ensure_dangerous_actions_enabled = ctx["ensure_dangerous_actions_enabled"]
    validate_webhook_url = ctx["_validate_webhook_url"]
    alert_destination_type = ctx["_alert_destination_type"]
    set_alert_webhook_url = ctx["_set_alert_webhook_url"]
    alert_service = ctx["alert_service"]
    secret_store = ctx["secret_store"]
    db = ctx["db"]
    request_workspace_id = ctx["_request_workspace_id"]

    @app.post(
        "/alerts/test",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def test_alert_webhook(request: Request, payload: AlertWebhookRequest) -> dict[str, Any]:
        webhook_url = validate_webhook_url(payload.webhook_url)
        result = alert_service.dispatch(
            webhook_url,
            {"product": "ShadowLab", "title": "ShadowLab test alert", "summary": payload.message, "severity": "info"},
        )
        conn = db.create_connection()
        if conn:
            try:
                db.log_alert(
                    conn,
                    webhook_url,
                    alert_destination_type(webhook_url),
                    "info",
                    "ShadowLab test alert",
                    result.status,
                    result.detail,
                    workspace_id=request_workspace_id(request),
                )
            finally:
                conn.close()
        return result.to_dict()

    @app.post(
        "/alerts/configure",
        dependencies=[Depends(require_admin), Depends(ensure_dangerous_actions_enabled)],
    )
    def configure_alert_webhook(payload: AlertWebhookRequest) -> dict[str, Any]:
        webhook_url = validate_webhook_url(payload.webhook_url)
        set_alert_webhook_url(webhook_url)
        encrypted = secret_store.encrypt_text(webhook_url)
        conn = db.create_connection()
        if conn:
            try:
                db.set_app_setting(conn, "alert_webhook_url_enc", encrypted)
            finally:
                conn.close()
        # Intentionally omit the `encrypted_webhook` ciphertext from the
        # response: any admin read that leaks `enc:v2:...` lets offline
        # decryption attempts run against a weak/leaked master key. The
        # encrypted value is already persisted in DB under alert_webhook_url_enc.
        return {"status": "configured", "webhook_url": webhook_url}
