"""Webhook destination helpers (validation + routing classification)."""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from services.outbound_security import normalize_outbound_url


def alert_destination_type(webhook_url: str) -> str:
    """Classify a webhook URL by provider to drive payload shaping."""
    if "discord.com/api/webhooks" in webhook_url:
        return "discord"
    if "hooks.slack.com" in webhook_url:
        return "slack"
    if "api.telegram.org" in webhook_url:
        return "telegram"
    return "webhook"


def validate_webhook_url(webhook_url: str) -> str:
    """Return the normalized webhook URL or raise HTTP 400 if unsafe."""
    normalized = normalize_outbound_url(webhook_url)
    if not normalized:
        raise HTTPException(status_code=400, detail="Webhook URL must be a safe http(s) destination")
    return normalized


def send_webhook_alert(alert_service: Any, webhook_url: str, payload: dict[str, Any]) -> None:
    """Thin adapter that dispatches through the configured AlertingService."""
    alert_service.dispatch(webhook_url, payload)
