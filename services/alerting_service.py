from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import requests
from services.outbound_security import normalize_outbound_url


@dataclass(slots=True)
class AlertResult:
    destination: str
    status: str
    status_code: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertingService:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def dispatch(self, destination: str, payload: dict[str, Any]) -> AlertResult:
        # Re-validate at dispatch and disable redirect-following so a
        # public-looking host cannot 30x-bounce the request into a private
        # range (DNS-rebinding / open-redirect SSRF chain).
        destination = self._normalize_destination(destination)
        if not destination:
            return AlertResult(destination="", status="skipped", detail="No alert destination configured.")

        body = self._normalize_payload(payload)
        post_kwargs = {"timeout": self.timeout, "allow_redirects": False}
        try:
            if "discord.com/api/webhooks" in destination:
                response = requests.post(
                    destination,
                    json={
                        "username": "ShadowLab",
                        "content": body["text"],
                        "embeds": [{"title": body["title"], "description": body["text"]}],
                    },
                    **post_kwargs,
                )
            elif "hooks.slack.com" in destination:
                response = requests.post(
                    destination,
                    json={"text": f"*{body['title']}*\n{body['text']}"},
                    **post_kwargs,
                )
            elif "api.telegram.org" in destination:
                response = requests.post(
                    destination,
                    json={"text": f"{body['title']}\n{body['text']}"},
                    **post_kwargs,
                )
            else:
                response = requests.post(destination, json=body, **post_kwargs)

            if 300 <= response.status_code < 400:
                return AlertResult(
                    destination=destination,
                    status="failed",
                    status_code=response.status_code,
                    detail="Alert destination returned a redirect; refusing to follow for SSRF safety.",
                )
            response.raise_for_status()
            return AlertResult(
                destination=destination,
                status="sent",
                status_code=response.status_code,
                detail="Alert delivered successfully.",
            )
        except Exception as exc:
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            return AlertResult(
                destination=destination,
                status="failed",
                status_code=status_code,
                detail=str(exc),
            )

    def _normalize_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        title = str(payload.get("title") or "ShadowLab Alert")
        lines = [
            f"Severity: {payload.get('severity', 'unknown')}",
            f"Summary: {payload.get('summary', 'No summary provided.')}",
        ]
        incident_id = payload.get("incident_id")
        if incident_id:
            lines.append(f"Incident: {incident_id}")
        findings = payload.get("findings") or []
        if findings:
            lines.append(f"Findings: {len(findings)}")
        return {"title": title, "text": "\n".join(lines)}

    def _normalize_destination(self, destination: str) -> str:
        return normalize_outbound_url(destination)
