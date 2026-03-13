from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import requests


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
        destination = (destination or "").strip()
        if not destination:
            return AlertResult(destination="", status="skipped", detail="No alert destination configured.")

        body = self._normalize_payload(payload)
        try:
            if "discord.com/api/webhooks" in destination:
                response = requests.post(
                    destination,
                    json={
                        "username": "ShadowLab",
                        "content": body["text"],
                        "embeds": [{"title": body["title"], "description": body["text"]}],
                    },
                    timeout=self.timeout,
                )
            elif "hooks.slack.com" in destination:
                response = requests.post(
                    destination,
                    json={"text": f"*{body['title']}*\n{body['text']}"},
                    timeout=self.timeout,
                )
            elif "api.telegram.org" in destination:
                response = requests.post(
                    destination,
                    json={"text": f"{body['title']}\n{body['text']}"},
                    timeout=self.timeout,
                )
            else:
                response = requests.post(destination, json=body, timeout=self.timeout)

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
