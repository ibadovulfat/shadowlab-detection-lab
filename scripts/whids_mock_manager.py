from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def load_fixture(repo_root: Path) -> list[dict]:
    fixture_path = repo_root.parent / "whids-master" / "agent" / "test" / "events.json"
    records: list[dict] = []
    if fixture_path.exists():
        for line in fixture_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
    return records


def build_detection_records(records: list[dict], endpoint_uuid: str) -> list[dict]:
    detections: list[dict] = []
    for index, item in enumerate(records[:12]):
        event = item.get("Event", {}) if isinstance(item.get("Event"), dict) else {}
        system = event.get("System", {}) if isinstance(event.get("System"), dict) else {}
        event_data = event.get("EventData", {}) if isinstance(event.get("EventData"), dict) else {}
        detection = {
            "Event": {
                "System": system,
                "EventData": {
                    "SourceImage": str(event_data.get("Image") or event_data.get("SourceImage") or f"C:\\Temp\\fixture-{index}.exe"),
                    "TargetImage": str(event_data.get("ParentImage") or event_data.get("TargetImage") or "C:\\Windows\\System32\\lsass.exe"),
                    "SourceUser": str(event_data.get("User") or event_data.get("SourceUser") or "NT AUTHORITY\\SYSTEM"),
                },
            },
            "EdrData": {
                "Endpoint": {
                    "UUID": endpoint_uuid,
                    "Hostname": str(system.get("Computer") or "WHIDS-LAB"),
                    "IP": "127.0.0.1",
                },
                "Event": {
                    "Hash": f"{index + 1:040x}"[-40:],
                    "ReceiptTime": str((system.get("TimeCreated") or {}).get("SystemTime") or "2026-03-21T12:00:00Z"),
                },
            },
            "Detection": {
                "Signature": [f"MockSignature{index}", "T1003: Credential Access"] if index == 0 else [f"MockSignature{index}"],
                "Criticality": 8 if index == 0 else 5,
                "Actions": ["report", "memdump"] if index == 0 else ["report"],
            },
        }
        detections.append(detection)
    return detections


class Handler(BaseHTTPRequestHandler):
    server_version = "WHIDSMock/1.0"

    def do_GET(self) -> None:
        expected_key = self.server.api_key  # type: ignore[attr-defined]
        if self.headers.get("X-Api-Key", "") != expected_key:
            self._json(401, {"data": None, "message": "NOK", "error": "invalid api key"})
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)
        endpoint_uuid = self.server.endpoint_uuid  # type: ignore[attr-defined]
        base_endpoint = f"/endpoints/{endpoint_uuid}"

        if path == "/endpoints":
            payload = {
                "data": [
                    {
                        "uuid": endpoint_uuid,
                        "hostname": "WHIDS-LAB",
                        "ip": "127.0.0.1",
                        "criticality": 8,
                        "score": 72,
                        "status": "online",
                        "system-info": {
                            "os": {"product": "Windows 10 Pro", "version": "10.0.19045"},
                            "edr": {"version": "mock-1.0"},
                        },
                    }
                ],
                "message": "OK",
                "error": "",
            }
            self._json(200, payload)
            return

        if path == f"{base_endpoint}/detections":
            self._json(200, {"data": self.server.detections, "message": "OK", "error": ""})  # type: ignore[attr-defined]
            return

        if path == f"{base_endpoint}/config":
            config_format = (query.get("format") or ["json"])[0]
            payload = {
                "data": {
                    "format": config_format,
                    "channels": ["Microsoft-Windows-Sysmon/Operational"],
                    "criticality-treshold": 5,
                    "forwarder": {"manager": {"host": "127.0.0.1", "port": self.server.server_port}},  # type: ignore[attr-defined]
                },
                "message": "OK",
                "error": "",
            }
            self._json(200, payload)
            return

        if path == f"{base_endpoint}/report/archive":
            payload = {
                "data": [
                    {"identifier": endpoint_uuid, "score": 72, "alert-count": 3, "created-at": "2026-03-21T12:00:00Z"},
                    {"identifier": endpoint_uuid, "score": 65, "alert-count": 2, "created-at": "2026-03-20T12:00:00Z"},
                ],
                "message": "OK",
                "error": "",
            }
            self._json(200, payload)
            return

        if path == f"{base_endpoint}/report":
            payload = {
                "data": {
                    "identifier": endpoint_uuid,
                    "score": 72,
                    "alert-count": 3,
                    "signatures": ["MockSignature0", "MockSignature1"],
                },
                "message": "OK",
                "error": "",
            }
            self._json(200, payload)
            return

        self._json(404, {"data": None, "message": "NOK", "error": f"unsupported path {path}"})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local WHIDS-compatible mock manager.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1520)
    parser.add_argument("--api-key", default="whids-mock-key")
    parser.add_argument("--endpoint-uuid", default="mock-endpoint-1")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    detections = build_detection_records(load_fixture(repo_root), args.endpoint_uuid)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.api_key = args.api_key  # type: ignore[attr-defined]
    server.endpoint_uuid = args.endpoint_uuid  # type: ignore[attr-defined]
    server.detections = detections  # type: ignore[attr-defined]
    print(f"WHIDS mock manager listening on http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
