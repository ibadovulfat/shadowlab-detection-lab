from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from typing import Any

import requests


def signed_headers(api_key: str, method: str, path: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(12)
    payload = "\n".join([method.upper(), path, timestamp, nonce])
    signature = hmac.new(api_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-API-Key": api_key,
        "X-ShadowLab-Timestamp": timestamp,
        "X-ShadowLab-Nonce": nonce,
        "X-ShadowLab-Signature": signature,
    }


def check_response(response: requests.Response, label: str) -> tuple[bool, str]:
    if response.ok:
        return True, f"{label}: {response.status_code}"
    detail = response.text.strip()
    return False, f"{label}: {response.status_code} {detail[:300]}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test ShadowLab live integration endpoints.")
    parser.add_argument("--base-url", default=os.environ.get("SHADOWLAB_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.environ.get("SHADOWLAB_ADMIN_API_KEY", ""))
    parser.add_argument("--manager-url", default=os.environ.get("SHADOWLAB_WHIDS_MANAGER_URL", ""))
    parser.add_argument("--manager-api-key", default=os.environ.get("SHADOWLAB_WHIDS_API_KEY", ""))
    parser.add_argument("--endpoint-uuid", default=os.environ.get("SHADOWLAB_WHIDS_ENDPOINT_UUID", ""))
    parser.add_argument("--since", default=os.environ.get("SHADOWLAB_WHIDS_REPORT_SINCE", ""))
    parser.add_argument("--insecure-whids", action="store_true")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    session = requests.Session()
    checks: list[tuple[str, bool, str]] = []

    try:
        response = session.get(f"{base_url}/health", timeout=15)
        checks.append(("health", *check_response(response, "health")))
    except Exception as exc:
        checks.append(("health", False, f"health: {exc}"))

    if not args.api_key:
        checks.append(("admin_api_key", False, "Provide --api-key or SHADOWLAB_ADMIN_API_KEY for auth-enabled smoke testing"))
    else:
        session.headers.update({"X-API-Key": args.api_key})
        endpoints = [
            ("auth_context", "GET", "/auth/context", None),
            ("ossec_live_status", "GET", "/integrations/ossec/live/status", None),
            ("whids_scheduler_status", "GET", "/integrations/whids/scheduler/status", None),
            ("response_policy_get", "GET", "/integrations/response-policy", None),
        ]
        fetched_policy: dict[str, Any] = {}
        for name, method, path, payload in endpoints:
            try:
                response = session.request(method, f"{base_url}{path}", timeout=20, json=payload)
                ok, detail = check_response(response, name)
                checks.append((name, ok, detail))
                if ok and name == "response_policy_get":
                    body = response.json()
                    if isinstance(body, dict):
                        fetched_policy = body
            except Exception as exc:
                checks.append((name, False, f"{name}: {exc}"))

        if fetched_policy:
            path = "/integrations/response-policy"
            payload = {"policy": fetched_policy}
            headers = signed_headers(args.api_key, "POST", path)
            try:
                response = session.post(f"{base_url}{path}", json=payload, headers=headers, timeout=20)
                checks.append(("response_policy_post", *check_response(response, "response_policy_post")))
            except Exception as exc:
                checks.append(("response_policy_post", False, f"response_policy_post: {exc}"))
        else:
            checks.append(("response_policy_post", False, "Skipped because GET /integrations/response-policy did not succeed"))

    if args.manager_url and args.manager_api_key and args.endpoint_uuid and args.api_key:
        verify_tls = not args.insecure_whids
        whids_calls = [
            (
                "whids_config",
                "/integrations/whids/config",
                {
                    "manager_url": args.manager_url,
                    "api_key": args.manager_api_key,
                    "endpoint_uuid": args.endpoint_uuid,
                    "config_format": "json",
                    "verify_tls": verify_tls,
                },
            ),
            (
                "whids_report_archive",
                "/integrations/whids/report-archive",
                {
                    "manager_url": args.manager_url,
                    "api_key": args.manager_api_key,
                    "endpoint_uuid": args.endpoint_uuid,
                    "since": args.since,
                    "verify_tls": verify_tls,
                },
            ),
        ]
        for name, path, payload in whids_calls:
            headers = signed_headers(args.api_key, "POST", path)
            try:
                response = session.post(f"{base_url}{path}", json=payload, headers=headers, timeout=45)
                checks.append((name, *check_response(response, name)))
            except Exception as exc:
                checks.append((name, False, f"{name}: {exc}"))
    else:
        checks.append(
            (
                "whids_live_validation",
                False,
                "Skipped live WHIDS validation because manager_url, manager_api_key, endpoint_uuid, or admin api key is missing",
            )
        )

    print("ShadowLab live integration smoke test")
    for _, ok, detail in checks:
        state = "PASS" if ok else "FAIL"
        print(f"[{state}] {detail}")
    failures = [item for item in checks if not item[1]]
    print(f"\nSummary: {len(checks) - len(failures)} passed / {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
