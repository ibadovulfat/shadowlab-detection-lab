from __future__ import annotations

import hashlib
import hmac
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient


def _signed_headers(api_key: str, method: str, path: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = hashlib.sha256(f"{timestamp}:{path}:{time.time_ns()}".encode("utf-8")).hexdigest()[:24]
    payload = "\n".join([method.upper(), path, timestamp, nonce])
    signature = hmac.new(api_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-API-Key": api_key,
        "X-ShadowLab-Timestamp": timestamp,
        "X-ShadowLab-Nonce": nonce,
        "X-ShadowLab-Signature": signature,
    }


def _role_digest(role: str) -> tuple[str, str]:
    token = f"{role}-secret"
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    import api.main as api_main
    import api.security as security
    from api.security import SecuritySettings, build_capabilities
    from desktop.main import QApplication, QPushButton, ShadowLabDesktop

    class FakeResponse:
        def __init__(self, payload: object) -> None:
            self._payload = payload

        def json(self) -> object:
            return self._payload

    class FakeSettings:
        def value(self, _key: str, default_value: object = "") -> object:
            return default_value

        def setValue(self, *_args, **_kwargs) -> None:
            return

        def sync(self) -> None:
            return

        def remove(self, *_args, **_kwargs) -> None:
            return

    viewer_key, viewer_digest = _role_digest("viewer")
    analyst_key, analyst_digest = _role_digest("analyst")
    admin_key, admin_digest = _role_digest("admin")
    settings = SecuritySettings(
        api_key="",
        api_key_sha256="",
        api_keys={},
        api_keys_sha256={
            "viewer": viewer_digest,
            "analyst": analyst_digest,
            "admin": admin_digest,
        },
        auth_required=True,
        enable_dangerous_actions=True,
        enable_network_warfare=False,
        allow_destructive_file_delete=False,
        allowed_origins=["http://127.0.0.1", "http://localhost"],
        protected_process_names=["lsass.exe", "wininit.exe"],
        policy_profile="lab",
    )

    security._RATE_LIMIT_BUCKETS.clear()
    security._SIGNATURE_NONCES.clear()
    results: list[tuple[str, bool, str]] = []

    with mock.patch.object(api_main, "security_settings", settings), mock.patch.object(security, "security_settings", settings):
        client = TestClient(api_main.app)
        role_matrix = [
            ("viewer", viewer_key),
            ("analyst", analyst_key),
            ("admin", admin_key),
        ]
        for role, token in role_matrix:
            response = client.get("/auth/context", headers={"X-API-Key": token})
            ok = response.status_code == 200 and response.json().get("role") == role
            role_value = response.json().get("role") if response.status_code == 200 else "n/a"
            results.append((f"api_auth_context_{role}", ok, f"{response.status_code} role={role_value}"))

        viewer_response = client.get("/integrations/whids/scheduler/status", headers={"X-API-Key": viewer_key})
        analyst_response = client.get("/integrations/whids/scheduler/status", headers={"X-API-Key": analyst_key})
        admin_response = client.get("/integrations/whids/scheduler/status", headers={"X-API-Key": admin_key})
        results.append(("api_admin_deny_viewer", viewer_response.status_code == 403, f"{viewer_response.status_code}"))
        results.append(("api_admin_deny_analyst", analyst_response.status_code == 403, f"{analyst_response.status_code}"))
        results.append(("api_admin_allow_admin", admin_response.status_code == 200, f"{admin_response.status_code}"))

        missing_sig = client.post("/integrations/response-policy", json={"policy": {}}, headers={"X-API-Key": admin_key})
        results.append(("api_signed_required_admin", missing_sig.status_code == 401, f"{missing_sig.status_code}"))
        signed_headers = _signed_headers(admin_key, "POST", "/integrations/response-policy")
        signed_ok = client.post("/integrations/response-policy", json={"policy": {}}, headers=signed_headers)
        results.append(("api_signed_accept_admin", signed_ok.status_code == 200, f"{signed_ok.status_code}"))

        app = QApplication.instance() or QApplication([])
        with mock.patch.object(ShadowLabDesktop, "check_api_health", lambda self: None):
            with mock.patch("desktop.main.QSettings", return_value=FakeSettings()):
                window = ShadowLabDesktop()
            try:
                roles = [
                    ("viewer", build_capabilities("viewer", settings=settings)),
                    ("analyst", build_capabilities("analyst", settings=settings)),
                    ("admin", build_capabilities("admin", settings=settings)),
                ]
                for role, capabilities in roles:
                    window._apply_auth_context({"role": role, "capabilities": capabilities, "features": {"policy_profile": "lab"}})
                    if role == "admin":
                        with mock.patch.object(window, "_integration_rows", side_effect=lambda name: [{"status": "success", "export_type": "import_file", "target": name, "detail": "ok", "created_at": "now"}]):
                            with mock.patch.object(window, "_incident_rows_for_prefix", side_effect=lambda _prefix: [{"incident_id": "WHIDS-1"}]):
                                with mock.patch.object(window, "_get", side_effect=lambda path, timeout=15: FakeResponse({"running": False, "last_error": ""}) if "scheduler" in path or "live/status" in path else FakeResponse([])):
                                    window.refresh_whids_workspace()
                                    window.refresh_hids_workspace()
                    else:
                        window.refresh_whids_workspace()
                        window.refresh_hids_workspace()
                    whids_locked = "locked" in window.whids_health_badge.text().lower()
                    hids_locked = "locked" in window.hids_health_badge.text().lower()
                    if role == "admin":
                        ok = not whids_locked and not hids_locked
                        detail = f"whids={window.whids_health_badge.text()} hids={window.hids_health_badge.text()}"
                    else:
                        ok = whids_locked and hids_locked
                        detail = f"whids={window.whids_health_badge.text()} hids={window.hids_health_badge.text()}"
                    results.append((f"ui_lock_state_{role}", ok, detail))

                buttons = {button.text(): button for button in window.findChildren(QPushButton)}
                window._apply_auth_context({"role": "viewer", "capabilities": build_capabilities("viewer", settings=settings), "features": {}})
                viewer_ok = not buttons["Pull WHIDS Manager"].isEnabled() and not buttons["Open Enterprise Case"].isEnabled()
                results.append(("ui_buttons_viewer_disabled", viewer_ok, f"pull={buttons['Pull WHIDS Manager'].isEnabled()} case={buttons['Open Enterprise Case'].isEnabled()}"))
                window._apply_auth_context({"role": "analyst", "capabilities": build_capabilities("analyst", settings=settings), "features": {}})
                analyst_ok = not buttons["Pull WHIDS Manager"].isEnabled() and buttons["Open Enterprise Case"].isEnabled()
                results.append(("ui_buttons_analyst_mixed", analyst_ok, f"pull={buttons['Pull WHIDS Manager'].isEnabled()} case={buttons['Open Enterprise Case'].isEnabled()}"))
                window._apply_auth_context({"role": "admin", "capabilities": build_capabilities("admin", settings=settings), "features": {}})
                admin_ok = buttons["Pull WHIDS Manager"].isEnabled() and buttons["Open Enterprise Case"].isEnabled()
                results.append(("ui_buttons_admin_enabled", admin_ok, f"pull={buttons['Pull WHIDS Manager'].isEnabled()} case={buttons['Open Enterprise Case'].isEnabled()}"))
            finally:
                window.close()
                app.quit()

    print("ShadowLab RBAC smoke matrix")
    failures = [item for item in results if not item[1]]
    for name, ok, detail in results:
        state = "PASS" if ok else "FAIL"
        print(f"[{state}] {name}: {detail}")
    print(f"\nSummary: {len(results) - len(failures)} passed / {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
