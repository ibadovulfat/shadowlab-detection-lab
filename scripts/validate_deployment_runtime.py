from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse
from pathlib import Path


TRUE_VALUES = {"1", "true", "yes", "on"}


def as_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    out_dir = repo_root / "shadowlab_out"
    runtime_path = out_dir / "integration_runtime.json"
    policy_path = out_dir / "integration_response_policy.json"
    ossec_home = Path(os.environ.get("SHADOWLAB_OSSEC_HOME", str(Path.home() / "Documents" / "ossec-hids-main")))
    whids_manager_url = os.environ.get("SHADOWLAB_WHIDS_MANAGER_URL", "").strip()
    whids_endpoint_uuid = os.environ.get("SHADOWLAB_WHIDS_ENDPOINT_UUID", "").strip()
    whids_api_key = os.environ.get("SHADOWLAB_WHIDS_API_KEY", "").strip()

    checks: list[tuple[str, bool, str]] = []
    checks.append(("policy_file", policy_path.exists(), str(policy_path)))
    checks.append(("runtime_file", runtime_path.exists(), str(runtime_path)))
    checks.append(("restore_runtime_enabled", as_bool("SHADOWLAB_RESTORE_INTEGRATION_RUNTIME", True), os.environ.get("SHADOWLAB_RESTORE_INTEGRATION_RUNTIME", "true")))
    checks.append(("auth_required_set", "SHADOWLAB_REQUIRE_AUTH" in os.environ, os.environ.get("SHADOWLAB_REQUIRE_AUTH", "")))
    checks.append(("policy_profile_set", bool(os.environ.get("SHADOWLAB_POLICY_PROFILE", "").strip()), os.environ.get("SHADOWLAB_POLICY_PROFILE", "")))
    checks.append(("api_keys_present", bool(os.environ.get("SHADOWLAB_API_KEYS_SHA256", "").strip() or os.environ.get("SHADOWLAB_API_KEYS", "").strip()), "configured" if (os.environ.get("SHADOWLAB_API_KEYS_SHA256") or os.environ.get("SHADOWLAB_API_KEYS")) else "missing"))
    checks.append(("ossec_home_exists", ossec_home.exists(), str(ossec_home)))
    checks.append(("ossec_firewall_drop_exists", (ossec_home / "active-response" / "win" / "firewall-drop.cmd").exists(), str(ossec_home / "active-response" / "win" / "firewall-drop.cmd")))
    checks.append(("ossec_route_null_exists", (ossec_home / "active-response" / "win" / "route-null.cmd").exists(), str(ossec_home / "active-response" / "win" / "route-null.cmd")))
    checks.append(("ossec_validation_script_exists", (repo_root / "scripts" / "validate_ossec_active_response.ps1").exists(), str(repo_root / "scripts" / "validate_ossec_active_response.ps1")))
    checks.append(("live_smoke_script_exists", (repo_root / "scripts" / "smoke_test_live_integrations.py").exists(), str(repo_root / "scripts" / "smoke_test_live_integrations.py")))

    try:
        if os.name == "nt":
            import ctypes

            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            checks.append(
                (
                    "windows_admin_session",
                    True,
                    "elevated shell detected" if is_admin else "not elevated; elevate before running validate_ossec_active_response.ps1",
                )
            )
    except Exception as exc:
        checks.append(("windows_admin_session", True, f"admin check unavailable: {exc}"))

    try:
        from api.security import load_security_settings

        settings = load_security_settings()
        checks.append(("security_settings_valid", True, settings.policy_profile))
        checks.append(("policy_profile_valid", settings.policy_profile in {"lab", "corp", "prod"}, settings.policy_profile))
        checks.append(("auth_mode_consistent", (not settings.auth_required) or bool(settings.api_key or settings.api_key_sha256 or settings.api_keys or settings.api_keys_sha256), "auth/keys configuration"))
    except Exception as exc:
        checks.append(("security_settings_valid", False, str(exc)))

    if whids_manager_url:
        parsed = urlparse(whids_manager_url)
        checks.append(("whids_manager_url_valid", bool(parsed.scheme and parsed.netloc), whids_manager_url))
        checks.append(("whids_manager_api_key_present", bool(whids_api_key), "configured" if whids_api_key else "missing"))
        checks.append(("whids_endpoint_uuid_present", bool(whids_endpoint_uuid), whids_endpoint_uuid or "missing"))
    else:
        checks.append(("whids_manager_url_valid", True, "WHIDS manager env not configured; live manager validation skipped"))

    runtime_payload: dict[str, object] = {}
    if runtime_path.exists():
        try:
            runtime_payload = json.loads(runtime_path.read_text(encoding="utf-8"))
        except Exception as exc:
            checks.append(("runtime_json_valid", False, str(exc)))
        else:
            checks.append(("runtime_json_valid", True, "ok"))
            whids_runtime = runtime_payload.get("whids_scheduler", {})
            ossec_runtime = runtime_payload.get("ossec_live", {})
            checks.append(("runtime_has_whids_scheduler", isinstance(whids_runtime, dict), str(bool(whids_runtime))))
            checks.append(("runtime_has_ossec_live", isinstance(ossec_runtime, dict), str(bool(ossec_runtime))))
            if isinstance(whids_runtime, dict):
                checks.append(
                    (
                        "runtime_whids_enabled_field",
                        ("enabled" in whids_runtime) or not whids_runtime,
                        json.dumps(whids_runtime) if whids_runtime else "WHIDS scheduler not yet configured",
                    )
                )
            if isinstance(ossec_runtime, dict):
                checks.append(("runtime_ossec_enabled_field", "enabled" in ossec_runtime, json.dumps(ossec_runtime)))

    failures = [item for item in checks if not item[1]]
    print("ShadowLab deployment validation")
    for name, ok, detail in checks:
        state = "PASS" if ok else "FAIL"
        print(f"[{state}] {name}: {detail}")
    print(f"\nSummary: {len(checks) - len(failures)} passed / {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
