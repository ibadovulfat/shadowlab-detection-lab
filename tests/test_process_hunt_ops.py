from __future__ import annotations

import json
import time
from types import SimpleNamespace

from desktop.process_hunt_ops import ProcessHuntWorkspaceController


def controller(tmp_path):
    app = SimpleNamespace(process_reputation_cache={})
    ctrl = ProcessHuntWorkspaceController(app)
    ctrl.reputation_cache_path = lambda: tmp_path / "process-reputation-cache.json"  # type: ignore[method-assign]
    return ctrl, app


def test_risk_scoring_flags_lolbin_parent_path_and_public_egress(tmp_path):
    ctrl, _ = controller(tmp_path)
    score, label, reasons = ctrl.score_process(
        {
            "pid": 42,
            "name": "powershell.exe",
            "parent_name": "winword.exe",
            "exe": r"C:\Users\pc\AppData\Temp\powershell.exe",
            "cmdline": "powershell -enc AAAA http://8.8.8.8/a",
            "signature_status": "unsigned",
            "sha256": "a" * 64,
            "network_connections": ["10.0.0.2:49152->8.8.8.8:443"],
            "execution_context": {"office_parent": True, "lolbin": True},
            "create_time": time.time(),
        }
    )

    joined = " ".join(reasons).lower()
    assert score >= 75
    assert label == "critical"
    assert "office" in joined
    assert "lolbin" in joined
    assert "public network" in joined


def test_known_good_windows_baseline_does_not_auto_high_on_shallow_signature(tmp_path):
    ctrl, _ = controller(tmp_path)
    score, label, reasons = ctrl.score_process(
        {
            "pid": 4,
            "name": "System",
            "exe": "",
            "cmdline": "",
            "signature_status": "n/a",
            "cpu_percent": 0,
            "memory_percent": 0,
        }
    )

    assert score < 30
    assert label == "low"
    assert any("known-good" in reason for reason in reasons)


def test_reputation_cache_persists_and_expires(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_reputation_cache["fresh"] = {"severity": "low", "cached_at": time.time()}
    app.process_reputation_cache["old"] = {"severity": "high", "cached_at": time.time() - ctrl.reputation_cache_ttl_seconds() - 5}
    ctrl.save_process_reputation_cache()

    loaded = ctrl.load_process_reputation_cache()
    assert "fresh" in loaded
    assert "old" not in loaded


def test_reputation_label_marks_stale(tmp_path):
    ctrl, _ = controller(tmp_path)
    label = ctrl.reputation_label({"severity": "medium", "score": 44, "cached_at": time.time() - 90000}, True)
    assert "stale" in label


def test_protected_process_helper(tmp_path):
    ctrl, _ = controller(tmp_path)
    assert ctrl.is_protected_process("lsass.exe")
    assert not ctrl.is_protected_process("notepad.exe")


def test_partial_telemetry_badges_expose_missing_fields(tmp_path):
    ctrl, _ = controller(tmp_path)
    html = ctrl.partial_telemetry_badges({"name": "x", "signature_status": "unknown", "session_id": "unknown"})
    assert "Hash" in html
    assert "partial" in html


def test_reputation_cache_file_is_json(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_reputation_cache["abc"] = {"severity": "high", "score": 80, "cached_at": time.time()}
    ctrl.save_process_reputation_cache()

    raw = json.loads((tmp_path / "process-reputation-cache.json").read_text(encoding="utf-8"))
    assert raw["abc"]["severity"] == "high"


def test_command_button_badges(tmp_path):
    ctrl, _ = controller(tmp_path)
    assert ctrl.command_button_text("Kill", "Kill", True).endswith("[DANGER]")
    assert ctrl.command_button_text("Scan", "Scan Selected", False).endswith("[PROV]")
    assert ctrl.command_button_text("Clear", "Clear Reputation", False).endswith("[CACHE]")
    assert ctrl.command_policy_label("Kill") == "[DANGER][ADMIN]"
    assert ctrl.command_policy_label("Scan Selected") == "[PROVIDER]"
    assert ctrl.command_button_width("Quarantine", 200) <= 92


def test_reputation_cache_stats_counts_stale(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_reputation_cache = {
        "fresh": {"cached_at": time.time()},
        "stale": {"cached_at": time.time() - 90000},
    }
    stats = ctrl.reputation_cache_stats()
    assert stats["count"] == 2
    assert stats["stale"] == 1


def test_action_policy_preview_includes_target_policy_and_rollback(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_dry_run_toggle = SimpleNamespace(isChecked=lambda: True)
    preview = ctrl.action_policy_preview(
        "kill",
        [("1", "notepad.exe"), ("2", "lsass.exe")],
        "high",
        "low",
        {"exe": r"C:\Windows\System32\notepad.exe"},
    )
    assert "Target count: 2" in preview
    assert "Protected targets: 1" in preview
    assert "Dry-run: on" in preview
    assert "Rollback confidence: low" in preview


def test_cache_clear_removes_memory_and_file(tmp_path):
    ctrl, app = controller(tmp_path)

    class Sink:
        def setHtml(self, value):
            self.value = value

    class Status:
        def showMessage(self, value):
            self.value = value

    app.process_reputation_cache = {"abc": {"cached_at": time.time()}}
    app.process_audit_log = []
    app.hunt_out = Sink()
    app.statusBar = lambda: Status()
    app.process_timeline_view = Sink()
    app.process_audit_view = Sink()
    app.selected_process = None
    ctrl.save_process_reputation_cache()
    assert ctrl.reputation_cache_path().exists()

    ctrl.clear_reputation_cache()
    assert app.process_reputation_cache == {}
    assert not ctrl.reputation_cache_path().exists()


def test_command_group_order_puts_intel_before_response(tmp_path):
    ctrl, _ = controller(tmp_path)
    rows = ctrl.command_group_rows()
    assert [group[0] for group in rows[0]] == ["Load", "Triage", "Intel"]
    assert [group[0] for group in rows[1]] == ["State", "Forensics", "Response"]


def test_provider_readiness_html_shows_missing_keys_and_cache_stats(tmp_path):
    ctrl, app = controller(tmp_path)

    class Field:
        def __init__(self, value=""):
            self.value = value

        def text(self):
            return self.value

    app.vt_key = Field("")
    app.malwarebazaar_key = Field("mb-key")
    app.yaraify_key = Field("")
    app.process_reputation_cache = {
        "fresh": {"cached_at": time.time()},
        "stale": {"cached_at": time.time() - 90000},
    }
    html = ctrl.render_provider_readiness_html()
    assert "Provider Readiness" in html
    assert "VirusTotal" in html
    assert "missing API key" in html
    assert "MalwareBazaar" in html
    assert "2 verdict" in html
    assert "1 stale" in html


def test_enterprise_audit_records_request_policy_mode_and_status(tmp_path):
    ctrl, app = controller(tmp_path)

    class Sink:
        def setHtml(self, value):
            self.value = value

    app.process_audit_log = []
    app.process_audit_view = Sink()
    app.process_timeline_view = Sink()
    app.selected_process = None
    app.auth_context = {"role": "admin"}

    ctrl.append_process_audit(
        "kill",
        "123",
        "bad.exe",
        "completed | reason: isolated threat",
        {"request_id": "req-1", "policy": "admin response", "mode": "live", "rollback": "low"},
    )

    entry = app.process_audit_log[0]
    assert entry["request_id"] == "req-1"
    assert entry["actor"] == "admin"
    assert entry["policy"] == "admin response"
    assert entry["mode"] == "live"
    assert entry["rollback"] == "low"
    assert entry["status"] == "ok"
    assert "Request" in app.process_audit_view.value


def test_risk_scoring_policy_config_can_suppress_process(tmp_path):
    ctrl, _ = controller(tmp_path)
    policy = tmp_path / "process_risk_policy.json"
    policy.write_text(
        json.dumps(
            {
                "known_good_windows": [],
                "suppressions": ["customagent.exe"],
                "weights": {"known_good_discount": -40, "missing_hash": 0, "shallow_signature": 0, "missing_exe": 0},
            }
        ),
        encoding="utf-8",
    )
    ctrl.risk_policy_path = lambda: policy  # type: ignore[method-assign]
    score, label, reasons = ctrl.score_process({"name": "customagent.exe", "signature_status": "valid", "sha256": "a" * 64})
    assert score == 0
    assert label == "low"
    assert any("suppression" in reason for reason in reasons)


def test_job_status_html_exposes_running_job_metadata(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_active_job = {
        "id": "job-123",
        "label": "Memory analysis PID 42",
        "status": "running",
        "started": time.time() - 3,
        "timeout_seconds": 60,
    }
    html = ctrl.render_job_status_html()
    assert "job-123" in html
    assert "Memory analysis PID 42" in html
    assert "Best-effort UI cancellation" in html


def test_job_history_renders_after_completed_job(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_active_job = None
    app.process_job_history = []
    ctrl.record_job_history(
        {
            "id": "job-777",
            "label": "YARA PID 7",
            "status": "completed",
            "started": time.time() - 2,
            "finished": time.time(),
        }
    )
    html = ctrl.render_job_status_html()
    assert "Recent Process Jobs" in html
    assert "job-777" in html
    assert "completed" in html


def test_job_history_deduplicates_cancelled_job(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_job_history = []
    job = {
        "id": "job-cancel",
        "label": "Sandbox PID 9",
        "status": "cancelled",
        "started": time.time() - 1,
        "finished": time.time(),
    }
    ctrl.record_job_history(job)
    ctrl.record_job_history(job)
    html = ctrl.render_job_status_html()
    assert len(app.process_job_history) == 1
    assert "job-cancel" in html
    assert "cancelled" in html


def test_command_access_matrix_allows_analyst_hunt_but_not_response(tmp_path):
    ctrl, _ = controller(tmp_path)
    matrix = ctrl.command_access_matrix({"can_run_hunt": True, "can_run_triage": True, "can_manage_process_actions": False})
    assert matrix["Scan Selected"] is True
    assert matrix["Auto Triage"] is True
    assert matrix["Kill"] is False
    assert matrix["Quarantine"] is False


def test_bulk_scan_timeout_caps_total_budget():
    from desktop.process_hunt_jobs import bulk_scan_timeout

    # Single-call budget — at least the per-call value
    assert bulk_scan_timeout(70, 1) == 70
    # Small bulk — adds modest slack per extra call
    assert bulk_scan_timeout(70, 5) == 90
    # Large bulk used to multiply naively (`100 * 70 = 7000`); the new
    # cap keeps the watchdog within 10 minutes regardless of count.
    assert bulk_scan_timeout(70, 100) <= 600
    # Custom cap honours upper bound
    assert bulk_scan_timeout(70, 500, total_cap=300) == 300


def test_response_action_allowlist_matches_backend():
    from desktop.process_hunt_ops import RESPONSE_ACTION_ALLOWLIST

    # Mirror of api/routes/processes.py::process_action server-side
    # action set — adding an entry here without a matching server
    # endpoint will produce a 400 at runtime, which is the intended
    # signal: the client allowlist is the contract.
    assert RESPONSE_ACTION_ALLOWLIST == frozenset({"suspend", "resume", "kill", "kill-tree", "quarantine"})


def test_reputation_cache_skips_pid_only_entries_on_reload(tmp_path):
    ctrl, app = controller(tmp_path)
    app.process_reputation_cache = {
        "abc123": {"severity": "high", "score": 90, "cached_at": time.time()},
        "1234": {"severity": "low", "score": 5, "cached_at": time.time(), "_volatile": True},
    }
    ctrl.save_process_reputation_cache()

    loaded = ctrl.load_process_reputation_cache()
    # SHA-style key survives the round-trip; the PID-only / volatile
    # entry must NOT — OS PIDs are reused across reboots.
    assert "abc123" in loaded
    assert "1234" not in loaded


def test_audit_log_persists_to_disk_and_reloads(tmp_path):
    ctrl, app = controller(tmp_path)
    ctrl.audit_log_path = lambda: tmp_path / "process-audit-log.json"  # type: ignore[method-assign]

    class Sink:
        def setHtml(self, value):
            self.value = value

    app.process_audit_log = []
    app.process_audit_view = Sink()
    app.process_timeline_view = Sink()
    app.selected_process = None
    app.auth_context = {"role": "analyst"}

    ctrl.append_process_audit(
        "kill",
        "555",
        "evil.exe",
        "completed",
        {
            "request_id": "req-99",
            "ticket_id": "SOC-1234",
            "reason_category": "incident-confirmed",
            "reason_text": "active beaconing observed in netflow",
        },
    )

    # The on-disk JSON should round-trip the structured reason fields.
    raw = json.loads((tmp_path / "process-audit-log.json").read_text(encoding="utf-8"))
    assert raw[0]["ticket_id"] == "SOC-1234"
    assert raw[0]["reason_category"] == "incident-confirmed"
    assert "ts" in raw[0]
    assert raw[0]["workspace"] == "default"

    # And reload returns a list with the same record.
    loaded = ctrl.load_process_audit_log()
    assert loaded[0]["ticket_id"] == "SOC-1234"


def test_risk_policy_html_exposes_loaded_policy_counts(tmp_path):
    ctrl, _ = controller(tmp_path)
    policy = tmp_path / "process_risk_policy.json"
    policy.write_text(
        json.dumps({"known_good_windows": ["system"], "suppressions": ["agent.exe"], "weights": {"lolbin": 12}}),
        encoding="utf-8",
    )
    ctrl.risk_policy_path = lambda: policy  # type: ignore[method-assign]
    html = ctrl.render_risk_policy_html()
    assert "Risk Scoring Policy" in html
    assert "Known-good" in html
    assert "Suppressions" in html
    assert "lolbin" in html
