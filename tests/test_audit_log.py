from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from desktop._audit_log import AuditLogStore, actor_workspace_pair


def _store(tmp_path):
    return AuditLogStore(lambda: tmp_path / "audit.json", retention=3)


def test_append_writes_record_with_canonical_fields(tmp_path):
    store = _store(tmp_path)
    entry = store.append(
        category="response",
        action="kill",
        target="PID 42",
        severity="high",
        status="ok",
        payload={"echo": True},
        actor="analyst-1",
        workspace="lab",
    )

    # Must include the canonical schema keys + ISO timestamp with offset.
    assert entry["category"] == "response"
    assert entry["action"] == "kill"
    assert entry["target"] == "PID 42"
    assert entry["severity"] == "high"
    assert entry["status"] == "ok"
    assert entry["actor"] == "analyst-1"
    assert entry["workspace"] == "lab"
    assert "T" in entry["ts"]
    # Persisted to disk newest-first.
    raw = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    assert raw[0]["target"] == "PID 42"


def test_reason_metadata_round_trips(tmp_path):
    store = _store(tmp_path)
    store.append(
        category="response",
        action="quarantine",
        target="C:/temp/evil.exe",
        severity="high",
        status="ok",
        payload={},
        reason={"ticket_id": "SOC-99", "reason_category": "ioc-match", "reason_text": "VT detection"},
    )
    raw = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    assert raw[0]["ticket_id"] == "SOC-99"
    assert raw[0]["reason_category"] == "ioc-match"
    assert raw[0]["reason_text"] == "VT detection"


def test_retention_caps_history(tmp_path):
    store = _store(tmp_path)  # retention=3
    for i in range(5):
        store.append(
            category="incident",
            action="status:open",
            target=f"INC-{i}",
            severity="medium",
            status="ok",
            payload={},
        )
    on_disk = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    # Newest-first, retention drops the two oldest entries.
    assert [item["target"] for item in on_disk] == ["INC-4", "INC-3", "INC-2"]


def test_load_skips_non_dict_entries(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps([{"target": "ok"}, "junk", 42, {"target": "alive"}]), encoding="utf-8")
    store = AuditLogStore(lambda: path, retention=10)
    loaded = store.load()
    assert [item["target"] for item in loaded] == ["ok", "alive"]


def test_load_handles_corrupt_json(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text("{not json", encoding="utf-8")
    store = AuditLogStore(lambda: path, retention=10)
    assert store.load() == []
    assert store.entries() == []


def test_save_swallows_io_errors(tmp_path, monkeypatch):
    store = _store(tmp_path)
    store._cache = [{"target": "x"}]

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("pathlib.Path.write_text", boom)
    # Must NOT raise — audit failures shouldn't tear down the response action.
    store.save()


def test_actor_workspace_pair_falls_back_to_defaults():
    actor, workspace = actor_workspace_pair(SimpleNamespace())
    assert actor == "desktop"
    assert workspace == "default"


def test_actor_workspace_pair_reads_qt_widgets():
    class Field:
        def __init__(self, value: str) -> None:
            self._value = value

        def text(self) -> str:
            return self._value

    app = SimpleNamespace(actor_name=Field("amos.salazar"), workspace_id=Field("prod"))
    actor, workspace = actor_workspace_pair(app)
    assert actor == "amos.salazar"
    assert workspace == "prod"


def test_mirror_callback_fires_after_append(tmp_path):
    received: list[dict] = []
    store = AuditLogStore(
        lambda: tmp_path / "audit.json",
        retention=10,
        mirror_callback=lambda entry: received.append(entry),
    )
    store.append(
        category="case",
        action="assign",
        target="case=99",
        severity="medium",
        status="ok",
        payload={},
    )
    assert len(received) == 1
    assert received[0]["action"] == "assign"


def test_mirror_callback_exception_does_not_break_append(tmp_path):
    """A flaky backend mustn't tear down the local audit chain."""

    def boom(_entry):
        raise RuntimeError("backend down")

    store = AuditLogStore(
        lambda: tmp_path / "audit.json",
        retention=10,
        mirror_callback=boom,
    )
    # Must not raise — local-disk write is the source of truth.
    entry = store.append(
        category="case",
        action="approval",
        target="case=99",
        severity="high",
        status="ok",
        payload={},
    )
    assert entry["action"] == "approval"
    on_disk = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    assert on_disk[0]["action"] == "approval"


def test_set_mirror_callback_can_be_swapped_at_runtime(tmp_path):
    captured: list[dict] = []
    store = AuditLogStore(lambda: tmp_path / "audit.json", retention=10)

    # No callback initially — append shouldn't error.
    store.append(category="case", action="create", target="x", severity="low", status="ok", payload={})
    assert captured == []

    store.set_mirror_callback(lambda entry: captured.append(entry))
    store.append(category="case", action="assign", target="x", severity="medium", status="ok", payload={})
    assert len(captured) == 1
    assert captured[0]["action"] == "assign"

    # Clear the callback again.
    store.set_mirror_callback(None)
    store.append(category="case", action="export", target="x", severity="low", status="ok", payload={})
    assert len(captured) == 1  # still 1 — last append did NOT call the (now-cleared) callback


def test_extra_metadata_is_preserved(tmp_path):
    store = _store(tmp_path)
    store.append(
        category="incident",
        action="status:closed",
        target="INC-7",
        severity="high",
        status="ok",
        payload={},
        extra={"previous_status": "investigating", "approval_id": "APP-3"},
    )
    raw = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    assert raw[0]["previous_status"] == "investigating"
    assert raw[0]["approval_id"] == "APP-3"
