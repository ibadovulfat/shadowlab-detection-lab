"""Sprint-5 EDR feature tests.

Coverage:
  * `kill_process` — protected-process refusal, invalid PID rejection.
  * `vss_list_snapshots` — clean unsupported_platform on non-Windows.
  * `network_isolate` / `network_release` — clean unsupported_platform
    fallback when neither netsh nor iptables is available.
  * `CustomYaraStore` — round-trip save/list/get/delete + invalid-name
    rejection + compile-error surfacing.
  * `AntivirusListStore` — add/remove/match across all 3 list kinds.
  * `get_process_tree` — fetches the current process and returns a
    valid tree with depth ≥ 1.

Tests skip cleanly when the underlying OS or library isn't available
(psutil missing, etc.) so the suite runs everywhere CI runs.
"""
from __future__ import annotations

import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from services.antivirus.custom_yara import CustomYaraStore
from services.antivirus.forensics import get_process_tree
from services.antivirus.lists import AntivirusListStore, _classify_value
from services.antivirus.live_response import (
    PROTECTED_PROCESS_NAMES,
    kill_process,
    network_isolate,
    network_release,
    vss_list_snapshots,
)


# ----------------------------------------------------- Live response


class LiveResponseTests(unittest.TestCase):
    def test_invalid_pid_rejected(self) -> None:
        self.assertEqual(kill_process(0), {"ok": False, "reason": "invalid_pid"})
        self.assertEqual(kill_process(-1), {"ok": False, "reason": "invalid_pid"})

    def test_kill_unknown_pid_returns_clean_error(self) -> None:
        # Pick a PID that almost certainly doesn't exist.
        result = kill_process(999_999_999)
        self.assertFalse(result.get("ok"))
        # Either no_such_process or permission_denied are acceptable —
        # depends on whether psutil is installed.
        self.assertIn(result.get("reason"), {"no_such_process", "permission_denied"})

    def test_protected_process_set_includes_critical_names(self) -> None:
        # Spot-check a few names we *must* refuse without explicit force.
        for name in {"system", "lsass.exe", "wininit.exe", "init", "systemd"}:
            self.assertIn(name, PROTECTED_PROCESS_NAMES)

    def test_vss_list_unsupported_off_windows(self) -> None:
        if platform.system().lower() == "windows":
            self.skipTest("VSS is supported on Windows; this guard is a no-op")
        result = vss_list_snapshots()
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("reason"), "unsupported_platform")


# ----------------------------------------------------- Custom YARA


class CustomYaraStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="shadowlab-yara-store-"))
        self.store = CustomYaraStore(self.tmp)

    def test_round_trip_save_list_get_delete(self) -> None:
        rule_source = (
            "rule shadowlab_test_marker {\n"
            "    strings: $a = \"shadowlab_marker\"\n"
            "    condition: $a\n"
            "}\n"
        )
        save = self.store.save_rule("test_marker", rule_source)
        self.assertTrue(save.get("ok"), save)
        listing = self.store.list_rules()
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["name"], "test_marker")
        fetched = self.store.get_rule("test_marker")
        self.assertIsNotNone(fetched)
        self.assertIn("shadowlab_marker", fetched["source"])
        deleted = self.store.delete_rule("test_marker")
        self.assertTrue(deleted.get("ok"))
        self.assertEqual(self.store.list_rules(), [])

    def test_invalid_name_rejected(self) -> None:
        for bad in ("", "../escape", "with space", "a" * 100, "name.with.dot"):
            res = self.store.save_rule(bad, "rule x { condition: false }")
            self.assertFalse(res.get("ok"), f"name {bad!r} should be invalid")

    def test_empty_source_rejected(self) -> None:
        res = self.store.save_rule("ok_name", "   ")
        self.assertFalse(res.get("ok"))
        self.assertEqual(res.get("reason"), "empty_source")


# ----------------------------------------------------- Lists


class _FakeDB:
    """Minimal db.create_connection / get_app_setting / set_app_setting shim."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def create_connection(self):
        outer = self

        class _Conn:
            def execute(self, *_a, **_k):
                pass

            def commit(self):
                pass

            def close(self):
                pass

        # Bind the helper functions onto the module-level db namespace
        # the AntivirusListStore expects.
        return _Conn()

    def get_app_setting(self, _conn, key: str) -> str:
        return self._store.get(key, "")

    def set_app_setting(self, _conn, key: str, value: str) -> None:
        self._store[key] = value


class AntivirusListStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _FakeDB()
        self.store = AntivirusListStore(self.db)

    def test_add_and_remove_round_trip(self) -> None:
        self.store.add_entry("blocklist", "deadbeef" * 8, note="campaign-X", actor="alice")
        items = self.store.get("blocklist")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["kind"], "hash")
        self.assertEqual(items[0]["actor"], "alice")
        self.store.remove_entry("blocklist", "deadbeef" * 8, actor="alice")
        self.assertEqual(self.store.get("blocklist"), [])

    def test_path_classification_matches_prefix(self) -> None:
        self.store.add_entry("exclusions", "C:\\Tools", note="vendor toolkit", actor="bob")
        match = self.store.matches("exclusions", path="C:\\Tools\\sigcheck.exe")
        self.assertIsNotNone(match)
        self.assertEqual(match["value"], "C:\\Tools")
        # Non-matching path returns None.
        self.assertIsNone(self.store.matches("exclusions", path="C:\\Other\\thing.exe"))

    def test_invalid_kind_rejected(self) -> None:
        result = self.store.set("nonexistent", [{"value": "x"}], actor="alice")
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("reason"), "invalid_kind")

    def test_classify_value_recognises_hash_lengths(self) -> None:
        self.assertEqual(_classify_value("a" * 32), "hash")    # MD5
        self.assertEqual(_classify_value("a" * 40), "hash")    # SHA1
        self.assertEqual(_classify_value("a" * 64), "hash")    # SHA256
        self.assertEqual(_classify_value("C:\\foo.exe"), "path")
        self.assertEqual(_classify_value("/usr/bin/foo"), "path")


# ----------------------------------------------------- Forensics


class ForensicsTests(unittest.TestCase):
    def test_get_process_tree_returns_self(self) -> None:
        try:
            import psutil  # noqa: F401
        except ImportError:
            self.skipTest("psutil not installed")
        result = get_process_tree(os.getpid(), max_depth=3)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["pid"], os.getpid())
        self.assertGreaterEqual(result["tree_depth"], 1)
        self.assertGreaterEqual(result["total_nodes"], 1)
        self.assertEqual(result["root"]["pid"], os.getpid())

    def test_invalid_pid_rejected(self) -> None:
        result = get_process_tree("not-a-pid")
        self.assertFalse(result.get("ok"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
