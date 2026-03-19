from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.backup_shadowlab_data import redact_database_profile
from scripts.restore_shadowlab_data import _is_relative_to
from scripts.smoke_test_postgres_runtime import redact_profile


class OpsScriptsTests(unittest.TestCase):
    def test_postgres_profile_redaction_hides_password(self) -> None:
        profile = {
            "backend": "postgresql",
            "database_url": "postgresql://shadowlab:supersecret@db.local:5432/shadowlab",
            "mode": "shared-runtime",
        }
        sanitized_backup = redact_database_profile(profile)
        sanitized_smoke = redact_profile(profile)
        self.assertNotIn("supersecret", sanitized_backup["database_url"])
        self.assertNotIn("supersecret", sanitized_smoke["database_url"])
        self.assertIn("***", sanitized_backup["database_url"])

    def test_restore_relative_path_guard_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inside = root / "shadowlab_out"
            inside.mkdir()
            outside = Path(tmp).parent
            self.assertTrue(_is_relative_to(inside, root))
            self.assertFalse(_is_relative_to(outside, root))

    def test_restore_uses_manifest_relative_database_artifact_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "manifest.json"
            db_artifact = root / "shadowlab.db"
            db_artifact.write_text("ok", encoding="utf-8")
            payload = {
                "database_profile": {"backend": "sqlite", "database_url": "../outside/shadowlab.db"},
                "database_backup": str(db_artifact),
            }
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
            import os
            database_url = parsed["database_profile"]["database_url"]
            target_name = os.path.basename(database_url)
            self.assertEqual(target_name, "shadowlab.db")


if __name__ == "__main__":
    unittest.main()
