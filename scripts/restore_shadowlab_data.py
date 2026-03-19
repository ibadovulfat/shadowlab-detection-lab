from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


DEFAULT_DIRS = ("shadowlab_out", "evidence_locker", "shadowlab_quarantine")


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Restore a ShadowLab backup bundle created by backup_shadowlab_data.py.")
    parser.add_argument("manifest", help="Path to the backup manifest.json file.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    backup_root = manifest_path.parent

    for name in DEFAULT_DIRS:
        src = backup_root / name
        if src.exists() and _is_relative_to(src, backup_root):
            shutil.copytree(src, Path(name), dirs_exist_ok=True)

    database_backup = Path(str(manifest.get("database_backup", ""))).resolve()
    profile = manifest.get("database_profile", {})
    import os
    db_url_raw = str(profile.get("database_url", "shadowlab.db"))
    target_name = os.path.basename(db_url_raw.replace("\\", "/"))
    target_path = Path(target_name)
    if profile.get("backend") == "sqlite" and database_backup.exists() and _is_relative_to(database_backup, backup_root):
        if database_backup.suffix.lower() != ".db":
            raise ValueError("Backup manifest contains an invalid SQLite database artifact.")
        shutil.copy2(database_backup, target_path)

    print(str(manifest_path))


if __name__ == "__main__":
    main()
