from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import database as db


DEFAULT_DIRS = ("shadowlab_out", "evidence_locker", "shadowlab_quarantine")


def redact_database_profile(profile: dict[str, str]) -> dict[str, str]:
    sanitized = dict(profile)
    raw_url = str(sanitized.get("database_url", "")).strip()
    parsed = urlparse(raw_url)
    if parsed.scheme in {"postgres", "postgresql"} and parsed.hostname:
        auth = parsed.username or ""
        if auth:
            auth = f"{auth}:***@"
        netloc = f"{auth}{parsed.hostname}"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        sanitized["database_url"] = urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )
    return sanitized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a timestamped ShadowLab backup bundle.")
    parser.add_argument("--output-dir", default="backups", help="Directory where backups are written.")
    return parser.parse_args()


def export_sqlite(profile: dict[str, str], target_dir: Path) -> str:
    if profile["backend"] != "sqlite":
        return profile["database_url"]
    source = Path(profile["database_url"])
    destination = target_dir / source.name
    if source.exists():
        with sqlite3.connect(source) as src_conn:
            with sqlite3.connect(destination) as dst_conn:
                src_conn.backup(dst_conn)
    return str(destination)


def copy_directory(name: str, target_dir: Path) -> str:
    source = Path(name)
    destination = target_dir / name
    if source.exists():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    return str(destination)


def main() -> None:
    args = parse_args()
    profile = db.database_runtime_profile()
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup_root = Path(args.output_dir).resolve() / f"shadowlab_backup_{stamp}"
    backup_root.mkdir(parents=True, exist_ok=True)

    manifest = {
        "created_at": time.time(),
        "database_profile": redact_database_profile(profile),
        "database_backup": export_sqlite(profile, backup_root),
        "copied_dirs": {name: copy_directory(name, backup_root) for name in DEFAULT_DIRS},
    }
    manifest_path = backup_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(str(manifest_path))


if __name__ == "__main__":
    main()
