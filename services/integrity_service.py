from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import database as db
from services.secret_store import secret_store


class IntegrityService:
    def __init__(self, base_dir: Path, out_dir: Path):
        self.base_dir = Path(base_dir)
        self.out_dir = Path(out_dir)
        self.evidence_dir = self.base_dir / "evidence_locker"
        self.quarantine_dir = self.base_dir / "shadowlab_quarantine"
        self.manifest_path = self.out_dir / "integrity_manifest.json"
        self.history_path = self.out_dir / "integrity_manifest_history.jsonl"
        self.signing_key_setting = "integrity_signing_key_enc"

    def refresh_manifest(self) -> dict[str, Any]:
        manifest = self._build_manifest()
        manifest["signature"] = self._sign_manifest(manifest)
        manifest["signature_status"] = "signed" if manifest["signature"] else "unsigned"
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with self.history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"generated_at": manifest.get("generated_at"), "signature": manifest.get("signature", ""), "file_count": len(manifest.get("files", {}))}) + "\n")
        return manifest

    def verify_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {
                "status": "missing_manifest",
                "manifest_path": str(self.manifest_path),
                "recommendation": "Run integrity refresh to create a trusted baseline.",
            }
        stored = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        current = self._build_manifest()
        stored_files = stored.get("files", {})
        current_files = current.get("files", {})
        missing = sorted(path for path in stored_files if path not in current_files)
        untracked = sorted(path for path in current_files if path not in stored_files)
        modified = sorted(
            path
            for path in stored_files
            if path in current_files and (
                stored_files[path].get("sha256") != current_files[path].get("sha256")
                or stored_files[path].get("size") != current_files[path].get("size")
            )
        )
        verified = sorted(
            path
            for path in stored_files
            if path in current_files and path not in modified
        )
        status = "ok" if not missing and not untracked and not modified else "drift_detected"
        signature_state = self._signature_state(stored)
        return {
            "status": "signature_invalid" if signature_state == "invalid" else status,
            "manifest_path": str(self.manifest_path),
            "roots": current.get("roots", {}),
            "counts": {
                "verified": len(verified),
                "missing": len(missing),
                "modified": len(modified),
                "untracked": len(untracked),
            },
            "signature_valid": signature_state == "valid",
            "signature_state": signature_state,
            "verified": verified[:100],
            "missing": missing[:100],
            "modified": modified[:100],
            "untracked": untracked[:100],
            "generated_at": current.get("generated_at"),
        }

    def rotate_signing_key(self) -> dict[str, Any]:
        signing_key = secrets.token_hex(32)
        encrypted = secret_store.encrypt_text(signing_key)
        conn = db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            db.set_app_setting(conn, self.signing_key_setting, encrypted)
        finally:
            conn.close()
        manifest = self.refresh_manifest()
        return {
            "status": "rotated",
            "manifest_path": manifest.get("manifest_path", ""),
            "signature_status": manifest.get("signature_status", "unsigned"),
        }

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        lines = self.history_path.read_text(encoding="utf-8").splitlines()[-limit:]
        history: list[dict[str, Any]] = []
        for line in lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                history.append(item)
        return history

    def _build_manifest(self) -> dict[str, Any]:
        files: dict[str, dict[str, Any]] = {}
        roots = {
            "artifacts": str(self.out_dir.resolve()),
            "evidence": str(self.evidence_dir.resolve()),
            "quarantine": str(self.quarantine_dir.resolve()),
        }
        for directory, allowed_suffixes in (
            (self.out_dir, {".csv", ".json", ".html", ".pdf", ".jsonl", ".sql"}),
            (self.evidence_dir, {".png", ".jpg", ".jpeg", ".webp"}),
            (self.quarantine_dir, None),
        ):
            if not directory.exists():
                continue
            for path in sorted(item for item in directory.rglob("*") if item.is_file()):
                if path.resolve() in {self.manifest_path.resolve(), self.history_path.resolve()}:
                    continue
                if allowed_suffixes and path.suffix.lower() not in allowed_suffixes:
                    continue
                relative = path.resolve().relative_to(self.base_dir.resolve()).as_posix()
                files[relative] = {
                    "sha256": self._sha256(path),
                    "size": path.stat().st_size,
                    "modified_at": path.stat().st_mtime,
                }
        return {
            "generated_at": time.time(),
            "manifest_path": str(self.manifest_path),
            "roots": roots,
            "files": files,
        }

    def _sign_manifest(self, manifest: dict[str, Any]) -> str:
        signing_key = self._load_signing_key()
        if not signing_key:
            return ""
        payload = json.dumps(self._unsigned_manifest(manifest), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(signing_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def _signature_state(self, manifest: dict[str, Any]) -> str:
        signature = str(manifest.get("signature", "") or "")
        if not signature:
            return "missing"
        expected = self._sign_manifest(manifest)
        if not expected:
            return "missing"
        return "valid" if hmac.compare_digest(signature, expected) else "invalid"

    def _unsigned_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        payload = dict(manifest)
        payload.pop("signature", None)
        payload.pop("signature_status", None)
        return payload

    def _load_signing_key(self) -> str:
        env_key = str(os.environ.get("SHADOWLAB_INTEGRITY_SIGNING_KEY", "")).strip()
        if env_key:
            return env_key
        conn = db.create_connection()
        if conn is None:
            return ""
        try:
            encrypted = db.get_app_setting(conn, self.signing_key_setting)
        finally:
            conn.close()
        if not encrypted:
            return ""
        try:
            return secret_store.decrypt_text(encrypted)
        except Exception:
            return ""

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()
