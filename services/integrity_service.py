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

    def refresh_manifest(self, workspace_id: str = "default") -> dict[str, Any]:
        manifest = self._build_manifest(workspace_id=workspace_id)
        manifest["signature"] = self._sign_manifest(manifest)
        manifest["signature_status"] = "signed" if manifest["signature"] else "unsigned"
        manifest_path = self._manifest_path(workspace_id)
        history_path = self._history_path(workspace_id)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with history_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "generated_at": manifest.get("generated_at"),
                        "signature": manifest.get("signature", ""),
                        "file_count": len(manifest.get("files", {})),
                        "workspace_id": workspace_id,
                    }
                )
                + "\n"
            )
        return manifest

    def verify_manifest(self, workspace_id: str = "default") -> dict[str, Any]:
        manifest_path = self._manifest_path(workspace_id)
        if not manifest_path.exists():
            return {
                "status": "missing_manifest",
                "manifest_path": str(manifest_path),
                "recommendation": "Run integrity refresh to create a trusted baseline.",
            }
        stored = json.loads(manifest_path.read_text(encoding="utf-8"))
        current = self._build_manifest(workspace_id=workspace_id)
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
        # Fail-closed when an integrity manifest is unsigned/unverifiable in
        # any non-lab profile. This prevents an attacker with write access to
        # shadowlab_out/integrity_manifest.json from silently stripping the
        # signature field and having verify_manifest still return "ok".
        effective_status = status
        if signature_state == "invalid":
            effective_status = "signature_invalid"
        elif signature_state == "missing" and self._strict_signature_required():
            effective_status = "signature_missing"
        return {
            "status": effective_status,
            "manifest_path": str(manifest_path),
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

    def history(self, limit: int = 50, workspace_id: str = "default") -> list[dict[str, Any]]:
        history_path = self._history_path(workspace_id)
        if not history_path.exists():
            return []
        lines = history_path.read_text(encoding="utf-8").splitlines()[-limit:]
        history: list[dict[str, Any]] = []
        for line in lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                history.append(item)
        return history

    def _build_manifest(self, workspace_id: str = "default") -> dict[str, Any]:
        files: dict[str, dict[str, Any]] = {}
        manifest_path = self._manifest_path(workspace_id)
        history_path = self._history_path(workspace_id)
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
                if path.resolve() in {manifest_path.resolve(), history_path.resolve()}:
                    continue
                if allowed_suffixes and path.suffix.lower() not in allowed_suffixes:
                    continue
                if directory == self.out_dir and workspace_id != "default":
                    workspace_root = (self.out_dir / "workspaces" / workspace_id).resolve()
                    resolved_path = path.resolve()
                    if workspace_root not in resolved_path.parents and resolved_path != workspace_root:
                        continue
                relative = path.resolve().relative_to(self.base_dir.resolve()).as_posix()
                files[relative] = {
                    "sha256": self._sha256(path),
                    "size": path.stat().st_size,
                    "modified_at": path.stat().st_mtime,
                }
        return {
            "generated_at": time.time(),
            "manifest_path": str(manifest_path),
            "roots": roots,
            "files": files,
        }

    def _manifest_path(self, workspace_id: str) -> Path:
        current = str(workspace_id or "default").strip().lower() or "default"
        if current == "default":
            return self.manifest_path
        target = self.out_dir / "workspaces" / current
        target.mkdir(parents=True, exist_ok=True)
        return target / "integrity_manifest.json"

    def _history_path(self, workspace_id: str) -> Path:
        current = str(workspace_id or "default").strip().lower() or "default"
        if current == "default":
            return self.history_path
        target = self.out_dir / "workspaces" / current
        target.mkdir(parents=True, exist_ok=True)
        return target / "integrity_manifest_history.jsonl"

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

    def _strict_signature_required(self) -> bool:
        """Return True when an unsigned manifest must be treated as tampered.

        In `lab` (the development default) we tolerate missing signing keys
        so first-run bootstrap stays friendly. In `corp`/`prod` profiles we
        require a real HMAC to cross the chain-of-custody bar.
        """
        profile = os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab").strip().lower() or "lab"
        return profile in {"corp", "prod"}

    def _load_signing_key(self) -> str:
        import logging as _logging
        _logger = _logging.getLogger(__name__)
        env_key = str(os.environ.get("SHADOWLAB_INTEGRITY_SIGNING_KEY", "")).strip()
        if env_key:
            return env_key
        conn = db.create_connection()
        if conn is None:
            _logger.warning("integrity signing key not loaded: database unavailable")
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
            _logger.exception("failed to decrypt integrity signing key — manifest will be unsigned")
            return ""

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()
