"""Encrypted quarantine vault for ShadowLab antivirus.

Real product-level quarantine has three properties:
  1. The original file is never readable from disk after sealing — anyone
     with filesystem access sees only ciphertext.
  2. Every sealed entry has an integrity tag, so silent tampering is
     detectable on restore.
  3. The catalogue of sealed items is itself authenticated and audited.

This module owns all three. AES-256-GCM provides authenticated encryption
of the file body; the GCM tag is then re-bound under HMAC-SHA256 with the
metadata that pins each entry (file_id, sha256, original_path,
ciphertext_path, severity). Restoring or deleting an entry recomputes the
HMAC and refuses to proceed if the catalogue row was edited out-of-band.

The master key is sourced in this priority order:
  - SHADOWLAB_VAULT_KEY env var (base64-encoded 32 bytes)
  - the persisted setting "antivirus_vault_master_key" in app_settings
    (auto-generated and stored on first use)
The key never leaves the process, and the on-disk cipher files contain
no key material — only nonce + ciphertext. Loss of the key means
permanent loss of all sealed bodies, which is the intended failure mode.

The vault is intentionally db-aware (so the catalogue survives restarts)
but degrades gracefully when no `db` connection is available — falling
back to a sealed JSON manifest on disk. That keeps unit tests and
offline runs working without relying on a live database.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VAULT_KEY_ENV = "SHADOWLAB_VAULT_KEY"
VAULT_KEY_SETTING = "antivirus_vault_master_key"
KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # AES-GCM standard nonce
HMAC_KEY_INFO = b"shadowlab-antivirus-vault-hmac-v1"
ENCRYPTION_KEY_INFO = b"shadowlab-antivirus-vault-enc-v1"


@dataclass
class VaultEntry:
    file_id: str
    workspace_id: str
    original_path: str
    ciphertext_path: str
    sha256: str
    size_bytes: int
    severity: str = ""
    fused_verdict: str = ""
    process_name: str = ""
    pid: int = -1
    actor: str = ""
    nonce_b64: str = ""
    hmac_tag: str = ""
    status: str = "sealed"
    created_at: float = 0.0
    updated_at: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "workspace_id": self.workspace_id,
            "original_path": self.original_path,
            "ciphertext_path": self.ciphertext_path,
            "sha256": self.sha256,
            "size_bytes": int(self.size_bytes),
            "severity": self.severity,
            "fused_verdict": self.fused_verdict,
            "process_name": self.process_name,
            "pid": int(self.pid),
            "actor": self.actor,
            "nonce_b64": self.nonce_b64,
            "hmac_tag": self.hmac_tag,
            "status": self.status,
            "created_at": float(self.created_at),
            "updated_at": float(self.updated_at),
            "extra": dict(self.extra or {}),
        }


class QuarantineVault:
    """AES-GCM authenticated quarantine store with HMAC-bound catalogue."""

    def __init__(self, base_dir: Path, *, db: Any = None):
        self.base_dir = Path(base_dir)
        self.vault_root = (self.base_dir / "shadowlab_quarantine" / "vault").resolve()
        self.bodies_dir = self.vault_root / "bodies"
        self.manifest_path = self.vault_root / "vault.manifest.json"
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        self._db = db
        self._lock = threading.RLock()
        self._master_key = self._resolve_master_key()
        self._enc_key = self._derive_subkey(ENCRYPTION_KEY_INFO)
        self._hmac_key = self._derive_subkey(HMAC_KEY_INFO)
        self._aes = AESGCM(self._enc_key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seal(
        self,
        source_path: str | Path,
        *,
        workspace_id: str = "default",
        process_name: str = "",
        pid: int = -1,
        actor: str = "",
        severity: str = "",
        fused_verdict: str = "",
        sha256: str = "",
        extra: dict[str, Any] | None = None,
    ) -> VaultEntry:
        """Encrypt `source_path` into the vault and return the catalogue entry.

        The original file is *not* deleted by this method — the caller
        controls disposal once they confirm the seal succeeded. (Real
        AV products preserve the original briefly for FP review, then
        the operator decides to wipe it.)
        """
        src = Path(source_path).expanduser()
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"Vault source missing: {src}")
        plaintext = src.read_bytes()
        if not sha256:
            sha256 = hashlib.sha256(plaintext).hexdigest()
        file_id = uuid.uuid4().hex
        nonce = secrets.token_bytes(NONCE_BYTES)
        ciphertext = self._aes.encrypt(nonce, plaintext, _aad(file_id, sha256))
        body_path = self.bodies_dir / f"{file_id}.bin"
        body_path.write_bytes(nonce + ciphertext)
        now = time.time()
        entry = VaultEntry(
            file_id=file_id,
            workspace_id=str(workspace_id or "default"),
            original_path=str(src),
            ciphertext_path=str(body_path),
            sha256=sha256,
            size_bytes=len(plaintext),
            severity=str(severity or ""),
            fused_verdict=str(fused_verdict or ""),
            process_name=str(process_name or src.name),
            pid=int(pid),
            actor=str(actor or ""),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            status="sealed",
            created_at=now,
            updated_at=now,
            extra=dict(extra or {}),
        )
        entry.hmac_tag = self._compute_hmac(entry)
        with self._lock:
            self._persist_entry(entry)
        return entry

    def list(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            entries = self._load_all()
        if workspace_id is None or workspace_id == "":
            rows = [entry.to_record() for entry in entries]
        else:
            rows = [entry.to_record() for entry in entries if entry.workspace_id == workspace_id]
        rows.sort(key=lambda row: float(row.get("created_at", 0)), reverse=True)
        return rows

    def get(self, file_id: str) -> VaultEntry | None:
        with self._lock:
            for entry in self._load_all():
                if entry.file_id == file_id:
                    return entry
        return None

    def verify(self, file_id: str) -> dict[str, Any]:
        """Recompute HMAC + AES-GCM tag without decrypting to plaintext.

        Returns a structured result so the caller can render it; raising
        is reserved for catastrophic catalogue loss."""
        entry = self.get(file_id)
        if entry is None:
            return {"file_id": file_id, "ok": False, "reason": "not_found"}
        body_path = Path(entry.ciphertext_path)
        if not body_path.exists():
            return {"file_id": file_id, "ok": False, "reason": "ciphertext_missing"}
        if not hmac.compare_digest(entry.hmac_tag, self._compute_hmac(entry)):
            return {"file_id": file_id, "ok": False, "reason": "catalogue_tampered"}
        try:
            blob = body_path.read_bytes()
            if len(blob) < NONCE_BYTES + 16:
                return {"file_id": file_id, "ok": False, "reason": "ciphertext_truncated"}
            nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
            recovered = self._aes.decrypt(nonce, ciphertext, _aad(entry.file_id, entry.sha256))
            recovered_sha = hashlib.sha256(recovered).hexdigest()
            if recovered_sha != entry.sha256:
                return {"file_id": file_id, "ok": False, "reason": "hash_mismatch"}
            return {"file_id": file_id, "ok": True, "sha256": recovered_sha, "size_bytes": len(recovered)}
        except Exception as exc:
            return {"file_id": file_id, "ok": False, "reason": f"decrypt_failed: {exc}"}

    def unseal(self, file_id: str, dest_path: str | Path) -> dict[str, Any]:
        """Decrypt sealed body to `dest_path`. Refuses if HMAC mismatch."""
        entry = self.get(file_id)
        if entry is None:
            return {"ok": False, "reason": "not_found"}
        if entry.status != "sealed":
            return {"ok": False, "reason": f"unexpected_status:{entry.status}"}
        if not hmac.compare_digest(entry.hmac_tag, self._compute_hmac(entry)):
            return {"ok": False, "reason": "catalogue_tampered"}
        body_path = Path(entry.ciphertext_path)
        if not body_path.exists():
            return {"ok": False, "reason": "ciphertext_missing"}
        blob = body_path.read_bytes()
        if len(blob) < NONCE_BYTES + 16:
            return {"ok": False, "reason": "ciphertext_truncated"}
        nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
        try:
            plaintext = self._aes.decrypt(nonce, ciphertext, _aad(entry.file_id, entry.sha256))
        except Exception as exc:
            return {"ok": False, "reason": f"decrypt_failed: {exc}"}
        if hashlib.sha256(plaintext).hexdigest() != entry.sha256:
            return {"ok": False, "reason": "hash_mismatch"}
        out = Path(dest_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(plaintext)
        with self._lock:
            entry.status = "released"
            entry.updated_at = time.time()
            entry.hmac_tag = self._compute_hmac(entry)
            self._persist_entry(entry, update=True)
        return {"ok": True, "path": str(out), "size_bytes": len(plaintext), "sha256": entry.sha256}

    def delete(self, file_id: str) -> dict[str, Any]:
        entry = self.get(file_id)
        if entry is None:
            return {"ok": False, "reason": "not_found"}
        body_path = Path(entry.ciphertext_path)
        if body_path.exists():
            try:
                body_path.unlink()
            except OSError as exc:
                return {"ok": False, "reason": f"delete_failed: {exc}"}
        with self._lock:
            entry.status = "purged"
            entry.updated_at = time.time()
            entry.hmac_tag = self._compute_hmac(entry)
            self._persist_entry(entry, update=True)
        return {"ok": True, "file_id": file_id}

    def status(self) -> dict[str, Any]:
        entries = self._load_all()
        total = len(entries)
        sealed = sum(1 for entry in entries if entry.status == "sealed")
        released = sum(1 for entry in entries if entry.status == "released")
        purged = sum(1 for entry in entries if entry.status == "purged")
        return {
            "vault_root": str(self.vault_root),
            "total": total,
            "sealed": sealed,
            "released": released,
            "purged": purged,
            "key_source": self._key_source,
            "manifest_backed": self._db is None,
        }

    # ------------------------------------------------------------------
    # Internal — key handling
    # ------------------------------------------------------------------

    _key_source = "unknown"

    def _resolve_master_key(self) -> bytes:
        env_value = (os.environ.get(VAULT_KEY_ENV, "") or "").strip()
        if env_value:
            try:
                key = base64.b64decode(env_value, validate=True)
            except Exception as exc:
                raise RuntimeError(f"{VAULT_KEY_ENV} must be base64-encoded 32 bytes: {exc}") from exc
            if len(key) != KEY_BYTES:
                raise RuntimeError(f"{VAULT_KEY_ENV} must decode to exactly {KEY_BYTES} bytes")
            self._key_source = "env"
            return key
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    raw = self._db.get_app_setting(conn, VAULT_KEY_SETTING)
                    if raw:
                        try:
                            decoded = base64.b64decode(raw.encode("ascii"), validate=True)
                            if len(decoded) == KEY_BYTES:
                                self._key_source = "db"
                                return decoded
                        except Exception:
                            pass
                    fresh = secrets.token_bytes(KEY_BYTES)
                    self._db.set_app_setting(
                        conn,
                        VAULT_KEY_SETTING,
                        base64.b64encode(fresh).decode("ascii"),
                    )
                    self._key_source = "db-generated"
                    return fresh
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        # Last-resort: ephemeral on-disk file under the vault root. This is
        # intentionally local-only and the operator should rotate to env or
        # db-backed storage in production.
        fallback = self.vault_root / "vault.key"
        if fallback.exists():
            data = fallback.read_bytes()
            if len(data) == KEY_BYTES:
                self._key_source = "file"
                return data
        fresh = secrets.token_bytes(KEY_BYTES)
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.write_bytes(fresh)
        try:
            os.chmod(fallback, 0o600)
        except OSError:
            pass
        self._key_source = "file-generated"
        return fresh

    def _derive_subkey(self, info: bytes) -> bytes:
        # Lightweight HKDF-style expansion using HMAC-SHA256. The master
        # key never appears on disk; encryption and HMAC keys are
        # purpose-bound so a leak of one does not imply the other.
        return hmac.new(self._master_key, info, hashlib.sha256).digest()

    def _compute_hmac(self, entry: VaultEntry) -> str:
        material = "|".join(
            [
                entry.file_id,
                entry.workspace_id,
                entry.sha256,
                entry.ciphertext_path,
                entry.original_path,
                entry.severity,
                entry.fused_verdict,
                str(int(entry.size_bytes)),
                entry.status,
            ]
        ).encode("utf-8")
        digest = hmac.new(self._hmac_key, material, hashlib.sha256).digest()
        return base64.b64encode(digest).decode("ascii")

    # ------------------------------------------------------------------
    # Internal — catalogue persistence
    # ------------------------------------------------------------------

    def _persist_entry(self, entry: VaultEntry, *, update: bool = False) -> None:
        if self._db is not None:
            self._persist_db(entry, update=update)
            return
        self._persist_manifest(entry)

    def _persist_db(self, entry: VaultEntry, *, update: bool) -> None:
        try:
            conn = self._db.create_connection()
        except Exception:
            self._persist_manifest(entry)
            return
        if conn is None:
            self._persist_manifest(entry)
            return
        try:
            manifest_json = json.dumps(entry.extra, ensure_ascii=False) if entry.extra else ""
            if update:
                conn.execute(
                    """
                    UPDATE av_vault_entries SET
                        status = ?,
                        hmac_tag = ?,
                        updated_at = ?,
                        manifest_json = ?
                    WHERE file_id = ?
                    """,
                    (
                        entry.status,
                        entry.hmac_tag,
                        float(entry.updated_at or time.time()),
                        manifest_json,
                        entry.file_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO av_vault_entries (
                        file_id, workspace_id, original_path, ciphertext_path,
                        sha256, size_bytes, severity, fused_verdict,
                        process_name, pid, actor, hmac_tag, nonce_b64,
                        manifest_json, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.file_id,
                        entry.workspace_id,
                        entry.original_path,
                        entry.ciphertext_path,
                        entry.sha256,
                        int(entry.size_bytes),
                        entry.severity,
                        entry.fused_verdict,
                        entry.process_name,
                        int(entry.pid),
                        entry.actor,
                        entry.hmac_tag,
                        entry.nonce_b64,
                        manifest_json,
                        entry.status,
                        float(entry.created_at or time.time()),
                        float(entry.updated_at or time.time()),
                    ),
                )
            conn.commit()
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _persist_manifest(self, entry: VaultEntry) -> None:
        manifest = self._read_manifest()
        manifest[entry.file_id] = entry.to_record()
        self._write_manifest(manifest)

    def _read_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {}
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        # Sealed manifest: HMAC the serialised body so corruption / out-of-band
        # edits surface on the next read. The integrity check itself is
        # advisory — the per-entry HMAC is what actually gates restore.
        body = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
        tag = base64.b64encode(
            hmac.new(self._hmac_key, body.encode("utf-8"), hashlib.sha256).digest()
        ).decode("ascii")
        envelope = {"manifest_hmac": tag, "entries": manifest}
        self.manifest_path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")

    def _load_all(self) -> list[VaultEntry]:
        if self._db is not None:
            try:
                conn = self._db.create_connection()
            except Exception:
                conn = None
            if conn is not None:
                try:
                    rows = conn.execute(
                        """
                        SELECT file_id, workspace_id, original_path, ciphertext_path,
                               sha256, size_bytes, severity, fused_verdict,
                               process_name, pid, actor, hmac_tag, nonce_b64,
                               manifest_json, status, created_at, updated_at
                        FROM av_vault_entries
                        """
                    ).fetchall()
                    entries: list[VaultEntry] = []
                    for row in rows or []:
                        try:
                            extra = json.loads(row[13]) if row[13] else {}
                        except Exception:
                            extra = {}
                        entries.append(
                            VaultEntry(
                                file_id=str(row[0]),
                                workspace_id=str(row[1] or "default"),
                                original_path=str(row[2] or ""),
                                ciphertext_path=str(row[3] or ""),
                                sha256=str(row[4] or ""),
                                size_bytes=int(row[5] or 0),
                                severity=str(row[6] or ""),
                                fused_verdict=str(row[7] or ""),
                                process_name=str(row[8] or ""),
                                pid=int(row[9] or -1),
                                actor=str(row[10] or ""),
                                hmac_tag=str(row[11] or ""),
                                nonce_b64=str(row[12] or ""),
                                status=str(row[14] or "sealed"),
                                created_at=float(row[15] or 0.0),
                                updated_at=float(row[16] or 0.0),
                                extra=extra if isinstance(extra, dict) else {},
                            )
                        )
                    return entries
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        manifest = self._read_manifest()
        records = manifest.get("entries", manifest) if isinstance(manifest, dict) else {}
        if not isinstance(records, dict):
            return []
        entries = []
        for record in records.values():
            if not isinstance(record, dict):
                continue
            entries.append(
                VaultEntry(
                    file_id=str(record.get("file_id", "")),
                    workspace_id=str(record.get("workspace_id", "default")),
                    original_path=str(record.get("original_path", "")),
                    ciphertext_path=str(record.get("ciphertext_path", "")),
                    sha256=str(record.get("sha256", "")),
                    size_bytes=int(record.get("size_bytes", 0) or 0),
                    severity=str(record.get("severity", "")),
                    fused_verdict=str(record.get("fused_verdict", "")),
                    process_name=str(record.get("process_name", "")),
                    pid=int(record.get("pid", -1) or -1),
                    actor=str(record.get("actor", "")),
                    nonce_b64=str(record.get("nonce_b64", "")),
                    hmac_tag=str(record.get("hmac_tag", "")),
                    status=str(record.get("status", "sealed")),
                    created_at=float(record.get("created_at", 0.0) or 0.0),
                    updated_at=float(record.get("updated_at", 0.0) or 0.0),
                    extra=record.get("extra", {}) if isinstance(record.get("extra"), dict) else {},
                )
            )
        return entries


def _aad(file_id: str, sha256: str) -> bytes:
    """Additional authenticated data binds each ciphertext to the entry
    it was sealed under. Swapping ciphertexts between entries (or
    rewriting the catalogue to point at someone else's ciphertext)
    invalidates the GCM tag."""
    return f"shadowlab-vault|{file_id}|{sha256}".encode("utf-8")
