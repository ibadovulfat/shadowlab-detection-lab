"""Operator-authored YARA rule store.

The vendor-shipped YARA pack tree (`enterprise`, `signature_base`, etc.)
is great for known-bad coverage, but every analyst eventually needs to
write a one-off rule for an in-flight investigation: "match the
specific PowerShell encoded blob this campaign is using". Until now
ShadowLab had no surface for that — the operator had to drop a `.yar`
file into `plugins/yara_packs/` by hand and restart the engine.

This module fixes that with a tight CRUD surface:
  * **list_rules** — every rule the operator has saved, plus
    compile-success status and last-modified timestamp.
  * **save_rule(name, source)** — validate via `yara.compile(source=...)`
    and persist to `<base_dir>/shadowlab_out/yara/custom/<name>.yar`.
    Compile failures return the YARA error verbatim so the analyst can
    fix syntax inline.
  * **delete_rule(name)** — remove the file.
  * **dry_run(name, sample_path)** — compile the rule + scan a single
    target. Returns matches or "no match" without polluting the global
    pack scan path.

Rules saved here are loaded by `plugins.yara_scanner` on its next pack
discovery (the scanner walks a configured directory list — we just
write into one of those directories). The desktop's "Rules" drawer
talks to this module via the API routes in `api/routes/antivirus.py`.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any


_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class CustomYaraStore:
    """File-backed CRUD over operator-authored YARA rules."""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.rules_dir = self.base_dir / "shadowlab_out" / "yara" / "custom"
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ list

    def list_rules(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for path in sorted(self.rules_dir.glob("*.yar")):
            try:
                stat = path.stat()
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            valid, error = self._compile_check(source)
            out.append({
                "name": path.stem,
                "path": str(path),
                "size_bytes": int(stat.st_size),
                "last_modified": float(stat.st_mtime),
                "valid": valid,
                "error": error,
                "rule_count": source.lower().count("rule "),
            })
        return out

    # ------------------------------------------------------------------ get

    def get_rule(self, name: str) -> dict[str, Any] | None:
        path = self._path_for(name)
        if path is None or not path.exists():
            return None
        try:
            source = path.read_text(encoding="utf-8")
            stat = path.stat()
        except OSError as exc:
            return {"name": name, "error": f"read_failed: {exc}"}
        valid, error = self._compile_check(source)
        return {
            "name": name,
            "path": str(path),
            "source": source,
            "size_bytes": int(stat.st_size),
            "last_modified": float(stat.st_mtime),
            "valid": valid,
            "error": error,
        }

    # ------------------------------------------------------------------ save

    def save_rule(self, name: str, source: str) -> dict[str, Any]:
        path = self._path_for(name)
        if path is None:
            return {"ok": False, "reason": "invalid_name"}
        cleaned = (source or "").strip()
        if not cleaned:
            return {"ok": False, "reason": "empty_source"}
        valid, error = self._compile_check(cleaned)
        if not valid:
            return {"ok": False, "reason": "compile_error", "error": error}
        try:
            path.write_text(cleaned, encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "reason": f"write_failed: {exc}"}
        return {
            "ok": True,
            "name": name,
            "path": str(path),
            "saved_at": time.time(),
            "rule_count": cleaned.lower().count("rule "),
        }

    # ------------------------------------------------------------------ delete

    def delete_rule(self, name: str) -> dict[str, Any]:
        path = self._path_for(name)
        if path is None:
            return {"ok": False, "reason": "invalid_name"}
        if not path.exists():
            return {"ok": False, "reason": "not_found"}
        try:
            path.unlink()
        except OSError as exc:
            return {"ok": False, "reason": f"delete_failed: {exc}"}
        return {"ok": True, "name": name, "deleted_at": time.time()}

    # ------------------------------------------------------------------ dry-run

    def dry_run(self, name: str, sample_path: str) -> dict[str, Any]:
        """Compile + scan a single file. Used by the `Test rule` button."""
        path = self._path_for(name)
        if path is None or not path.exists():
            return {"ok": False, "reason": "rule_not_found"}
        target = Path(sample_path).expanduser()
        if not target.exists() or not target.is_file():
            return {"ok": False, "reason": "sample_not_found", "path": str(target)}
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            return {"ok": False, "reason": "yara_python_not_available"}
        try:
            source = path.read_text(encoding="utf-8")
            rules = yara.compile(source=source)
        except Exception as exc:
            return {"ok": False, "reason": "compile_error", "error": str(exc)}
        try:
            started = time.time()
            matches = rules.match(str(target), timeout=30)
            elapsed_ms = int((time.time() - started) * 1000)
        except Exception as exc:
            return {"ok": False, "reason": "scan_error", "error": str(exc)}
        match_rows = []
        for m in matches:
            try:
                match_rows.append({
                    "rule": str(getattr(m, "rule", "")),
                    "namespace": str(getattr(m, "namespace", "default")),
                    "tags": list(getattr(m, "tags", []) or []),
                    "meta": {str(k): str(v) for k, v in (getattr(m, "meta", {}) or {}).items()},
                    "string_count": len(getattr(m, "strings", []) or []),
                })
            except Exception:
                continue
        return {
            "ok": True,
            "name": name,
            "sample": str(target),
            "match_count": len(match_rows),
            "matches": match_rows,
            "elapsed_ms": elapsed_ms,
        }

    # ------------------------------------------------------------------ helpers

    def _path_for(self, name: str) -> Path | None:
        canonical = (name or "").strip()
        if not _NAME_PATTERN.match(canonical):
            return None
        return self.rules_dir / f"{canonical}.yar"

    @staticmethod
    def _compile_check(source: str) -> tuple[bool, str]:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            return True, "yara-python not installed; rules saved unchecked"
        try:
            yara.compile(source=source)
            return True, ""
        except Exception as exc:
            return False, str(exc)
