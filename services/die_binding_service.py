"""Native Python binding wrapper for Detect It Easy via elastic/die-python.

This service provides a thin, safe wrapper around the ``die`` package
published by Elastic (``pip install die-python``).  It ships with the
complete DiE signature database so no external ``diec.exe`` is required.

When ``die-python`` is not installed, every public method degrades
gracefully instead of raising an import error.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safe import — package is optional
# ---------------------------------------------------------------------------
try:
    import die as _die  # type: ignore[import-untyped]

    _DIE_AVAILABLE = True
except Exception:  # pragma: no cover – import may fail at build-time
    _die = None  # type: ignore[assignment]
    _DIE_AVAILABLE = False


class DieBindingService:
    """Wrapper around ``die.scan_file`` with structured JSON output."""

    # -- availability -------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """Return *True* when the ``die`` native binding is importable."""
        return _DIE_AVAILABLE

    @staticmethod
    def database_path() -> Path | None:
        """Return the bundled signature-database directory, if available."""
        if not _DIE_AVAILABLE:
            return None
        try:
            return Path(_die.database_path)
        except Exception:
            return None

    # -- scanning -----------------------------------------------------------

    def scan_file(self, file_path: str, *, deep: bool = True) -> dict[str, Any]:
        """Scan a single file and return a normalised result dict.

        Returns
        -------
        dict
            Keys: ``status``, ``file_path``, ``filetype``, ``detects``,
            ``raw_json``, ``highlights``.
        """
        target = Path(file_path).expanduser()
        if not target.exists() or not target.is_file():
            return {
                "status": "missing",
                "file_path": str(target),
                "summary": "Target file not found.",
            }

        if not _DIE_AVAILABLE:
            return {
                "status": "unavailable",
                "file_path": str(target),
                "summary": "die-python is not installed.",
            }

        flags = _die.ScanFlags.RESULT_AS_JSON
        if deep:
            flags |= _die.ScanFlags.DEEP_SCAN

        try:
            db = str(self.database_path()) if self.database_path() else None
            if db:
                raw = _die.scan_file(str(target), flags, db)
            else:
                raw = _die.scan_file(str(target), flags)
        except Exception as exc:
            logger.warning("die.scan_file failed: %s", exc)
            return {
                "status": "error",
                "file_path": str(target),
                "summary": f"die.scan_file failed: {exc}",
            }

        return self._parse_result(target, raw)

    # -- internal -----------------------------------------------------------

    def _parse_result(self, target: Path, raw: str) -> dict[str, Any]:
        """Parse the JSON string returned by ``die.scan_file``."""
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            return {
                "status": "ok",
                "file_path": str(target),
                "filetype": "",
                "detects": [],
                "highlights": [],
                "raw_json": raw if isinstance(raw, str) else str(raw),
                "summary": raw[:500] if isinstance(raw, str) else str(raw)[:500],
            }

        # die-python returns: {"detects": [{"filetype": "PE64", "values": [...]}]}
        detects_list: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            detects_list = payload.get("detects", [])
        elif isinstance(payload, list):
            detects_list = payload

        filetype = ""
        highlights: list[dict[str, str]] = []
        all_values: list[dict[str, str]] = []

        for detect_block in detects_list:
            if not isinstance(detect_block, dict):
                continue
            filetype = filetype or detect_block.get("filetype", "")
            for value in detect_block.get("values", []):
                if not isinstance(value, dict):
                    continue
                entry = {
                    "type": str(value.get("type", "")),
                    "name": str(value.get("name", "")),
                    "version": str(value.get("version", "")),
                    "string": str(value.get("string", "")),
                    "info": str(value.get("info", "")),
                }
                all_values.append(entry)
                highlights.append(self._classify_value(entry))

        summary_parts = [f"FileType: {filetype}"] if filetype else []
        for val in all_values[:5]:
            summary_parts.append(val["string"] or f"{val['type']}: {val['name']}")

        return {
            "status": "ok",
            "file_path": str(target),
            "filetype": filetype,
            "detects": all_values,
            "highlights": highlights,
            "raw_json": raw if isinstance(raw, str) else json.dumps(payload),
            "summary": " | ".join(summary_parts) if summary_parts else "No detections.",
        }

    @staticmethod
    def _classify_value(entry: dict[str, str]) -> dict[str, str]:
        """Map a single detection value to the highlight schema used by
        ``MalwareAnalystService``."""
        typ = entry.get("type", "").lower()
        name = entry.get("name", "").lower()
        display = entry.get("string") or f"{entry.get('type', '')}: {entry.get('name', '')}"

        if typ in ("packer", "protector", "cryptor"):
            return {"category": "packing", "text": display}
        if typ in ("compiler", "linker", "tool"):
            return {"category": "toolchain", "text": display}
        if typ in ("library", "runtime", "framework"):
            return {"category": "framework", "text": display}
        if any(token in name for token in ("pe32", "pe64", "elf", "apk", "dex", "mach")):
            return {"category": "format", "text": display}
        if any(token in typ for token in ("overlay", "entropy", "resource", "section")):
            return {"category": "structure", "text": display}
        if typ:
            return {"category": typ, "text": display}
        return {"category": "info", "text": display}
