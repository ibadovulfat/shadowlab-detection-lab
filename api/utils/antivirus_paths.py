from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException


def allowed_antivirus_scan_roots(base_dir: str | Path) -> list[Path]:
    configured = str(os.environ.get("SHADOWLAB_ANTIVIRUS_SCAN_ROOTS", "") or "").strip()
    roots: list[Path] = []
    if configured:
        for raw in configured.split(","):
            candidate = str(raw or "").strip()
            if not candidate:
                continue
            try:
                resolved = Path(candidate).expanduser().resolve(strict=False)
            except OSError:
                continue
            if resolved not in roots:
                roots.append(resolved)
        return roots

    root = Path(base_dir).resolve()
    defaults = [
        root,
        Path.home().resolve(),
        (root / "shadowlab_out").resolve(),
        (root / "shadowlab_quarantine").resolve(),
    ]
    for item in defaults:
        if item not in roots:
            roots.append(item)
    return roots


def validate_antivirus_scan_target(file_path: str, base_dir: str | Path) -> Path:
    target = Path(file_path or "").expanduser()
    if not str(target).strip():
        raise HTTPException(status_code=422, detail="file_path is required")
    try:
        resolved = target.resolve(strict=False)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid file_path: {exc}") from exc
    allowed_roots = allowed_antivirus_scan_roots(base_dir)
    allowed = any(resolved == root or root in resolved.parents for root in allowed_roots)
    if not allowed:
        allowed_labels = ", ".join(str(root) for root in allowed_roots)
        raise HTTPException(
            status_code=400,
            detail=f"file_path must stay within approved antivirus scan roots: {allowed_labels}",
        )
    return resolved
