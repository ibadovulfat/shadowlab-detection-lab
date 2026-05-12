"""Filesystem path validators for replay + quarantine flows.

Each helper normalizes the caller-provided path and rejects anything that
steps outside the expected root with a 400 response. Centralizing the logic
keeps route handlers small and prevents subtle traversal mistakes.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException


def _reject_tilde(raw: str) -> None:
    """Reject `~` expansion attempts before they reach `Path`.

    We deliberately do NOT call `Path.expanduser()` in this module:
    `~root/.ssh/id_rsa` and Windows `~/Documents/..` patterns produce a
    user-profile expansion that can shadow validation intent (a path
    looking innocuous on the wire suddenly resolves into an operator
    home dir). The route-level callers always pass absolute paths or
    paths under approved roots; a leading `~` is therefore a bug or an
    attack, not a feature.
    """
    if raw.startswith("~"):
        raise HTTPException(status_code=400, detail="Home-directory expansion is not allowed in this path")


def validate_replay_artifact_path(artifact_path: str, out_dir: Path) -> Path:
    """Return a resolved Path for a replay artifact, rooted under `out_dir`."""
    raw = str(artifact_path or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="artifact_path is required")
    _reject_tilde(raw)
    candidate = Path(raw)
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid artifact path: {exc}") from exc
    allowed_root = out_dir.resolve()
    if allowed_root not in resolved.parents:
        raise HTTPException(status_code=400, detail="Replay artifacts must stay within shadowlab_out")
    if resolved.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Replay artifacts must be JSON files")
    return resolved


def validate_quarantine_file_path(path_value: str, base_dir: Path) -> Path:
    """Return a resolved Path under `<base_dir>/shadowlab_quarantine`."""
    raw = str(path_value or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Quarantine path missing")
    _reject_tilde(raw)
    target = Path(raw)
    resolved = target.resolve(strict=False)
    quarantine_root = (base_dir / "shadowlab_quarantine").resolve()
    if quarantine_root not in resolved.parents:
        raise HTTPException(status_code=400, detail="Invalid quarantine path")
    return resolved


def validate_quarantine_restore_paths(
    quarantine_path: str,
    original_path: str,
    base_dir: Path,
) -> tuple[Path, Path]:
    """Resolve (source, destination) for a quarantine restore operation."""
    source = validate_quarantine_file_path(quarantine_path, base_dir)
    raw_original = str(original_path or "").strip()
    if not raw_original:
        raise HTTPException(status_code=400, detail="Original path missing")
    _reject_tilde(raw_original)
    target = Path(raw_original)
    resolved_target = target.resolve(strict=False)
    if resolved_target == source:
        raise HTTPException(status_code=400, detail="Invalid restore target")
    # Product hardening: only allow quarantine restores into explicitly
    # approved roots. This blocks DB-tampering scenarios from turning restore
    # into arbitrary file write across the host.
    allowed_roots = _allowed_quarantine_restore_roots(base_dir)
    if not any(_is_same_or_child(resolved_target, root) for root in allowed_roots):
        allowed_labels = ", ".join(str(root) for root in allowed_roots)
        raise HTTPException(
            status_code=400,
            detail=f"Restore target must stay within approved roots: {allowed_labels}",
        )
    return source, resolved_target


def _allowed_quarantine_restore_roots(base_dir: Path) -> list[Path]:
    configured = str(os.environ.get("SHADOWLAB_QUARANTINE_RESTORE_ROOTS", "") or "").strip()
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
    # Secure defaults: restore only under ShadowLab workspace and current user
    # profile unless operators explicitly widen this via env configuration.
    defaults = [base_dir.resolve(), Path.home().resolve()]
    for root in defaults:
        if root not in roots:
            roots.append(root)
    return roots


def _is_same_or_child(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents
