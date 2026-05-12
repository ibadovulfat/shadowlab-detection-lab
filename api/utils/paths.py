"""Shared path constants and import-root resolution helpers."""
from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent
OUT_DIR = BASE_DIR / "shadowlab_out"
OUT_DIR.mkdir(exist_ok=True, parents=True)
WHIDS_IMPORT_ROOT = OUT_DIR / "whids"
WHIDS_IMPORT_ROOT.mkdir(exist_ok=True, parents=True)
MITRE_IMPORT_ROOT = OUT_DIR / "mitre"
MITRE_IMPORT_ROOT.mkdir(exist_ok=True, parents=True)


def configured_ossec_roots() -> list[Path]:
    configured_home = (os.environ.get("SHADOWLAB_OSSEC_HOME", "") or "").strip()
    candidates = [Path(configured_home).expanduser() if configured_home else None, BASE_DIR.parent / "ossec-hids-main"]
    roots: list[Path] = []
    for candidate in candidates:
        if candidate is None:
            continue
        if candidate not in roots:
            roots.append(candidate)
    return roots


def allowed_integration_import_roots(kind: str) -> list[Path]:
    roots = [OUT_DIR, WHIDS_IMPORT_ROOT]
    if kind == "ossec":
        for ossec_root in configured_ossec_roots():
            roots.append(ossec_root)
            roots.append(ossec_root / "logs")
    elif kind == "mitre":
        roots.append(MITRE_IMPORT_ROOT)
        roots.append(BASE_DIR)
        roots.append(Path.home() / "Downloads")
    deduped: list[Path] = []
    for root in roots:
        if root not in deduped:
            deduped.append(root)
    return deduped


def validate_integration_import_path(value: str, *, kind: str) -> str:
    path = Path(value).expanduser()
    if not str(path).strip():
        raise ValueError("File path is required")
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise ValueError(f"Invalid file path: {exc}") from exc
    for root in allowed_integration_import_roots(kind):
        try:
            resolved_root = root.expanduser().resolve(strict=False)
        except OSError:
            continue
        if resolved == resolved_root or resolved_root in resolved.parents:
            return str(resolved)
    allowed_roots = ", ".join(str(root) for root in allowed_integration_import_roots(kind))
    raise ValueError(f"File path must stay within approved {kind.upper()} import roots: {allowed_roots}")


def workspace_artifact_dir(workspace_id: str) -> Path:
    # Defense in depth: even though every route that owns a workspace
    # context already runs the header through `normalize_workspace_id`,
    # this helper is also called from background workers, retention
    # jobs, and tests where the caller may forward a raw value. Re-
    # validate so a typo like `"../../etc"` can never become a real
    # `mkdir(parents=True)` outside `OUT_DIR`.
    from core.workspace_context import normalize_workspace_id

    raw = str(workspace_id or "").strip().lower()
    if not raw or raw == "default":
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        return OUT_DIR
    # `normalize_workspace_id` raises ValueError on traversal / illegal
    # characters; let the caller turn that into a 400 if it surfaces.
    current = normalize_workspace_id(raw)
    target = (OUT_DIR / "workspaces" / current).resolve()
    out_root = OUT_DIR.resolve()
    # Belt: even with the regex, ensure resolved path stays under OUT_DIR.
    if out_root not in target.parents:
        raise ValueError(f"workspace artifact dir escaped OUT_DIR: {target}")
    target.mkdir(parents=True, exist_ok=True)
    return target
