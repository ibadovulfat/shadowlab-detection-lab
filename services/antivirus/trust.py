from __future__ import annotations

import os
from pathlib import Path


TRUE_VALUES = {"1", "true", "yes", "on"}


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in TRUE_VALUES


def _policy_profile() -> str:
    return str(os.environ.get("SHADOWLAB_POLICY_PROFILE", "lab") or "lab").strip().lower() or "lab"


def strict_binary_trust_enabled() -> bool:
    default = _policy_profile() in {"corp", "prod"}
    return _as_bool(os.environ.get("SHADOWLAB_AV_STRICT_BINARY_TRUST"), default)


def strict_source_trust_enabled() -> bool:
    default = _policy_profile() in {"corp", "prod"}
    return _as_bool(os.environ.get("SHADOWLAB_AV_STRICT_SOURCE_TRUST"), default)


def trusted_binary_roots(base_dir: Path) -> list[Path]:
    configured = str(os.environ.get("SHADOWLAB_AV_TRUSTED_BIN_DIRS", "") or "").strip()
    if configured:
        return _parse_roots(configured)
    roots: list[Path] = [
        (base_dir / "shadowlab_out" / "tools").resolve(),
    ]
    if os.name == "nt":
        roots.extend(
            [
                Path(r"C:\Program Files\ClamAV").resolve(),
                Path(r"C:\Program Files (x86)\ClamAV").resolve(),
            ]
        )
    else:
        roots.extend([Path("/usr/bin").resolve(), Path("/usr/local/bin").resolve()])
    return _dedupe(roots)


def trusted_source_roots(base_dir: Path) -> list[Path]:
    configured = str(os.environ.get("SHADOWLAB_AV_TRUSTED_SOURCE_DIRS", "") or "").strip()
    if configured:
        return _parse_roots(configured)
    roots = [
        (base_dir / "shadowlab_out" / "antivirus").resolve(),
        (Path.home() / "Downloads" / "kicomav-master").resolve(),
    ]
    return _dedupe(roots)


def is_same_or_child(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def is_trusted_path(path: Path, roots: list[Path]) -> bool:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        return False
    return any(is_same_or_child(resolved, root) for root in roots)


def _parse_roots(raw: str) -> list[Path]:
    roots: list[Path] = []
    for chunk in raw.split(","):
        candidate = str(chunk or "").strip()
        if not candidate:
            continue
        try:
            resolved = Path(candidate).expanduser().resolve(strict=False)
        except OSError:
            continue
        roots.append(resolved)
    return _dedupe(roots)


def _dedupe(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    for item in paths:
        if item not in unique:
            unique.append(item)
    return unique
