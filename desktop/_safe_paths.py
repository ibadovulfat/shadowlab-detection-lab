"""Defense-in-depth path validation for server-supplied filesystem paths.

The desktop client opens / deletes / hashes files whose paths arrive in
server JSON (artifacts, quarantine, integration exports). A compromised
or MitM'd backend could therefore return absolute paths like
``C:\\Windows\\System32\\drivers\\etc\\hosts`` or
``\\\\evil-share\\payload.lnk`` and ride the desktop's filesystem
permissions to read, delete, or shell-launch arbitrary files.

This module provides ``ensure_under_artifact_root`` — a single chokepoint
every desktop open/delete/read call MUST funnel through. Paths that do
not resolve under the configured artifact root (``shadowlab_out/``,
``shadowlab_quarantine/``, or an explicit override via
``SHADOWLAB_ARTIFACT_ROOTS``) are rejected with a typed
``UnsafeArtifactPath`` exception, which call sites surface via the
status bar instead of falling through to ``QDesktopServices.openUrl``
or ``Path.unlink``.

The realpath check is symmetric on both ends to defeat junction /
symlink swaps inside the artifact root. Executable suffixes are
rejected from the shell-open helper because the quarantine vault by
definition stores known-bad binaries; opening them with the OS shell
handler would detonate the malware on the analyst host.
"""
from __future__ import annotations

import os
from pathlib import Path


# Executable / scriptable suffixes that are NEVER safe to hand to the
# OS shell handler, regardless of which root they live under. The
# quarantine vault is the obvious case — it holds malware on purpose —
# but the same list also blocks an attacker from staging a `.lnk` or
# `.scr` inside `shadowlab_out/` and tricking the operator into
# detonating it through the artifact pane.
_BLOCKED_SHELL_SUFFIXES = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl",
    ".msi", ".msp", ".mst", ".jar",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".lnk", ".url", ".reg",
    ".sh", ".bash", ".zsh", ".py", ".pyw", ".rb", ".pl",
})


class UnsafeArtifactPath(ValueError):
    """Raised when a server-supplied path tries to escape the artifact root."""


def _base_dir() -> Path:
    """Repo root for the running desktop (one level above ``desktop/``)."""
    return Path(__file__).resolve().parent.parent


def configured_artifact_roots() -> list[Path]:
    """Return the set of directories that may legitimately host artifacts.

    Always includes ``<repo>/shadowlab_out`` and
    ``<repo>/shadowlab_quarantine``. Operators running the desktop in a
    detached install (frozen exe, network-shared workspace) can extend
    the list via ``SHADOWLAB_ARTIFACT_ROOTS`` (OS path-separator
    delimited list of absolute paths). Empty / unresolvable entries are
    silently dropped so a typo in the env var does NOT widen the
    allow-list to ``/`` or similar.
    """
    base = _base_dir()
    roots: list[Path] = []
    for default in (base / "shadowlab_out", base / "shadowlab_quarantine"):
        try:
            roots.append(default.resolve(strict=False))
        except OSError:
            continue
    extra_raw = (os.environ.get("SHADOWLAB_ARTIFACT_ROOTS", "") or "").strip()
    if extra_raw:
        for chunk in extra_raw.split(os.pathsep):
            candidate = chunk.strip()
            if not candidate:
                continue
            try:
                resolved = Path(candidate).expanduser().resolve(strict=False)
            except OSError:
                continue
            if resolved not in roots and str(resolved).strip() not in ("", "/", "\\"):
                roots.append(resolved)
    return roots


def ensure_under_artifact_root(
    candidate: str | os.PathLike[str],
    *,
    allow_shell_open: bool = False,
) -> Path:
    """Resolve ``candidate`` and require it to live under an artifact root.

    Returns the realpath'd Path on success. Raises ``UnsafeArtifactPath``
    when the candidate is empty, contains a NUL/control byte, escapes
    every configured root, or — when ``allow_shell_open=True`` — has a
    suffix in the executable / scripting deny-list.

    Symlinks are resolved on both the candidate and the configured
    roots so an attacker who plants a junction inside the artifact root
    pointing to ``C:\\Windows\\`` is still blocked.
    """
    raw = str(candidate or "").strip()
    if not raw:
        raise UnsafeArtifactPath("empty path")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in raw):
        raise UnsafeArtifactPath("path contains control characters")
    # Reject UNC paths up front — even when they happen to resolve under
    # an artifact root, opening or deleting via UNC routes through the
    # SMB redirector, which is a credentials-leak surface.
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise UnsafeArtifactPath("UNC paths are not permitted")
    try:
        target = Path(os.path.realpath(raw))
    except OSError as exc:
        raise UnsafeArtifactPath(f"unresolvable path: {exc}") from exc
    roots = configured_artifact_roots()
    if not roots:
        raise UnsafeArtifactPath("no artifact roots are configured")
    inside = False
    for root in roots:
        try:
            target.relative_to(root)
        except ValueError:
            continue
        inside = True
        break
    if not inside:
        roots_repr = ", ".join(str(r) for r in roots)
        raise UnsafeArtifactPath(
            f"path is outside the configured artifact roots ({roots_repr}): {target}"
        )
    if allow_shell_open and target.suffix.lower() in _BLOCKED_SHELL_SUFFIXES:
        raise UnsafeArtifactPath(
            f"refusing to shell-open executable/script artifact: {target.suffix}"
        )
    return target
