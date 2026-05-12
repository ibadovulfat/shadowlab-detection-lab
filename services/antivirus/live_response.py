"""Live Response — the EDR action layer.

Verdicts are useless without the ability to *do something*. Real EDR
products (Falcon RTR, SentinelOne Hunter, Defender LiveResponse) wrap a
small set of high-impact host actions behind heavy guard-rails:

  * **kill_process** — stop a running PID. Single most common analyst
    intervention after a confirmed detection.
  * **network_isolate / network_release** — sever the host's network
    plane *except* the management connection. Stops C2 lateral
    movement while preserving the analyst's ability to investigate.
  * **collect_artifacts** — snapshot of process metadata (cmdline,
    parent chain, loaded DLLs, open handles when psutil is available).
    No memory dumping by default — that's too easy a footgun for a lab
    tool to ship to every operator.
  * **vss_list_snapshots / vss_restore_path** — Volume Shadow Copy
    rollback for ransomware-class detections. Windows only; on other
    platforms the calls return a clean `unsupported_platform` reason.

All actions are guarded server-side by `require_admin` +
`ensure_dangerous_actions_enabled` + (for network/VSS) enterprise
approval. The module itself stays platform-aware so it can fail fast
with a useful reason instead of raising on a non-Windows host.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


def _normalize_single_ip(value: str) -> str | None:
    """Return a canonical single IP string, or None if invalid.

    `netsh advfirewall ... remoteip=` and `iptables -d` both accept
    comma-separated values, hostnames, and ranges. We hard-restrict to a
    single literal IPv4/IPv6 address so an admin caller cannot widen the
    "management" allow-list to 0.0.0.0/0.
    """
    candidate = (value or "").strip()
    if not candidate or "," in candidate or "/" in candidate or " " in candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


PROTECTED_PROCESS_NAMES = frozenset({
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "explorer.exe",
    "init", "systemd", "kernel_task", "launchd",
})

ISOLATION_FIREWALL_RULE = "ShadowLab-NetworkIsolation"


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _safe_run(args: list[str], *, timeout: int = 30) -> tuple[int, str, str]:
    """Run a subprocess with bounded timeout, return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, "", f"timeout after {timeout}s: {exc}"
    except FileNotFoundError as exc:
        return 127, "", f"binary not found: {exc}"
    except Exception as exc:
        return 1, "", f"subprocess failure: {exc}"


# ----------------------------------------------------------------- Kill process


def kill_process(pid: int, *, force: bool = False) -> dict[str, Any]:
    """Terminate a PID. Refuses critical-OS process names without an
    explicit `force=True` — catches the obvious `kill 4` / `kill 1` errors."""
    try:
        pid = int(pid)
    except Exception:
        return {"ok": False, "reason": "invalid_pid"}
    if pid <= 0:
        return {"ok": False, "reason": "invalid_pid"}

    name = ""
    try:
        import psutil  # local import: psutil is optional
        proc = psutil.Process(pid)
        name = (proc.name() or "").lower()
        if not force and name in PROTECTED_PROCESS_NAMES:
            return {"ok": False, "reason": "protected_process", "process_name": name}
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
        return {"ok": True, "pid": pid, "process_name": name, "method": "psutil"}
    except ImportError:
        # Fallback to os.kill — no protection check possible without psutil.
        try:
            import signal
            os.kill(pid, signal.SIGTERM if hasattr(signal, "SIGTERM") else 15)
            return {"ok": True, "pid": pid, "method": "os.kill"}
        except ProcessLookupError:
            return {"ok": False, "reason": "no_such_process"}
        except PermissionError:
            return {"ok": False, "reason": "permission_denied"}
        except Exception as exc:
            return {"ok": False, "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001
        # psutil raises typed exceptions; the class name carries the
        # diagnostic, str(exc) gives only the human-readable detail.
        type_name = type(exc).__name__
        msg = str(exc)
        if type_name == "NoSuchProcess" or "NoSuchProcess" in msg or "PID not found" in msg:
            return {"ok": False, "reason": "no_such_process"}
        if type_name == "AccessDenied" or "AccessDenied" in msg or "Access is denied" in msg:
            return {"ok": False, "reason": "permission_denied"}
        return {"ok": False, "reason": msg}


# --------------------------------------------------------------- Network isolation


def network_isolate(*, allow_management_ip: str = "127.0.0.1") -> dict[str, Any]:
    """Block all outbound traffic except to `allow_management_ip`.

    Windows: adds two `netsh advfirewall firewall add rule` entries — a
    block-all rule and an allow-management exception. Linux: best-effort
    iptables rule. macOS / unknown: returns `unsupported_platform`.

    The block is reversible via `network_release()`. Admin + dangerous
    + enterprise approval are enforced at the API layer."""
    safe_mgmt_ip = _normalize_single_ip(allow_management_ip)
    if safe_mgmt_ip is None:
        return {"ok": False, "reason": "invalid_management_ip"}
    if _is_windows():
        # Block everything outbound first.
        rc1, out1, err1 = _safe_run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ISOLATION_FIREWALL_RULE}",
            "dir=out", "action=block", "protocol=any", "enable=yes",
        ])
        # Then allow management plane.
        rc2, out2, err2 = _safe_run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ISOLATION_FIREWALL_RULE}-allow",
            "dir=out", "action=allow", "protocol=any",
            f"remoteip={safe_mgmt_ip}", "enable=yes",
        ])
        if rc1 != 0 or rc2 != 0:
            return {
                "ok": False,
                "reason": "netsh_failed",
                "block_rc": rc1, "block_err": err1[:240],
                "allow_rc": rc2, "allow_err": err2[:240],
            }
        return {
            "ok": True, "platform": "windows",
            "rule_name": ISOLATION_FIREWALL_RULE,
            "management_allowed": safe_mgmt_ip,
            "isolated_at": time.time(),
        }
    if platform.system().lower() == "linux" and shutil.which("iptables"):
        rc1, _o, e1 = _safe_run(["iptables", "-A", "OUTPUT", "-d", safe_mgmt_ip, "-j", "ACCEPT"])
        rc2, _o, e2 = _safe_run(["iptables", "-A", "OUTPUT", "-j", "DROP"])
        if rc1 != 0 or rc2 != 0:
            return {"ok": False, "reason": "iptables_failed", "stderr": (e1 + e2)[:480]}
        return {"ok": True, "platform": "linux", "isolated_at": time.time()}
    return {"ok": False, "reason": "unsupported_platform", "platform": platform.system()}


def network_release() -> dict[str, Any]:
    """Undo the rule(s) installed by `network_isolate()`."""
    if _is_windows():
        rc1, _o1, e1 = _safe_run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={ISOLATION_FIREWALL_RULE}",
        ])
        rc2, _o2, e2 = _safe_run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={ISOLATION_FIREWALL_RULE}-allow",
        ])
        return {
            "ok": rc1 == 0 and rc2 == 0,
            "platform": "windows",
            "block_rc": rc1, "allow_rc": rc2,
            "stderr": (e1 + e2)[:480],
        }
    if platform.system().lower() == "linux" and shutil.which("iptables"):
        # Best effort — iptables -F OUTPUT wipes everything in the chain
        # which is too aggressive. We try targeted deletes.
        rc, _o, err = _safe_run(["iptables", "-D", "OUTPUT", "-j", "DROP"])
        return {"ok": rc == 0, "platform": "linux", "stderr": err[:480]}
    return {"ok": False, "reason": "unsupported_platform"}


# --------------------------------------------------------------- Artifact collection


def collect_artifacts(pid: int) -> dict[str, Any]:
    """Capture a forensically-useful metadata snapshot for `pid`.

    No memory dump by default — analysts who need that should pivot to
    a dedicated DFIR tool. We capture what's safe and synchronous:
    cmdline, exe path, parent chain, open file handles (limited),
    network connections, environ keys."""
    try:
        pid = int(pid)
    except Exception:
        return {"ok": False, "reason": "invalid_pid"}
    try:
        import psutil
    except ImportError:
        return {"ok": False, "reason": "psutil_not_available"}
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"ok": False, "reason": "no_such_process"}
    snap: dict[str, Any] = {
        "ok": True,
        "pid": pid,
        "captured_at": time.time(),
        "process": {
            "name": _safe_attr(proc.name),
            "exe": _safe_attr(proc.exe),
            "cmdline": _safe_attr(proc.cmdline),
            "create_time": _safe_attr(proc.create_time),
            "username": _safe_attr(proc.username),
            "status": _safe_attr(proc.status),
            "cwd": _safe_attr(proc.cwd),
        },
        "parent_chain": _parent_chain(proc),
        "children": _children(proc),
        "open_files": _open_files(proc),
        "connections": _connections(proc),
        "env_keys": _env_keys(proc),
    }
    return snap


def _safe_attr(callable_obj):
    try:
        result = callable_obj()
        if isinstance(result, list):
            return [str(x) for x in result]
        return result
    except Exception:
        return None


def _parent_chain(proc) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    try:
        current = proc
        for _ in range(8):  # cap depth
            parent = current.parent()
            if parent is None:
                break
            chain.append({
                "pid": parent.pid,
                "name": _safe_attr(parent.name),
                "cmdline": _safe_attr(parent.cmdline),
            })
            current = parent
    except Exception:
        pass
    return chain


def _children(proc) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for child in proc.children(recursive=False)[:30]:
            out.append({
                "pid": child.pid,
                "name": _safe_attr(child.name),
                "cmdline": _safe_attr(child.cmdline),
            })
    except Exception:
        pass
    return out


def _open_files(proc) -> list[str]:
    try:
        return [str(item.path) for item in proc.open_files()[:20]]
    except Exception:
        return []


def _connections(proc) -> list[dict[str, Any]]:
    try:
        out: list[dict[str, Any]] = []
        for conn in proc.connections(kind="inet")[:25]:
            out.append({
                "fd": getattr(conn, "fd", -1),
                "family": str(getattr(conn, "family", "")),
                "type": str(getattr(conn, "type", "")),
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                "status": str(conn.status),
            })
        return out
    except Exception:
        return []


def _env_keys(proc) -> list[str]:
    try:
        env = proc.environ()
        return sorted(env.keys())[:60] if isinstance(env, dict) else []
    except Exception:
        return []


# --------------------------------------------------------------- VSS rollback


def vss_list_snapshots() -> dict[str, Any]:
    """Enumerate Volume Shadow Copy snapshots. Windows-only."""
    if not _is_windows():
        return {"ok": False, "reason": "unsupported_platform"}
    rc, out, err = _safe_run(["vssadmin", "list", "shadows"], timeout=15)
    if rc != 0:
        return {"ok": False, "reason": "vssadmin_failed", "rc": rc, "stderr": err[:480]}
    snapshots: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Contents of shadow copy set ID:"):
            current = {"set_id": line.split(":", 1)[1].strip()}
        elif line.startswith("Contained 1 shadow copies at creation time:"):
            if current is not None:
                current["created_at"] = line.split("time:", 1)[1].strip()
        elif line.startswith("Shadow Copy ID:") and current is not None:
            current["shadow_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Original Volume:") and current is not None:
            current["original_volume"] = line.split(":", 1)[1].strip()
        elif line.startswith("Shadow Copy Volume:") and current is not None:
            current["shadow_volume"] = line.split(":", 1)[1].strip()
            snapshots.append(current)
            current = None
    return {"ok": True, "count": len(snapshots), "snapshots": snapshots}


_VSS_SHADOW_VOLUME_RE = None  # built lazily; pattern: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyNN


def _validate_vss_shadow_volume(value: str) -> bool:
    r"""Only accept the canonical GLOBALROOT shadow-copy device paths.

    Listing comes from `vssadmin list shadows` and always emits the same
    `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>` form. Anything else
    (UNC paths, drive letters, relative pieces) is rejected so an admin
    caller cannot redirect the read to an arbitrary location.
    """
    import re
    global _VSS_SHADOW_VOLUME_RE
    if _VSS_SHADOW_VOLUME_RE is None:
        _VSS_SHADOW_VOLUME_RE = re.compile(
            r"^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+\\?$",
            re.IGNORECASE,
        )
    return bool(_VSS_SHADOW_VOLUME_RE.fullmatch(value or ""))


def _allowed_vss_restore_roots() -> list[Path]:
    """Roots an analyst is permitted to copy snapshot files into.

    Default whitelist is `<repo>/shadowlab_out/vss_restore` plus the
    current user's home. Operators can widen via
    `SHADOWLAB_VSS_RESTORE_ROOTS` (comma-separated absolute paths).
    """
    base_dir = Path(__file__).resolve().parents[2]
    configured = (os.environ.get("SHADOWLAB_VSS_RESTORE_ROOTS", "") or "").strip()
    roots: list[Path] = []
    if configured:
        for raw in configured.split(","):
            candidate = raw.strip()
            if not candidate:
                continue
            try:
                resolved = Path(candidate).expanduser().resolve(strict=False)
            except OSError:
                continue
            if resolved not in roots:
                roots.append(resolved)
        return roots
    defaults = [
        (base_dir / "shadowlab_out" / "vss_restore").resolve(),
        Path.home().resolve(),
    ]
    for root in defaults:
        if root not in roots:
            roots.append(root)
    return roots


def _is_safe_relative_segment(value: str) -> bool:
    """Reject absolute paths, drive letters, `..` traversal, or NUL bytes."""
    candidate = (value or "").strip()
    if not candidate:
        return False
    if "\x00" in candidate:
        return False
    normalized = candidate.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return False
    # Reject drive-letter or device prefixes (`C:`, `\\?\`, `\\.\`).
    if len(candidate) >= 2 and candidate[1] == ":":
        return False
    if candidate.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        return False
    for part in normalized.split("/"):
        if part in {"", ".", ".."}:
            return False
    return True


def vss_restore_path(*, shadow_volume: str, relative_path: str, destination_path: str) -> dict[str, Any]:
    """Copy a single file out of a VSS snapshot to a destination on disk.

    `shadow_volume` is the `\\\\?\\GLOBALROOT\\...` path returned by
    `vss_list_snapshots()`. `relative_path` is the file's path inside
    that volume (`Users/Foo/Documents/important.docx`). `destination_path`
    must resolve within an allow-listed root so an admin caller cannot
    overwrite arbitrary files on the host (Windows startup hooks,
    System32, etc.) even with enterprise approval.
    """
    if not _is_windows():
        return {"ok": False, "reason": "unsupported_platform"}
    if not shadow_volume or not relative_path or not destination_path:
        return {"ok": False, "reason": "missing_arguments"}
    if not _validate_vss_shadow_volume(shadow_volume):
        return {"ok": False, "reason": "invalid_shadow_volume"}
    if not _is_safe_relative_segment(relative_path):
        return {"ok": False, "reason": "invalid_relative_path"}

    source = Path(shadow_volume.rstrip("\\")) / relative_path.lstrip("\\/").replace("\\", "/")
    try:
        dest = Path(destination_path).expanduser().resolve(strict=False)
    except OSError as exc:
        return {"ok": False, "reason": f"invalid_destination: {exc}"}

    allowed_roots = _allowed_vss_restore_roots()
    if not any(dest == root or root in dest.parents for root in allowed_roots):
        return {
            "ok": False,
            "reason": "destination_outside_allowed_roots",
            "allowed_roots": [str(root) for root in allowed_roots],
        }

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return {"ok": False, "reason": f"destination_mkdir_failed: {exc}"}
    try:
        shutil.copy2(str(source), str(dest))
    except FileNotFoundError:
        return {"ok": False, "reason": "source_not_in_snapshot", "source": str(source)}
    except PermissionError as exc:
        return {"ok": False, "reason": f"permission_denied: {exc}"}
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}
    return {
        "ok": True,
        "source": str(source),
        "destination": str(dest),
        "bytes_written": dest.stat().st_size if dest.exists() else 0,
        "restored_at": time.time(),
    }
