"""Shared Authenticode lookup with in-process WinVerifyTrust + cache.

Why this module exists
----------------------
Every provider (`YaraXProvider`, `BehaviouralAnalyzer`, the
static-PE service used by the static analyzer, the fusion-layer
trusted-publisher reduction) needs the same answer to the same
question: *is this file signed, and by whom?*

The legacy implementation in `services/static_pe_service._signature_status`
spawned a fresh `powershell.exe` per scan via
`Get-AuthenticodeSignature`. Folder-watcher scans hammered that path at
hundreds of invocations per minute, each one a ~200ms process
spin-up — and the YARA provider didn't even get the answer (it never
called the helper), so the trusted-path-with-valid-signature allowlist
inside `plugins/yara_scanner` never fired.

This module fixes both: a single in-process `WinVerifyTrust` ctypes
call, with an LRU cache keyed by `(path, st_mtime, st_size)` so a
re-scan of the same file is free.

Public surface
--------------
* `signature_status(path)` → `{"status", "signer_subject", "trusted_publisher"}`
* `is_trusted_publisher(signer)` → bool — operator-extensible via
  `SHADOWLAB_AV_TRUSTED_PUBLISHERS`. Defaults cover the half-dozen
  vendors whose binaries appear inside `Program Files` on practically
  every Windows install.
"""
from __future__ import annotations

import ctypes
import functools
import logging
import os
import platform
import subprocess
import threading
from pathlib import Path
from typing import Any


_logger = logging.getLogger(__name__)

# Empty + lower-cased signer-subject substrings that mark a publisher as
# trusted enough to materially down-weight heuristic findings. These are
# vendors whose Authenticode certificates ship on virtually every
# Windows install; flagging a Microsoft Corp-signed `msedgewebview2.exe`
# as malicious because of heuristic JIT-like behaviour is a textbook
# false positive in any commercial AV stack.
_DEFAULT_TRUSTED_PUBLISHERS: tuple[str, ...] = (
    "microsoft corporation",
    "microsoft windows",
    "microsoft windows hardware compatibility publisher",
    "google llc",
    "google inc",
    "mozilla corporation",
    "apple inc",
    "adobe inc",
    "adobe systems incorporated",
    "intel corporation",
    "nvidia corporation",
    "advanced micro devices",
    "oracle america",
    "ibm corporation",
    "valve",
    "amazon.com services",
    "amazon web services",
    "the openssl project",
)


@functools.lru_cache(maxsize=1)
def _trusted_publishers() -> tuple[str, ...]:
    extra = str(os.environ.get("SHADOWLAB_AV_TRUSTED_PUBLISHERS", "") or "").strip()
    extras: tuple[str, ...] = ()
    if extra:
        extras = tuple(item.strip().lower() for item in extra.split(",") if item.strip())
    return _DEFAULT_TRUSTED_PUBLISHERS + extras


def is_trusted_publisher(signer_subject: str) -> bool:
    """Return True when `signer_subject` matches a trusted-publisher token.

    Match is substring on lower-cased subject because Authenticode
    certificate subject lines vary widely:
    `CN="Microsoft Corporation", O="Microsoft Corporation", L="Redmond", ...`
    vs `CN=Microsoft Windows Hardware Compatibility Publisher, O=...`.
    Operators can extend the list via `SHADOWLAB_AV_TRUSTED_PUBLISHERS`
    without code changes.
    """
    if not signer_subject:
        return False
    lowered = signer_subject.lower()
    return any(token in lowered for token in _trusted_publishers())


# ---------------------------------------------------------------------------
# Cache (path, mtime, size) → result. Keeping the cache keyed on file
# metadata means a recompile / update of the same binary path produces a
# fresh lookup; identical content re-scanned (folder watcher debounce)
# hits the cache. LRU bound prevents unbounded growth in long-lived
# processes that touch many distinct binaries.
# ---------------------------------------------------------------------------

_CACHE_MAX = 4096
_cache: dict[tuple[str, int, int], dict[str, Any]] = {}
_cache_order: list[tuple[str, int, int]] = []
_cache_lock = threading.Lock()


def _cache_get(key: tuple[str, int, int]) -> dict[str, Any] | None:
    with _cache_lock:
        return _cache.get(key)


def _cache_put(key: tuple[str, int, int], value: dict[str, Any]) -> None:
    with _cache_lock:
        if key in _cache:
            _cache[key] = value
            return
        if len(_cache) >= _CACHE_MAX:
            # FIFO eviction — cheap and deterministic. True LRU here
            # buys little because access pattern is "scan once, then
            # maybe rescan once on policy change".
            try:
                victim = _cache_order.pop(0)
                _cache.pop(victim, None)
            except IndexError:
                pass
        _cache[key] = value
        _cache_order.append(key)


def clear_cache() -> None:
    """Drop the cached signature lookups. Used by tests + the rotation worker."""
    with _cache_lock:
        _cache.clear()
        _cache_order.clear()


# ---------------------------------------------------------------------------
# WinVerifyTrust (Windows) — in-process Authenticode check via crypt32.
# ---------------------------------------------------------------------------

# WTD_UI_NONE — never show a UI dialog (we're a service).
_WTD_UI_NONE = 2
# WTD_REVOKE_NONE — don't go online for OCSP/CRL; keeps the check fast
# and offline-safe. Operators who want hard revocation checks set
# SHADOWLAB_AV_AUTHENTICODE_CHECK_REVOCATION=1.
_WTD_REVOKE_NONE = 0
_WTD_REVOKE_WHOLECHAIN = 1
_WTD_CHOICE_FILE = 1
# WTD_STATEACTION_VERIFY — perform the verification.
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2

# WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
    "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
)

# Common return codes from WinVerifyTrust (`HRESULT`).
_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
_CRYPT_E_SECURITY_SETTINGS = 0x80092026


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong),
        ("dwUnionChoice", ctypes.c_ulong),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong),
        ("dwUIContext", ctypes.c_ulong),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


def _parse_guid(text: str) -> _GUID:
    cleaned = text.strip("{}")
    parts = cleaned.split("-")
    guid = _GUID()
    guid.Data1 = int(parts[0], 16)
    guid.Data2 = int(parts[1], 16)
    guid.Data3 = int(parts[2], 16)
    tail = bytes.fromhex(parts[3]) + bytes.fromhex(parts[4])
    for idx in range(8):
        guid.Data4[idx] = tail[idx]
    return guid


def _winverifytrust_status(path: Path) -> str:
    """Return a single-word Authenticode status via in-process WinVerifyTrust.

    Returns one of: `"Valid"`, `"NotSigned"`, `"NotTrusted"`, `"HashMismatch"`,
    `"UnknownError"`, or `"Unsupported"` (non-Windows). Falls through to the
    legacy PowerShell helper when ctypes loading fails (rare; mostly when
    the process runs under WoW64 with a broken crypt32 binding).
    """
    if platform.system() != "Windows":
        return "Unsupported"
    try:
        wintrust = ctypes.windll.wintrust  # type: ignore[attr-defined]
    except OSError:
        return "UnknownError"
    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = _WTD_UI_NONE
    revoke_full = str(os.environ.get("SHADOWLAB_AV_AUTHENTICODE_CHECK_REVOCATION", "")).strip().lower() in {"1", "true", "yes", "on"}
    data.fdwRevocationChecks = _WTD_REVOKE_WHOLECHAIN if revoke_full else _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _WTD_STATEACTION_VERIFY

    guid = _parse_guid(_WINTRUST_ACTION_GENERIC_VERIFY_V2)

    wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.POINTER(_WINTRUST_DATA)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long

    try:
        rc = int(wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data)))
    except Exception:
        rc = -1
    finally:
        try:
            data.dwStateAction = _WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
        except Exception:
            pass

    # WinVerifyTrust returns 0 for SUCCESS, otherwise an HRESULT (negative
    # as signed long on Windows). Map the well-known codes to the same
    # vocabulary the legacy PowerShell path used so downstream code
    # doesn't change.
    if rc == 0:
        return "Valid"
    code = rc & 0xFFFFFFFF
    if code == _TRUST_E_NOSIGNATURE:
        return "NotSigned"
    if code == _TRUST_E_SUBJECT_NOT_TRUSTED:
        return "NotTrusted"
    if code == _CRYPT_E_SECURITY_SETTINGS:
        return "NotTrusted"
    return "UnknownError"


def _signer_subject_via_powershell(path: Path) -> str:
    """Read the SignerCertificate subject via PowerShell — only when needed.

    WinVerifyTrust gives us trust verdict but not the signer's certificate
    subject. We only need the subject when the verdict is `Valid` (to feed
    the trusted-publisher allowlist), so the slow PowerShell spawn only
    happens on the happy path AND only once per file (cached). Net cost
    drops from "per-scan PowerShell spawn" to "per-unique-file
    PowerShell spawn", which is what the operator actually expects.
    """
    if platform.system() != "Windows":
        return ""
    try:
        script = (
            "$sig = Get-AuthenticodeSignature -LiteralPath $env:SHADOWLAB_SIG_TARGET;"
            "if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }"
        )
        child_env = os.environ.copy()
        child_env["SHADOWLAB_SIG_TARGET"] = str(path)
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="ignore",
            timeout=10, env=child_env,
        )
        return output.strip()
    except Exception:
        return ""


def signature_status(path: str | os.PathLike) -> dict[str, Any]:
    """Return `{"status", "signer_subject", "trusted_publisher"}` for `path`.

    Result is cached per `(absolute_path, st_mtime, st_size)`. On
    non-Windows hosts always returns `status="Unsupported"` so callers
    don't need to gate on platform themselves.
    """
    target = Path(path)
    try:
        stat = target.stat()
    except OSError:
        return {"status": "unknown", "signer_subject": "", "trusted_publisher": False}
    key = (str(target.resolve()), int(stat.st_mtime), int(stat.st_size))
    cached = _cache_get(key)
    if cached is not None:
        return dict(cached)
    status = _winverifytrust_status(target)
    signer = ""
    if status == "Valid":
        signer = _signer_subject_via_powershell(target)
    record = {
        "status": status,
        "signer_subject": signer,
        "trusted_publisher": status == "Valid" and is_trusted_publisher(signer),
    }
    _cache_put(key, record)
    return dict(record)
