"""EICAR-based validation suite for the antivirus pipeline.

The EICAR anti-malware test file is the industry-standard way to
validate that an AV engine is online, sees disk I/O, and is correctly
wired to its signature database — without shipping live malware. Every
commercial AV honours it. ShadowLab uses the exact standard string,
written through a tight context manager so the test sample is deleted
immediately after the scan even if the scan raises.

Public surface:
  * `eicar_bytes()` — returns the canonical 68-byte test string.
  * `run_eicar(service)` — materialises EICAR in a temp directory,
    scans it through every active provider, and returns a structured
    report: which providers flagged it, which missed it, how long each
    took. Passes through the normal `scan_file()` code path, so the
    cache, worker pool, and fusion logic are all exercised.

Failure modes are never silent: if a provider is enabled in the policy
but misses EICAR, it is surfaced as `status: missed` so the operator
gets a visible red light on the provider card.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator


EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def eicar_bytes() -> bytes:
    return EICAR_STRING.encode("ascii")


@contextlib.contextmanager
def materialise_eicar(directory: Path | None = None, *, filename: str = "eicar.com") -> Iterator[Path]:
    """Write EICAR to a temp file and yield its path. The file is
    deleted on exit — even on exception — so a crashed scan never
    leaves a detection bait on disk."""
    if directory is None:
        tmp = Path(tempfile.mkdtemp(prefix="shadowlab-eicar-"))
        cleanup_dir = tmp
    else:
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory
        cleanup_dir = None
    target = tmp / filename
    try:
        target.write_bytes(eicar_bytes())
        yield target
    finally:
        try:
            if target.exists():
                target.unlink()
        except OSError:
            pass
        if cleanup_dir is not None:
            try:
                cleanup_dir.rmdir()
            except OSError:
                pass


def run_eicar(service: Any, *, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a full EICAR validation through the given antivirus service.

    Returns a structured verdict with per-provider pass/miss breakdown,
    duration, and a boolean overall `pass` signal. The service must
    expose `scan_file(path, policy=...)` matching `AntivirusService`.
    """
    started = time.time()
    with materialise_eicar() as eicar_path:
        scan_result = service.scan_file(str(eicar_path), policy=policy)
    duration_ms = int((time.time() - started) * 1000)

    providers = scan_result.get("providers", {}) if isinstance(scan_result.get("providers"), dict) else {}
    provider_rows: list[dict[str, Any]] = []
    caught: list[str] = []
    missed: list[str] = []
    errored: list[str] = []

    for provider_key, result in providers.items():
        if not isinstance(result, dict):
            continue
        status = str(result.get("status", "")).lower()
        engine = str(result.get("engine", provider_key))
        row = {
            "provider_key": provider_key,
            "engine": engine,
            "status": status,
            "malware_name": str(result.get("malware_name", "") or ""),
            "scan_time_ms": int(result.get("scan_time_ms", 0) or 0),
            "error": str(result.get("error", "") or ""),
        }
        if status == "infected":
            caught.append(provider_key)
            row["outcome"] = "caught"
        elif status in {"unavailable", "skipped", "disabled", "error"}:
            errored.append(provider_key)
            row["outcome"] = "errored"
        else:
            missed.append(provider_key)
            row["outcome"] = "missed"
        provider_rows.append(row)

    summary = scan_result.get("summary", {}) if isinstance(scan_result.get("summary"), dict) else {}
    policy_providers = scan_result.get("policy", {}).get("providers", []) if isinstance(scan_result.get("policy"), dict) else []
    expected = [p for p in policy_providers if p not in errored]
    passed = bool(caught) and not any(p for p in expected if p not in caught and p not in errored)

    return {
        "pass": passed,
        "sha256": scan_result.get("sha256", ""),
        "sha256_expected": EICAR_SHA256,
        "hash_match": str(scan_result.get("sha256", "")).lower() == EICAR_SHA256,
        "duration_ms": duration_ms,
        "providers": provider_rows,
        "caught_by": caught,
        "missed_by": missed,
        "errored": errored,
        "fused_verdict": summary.get("fused_verdict", ""),
        "severity": summary.get("severity", ""),
        "score": summary.get("score", 0),
        "confidence": summary.get("confidence", ""),
        "scan": scan_result,
    }
