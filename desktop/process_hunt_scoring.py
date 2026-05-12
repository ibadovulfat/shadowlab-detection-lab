"""Risk scoring + risk-policy cache for the Process Hunt console.

Split out of `process_hunt_ops.py` so the math can be tested without Qt
and so the policy file is read at most once per change instead of once
per process row on every refresh.
"""
from __future__ import annotations

import ipaddress
import json
import math
import time
from pathlib import Path
from typing import Callable

DEFAULT_KNOWN_GOOD_WINDOWS = (
    "system idle process", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "explorer.exe", "sihost.exe", "taskhostw.exe",
    "spoolsv.exe", "audiodg.exe", "searchindexer.exe", "runtimebroker.exe", "wudfhost.exe",
)

DEFAULT_WEIGHTS = {
    "known_good_discount": -10,
    "shallow_signature": 6,
    "bad_signature": 25,
    "missing_exe": 18,
    "user_writable_path": 22,
    "system_name_wrong_path": 35,
    "lolbin": 18,
    "office_parent": 22,
    "browser_anomaly": 18,
    "suspicious_chain": 16,
    "recent_spawn": 10,
    "suspicious_command": 20,
    "high_entropy_command": 10,
    "high_cpu": 12,
    "medium_cpu": 7,
    "high_memory": 10,
    "missing_hash": 8,
    "network_connection_cap": 15,
    "network_connection_each": 3,
    "public_egress": 15,
}

PROTECTED_PROCESS_NAMES = frozenset({
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
})

LOLBINS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "installutil.exe",
})

OFFICE_PARENTS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"})

SYSTEM_PROCESS_NAMES = frozenset({"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe"})

USER_WRITABLE_ROOTS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\", "\\programdata\\")

SUSPICIOUS_COMMAND_TERMS = (
    "powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32", "mshta",
    "encodedcommand", "downloadstring", "invoke-", "frombase64string", "http://", "https://",
)


def default_policy() -> dict:
    return {
        "known_good_windows": list(DEFAULT_KNOWN_GOOD_WINDOWS),
        "suppressions": [],
        "weights": dict(DEFAULT_WEIGHTS),
    }


class RiskPolicyCache:
    """Lazy mtime-based cache around the on-disk risk policy.

    The previous implementation read + parsed the JSON on every call to
    `risk_weight`, which fires once per signal per process row. On a
    400-row refresh that's ~6000 disk reads. This cache reads the file
    only when its mtime advances.
    """

    def __init__(self, path_provider: Callable[[], Path]) -> None:
        self._path_provider = path_provider
        self._policy: dict = default_policy()
        self._loaded_path: Path | None = None
        self._loaded_mtime: float = -1.0

    def get(self) -> dict:
        try:
            path = self._path_provider()
        except Exception:
            return self._policy
        try:
            stat = path.stat() if path.exists() else None
        except Exception:
            stat = None
        if stat is None:
            if self._loaded_path != path:
                self._policy = default_policy()
                self._loaded_path = path
                self._loaded_mtime = -1.0
            return self._policy
        mtime = float(stat.st_mtime)
        if path == self._loaded_path and mtime == self._loaded_mtime:
            return self._policy
        merged = default_policy()
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            loaded = None
        if isinstance(loaded, dict):
            if isinstance(loaded.get("known_good_windows"), list):
                merged["known_good_windows"] = list(loaded["known_good_windows"])
            if isinstance(loaded.get("suppressions"), list):
                merged["suppressions"] = list(loaded["suppressions"])
            if isinstance(loaded.get("weights"), dict):
                merged["weights"].update(loaded["weights"])
        self._policy = merged
        self._loaded_path = path
        self._loaded_mtime = mtime
        return self._policy

    def weight(self, name: str) -> int:
        try:
            return int((self.get().get("weights") or {}).get(name, 0))
        except Exception:
            return 0

    def invalidate(self) -> None:
        self._loaded_path = None
        self._loaded_mtime = -1.0


def is_protected_process(name: str) -> bool:
    return (name or "").strip().lower() in PROTECTED_PROCESS_NAMES


def command_entropy(value: str) -> float:
    text = value or ""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_public_network_destination(value: str) -> bool:
    for token in (value or "").replace("->", " ").replace(":", " ").split():
        try:
            ip = ipaddress.ip_address(token.strip("[]"))
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved):
            return True
    return False


def risk_pill_text(label: str, score) -> str:
    icons = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
    return f"{icons.get((label or '').lower(), (label or '').upper())} {score}"


def state_pill_text(state: str) -> str:
    return f"[{(state or '').upper()}]"


def signature_pill_text(signature: str) -> str:
    value = (signature or "unknown").lower()
    if value == "valid":
        return "TRUSTED"
    if value in {"unsigned", "invalid"}:
        return value.upper()
    return "UNKNOWN"


def score_process(process: dict, *, policy: dict | None = None, weight_fn: Callable[[str], int] | None = None) -> tuple[int, str, list[str]]:
    """Pure scoring function.

    Pass either an already-loaded `policy` dict OR a `weight_fn` lookup.
    The two-shape input lets the controller hand in a `RiskPolicyCache`
    bound method directly to skip an extra dict copy.
    """
    if weight_fn is None:
        cfg = policy if isinstance(policy, dict) else default_policy()
        weights = cfg.get("weights", {}) if isinstance(cfg.get("weights"), dict) else {}

        def weight_fn(name: str) -> int:  # noqa: F811 - local override
            try:
                return int(weights.get(name, 0))
            except Exception:
                return 0
    cfg = policy if isinstance(policy, dict) else default_policy()
    score = 0
    reasons: list[str] = []
    name = str(process.get("name", "") or "").lower()
    exe = str(process.get("exe", "") or "")
    cmdline = process.get("cmdline", "")
    cmdline_text = " ".join(str(part) for part in cmdline) if isinstance(cmdline, list) else str(cmdline or "")
    cmd_lower = cmdline_text.lower()
    sig = str(process.get("signature_status", "") or "unknown").lower()
    try:
        cpu = float(process.get("cpu_percent", 0) or 0)
    except Exception:
        cpu = 0.0
    try:
        mem = float(process.get("memory_percent", 0) or 0)
    except Exception:
        mem = 0.0
    known_good_windows = {str(item).lower() for item in cfg.get("known_good_windows", [])}
    suppressions = {str(item).lower() for item in cfg.get("suppressions", [])}
    parent_name = str(process.get("parent_name", "") or "").lower()
    create_time = process.get("create_time")
    execution_context = process.get("execution_context") if isinstance(process.get("execution_context"), dict) else {}
    shallow_signature = "signature_status" not in process and "signature" not in process
    exe_lower_norm = exe.lower().replace("/", "\\")
    known_good_baseline = name in known_good_windows and (
        not exe or "\\windows\\" in exe_lower_norm or name in {"system idle process", "system", "registry"}
    )
    if name in suppressions:
        score += weight_fn("known_good_discount")
        reasons.append("local risk policy suppression lowers priority")
    if known_good_baseline and sig in {"valid", "unknown", "n/a"}:
        score += weight_fn("known_good_discount")
        reasons.append("known-good Windows process baseline lowers priority")
    if sig in {"unsigned", "unknown", "invalid", "n/a", "none", ""} and not known_good_baseline:
        if shallow_signature:
            score += weight_fn("shallow_signature")
            reasons.append("signature trust has not been collected for this row")
        else:
            score += weight_fn("bad_signature")
            reasons.append("signature is missing, unknown, or not trusted")
    elif sig in {"unsigned", "invalid"}:
        score += weight_fn("bad_signature")
        reasons.append("signature is not trusted")
    if not exe:
        score += weight_fn("missing_exe")
        reasons.append("executable path is unavailable")
    else:
        if any(part in exe_lower_norm for part in USER_WRITABLE_ROOTS):
            score += weight_fn("user_writable_path")
            reasons.append("process is running from a user-writable or staging path")
        if name in SYSTEM_PROCESS_NAMES and "\\windows\\system32\\" not in exe_lower_norm:
            score += weight_fn("system_name_wrong_path")
            reasons.append("system process name is not running from System32")
    if execution_context.get("lolbin") or name in LOLBINS:
        score += weight_fn("lolbin")
        reasons.append("LOLBin or proxy-execution binary baseline match")
    if execution_context.get("office_parent") or parent_name in OFFICE_PARENTS:
        score += weight_fn("office_parent")
        reasons.append("Office parent-child execution anomaly")
    if execution_context.get("browser_parent") and (execution_context.get("script_like") or execution_context.get("user_writable_path")):
        score += weight_fn("browser_anomaly")
        reasons.append("browser-spawned execution with script/path anomaly")
    if execution_context.get("suspicious_chain_matches"):
        score += weight_fn("suspicious_chain")
        reasons.extend(str(item) for item in execution_context.get("suspicious_chain_matches", [])[:2])
    if isinstance(create_time, (int, float)) and create_time > 0:
        age_seconds = max(0.0, time.time() - float(create_time))
        if age_seconds < 300 and score >= 20:
            score += weight_fn("recent_spawn")
            reasons.append("recently spawned process with risk signals")
    if any(term in name or term in cmd_lower for term in SUSPICIOUS_COMMAND_TERMS):
        score += weight_fn("suspicious_command")
        reasons.append("command line or process name contains attacker-useful tooling indicators")
    if command_entropy(cmdline_text) >= 4.4 and len(cmdline_text) >= 120:
        score += weight_fn("high_entropy_command")
        reasons.append("high-entropy command line suggests encoded or packed arguments")
    if known_good_baseline and name in {"system idle process", "system"}:
        cpu = min(cpu, 5.0)
    if cpu >= 30:
        score += weight_fn("high_cpu")
        reasons.append(f"high CPU pressure observed ({cpu:.1f}%)")
    elif cpu >= 15:
        score += weight_fn("medium_cpu")
        reasons.append(f"moderate CPU pressure observed ({cpu:.1f}%)")
    if mem >= 8:
        score += weight_fn("high_memory")
        reasons.append(f"high memory share observed ({mem:.1f}%)")
    if not process.get("sha256"):
        score += weight_fn("missing_hash")
        reasons.append("SHA-256 is not available for enrichment")
    network_connections = process.get("network_connections") or []
    if isinstance(network_connections, list) and network_connections:
        score += min(
            weight_fn("network_connection_cap"),
            len(network_connections) * weight_fn("network_connection_each"),
        )
        reasons.append(f"{len(network_connections)} network connection(s) observed")
        if any(is_public_network_destination(str(item)) for item in network_connections):
            score += weight_fn("public_egress")
            reasons.append("public network destination observed")
    score = max(0, min(100, score))
    if score >= 75:
        label = "critical"
    elif score >= 55:
        label = "high"
    elif score >= 30:
        label = "medium"
    else:
        label = "low"
    if not reasons:
        reasons.append("no immediate weak signal from local metadata")
    return score, label, reasons
