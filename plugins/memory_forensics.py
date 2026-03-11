from __future__ import annotations

import shutil
import random
import time
from pathlib import Path
from typing import Any


def acquire_memory_dump(pid: int, pname: str) -> dict[str, Any]:
    dump_dir = Path("shadowlab_out") / "memory_dumps"
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = dump_dir / f"memdump_{pname}_{pid}.raw"
    dump_path.write_bytes(b"SHADOWLAB_SIMULATED_DUMP")
    dump_size = random.randint(300, 1500)
    return {
        "filename": dump_path.name,
        "path": str(dump_path),
        "size_mb": dump_size,
        "status": "completed",
        "collected_at": time.time(),
    }


def run_volatility_analysis(pid: int, pname: str) -> dict[str, Any]:
    transcript: list[str] = []
    volatility_path = shutil.which("vol") or shutil.which("volatility") or shutil.which("volatility3")

    def log(line: str) -> None:
        transcript.append(line)

    if volatility_path:
        log(f"Volatility binary detected: {volatility_path}")
    else:
        log("Volatility binary not found; using simulated analysis transcript.")
    log("Volatility 3 Framework 2.4.1")
    log(f"INFO: Reading memory dump: memdump_{pname}_{pid}.raw")
    log("INFO: Detected Windows 10/11 x64 (Build 19045)")

    is_injected = random.random() > 0.5
    base_addr = f"0x{random.randint(0x10000000, 0x7FFFFFFF):016x}"
    log(">>> Running plugin: windows.malfind.Malfind")
    if is_injected:
        log(f"PID: {pid}")
        log(f"Process: {pname}")
        log(f"Start VPN: {base_addr}")
        log("Protection: PAGE_EXECUTE_READWRITE")
        log("CommitCharge: 4")
        log("[!] ALERT: Hidden PE file detected (DLL Injection) at executable memory segment.")
    else:
        log("No injected code found in PAGE_EXECUTE_READWRITE segments.")

    is_hidden = random.random() > 0.8
    log(">>> Running plugin: windows.psxview.PsXview")
    if is_hidden:
        log("[!] ALERT: Process found in pool scanning (psscan) but missing from active process list (pslist).")
        log("[!] INTERPRETATION: DKOM Rootkit hiding process.")
    else:
        log("Process links are intact. No DKOM rootkit behavior detected.")

    verdict = "clean"
    severity = "low"
    summary = f"No advanced memory manipulation detected in {pname} (PID: {pid})."
    if is_injected and is_hidden:
        verdict = "dll_injection_and_hidden_process"
        severity = "critical"
        summary = f"{pname} (PID: {pid}) exhibits DLL injection and hidden-process behavior."
    elif is_injected:
        verdict = "dll_injection"
        severity = "high"
        summary = f"{pname} (PID: {pid}) shows injected executable content in memory."
    elif is_hidden:
        verdict = "hidden_process"
        severity = "critical"
        summary = f"{pname} (PID: {pid}) appears hidden from normal process views."

    return {
        "pid": pid,
        "process_name": pname,
        "volatility_available": bool(volatility_path),
        "severity": severity,
        "verdict": verdict,
        "summary": summary,
        "transcript": transcript,
    }


def run_analysis(pid: int, pname: str) -> dict[str, Any]:
    dump = acquire_memory_dump(pid, pname)
    analysis = run_volatility_analysis(pid, pname)
    return {
        "dump": dump,
        "analysis": analysis,
    }
