from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


VOLATILITY_PLUGINS = [
    "windows.info",
    "windows.cmdline",
    "windows.psxview",
    "windows.malfind",
    "windows.netscan",
]


def acquire_memory_dump(pid: int, pname: str) -> dict[str, Any]:
    dump_dir = Path("shadowlab_out") / "memory_dumps"
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = dump_dir / f"memdump_{pname}_{pid}.raw"
    dump_tool = shutil.which("procdump64.exe") or shutil.which("procdump.exe")

    if dump_tool:
        try:
            subprocess.run(
                [dump_tool, "-accepteula", "-ma", str(pid), str(dump_path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            return {
                "filename": dump_path.name,
                "path": str(dump_path),
                "size_mb": round(dump_path.stat().st_size / (1024 * 1024), 2),
                "status": "completed",
                "collector": Path(dump_tool).name,
                "collected_at": time.time(),
                "simulated": False,
            }
        except Exception as exc:
            dump_path.write_bytes(b"SHADOWLAB_FALLBACK_DUMP")
            return {
                "filename": dump_path.name,
                "path": str(dump_path),
                "size_mb": round(dump_path.stat().st_size / (1024 * 1024), 2),
                "status": "fallback",
                "collector": Path(dump_tool).name,
                "collected_at": time.time(),
                "simulated": True,
                "error": str(exc),
            }

    dump_path.write_bytes(b"SHADOWLAB_SIMULATED_DUMP")
    return {
        "filename": dump_path.name,
        "path": str(dump_path),
        "size_mb": round(dump_path.stat().st_size / (1024 * 1024), 2),
        "status": "completed",
        "collector": "simulated",
        "collected_at": time.time(),
        "simulated": True,
    }


def run_volatility_analysis(pid: int, pname: str, dump_path: str | Path | None = None) -> dict[str, Any]:
    transcript: list[str] = []
    findings: list[dict[str, Any]] = []
    dump_path = Path(dump_path) if dump_path else Path("shadowlab_out") / "memory_dumps" / f"memdump_{pname}_{pid}.raw"
    volatility_path = shutil.which("vol") or shutil.which("volatility") or shutil.which("volatility3")

    def log(line: str) -> None:
        transcript.append(line)

    if volatility_path and dump_path.exists():
        log(f"Volatility binary detected: {volatility_path}")
        log(f"INFO: Reading memory dump: {dump_path.name}")
        for plugin in VOLATILITY_PLUGINS:
            log(f">>> Running plugin: {plugin}")
            try:
                completed = subprocess.run(
                    [volatility_path, "-f", str(dump_path), plugin],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                output = completed.stdout or completed.stderr or ""
                transcript.extend(line for line in output.splitlines()[:30] if line.strip())
                findings.extend(_parse_volatility_output(plugin, output, pid, pname))
            except Exception as exc:
                log(f"[!] Plugin error for {plugin}: {exc}")
    else:
        if not volatility_path:
            log("Volatility binary not found; using deterministic fallback analysis.")
        else:
            log("Memory dump path missing; using deterministic fallback analysis.")
        findings, fallback_lines = _simulate_findings(pid, pname)
        transcript.extend(fallback_lines)

    severity, verdict, summary = _summarize_findings(findings, pid, pname)
    return {
        "pid": pid,
        "process_name": pname,
        "volatility_available": bool(volatility_path),
        "severity": severity,
        "verdict": verdict,
        "summary": summary,
        "transcript": transcript,
        "findings": findings,
    }


def run_analysis(pid: int, pname: str) -> dict[str, Any]:
    dump = acquire_memory_dump(pid, pname)
    analysis = run_volatility_analysis(pid, pname, dump.get("path"))
    return {
        "dump": dump,
        "analysis": analysis,
    }


def _simulate_findings(pid: int, pname: str) -> tuple[list[dict[str, Any]], list[str]]:
    seed = int(hashlib.sha256(f"{pid}:{pname}".encode("utf-8")).hexdigest()[:8], 16)
    findings: list[dict[str, Any]] = []
    lines = [
        "Volatility 3 fallback transcript",
        f"INFO: Simulating Windows memory profile for {pname} ({pid})",
        ">>> Running plugin: windows.psxview",
    ]

    if seed % 3 == 0:
        findings.append(
            {
                "plugin": "windows.psxview",
                "severity": "critical",
                "title": "Hidden process discrepancy",
                "detail": "Process visible in pool scan but inconsistent across active process lists.",
            }
        )
        lines.append("[!] ALERT: Hidden process discrepancy detected.")
    if seed % 5 == 0:
        findings.append(
            {
                "plugin": "windows.malfind",
                "severity": "high",
                "title": "Injected executable region",
                "detail": "Executable memory with write permissions and MZ header characteristics observed.",
            }
        )
        lines.append("[!] ALERT: Executable RWX region matched malfind heuristics.")
    if seed % 7 == 0:
        findings.append(
            {
                "plugin": "windows.netscan",
                "severity": "medium",
                "title": "Unusual network socket persistence",
                "detail": "Active socket state remained present across simulated scans.",
            }
        )
        lines.append("[!] WARN: Unusual network persistence observed in netscan.")
    if not findings:
        lines.append("No injected code or hidden process artefacts identified in fallback mode.")
    return findings, lines


def _parse_volatility_output(plugin: str, output: str, pid: int, pname: str) -> list[dict[str, Any]]:
    lowered = output.lower()
    findings: list[dict[str, Any]] = []
    if plugin == "windows.malfind" and ("vad" in lowered or "execute" in lowered or "rwx" in lowered):
        findings.append(
            {
                "plugin": plugin,
                "severity": "high",
                "title": "Injected executable memory",
                "detail": f"{pname} ({pid}) exposed malfind indicators consistent with code injection or hollowing.",
            }
        )
    if plugin == "windows.psxview" and ("false" in lowered or "hidden" in lowered):
        findings.append(
            {
                "plugin": plugin,
                "severity": "critical",
                "title": "Cross-view process inconsistency",
                "detail": f"{pname} ({pid}) showed psxview inconsistencies consistent with hidden process behavior.",
            }
        )
    if plugin == "windows.cmdline" and ("powershell" in lowered or "encodedcommand" in lowered):
        findings.append(
            {
                "plugin": plugin,
                "severity": "medium",
                "title": "Suspicious memory-resident command line",
                "detail": "PowerShell or encoded command arguments were present in memory artifacts.",
            }
        )
    if plugin == "windows.netscan" and (":443" in lowered or "http" in lowered):
        findings.append(
            {
                "plugin": plugin,
                "severity": "medium",
                "title": "Network artefacts present in memory",
                "detail": "Netscan surfaced active remote communication artefacts during memory analysis.",
            }
        )
    return findings


def _summarize_findings(findings: list[dict[str, Any]], pid: int, pname: str) -> tuple[str, str, str]:
    if not findings:
        return (
            "low",
            "clean",
            f"No advanced memory-manipulation artefacts were identified for {pname} (PID: {pid}).",
        )

    severities = [finding["severity"] for finding in findings]
    if "critical" in severities and "high" in severities:
        return (
            "critical",
            "multi-stage-memory-compromise",
            f"{pname} (PID: {pid}) exhibits multiple memory artefacts consistent with stealth and injection behavior.",
        )
    if "critical" in severities:
        return (
            "critical",
            "hidden-process-behavior",
            f"{pname} (PID: {pid}) exhibits memory artefacts consistent with hidden process behavior.",
        )
    if "high" in severities:
        return (
            "high",
            "memory-injection",
            f"{pname} (PID: {pid}) exhibits code-injection or hollowing indicators in memory.",
        )
    return (
        "medium",
        "memory-anomaly",
        f"{pname} (PID: {pid}) exhibits suspicious but non-critical memory anomalies.",
    )
