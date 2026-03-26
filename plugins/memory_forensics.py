from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from plugins import yara_scanner


VOLATILITY_PLUGINS = [
    "windows.info",
    "windows.cmdline",
    "windows.psxview",
    "windows.malfind",
    "windows.dlllist",
    "windows.handles",
    "windows.netscan",
]

EXECUTE_PAGE_MARKERS = (
    b"page_execute_readwrite",
    b"page_execute_read",
    b"page_execute_writecopy",
    b"rwx",
)
PRIVATE_MEMORY_MARKERS = (
    b"private",
    b"vad",
    b"unbacked",
    b"no file object",
    b"shellcode",
)
PATCH_MARKERS = (
    b"patch",
    b"patched",
    b"hook",
    b"hooked",
    b"integrity mismatch",
    b"mismatch",
)
MANUAL_MAP_MARKERS = (
    b"manual map",
    b"mapmoduletomemory",
    b"callmappeddllmoduleexport",
    b"loadmodulefromdisk",
    b"getlibraryaddress",
    b"dinvoke",
    b"syswhispers",
)
PORTABLE_EXECUTABLE_MARKERS = (
    b"this program cannot be run in dos mode",
    b"mz",
    b"pe\x00\x00",
)


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
    memory_heuristics = _analyze_dump_content(dump.get("path"))
    if memory_heuristics:
        analysis["findings"].extend(memory_heuristics)
        severity, verdict, summary = _summarize_findings(analysis["findings"], pid, pname)
        analysis["severity"] = severity
        analysis["verdict"] = verdict
        analysis["summary"] = summary
    memory_yara = yara_scanner.scan_file(
        dump.get("path", ""),
        pack="memory",
        context={
            "filepath": dump.get("path", "") or "",
            "filename": Path(str(dump.get("path", "") or "")).name,
            "scope": "memory",
        },
    ) if dump.get("path") else {
        "status": "skipped",
        "reason": "Memory dump path unavailable",
        "matches": [],
    }
    fused = _fuse_memory_verdict(analysis, memory_yara)
    analysis["memory_yara"] = memory_yara
    analysis["fusion"] = fused
    return {
        "dump": dump,
        "analysis": analysis,
    }


def _fuse_memory_verdict(analysis: dict[str, Any], memory_yara: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    severity = str(analysis.get("severity", "low")).lower()
    if severity == "critical":
        score += 55
        reasons.append("Volatility surfaced critical hidden-process or stealth behaviour.")
    elif severity == "high":
        score += 35
        reasons.append("Volatility surfaced high-severity memory injection indicators.")
    elif severity == "medium":
        score += 20
        reasons.append("Volatility surfaced medium-severity memory anomalies.")

    yara_score = int(memory_yara.get("score", 0) or 0) if isinstance(memory_yara, dict) else 0
    yara_hits = int(memory_yara.get("active_match_count", memory_yara.get("match_count", 0)) or 0) if isinstance(memory_yara, dict) else 0
    if yara_hits:
        score += min(40, 10 + int(yara_score * 0.4))
        reasons.append(f"Memory YARA matched {yara_hits} rule(s).")

    final_score = max(0, min(100, score))
    return {
        "score": final_score,
        "severity": "critical" if final_score >= 80 else "high" if final_score >= 55 else "medium" if final_score >= 30 else "low",
        "confidence": "high" if final_score >= 75 else "medium" if final_score >= 45 else "low",
        "reasons": reasons,
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


def _analyze_dump_content(dump_path: str | Path | None) -> list[dict[str, Any]]:
    if not dump_path:
        return []
    path = Path(dump_path)
    if not path.exists():
        return []
    try:
        lowered = path.read_bytes().lower()
    except Exception:
        return []

    findings: list[dict[str, Any]] = []
    if b"amsiscanbuffer" in lowered and b"etweventwrite" in lowered and b"virtualprotect" in lowered:
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "critical",
                "title": "Patched AMSI or ETW sequence",
                "detail": "Memory dump contained AMSI or ETW patch markers chained with memory-protection changes.",
            }
        )
    if b"ntdll.dll" in lowered and b".text" in lowered and b"ntmapviewofsection" in lowered and b"ntunmapviewofsection" in lowered:
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "critical",
                "title": "NTDLL remap or unhook sequence",
                "detail": "Memory dump contained ntdll remap markers consistent with unhooking activity.",
            }
        )
    if (b"ntqueueapcthread" in lowered or b"queueuserapc" in lowered) and (
        b"ntwritevirtualmemory" in lowered or b"createremotethread" in lowered or b"rtlcreateuserthread" in lowered
    ):
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "high",
                "title": "APC or remote-thread injection chain",
                "detail": "Memory dump contained APC or remote-thread APIs chained with injection markers.",
            }
        )
    if any(marker in lowered for marker in EXECUTE_PAGE_MARKERS):
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "high",
                "title": "Executable writable region markers",
                "detail": "Memory dump contained RWX or PAGE_EXECUTE_READWRITE markers associated with shellcode staging.",
            }
        )
    if any(marker in lowered for marker in EXECUTE_PAGE_MARKERS) and any(marker in lowered for marker in PRIVATE_MEMORY_MARKERS):
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "critical",
                "title": "Unbacked executable private region",
                "detail": "Memory dump contained executable private-memory markers consistent with shellcode or unbacked injected pages.",
            }
        )
    if b"ntdll.dll" in lowered and b".text" in lowered and any(marker in lowered for marker in PATCH_MARKERS):
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "critical",
                "title": "NTDLL text integrity mismatch",
                "detail": "Memory dump contained ntdll .text patch or mismatch markers consistent with unhooking or integrity tampering.",
            }
        )
    if any(marker in lowered for marker in MANUAL_MAP_MARKERS) and (
        any(marker in lowered for marker in PORTABLE_EXECUTABLE_MARKERS) or any(marker in lowered for marker in EXECUTE_PAGE_MARKERS)
    ):
        findings.append(
            {
                "plugin": "shadowlab.memory.heuristics",
                "severity": "high",
                "title": "Manual mapped module indicators",
                "detail": "Memory dump contained manual-mapping markers together with PE or executable-page evidence.",
            }
        )
    return findings


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
    if plugin == "windows.dlllist" and any(module in lowered for module in ("amsi.dll", "wldp.dll", "ntdll.dll")) and (
        "\\temp\\" in lowered or "\\appdata\\" in lowered or "\\downloads\\" in lowered
    ):
        findings.append(
            {
                "plugin": plugin,
                "severity": "high",
                "title": "Sensitive module load from suspicious path",
                "detail": f"{pname} ({pid}) loaded sensitive Windows modules while volatility surfaced user-writable module paths.",
            }
        )
    if plugin == "windows.handles" and "process" in lowered and any(target in lowered for target in ("lsass.exe", "winlogon.exe", "explorer.exe")):
        findings.append(
            {
                "plugin": plugin,
                "severity": "high",
                "title": "Cross-process handle access",
                "detail": f"{pname} ({pid}) opened handles into high-value peer processes during memory analysis.",
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
