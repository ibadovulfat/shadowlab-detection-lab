"""Indicator-to-MITRE-ATT&CK mapper for the antivirus pipeline.

When an engine fires it tells you *something* matched — a signature,
a YARA rule, a behavioural pattern, a sandbox observation. Real EDR
products turn that signal into ATT&CK technique coverage so an
analyst can see "this sample exhibits T1055 Process Injection,
T1027.002 Software Packing, T1059.001 PowerShell" without manually
mapping every detection name.

This mapper is intentionally lightweight and self-contained:
  * No dependency on the heavy `MitreAttackService` (which loads full
    STIX bundles for the enterprise case workbench).
  * Pure-data lookup tables — no network calls, no DB.
  * Operates on the per-provider results already produced by
    `AntivirusService._fuse`, plus the sandbox provider's
    `techniques` field which is *already* ATT&CK-shaped.

Two indicator sources feed it:
  1. **Behavioural reasons** — strings emitted by the static PE
     analyzer ("RWX section(s)", "Suspicious imports: VirtualAllocEx,
     WriteProcessMemory, CreateRemoteThread", "TLS callback(s)",
     "Suspicious section name(s): .upx0"). Each substring trigger
     maps to a technique ID.
  2. **YARA rule names / tags** — high-signal tags emitted by
     `plugins/yara_scanner` (`inject_thread`, `process_hollowing`,
     `amsi`, `etw`, `wldp`, `credential_access`, `ransomware`).

The output is a `[{id, name, tactic, sources}]` list deduplicated
across providers. Tactic is the canonical MITRE tactic name; sources
captures which provider triggered the technique so analysts can
trace it back.
"""
from __future__ import annotations

from typing import Any


# Curated mapping table. Keys are case-insensitive substrings searched
# in behavioural reason strings or YARA tags / rule names.
INDICATOR_TO_TECHNIQUE: dict[str, dict[str, str]] = {
    # Process injection family
    "virtualallocex": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "writeprocessmemory": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "createremotethread": {"id": "T1055.002", "name": "Portable Executable Injection", "tactic": "Defense Evasion"},
    "ntcreatethreadex": {"id": "T1055.002", "name": "Portable Executable Injection", "tactic": "Defense Evasion"},
    "queueuserapc": {"id": "T1055.004", "name": "Asynchronous Procedure Call", "tactic": "Defense Evasion"},
    "process_hollowing": {"id": "T1055.012", "name": "Process Hollowing", "tactic": "Defense Evasion"},
    "process hollowing": {"id": "T1055.012", "name": "Process Hollowing", "tactic": "Defense Evasion"},
    "inject_thread": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "injection": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "remote memory/thread injection": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    # Defense-evasion: signing / AMSI / ETW / WLDP
    "amsiscanbuffer": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    "amsi": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    "etweventwrite": {"id": "T1562.006", "name": "Indicator Blocking", "tactic": "Defense Evasion"},
    "etw": {"id": "T1562.006", "name": "Indicator Blocking", "tactic": "Defense Evasion"},
    "wldpquerydynamiccodetrust": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    "wldp": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    # Packing / obfuscation
    "high-entropy section": {"id": "T1027.002", "name": "Software Packing", "tactic": "Defense Evasion"},
    "rwx section": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "suspicious section name": {"id": "T1027.002", "name": "Software Packing", "tactic": "Defense Evasion"},
    "packer": {"id": "T1027.002", "name": "Software Packing", "tactic": "Defense Evasion"},
    "packed": {"id": "T1027.002", "name": "Software Packing", "tactic": "Defense Evasion"},
    "overlay detected": {"id": "T1027.009", "name": "Embedded Payloads", "tactic": "Defense Evasion"},
    # Persistence / TLS callback
    "tls callback": {"id": "T1546", "name": "Event Triggered Execution", "tactic": "Persistence"},
    # Execution
    "winexec": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "shellexecute": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "powershell": {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    "cmd.exe": {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
    # Discovery / ingress
    "urldownloadtofile": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    # Credential access
    "credential_access": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    "credential access": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    "lsass": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    "mimikatz": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    # Impact
    "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    "wiper": {"id": "T1485", "name": "Data Destruction", "tactic": "Impact"},
    # Discovery
    "shellcode": {"id": "T1106", "name": "Native API", "tactic": "Execution"},
}


class MitreMapper:
    """Stateless mapper — every call is independent."""

    def __init__(self, table: dict[str, dict[str, str]] | None = None):
        self._table = {key.lower(): dict(value) for key, value in (table or INDICATOR_TO_TECHNIQUE).items()}

    def map_provider_results(self, provider_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Aggregate ATT&CK techniques across every provider's findings.

        Returns deduplicated `[{id, name, tactic, sources}]` rows where
        `sources` is the set of provider keys that contributed."""
        accumulated: dict[str, dict[str, Any]] = {}
        for provider_key, result in (provider_results or {}).items():
            if not isinstance(result, dict):
                continue
            for technique in self._techniques_from_result(provider_key, result):
                tid = str(technique.get("id", "")).strip().upper()
                if not tid:
                    continue
                row = accumulated.setdefault(
                    tid,
                    {
                        "id": tid,
                        "name": str(technique.get("name", "")),
                        "tactic": str(technique.get("tactic", "")),
                        "sources": [],
                    },
                )
                if provider_key not in row["sources"]:
                    row["sources"].append(provider_key)
                # Prefer non-empty name/tactic if a previous mapping was thin.
                if not row.get("name") and technique.get("name"):
                    row["name"] = str(technique["name"])
                if not row.get("tactic") and technique.get("tactic"):
                    row["tactic"] = str(technique["tactic"])
        return sorted(accumulated.values(), key=lambda row: row["id"])

    def _techniques_from_result(self, provider_key: str, result: dict[str, Any]) -> list[dict[str, str]]:
        techniques: list[dict[str, str]] = []
        # 1. Direct sandbox-style technique payload — already ATT&CK-shaped.
        for item in result.get("techniques", []) or []:
            if not isinstance(item, dict):
                continue
            tid = str(item.get("id") or "").strip()
            if tid:
                techniques.append(
                    {
                        "id": tid,
                        "name": str(item.get("name", "")),
                        "tactic": str(item.get("tactic", "")),
                    }
                )
        # 2. String-indicator scan: behavioural reasons + malware_name.
        candidate_strings: list[str] = []
        for reason in result.get("reasons", []) or []:
            candidate_strings.append(str(reason))
        for rule in result.get("matched_rules", []) or []:
            candidate_strings.append(str(rule))
        if result.get("malware_name"):
            candidate_strings.append(str(result["malware_name"]))
        # YARA tags can ride on the behavioural_report or matches list.
        behavioural = result.get("behavioural_report")
        if isinstance(behavioural, dict):
            candidate_strings.append(str(behavioural.get("summary", "")))
        for blob in candidate_strings:
            lowered = blob.lower()
            for indicator, technique in self._table.items():
                if indicator in lowered:
                    techniques.append(dict(technique))
        return techniques

    def coverage_summary(self, techniques: list[dict[str, Any]]) -> dict[str, Any]:
        """Group mapped techniques by tactic for quick UI rendering."""
        by_tactic: dict[str, list[dict[str, Any]]] = {}
        for row in techniques:
            tactic = str(row.get("tactic", "")).strip() or "Unmapped"
            by_tactic.setdefault(tactic, []).append(row)
        return {
            "total_techniques": len(techniques),
            "tactics_covered": sorted(by_tactic.keys()),
            "by_tactic": {tactic: rows for tactic, rows in by_tactic.items()},
        }
