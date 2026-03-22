from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
from typing import Any

try:
    import yara  # type: ignore
except Exception:
    yara = None


YARA_AVAILABLE = yara is not None
BASE_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = Path(__file__).resolve().parent / "rules"
POLICY_PATH = RULES_DIR / "local_yara_policy.json"
DOCUMENTS_DIR = Path.home() / "Documents"
RULES_MASTER_DIR = DOCUMENTS_DIR / "rules-master"
SIGNATURE_BASE_DIR = DOCUMENTS_DIR / "signature-base-master"

SIGNATURE_BASE_EXT_VAR_FILES = {
    "generic_anomalies.yar",
    "general_cloaking.yar",
    "gen_webshells_ext_vars.yar",
    "thor_inverse_matches.yar",
    "yara_mixed_ext_vars.yar",
    "configured_vulns_ext_vars.yar",
    "gen_fake_amsi_dll.yar",
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar",
    "yara-rules_vuln_drivers_strict_renamed.yar",
}
RULES_MASTER_SKIP_FILES = {
    "domain.yar",
    "MALW_AZORULT.yar",
    "MALW_Httpsd_ELF.yar",
    "MALW_Mirai_Okiru_ELF.yar",
    "MALW_Mirai_Satori_ELF.yar",
    "MALW_Rebirth_Vulcan_ELF.yar",
    "RAT_PoetRATPython.yar",
    "MALW_TinyShell_Backdoor_gen.yar",
    "MALW_Torte_ELF.yar",
    "TOOLKIT_Mandibule.yar",
}
EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "md5": "",
}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_SOURCE_WEIGHTS = {
    "shadowlab": 22,
    "inceptor": 32,
    "signature_base": 18,
    "rules_master": 12,
}
HIGH_RISK_TAGS = {
    "malware",
    "inject_thread",
    "injection",
    "shellcode",
    "amsi",
    "etw",
    "wldp",
    "process_hollowing",
    "credential_access",
    "ransomware",
}
LOW_SIGNAL_TAGS = {
    "packer",
    "packed",
    "generic",
    "heuristic",
    "suspicious",
    "webshell",
    "macro",
}
DEFAULT_ALLOWLIST_PATH_PREFIXES = (
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
)


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _source_for_path(path: Path) -> str:
    path_str = str(path).lower()
    if "signature-base-master" in path_str:
        return "signature_base"
    if "rules-master" in path_str:
        return "rules_master"
    if str(RULES_DIR).lower() in path_str:
        if path.name == "inceptor_tradecraft.yar":
            return "inceptor"
        return "shadowlab"
    return "unknown"


def _severity_from_meta(meta: dict[str, Any], tags: list[str], source: str, path: Path) -> str:
    for key in ("severity", "level", "confidence"):
        value = str(meta.get(key, "")).strip().lower()
        if value in SEVERITY_ORDER:
            return value
    lowered_tags = {str(tag).lower() for tag in tags}
    path_str = str(path).lower()
    if source == "inceptor":
        return "critical" if "syscalls" in path_str or "unhook" in path_str else "high"
    if "critical" in lowered_tags:
        return "critical"
    description = str(meta.get("description", "")).lower()
    if any(tag in lowered_tags for tag in HIGH_RISK_TAGS):
        return "critical" if {"amsi", "etw", "injection", "process_hollowing"} & lowered_tags else "high"
    if any(marker in description for marker in ("manual map", "manual mapping", "syscall", "unhook", "amsi", "etw")):
        return "high"
    if any(tag in lowered_tags for tag in {"antidebug", "debuggerhiding", "inject_thread", "malware"}):
        return "high"
    if "deprecated" in path.parts or "mobile_malware" in path.parts:
        return "low"
    if "packers" in path_str or "capabilities" in path_str:
        return "medium"
    if source == "signature_base":
        return "medium"
    return "low"


def _weight_for_match(path: Path, source: str, severity: str) -> int:
    weight = DEFAULT_SOURCE_WEIGHTS.get(source, 10)
    lowered = str(path).lower()
    if "deprecated" in path.parts:
        weight -= 10
    if "mobile_malware" in path.parts:
        weight -= 8
    if "email" in path.parts:
        weight -= 4
    if "packers" in path.parts:
        weight -= 2
    if "capabilities" in lowered:
        weight -= 1
    if "exploit" in lowered or "cve" in lowered:
        weight += 2
    if "antidebug" in lowered or "antivm" in lowered:
        weight += 4
    if "manual" in lowered or "dinvoke" in lowered or "syscall" in lowered or "unhook" in lowered:
        weight += 5
    weight += SEVERITY_ORDER.get(severity, 1) * 5
    return max(5, min(40, weight))


def _csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


@lru_cache(maxsize=1)
def _load_policy() -> dict[str, Any]:
    if not POLICY_PATH.exists():
        return {}
    try:
        payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _policy_list(name: str) -> list[str]:
    value = _load_policy().get(name, [])
    return [str(item).strip() for item in value if str(item).strip()] if isinstance(value, list) else []


def _policy_map(name: str) -> dict[str, Any]:
    value = _load_policy().get(name, {})
    return dict(value) if isinstance(value, dict) else {}


def load_policy() -> dict[str, Any]:
    return dict(_load_policy())


def save_policy(policy: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(policy or {})
    POLICY_PATH.write_text(json.dumps(normalized, indent=2, ensure_ascii=False), encoding="utf-8")
    _load_policy.cache_clear()
    return load_policy()


def _trusted_path_prefixes() -> tuple[str, ...]:
    extra = tuple(_csv_env("SHADOWLAB_YARA_ALLOWLIST_PATH_PREFIXES")) + tuple(_policy_list("allowlist_path_prefixes"))
    return DEFAULT_ALLOWLIST_PATH_PREFIXES + extra


def _trusted_hashes() -> set[str]:
    values = _csv_env("SHADOWLAB_YARA_ALLOWLIST_HASHES") + _policy_list("allowlist_hashes")
    return {item.lower() for item in values}


def _allowlisted_rule_patterns() -> list[str]:
    return [item.lower() for item in _policy_list("allowlist_rule_patterns")]


def _suppressed_rule_patterns() -> list[str]:
    return [item.lower() for item in _policy_list("suppressed_rule_patterns")]


def _boosted_rule_patterns() -> dict[str, int]:
    raw = _policy_map("boost_rule_patterns")
    return {str(key).lower(): int(value) for key, value in raw.items() if str(key).strip()}


def _scope_rule_patterns(scope: str, key: str) -> list[str]:
    return [item.lower() for item in _policy_list(f"{scope}_{key}")]


def _scope_boost_patterns(scope: str) -> dict[str, int]:
    raw = _policy_map(f"{scope}_boost_rule_patterns")
    return {str(key).lower(): int(value) for key, value in raw.items() if str(key).strip()}


def _registry_rule_overrides() -> dict[str, dict[str, Any]]:
    try:
        import database as db

        conn = db.create_connection()
        if conn is None:
            return {}
        try:
            frame = db.get_detection_rules(conn)
        finally:
            conn.close()
        if frame.empty:
            return {}
        overrides: dict[str, dict[str, Any]] = {}
        for item in frame.fillna("").to_dict(orient="records"):
            rule_id = str(item.get("rule_id", "")).strip().lower()
            if not rule_id:
                continue
            try:
                tuning = json.loads(str(item.get("tuning_json", "{}") or "{}"))
            except Exception:
                tuning = {}
            try:
                suppressions = json.loads(str(item.get("suppression_json", "{}") or "{}"))
            except Exception:
                suppressions = {}
            overrides[rule_id] = {
                "tuning": tuning if isinstance(tuning, dict) else {},
                "suppressions": suppressions if isinstance(suppressions, dict) else {},
                "status": str(item.get("status", "active")),
            }
        return overrides
    except Exception:
        return {}


def _path_matches_any(value: str, patterns: list[str]) -> bool:
    lowered = value.lower()
    return any(pattern in lowered for pattern in patterns)


def _normalize_context(context: dict[str, Any] | None, target: Path) -> dict[str, Any]:
    values = dict(context or {})
    values.setdefault("filepath", str(target))
    values.setdefault("filename", target.name)
    values.setdefault("extension", target.suffix.lstrip("."))
    values.setdefault("filetype", target.suffix.lower())
    values.setdefault("signature_status", "")
    values.setdefault("sha256", "")
    values.setdefault("scope", "file")
    return values


def _is_high_signal_match(source: str, severity: str, tags: list[str], meta: dict[str, Any]) -> bool:
    lowered_tags = {str(tag).lower() for tag in tags}
    description = str(meta.get("description", "")).lower()
    if source in {"inceptor", "shadowlab"}:
        return True
    if severity == "critical":
        return True
    return any(tag in lowered_tags for tag in HIGH_RISK_TAGS) or any(
        marker in description for marker in ("manual map", "syscall", "unhook", "amsi", "etw")
    )


def _suppression_reasons(match: dict[str, Any], context: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    source = str(match.get("source", "unknown"))
    severity = str(match.get("severity", "low"))
    tags = list(match.get("tags", []) or [])
    meta = dict(match.get("meta", {}) or {})
    path_value = str(context.get("filepath", "") or "").lower()
    sha256 = str(context.get("sha256", "") or "").lower()
    signature_status = str(context.get("signature_status", "") or "").strip().lower()
    rule_name = str(match.get("rule", "") or "").lower()
    source_path = str(match.get("source_path", "") or "").lower()
    scope = str(context.get("scope", "file") or "file").lower()
    registry = _registry_rule_overrides().get(rule_name, {})
    suppressions = registry.get("suppressions", {}) if isinstance(registry, dict) else {}

    if _is_high_signal_match(source, severity, tags, meta):
        if not bool(suppressions.get("force")):
            return reasons
    if bool(suppressions.get("disabled")):
        reasons.append("rule disabled by registry tuning")
    if _path_matches_any(rule_name, _allowlisted_rule_patterns()) or _path_matches_any(source_path, _allowlisted_rule_patterns()):
        reasons.append("rule pattern allowlisted")
    if _path_matches_any(rule_name, _scope_rule_patterns(scope, "allowlist_rule_patterns")) or _path_matches_any(source_path, _scope_rule_patterns(scope, "allowlist_rule_patterns")):
        reasons.append(f"{scope} rule pattern allowlisted")
    if _path_matches_any(rule_name, _suppressed_rule_patterns()) or _path_matches_any(source_path, _suppressed_rule_patterns()):
        reasons.append("rule pattern suppressed by local policy")
    if _path_matches_any(rule_name, _scope_rule_patterns(scope, "suppressed_rule_patterns")) or _path_matches_any(source_path, _scope_rule_patterns(scope, "suppressed_rule_patterns")):
        reasons.append(f"{scope} rule pattern suppressed by local policy")
    if sha256 and sha256 in _trusted_hashes():
        reasons.append("known-good hash allowlisted")
    if signature_status == "valid" and any(path_value.startswith(prefix.lower()) for prefix in _trusted_path_prefixes()):
        reasons.append("trusted path with valid signature")
    return reasons


def _apply_suppression(match: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    reasons = _suppression_reasons(match, context)
    if not reasons:
        match["suppressed"] = False
        match["suppression_reasons"] = []
        return match
    match["suppressed"] = True
    match["suppression_reasons"] = reasons
    suppressed_score = max(0, int(match.get("score", 0) * 0.2))
    match["original_score"] = match.get("score", 0)
    match["score"] = suppressed_score
    match["severity"] = "info" if suppressed_score < 10 else "low"
    match["confidence"] = "low"
    return match


def _apply_boost(match: dict[str, Any]) -> dict[str, Any]:
    scope = str(match.get("scope", "file") or "file").lower()
    boosts = {**_boosted_rule_patterns(), **_scope_boost_patterns(scope)}
    registry = _registry_rule_overrides().get(str(match.get("rule", "")).lower(), {})
    tuning = registry.get("tuning", {}) if isinstance(registry, dict) else {}
    if str(registry.get("status", "active")).lower() in {"disabled", "retired"}:
        boosts = {}
    if (not boosts and not tuning) or match.get("suppressed"):
        return match
    rule_name = str(match.get("rule", "") or "").lower()
    source_path = str(match.get("source_path", "") or "").lower()
    delta = 0
    for pattern, boost in boosts.items():
        if pattern and (pattern in rule_name or pattern in source_path):
            delta = max(delta, int(boost))
    delta = max(delta, int(tuning.get("score_delta", 0) or 0))
    if delta <= 0:
        return match
    boosted = min(40, int(match.get("score", 0)) + delta)
    match["original_score"] = match.get("original_score", match.get("score", 0))
    match["score"] = boosted
    if boosted >= 30:
        match["severity"] = "critical"
    elif boosted >= 24 and SEVERITY_ORDER.get(str(match.get("severity", "low")), 1) < SEVERITY_ORDER["high"]:
        match["severity"] = "high"
    match["confidence"] = _confidence_label(boosted)
    match["boosted"] = True
    match["boost_delta"] = delta
    return match


def _log_scan_result(target: Path, pack: str, result: dict[str, Any]) -> None:
    try:
        import database as db

        conn = db.create_connection()
        if conn is None:
            return
        try:
            matches = result.get("matches", []) if isinstance(result, dict) else []
            source_counts: dict[str, int] = {}
            for item in matches:
                source = str(item.get("source", "unknown"))
                source_counts[source] = source_counts.get(source, 0) + 1
            scope = "memory" if pack == "memory" else "file"
            db.log_yara_scan(
                conn,
                target_path=str(target),
                pack=pack,
                scope=scope,
                status=str(result.get("status", "")),
                match_count=int(result.get("match_count", 0) or 0),
                suppressed_count=int(result.get("suppressed_match_count", 0) or 0),
                compile_error_count=len(result.get("compile_errors", []) or []),
                source_counts_json=json.dumps(source_counts, ensure_ascii=False),
                matched_rules_json=json.dumps(result.get("matched_rules", []), ensure_ascii=False),
                errors_json=json.dumps(result.get("compile_errors", []), ensure_ascii=False),
            )
            for item in matches:
                db.log_yara_rule_hit(
                    conn,
                    rule_id=str(item.get("rule", "")),
                    source=str(item.get("source", "")),
                    source_path=str(item.get("source_path", "")),
                    pack=pack,
                    scope=scope,
                    severity=str(item.get("severity", "low")),
                    confidence=str(item.get("confidence", "low")),
                    score=int(item.get("score", 0) or 0),
                    suppressed=bool(item.get("suppressed", False)),
                )
        finally:
            conn.close()
    except Exception:
        return


def _confidence_label(score: int) -> str:
    if score >= 85:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _shadowlab_rules() -> list[Path]:
    return sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))


def _rules_master_rules() -> list[Path]:
    if not RULES_MASTER_DIR.exists():
        return []
    rule_paths = [
        path
        for path in RULES_MASTER_DIR.rglob("*.yar")
        if path.is_file()
        and ".github" not in path.parts
        and not path.name.startswith(".")
        and "deprecated" not in path.parts
        and "mobile_malware" not in path.parts
        and path.name not in RULES_MASTER_SKIP_FILES
        and not path.name.endswith("_index.yar")
        and path.name not in {"index.yar", "index_w_mobile.yar"}
    ]
    return sorted(rule_paths)


def _signature_base_rules() -> list[Path]:
    yara_dir = SIGNATURE_BASE_DIR / "yara"
    vendor_dir = SIGNATURE_BASE_DIR / "vendor" / "yara"
    if not yara_dir.exists():
        return []
    rule_paths = [
        path
        for path in sorted(yara_dir.glob("*.yar"))
        if path.name not in SIGNATURE_BASE_EXT_VAR_FILES
    ]
    rule_paths.extend(sorted(vendor_dir.glob("*.yar")))
    return rule_paths


def available_packs() -> dict[str, list[Path]]:
    shadowlab = _shadowlab_rules()
    memory_shadowlab = [path for path in shadowlab if path.name in {"basic.yar", "inceptor_tradecraft.yar", "memory_tradecraft.yar"}]
    rules_master = _rules_master_rules()
    signature_base = _signature_base_rules()
    curated_rules_master = [
        path for path in rules_master
        if any(part in {"antidebug_antivm", "capabilities", "packers", "malware"} for part in path.parts)
    ]
    curated_signature_base = [
        path for path in signature_base
        if "generic" not in path.name.lower() and "deprecated" not in str(path).lower()
    ]
    packs = {
        "basic": shadowlab,
        "shadowlab": shadowlab,
        "memory": memory_shadowlab,
        "rules_master": rules_master,
        "signature_base": signature_base,
        "community": _dedupe_paths(rules_master + signature_base),
    }
    packs["fast"] = [path for path in shadowlab if path.name in {"basic.yar", "inceptor_tradecraft.yar"}]
    packs["balanced"] = _dedupe_paths(shadowlab + curated_rules_master + curated_signature_base[:200])
    packs["deep"] = _dedupe_paths(shadowlab + packs["community"])
    packs["hybrid"] = packs["balanced"]
    packs["enterprise"] = packs["deep"]
    packs["inceptor"] = [
        path for path in shadowlab
        if path.name in {"inceptor_tradecraft.yar", "basic.yar"}
    ]
    return {name: paths for name, paths in packs.items() if paths}


def _file_signature(paths: list[Path]) -> tuple[tuple[str, int, int], ...]:
    signature: list[tuple[str, int, int]] = []
    for path in paths:
        stat = path.stat()
        signature.append((str(path), int(stat.st_mtime), stat.st_size))
    return tuple(signature)


@lru_cache(maxsize=16)
def _compile_cached(signature: tuple[tuple[str, int, int], ...]):
    if not YARA_AVAILABLE:
        return None, [], ["yara-python not installed"]

    valid_filepaths: dict[str, str] = {}
    errors: list[str] = []
    loaded: list[str] = []
    for idx, (path_str, _, _) in enumerate(signature):
        try:
            yara.compile(filepath=path_str, externals=EXTERNALS)
            valid_filepaths[f"rule_{idx}"] = path_str
            loaded.append(path_str)
        except Exception as exc:
            errors.append(f"{Path(path_str).name}: {exc}")

    if not valid_filepaths:
        return None, [], errors

    try:
        compiled = yara.compile(filepaths=valid_filepaths, externals=EXTERNALS)
        return compiled, loaded, errors
    except Exception as exc:
        errors.append(str(exc))
        return None, [], errors


def scan_file(path: str | Path, pack: str = "enterprise", context: dict[str, Any] | None = None) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"status": "missing", "reason": "Target file not found", "matches": []}
    if not YARA_AVAILABLE:
        return {"status": "unavailable", "reason": "yara-python not installed", "matches": []}

    packs = available_packs()
    chosen = packs.get(pack) or packs.get("enterprise") or packs.get("hybrid") or []
    if not chosen:
        return {"status": "skipped", "reason": "No local YARA packs available", "matches": []}

    compiled, loaded_rules, errors = _compile_cached(_file_signature(chosen))
    if compiled is None:
        return {
            "status": "error",
            "reason": "No valid YARA rules could be compiled",
            "matches": [],
            "errors": errors[:20],
        }

    scan_context = _normalize_context(context, target)
    if "scope" not in dict(context or {}):
        scan_context["scope"] = "memory" if pack == "memory" else "file"
    try:
        raw_matches = compiled.match(
            str(target),
            externals={
                "filename": str(scan_context.get("filename", target.name)),
                "filepath": str(scan_context.get("filepath", str(target))),
                "extension": str(scan_context.get("extension", target.suffix.lstrip("."))),
                "filetype": str(scan_context.get("filetype", target.suffix.lower())),
                "md5": "",
            },
        )
    except Exception as exc:
        return {"status": "error", "reason": str(exc), "matches": [], "errors": errors[:20]}

    matches: list[dict[str, Any]] = []
    aggregate_score = 0
    aggregate_severity = "low"
    suppressed_count = 0
    for match in raw_matches:
        source_path = next((item for item in loaded_rules if Path(item).stem == match.namespace), None)
        if source_path is None and str(getattr(match, "namespace", "")).startswith("rule_"):
            try:
                idx = int(str(match.namespace).split("_", 1)[1])
                if 0 <= idx < len(loaded_rules):
                    source_path = loaded_rules[idx]
            except Exception:
                source_path = None
        if source_path is None and getattr(match, "namespace", "") not in {"default", ""}:
            candidate = next((item for item in loaded_rules if Path(item).name.startswith(str(match.namespace))), None)
            source_path = candidate
        source_path = source_path or next((item for item in loaded_rules if Path(item).name == f"{match.rule}.yar"), "")
        resolved_path = Path(source_path) if source_path else Path("")
        tags = list(getattr(match, "tags", []) or [])
        meta = dict(getattr(match, "meta", {}) or {})
        source = _source_for_path(resolved_path) if source_path else "unknown"
        severity = _severity_from_meta(meta, tags, source, resolved_path)
        score = _weight_for_match(resolved_path, source, severity)
        aggregate_score += score
        strings = []
        for item in getattr(match, "strings", [])[:20]:
            identifier = getattr(item, "identifier", "")
            instances = getattr(item, "instances", []) or []
            offsets = [getattr(instance, "offset", None) for instance in instances[:10]]
            strings.append({"identifier": identifier, "offsets": [offset for offset in offsets if offset is not None]})
        match_entry = {
            "rule": match.rule,
            "namespace": match.namespace,
            "source": source,
            "source_path": str(resolved_path) if source_path else "",
            "severity": severity,
            "score": score,
            "confidence": _confidence_label(score),
            "tags": tags,
            "meta": meta,
            "strings": strings,
            "scope": str(scan_context.get("scope", "file")),
        }
        match_entry = _apply_suppression(match_entry, scan_context)
        match_entry = _apply_boost(match_entry)
        if match_entry.get("suppressed"):
            suppressed_count += 1
        aggregate_score += int(match_entry.get("score", 0) or 0) - score
        if SEVERITY_ORDER.get(str(match_entry.get("severity", "low")), 1) > SEVERITY_ORDER.get(aggregate_severity, 1):
            aggregate_severity = str(match_entry.get("severity", "low"))
        matches.append(match_entry)

    final_score = min(100, max(0, aggregate_score))
    active_matches = [item for item in matches if not item.get("suppressed")]
    result = {
        "status": "ok",
        "pack": pack if pack in packs else "enterprise",
        "rules_requested": len(chosen),
        "rules_loaded": len(loaded_rules),
        "rule_sources": loaded_rules[:50],
        "compile_errors": errors[:20],
        "match_count": len(matches),
        "active_match_count": len(active_matches),
        "suppressed_match_count": suppressed_count,
        "score": final_score,
        "severity": aggregate_severity if active_matches else "low",
        "confidence": _confidence_label(final_score),
        "matched_rules": [item["rule"] for item in active_matches],
        "suppressed_rules": [item["rule"] for item in matches if item.get("suppressed")],
        "matches": matches,
    }
    _log_scan_result(target, str(result.get("pack", pack)), result)
    return result


def analyze_sources(limit: int = 500) -> dict[str, Any]:
    try:
        import database as db

        conn = db.create_connection()
        if conn is None:
            return {"status": "unavailable", "reason": "Database unavailable", "sources": []}
        try:
            hits = db.get_yara_rule_hits(conn, limit=limit)
            if hits.empty:
                return {"status": "ok", "sources": [], "top_rules": [], "recent_scans": []}
            hits["score"] = hits["score"].fillna(0)
            by_source = (
                hits.groupby("source", dropna=False)
                .agg(
                    total_hits=("id", "count"),
                    suppressed_hits=("suppressed", "sum"),
                    avg_score=("score", "mean"),
                )
                .reset_index()
            )
            sources = by_source.to_dict("records")
            top_rules = (
                hits.groupby(["rule_id", "source"], dropna=False)
                .agg(total_hits=("id", "count"), avg_score=("score", "mean"))
                .reset_index()
                .sort_values(["total_hits", "avg_score"], ascending=[False, False])
                .head(20)
                .to_dict("records")
            )
            scans = db.get_yara_scan_log(conn, limit=min(limit, 100))
            recent_scans = scans.to_dict("records")
            return {"status": "ok", "sources": sources, "top_rules": top_rules, "recent_scans": recent_scans}
        finally:
            conn.close()
    except Exception as exc:
        return {"status": "error", "reason": str(exc), "sources": []}


def _directory_signature(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: str(item).lower()):
        digest.update(str(path).encode("utf-8", errors="ignore"))
        try:
            stat = path.stat()
            digest.update(str(int(stat.st_mtime)).encode("utf-8"))
            digest.update(str(stat.st_size).encode("utf-8"))
        except Exception:
            continue
    return digest.hexdigest()


def build_update_workflow_report() -> dict[str, Any]:
    inventory = {
        "shadowlab": {"count": len(_shadowlab_rules()), "signature": _directory_signature(_shadowlab_rules())},
        "rules_master": {"count": len(_rules_master_rules()), "signature": _directory_signature(_rules_master_rules())},
        "signature_base": {"count": len(_signature_base_rules()), "signature": _directory_signature(_signature_base_rules())},
    }
    policy = load_policy()
    policy_signature = hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest()
    last_snapshot: dict[str, Any] = {}
    try:
        import database as db

        conn = db.create_connection()
        if conn:
            try:
                raw = db.get_app_setting(conn, "local_yara_update_snapshot_json")
                last_snapshot = json.loads(raw) if raw else {}
            except Exception:
                last_snapshot = {}
            finally:
                conn.close()
    except Exception:
        last_snapshot = {}
    return {
        "status": "ok",
        "inventory": inventory,
        "policy_signature": policy_signature,
        "last_snapshot": last_snapshot,
        "recommended_steps": [
            "Refresh community repositories outside production first.",
            "Compare inventory signatures and compile-error drift before promotion.",
            "Reapply local policy and registry tuning after community updates.",
        ],
    }


def save_update_snapshot() -> dict[str, Any]:
    report = build_update_workflow_report()
    try:
        import database as db

        conn = db.create_connection()
        if conn:
            try:
                db.set_app_setting(conn, "local_yara_update_snapshot_json", json.dumps(report, ensure_ascii=False))
            finally:
                conn.close()
    except Exception:
        return report
    return report


def build_health_report() -> dict[str, Any]:
    packs = available_packs()
    pack_counts = {name: len(paths) for name, paths in packs.items()}
    selected = packs.get("enterprise") or []
    compiled, loaded, errors = _compile_cached(_file_signature(selected)) if selected else (None, [], [])
    policy = _load_policy()
    return {
        "status": "ok",
        "policy_path": str(POLICY_PATH),
        "policy_loaded": bool(policy),
        "allowlist_hash_count": len(_trusted_hashes()),
        "allowlist_path_count": len(_trusted_path_prefixes()),
        "allowlist_rule_pattern_count": len(_allowlisted_rule_patterns()),
        "suppressed_rule_pattern_count": len(_suppressed_rule_patterns()),
        "boosted_rule_pattern_count": len(_boosted_rule_patterns()),
        "pack_counts": pack_counts,
        "enterprise_rules_requested": len(selected),
        "enterprise_rules_loaded": len(loaded),
        "compile_error_count": len(errors),
        "compile_errors": errors[:25],
        "compiler_ready": compiled is not None,
    }
