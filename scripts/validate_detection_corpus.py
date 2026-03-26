from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.static_pe_service import StaticPEAnalysisService
import threat_intelligence

DEFAULT_MANIFEST = ROOT / "config" / "detection_validation_corpus.json"


def load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Validation corpus manifest must be a JSON object")
    payload.setdefault("samples", [])
    return payload


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, sample in enumerate(manifest.get("samples", [])):
        if not isinstance(sample, dict):
            errors.append(f"sample[{index}] is not an object")
            continue
        for key in ("id", "path", "yara_pack"):
            if not str(sample.get(key, "")).strip():
                errors.append(f"sample[{index}] missing `{key}`")
    return errors


def evaluate_sample(sample: dict[str, Any], static_service: StaticPEAnalysisService | None = None) -> dict[str, Any]:
    target = Path(str(sample.get("path", "")))
    if not target.exists():
        return {"id": sample.get("id", ""), "status": "missing", "path": str(target)}

    yara_pack = str(sample.get("yara_pack", "enterprise") or "enterprise")
    yara_result = threat_intelligence.run_local_yara_scan(str(target), pack=yara_pack)
    expected_rules = [str(item) for item in sample.get("expected_rules_any", []) if str(item).strip()]
    matched_rules = [str(item) for item in yara_result.get("matched_rules", []) if str(item).strip()]
    expected_hit = any(rule in matched_rules for rule in expected_rules) if expected_rules else True

    static_service = static_service or StaticPEAnalysisService()
    static_result = static_service.analyze_file(str(target))
    static_score = 0
    if isinstance(static_result, dict):
        risk = static_result.get("risk", {}) if isinstance(static_result.get("risk"), dict) else {}
        static_score = int(risk.get("score", 0) or 0)
    expected_static_min = int(sample.get("expected_static_min_score", 0) or 0)
    static_ok = static_score >= expected_static_min

    status = "passed" if expected_hit and static_ok else "failed"
    return {
        "id": sample.get("id", ""),
        "path": str(target),
        "status": status,
        "kind": sample.get("kind", "file"),
        "yara_pack": yara_pack,
        "expected_rules_any": expected_rules,
        "matched_rules": matched_rules,
        "expected_static_min_score": expected_static_min,
        "static_score": static_score,
        "yara_status": yara_result.get("status", ""),
    }


def run_validation(manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    errors = validate_manifest(manifest)
    if errors:
        return {"status": "invalid", "errors": errors, "manifest_path": str(manifest_path)}

    static_service = StaticPEAnalysisService()
    results = [evaluate_sample(sample, static_service) for sample in manifest.get("samples", [])]
    passed = sum(1 for item in results if item.get("status") == "passed")
    missing = sum(1 for item in results if item.get("status") == "missing")
    failed = sum(1 for item in results if item.get("status") == "failed")
    status = "ok" if failed == 0 else "failed"
    return {
        "status": status,
        "manifest_path": str(manifest_path),
        "summary": {
            "total": len(results),
            "passed": passed,
            "missing": missing,
            "failed": failed,
        },
        "results": results,
    }


def main() -> None:
    result = run_validation(DEFAULT_MANIFEST)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("status") in {"failed", "invalid"}:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
