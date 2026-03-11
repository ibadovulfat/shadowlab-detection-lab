from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from core.models import DetectionFinding


@dataclass(slots=True)
class RuleEvaluationContext:
    metrics: dict[str, float]


class RuleEngine:
    def __init__(self, rules_path: str | Path | None = None):
        base_dir = Path(__file__).resolve().parent
        self.rules_path = Path(rules_path) if rules_path else base_dir / "default_rules.yaml"
        self.rules = self._load_rules()

    def evaluate(self, metrics: dict[str, float]) -> list[DetectionFinding]:
        context = RuleEvaluationContext(metrics=metrics)
        findings: list[DetectionFinding] = []
        for rule in self.rules:
            if self._matches(rule.get("when", {}), context):
                findings.append(
                    DetectionFinding(
                        rule_id=str(rule.get("id", "unknown_rule")),
                        title=str(rule.get("title", "Detection Rule")),
                        severity=str(rule.get("severity", "low")),
                        score=float(rule.get("score", 0.0)),
                        summary=str(rule.get("summary", "")),
                        evidence={"metrics": metrics},
                        mitre_techniques=list(rule.get("tags", [])),
                    )
                )
        return findings

    def _load_rules(self) -> list[dict[str, Any]]:
        with self.rules_path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or []
        if not isinstance(loaded, list):
            raise ValueError("Detection rules file must contain a list of rules.")
        return loaded

    def _matches(self, condition: dict[str, Any], context: RuleEvaluationContext) -> bool:
        if not condition:
            return False
        if "all" in condition:
            return all(self._matches(item, context) for item in condition["all"])
        if "any" in condition:
            return any(self._matches(item, context) for item in condition["any"])

        metric_name = condition.get("metric")
        metric_value = float(context.metrics.get(str(metric_name), 0.0))
        if "gte" in condition and metric_value < float(condition["gte"]):
            return False
        if "lte" in condition and metric_value > float(condition["lte"]):
            return False
        if "gt" in condition and metric_value <= float(condition["gt"]):
            return False
        if "lt" in condition and metric_value >= float(condition["lt"]):
            return False
        return True

