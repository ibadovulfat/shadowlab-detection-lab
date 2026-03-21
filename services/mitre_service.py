from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import time
from typing import Any


class MitreAttackService:
    def __init__(self, base_dir: Path, db_module) -> None:
        self.base_dir = Path(base_dir)
        self.db = db_module
        self.out_dir = self.base_dir / "shadowlab_out" / "mitre"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._bundle_path: str = ""
        self._bundle_source: str = ""
        self._bundle_loaded_at: float = 0.0
        self._bundle_id: str = ""
        self._bundle_version: str = ""
        self._bundle_modified: str = ""
        self._bundle_domain: str = "enterprise-attack"
        self._bundle_sha256: str = ""
        self._bundle_object_counts: dict[str, int] = {}
        self._objects: list[dict[str, Any]] = []
        self._by_stix_id: dict[str, dict[str, Any]] = {}
        self._techniques_by_attack_id: dict[str, dict[str, Any]] = {}
        self._tactics_by_shortname: dict[str, dict[str, Any]] = {}
        self._relationships_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._relationships_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._official_reference_paths = [
            Path("C:/Users/ulfat/Documents/mitreattack-python-main/tests/resources/enterprise-bundle.json"),
            Path("C:/Users/ulfat/Documents/mitreattack-python-main/tests/resources/changelog-v16.1_to_v17.0/changelog.json"),
            Path("C:/Users/ulfat/Documents/attack-navigator-master/layers/samples/heatmap_layer.json"),
        ]
        self._allowed_roots = [self.base_dir, self.out_dir]
        self._allowed_roots.extend(path.parent if path.suffix else path for path in self._official_reference_paths)
        self._discovery_cache: list[dict[str, Any]] = []
        self._discovery_cached_at = 0.0
        self._discovery_cache_ttl_seconds = 30.0
        self._inference_rules = self._build_inference_rules()
        self._autoload_saved_bundle()

    def status(self) -> dict[str, Any]:
        discovered = self.discover_bundle_sources()
        active = next((item for item in discovered if item.get("path") == self._bundle_path), None)
        return {
            "loaded": bool(self._techniques_by_attack_id),
            "bundle_path": self._bundle_path,
            "bundle_source": self._bundle_source,
            "loaded_at": self._bundle_loaded_at,
            "bundle_id": self._bundle_id,
            "bundle_version": self._bundle_version,
            "bundle_modified": self._bundle_modified,
            "bundle_domain": self._bundle_domain,
            "bundle_sha256": self._bundle_sha256,
            "technique_count": len(self._techniques_by_attack_id),
            "tactic_count": len(self._tactics_by_shortname),
            "object_counts": dict(self._bundle_object_counts),
            "reference_paths": [str(path) for path in self._official_reference_paths if path.exists()],
            "discovered_bundles": discovered[:12],
            "active_bundle_diff": self.compare_bundle(self._bundle_path) if active else {},
        }

    def discover_bundle_sources(self) -> list[dict[str, Any]]:
        now = time.time()
        if self._discovery_cache and (now - self._discovery_cached_at) < self._discovery_cache_ttl_seconds:
            return [dict(item) for item in self._discovery_cache]
        candidates: list[Path] = []
        search_roots = []
        for root in self._allowed_roots:
            try:
                resolved = root.resolve()
            except Exception:
                continue
            if resolved not in search_roots:
                search_roots.append(resolved)
        seen: set[str] = set()
        for root in search_roots:
            if not root.exists():
                continue
            if root.is_file() and root.suffix.lower() == ".json":
                candidates.append(root)
                continue
            for pattern in ("*bundle*.json", "*enterprise*.json", "*changelog*.json"):
                for item in root.rglob(pattern):
                    if item.is_file() and item.suffix.lower() == ".json":
                        candidates.append(item)
        discovered: list[dict[str, Any]] = []
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            meta = self._bundle_file_metadata(path)
            if meta:
                discovered.append(meta)
        discovered.sort(key=lambda item: (str(item.get("version", "")), str(item.get("modified", "")), str(item.get("path", ""))), reverse=True)
        self._discovery_cache = [dict(item) for item in discovered]
        self._discovery_cached_at = now
        return [dict(item) for item in discovered]

    def load_bundle(self, file_path: str, *, source: str = "manual") -> dict[str, Any]:
        path = self._resolve_allowed_json_path(file_path)
        payload = self._load_json_file(path)
        objects = payload.get("objects", []) if isinstance(payload, dict) else []
        if not isinstance(objects, list):
            raise ValueError("ATT&CK STIX bundle must contain an objects list")
        self._hydrate(payload, objects, bundle_path=str(path), source=source)
        self._persist_bundle_reference(str(path))
        return self.status()

    def compare_bundle(self, file_path: str) -> dict[str, Any]:
        candidate = str(file_path or "").strip()
        if not candidate:
            return {}
        path = self._resolve_allowed_json_path(candidate)
        payload = self._load_json_file(path)
        objects = payload.get("objects", []) if isinstance(payload, dict) else []
        if not isinstance(objects, list):
            raise ValueError("ATT&CK STIX bundle must contain an objects list")
        candidate_techniques: dict[str, dict[str, Any]] = {}
        candidate_counts = Counter()
        candidate_version = ""
        candidate_modified = ""
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = str(obj.get("type", "")).strip()
            if obj_type:
                candidate_counts[obj_type] += 1
            if not candidate_version:
                candidate_version = str(obj.get("x_mitre_version", "") or candidate_version)
            candidate_modified = max(candidate_modified, str(obj.get("modified", "") or ""))
            if obj_type == "attack-pattern":
                attack_id = self._attack_id(obj)
                if attack_id:
                    candidate_techniques[attack_id] = obj
        current_ids = set(self._techniques_by_attack_id)
        candidate_ids = set(candidate_techniques)
        modified = []
        for attack_id in sorted(current_ids & candidate_ids):
            current_obj = self._techniques_by_attack_id[attack_id]
            candidate_obj = candidate_techniques[attack_id]
            if str(current_obj.get("modified", "")) != str(candidate_obj.get("modified", "")) or str(current_obj.get("name", "")) != str(candidate_obj.get("name", "")):
                modified.append(
                    {
                        "technique_id": attack_id,
                        "current_modified": str(current_obj.get("modified", "")),
                        "candidate_modified": str(candidate_obj.get("modified", "")),
                        "name": str(candidate_obj.get("name", "")),
                    }
                )
        return {
            "path": str(path),
            "candidate_version": candidate_version,
            "candidate_modified": candidate_modified,
            "candidate_counts": dict(candidate_counts),
            "new_techniques": sorted(candidate_ids - current_ids)[:50],
            "retired_or_missing": sorted(current_ids - candidate_ids)[:50],
            "modified_techniques": modified[:50],
        }

    def changelog_summary(self, file_path: str) -> dict[str, Any]:
        path = self._resolve_allowed_json_path(file_path)
        payload = self._load_json_file(path)
        if not isinstance(payload, dict):
            raise ValueError("Changelog payload must be a JSON object")
        summary: dict[str, Any] = {"path": str(path), "sections": {}}
        for key, value in payload.items():
            if isinstance(value, list):
                summary["sections"][key] = len(value)
        summary["raw_keys"] = sorted(payload.keys())
        return summary

    def technique_details(self, attack_id: str) -> dict[str, Any]:
        normalized_id = str(attack_id or "").strip().upper()
        technique = self._techniques_by_attack_id.get(normalized_id)
        if not technique:
            raise KeyError(f"Unknown ATT&CK technique: {normalized_id}")
        return self._technique_view(technique)

    def incident_coverage(self, incident_id: str) -> dict[str, Any]:
        incident = self._get_incident(incident_id)
        explicit = self._safe_json_list(incident.get("mitre_mapping"))
        inferred = self._infer_techniques_for_incident(incident)
        combined = list(dict.fromkeys(explicit + inferred))
        tactic_list = self._safe_json_list(incident.get("attack_chain"))
        techniques = [self._technique_view(self._techniques_by_attack_id[item]) for item in combined if item in self._techniques_by_attack_id]
        missing = [item for item in combined if item not in self._techniques_by_attack_id]
        coverage_summary = self._coverage_summary(techniques, tactic_list=tactic_list)
        return {
            "incident_id": incident_id,
            "title": str(incident.get("title", "")),
            "severity": str(incident.get("severity", "")),
            "attack_chain": tactic_list,
            "explicit_mapped_techniques": explicit,
            "inferred_techniques": inferred,
            "mapped_techniques": combined,
            "known_techniques": techniques,
            "missing_techniques": missing,
            "coverage_summary": coverage_summary,
            "telemetry_cues": self._incident_cues(incident),
        }

    def case_coverage(self, case_id: int) -> dict[str, Any]:
        incident_ids = self._case_incident_ids(case_id)
        if not incident_ids:
            return {
                "case_id": int(case_id),
                "incident_ids": [],
                "techniques": [],
                "mapped_techniques": [],
                "coverage_summary": self._coverage_summary([], tactic_list=[]),
            }
        return self._aggregate_coverages(incident_ids=incident_ids, case_id=int(case_id))

    def enterprise_summary(self, *, limit: int = 50) -> dict[str, Any]:
        conn = self.db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            incidents = self.db.get_incidents(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        recent = incidents[: max(1, int(limit))]
        incident_ids = [str(item.get("incident_id", "")).strip() for item in recent if str(item.get("incident_id", "")).strip()]
        summary = self._aggregate_coverages(incident_ids=incident_ids)
        summary["recent_incident_count"] = len(recent)
        summary["dataset_lifecycle"] = self.status()
        coverage_summary = summary.get("coverage_summary", {}) if isinstance(summary.get("coverage_summary"), dict) else {}
        for key, value in coverage_summary.items():
            summary.setdefault(key, value)
        return summary

    def export_navigator_layer(
        self,
        *,
        incident_ids: list[str] | None = None,
        case_id: int | None = None,
        layer_name: str = "",
        description: str = "",
        include_subtechniques: bool = True,
    ) -> dict[str, Any]:
        coverage = self._coverage_bundle(case_id=case_id, incident_ids=incident_ids)
        selected_incident_ids = coverage["incident_ids"]
        if not selected_incident_ids:
            raise ValueError("At least one incident_id or case_id is required to export a Navigator layer")

        techniques = []
        for technique in coverage["techniques"]:
            technique_id = str(technique.get("attack_id", ""))
            score = int(coverage["technique_scores"].get(technique_id, 0))
            techniques.append(
                {
                    "techniqueID": technique_id,
                    "score": min(score, 100),
                    "comment": " | ".join(coverage["technique_comments"].get(technique_id, [])[:4]),
                    "enabled": True,
                    "showSubtechniques": include_subtechniques,
                    "tactic": ",".join(technique.get("tactics", [])),
                    "metadata": [
                        {"name": "Technique", "value": technique.get("name", technique_id)},
                        {"name": "Incidents", "value": str(len(coverage["technique_comments"].get(technique_id, [])))},
                        {"name": "Mitigations", "value": ", ".join(item.get("name", "") for item in technique.get("mitigations", [])[:4]) or "None"},
                    ],
                }
            )

        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = layer_name.strip() or f"ShadowLab ATT&CK Coverage {stamp}"
        payload = {
            "name": name,
            "description": description.strip() or f"Navigator layer exported by ShadowLab for incidents: {', '.join(selected_incident_ids)}",
            "domain": self._bundle_domain,
            "versions": {"attack": self._bundle_version or "unknown", "navigator": "4.8.0", "layer": "4.4"},
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True, "showAggregateScores": True, "aggregateFunction": "sum"},
            "techniques": techniques,
            "gradient": {"colors": ["#ffe8a3", "#ff9f43", "#d64550"], "minValue": 0, "maxValue": 100},
            "legendItems": [
                {"label": "Observed in ShadowLab", "color": "#ff9f43"},
                {"label": "High-confidence / repeated", "color": "#d64550"},
            ],
            "metadata": [
                {"name": "Source", "value": "ShadowLab MITRE export"},
                {"name": "Bundle Version", "value": self._bundle_version or "unknown"},
                {"name": "Incident Count", "value": str(len(selected_incident_ids))},
            ],
        }
        target = self.out_dir / f"navigator-layer-{stamp}.json"
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"saved_path": str(target), "technique_count": len(techniques), "incident_ids": selected_incident_ids, "layer": payload}

    def workbench_export(self, *, case_id: int | None = None, incident_ids: list[str] | None = None) -> dict[str, Any]:
        coverage_items = self._coverage_bundle(case_id=case_id, incident_ids=incident_ids)
        notes = []
        relationships = []
        for technique in coverage_items["techniques"]:
            attack_id = str(technique.get("attack_id", ""))
            notes.append(
                {
                    "type": "note",
                    "id": f"note--shadowlab-{attack_id.lower()}",
                    "abstract": f"ShadowLab coverage for {attack_id}",
                    "content": f"{technique.get('name', attack_id)} observed in ShadowLab enterprise workflow.",
                    "object_refs": [str(technique.get("stix_id", ""))],
                    "labels": ["shadowlab", "attack-workbench"],
                }
            )
            for mitigation in technique.get("mitigations", [])[:3]:
                relationships.append(
                    {
                        "source_attack_id": attack_id,
                        "target_name": mitigation.get("name", ""),
                        "relationship_type": "mitigates",
                    }
                )
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        payload = {
            "workspace": {
                "bundle_path": self._bundle_path,
                "bundle_version": self._bundle_version,
                "generated_at": stamp,
                "domain": self._bundle_domain,
            },
            "coverage": coverage_items,
            "notes": notes,
            "relationship_hints": relationships,
        }
        target = self.out_dir / f"workbench-coverage-{stamp}.json"
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"saved_path": str(target), "workspace": payload["workspace"], "technique_count": len(coverage_items["techniques"])}

    def _autoload_saved_bundle(self) -> None:
        conn = self.db.create_connection()
        if conn is None:
            return
        try:
            saved = self.db.get_app_setting(conn, "mitre_attack_bundle_path")
        finally:
            conn.close()
        for candidate in [saved, *[str(path) for path in self._official_reference_paths if path.exists() and "bundle" in path.name.lower()]]:
            if not candidate:
                continue
            path = Path(candidate).expanduser()
            if path.exists() and path.is_file():
                try:
                    self.load_bundle(str(path), source="persisted")
                    self._invalidate_discovery_cache()
                    return
                except Exception:
                    continue

    def _persist_bundle_reference(self, file_path: str) -> None:
        conn = self.db.create_connection()
        if conn is None:
            return
        try:
            self.db.set_app_setting(conn, "mitre_attack_bundle_path", file_path)
        finally:
            conn.close()
        self._invalidate_discovery_cache()

    def _hydrate(self, payload: dict[str, Any], objects: list[dict[str, Any]], *, bundle_path: str, source: str) -> None:
        self._objects = [item for item in objects if isinstance(item, dict)]
        self._bundle_path = bundle_path
        self._bundle_source = source
        self._bundle_loaded_at = time.time()
        self._bundle_id = str(payload.get("id", ""))
        self._bundle_version = ""
        self._bundle_modified = ""
        self._bundle_domain = "enterprise-attack"
        self._bundle_sha256 = hashlib.sha256(Path(bundle_path).read_bytes()).hexdigest() if Path(bundle_path).exists() else ""
        self._bundle_object_counts = dict(Counter(str(obj.get("type", "")).strip() for obj in self._objects if str(obj.get("type", "")).strip()))
        self._by_stix_id = {}
        self._techniques_by_attack_id = {}
        self._tactics_by_shortname = {}
        self._relationships_by_target = defaultdict(list)
        self._relationships_by_source = defaultdict(list)

        for obj in self._objects:
            stix_id = str(obj.get("id", "")).strip()
            if stix_id:
                self._by_stix_id[stix_id] = obj
            obj_type = str(obj.get("type", "")).strip()
            self._bundle_version = str(obj.get("x_mitre_version", "") or self._bundle_version)
            self._bundle_modified = max(self._bundle_modified, str(obj.get("modified", "") or ""))
            domains = obj.get("x_mitre_domains", []) if isinstance(obj.get("x_mitre_domains", []), list) else []
            if domains and self._bundle_domain == "enterprise-attack":
                self._bundle_domain = str(domains[0])
            if obj_type == "relationship":
                source_ref = str(obj.get("source_ref", "")).strip()
                target_ref = str(obj.get("target_ref", "")).strip()
                if source_ref and target_ref:
                    self._relationships_by_source[source_ref].append(obj)
                    self._relationships_by_target[target_ref].append(obj)
            elif obj_type == "x-mitre-tactic":
                shortname = str(obj.get("x_mitre_shortname", "")).strip()
                if shortname:
                    self._tactics_by_shortname[shortname] = obj
            elif obj_type == "attack-pattern":
                attack_id = self._attack_id(obj)
                if attack_id:
                    self._techniques_by_attack_id[attack_id] = obj

    def _attack_id(self, obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []) if isinstance(obj.get("external_references", []), list) else []:
            if not isinstance(ref, dict):
                continue
            source_name = str(ref.get("source_name", "")).lower()
            external_id = str(ref.get("external_id", "")).strip().upper()
            if source_name.startswith("mitre-attack") and external_id.startswith("T"):
                return external_id
        return ""

    def _technique_view(self, technique: dict[str, Any]) -> dict[str, Any]:
        attack_id = self._attack_id(technique)
        relationships = self._relationships_by_target.get(str(technique.get("id", "")), [])
        mitigations = []
        software = []
        groups = []
        campaigns = []
        parent = None
        subtechniques = []
        for rel in relationships:
            rel_type = str(rel.get("relationship_type", "")).strip()
            source_obj = self._by_stix_id.get(str(rel.get("source_ref", "")))
            if not source_obj:
                continue
            source_type = str(source_obj.get("type", "")).strip()
            if rel_type == "mitigates" and source_type == "course-of-action":
                mitigations.append(self._related_object_view(source_obj))
            elif rel_type == "uses" and source_type in {"tool", "malware"}:
                software.append(self._related_object_view(source_obj))
            elif rel_type == "uses" and source_type == "intrusion-set":
                groups.append(self._related_object_view(source_obj))
            elif rel_type == "uses" and source_type == "campaign":
                campaigns.append(self._related_object_view(source_obj))
            elif rel_type == "subtechnique-of" and source_type == "attack-pattern":
                parent = self._related_object_view(source_obj)
        for rel in self._relationships_by_source.get(str(technique.get("id", "")), []):
            if str(rel.get("relationship_type", "")).strip() != "subtechnique-of":
                continue
            target_obj = self._by_stix_id.get(str(rel.get("target_ref", "")))
            if target_obj:
                subtechniques.append(self._related_object_view(target_obj))
        tactics = [str(item.get("phase_name", "")).strip() for item in technique.get("kill_chain_phases", []) if isinstance(item, dict)]
        return {
            "attack_id": attack_id,
            "stix_id": str(technique.get("id", "")),
            "name": str(technique.get("name", "")),
            "description": str(technique.get("description", "")),
            "platforms": [str(item) for item in technique.get("x_mitre_platforms", []) if str(item).strip()],
            "data_sources": [str(item) for item in technique.get("x_mitre_data_sources", []) if str(item).strip()],
            "detection": str(technique.get("x_mitre_detection", "")),
            "domains": [str(item) for item in technique.get("x_mitre_domains", []) if str(item).strip()],
            "is_subtechnique": bool(technique.get("x_mitre_is_subtechnique", False)),
            "tactics": tactics,
            "mitigations": mitigations,
            "software": software,
            "groups": groups,
            "campaigns": campaigns,
            "parent_technique": parent,
            "subtechniques": subtechniques,
        }

    def _related_object_view(self, obj: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(obj.get("id", "")),
            "name": str(obj.get("name", "")),
            "type": str(obj.get("type", "")),
            "attack_id": self._attack_id(obj),
        }

    def _coverage_summary(self, techniques: list[dict[str, Any]], *, tactic_list: list[str]) -> dict[str, Any]:
        technique_ids = [str(item.get("attack_id", "")) for item in techniques if str(item.get("attack_id", "")).strip()]
        tactic_counter = Counter(tactic_list)
        if not tactic_counter:
            tactic_counter.update(
                tactic
                for technique in techniques
                for tactic in technique.get("tactics", [])
                if str(tactic).strip()
            )
        mitigation_counter = Counter(item.get("name", "") for technique in techniques for item in technique.get("mitigations", []))
        software_counter = Counter(item.get("name", "") for technique in techniques for item in technique.get("software", []))
        group_counter = Counter(item.get("name", "") for technique in techniques for item in technique.get("groups", []))
        parent_counter = Counter(str(item.get("parent_technique", {}).get("attack_id", "")) for item in techniques if item.get("parent_technique"))
        tactic_heat = [{"name": name, "count": count, "score": min(100, count * 18)} for name, count in tactic_counter.most_common(12)]
        progression = [item["name"] for item in tactic_heat]
        return {
            "technique_count": len(set(technique_ids)),
            "top_tactics": [{"name": name, "count": count} for name, count in tactic_counter.most_common(10)],
            "top_mitigations": [{"name": name, "count": count} for name, count in mitigation_counter.most_common(10) if name],
            "top_software": [{"name": name, "count": count} for name, count in software_counter.most_common(10) if name],
            "top_groups": [{"name": name, "count": count} for name, count in group_counter.most_common(10) if name],
            "subtechnique_count": len([item for item in techniques if item.get("is_subtechnique")]),
            "parent_technique_rollup": [{"attack_id": attack_id, "count": count} for attack_id, count in parent_counter.most_common(10) if attack_id],
            "tactic_heat": tactic_heat,
            "tactic_progression": progression,
        }

    def _severity_score(self, severity: str) -> int:
        return {"critical": 100, "high": 80, "medium": 55, "low": 30, "info": 10}.get(severity.lower(), 40)

    def _safe_json_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value or "").strip()
        if not text:
            return []
        try:
            loaded = json.loads(text)
        except Exception:
            return []
        if not isinstance(loaded, list):
            return []
        return [str(item).strip() for item in loaded if str(item).strip()]

    def _load_json_file(self, path: Path) -> dict[str, Any]:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"ATT&CK bundle not found: {path}")
        if path.suffix.lower() != ".json":
            raise ValueError(f"ATT&CK resources must be JSON files: {path}")
        if path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError(f"ATT&CK resource is too large to load safely: {path}")
        raw = path.read_bytes()
        text = ""
        for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if not text:
            raise ValueError(f"Unable to decode JSON file: {path}")
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")
        return payload

    def _resolve_allowed_json_path(self, file_path: str) -> Path:
        path = Path(str(file_path or "").strip()).expanduser().resolve()
        if not str(path).strip():
            raise ValueError("A JSON file path is required")
        for root in self._allowed_roots:
            try:
                resolved_root = root.resolve()
            except Exception:
                continue
            try:
                path.relative_to(resolved_root)
                return path
            except ValueError:
                continue
        raise ValueError(f"Path is outside approved ATT&CK locations: {path}")

    def _invalidate_discovery_cache(self) -> None:
        self._discovery_cache = []
        self._discovery_cached_at = 0.0

    def _bundle_file_metadata(self, path: Path) -> dict[str, Any] | None:
        try:
            payload = self._load_json_file(path)
        except Exception:
            return None
        objects = payload.get("objects", []) if isinstance(payload, dict) else []
        if not isinstance(objects, list):
            return None
        version = ""
        modified = ""
        domain = "enterprise-attack"
        counts = Counter()
        technique_count = 0
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = str(obj.get("type", "")).strip()
            if obj_type:
                counts[obj_type] += 1
            if obj_type == "attack-pattern" and self._attack_id(obj):
                technique_count += 1
            version = str(obj.get("x_mitre_version", "") or version)
            modified = max(modified, str(obj.get("modified", "") or ""))
            domains = obj.get("x_mitre_domains", []) if isinstance(obj.get("x_mitre_domains", []), list) else []
            if domains:
                domain = str(domains[0])
        return {
            "path": str(path.resolve()),
            "bundle_id": str(payload.get("id", "")),
            "version": version,
            "modified": modified,
            "domain": domain,
            "technique_count": technique_count,
            "object_counts": dict(counts),
        }

    def _get_incident(self, incident_id: str) -> dict[str, Any]:
        conn = self.db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            incident = self.db.get_incident_by_id(conn, incident_id)
        finally:
            conn.close()
        if not incident:
            raise KeyError(f"Incident not found: {incident_id}")
        return incident

    def _case_incident_ids(self, case_id: int) -> list[str]:
        conn = self.db.create_connection()
        if conn is None:
            raise RuntimeError("Database unavailable")
        try:
            cases = self.db.get_case_records(conn).fillna("").to_dict(orient="records")
        finally:
            conn.close()
        case_row = next((item for item in cases if int(item.get("id", 0) or 0) == int(case_id)), None)
        if not case_row:
            raise KeyError(f"Case not found: {case_id}")
        incident_id = str(case_row.get("incident_id", "")).strip()
        return [incident_id] if incident_id else []

    def _aggregate_coverages(self, *, incident_ids: list[str], case_id: int | None = None) -> dict[str, Any]:
        techniques_by_id: dict[str, dict[str, Any]] = {}
        tactic_list: list[str] = []
        explicit_ids: list[str] = []
        inferred_ids: list[str] = []
        cue_counter = Counter()
        for incident_id in incident_ids:
            coverage = self.incident_coverage(incident_id)
            tactic_list.extend(coverage.get("attack_chain", []))
            explicit_ids.extend(coverage.get("explicit_mapped_techniques", []))
            inferred_ids.extend(coverage.get("inferred_techniques", []))
            for cue in coverage.get("telemetry_cues", []):
                cue_counter[cue] += 1
            for technique in coverage.get("known_techniques", []):
                techniques_by_id[str(technique.get("attack_id", ""))] = technique
        techniques = list(techniques_by_id.values())
        coverage_summary = self._coverage_summary(techniques, tactic_list=tactic_list)
        top_techniques = Counter(explicit_ids + inferred_ids).most_common(10)
        coverage_summary["top_mapped_techniques"] = [
            {
                "technique_id": technique_id,
                "name": techniques_by_id.get(technique_id, {}).get("name", technique_id),
                "count": count,
            }
            for technique_id, count in top_techniques
            if technique_id
        ]
        coverage_summary["telemetry_cue_hotspots"] = [{"cue": cue, "count": count} for cue, count in cue_counter.most_common(12)]
        return {
            "case_id": case_id,
            "incident_ids": incident_ids,
            "techniques": techniques,
            "mapped_techniques": list(dict.fromkeys(explicit_ids + inferred_ids)),
            "explicit_mapped_techniques": list(dict.fromkeys(explicit_ids)),
            "inferred_techniques": list(dict.fromkeys(inferred_ids)),
            "coverage_summary": coverage_summary,
        }

    def _coverage_bundle(self, *, case_id: int | None = None, incident_ids: list[str] | None = None) -> dict[str, Any]:
        selected_incident_ids = [str(item).strip() for item in (incident_ids or []) if str(item).strip()]
        if case_id is not None:
            selected_incident_ids.extend(self._case_incident_ids(int(case_id)))
        selected_incident_ids = list(dict.fromkeys(selected_incident_ids))
        aggregated = self._aggregate_coverages(incident_ids=selected_incident_ids, case_id=case_id)
        technique_counter: Counter[str] = Counter()
        comments: dict[str, list[str]] = defaultdict(list)
        for incident_id in selected_incident_ids:
            coverage = self.incident_coverage(incident_id)
            title = str(coverage.get("title", incident_id))
            severity = str(coverage.get("severity", "medium")).lower()
            base_score = self._severity_score(severity)
            for technique_id in coverage.get("mapped_techniques", []):
                if technique_id not in self._techniques_by_attack_id:
                    continue
                technique_counter[technique_id] += base_score
                comments[technique_id].append(f"{incident_id}: {title}")
        aggregated["technique_scores"] = dict(technique_counter)
        aggregated["technique_comments"] = comments
        return aggregated

    def _incident_cues(self, incident: dict[str, Any]) -> list[str]:
        tokens = []
        blob = self._incident_blob(incident)
        for label, patterns in {
            "command_execution": ["powershell", "cmd.exe", "wscript", "mshta", "rundll32"],
            "payload_download": ["http://", "https://", "curl", "bitsadmin", "download"],
            "credential_access": ["lsass", "sekurlsa", "sam", "hashdump"],
            "persistence": ["run key", "scheduled task", "startup", "service", "syscheck"],
            "defense_evasion": ["disable", "defender", "tamper", "encodedcommand", "base64"],
            "lateral_movement": ["psexec", "wmic", "remote desktop", "ssh", "winrm"],
            "exfiltration": ["upload", "exfil", "webhook", "dns", "ftp"],
        }.items():
            if any(pattern in blob for pattern in patterns):
                tokens.append(label)
        return tokens

    def _incident_blob(self, incident: dict[str, Any]) -> str:
        components = [
            str(incident.get("title", "")),
            str(incident.get("summary", "")),
            str(incident.get("notes", "")),
            str(incident.get("recommended_actions", "")),
            str(incident.get("attack_chain", "")),
        ]
        return "\n".join(components).lower()

    def _infer_techniques_for_incident(self, incident: dict[str, Any]) -> list[str]:
        blob = self._incident_blob(incident)
        matched: list[str] = []
        for rule in self._inference_rules:
            if any(pattern in blob for pattern in rule["patterns"]):
                matched.extend(rule["techniques"])
        notes = self._json_loads_safe(str(incident.get("notes", "")))
        if isinstance(notes, dict):
            flattened = self._flatten_values(notes)
            note_blob = "\n".join(flattened).lower()
            for rule in self._inference_rules:
                if any(pattern in note_blob for pattern in rule["patterns"]):
                    matched.extend(rule["techniques"])
        return list(dict.fromkeys(item for item in matched if item in self._techniques_by_attack_id))

    def _build_inference_rules(self) -> list[dict[str, Any]]:
        return [
            {"patterns": ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"], "techniques": ["T1059", "T1218"]},
            {"patterns": ["download", "http://", "https://", "bitsadmin", "invoke-webrequest", "certutil"], "techniques": ["T1105"]},
            {"patterns": ["lsass", "credential", "hashdump", "mimikatz", "sekurlsa"], "techniques": ["T1003"]},
            {"patterns": ["run key", "startup", "scheduled task", "service install", "syscheck"], "techniques": ["T1547", "T1053", "T1543"]},
            {"patterns": ["reg add", "registry", "autorun", "hkcu\\software\\microsoft\\windows\\currentversion\\run"], "techniques": ["T1112", "T1547"]},
            {"patterns": ["psexec", "wmic", "remote service", "winrm", "rdp", "ssh"], "techniques": ["T1021"]},
            {"patterns": ["defender", "disable", "tamper", "exclude", "firewall stop"], "techniques": ["T1562"]},
            {"patterns": ["inject", "create remote thread", "process hollow", "reflective"], "techniques": ["T1055"]},
            {"patterns": ["dns", "beacon", "c2", "webhook", "outbound", "socket"], "techniques": ["T1071", "T1041"]},
            {"patterns": ["encodedcommand", "base64", "obfusc", "packed"], "techniques": ["T1027"]},
            {"patterns": ["tasklist", "whoami", "net user", "query user", "ipconfig"], "techniques": ["T1057", "T1082"]},
            {"patterns": ["rename", "masquerad", "svchost.exe", "explorer.exe"], "techniques": ["T1036"]},
        ]

    def _flatten_values(self, value: Any) -> list[str]:
        if isinstance(value, dict):
            flattened: list[str] = []
            for item in value.values():
                flattened.extend(self._flatten_values(item))
            return flattened
        if isinstance(value, list):
            flattened = []
            for item in value:
                flattened.extend(self._flatten_values(item))
            return flattened
        text = str(value or "").strip()
        return [text] if text else []

    def _json_loads_safe(self, value: str) -> Any:
        try:
            return json.loads(value)
        except Exception:
            return {}
