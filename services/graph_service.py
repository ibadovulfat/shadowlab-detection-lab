from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from pyvis.network import Network


class GraphService:
    def __init__(self, out_dir: Path):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def build_entity_graph(
        self,
        *,
        hosts: list[dict[str, Any]] | None = None,
        processes: list[dict[str, Any]] | None = None,
        connections: list[dict[str, Any]] | None = None,
        incidents: list[dict[str, Any]] | None = None,
        persistence_items: list[dict[str, Any]] | None = None,
        pid: int | None = None,
    ) -> dict[str, Any]:
        hosts = hosts or []
        processes = processes or []
        connections = connections or []
        incidents = incidents or []
        persistence_items = persistence_items or []

        if pid is not None:
            processes = [proc for proc in processes if int(proc.get("pid", -1) or -1) == pid]
            proc_ids = {int(proc.get("pid", -1) or -1) for proc in processes}
            connections = [conn for conn in connections if int(conn.get("pid", -1) or -1) in proc_ids]
        else:
            processes = self._focus_processes(processes, connections)
            proc_ids = {int(proc.get("pid", -1) or -1) for proc in processes}
            connections = self._focus_connections([conn for conn in connections if int(conn.get("pid", -1) or -1) in proc_ids])
            persistence_items = self._focus_persistence_items(persistence_items)
            incidents = self._focus_incidents(incidents)

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen_nodes: set[str] = set()
        seen_edges: set[tuple[str, str, str]] = set()
        process_risks: list[dict[str, Any]] = []
        remote_exposure: Counter[str] = Counter()
        finding_signals: list[str] = []

        ad_context = self._collect_ad_context()
        domain_node = None
        if ad_context.get("domain"):
            domain_node = self._add_node(
                nodes,
                seen_nodes,
                f"domain:{ad_context['domain']}",
                ad_context["domain"],
                "domain",
                title=f"Directory Domain\nLogon Server: {ad_context.get('logon_server', 'n/a')}",
                color="#5c7cfa",
            )
            for dc in ad_context.get("domain_controllers", []):
                dc_node = self._add_node(
                    nodes,
                    seen_nodes,
                    f"dc:{dc}",
                    dc,
                    "domain_controller",
                    title="Domain Controller",
                    color="#748ffc",
                )
                self._add_edge(edges, seen_edges, domain_node["id"], dc_node["id"], "serviced_by", "#5c7cfa")

        current_user = ad_context.get("user") or os.environ.get("USERNAME") or "unknown-user"
        user_node = self._add_node(
            nodes,
            seen_nodes,
            f"user:{current_user}",
            current_user,
            "user",
            title="Interactive User",
            color="#20c997",
        )
        if domain_node:
            self._add_edge(edges, seen_edges, user_node["id"], domain_node["id"], "member_of", "#20c997")

        host_lookup: dict[str, dict[str, Any]] = {}
        for host in hosts:
            host_id = str(host.get("host_id") or host.get("host") or "local-host")
            host_label = str(host.get("host") or host_id)
            host_node = self._add_node(
                nodes,
                seen_nodes,
                f"host:{host_id}",
                host_label,
                "host",
                title=f"{host.get('platform', 'unknown')}\n{host.get('ip_address', 'n/a')}",
                color="#339af0",
            )
            host_lookup[host_label.lower()] = host_node
            self._add_edge(edges, seen_edges, user_node["id"], host_node["id"], "operates", "#20c997")
            if domain_node:
                self._add_edge(edges, seen_edges, host_node["id"], domain_node["id"], "joined_to", "#5c7cfa")

        process_lookup: dict[int, dict[str, Any]] = {}
        for proc in processes[:28]:
            proc_pid = int(proc.get("pid", -1) or -1)
            if proc_pid < 0:
                continue
            proc_name = str(proc.get("name") or f"pid-{proc_pid}")
            risk = self._process_risk(proc, connections)
            process_risks.append(
                {
                    "pid": proc_pid,
                    "name": proc_name,
                    "risk_score": risk,
                    "signature_status": str(proc.get("signature_status", "n/a")),
                }
            )
            proc_node = self._add_node(
                nodes,
                seen_nodes,
                f"proc:{proc_pid}",
                self._short_label(f"{proc_name}\nPID {proc_pid}", 26),
                "process",
                title=(
                    f"Executable: {proc.get('exe', 'n/a')}\n"
                    f"Cmd: {proc.get('cmdline', '')[:180]}\n"
                    f"CPU: {proc.get('cpu_percent', 0)} | MEM: {proc.get('memory_percent', 0)}\n"
                    f"Signature: {proc.get('signature_status', 'n/a')}\n"
                    f"Graph Risk: {risk}"
                ),
                color=self._process_color(proc_name, risk),
                size=self._node_size_for_risk(risk),
                risk_score=risk,
                cluster=self._cluster_for_process(proc_name),
            )
            process_lookup[proc_pid] = proc_node
            parent_pid = int(proc.get("ppid", -1) or -1)
            if parent_pid in process_lookup:
                self._add_edge(edges, seen_edges, process_lookup[parent_pid]["id"], proc_node["id"], "spawned", "#adb5bd")
            if host_lookup:
                first_host = next(iter(host_lookup.values()))
                self._add_edge(edges, seen_edges, first_host["id"], proc_node["id"], "runs", "#339af0")

        for conn in connections[:24]:
            local_addr = str(conn.get("local_addr") or "")
            remote_addr = str(conn.get("remote_addr") or "")
            if not remote_addr:
                continue
            remote_ip = remote_addr.split(":")[0]
            exposure_type = self._remote_exposure_type(remote_ip)
            remote_exposure[exposure_type] += 1
            remote_node = self._add_node(
                nodes,
                seen_nodes,
                f"remote:{remote_ip}",
                self._short_label(remote_ip, 18),
                "remote_ip",
                title=f"Remote Endpoint\n{remote_addr}\nExposure: {exposure_type}",
                color="#fa5252" if exposure_type == "public" else "#f08c00" if exposure_type == "private" else "#868e96",
                cluster=f"remote:{exposure_type}",
            )
            pid_value = int(conn.get("pid", -1) or -1)
            if pid_value in process_lookup:
                self._add_edge(edges, seen_edges, process_lookup[pid_value]["id"], remote_node["id"], "connects_to", "#fa5252")
            elif host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], remote_node["id"], "observed_remote", "#ff8787")
            if local_addr and host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], remote_node["id"], f"socket {local_addr}", "#868e96")

        persistence_groups = self._group_persistence_items(persistence_items)
        for pers_type, items in persistence_groups.items():
            group_node = self._add_node(
                nodes,
                seen_nodes,
                f"persistence-group:{pers_type}",
                f"{self._display_persistence_type(pers_type)}\n{len(items)} items",
                "persistence_group",
                title=self._persistence_group_title(pers_type, items),
                color="#f08c00",
                size=34,
                cluster=f"persistence:{pers_type}",
            )
            if host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], group_node["id"], "persistence_cluster", "#ff922b")
            for item in items[:2]:
                pers_id = f"persistence:{item.get('type')}:{item.get('path')}:{item.get('name')}"
                persistence_name = str(item.get("name") or item.get("type") or "persistence")
                pers_node = self._add_node(
                    nodes,
                    seen_nodes,
                    pers_id,
                    self._short_label(persistence_name, 26),
                    "persistence",
                    title=f"{item.get('type', '')}\n{item.get('path', '')}\n{item.get('content_preview', '')[:180]}",
                    color="#ffb454",
                    cluster=f"persistence:{str(item.get('type') or 'generic').lower()}",
                )
                self._add_edge(edges, seen_edges, group_node["id"], pers_node["id"], "contains", "#ffb454")
                for proc_pid, proc_node in process_lookup.items():
                    proc_name = str(proc_node.get("label", "")).lower()
                    if persistence_name.lower() in proc_name or str(item.get("path", "")).lower() in str(proc_node.get("title", "")).lower():
                        self._add_edge(edges, seen_edges, pers_node["id"], proc_node["id"], "auto_starts", "#ff922b")

        for incident in incidents[:10]:
            incident_id = str(incident.get("incident_id") or "incident")
            sev = str(incident.get("severity", "low")).lower()
            incident_node = self._add_node(
                nodes,
                seen_nodes,
                f"incident:{incident_id}",
                self._short_label(incident_id, 18),
                "incident",
                title=str(incident.get("title") or "Behavioral incident"),
                color="#c92a2a" if sev in {"high", "critical"} else "#fab005",
            )
            if host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], incident_node["id"], "generated", "#c92a2a")
            for proc_pid, proc_node in process_lookup.items():
                if self._incident_matches_process(incident, proc_node):
                    self._add_edge(edges, seen_edges, proc_node["id"], incident_node["id"], "contributes_to", "#c92a2a")
            for tactic in self._safe_json_list(incident.get("attack_chain"))[:10]:
                tactic_node = self._add_node(
                    nodes,
                    seen_nodes,
                    f"tactic:{tactic}",
                    tactic,
                    "attack_tactic",
                    title="ATT&CK Tactic",
                    color="#e64980",
                )
                self._add_edge(edges, seen_edges, incident_node["id"], tactic_node["id"], "maps_to", "#e64980")
            for technique in self._safe_json_list(incident.get("mitre_mapping"))[:10]:
                tech_node = self._add_node(
                    nodes,
                    seen_nodes,
                    f"technique:{technique}",
                    technique,
                    "mitre_technique",
                    title="MITRE Technique",
                    color="#be4bdb",
                )
                self._add_edge(edges, seen_edges, incident_node["id"], tech_node["id"], "evidenced_by", "#be4bdb")

        summary = self._summary(nodes, edges, ad_context, process_risks, remote_exposure)
        finding_signals.extend(summary.get("priority_findings", []))
        html_path = self._render_graph(nodes, edges, pid=pid)
        json_path = self.out_dir / ("ShadowLab_EntityGraph.json" if pid is None else f"ShadowLab_EntityGraph_PID_{pid}.json")
        json_path.write_text(json.dumps({"nodes": nodes, "edges": edges, "summary": summary}, indent=2), encoding="utf-8")

        return {
            "summary": summary,
            "nodes": nodes,
            "edges": edges,
            "html_path": str(html_path),
            "json_path": str(json_path),
            "ad_context": ad_context,
            "priority_findings": finding_signals[:8],
        }

    def build_case_graph(
        self,
        *,
        case_record: dict[str, Any],
        assignments: list[dict[str, Any]] | None = None,
        tasks: list[dict[str, Any]] | None = None,
        activity: list[dict[str, Any]] | None = None,
        pins: list[dict[str, Any]] | None = None,
        notes: list[dict[str, Any]] | None = None,
        stories: list[dict[str, Any]] | None = None,
        hosts: list[dict[str, Any]] | None = None,
        processes: list[dict[str, Any]] | None = None,
        connections: list[dict[str, Any]] | None = None,
        incidents: list[dict[str, Any]] | None = None,
        persistence_items: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        assignments = assignments or []
        tasks = tasks or []
        activity = activity or []
        pins = pins or []
        notes = notes or []
        stories = stories or []
        hosts = hosts or []
        processes = processes or []
        connections = connections or []
        incidents = incidents or []
        persistence_items = persistence_items or []

        focus_terms = self._case_focus_terms(case_record, tasks, activity, pins, notes, stories)
        focus_pids = self._case_focus_pids(case_record, tasks, activity, pins, notes, stories)
        incident_id = str(case_record.get("incident_id") or "").strip().lower()

        filtered_processes = [
            proc for proc in processes
            if self._process_matches_case(proc, focus_terms, focus_pids)
        ]
        if not filtered_processes and focus_pids:
            filtered_processes = [proc for proc in processes if int(proc.get("pid", -1) or -1) in focus_pids]
        if not filtered_processes:
            filtered_processes = processes

        filtered_proc_ids = {int(proc.get("pid", -1) or -1) for proc in filtered_processes}
        filtered_connections = [
            conn for conn in connections
            if int(conn.get("pid", -1) or -1) in filtered_proc_ids or self._text_matches_case(conn, focus_terms)
        ]
        if not filtered_connections:
            filtered_connections = [conn for conn in connections if int(conn.get("pid", -1) or -1) in filtered_proc_ids]

        filtered_incidents = [
            incident for incident in incidents
            if self._incident_matches_case(incident, incident_id, focus_terms)
        ]
        if not filtered_incidents and incident_id:
            filtered_incidents = [incident for incident in incidents if str(incident.get("incident_id", "")).strip().lower() == incident_id]

        filtered_persistence = [
            item for item in persistence_items
            if self._text_matches_case(item, focus_terms)
        ]

        graph = self.build_entity_graph(
            hosts=hosts,
            processes=filtered_processes,
            connections=filtered_connections,
            incidents=filtered_incidents,
            persistence_items=filtered_persistence,
            pid=next(iter(focus_pids)) if len(focus_pids) == 1 else None,
        )
        summary = dict(graph.get("summary", {}))
        summary["case_scope"] = {
            "case_id": int(case_record.get("id", 0) or 0),
            "title": str(case_record.get("title") or ""),
            "incident_id": str(case_record.get("incident_id") or ""),
            "focus_pid_count": len(focus_pids),
            "focus_terms": focus_terms[:12],
            "assignments": len(assignments),
            "open_tasks": sum(1 for task in tasks if str(task.get("status", "todo")).lower() not in {"done", "closed", "resolved"}),
            "pins": len(pins),
            "notes": len(notes),
            "stories": len(stories),
            "activity_events": len(activity),
        }
        priority_findings = list(graph.get("priority_findings", []))
        if focus_pids:
            priority_findings.insert(0, f"Case scope narrowed around {len(focus_pids)} explicit PID indicators.")
        if filtered_incidents:
            priority_findings.insert(0, f"{len(filtered_incidents)} incidents matched the selected case context.")
        graph["summary"] = summary
        graph["case_context"] = summary["case_scope"]
        graph["priority_findings"] = priority_findings[:8]
        return graph

    def _render_graph(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]], pid: int | None = None) -> Path:
        html_path = self.out_dir / ("ShadowLab_EntityGraph.html" if pid is None else f"ShadowLab_EntityGraph_PID_{pid}.html")
        net = Network(height="760px", width="100%", bgcolor="#0f1723", font_color="#eef4fb", directed=True)
        for node in nodes:
            net.add_node(
                node["id"],
                label=node["label"],
                title=node.get("title", ""),
                color=node.get("color", "#74c0fc"),
                shape=self._shape_for_group(node.get("group", "")),
                size=node.get("size", 22),
            )
        for edge in edges:
            net.add_edge(
                edge["from"],
                edge["to"],
                label=edge.get("label", ""),
                color=edge.get("color", "#868e96"),
                width=edge.get("width", 1),
            )
        net.set_options(
            """
            {
              "nodes": { "font": { "face": "Segoe UI", "size": 16 }, "borderWidth": 1, "shadow": true, "scaling": { "min": 16, "max": 42 } },
              "edges": { "arrows": { "to": { "enabled": true, "scaleFactor": 0.6 } }, "smooth": { "type": "dynamic" }, "font": { "size": 10, "strokeWidth": 0 }, "selectionWidth": 2 },
              "layout": { "improvedLayout": true },
              "interaction": { "hover": true, "navigationButtons": true, "keyboard": true, "multiselect": true },
              "physics": {
                "enabled": true,
                "solver": "forceAtlas2Based",
                "forceAtlas2Based": { "gravitationalConstant": -85, "springLength": 220, "springConstant": 0.03, "avoidOverlap": 1 },
                "stabilization": { "enabled": true, "iterations": 160, "fit": true }
              }
            }
            """
        )
        net.write_html(str(html_path), notebook=False)
        html_text = html_path.read_text(encoding="utf-8", errors="ignore")
        html_text = html_text.replace(
            "</body>",
            """
<script>
var legend = document.createElement('div');
legend.innerHTML = '<div style="position:fixed;left:18px;top:18px;z-index:9999;background:rgba(12,18,28,0.92);color:#eef4fb;padding:12px 14px;border:1px solid #2b425b;border-radius:10px;font-family:Segoe UI,Arial,sans-serif;font-size:12px;line-height:1.5;"><b>Enterprise Graph</b><br><span style="color:#74c0fc">Blue</span>: Process / Host<br><span style="color:#fa5252">Red</span>: Public remote exposure<br><span style="color:#f08c00">Orange</span>: Persistence clusters<br><span style="color:#fab005">Gold</span>: Incident nodes</div>';
document.body.appendChild(legend);
window.addEventListener('load', function () {
  setTimeout(function () {
    document.querySelectorAll('.vis-network .vis-loading-bar, .vis-network .vis-loader, #loadingBar').forEach(function (el) {
      el.style.display = 'none';
      el.style.visibility = 'hidden';
      el.style.opacity = '0';
    });
  }, 2500);
});
</script>
</body>
""",
        )
        html_path.write_text(html_text, encoding="utf-8")
        return html_path

    def _collect_ad_context(self) -> dict[str, Any]:
        domain = ""
        logon_server = os.environ.get("LOGONSERVER", "").lstrip("\\")
        user = self._command_output(["whoami"]) or f"{socket.gethostname()}\\{os.environ.get('USERNAME', 'user')}"
        if platform.system() == "Windows":
            domain = self._powershell("(Get-CimInstance Win32_ComputerSystem).Domain")
            if not domain or domain.lower() in {"workgroup", socket.gethostname().lower()}:
                domain = ""
        domain_controllers = self._domain_controllers(domain) if domain else []
        return {
            "domain": domain,
            "logon_server": logon_server,
            "domain_controllers": domain_controllers,
            "user": user.strip(),
        }

    def _domain_controllers(self, domain: str) -> list[str]:
        if not domain or not shutil.which("nltest"):
            return []
        output = self._command_output(["nltest", f"/dclist:{domain}"])
        controllers = []
        for line in output.splitlines():
            cleaned = line.strip()
            if cleaned.startswith("\\\\"):
                controllers.append(cleaned.lstrip("\\").split()[0])
        return controllers[:10]

    def _powershell(self, command: str) -> str:
        return self._command_output(["powershell", "-NoProfile", "-Command", command]).strip()

    def _command_output(self, command: list[str]) -> str:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
            return (completed.stdout or completed.stderr or "").strip()
        except Exception:
            return ""

    def _summary(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        ad_context: dict[str, Any],
        process_risks: list[dict[str, Any]],
        remote_exposure: Counter[str],
    ) -> dict[str, Any]:
        by_group: dict[str, int] = {}
        for node in nodes:
            group = str(node.get("group", "unknown"))
            by_group[group] = by_group.get(group, 0) + 1
        sorted_process_risks = sorted(process_risks, key=lambda item: float(item.get("risk_score", 0)), reverse=True)
        top_processes = sorted_process_risks[:5]
        peak_risk = float(top_processes[0].get("risk_score", 0)) if top_processes else 0.0
        average_risk = sum(float(item.get("risk_score", 0)) for item in top_processes) / max(len(top_processes), 1)
        exposure_bonus = min(15.0, float(remote_exposure.get("public", 0) * 4))
        persistence_bonus = 8.0 if by_group.get("persistence", 0) else 0.0
        incident_bonus = 10.0 if by_group.get("incident", 0) else 0.0
        overall_risk = min(100, int(max(peak_risk, average_risk) + exposure_bonus + persistence_bonus + incident_bonus))
        priority_findings: list[str] = []
        if remote_exposure.get("public", 0):
            priority_findings.append(f"Public remote exposure observed across {remote_exposure.get('public', 0)} graph edges.")
        if by_group.get("persistence", 0):
            priority_findings.append(f"{by_group.get('persistence', 0)} persistence anchors are present in the attack surface.")
        if any(float(item.get("risk_score", 0)) >= 75 for item in top_processes):
            highest = top_processes[0]
            priority_findings.append(
                f"Top process hotspot: {highest.get('name')} (PID {highest.get('pid')}) scored {int(float(highest.get('risk_score', 0)))}."
            )
        if by_group.get("incident", 0):
            priority_findings.append(f"{by_group.get('incident', 0)} incidents are linked into the graph context.")
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "groups": by_group,
            "domain_joined": bool(ad_context.get("domain")),
            "domain": ad_context.get("domain", ""),
            "overall_risk": overall_risk,
            "top_processes": top_processes,
            "remote_exposure": dict(remote_exposure),
            "priority_findings": priority_findings[:6],
        }

    def _case_focus_terms(
        self,
        case_record: dict[str, Any],
        tasks: list[dict[str, Any]],
        activity: list[dict[str, Any]],
        pins: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
    ) -> list[str]:
        raw_terms: set[str] = set()
        sources: list[Any] = [
            case_record.get("title", ""),
            case_record.get("incident_id", ""),
            case_record.get("narrative", ""),
            case_record.get("tags_json", ""),
        ]
        for item in tasks:
            sources.extend([item.get("title", ""), item.get("description", ""), item.get("assigned_to", "")])
        for item in activity:
            sources.extend([item.get("summary", ""), item.get("detail_json", "")])
        for item in pins:
            sources.extend([item.get("item_title", ""), item.get("item_payload_json", ""), item.get("rationale", "")])
        for item in notes:
            sources.extend([item.get("item_title", ""), item.get("note_text", ""), item.get("tags_json", "")])
        for item in stories:
            sources.extend([item.get("title", ""), item.get("hypothesis", ""), item.get("summary", ""), item.get("tags_json", "")])

        ignore = {
            "case", "open", "task", "story", "note", "review", "validate", "analysis", "analyst", "desktop",
            "high", "medium", "low", "triage", "owner", "unit", "test", "investigation", "added", "updated",
            "created", "event", "process", "network", "report", "board", "json", "html", "pdf", "risk",
        }
        for source in sources:
            text = self._normalize_text(source)
            for token in re.findall(r"[a-z0-9_.-]{4,}", text):
                if token.isdigit() or token in ignore:
                    continue
                raw_terms.add(token)
        return sorted(raw_terms)

    def _case_focus_pids(
        self,
        case_record: dict[str, Any],
        tasks: list[dict[str, Any]],
        activity: list[dict[str, Any]],
        pins: list[dict[str, Any]],
        notes: list[dict[str, Any]],
        stories: list[dict[str, Any]],
    ) -> set[int]:
        pid_candidates: set[int] = set()
        sources: list[Any] = [case_record]
        sources.extend(tasks)
        sources.extend(activity)
        sources.extend(pins)
        sources.extend(notes)
        sources.extend(stories)
        for source in sources:
            pid_candidates.update(self._extract_pids(source))
        return {pid for pid in pid_candidates if 1 <= pid <= 999999}

    def _extract_pids(self, value: Any) -> set[int]:
        found: set[int] = set()
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() == "pid":
                    try:
                        found.add(int(item))
                    except Exception:
                        pass
                found.update(self._extract_pids(item))
            return found
        if isinstance(value, list):
            for item in value:
                found.update(self._extract_pids(item))
            return found
        text = self._normalize_text(value)
        for match in re.findall(r"\bpid(?:\s*[:#-]?\s*)(\d{1,6})\b", text):
            found.add(int(match))
        return found

    def _normalize_text(self, value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(self._normalize_text(item) for item in value.values())
        if isinstance(value, list):
            return " ".join(self._normalize_text(item) for item in value)
        if value is None:
            return ""
        text = str(value)
        try:
            parsed = json.loads(text)
        except Exception:
            return text.lower()
        return self._normalize_text(parsed).lower()

    def _text_matches_case(self, item: Any, focus_terms: list[str]) -> bool:
        if not focus_terms:
            return False
        text = self._normalize_text(item)
        return any(term in text for term in focus_terms)

    def _process_matches_case(self, process: dict[str, Any], focus_terms: list[str], focus_pids: set[int]) -> bool:
        proc_pid = int(process.get("pid", -1) or -1)
        if proc_pid in focus_pids:
            return True
        searchable = " ".join(
            [
                str(process.get("name", "")),
                str(process.get("exe", "")),
                str(process.get("cmdline", "")),
                str(process.get("signature_status", "")),
            ]
        ).lower()
        return any(term in searchable for term in focus_terms)

    def _incident_matches_case(self, incident: dict[str, Any], incident_id: str, focus_terms: list[str]) -> bool:
        if incident_id and str(incident.get("incident_id", "")).strip().lower() == incident_id:
            return True
        searchable = " ".join(
            [
                str(incident.get("incident_id", "")),
                str(incident.get("title", "")),
                str(incident.get("summary", "")),
                str(incident.get("notes", "")),
                str(incident.get("correlation_story", "")),
                str(incident.get("recommended_actions", "")),
            ]
        ).lower()
        return any(term in searchable for term in focus_terms)

    def _add_node(
        self,
        nodes: list[dict[str, Any]],
        seen: set[str],
        node_id: str,
        label: str,
        group: str,
        *,
        title: str = "",
        color: str = "#74c0fc",
        size: int = 22,
        risk_score: float = 0,
        cluster: str = "",
    ) -> dict[str, Any]:
        if node_id not in seen:
            nodes.append(
                {
                    "id": node_id,
                    "label": label,
                    "group": group,
                    "title": title,
                    "color": color,
                    "size": size,
                    "risk_score": risk_score,
                    "cluster": cluster,
                }
            )
            seen.add(node_id)
        return next(node for node in nodes if node["id"] == node_id)

    def _add_edge(
        self,
        edges: list[dict[str, Any]],
        seen: set[tuple[str, str, str]],
        source: str,
        target: str,
        label: str,
        color: str,
    ) -> None:
        key = (source, target, label)
        if key in seen:
            return
        seen.add(key)
        width = 2 if label in {"connects_to", "contributes_to", "auto_starts"} else 1
        edges.append({"from": source, "to": target, "label": label, "color": color, "width": width})

    def _shape_for_group(self, group: str) -> str:
        return {
            "domain": "hexagon",
            "domain_controller": "box",
            "host": "dot",
            "user": "ellipse",
            "process": "ellipse",
            "remote_ip": "diamond",
            "incident": "star",
            "persistence": "database",
            "persistence_group": "box",
            "attack_tactic": "triangle",
            "mitre_technique": "triangleDown",
        }.get(group, "dot")

    def _safe_json_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        if not value:
            return []
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except Exception:
            pass
        return []

    def _focus_processes(self, processes: list[dict[str, Any]], connections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        connection_pids = {
            int(conn.get("pid", -1) or -1)
            for conn in connections
            if int(conn.get("pid", -1) or -1) >= 0 and conn.get("remote_addr")
        }
        ranked = []
        for proc in processes:
            pid = int(proc.get("pid", -1) or -1)
            name = str(proc.get("name", "")).lower()
            score = float(proc.get("cpu_percent", 0) or 0) + float(proc.get("memory_percent", 0) or 0)
            if pid in connection_pids:
                score += 25
            if any(token in name for token in ["powershell", "cmd", "wscript", "cscript", "rundll32", "mshta", "wmic"]):
                score += 20
            ranked.append((score, proc))
        ranked.sort(key=lambda item: item[0], reverse=True)
        focused = [proc for _, proc in ranked[:24]]
        return focused

    def _focus_connections(self, connections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ranked: list[tuple[float, dict[str, Any]]] = []
        for conn in connections:
            remote_addr = str(conn.get("remote_addr") or "")
            if not remote_addr:
                continue
            remote_ip = remote_addr.split(":")[0]
            exposure = self._remote_exposure_type(remote_ip)
            score = 30.0 if exposure == "public" else 15.0 if exposure == "private" else 5.0
            if str(conn.get("status", "")).upper() == "ESTABLISHED":
                score += 10.0
            ranked.append((score, conn))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [item for _, item in ranked[:24]]

    def _focus_persistence_items(self, persistence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ranked: list[tuple[float, dict[str, Any]]] = []
        for item in persistence_items:
            item_type = str(item.get("type") or "").lower()
            name = str(item.get("name") or "").lower()
            path = str(item.get("path") or "").lower()
            score = 10.0
            if "run" in item_type or "startup" in item_type:
                score += 18.0
            if "scheduled task" in item_type:
                score += 12.0
            if any(token in f"{name} {path}" for token in ["powershell", "cmd", "wscript", "cscript", "rundll32", "mshta", "regsvr32"]):
                score += 25.0
            ranked.append((score, item))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [item for _, item in ranked[:18]]

    def _focus_incidents(self, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        ranked = sorted(
            incidents,
            key=lambda item: (
                severity_rank.get(str(item.get("severity", "low")).lower(), 1),
                float(item.get("created_at", 0) or 0),
            ),
            reverse=True,
        )
        return ranked[:10]

    def _group_persistence_items(self, persistence_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in persistence_items:
            key = str(item.get("type") or "generic").strip().lower() or "generic"
            grouped.setdefault(key, []).append(item)
        return grouped

    def _display_persistence_type(self, value: str) -> str:
        return value.replace("_", " ").replace("-", " ").title()

    def _persistence_group_title(self, pers_type: str, items: list[dict[str, Any]]) -> str:
        sample = "\n".join(str(item.get("name") or item.get("path") or "item") for item in items[:4])
        return f"{self._display_persistence_type(pers_type)}\nCount: {len(items)}\nTop Items:\n{sample}"

    def _short_label(self, value: str, limit: int) -> str:
        cleaned = " ".join(str(value).split())
        if len(cleaned) <= limit:
            return cleaned
        return f"{cleaned[: max(0, limit - 3)]}..."

    def _process_risk(self, proc: dict[str, Any], connections: list[dict[str, Any]]) -> float:
        pid = int(proc.get("pid", -1) or -1)
        name = str(proc.get("name", "")).lower()
        cpu = float(proc.get("cpu_percent", 0) or 0)
        memory = float(proc.get("memory_percent", 0) or 0)
        signature = str(proc.get("signature_status", "")).lower()
        remote_count = sum(1 for conn in connections if int(conn.get("pid", -1) or -1) == pid and conn.get("remote_addr"))
        risk = min(40.0, cpu + (memory * 2.0))
        if remote_count:
            risk += min(25.0, float(remote_count * 6))
        if any(token in name for token in ["powershell", "cmd", "wscript", "cscript", "rundll32", "mshta", "regsvr32", "wmic"]):
            risk += 24
        if signature in {"unsigned", "unknown", "invalid"}:
            risk += 12
        return min(100.0, round(risk, 1))

    def _process_color(self, name: str, risk: float) -> str:
        lowered = name.lower()
        if risk >= 80:
            return "#d9485f"
        if any(token in lowered for token in ["powershell", "cmd", "wscript", "cscript", "rundll32", "mshta", "wmic"]):
            return "#ffd43b"
        if risk >= 55:
            return "#ff922b"
        return "#74c0fc"

    def _node_size_for_risk(self, risk: float) -> int:
        return max(20, min(38, int(18 + (risk / 5.0))))

    def _cluster_for_process(self, name: str) -> str:
        lowered = name.lower()
        if any(token in lowered for token in ["powershell", "cmd", "wscript", "cscript", "rundll32", "mshta", "wmic"]):
            return "execution"
        if any(token in lowered for token in ["chrome", "firefox", "edge", "browser"]):
            return "browser"
        if any(token in lowered for token in ["svchost", "services", "wininit", "lsass"]):
            return "system"
        return "general"

    def _remote_exposure_type(self, value: str) -> str:
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_loopback:
                return "loopback"
            if ip.is_private:
                return "private"
            return "public"
        except ValueError:
            return "unknown"

    def _incident_matches_process(self, incident: dict[str, Any], proc_node: dict[str, Any]) -> bool:
        incident_blob = " ".join(
            [
                str(incident.get("title", "")),
                str(incident.get("summary", "")),
                str(incident.get("correlation_story", "")),
                str(incident.get("recommended_actions", "")),
            ]
        ).lower()
        proc_label = str(proc_node.get("label", "")).lower()
        return any(part and part in incident_blob for part in [proc_label.split("\n")[0], "powershell", "cmd.exe", "rundll32", "wscript"])
