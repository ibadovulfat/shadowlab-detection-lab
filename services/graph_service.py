from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
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
            connections = [conn for conn in connections if int(conn.get("pid", -1) or -1) in proc_ids][:120]
            persistence_items = persistence_items[:40]
            incidents = incidents[:20]

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen_nodes: set[str] = set()
        seen_edges: set[tuple[str, str, str]] = set()

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
        for proc in processes[:80]:
            proc_pid = int(proc.get("pid", -1) or -1)
            if proc_pid < 0:
                continue
            proc_name = str(proc.get("name") or f"pid-{proc_pid}")
            proc_node = self._add_node(
                nodes,
                seen_nodes,
                f"proc:{proc_pid}",
                f"{proc_name}\nPID {proc_pid}",
                "process",
                title=f"Executable: {proc.get('exe', 'n/a')}\nCmd: {proc.get('cmdline', '')[:180]}",
                color="#ffd43b" if "powershell" in proc_name.lower() else "#74c0fc",
            )
            process_lookup[proc_pid] = proc_node
            parent_pid = int(proc.get("ppid", -1) or -1)
            if parent_pid in process_lookup:
                self._add_edge(edges, seen_edges, process_lookup[parent_pid]["id"], proc_node["id"], "spawned", "#adb5bd")
            if host_lookup:
                first_host = next(iter(host_lookup.values()))
                self._add_edge(edges, seen_edges, first_host["id"], proc_node["id"], "runs", "#339af0")

        for conn in connections[:120]:
            local_addr = str(conn.get("local_addr") or "")
            remote_addr = str(conn.get("remote_addr") or "")
            if not remote_addr:
                continue
            remote_ip = remote_addr.split(":")[0]
            remote_node = self._add_node(
                nodes,
                seen_nodes,
                f"remote:{remote_ip}",
                remote_ip,
                "remote_ip",
                title=f"Remote Endpoint\n{remote_addr}",
                color="#fa5252",
            )
            pid_value = int(conn.get("pid", -1) or -1)
            if pid_value in process_lookup:
                self._add_edge(edges, seen_edges, process_lookup[pid_value]["id"], remote_node["id"], "connects_to", "#fa5252")
            elif host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], remote_node["id"], "observed_remote", "#ff8787")
            if local_addr and host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], remote_node["id"], f"socket {local_addr}", "#868e96")

        for item in persistence_items[:120]:
            pers_id = f"persistence:{item.get('type')}:{item.get('path')}:{item.get('name')}"
            pers_node = self._add_node(
                nodes,
                seen_nodes,
                pers_id,
                str(item.get("name") or item.get("type") or "persistence"),
                "persistence",
                title=f"{item.get('type', '')}\n{item.get('path', '')}\n{item.get('content_preview', '')[:180]}",
                color="#ff922b",
            )
            if host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], pers_node["id"], "persists_via", "#ff922b")

        for incident in incidents[:80]:
            incident_id = str(incident.get("incident_id") or "incident")
            sev = str(incident.get("severity", "low")).lower()
            incident_node = self._add_node(
                nodes,
                seen_nodes,
                f"incident:{incident_id}",
                incident_id,
                "incident",
                title=str(incident.get("title") or "Behavioral incident"),
                color="#c92a2a" if sev in {"high", "critical"} else "#fab005",
            )
            if host_lookup:
                self._add_edge(edges, seen_edges, next(iter(host_lookup.values()))["id"], incident_node["id"], "generated", "#c92a2a")
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

        html_path = self._render_graph(nodes, edges, pid=pid)
        json_path = self.out_dir / ("ShadowLab_EntityGraph.json" if pid is None else f"ShadowLab_EntityGraph_PID_{pid}.json")
        json_path.write_text(json.dumps({"nodes": nodes, "edges": edges, "summary": self._summary(nodes, edges, ad_context)}, indent=2), encoding="utf-8")

        return {
            "summary": self._summary(nodes, edges, ad_context),
            "nodes": nodes,
            "edges": edges,
            "html_path": str(html_path),
            "json_path": str(json_path),
            "ad_context": ad_context,
        }

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
            )
        for edge in edges:
            net.add_edge(edge["from"], edge["to"], label=edge.get("label", ""), color=edge.get("color", "#868e96"))
        net.set_options(
            """
            {
              "nodes": { "font": { "face": "Segoe UI", "size": 16 }, "borderWidth": 1, "shadow": true },
              "edges": { "arrows": { "to": { "enabled": true, "scaleFactor": 0.6 } }, "smooth": { "type": "continuous" }, "font": { "size": 10 } },
              "layout": { "improvedLayout": true },
              "interaction": { "hover": true, "navigationButtons": true, "keyboard": true },
              "physics": { "enabled": true, "stabilization": { "enabled": true, "iterations": 120, "fit": true } }
            }
            """
        )
        net.write_html(str(html_path), notebook=False)
        html_text = html_path.read_text(encoding="utf-8", errors="ignore")
        html_text = html_text.replace(
            "</body>",
            """
<script>
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

    def _summary(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]], ad_context: dict[str, Any]) -> dict[str, Any]:
        by_group: dict[str, int] = {}
        for node in nodes:
            group = str(node.get("group", "unknown"))
            by_group[group] = by_group.get(group, 0) + 1
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "groups": by_group,
            "domain_joined": bool(ad_context.get("domain")),
            "domain": ad_context.get("domain", ""),
        }

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
    ) -> dict[str, Any]:
        if node_id not in seen:
            nodes.append({"id": node_id, "label": label, "group": group, "title": title, "color": color})
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
        edges.append({"from": source, "to": target, "label": label, "color": color})

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
        focused = [proc for _, proc in ranked[:60]]
        return focused
