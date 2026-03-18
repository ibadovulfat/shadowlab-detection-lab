from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from services.graph_service import GraphService


class GraphServiceTests(unittest.TestCase):
    def test_entity_graph_summary_prioritizes_risk_and_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service = GraphService(Path(tmp))
            graph = service.build_entity_graph(
                hosts=[{"host_id": "h1", "host": "workstation-1", "platform": "Windows", "ip_address": "10.0.0.5"}],
                processes=[
                    {"pid": 101, "ppid": 1, "name": "powershell.exe", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmdline": "powershell -enc ...", "cpu_percent": 18, "memory_percent": 6, "signature_status": "unknown"},
                    {"pid": 202, "ppid": 101, "name": "chrome.exe", "exe": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "cmdline": "chrome", "cpu_percent": 4, "memory_percent": 2, "signature_status": "Valid"},
                ],
                connections=[
                    {"pid": 101, "local_addr": "10.0.0.5:50432", "remote_addr": "8.8.8.8:443"},
                    {"pid": 101, "local_addr": "10.0.0.5:50433", "remote_addr": "203.0.113.10:443"},
                ],
                incidents=[
                    {"incident_id": "INC-1", "severity": "high", "title": "Suspicious PowerShell beacon", "summary": "powershell.exe contacted remote infrastructure", "attack_chain": '["Command and Scripting Interpreter"]', "mitre_mapping": '["T1059"]'},
                ],
                persistence_items=[{"type": "registry_run", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "name": "powershell", "content_preview": "autorun"}],
            )
        summary = graph["summary"]
        self.assertGreaterEqual(summary["overall_risk"], 50)
        self.assertTrue(summary["top_processes"])
        self.assertEqual(summary["top_processes"][0]["name"], "powershell.exe")
        self.assertGreaterEqual(summary["remote_exposure"].get("public", 0), 1)
        self.assertTrue(summary["priority_findings"])


if __name__ == "__main__":
    unittest.main()
