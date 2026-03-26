from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

import plugins.sandbox as sandbox


class SandboxTraceTests(unittest.TestCase):
    def test_trace_includes_execution_context_and_summary(self) -> None:
        tracer = sandbox.ProcessTracer(100)
        process = mock.Mock()
        process.pid = 100
        process.exe.return_value = r"C:\Users\ulfat\AppData\Local\Temp\dropper.exe"
        process.name.return_value = "dropper.exe"
        process.ppid.return_value = 99
        process.cmdline.return_value = ["powershell.exe", "-enc", "AAAA"]
        process.status.return_value = "running"
        process.create_time.return_value = 123.0
        process.open_files.return_value = []
        process.net_connections.return_value = []
        process.children.return_value = []
        process.memory_maps.return_value = []
        process.is_running.return_value = False
        tracer.process = process

        with mock.patch.object(sandbox.time, "time", side_effect=[0, 0]), \
             mock.patch.object(sandbox.time, "strftime", return_value="12:00:00"):
            result = tracer.trace(duration=1, interval=0)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["process_snapshot"]["path_flags"], ["temp", "user_profile"])
        self.assertIn("encoded-command", result["process_snapshot"]["cmdline_flags"])
        self.assertTrue(any(event["type"] == "EXECUTION_CONTEXT" for event in result["events"]))
        self.assertTrue(any(item.startswith("process_path:temp") for item in result["summary"]["suspicious_indicators"]))

    def test_trace_captures_child_and_module_events(self) -> None:
        tracer = sandbox.ProcessTracer(200)
        process = mock.Mock()
        process.pid = 200
        process.exe.return_value = r"C:\Windows\System32\svchost.exe"
        process.name.return_value = "svchost.exe"
        process.ppid.return_value = 4
        process.cmdline.return_value = ["svchost.exe"]
        process.status.return_value = "running"
        process.create_time.return_value = 123.0
        process.open_files.return_value = [
            SimpleNamespace(path=r"C:\Users\ulfat\Downloads\payload.bin", mode="r")
        ]
        process.net_connections.return_value = [
            SimpleNamespace(laddr="127.0.0.1:5000", raddr="8.8.8.8:443", status="ESTABLISHED", type="TCP")
        ]
        process.children.return_value = [
            mock.Mock(
                pid=201,
                **{
                    "name.return_value": "cmd.exe",
                    "exe.return_value": r"C:\Users\ulfat\AppData\Local\Temp\cmd.exe",
                },
            )
        ]
        process.memory_maps.return_value = [
            SimpleNamespace(path=r"C:\Users\ulfat\AppData\Roaming\evil.dll", perms="rwx")
        ]
        process.is_running.side_effect = [True, False]
        tracer.process = process

        with mock.patch.object(sandbox.time, "time", side_effect=[0, 0, 2]), \
             mock.patch.object(sandbox.time, "strftime", return_value="12:00:00"), \
             mock.patch.object(sandbox.time, "sleep"):
            result = tracer.trace(duration=1, interval=0)

        event_types = [event["type"] for event in result["events"]]
        self.assertIn("FILE_OPEN", event_types)
        self.assertIn("NET_CONN", event_types)
        self.assertIn("CHILD_PROCESS", event_types)
        self.assertIn("MODULE_LOAD", event_types)
        self.assertEqual(result["summary"]["event_type_counts"]["MODULE_LOAD"], 1)
        self.assertTrue(any(item.startswith("module:rwx-perms") for item in result["summary"]["suspicious_indicators"]))


if __name__ == "__main__":
    unittest.main()
