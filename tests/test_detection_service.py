from __future__ import annotations

import unittest

from services.detection_service import DetectionOrchestrator


class DetectionServiceTests(unittest.TestCase):
    def test_compute_metrics_exposes_new_sysmon_breakouts(self) -> None:
        orchestrator = DetectionOrchestrator()
        telemetry_rows = [
            {"cpu": 10, "proc_threads": 20, "tcp_conns": 2, "bytes_sent_rate": 1000, "bytes_recv_rate": 500},
            {"cpu": 30, "proc_threads": 40, "tcp_conns": 4, "bytes_sent_rate": 4000, "bytes_recv_rate": 1000},
        ]
        defender_summary = {"total": 2, "by_id": {"Remediation failed": 1}}
        sysmon_summary = {
            "total": 12,
            "by_id": {
                "DNS query": 6,
                "CreateRemoteThread": 1,
                "Process creation": 3,
                "Image loaded": 9,
                "Process accessed": 4,
                "File create": 5,
                "Registry add": 1,
                "Registry set": 2,
            },
        }

        metrics = orchestrator.compute_metrics(telemetry_rows, defender_summary, sysmon_summary)

        self.assertEqual(metrics["sysmon_dns_queries"], 6.0)
        self.assertEqual(metrics["sysmon_create_remote_thread"], 1.0)
        self.assertEqual(metrics["sysmon_process_create"], 3.0)
        self.assertEqual(metrics["sysmon_process_access"], 4.0)
        self.assertEqual(metrics["sysmon_file_create"], 5.0)
        self.assertEqual(metrics["sysmon_registry_add"], 1.0)
        self.assertEqual(metrics["sysmon_registry_set"], 2.0)
        self.assertEqual(metrics["defender_remediation_failed"], 1.0)

    def test_incremental_score_triggers_new_behavior_rules(self) -> None:
        orchestrator = DetectionOrchestrator()
        telemetry_rows = [
            {"cpu": 45, "proc_threads": 42, "tcp_conns": 5, "bytes_sent_rate": 2500, "bytes_recv_rate": 1300},
            {"cpu": 35, "proc_threads": 38, "tcp_conns": 4, "bytes_sent_rate": 3100, "bytes_recv_rate": 1100},
        ]
        defender_summary = {"total": 3, "by_id": {"Remediation failed": 1}}
        sysmon_summary = {
            "total": 24,
            "by_id": {
                "DNS query": 7,
                "CreateRemoteThread": 1,
                "Process creation": 4,
                "Image loaded": 11,
                "Process accessed": 5,
                "File create": 3,
                "Registry set": 2,
            },
        }

        result = orchestrator.incremental_score(telemetry_rows, defender_summary, sysmon_summary)
        rule_ids = [item["rule_id"] for item in result.get("rule_findings", [])]

        self.assertIn("remote_thread_injection_chain", rule_ids)
        self.assertIn("dns_beaconing_process_spawn", rule_ids)
        self.assertIn("image_load_injection_profile", rule_ids)
        self.assertIn("defender_failure_with_sysmon_injection", rule_ids)
        self.assertIn("staged_payload_drop_and_execution", rule_ids)
        self.assertIn("persistence_registry_with_spawn", rule_ids)
        self.assertIn("registry_backed_beaconing", rule_ids)
        self.assertIn("high_load_injection_sequence", rule_ids)
        self.assertGreater(result["likelihood"], 0.0)


if __name__ == "__main__":
    unittest.main()
