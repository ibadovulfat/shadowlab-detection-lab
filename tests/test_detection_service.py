from __future__ import annotations

import unittest

from services.detection_service import DetectionOrchestrator


class DetectionServiceTests(unittest.TestCase):
    def test_compute_metrics_exposes_new_sysmon_breakouts(self) -> None:
        orchestrator = DetectionOrchestrator()
        telemetry_rows = [
            {"cpu": 10, "proc_threads": 20, "tcp_conns": 2, "bytes_sent_rate": 1000, "bytes_recv_rate": 500, "remote_ips": ["1.1.1.1"]},
            {"cpu": 30, "proc_threads": 40, "tcp_conns": 4, "bytes_sent_rate": 4000, "bytes_recv_rate": 1000, "remote_ips": ["1.1.1.1", "2.2.2.2"]},
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
        self.assertEqual(metrics["max_cpu"], 30.0)
        self.assertEqual(metrics["cpu_spike_delta"], 20.0)
        self.assertEqual(metrics["max_threads"], 40.0)
        self.assertEqual(metrics["thread_spike_delta"], 20.0)
        self.assertEqual(metrics["max_tcp_conns"], 4.0)
        self.assertEqual(metrics["remote_ip_churn"], 2.0)
        self.assertGreater(metrics["stable_remote_fraction"], 0.0)

    def test_incremental_score_triggers_new_behavior_rules(self) -> None:
        orchestrator = DetectionOrchestrator()
        telemetry_rows = [
            {"cpu": 20, "proc_threads": 25, "tcp_conns": 1, "bytes_sent_rate": 1200, "bytes_recv_rate": 100, "remote_ips": ["8.8.8.8"]},
            {"cpu": 50, "proc_threads": 42, "tcp_conns": 2, "bytes_sent_rate": 2800, "bytes_recv_rate": 200, "remote_ips": ["8.8.8.8"]},
            {"cpu": 18, "proc_threads": 40, "tcp_conns": 2, "bytes_sent_rate": 2400, "bytes_recv_rate": 120, "remote_ips": ["8.8.8.8"]},
            {"cpu": 22, "proc_threads": 38, "tcp_conns": 3, "bytes_sent_rate": 2600, "bytes_recv_rate": 110, "remote_ips": ["8.8.8.8"]},
            {"cpu": 15, "proc_threads": 35, "tcp_conns": 8, "bytes_sent_rate": 12000, "bytes_recv_rate": 150, "remote_ips": ["8.8.8.8", "1.1.1.1", "2.2.2.2", "3.3.3.3"]},
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
        self.assertIn("bursty_connection_exfil_sequence", rule_ids)
        self.assertIn("remote_ip_churn_staging_profile", rule_ids)
        self.assertIn("cpu_thread_spike_injection_profile", rule_ids)
        self.assertGreater(result["likelihood"], 0.0)

    def test_incremental_score_captures_low_and_slow_beaconing(self) -> None:
        orchestrator = DetectionOrchestrator()
        telemetry_rows = [
            {"cpu": 12, "proc_threads": 18, "tcp_conns": 1, "bytes_sent_rate": 600, "bytes_recv_rate": 120, "remote_ips": ["9.9.9.9"]},
            {"cpu": 14, "proc_threads": 19, "tcp_conns": 1, "bytes_sent_rate": 700, "bytes_recv_rate": 110, "remote_ips": ["9.9.9.9"]},
            {"cpu": 16, "proc_threads": 20, "tcp_conns": 2, "bytes_sent_rate": 900, "bytes_recv_rate": 140, "remote_ips": ["9.9.9.9"]},
            {"cpu": 13, "proc_threads": 18, "tcp_conns": 2, "bytes_sent_rate": 850, "bytes_recv_rate": 150, "remote_ips": ["9.9.9.9"]},
            {"cpu": 15, "proc_threads": 21, "tcp_conns": 3, "bytes_sent_rate": 1000, "bytes_recv_rate": 130, "remote_ips": ["9.9.9.9", "5.5.5.5"]},
        ]
        defender_summary = {"total": 0, "by_id": {}}
        sysmon_summary = {
            "total": 14,
            "by_id": {
                "DNS query": 6,
                "Process creation": 2,
            },
        }

        result = orchestrator.incremental_score(telemetry_rows, defender_summary, sysmon_summary)
        rule_ids = [item["rule_id"] for item in result.get("rule_findings", [])]

        self.assertIn("low_and_slow_dns_beacon", rule_ids)


if __name__ == "__main__":
    unittest.main()
