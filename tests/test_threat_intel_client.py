"""Tests for ThreatIntelClient — the class-based surface introduced when
the old module-level free functions were consolidated.

These tests cover the concerns that the free functions previously couldn't
express cleanly:
  * SSRF allowlist enforcement (per-instance, not global env var)
  * Session injection (so offline tests don't hit the real internet)
  * Per-client key override (so a tenant-specific client doesn't leak
    credentials into the default client's audit trail)
  * `scan_process` still picks up `mock.patch.object(threat_intelligence, ...)`
    patches on module-level functions — this compat contract is what
    makes the refactor land without touching any existing call site.
"""
from __future__ import annotations

import unittest
from unittest import mock

import threat_intelligence
from threat_intelligence import ThreatIntelClient


def _fake_response(status_code: int = 200, json_body=None):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_body or {}
    resp.raise_for_status.return_value = None
    return resp


class ThreatIntelClientSSRFTests(unittest.TestCase):
    def test_safe_request_blocks_disallowed_host(self) -> None:
        """Cornerstone SSRF check: any host not in the allowlist is
        rejected before the socket is opened."""
        client = ThreatIntelClient(
            allowed_outbound_hosts={"api.abuseipdb.com"},
            session=mock.MagicMock(),
        )
        with self.assertRaises(ValueError) as cx:
            client._safe_request("test", "GET", "https://evil.example.com/path")
        self.assertIn("Blocked outbound target", str(cx.exception))
        # Session must NOT have been dialled.
        client._session.request.assert_not_called()

    def test_safe_request_uses_injected_session(self) -> None:
        session = mock.MagicMock()
        session.request.return_value = _fake_response(200)
        client = ThreatIntelClient(
            allowed_outbound_hosts={"api.abuseipdb.com"},
            session=session,
        )
        resp = client._safe_request("x", "GET", "https://api.abuseipdb.com/q")
        self.assertEqual(resp.status_code, 200)
        session.request.assert_called_once()


class ThreatIntelClientProviderTests(unittest.TestCase):
    def test_check_ip_returns_none_when_no_key(self) -> None:
        client = ThreatIntelClient(abuseipdb_api_key=None, session=mock.MagicMock())
        self.assertIsNone(client.check_ip("8.8.8.8"))

    def test_check_ip_calls_abuseipdb_with_per_instance_key(self) -> None:
        session = mock.MagicMock()
        session.request.return_value = _fake_response(200, {"data": {"abuseConfidenceScore": 12}})
        client = ThreatIntelClient(abuseipdb_api_key="tenant-key", session=session)
        result = client.check_ip("1.2.3.4")
        self.assertEqual(result, {"abuseConfidenceScore": 12})
        call = session.request.call_args
        # Key must come from instance, not from the module-level default.
        self.assertEqual(call.kwargs["headers"]["Key"], "tenant-key")

    def test_check_file_vt_skipped_without_api_key(self) -> None:
        client = ThreatIntelClient(session=mock.MagicMock())
        result = client.check_file_vt("a" * 64, api_key=None)
        self.assertEqual(result["status"], "skipped")

    def test_check_file_vt_maps_429_to_rate_limited(self) -> None:
        session = mock.MagicMock()
        session.request.return_value = _fake_response(429)
        client = ThreatIntelClient(session=session)
        result = client.check_file_vt("a" * 64, api_key="k")
        self.assertEqual(result["status"], "rate_limited")

    def test_check_file_vt_maps_404_to_not_found(self) -> None:
        session = mock.MagicMock()
        session.request.return_value = _fake_response(404)
        client = ThreatIntelClient(session=session)
        result = client.check_file_vt("a" * 64, api_key="k")
        self.assertEqual(result["status"], "not_found")


class ModuleLevelCompatTests(unittest.TestCase):
    """The module-level free functions must still work and must still be
    patchable — that's the contract that lets the refactor land without
    touching any call site. `scan_process` in particular has to pick up
    `mock.patch.object(threat_intelligence, "check_file_vt", ...)`."""

    def test_scan_process_honors_module_level_patches(self) -> None:
        with mock.patch.object(threat_intelligence, "calculate_file_hash", return_value="deadbeef"):
            with mock.patch.object(threat_intelligence, "check_file_vt", return_value={"status": "mocked_vt"}) as vt:
                with mock.patch.object(threat_intelligence, "check_file_malwarebazaar", return_value={"status": "mocked_mb"}):
                    with mock.patch.object(threat_intelligence, "check_file_yaraify", return_value={"status": "ok", "matched_rules": ["hit"], "yara_rule_count": 1}):
                        with mock.patch.object(threat_intelligence, "run_static_pe_analysis", return_value={"combined_static": {}}):
                            result = threat_intelligence.scan_process({"exe": "/tmp/x", "pid": 1, "name": "x"})
        self.assertEqual(result["virustotal"], {"status": "mocked_vt"})
        vt.assert_called_once_with("deadbeef", None)

    def test_default_client_reflects_env_defaults(self) -> None:
        """The module-level `default_client` is built from env-var-derived
        module constants — no funny business."""
        self.assertIs(threat_intelligence.default_client.abuseipdb_api_key, threat_intelligence.ABUSEIPDB_API_KEY)


class FuseDetectionVerdictTests(unittest.TestCase):
    def test_empty_inputs_returns_low_severity_zero_score(self) -> None:
        client = ThreatIntelClient(session=mock.MagicMock())
        verdict = client.fuse_detection_verdict()
        self.assertEqual(verdict["score"], 0)
        self.assertEqual(verdict["severity"], "low")
        self.assertEqual(verdict["confidence"], "low")
        self.assertEqual(verdict["reasons"], [])

    def test_all_high_signals_saturates_at_critical(self) -> None:
        client = ThreatIntelClient(session=mock.MagicMock())
        verdict = client.fuse_detection_verdict(
            yaraify_result={"status": "ok", "matched_rules": ["a", "b", "c"]},
            local_yara_result={"score": 80, "active_match_count": 3, "confidence": "high", "suppressed_match_count": 1},
            virustotal_result={"last_analysis_stats": {"malicious": 25, "suspicious": 5}},
            malwarebazaar_result={"status": "ok", "signature": "Cobalt"},
            static_result={"combined_static": {"score": 70, "confidence": "high", "suspicious_indicators": ["VirtualProtect", "OpenProcess"]}},
            memory_result={"analysis": {"severity": "critical", "memory_yara": {"match_count": 2, "score": 50}}},
            behavior_result={"likelihood": 0.9},
        )
        self.assertEqual(verdict["score"], 100)  # Clamped.
        self.assertEqual(verdict["severity"], "critical")
        self.assertGreater(len(verdict["reasons"]), 5)


if __name__ == "__main__":
    unittest.main()
