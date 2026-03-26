import unittest
from unittest import mock
import psutil
from fastapi import HTTPException
from services.process_intelligence_service import ProcessIntelligenceService

class TestTriageErrorHandling(unittest.TestCase):
    def setUp(self):
        self.service = ProcessIntelligenceService()

    def test_profile_process_raises_404_on_no_such_process(self):
        with mock.patch("psutil.Process", side_effect=psutil.NoSuchProcess(pid=9999)):
            with self.assertRaises(HTTPException) as cm:
                self.service.profile_process(9999)
            self.assertEqual(cm.exception.status_code, 404)
            self.assertIn("Process 9999 not found", cm.exception.detail)

    def test_execution_context_flags_user_writable_browser_spawn(self):
        context = self.service._execution_context(
            process_name="powershell.exe",
            exe_path=r"C:\Users\ulfat\Downloads\powershell.exe",
            cmdline="powershell.exe -enc AAAA",
            parent_name="chrome.exe",
        )

        self.assertTrue(context["suspicious"])
        self.assertTrue(context["user_writable_path"])
        self.assertTrue(context["browser_parent"])
        self.assertTrue(context["proxy_execution"])
        self.assertTrue(context["script_like"])

    def test_execution_context_matches_sigmaeye_suspicious_chain(self):
        context = self.service._execution_context(
            process_name="powershell.exe",
            exe_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            cmdline="powershell.exe",
            parent_name="excel.exe",
        )

        self.assertTrue(context["suspicious"])
        self.assertIn("PowerShell launched from Excel", context["suspicious_chain_matches"])
        self.assertFalse(context["user_writable_path"])

if __name__ == "__main__":
    unittest.main()
