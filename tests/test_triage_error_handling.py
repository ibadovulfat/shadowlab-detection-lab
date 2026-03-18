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

if __name__ == "__main__":
    unittest.main()
