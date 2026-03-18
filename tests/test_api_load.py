from __future__ import annotations

import concurrent.futures
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import api.main
import api.security as security
from tests.test_security import make_settings


class ApiLoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(api.main.app)

    def test_health_endpoint_handles_parallel_requests(self) -> None:
        settings = make_settings(auth_required=False, enable_dangerous_actions=True)
        with mock.patch.object(api.main, "security_settings", settings):
            with mock.patch.object(security, "security_settings", settings):
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    responses = list(executor.map(lambda _: self.client.get("/health").status_code, range(24)))
        self.assertTrue(all(status == 200 for status in responses))


if __name__ == "__main__":
    unittest.main()
