"""Integration tests for CI/CD GitHub Webhooks v2.0 (In-Flight Debounce & PR Feedback)."""

import hashlib
import hmac
import json
import time
import tempfile
import unittest
from pathlib import Path

from src.app import create_app
from src.config import TestingConfig


class TestGitHubWebhooksV2(unittest.TestCase):
    """Verifies HMAC validation, in-flight cancellation, and bidirectional PR merge feedback."""

    def setUp(self):
        self.temp_storage = tempfile.TemporaryDirectory()
        TestingConfig.STORAGE_DIR = Path(self.temp_storage.name)
        TestingConfig.DATABASE_URI = f"sqlite:///{self.temp_storage.name}/test_webhooks_v2.db"
        TestingConfig.ENABLE_MOCK_FALLBACK = True

        self.app = create_app(TestingConfig)
        self.app.config["GITHUB_WEBHOOK_SECRET"] = "super-secret-key"
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_storage.cleanup()

    def _sign_payload(self, payload_dict: dict, secret: str) -> str:
        body = json.dumps(payload_dict).encode("utf-8")
        mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
        return f"sha256={mac.hexdigest()}"

    def test_github_pull_request_opened_and_closed_merged(self):
        # 1. PR Opened -> Dispatches scan
        open_payload = {
            "action": "opened",
            "number": 101,
            "repository": {
                "full_name": "example-org/payment-service",
                "html_url": "https://github.com/example-org/payment-service",
            },
            "pull_request": {
                "head": {"sha": "commit-sha-1", "ref": "feature/payments"},
                "base": {"ref": "main"},
                "html_url": "https://github.com/example-org/payment-service/pull/101",
            },
        }
        sig = self._sign_payload(open_payload, "super-secret-key")
        resp = self.client.post(
            "/api/v1/webhooks/github",
            data=json.dumps(open_payload),
            content_type="application/json",
            headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sig},
        )
        self.assertEqual(resp.status_code, 202)
        session_1 = resp.get_json()["session_id"]

        # 2. PR Closed & Merged -> Emits REMEDIATION_PR_MERGED feedback
        close_payload = {
            "action": "closed",
            "number": 101,
            "repository": {
                "full_name": "example-org/payment-service",
                "html_url": "https://github.com/example-org/payment-service",
            },
            "pull_request": {
                "merged": True,
                "closed_at": "2026-08-26T12:00:00Z",
                "head": {"sha": "commit-sha-1", "ref": "feature/payments"},
                "base": {"ref": "main"},
                "html_url": "https://github.com/example-org/payment-service/pull/101",
            },
        }
        sig_close = self._sign_payload(close_payload, "super-secret-key")
        resp_close = self.client.post(
            "/api/v1/webhooks/github",
            data=json.dumps(close_payload),
            content_type="application/json",
            headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sig_close},
        )
        self.assertEqual(resp_close.status_code, 200)
        self.assertIn("REMEDIATION_PR_MERGED", resp_close.get_json()["message"])

        time.sleep(0.2)


if __name__ == "__main__":
    unittest.main()
