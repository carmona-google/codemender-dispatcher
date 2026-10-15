"""Integration tests for Dispatcher REST API and Web Routes."""

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from src.app import create_app
from src.config import TestingConfig


class TestDispatcherAPI(unittest.TestCase):
    """Integration test suite for the Dispatcher API and Web Portal."""

    def setUp(self):
        self.temp_storage = tempfile.TemporaryDirectory()
        TestingConfig.STORAGE_DIR = Path(self.temp_storage.name)
        TestingConfig.DATABASE_URI = f"sqlite:///{self.temp_storage.name}/test.db"
        TestingConfig.ENABLE_MOCK_FALLBACK = True

        self.app = create_app(TestingConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_storage.cleanup()

    def _create_sample_zip(self) -> io.BytesIO:
        """Creates an in-memory zip archive containing a mock vulnerable Python file."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "app/db/query_builder.py",
                "def get_user_by_id(cursor, user_id: str):\n"
                "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
                "    cursor.execute(query)\n"
                "    return cursor.fetchone()\n",
            )
        zip_buffer.seek(0)
        return zip_buffer

    def test_dashboard_index(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CodeMender", response.data)
        self.assertIn(b"Upload Codebase Archive", response.data)

    def test_submit_scan_and_inspect_results(self):
        zip_data = self._create_sample_zip()
        data = {
            "file": (zip_data, "vulnerable_repo.zip"),
            "language_flavor": "python",
        }
        # 1. Submit scan
        post_resp = self.client.post(
            "/api/v1/scans",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(post_resp.status_code, 202)
        resp_json = post_resp.get_json()
        self.assertIn("session_id", resp_json)
        self.assertEqual(resp_json["model_name"], "gemini-4-argon")
        session_id = resp_json["session_id"]

        # 2. Query scan status API
        get_resp = self.client.get(f"/api/v1/scans/{session_id}")
        self.assertEqual(get_resp.status_code, 200)
        status_data = get_resp.get_json()
        self.assertEqual(status_data["status"], "COMPLETED")
        self.assertEqual(status_data["model_name"], "gemini-4-argon")
        self.assertEqual(status_data["vulnerabilities_verified"], 1)
        self.assertIn("report", status_data)
        self.assertEqual(status_data["report"]["cm_version"], "0.14.0")
        self.assertIn("patches", status_data)

        # 3. Query logs API
        log_resp = self.client.get(f"/api/v1/scans/{session_id}/logs")
        self.assertEqual(log_resp.status_code, 200)
        log_data = log_resp.get_json()
        self.assertIn("CodeMender", log_data["logs"])
        self.assertIn("Remediation Log", log_data["logs"])

        # 4. View Scan Detail Console Web Page
        page_resp = self.client.get(f"/scans/{session_id}")
        self.assertEqual(page_resp.status_code, 200)
        self.assertIn(b"Scan Console", page_resp.data)
        self.assertIn(b"SQL_INJECTION", page_resp.data)
        self.assertIn(b"gemini-4-argon", page_resp.data)

        # 5. Stream SSE Events
        sse_resp = self.client.get(f"/api/v1/events/{session_id}")
        self.assertEqual(sse_resp.status_code, 200)
        self.assertEqual(sse_resp.mimetype, "text/event-stream")
        first_chunk = next(sse_resp.response)
        self.assertIn(b"event:", first_chunk)

    def test_staged_scan_verify_and_fix_endpoints(self):
        """Tests step-by-step Scan (find) -> Verify by ID -> Fix by ID and model selection via REST API."""
        zip_data = self._create_sample_zip()
        data = {
            "file": (zip_data, "staged_repo.zip"),
            "language_flavor": "python",
            "model_name": "gemini-4-argon",
            "stage": "find",
        }
        # 1. Step 1: Scan (cm find)
        post_resp = self.client.post(
            "/api/v1/scans",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(post_resp.status_code, 202)
        resp_json = post_resp.get_json()
        session_id = resp_json["session_id"]
        self.assertEqual(resp_json["model_name"], "gemini-4-argon")
        self.assertEqual(resp_json["stage"], "FIND")

        status_find = self.client.get(f"/api/v1/scans/{session_id}").get_json()
        self.assertEqual(status_find["status"], "COMPLETED")
        self.assertEqual(status_find["stage"], "FIND")
        self.assertEqual(status_find["vulnerabilities_found"], 1)
        self.assertEqual(status_find["vulnerabilities_verified"], 0)
        self.assertEqual(status_find["patches_applied"], 0)
        finding_id = status_find["report"]["findings"][0]["id"]

        # 2. Step 2: Verify finding_id (cm verify)
        verify_resp = self.client.post(
            f"/api/v1/scans/{session_id}/verify",
            json={"finding_ids": [finding_id], "model_name": "gemini-4-argon"},
        )
        self.assertEqual(verify_resp.status_code, 200)
        verify_json = verify_resp.get_json()
        self.assertEqual(verify_json["status"], "COMPLETED")
        self.assertEqual(verify_json["stage"], "VERIFY")
        self.assertEqual(verify_json["vulnerabilities_verified"], 1)
        self.assertEqual(verify_json["patches_applied"], 0)

        # 3. Step 3: Fix finding_id (cm fix)
        fix_resp = self.client.post(
            f"/api/v1/scans/{session_id}/fix",
            json={"finding_ids": [finding_id], "model_name": "gemini-4-argon"},
        )
        self.assertEqual(fix_resp.status_code, 200)
        fix_json = fix_resp.get_json()
        self.assertEqual(fix_json["status"], "COMPLETED")
        self.assertEqual(fix_json["stage"], "FIX")
        self.assertEqual(fix_json["patches_applied"], 1)

        # 4. Verify web console renders exploit telemetry and 3-stage pipeline controls
        page_resp = self.client.get(f"/scans/{session_id}")
        self.assertEqual(page_resp.status_code, 200)
        self.assertIn(b"Sandbox Verification &amp; PoC Exploit Telemetry", page_resp.data)
        self.assertIn(b"VERIFIED_EXPLOITABLE", page_resp.data)


if __name__ == "__main__":
    unittest.main()

