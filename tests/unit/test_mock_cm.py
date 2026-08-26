"""Unit tests for CodeMender mock CLI and output artifact schemas."""

import json
import os
import subprocess
import tempfile
import unittest


class TestMockCMHarness(unittest.TestCase):
    """Verifies that mock_cm.sh produces compliant schemas for find, verify, and fix."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = os.path.join(self.temp_dir.name, "output")
        self.state_dir = os.path.join(self.temp_dir.name, "state")
        self.script_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "mocks",
                "mock_cm.sh",
            )
        )
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "CODEMENDER_OUTPUT_DIR": self.output_dir,
            "CODEMENDER_STATE_DIR": self.state_dir,
            "CODEMENDER_SESSION_ID": "test-session-123",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_mock_find_stage(self):
        result = subprocess.run(
            ["bash", self.script_path, "find"],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        findings_path = os.path.join(self.output_dir, "findings.json")
        self.assertTrue(os.path.exists(findings_path))

        with open(findings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["scan_id"], "test-session-123")
        self.assertGreater(len(data["findings"]), 0)
        first_finding = data["findings"][0]
        self.assertIn("id", first_finding)
        self.assertIn("type", first_finding)
        self.assertIn("severity", first_finding)

    def test_mock_verify_stage(self):
        result = subprocess.run(
            ["bash", self.script_path, "verify"],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        verification_path = os.path.join(self.output_dir, "verification.json")
        self.assertTrue(os.path.exists(verification_path))

        with open(verification_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["scan_id"], "test-session-123")
        self.assertEqual(
            data["verified_findings"][0]["status"],
            "VERIFIED_EXPLOITABLE",
        )

    def test_mock_fix_stage_and_report(self):
        result = subprocess.run(
            ["bash", self.script_path, "fix"],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)

        report_path = os.path.join(self.output_dir, "report.json")
        log_path = os.path.join(self.output_dir, "LOG.md")
        patch_path = os.path.join(self.output_dir, "patches", "SEC-FIND-101.diff")

        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.exists(log_path))
        self.assertTrue(os.path.exists(patch_path))

        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["total_patches_applied"], 1)
        self.assertIn("token_usage", report)


if __name__ == "__main__":
    unittest.main()
