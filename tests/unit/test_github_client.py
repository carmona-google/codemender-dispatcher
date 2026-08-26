"""Unit tests for GitHubClient formatting and mock API flows."""

import unittest
from src.core.github_client import GitHubClient


class TestGitHubClient(unittest.TestCase):
    """Verifies GitHub PR comment generation and mock API operations."""

    def setUp(self):
        self.client = GitHubClient(enable_mock=True)

    def test_format_vulnerability_pr_comment_with_findings(self):
        report = {
            "total_vulnerabilities_found": 1,
            "total_vulnerabilities_verified": 1,
            "total_patches_applied": 1,
            "findings": [
                {
                    "id": "SEC-001-100",
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "file": "app/db.py",
                    "line": 42,
                }
            ],
        }
        comment = self.client.format_vulnerability_pr_comment(report, "scan-12345")
        self.assertIn("CodeMender Security Report", comment)
        self.assertIn("SQL_INJECTION", comment)
        self.assertIn("app/db.py:42", comment)
        self.assertIn("CRITICAL", comment)
        self.assertIn("scan-12345", comment)

    def test_format_vulnerability_pr_comment_clean(self):
        report = {
            "total_vulnerabilities_found": 0,
            "total_vulnerabilities_verified": 0,
            "total_patches_applied": 0,
            "findings": [],
        }
        comment = self.client.format_vulnerability_pr_comment(report, "scan-clean-01")
        self.assertIn("CLEAN", comment)
        self.assertIn("No high-confidence vulnerabilities detected", comment)

    def test_mock_post_comment_and_create_pr(self):
        comment_resp = self.client.post_pr_comment("org/repo", 42, "Security check passed.")
        self.assertIn("html_url", comment_resp)
        self.assertIn("pull/42", comment_resp["html_url"])

        pr_resp = self.client.create_remediation_pr(
            repo_name="org/repo",
            base_branch="main",
            feature_branch="codemender/patch-pr-42",
            title="fix(security): Fix SQLi",
            body="Remediated query injection.",
        )
        self.assertIn("number", pr_resp)
        self.assertEqual(pr_resp["head"]["ref"], "codemender/patch-pr-42")


if __name__ == "__main__":
    unittest.main()
