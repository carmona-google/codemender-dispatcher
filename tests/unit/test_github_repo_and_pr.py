"""Unit and integration tests for carmona-google GitHub repository input and Step 4 Pull Request creation."""

import os
import shutil
import tempfile
import unittest

from src.app import create_app
from src.config import Config
from src.core.github_client import GitHubClient


class TestGitHubRepoAndPullRequestStep(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cm_gh_pr_test_")
        self.test_storage = os.path.join(self.temp_dir, "storage")
        os.makedirs(self.test_storage, exist_ok=True)

        test_storage_path = self.test_storage
        db_file_path = os.path.join(self.temp_dir, "test_cm.db")

        class TestConfig(Config):
            TESTING = True
            STORAGE_DIR = test_storage_path
            DATABASE_URI = f"sqlite:///{db_file_path}"
            ENABLE_MOCK_FALLBACK = True
            GITHUB_ACCOUNT = "carmona-google"

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_normalize_repo_name_defaults_to_carmona_google(self):
        """Ensure short repo names and full GitHub URLs normalize to carmona-google/<repo>."""
        self.assertEqual(
            GitHubClient.normalize_repo_name("my-service"),
            "carmona-google/my-service",
        )
        self.assertEqual(
            GitHubClient.normalize_repo_name("carmona-google/codemender-demo-app"),
            "carmona-google/codemender-demo-app",
        )
        self.assertEqual(
            GitHubClient.normalize_repo_name("https://github.com/carmona-google/supply-chain-demo.git"),
            "carmona-google/supply-chain-demo",
        )

    def test_list_github_repos_endpoint(self):
        """Verify GET /api/v1/scans/github/repos returns carmona-google repositories."""
        resp = self.client.get("/api/v1/scans/github/repos?account=carmona-google")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["account"], "carmona-google")
        self.assertTrue(len(data["repositories"]) >= 1)
        self.assertTrue(
            any(r["full_name"].startswith("carmona-google/") for r in data["repositories"])
        )

    def test_github_repo_input_and_step4_pull_request_after_fix(self):
        """Verify full flow: GitHub repo input -> find -> verify -> fix -> Step 4 Create PR."""
        # 1. Create scan session using carmona-google GitHub repository input (no zip file)
        create_resp = self.client.post(
            "/api/v1/scans",
            data={
                "github_repo": "codemender-demo-app",
                "github_branch": "main",
                "stage": "find",
                "model_name": "gemini-4-argon",
            },
        )
        self.assertEqual(create_resp.status_code, 202)
        create_data = create_resp.get_json()
        scan_id = create_data["session_id"]
        self.assertEqual(create_data["github_repo"], "carmona-google/codemender-demo-app")
        self.assertEqual(create_data["github_branch"], "main")

        # Verify candidate vulnerabilities were discovered in the cloned/seeded repo
        status_resp = self.client.get(f"/api/v1/scans/{scan_id}")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.get_json()
        self.assertGreaterEqual(status_data["vulnerabilities_found"], 1)

        # 2. Run Step 2: Verify
        verify_resp = self.client.post(
            f"/api/v1/scans/{scan_id}/verify",
            json={"model_name": "gemini-4-argon"},
        )
        self.assertEqual(verify_resp.status_code, 200)
        verify_data = verify_resp.get_json()
        self.assertEqual(verify_data["stage"], "VERIFY")
        self.assertGreaterEqual(verify_data["vulnerabilities_verified"], 1)

        # 3. Run Step 3: Fix
        fix_resp = self.client.post(
            f"/api/v1/scans/{scan_id}/fix",
            json={"model_name": "gemini-4-argon"},
        )
        self.assertEqual(fix_resp.status_code, 200)
        fix_data = fix_resp.get_json()
        self.assertEqual(fix_data["stage"], "FIX")
        self.assertGreaterEqual(fix_data["patches_applied"], 1)

        # 4. Run Step 4 (after Fix): Create Pull Request on carmona-google repo
        pr_resp = self.client.post(
            f"/api/v1/scans/{scan_id}/pr",
            json={
                "github_repo": "carmona-google/codemender-demo-app",
                "github_branch": "main",
                "model_name": "gemini-4-argon",
            },
        )
        self.assertEqual(pr_resp.status_code, 200)
        pr_data = pr_resp.get_json()
        self.assertEqual(pr_data["stage"], "PULL_REQUEST")
        self.assertEqual(pr_data["github_repo"], "carmona-google/codemender-demo-app")
        self.assertTrue(
            pr_data["pr_url"].startswith("https://github.com/carmona-google/codemender-demo-app/pull/")
        )
        self.assertIsNotNone(pr_data["pr_number"])
        self.assertIn("[CODEMENDER-PR] (carmona-google)", pr_data["logs"])

        # 5. Check Web UI renders Step 4 PR banner and carmona-google repo details
        detail_html = self.client.get(f"/scans/{scan_id}").get_data(as_text=True)
        self.assertIn("STEP 4 COMPLETE", detail_html)
        self.assertIn("carmona-google/codemender-demo-app", detail_html)
        self.assertIn(pr_data["pr_url"], detail_html)

    def test_autonomous_all_with_pr_mode(self):
        """Verify stage='all_with_pr' runs find -> verify -> fix -> pr autonomously."""
        resp = self.client.post(
            "/api/v1/scans",
            json={
                "github_repo": "https://github.com/carmona-google/supply-chain-demo",
                "github_branch": "main",
                "stage": "all_with_pr",
                "model_name": "gemini-4-argon",
            },
        )
        self.assertEqual(resp.status_code, 202)
        data = resp.get_json()
        self.assertEqual(data["stage"], "PULL_REQUEST")
        self.assertEqual(data["github_repo"], "carmona-google/supply-chain-demo")
        self.assertIn("https://github.com/carmona-google/supply-chain-demo/pull/", data["pr_url"])


if __name__ == "__main__":
    unittest.main()
