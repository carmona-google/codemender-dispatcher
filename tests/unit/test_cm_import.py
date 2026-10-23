import io
import json
import os
import shutil
import tempfile
import unittest

from src.app import create_app
from src.config import Config
from src.core.scanner import DynamicCodeScanner


class TestCmImportFunctionality(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cm_import_test_")
        self.source_dir = os.path.join(self.temp_dir, "source")
        self.output_dir = os.path.join(self.temp_dir, "output")
        self.state_dir = os.path.join(self.temp_dir, "state")
        os.makedirs(self.source_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.state_dir, exist_ok=True)
        self.scanner = DynamicCodeScanner(
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            session_id="scan-import-test",
            cm_version="0.14.0",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_import_wiz_code_json_and_verify_and_fix(self):
        """Verify cm import parses Wiz Code JSON, then cm verify and cm fix work end-to-end."""
        wiz_payload = {
            "scan_metadata": {"scanner": "Wiz Code Unified Scanner"},
            "vulnerabilities": [
                {
                    "id": "WIZ-VULN-2026-109618-COMPOSER",
                    "cve": "CVE-2026-109618",
                    "severity": "CRITICAL",
                    "package_name": "phpunit/phpunit",
                    "installed_version": "^10.5.0",
                    "fixed_version": "10.5.38",
                    "file_path": "composer.json",
                    "line": 12,
                },
                {
                    "id": "WIZ-VULN-2026-109619-PIP",
                    "cve": "CVE-2026-109619",
                    "severity": "CRITICAL",
                    "package_name": "pytest-cov-bridge",
                    "installed_version": "1.4.2",
                    "fixed_version": "1.4.3",
                    "file_path": "requirements.txt",
                    "line": 4,
                },
            ],
            "sast_cicd_findings": [
                {
                    "id": "WIZ-SAST-GHA-0019",
                    "rule_id": "CICD-GHA-UNTRUSTED-CHECKOUT-PR-TARGET",
                    "severity": "HIGH",
                    "file_path": ".github/workflows/ci-verification.yml",
                    "line": 18,
                    "snippet": "ref: ${{ github.event.pull_request.head.sha }}",
                }
            ],
        }
        ext_json_path = os.path.join(self.state_dir, "wiz_export.json")
        with open(ext_json_path, "w", encoding="utf-8") as f:
            json.dump(wiz_payload, f)

        # 1. Run cm import
        report = self.scanner.scan_and_remediate(
            stage="import",
            external_json_path=ext_json_path,
            source_tool="AUTO",
        )
        self.assertEqual(report["total_vulnerabilities_found"], 3)
        self.assertEqual(report["total_vulnerabilities_verified"], 0)
        self.assertEqual(report["total_patches_applied"], 0)
        self.assertTrue(all(f["source_tool"] == "WIZ_CODE" for f in report["findings"]))
        self.assertTrue(all(f["id"].startswith("IMP-") for f in report["findings"]))

        # 2. Run cm verify on imported findings
        verified_report = self.scanner.scan_and_remediate(
            stage="verify",
        )
        self.assertEqual(verified_report["total_vulnerabilities_verified"], 3)
        for finding in verified_report["findings"]:
            self.assertTrue(finding["verified"])
            self.assertIn("verification_details", finding)

        # 3. Run cm fix on imported findings (even without source files present)
        fixed_report = self.scanner.scan_and_remediate(
            stage="fix",
        )
        self.assertEqual(fixed_report["total_patches_applied"], 3)
        for finding in fixed_report["findings"]:
            self.assertTrue(finding["remediated"])
            patch_path = os.path.join(self.output_dir, finding["patch_file"])
            self.assertTrue(os.path.exists(patch_path))

    def test_import_sarif_json(self):
        """Verify cm import auto-detects and normalizes SARIF v2.1.0 JSON reports."""
        sarif_payload = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep OSS"}},
                    "results": [
                        {
                            "ruleId": "python.lang.security.audit.exec-detected",
                            "level": "error",
                            "message": {"text": "Detected dynamic command execution via subprocess."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/runner.py"},
                                        "region": {"startLine": 55},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        ext_json_path = os.path.join(self.state_dir, "results.sarif.json")
        with open(ext_json_path, "w", encoding="utf-8") as f:
            json.dump(sarif_payload, f)

        report = self.scanner.scan_and_remediate(
            stage="import",
            external_json_path=ext_json_path,
            source_tool="AUTO",
        )
        self.assertEqual(report["total_vulnerabilities_found"], 1)
        f0 = report["findings"][0]
        self.assertEqual(f0["type"], "PYTHON.LANG.SECURITY.AUDIT.EXEC_DETECTED")
        self.assertEqual(f0["severity"], "CRITICAL")
        self.assertEqual(f0["file"], "src/runner.py")
        self.assertEqual(f0["line"], 55)
        self.assertEqual(f0["source_tool"], "SEMGREP_OSS")

    def test_api_import_endpoints(self):
        """Verify POST /api/v1/scans/import and POST /api/v1/scans/<id>/import endpoints."""
        test_storage = os.path.join(self.temp_dir, "storage")
        os.makedirs(test_storage, exist_ok=True)

        class TestConfig(Config):
            TESTING = True
            STORAGE_DIR = test_storage

        app = create_app(TestConfig)
        client = app.test_client()

        json_bytes = json.dumps(
            {
                "findings": [
                    {
                        "id": "EXT-SQLI-01",
                        "type": "SQL_INJECTION",
                        "severity": "CRITICAL",
                        "file": "app/models.py",
                        "line": 29,
                        "snippet": "cursor.execute(f'SELECT * FROM accounts WHERE id={uid}')",
                    }
                ]
            }
        ).encode("utf-8")

        resp = client.post(
            "/api/v1/scans/import",
            data={
                "findings_file": (io.BytesIO(json_bytes), "external_findings.json"),
                "source_tool": "TRIVY",
                "model_name": "gemini-4-argon",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["status"], "COMPLETED")
        self.assertEqual(body["stage"], "IMPORT")
        self.assertEqual(body["findings_imported"], 1)
        scan_id = body["scan_id"]

        # Import an additional JSON file into the same scan session
        second_json = json.dumps(
            {
                "findings": [
                    {
                        "id": "EXT-SSRF-02",
                        "type": "SSRF",
                        "severity": "HIGH",
                        "file": "app/webhook.py",
                        "line": 74,
                        "snippet": "requests.get(user_supplied_url)",
                    }
                ]
            }
        ).encode("utf-8")

        resp2 = client.post(
            f"/api/v1/scans/{scan_id}/import",
            data={
                "findings_file": (io.BytesIO(second_json), "more_findings.json"),
                "source_tool": "SNYK",
                "model_name": "gemini-4-argon",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp2.status_code, 200)
        body2 = resp2.get_json()
        self.assertEqual(body2["findings_imported"], 2)

        # Trigger fix stage and verify red (before) and green (after) diff highlighting in Web UI
        fix_resp = client.post(
            f"/api/v1/scans/{scan_id}/fix",
            json={"model_name": "gemini-4-argon"},
        )
        self.assertEqual(fix_resp.status_code, 200)

        detail_resp = client.get(f"/scans/{scan_id}")
        self.assertEqual(detail_resp.status_code, 200)
        html = detail_resp.get_data(as_text=True)
        self.assertIn("diff-line-before", html)
        self.assertIn("bg-rose-950/60 text-rose-300 border-l-4 border-rose-500", html)
        self.assertIn("diff-line-after", html)
        self.assertIn("bg-emerald-950/60 text-emerald-300 border-l-4 border-emerald-500", html)


if __name__ == "__main__":
    unittest.main()
