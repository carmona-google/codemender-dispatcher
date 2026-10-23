"""Unit tests for CVE-2026-109618 and CVE-2026-109619 detection, verification, and patching."""

import tempfile
import unittest
import zipfile
from pathlib import Path
from src.core.scanner import DynamicCodeScanner


class TestCve2026Scanner(unittest.TestCase):
    """Verifies detection, sandbox telemetry, and .diff patches for codemender-cve-2026-test.zip."""

    def setUp(self):
        self.target_zip = (
            Path(__file__).resolve().parents[2] / "demo" / "codemender-cve-2026-test.zip"
        )
        self.assertTrue(self.target_zip.exists(), f"Expected archive at {self.target_zip}")

        self._src_tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._src_tmp.name)
        with zipfile.ZipFile(self.target_zip, "r") as zf:
            zf.extractall(self.repo_dir)

    def tearDown(self):
        self._src_tmp.cleanup()

    def test_scan_verify_and_fix_cve_2026_test_zip(self):
        """Scans codemender-cve-2026-test.zip and verifies all 9 findings and unified diffs."""
        with tempfile.TemporaryDirectory() as out_dir:
            output_path = Path(out_dir)
            scanner = DynamicCodeScanner(
                source_dir=self.repo_dir,
                output_dir=output_path,
                session_id="test-cve-2026-session",
            )
            report = scanner.scan_and_remediate()

            self.assertEqual(report["status"], "COMPLETED")
            self.assertEqual(report["total_vulnerabilities_found"], 9)
            self.assertEqual(report["total_vulnerabilities_verified"], 9)
            self.assertEqual(report["total_patches_applied"], 9)

            finding_types = {f["type"] for f in report["findings"]}
            self.assertIn("C_OOM_BAILOUT_STATE_CORRUPTION", finding_types)
            self.assertIn("C_CROSS_REQUEST_STALE_GLOBAL_UAF", finding_types)
            self.assertIn("PHP_OBJECT_INJECTION_GADGET", finding_types)
            self.assertIn("PHP_RUNTIME_MISCONFIGURATION", finding_types)
            self.assertIn("SUPPLY_CHAIN_VULNERABLE_RUNTIME", finding_types)
            self.assertIn("IAC_CLOUD_EXPOSURE_MISCONFIGURATION", finding_types)

            for finding in report["findings"]:
                self.assertTrue(
                    finding.get("description") and len(finding["description"]) > 20,
                    f"Expected non-empty description for {finding['id']}",
                )

            patches_dir = output_path / "patches"
            diff_files = list(patches_dir.glob("*.diff"))
            self.assertEqual(len(diff_files), 9)
            for diff_file in diff_files:
                content = diff_file.read_text(encoding="utf-8")
                self.assertIn("--- a/", content)
                self.assertIn("+++ b/", content)


if __name__ == "__main__":
    unittest.main()
