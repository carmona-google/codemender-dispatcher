"""Unit tests for supply-chain cascade detection and patching in DynamicCodeScanner."""

import tempfile
import unittest
import zipfile
from pathlib import Path
from src.core.scanner import DynamicCodeScanner


class TestSupplyChainScanner(unittest.TestCase):
    """Verifies AST/manifest detection and .diff generation for the 3-hop supply-chain cascade."""

    def setUp(self):
        self.demo_zip = Path(__file__).resolve().parents[2] / "demo" / "ai-supply-chain-cascade-demo.zip"
        self.assertTrue(self.demo_zip.exists(), f"Expected demo archive at {self.demo_zip}")
        self._src_tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._src_tmp.name)
        with zipfile.ZipFile(self.demo_zip, "r") as zf:
            zf.extractall(self.repo_dir)

    def tearDown(self):
        self._src_tmp.cleanup()

    def test_scan_ai_supply_chain_cascade_demo(self):
        """Scans the ai-supply-chain-cascade-demo repo and verifies all 6 findings and patches."""
        with tempfile.TemporaryDirectory() as out_dir:
            output_path = Path(out_dir)
            scanner = DynamicCodeScanner(
                source_dir=self.repo_dir,
                output_dir=output_path,
                session_id="test-cascade-session",
            )
            report = scanner.scan_and_remediate()

            self.assertEqual(report["status"], "COMPLETED")
            self.assertEqual(report["model_name"], "gemini-4-argon")
            self.assertEqual(report["cm_version"], "0.14.0")
            self.assertEqual(report["total_vulnerabilities_found"], 6)
            self.assertEqual(report["total_vulnerabilities_verified"], 6)
            self.assertEqual(report["total_patches_applied"], 6)

            finding_types = {f["type"] for f in report["findings"]}
            self.assertIn("SUPPLY_CHAIN_PTH_STARTUP_HOOK", finding_types)
            self.assertIn("SUPPLY_CHAIN_POISONED_DEPENDENCY", finding_types)
            self.assertIn("CICD_SUPPLY_CHAIN_UNPINNED_ACTION", finding_types)
            self.assertIn("HARDCODED_CREDENTIAL", finding_types)

            # Verify patches directory contains non-empty .diff files
            patches_dir = output_path / "patches"
            diff_files = list(patches_dir.glob("*.diff"))
            self.assertEqual(len(diff_files), 6)
            for diff_file in diff_files:
                content = diff_file.read_text(encoding="utf-8")
                self.assertIn("--- a/", content)
                self.assertIn("+++ b/", content)

    def test_staged_scan_verify_and_fix_by_id(self):
        """Verifies staged execution (find -> selective verify -> selective fix) and exploit telemetry."""
        with tempfile.TemporaryDirectory() as out_dir:
            output_path = Path(out_dir)
            scanner = DynamicCodeScanner(
                source_dir=self.repo_dir,
                output_dir=output_path,
                session_id="test-staged-session",
                model_name="gemini-3.8-cyber-flash",
            )

            # 1. Stage 1: Scan (cm find)
            report_find = scanner.scan_and_remediate(stage="find")
            self.assertEqual(report_find["status"], "COMPLETED")
            self.assertEqual(report_find["stage"], "FIND")
            self.assertEqual(report_find["model_name"], "gemini-3.8-cyber-flash")
            self.assertEqual(report_find["total_vulnerabilities_found"], 6)
            self.assertEqual(report_find["total_vulnerabilities_verified"], 0)
            self.assertEqual(report_find["total_patches_applied"], 0)

            discovered_ids = [f["id"] for f in report_find["findings"]]
            first_id = discovered_ids[0]
            second_id = discovered_ids[1]
            third_id = discovered_ids[2]

            # 2. Stage 2: Selective Verify (cm verify) for first 2 IDs
            report_verify = scanner.scan_and_remediate(
                stage="verify",
                finding_ids=[first_id, second_id],
            )
            self.assertEqual(report_verify["status"], "COMPLETED")
            self.assertEqual(report_verify["stage"], "VERIFY")
            self.assertEqual(report_verify["total_vulnerabilities_verified"], 2)
            self.assertEqual(report_verify["total_patches_applied"], 0)

            findings_by_id = {f["id"]: f for f in report_verify["findings"]}
            self.assertTrue(findings_by_id[first_id]["verified"])
            self.assertTrue(findings_by_id[second_id]["verified"])
            self.assertFalse(findings_by_id[third_id]["verified"])

            # Check rich verification exploit telemetry on first_id
            v_details = findings_by_id[first_id]["verification_details"]
            self.assertEqual(v_details["status"], "VERIFIED_EXPLOITABLE")
            self.assertEqual(v_details["model_used"], "gemini-3.8-cyber-flash")
            self.assertTrue(len(v_details["harness_type"]) > 0)
            self.assertTrue(len(v_details["exploit_summary"]) > 0)
            self.assertTrue(len(v_details["simulated_trigger"]) > 0)
            self.assertTrue(len(v_details["observed_behavior"]) > 0)
            self.assertTrue(len(v_details["sandbox_guardrails"]) >= 3)

            # 3. Stage 3: Selective Fix (cm fix) for first_id only
            report_fix = scanner.scan_and_remediate(
                stage="fix",
                finding_ids=[first_id],
            )
            self.assertEqual(report_fix["status"], "COMPLETED")
            self.assertEqual(report_fix["stage"], "FIX")
            self.assertEqual(report_fix["total_patches_applied"], 1)
            findings_by_id_after_fix = {f["id"]: f for f in report_fix["findings"]}
            self.assertTrue(findings_by_id_after_fix[first_id]["remediated"])
            self.assertFalse(findings_by_id_after_fix[second_id]["remediated"])


if __name__ == "__main__":
    unittest.main()

