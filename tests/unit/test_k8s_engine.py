"""Unit tests for GKE Autopilot K8sJobOrchestrator and manifest security hardening."""

import tempfile
import unittest
from pathlib import Path

from src.core.k8s_engine import K8sJobOrchestrator


class TestK8sJobOrchestrator(unittest.TestCase):
    """Verifies Kubernetes batch Job manifest security constraints and gVisor sandboxing."""

    def setUp(self):
        self.orchestrator = K8sJobOrchestrator(
            namespace="codemender-executors",
            enable_mock_fallback=True,
        )

    def test_job_manifest_security_specs(self):
        manifest = self.orchestrator.generate_job_manifest(
            session_id="sec-session-42",
            image_name="codemender-executor:polyglot",
            stage="all",
        )

        self.assertEqual(manifest["apiVersion"], "batch/v1")
        self.assertEqual(manifest["kind"], "Job")
        self.assertEqual(manifest["metadata"]["name"], "cm-job-sec-session-42")
        self.assertEqual(manifest["metadata"]["namespace"], "codemender-executors")

        # Verify gVisor sandbox runtime & annotation
        template_spec = manifest["spec"]["template"]["spec"]
        metadata = manifest["spec"]["template"]["metadata"]
        self.assertEqual(template_spec["runtimeClassName"], "gvisor")
        self.assertEqual(metadata["annotations"]["autopilot.gke.io/sandbox"], "gvisor")

        # Verify least-privileged container security context
        container = template_spec["containers"][0]
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])

        # Verify container environment variables
        env_vars = {env["name"]: env["value"] for env in container["env"]}
        self.assertEqual(env_vars.get("CODEMENDER_STAGE"), "all")
        self.assertEqual(env_vars.get("CODEMENDER_SESSION_ID"), "sec-session-42")
        self.assertEqual(env_vars.get("CODEMENDER_MODEL"), "gemini-3.7-flash")

        # Verify tmpfs state mount
        volumes = {v["name"]: v for v in template_spec["volumes"]}
        self.assertIn("runtime-state", volumes)
        self.assertEqual(volumes["runtime-state"]["emptyDir"]["medium"], "Memory")

    def test_k8s_fallback_execution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source_dir = base / "source"
            output_dir = base / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            (source_dir / "vuln.py").write_text(
                'import os\ndef run_cmd(user):\n    os.system(f"echo {user}")\n',
                encoding="utf-8",
            )

            paths = {"source_dir": source_dir, "output_dir": output_dir}
            log_lines = list(self.orchestrator.run_job("test-k8s-sess", paths))

            log_output = "".join(log_lines)
            self.assertIn("GKE-AUTOPILOT", log_output)
            self.assertIn("COMMAND_INJECTION", log_output)


if __name__ == "__main__":
    unittest.main()
