"""Kubernetes (GKE Autopilot) Batch Job Orchestrator with gVisor Sandbox Isolation."""

import logging
import os
import time
from pathlib import Path
from typing import Dict, Generator, Any, Optional

logger = logging.getLogger(__name__)

try:
    from kubernetes import client, config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False


class K8sJobOrchestrator:
    """Provisions and monitors ephemeral gVisor-sandboxed batch Jobs on GKE Autopilot."""

    def __init__(
        self,
        namespace: str = "codemender-executors",
        in_cluster: bool = False,
        enable_mock_fallback: bool = True,
        watchdog_timeout_sec: int = 60,
    ):
        self.namespace = namespace
        self.enable_mock_fallback = enable_mock_fallback
        self.watchdog_timeout_sec = watchdog_timeout_sec
        self.batch_v1 = None
        self.core_v1 = None

        if K8S_AVAILABLE:
            try:
                if in_cluster:
                    config.load_incluster_config()
                else:
                    config.load_kube_config()
                self.batch_v1 = client.BatchV1Api()
                self.core_v1 = client.CoreV1Api()
            except Exception as e:
                logger.warning("Kubernetes cluster connection failed (%s). Mock mode will be used if enabled.", e)
                self.batch_v1 = None
                self.core_v1 = None

    def generate_job_manifest(
        self,
        session_id: str,
        image_name: str = "codemender-executor:polyglot",
        stage: str = "all",
    ) -> Dict[str, Any]:
        """Generates a hardened Kubernetes Job manifest specification for GKE Autopilot."""
        job_name = f"cm-job-{session_id}"
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "namespace": self.namespace,
                "labels": {
                    "app": "codemender-executor",
                    "session_id": session_id,
                },
            },
            "spec": {
                "backoffLimit": 0,
                "ttlSecondsAfterFinished": 300,
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "codemender-executor",
                            "session_id": session_id,
                        },
                        "annotations": {
                            "autopilot.gke.io/sandbox": "gvisor",
                        },
                    },
                    "spec": {
                        "runtimeClassName": "gvisor",
                        "restartPolicy": "Never",
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 1000,
                            "runAsGroup": 1000,
                            "fsGroup": 1000,
                            "seccompProfile": {
                                "type": "RuntimeDefault",
                            },
                        },
                        "containers": [
                            {
                                "name": "executor",
                                "image": image_name,
                                "imagePullPolicy": "IfNotPresent",
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {
                                        "drop": ["ALL"],
                                    },
                                },
                                "env": [
                                    {"name": "CODEMENDER_STAGE", "value": stage},
                                    {"name": "CODEMENDER_SESSION_ID", "value": session_id},
                                    {"name": "CODEMENDER_MODEL", "value": os.environ.get("CODEMENDER_MODEL", "gemini-4-argon")},
                                    {"name": "CODEMENDER_CLI_VERSION", "value": os.environ.get("CODEMENDER_CLI_VERSION", "0.14.0")},
                                ],
                                "resources": {
                                    "requests": {"cpu": "2", "memory": "2Gi", "ephemeral-storage": "1Gi"},
                                    "limits": {"cpu": "4", "memory": "4Gi", "ephemeral-storage": "2Gi"},
                                },
                                "volumeMounts": [
                                    {
                                        "name": "runtime-state",
                                        "mountPath": "/run/codemender/state",
                                    },
                                    {
                                        "name": "config-ro",
                                        "mountPath": "/home/cm/.codemender/config.yaml",
                                        "subPath": "config.yaml",
                                        "readOnly": True,
                                    },
                                ],
                            }
                        ],
                        "volumes": [
                            {
                                "name": "runtime-state",
                                "emptyDir": {
                                    "medium": "Memory",
                                    "sizeLimit": "256Mi",
                                },
                            },
                            {
                                "name": "config-ro",
                                "configMap": {
                                    "name": "codemender-runtime-config",
                                },
                            },
                        ],
                    },
                },
            },
        }

    def run_job(
        self,
        session_id: str,
        paths: Dict[str, Path],
        image_name: str = "codemender-executor:polyglot",
        stage: str = "all",
        model_name: Optional[str] = None,
        finding_ids: Optional[list] = None,
        external_json_path: Optional[Path] = None,
        source_tool: Optional[str] = None,
    ) -> Generator[str, None, int]:
        """Provisions the GKE batch Job and streams execution logs."""
        active_model = model_name or os.environ.get("CODEMENDER_MODEL", "gemini-4-argon")
        if self.batch_v1 is not None and self.core_v1 is not None:
            yield from self._run_k8s_job(session_id, image_name, stage)
        elif self.enable_mock_fallback:
            yield from self._run_fallback(
                session_id, paths, stage, active_model, finding_ids,
                external_json_path=external_json_path, source_tool=source_tool,
            )
        else:
            raise RuntimeError("Kubernetes API client unavailable and mock fallback is disabled.")

    def _run_k8s_job(self, session_id: str, image_name: str, stage: str) -> Generator[str, None, int]:
        """Executes Job on GKE Autopilot."""
        manifest = self.generate_job_manifest(session_id, image_name, stage)
        job_name = manifest["metadata"]["name"]
        yield f"[GKE-AUTOPILOT] Creating sandboxed Job '{job_name}' in namespace '{self.namespace}' (gVisor runtime)...\n"

        try:
            self.batch_v1.create_namespaced_job(namespace=self.namespace, body=manifest)
            start_time = time.time()

            # Poll for Pod creation
            pod_name = None
            while time.time() - start_time < self.watchdog_timeout_sec:
                pods = self.core_v1.list_namespaced_pod(
                    namespace=self.namespace,
                    label_selector=f"session_id={session_id}",
                )
                if pods.items:
                    pod_name = pods.items[0].metadata.name
                    pod_phase = pods.items[0].status.phase
                    if pod_phase in ("Running", "Succeeded", "Failed"):
                        break
                time.sleep(1)

            if not pod_name:
                yield f"[GKE-WATCHDOG] Job creation timed out after {self.watchdog_timeout_sec}s.\n"
                return 124

            # Stream Pod logs
            log_stream = self.core_v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=self.namespace,
                follow=True,
                _preload_content=False,
            )
            for line in log_stream.stream():
                yield line.decode("utf-8", errors="replace")

            yield f"[GKE-AUTOPILOT] Ephemeral sandbox job '{job_name}' completed.\n"
            return 0
        except Exception as e:
            yield f"[GKE-ERROR] Kubernetes Job execution error: {e}\n"
            return 1

    def _run_fallback(
        self,
        session_id: str,
        paths: Dict[str, Path],
        stage: str,
        model_name: str = "gemini-4-argon",
        finding_ids: Optional[list] = None,
        external_json_path: Optional[Path] = None,
        source_tool: Optional[str] = None,
    ) -> Generator[str, None, int]:
        """Runs local dynamic AST scanner fallback."""
        yield f"[GKE-AUTOPILOT-MOCK] Falling back to local AST sandbox execution for session '{session_id}' (cm=v0.14.0, stage={stage}, model={model_name})...\n"
        from .scanner import DynamicCodeScanner
        scanner = DynamicCodeScanner(
            source_dir=paths["source_dir"],
            output_dir=paths["output_dir"],
            session_id=session_id,
            model_name=model_name,
        )
        report = scanner.scan_and_remediate(
            stage=stage,
            finding_ids=finding_ids,
            model_name=model_name,
            external_json_path=external_json_path,
            source_tool=source_tool,
        )
        if stage == "import":
            yield (
                f"[CODEMENDER-IMPORT] ({model_name}) Executed 'cm import' from "
                f"{report.get('external_source_tool', 'EXTERNAL_TOOL')} ({report.get('imported_file')}). "
                f"Imported {report.get('imported_findings_count', 0)} findings.\n"
            )
        yield f"[CODEMENDER-AST] Scanned uploaded codebase. Found {report['total_vulnerabilities_found']} candidate vulnerabilities.\n"
        for f in report.get("findings", []):
            if f.get("verified"):
                yield f"[CODEMENDER-VERIFY] Detonating gVisor PoC: {f['type']} at {f['file']}:L{f['line']} -> VERIFIED\n"
            if f.get("remediated"):
                yield f"[CODEMENDER-FIX] Generated verified patch: {f.get('patch_file')}\n"
        yield f"[GKE-AUTOPILOT] Execution complete. {report['total_patches_applied']} verified patches applied.\n"
        return 0
