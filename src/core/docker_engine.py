"""Docker container orchestrator with Watchdog Timer and PID/Resource Quotas."""

import os
import time
import signal
import subprocess
import logging
from pathlib import Path
from typing import Dict, Generator, Any, Optional

logger = logging.getLogger(__name__)

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


class DockerOrchestrator:
    """Spawns and monitors ephemeral Docker sandbox containers with Watchdog limits."""

    def __init__(
        self,
        socket_path: str = "/var/run/docker.sock",
        enable_mock_fallback: bool = True,
        watchdog_timeout_sec: int = 60,
    ):
        self.socket_path = socket_path
        self.enable_mock_fallback = enable_mock_fallback
        self.watchdog_timeout_sec = watchdog_timeout_sec
        self.client = None

        if DOCKER_AVAILABLE:
            try:
                self.client = docker.DockerClient(base_url=f"unix://{socket_path}")
                self.client.ping()
            except Exception as e:
                logger.warning("Docker daemon connection failed (%s). Mock mode will be used if enabled.", e)
                self.client = None

    def run_sandbox(
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
        """Runs the sandbox container with watchdog timeout and yields real-time log lines."""
        active_model = model_name or os.environ.get("CODEMENDER_MODEL", "gemini-4-argon")
        if self.client is not None:
            yield from self._run_docker_container(session_id, paths, image_name, stage, active_model)
        elif self.enable_mock_fallback:
            yield from self._run_mock_sandbox(
                session_id, paths, stage, active_model, finding_ids,
                external_json_path=external_json_path, source_tool=source_tool,
            )
        else:
            raise RuntimeError("Docker daemon is unavailable and mock fallback is disabled.")

    def _run_docker_container(
        self,
        session_id: str,
        paths: Dict[str, Path],
        image_name: str,
        stage: str,
        model_name: str,
    ) -> Generator[str, None, int]:
        """Executes sandbox container with PID limits and memory cgroups."""
        container_name = f"cm-sandbox-{session_id}-{stage}"
        volumes = {
            str(paths["source_dir"]): {"bind": "/workspace/source", "mode": "rw"},
            str(paths["output_dir"]): {"bind": "/workspace/output", "mode": "rw"},
            str(paths["config_dir"] / "config.yaml"): {"bind": "/home/cm/.codemender/config.yaml", "mode": "ro"},
        }
        environment = {
            "CODEMENDER_STAGE": stage,
            "CODEMENDER_SESSION_ID": session_id,
            "CODEMENDER_MODEL": model_name,
            "CODEMENDER_CLI_VERSION": os.environ.get("CODEMENDER_CLI_VERSION", "0.14.0"),
        }
        tmpfs = {"/run/codemender/state": "size=128M,exec"}

        yield f"[DISPATCHER-v2] Spawning hardened sandbox '{container_name}' (cm=v0.14.0, model={model_name}, stage={stage}, pids_limit=256, mem=2GB)...\n"

        try:
            container = self.client.containers.run(
                image=image_name,
                name=container_name,
                volumes=volumes,
                environment=environment,
                tmpfs=tmpfs,
                cap_drop=["ALL"],
                network_mode="none",
                pids_limit=256,
                mem_limit="2g",
                detach=True,
                remove=False,
            )

            # Stream logs with watchdog timeout
            start_time = time.time()
            for chunk in container.logs(stream=True, follow=True):
                yield chunk.decode("utf-8", errors="replace")
                if time.time() - start_time > self.watchdog_timeout_sec:
                    yield f"\n[DISPATCHER-WATCHDOG] Execution exceeded {self.watchdog_timeout_sec}s limit. Terminating sandbox container...\n"
                    container.kill()
                    container.remove(force=True)
                    return 124

            result = container.wait()
            exit_code = result.get("StatusCode", 0)
            yield f"[DISPATCHER] Container exited with status code: {exit_code}\n"
            container.remove(force=True)
            return exit_code

        except Exception as e:
            yield f"[DISPATCHER-ERROR] Failed executing container: {e}\n"
            return 1

    def _run_mock_sandbox(
        self,
        session_id: str,
        paths: Dict[str, Path],
        stage: str,
        model_name: str = "gemini-4-argon",
        finding_ids: Optional[list] = None,
        external_json_path: Optional[Path] = None,
        source_tool: Optional[str] = None,
    ) -> Generator[str, None, int]:
        """Dynamically scans real uploaded code or imports external JSON and executes the requested stage."""
        yield f"[DISPATCHER-v2] Sandbox active (cm v0.14.0 | Stage: {stage.upper()} | Model: {model_name}): analyzing {paths['source_dir']}...\n"

        from .scanner import DynamicCodeScanner
        scanner = DynamicCodeScanner(
            source_dir=paths["source_dir"],
            output_dir=paths["output_dir"],
            session_id=session_id,
            model_name=model_name,
        )

        try:
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
                    f"Imported {report.get('imported_findings_count', 0)} findings "
                    f"(Total active findings: {report['total_vulnerabilities_found']}).\n"
                )
            if stage in ("find", "all"):
                yield f"[CODEMENDER-FIND] ({model_name}) Scanned codebase. Found {report['total_vulnerabilities_found']} candidate vulnerabilities.\n"
            if stage in ("verify", "all"):
                for f in report.get("findings", []):
                    if f.get("verified") and (not finding_ids or f["id"] in finding_ids):
                        details = f.get("verification_details") or {}
                        yield (
                            f"[CODEMENDER-VERIFY] ({model_name}) {f['id']} ({f['type']} at {f['file']}:L{f['line']}) "
                            f"-> {details.get('status', 'VERIFIED_EXPLOITABLE')} via {details.get('harness_type', 'Sandbox')}\n"
                        )
            if stage in ("fix", "all"):
                for f in report.get("findings", []):
                    if f.get("remediated") and (not finding_ids or f["id"] in finding_ids):
                        yield f"[CODEMENDER-FIX] ({model_name}) {f['id']} -> Generated & validated patch: {f.get('patch_file')}\n"

            yield (
                f"[DISPATCHER] Stage '{stage.upper()}' complete. "
                f"Found: {report['total_vulnerabilities_found']} | "
                f"Verified: {report['total_vulnerabilities_verified']} | "
                f"Patched: {report['total_patches_applied']}\n"
            )
            return 0
        except Exception as e:
            yield f"[DISPATCHER-ERROR] Stage '{stage}' failed: {e}\n"
            return 1
