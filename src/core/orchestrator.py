"""Core orchestration engine coordinating scan tasks and persistence."""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from ..models.scan_job import ScanJob, ScanStatus, ScanStage, DatabaseManager
from .persistence import PersistenceManager
from .docker_engine import DockerOrchestrator
from .k8s_engine import K8sJobOrchestrator

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Coordinates end-to-end scan lifecycle."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        storage_dir: Path,
        docker_socket_path: str = "/var/run/docker.sock",
        enable_mock_fallback: bool = True,
        execution_backend: str = "auto",
        k8s_namespace: str = "codemender-executors",
    ):
        self.db_manager = db_manager
        self.persistence = PersistenceManager(storage_dir)
        self.execution_backend = execution_backend
        self.docker_engine = DockerOrchestrator(
            socket_path=docker_socket_path,
            enable_mock_fallback=enable_mock_fallback,
        )
        self.k8s_engine = K8sJobOrchestrator(
            namespace=k8s_namespace,
            enable_mock_fallback=enable_mock_fallback,
        )

    def execute_scan(
        self,
        session_id: str,
        zip_file_path: Optional[Path] = None,
        language_flavor: str = "polyglot",
        stage: str = "all",
    ) -> Dict[str, Any]:
        """Runs the complete scan lifecycle synchronously or within a worker task."""
        job = self.db_manager.get_job(session_id)

        if not job:
            job = ScanJob(
                id=session_id,
                language_flavor=language_flavor,
                status=ScanStatus.RUNNING.value,
                stage=ScanStage.PROVISIONING.value,
            )
        else:
            job.status = ScanStatus.RUNNING.value
            job.stage = ScanStage.PROVISIONING.value
        self.db_manager.save_job(job)

        try:
            # 1. Setup session directory & extract archive
            paths = self.persistence.setup_session(session_id, zip_file_path)

            # 2. Update stage to execution
            job.stage = ScanStage.FIND.value
            self.db_manager.save_job(job)

            # 3. Stream execution logs (K8s GKE Autopilot or Docker Sandbox)
            image_name = f"codemender-executor:{language_flavor}"
            log_buffer = []

            if self.execution_backend == "k8s" or (self.execution_backend == "auto" and self.k8s_engine.batch_v1 is not None):
                engine_stream = self.k8s_engine.run_job(session_id, paths, image_name, stage)
            else:
                engine_stream = self.docker_engine.run_sandbox(session_id, paths, image_name, stage)

            for line in engine_stream:
                log_buffer.append(line)

            # Append logs to LOG.md
            log_file = paths["output_dir"] / "LOG.md"
            with open(log_file, "a", encoding="utf-8") as f:
                f.writelines(log_buffer)

            # 4. Parse results
            report = self.persistence.load_report(session_id)
            job.stage = ScanStage.REPORTING.value

            if report:
                job.vulnerabilities_found = report.get("total_vulnerabilities_found", 0)
                job.vulnerabilities_verified = report.get("total_vulnerabilities_verified", 0)
                job.patches_applied = report.get("total_patches_applied", 0)
                job.token_usage_json = json.dumps(report.get("token_usage", {}))

            job.status = ScanStatus.COMPLETED.value
            job.stage = ScanStage.TEARDOWN.value
            self.db_manager.save_job(job)

            return {
                "session_id": session_id,
                "status": ScanStatus.COMPLETED.value,
                "report": report,
            }

        except Exception as e:
            logger.exception("Scan execution failed for session %s: %s", session_id, e)
            job.status = ScanStatus.FAILED.value
            job.error_message = str(e)
            self.db_manager.save_job(job)
            return {
                "session_id": session_id,
                "status": ScanStatus.FAILED.value,
                "error": str(e),
            }
