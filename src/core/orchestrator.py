"""Core orchestration engine coordinating scan tasks and persistence."""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from ..models.scan_job import ScanJob, ScanStatus, ScanStage, DatabaseManager
from .persistence import PersistenceManager
from .docker_engine import DockerOrchestrator
from .k8s_engine import K8sJobOrchestrator
from .github_client import GitHubClient, DEFAULT_GITHUB_ACCOUNT

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
        github_token: Optional[str] = None,
        github_account: str = DEFAULT_GITHUB_ACCOUNT,
    ):
        self.db_manager = db_manager
        self.persistence = PersistenceManager(storage_dir)
        self.execution_backend = execution_backend
        self.enable_mock_fallback = enable_mock_fallback
        self.github_token = github_token
        self.github_account = github_account or DEFAULT_GITHUB_ACCOUNT
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
        model_name: Optional[str] = None,
        finding_ids: Optional[list] = None,
        external_json_path: Optional[Path] = None,
        source_tool: Optional[str] = None,
        github_repo: Optional[str] = None,
        github_branch: Optional[str] = None,
        github_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Runs the requested scan stage ('import', 'find', 'verify', 'fix', 'pr', 'all', or 'all_with_pr')."""
        job = self.db_manager.get_job(session_id)
        stage_norm = (stage or "all").lower()

        stage_map = {
            "import": ScanStage.IMPORT.value,
            "find": ScanStage.FIND.value,
            "verify": ScanStage.VERIFY.value,
            "fix": ScanStage.FIX.value,
            "pr": ScanStage.PULL_REQUEST.value,
            "all": ScanStage.FIND.value,
            "all_with_pr": ScanStage.FIND.value,
        }
        target_stage_enum = stage_map.get(stage_norm, ScanStage.FIND.value)

        active_token = (github_token or self.github_token or "").strip() or None
        gh_client = GitHubClient(
            token=active_token,
            account=self.github_account,
            enable_mock=self.enable_mock_fallback,
        )

        normalized_repo = None
        if github_repo:
            normalized_repo = gh_client.normalize_repo_name(github_repo, default_owner=self.github_account)

        if not job:
            job = ScanJob(
                id=session_id,
                language_flavor=language_flavor,
                model_name=model_name,
                status=ScanStatus.RUNNING.value,
                stage=target_stage_enum,
                github_repo=normalized_repo,
                github_branch=github_branch or ("main" if normalized_repo else None),
            )
        else:
            job.status = ScanStatus.RUNNING.value
            job.stage = target_stage_enum
            if model_name:
                job.model_name = model_name
            if normalized_repo:
                job.github_repo = normalized_repo
            if github_branch:
                job.github_branch = github_branch
        self.db_manager.save_job(job)

        try:
            # 1. Setup session directory & extract archive (if zip_file_path provided)
            paths = self.persistence.setup_session(session_id, zip_file_path)

            # 1b. Clone GitHub repository if github_repo is configured and source_dir is empty
            source_has_files = any(paths["source_dir"].iterdir()) if paths["source_dir"].exists() else False
            if job.github_repo and not zip_file_path and not source_has_files:
                clone_info = gh_client.clone_repository(
                    repo_input=job.github_repo,
                    target_dir=paths["source_dir"],
                    branch=job.github_branch or "main",
                )
                job.github_repo = clone_info["repo_name"]
                job.github_branch = clone_info["branch"]
                if not job.source_filename:
                    job.source_filename = f"github:{clone_info['repo_name']}@{clone_info['branch']}"
                self.db_manager.save_job(job)

                log_file = paths["output_dir"] / "LOG.md"
                with open(log_file, "a", encoding="utf-8") as lf:
                    lf.write(
                        f"[GITHUB-INGESTION] Connected repository '{clone_info['repo_name']}' "
                        f"(branch: {clone_info['branch']}) via GitHub account '{gh_client.account}'.\n"
                    )

            # Copy external JSON into session state directory if provided
            staged_json_path = None
            if external_json_path and Path(external_json_path).exists():
                import shutil
                staged_json_path = paths["state_dir"] / Path(external_json_path).name
                if Path(external_json_path).resolve() != staged_json_path.resolve():
                    shutil.copy2(external_json_path, staged_json_path)

            # 2. Stream execution logs for sandbox stages (import, find, verify, fix, all)
            sandbox_stage = "all" if stage_norm == "all_with_pr" else stage_norm
            if sandbox_stage != "pr":
                image_name = f"codemender-executor:{job.language_flavor}"
                log_buffer = []

                if self.execution_backend == "k8s" or (self.execution_backend == "auto" and self.k8s_engine.batch_v1 is not None):
                    engine_stream = self.k8s_engine.run_job(
                        session_id, paths, image_name, sandbox_stage, job.model_name, finding_ids,
                        external_json_path=staged_json_path, source_tool=source_tool,
                    )
                else:
                    engine_stream = self.docker_engine.run_sandbox(
                        session_id, paths, image_name, sandbox_stage, job.model_name, finding_ids,
                        external_json_path=staged_json_path, source_tool=source_tool,
                    )

                for line in engine_stream:
                    log_buffer.append(line)

                log_file = paths["output_dir"] / "LOG.md"
                with open(log_file, "a", encoding="utf-8") as f:
                    f.writelines(log_buffer)

            # 3. Parse results
            report = self.persistence.load_report(session_id)

            # 4. Execute Pull Request Creation Stage ('pr' or 'all_with_pr')
            if stage_norm in ("pr", "all_with_pr"):
                # Ensure Fix has been run so patches exist before opening a PR
                if not report or report.get("total_patches_applied", 0) == 0:
                    from .scanner import DynamicCodeScanner
                    scanner = DynamicCodeScanner(
                        source_dir=paths["source_dir"],
                        output_dir=paths["output_dir"],
                        session_id=session_id,
                        model_name=job.model_name,
                    )
                    report = scanner.scan_and_remediate(
                        stage="fix",
                        finding_ids=finding_ids,
                        model_name=job.model_name,
                    )

                target_repo = job.github_repo or f"{self.github_account}/codemender-demo-app"
                target_branch = job.github_branch or "main"
                job.github_repo = gh_client.normalize_repo_name(target_repo, default_owner=self.github_account)
                job.github_branch = target_branch

                pr_data = gh_client.push_fix_branch_and_create_pr(
                    repo_name=job.github_repo,
                    base_branch=job.github_branch,
                    session_id=session_id,
                    source_dir=paths["source_dir"],
                    remediated_dir=paths["output_dir"] / "remediated",
                    patches_dir=paths["patches_dir"],
                    report=report or {},
                    finding_ids=finding_ids,
                )
                job.pr_url = pr_data.get("html_url")
                job.pr_number = pr_data.get("number")

                if report is not None:
                    report["stage"] = ScanStage.PULL_REQUEST.value
                    report["pull_request"] = {
                        "pr_url": job.pr_url,
                        "pr_number": job.pr_number,
                        "repo_name": job.github_repo,
                        "base_branch": job.github_branch,
                        "feature_branch": pr_data.get("feature_branch"),
                        "account": gh_client.account,
                        "files_updated": pr_data.get("files_updated", []),
                    }
                    report_file = paths["output_dir"] / "report.json"
                    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

                log_file = paths["output_dir"] / "LOG.md"
                with open(log_file, "a", encoding="utf-8") as lf:
                    lf.write(
                        f"\n## Phase 4: GitHub Pull Request Creation (`{gh_client.account}`)\n"
                        f"- Target Repository: `{job.github_repo}` (Base Branch: `{job.github_branch}`)\n"
                        f"- Remediation Branch: `{pr_data.get('feature_branch')}`\n"
                        f"- Pull Request Opened: #{job.pr_number} -> {job.pr_url}\n"
                        f"[CODEMENDER-PR] ({gh_client.account}) Created Pull Request #{job.pr_number} on {job.github_repo}: {job.pr_url}\n"
                    )

            if report:
                job.vulnerabilities_found = report.get("total_vulnerabilities_found", 0)
                job.vulnerabilities_verified = report.get("total_vulnerabilities_verified", 0)
                job.patches_applied = report.get("total_patches_applied", 0)
                job.token_usage_json = json.dumps(report.get("token_usage", {}))

            completed_stage_map = {
                "import": ScanStage.IMPORT.value,
                "find": ScanStage.FIND.value,
                "verify": ScanStage.VERIFY.value,
                "fix": ScanStage.FIX.value,
                "pr": ScanStage.PULL_REQUEST.value,
                "all": ScanStage.TEARDOWN.value,
                "all_with_pr": ScanStage.PULL_REQUEST.value,
            }
            job.status = ScanStatus.COMPLETED.value
            job.stage = completed_stage_map.get(stage_norm, ScanStage.TEARDOWN.value)
            self.db_manager.save_job(job)

            return {
                "session_id": session_id,
                "status": ScanStatus.COMPLETED.value,
                "stage": job.stage,
                "model_name": job.model_name,
                "vulnerabilities_found": job.vulnerabilities_found,
                "vulnerabilities_verified": job.vulnerabilities_verified,
                "patches_applied": job.patches_applied,
                "github_repo": job.github_repo,
                "github_branch": job.github_branch,
                "pr_url": job.pr_url,
                "pr_number": job.pr_number,
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
