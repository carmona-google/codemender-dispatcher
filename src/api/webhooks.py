"""Inbound webhook endpoints with In-Flight Cancellation, GitHub App Automation & PR Feedback."""

import hmac
import hashlib
import json
import uuid
import threading
from pathlib import Path
from typing import Dict, Optional
from flask import Blueprint, request, jsonify, current_app

from ..models.scan_job import ScanJob, ScanStatus
from ..itsm.schemas import (
    CodeMenderSecurityEvent,
    EventType,
    VulnerabilityFindingMetadata,
    RemediationPRMetadata,
    compute_provenance_digest,
)
from ..itsm.pubsub_publisher import ITSMPubSubPublisher
from ..core.github_client import GitHubClient
from ..core.persistence import PersistenceManager

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/v1/webhooks")

# Tracks active in-flight scan jobs by repository PR: (repo_name, pr_number) -> session_id
_IN_FLIGHT_SCANS: Dict[str, str] = {}
_IN_FLIGHT_LOCK = threading.Lock()


def verify_github_signature(payload_body: bytes, secret: str, signature_header: str) -> bool:
    """Verifies HMAC SHA-256 signature from GitHub webhook header."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_sig = signature_header.split("sha256=")[1]
    mac = hmac.new(secret.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), expected_sig)


def _execute_pr_scan_and_notify(
    session_id: str,
    repo_name: str,
    pr_number: int,
    base_branch: str,
    head_sha: str,
    storage_dir: Path,
    db_manager,
    docker_socket_path: str,
    enable_mock_fallback: bool,
    pubsub_project_id: str,
    pubsub_topic_id: str,
    github_token: str,
):
    """Orchestrates scan execution, posts PR comment, creates fix PR, and emits Pub/Sub events."""
    from ..core.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(
        db_manager=db_manager,
        storage_dir=storage_dir,
        docker_socket_path=docker_socket_path,
        enable_mock_fallback=enable_mock_fallback,
    )
    result = orchestrator.execute_scan(session_id, None, "polyglot")

    persistence = PersistenceManager(storage_dir)
    report = persistence.load_report(session_id) or {}

    # Initialize GitHub automation client
    gh_client = GitHubClient(token=github_token)

    # 1. Post PR summary comment
    comment_body = gh_client.format_vulnerability_pr_comment(report, session_id)
    gh_client.post_pr_comment(repo_name, pr_number, comment_body)

    # 2. If patches were applied, open companion Remediation PR & Publish to Pub/Sub
    if report.get("total_patches_applied", 0) > 0:
        feature_branch = f"codemender/patch-pr-{pr_number}"
        remediation_pr = gh_client.create_remediation_pr(
            repo_name=repo_name,
            base_branch=base_branch,
            feature_branch=feature_branch,
            title=f"fix(security): CodeMender remediation for PR #{pr_number}",
            body=comment_body,
        )

        # Publish REMEDIATION_PR_CREATED to Cloud Pub/Sub
        publisher = ITSMPubSubPublisher(
            project_id=pubsub_project_id,
            topic_id=pubsub_topic_id,
            enable_mock=True,
        )
        first_finding = report.get("findings", [{}])[0]
        finding_id = first_finding.get("id", f"FIND-{session_id}")

        event = CodeMenderSecurityEvent(
            event_id=f"pr-fix-{uuid.uuid4().hex[:8]}",
            event_type=EventType.REMEDIATION_PR_CREATED,
            timestamp_utc=str(report.get("session_id", "")),
            project_id=pubsub_project_id,
            session_id=session_id,
            finding=VulnerabilityFindingMetadata(
                finding_id=finding_id,
                vulnerability_type=first_finding.get("type", "VULNERABILITY"),
                severity=first_finding.get("severity", "HIGH"),
                affected_file_path=first_finding.get("file", "app"),
                line_number=first_finding.get("line", 1),
                verification_status="VERIFIED_EXPLOITABLE",
                provenance_digest=compute_provenance_digest(repo_name, head_sha, finding_id),
            ),
            remediation=RemediationPRMetadata(
                finding_id=finding_id,
                repository_url=f"https://github.com/{repo_name}",
                target_branch=base_branch,
                feature_branch=feature_branch,
                pull_request_url=remediation_pr.get("html_url", ""),
                files_modified_count=report.get("total_patches_applied", 1),
                verification_passed=True,
            ),
            token_usage=report.get("token_usage", {}),
        )
        publisher.publish_event(event)


@webhooks_bp.route("/github", methods=["POST"])
def github_webhook():
    """Receives GitHub pull_request events with in-flight debouncing, auto-PR, and feedback."""
    event_type = request.headers.get("X-GitHub-Event", "ping")
    signature = request.headers.get("X-Hub-Signature-256", "")
    secret = current_app.config.get("GITHUB_WEBHOOK_SECRET", "")

    if secret and not verify_github_signature(request.data, secret, signature):
        return jsonify({"error": "Invalid HMAC signature"}), 401

    if event_type == "ping":
        return jsonify({"message": "GitHub Webhook Ping acknowledged"}), 200

    payload = request.get_json(silent=True) or {}

    if event_type == "pull_request":
        action = payload.get("action", "")
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        repo_name = repo.get("full_name", "unknown/repo")
        pr_number = payload.get("number", 0)
        pr_key = f"{repo_name}#{pr_number}"
        base_branch = pr.get("base", {}).get("ref", "main")
        head_sha = pr.get("head", {}).get("sha", "HEAD")

        # 1. Bidirectional Human Feedback: PR Merged or Closed/Rejected
        if action == "closed":
            is_merged = pr.get("merged", False)
            feedback_event_type = (
                EventType.REMEDIATION_PR_MERGED if is_merged else EventType.REMEDIATION_PR_REJECTED
            )

            publisher = ITSMPubSubPublisher(
                project_id=current_app.config.get("PUBSUB_PROJECT_ID", "generic-security-project"),
                topic_id=current_app.config.get("PUBSUB_TOPIC_ID", "codemender-security-events"),
                enable_mock=True,
            )
            feedback_event = CodeMenderSecurityEvent(
                event_id=f"fb-{uuid.uuid4().hex[:8]}",
                event_type=feedback_event_type,
                timestamp_utc=pr.get("closed_at", ""),
                project_id=current_app.config.get("PUBSUB_PROJECT_ID", "generic-security-project"),
                session_id=f"feedback-pr-{pr_number}",
                finding=VulnerabilityFindingMetadata(
                    finding_id=f"FIND-PR-{pr_number}",
                    vulnerability_type="SECURITY_REMEDIATION",
                    severity="UNKNOWN",
                    affected_file_path="repository",
                    line_number=0,
                    verification_status="RESOLVED" if is_merged else "REJECTED",
                    provenance_digest=compute_provenance_digest(repo_name, head_sha, f"PR-{pr_number}"),
                ),
                remediation=RemediationPRMetadata(
                    finding_id=f"FIND-PR-{pr_number}",
                    repository_url=repo.get("html_url", ""),
                    target_branch=base_branch,
                    feature_branch=pr.get("head", {}).get("ref", ""),
                    pull_request_url=pr.get("html_url", ""),
                    human_review_status="MERGED" if is_merged else "REJECTED",
                ),
            )
            publisher.publish_event(feedback_event)

            return jsonify({
                "message": f"Recorded PR feedback: {feedback_event_type.value}",
                "merged": is_merged,
            }), 200

        # 2. In-Flight Job Cancellation on New Commit (synchronize / opened)
        if action in ("opened", "synchronize", "reopened"):
            with _IN_FLIGHT_LOCK:
                if pr_key in _IN_FLIGHT_SCANS:
                    stale_session_id = _IN_FLIGHT_SCANS[pr_key]
                    db_manager = current_app.db_manager
                    stale_job = db_manager.get_job(stale_session_id)
                    if stale_job and stale_job.status in (ScanStatus.PENDING.value, ScanStatus.RUNNING.value):
                        stale_job.status = ScanStatus.FAILED.value
                        stale_job.error_message = "Cancelled by newer commit on PR"
                        db_manager.save_job(stale_job)

            session_id = f"gh-pr-{pr_number}-{uuid.uuid4().hex[:8]}"
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT_SCANS[pr_key] = session_id

            # Record new scan job
            db_manager = current_app.db_manager
            job = ScanJob(
                id=session_id,
                source_filename=f"{repo_name}#PR-{pr_number}",
                language_flavor="polyglot",
                status=ScanStatus.PENDING.value,
            )
            db_manager.save_job(job)

            storage_dir = Path(current_app.config["STORAGE_DIR"])
            docker_socket = current_app.config.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
            enable_mock = current_app.config.get("ENABLE_MOCK_FALLBACK", True)
            pubsub_project = current_app.config.get("PUBSUB_PROJECT_ID", "generic-security-project")
            pubsub_topic = current_app.config.get("PUBSUB_TOPIC_ID", "codemender-security-events")
            gh_token = current_app.config.get("GITHUB_TOKEN", "")

            # If TESTING, execute synchronously; otherwise run in background thread
            if current_app.config.get("TESTING", False):
                _execute_pr_scan_and_notify(
                    session_id, repo_name, pr_number, base_branch, head_sha,
                    storage_dir, db_manager, docker_socket, enable_mock,
                    pubsub_project, pubsub_topic, gh_token,
                )
            else:
                thread = threading.Thread(
                    target=_execute_pr_scan_and_notify,
                    args=(
                        session_id, repo_name, pr_number, base_branch, head_sha,
                        storage_dir, db_manager, docker_socket, enable_mock,
                        pubsub_project, pubsub_topic, gh_token,
                    ),
                    daemon=True,
                )
                thread.start()

            return jsonify({
                "session_id": session_id,
                "event": "pull_request",
                "repo": repo_name,
                "pr_number": pr_number,
                "status": "SCAN_DISPATCHED",
            }), 202

    return jsonify({"message": f"Unhandled event type: {event_type}"}), 200
