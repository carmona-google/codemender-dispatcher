"""REST API endpoints for scan ingestion, staged execution (find/verify/fix), and status queries."""

import os
import uuid
import threading
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from ..models.scan_job import ScanJob, ScanStatus
from ..core.persistence import PersistenceManager

scans_bp = Blueprint("scans", __name__, url_prefix="/api/v1/scans")


def _build_orchestrator():
    """Creates a configured ScanOrchestrator instance from current_app settings."""
    from ..core.orchestrator import ScanOrchestrator
    return ScanOrchestrator(
        db_manager=current_app.db_manager,
        storage_dir=Path(current_app.config["STORAGE_DIR"]),
        docker_socket_path=current_app.config.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
        enable_mock_fallback=current_app.config.get("ENABLE_MOCK_FALLBACK", True),
        execution_backend=current_app.config.get("EXECUTION_BACKEND", "auto"),
        k8s_namespace=current_app.config.get("K8S_NAMESPACE", "codemender-executors"),
        github_token=current_app.config.get("GITHUB_TOKEN", ""),
        github_account=current_app.config.get("GITHUB_ACCOUNT", "carmona-google"),
    )


@scans_bp.route("/github/repos", methods=["GET"])
def list_github_repos():
    """Lists GitHub repositories under the carmona-google account."""
    from ..core.github_client import GitHubClient
    account = (
        request.args.get("account")
        or current_app.config.get("GITHUB_ACCOUNT", "carmona-google")
    ).strip()
    token = (
        request.headers.get("X-GitHub-Token")
        or current_app.config.get("GITHUB_TOKEN", "")
    ).strip()
    client = GitHubClient(
        token=token,
        account=account,
        enable_mock=current_app.config.get("ENABLE_MOCK_FALLBACK", True),
    )
    repos = client.list_user_repos(account=account)
    return jsonify({
        "account": account,
        "repositories": repos,
    }), 200


@scans_bp.route("", methods=["POST"])
def create_scan():
    """Uploads codebase archive or connects a carmona-google GitHub repo and initiates scan."""
    from ..core.github_client import GitHubClient

    json_body = request.get_json(silent=True) or {}
    github_repo = (
        request.form.get("github_repo")
        or json_body.get("github_repo")
        or ""
    ).strip()
    github_branch = (
        request.form.get("github_branch")
        or json_body.get("github_branch")
        or current_app.config.get("GITHUB_DEFAULT_BRANCH", "main")
    ).strip() or "main"
    github_token = (
        request.form.get("github_token")
        or json_body.get("github_token")
        or current_app.config.get("GITHUB_TOKEN", "")
    ).strip()
    github_account = current_app.config.get("GITHUB_ACCOUNT", "carmona-google")

    has_file = "file" in request.files and request.files["file"].filename != ""
    if not has_file and not github_repo:
        return jsonify({
            "error": "Provide either a codebase archive ('file') or a GitHub repository ('github_repo')."
        }), 400

    language_flavor = (
        request.form.get("language_flavor")
        or json_body.get("language_flavor")
        or "polyglot"
    )
    model_name = (
        request.form.get("model_name")
        or json_body.get("model_name")
        or current_app.config.get("CODEMENDER_MODEL", "gemini-4-argon")
    )
    stage = (
        request.form.get("stage")
        or json_body.get("stage")
        or "all"
    ).lower()
    if stage not in ("find", "verify", "fix", "pr", "all", "all_with_pr"):
        stage = "all"

    session_id = f"scan-{uuid.uuid4().hex[:12]}"
    temp_zip_path = None
    normalized_repo = None

    if has_file:
        file = request.files["file"]
        filename = secure_filename(file.filename)
        storage_dir = Path(current_app.config["STORAGE_DIR"])
        staging_dir = storage_dir / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        temp_zip_path = staging_dir / f"{session_id}_{filename}"
        file.save(temp_zip_path)

    if github_repo:
        try:
            normalized_repo = GitHubClient.normalize_repo_name(github_repo, default_owner=github_account)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not has_file:
            filename = f"github:{normalized_repo}@{github_branch}"

    # Record scan job in database
    db_manager = current_app.db_manager
    job = ScanJob(
        id=session_id,
        source_filename=filename,
        language_flavor=language_flavor,
        model_name=model_name,
        status=ScanStatus.PENDING.value,
        github_repo=normalized_repo,
        github_branch=github_branch if normalized_repo else None,
    )
    db_manager.save_job(job)

    use_celery = current_app.config.get("USE_CELERY", False)

    if current_app.config.get("TESTING", False) or stage in ("find", "all_with_pr", "pr"):
        orchestrator = _build_orchestrator()
        result = orchestrator.execute_scan(
            session_id=session_id,
            zip_file_path=temp_zip_path,
            language_flavor=language_flavor,
            stage=stage,
            model_name=model_name,
            github_repo=normalized_repo,
            github_branch=github_branch if normalized_repo else None,
            github_token=github_token or None,
        )
        return jsonify({
            "session_id": session_id,
            "status": result.get("status", ScanStatus.COMPLETED.value),
            "stage": result.get("stage", stage.upper()),
            "model_name": model_name,
            "github_repo": result.get("github_repo", normalized_repo),
            "github_branch": result.get("github_branch", github_branch if normalized_repo else None),
            "pr_url": result.get("pr_url"),
            "pr_number": result.get("pr_number"),
            "message": f"Scan submitted successfully (stage={stage}, model={model_name}).",
        }), 202
    elif use_celery and temp_zip_path is not None:
        from ..celery_app import execute_scan_task
        execute_scan_task.delay(session_id, str(temp_zip_path), language_flavor)
    else:
        orchestrator = _build_orchestrator()
        thread = threading.Thread(
            target=orchestrator.execute_scan,
            kwargs={
                "session_id": session_id,
                "zip_file_path": temp_zip_path,
                "language_flavor": language_flavor,
                "stage": stage,
                "model_name": model_name,
                "github_repo": normalized_repo,
                "github_branch": github_branch if normalized_repo else None,
                "github_token": github_token or None,
            },
            daemon=True,
        )
        thread.start()

    return jsonify({
        "session_id": session_id,
        "status": ScanStatus.PENDING.value,
        "stage": stage.upper(),
        "model_name": model_name,
        "github_repo": normalized_repo,
        "github_branch": github_branch if normalized_repo else None,
        "message": f"Scan submitted successfully (stage={stage}, model={model_name}).",
    }), 202


@scans_bp.route("/<scan_id>/stage", methods=["POST"])
def run_scan_stage(scan_id: str):
    """Executes 'find', 'verify', 'fix', 'pr', 'all', or 'all_with_pr' on an existing scan session."""
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    payload = request.get_json(silent=True) or {}
    stage = (payload.get("stage") or "verify").lower()
    if stage not in ("find", "verify", "fix", "pr", "all", "all_with_pr"):
        return jsonify({"error": f"Invalid stage '{stage}'. Expected find, verify, fix, pr, all, or all_with_pr."}), 400

    finding_ids = payload.get("finding_ids")
    if isinstance(finding_ids, str):
        finding_ids = [fid.strip() for fid in finding_ids.split(",") if fid.strip()]

    model_name = payload.get("model_name") or job.model_name or "gemini-4-argon"
    github_repo = (payload.get("github_repo") or job.github_repo or "").strip() or None
    github_branch = (payload.get("github_branch") or job.github_branch or "main").strip()
    github_token = (payload.get("github_token") or "").strip() or None

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=scan_id,
        zip_file_path=None,
        language_flavor=job.language_flavor,
        stage=stage,
        model_name=model_name,
        finding_ids=finding_ids,
        github_repo=github_repo,
        github_branch=github_branch,
        github_token=github_token,
    )
    if result.get("status") == ScanStatus.FAILED.value:
        return jsonify(result), 500

    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    result["patches"] = persistence.list_patches(scan_id)
    result["logs"] = persistence.load_log(scan_id)
    return jsonify(result), 200


@scans_bp.route("/<scan_id>/verify", methods=["POST"])
def verify_scan_findings(scan_id: str):
    """Convenience endpoint to run 'cm verify' on selected finding IDs."""
    payload = request.get_json(silent=True) or {}
    payload["stage"] = "verify"
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    finding_ids = payload.get("finding_ids")
    if isinstance(finding_ids, str):
        finding_ids = [fid.strip() for fid in finding_ids.split(",") if fid.strip()]
    model_name = payload.get("model_name") or job.model_name or "gemini-4-argon"

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=scan_id,
        zip_file_path=None,
        language_flavor=job.language_flavor,
        stage="verify",
        model_name=model_name,
        finding_ids=finding_ids,
    )
    if result.get("status") == ScanStatus.FAILED.value:
        return jsonify(result), 500

    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    result["patches"] = persistence.list_patches(scan_id)
    result["logs"] = persistence.load_log(scan_id)
    return jsonify(result), 200


@scans_bp.route("/<scan_id>/fix", methods=["POST"])
def fix_scan_findings(scan_id: str):
    """Convenience endpoint to run 'cm fix' on selected finding IDs."""
    payload = request.get_json(silent=True) or {}
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    finding_ids = payload.get("finding_ids")
    if isinstance(finding_ids, str):
        finding_ids = [fid.strip() for fid in finding_ids.split(",") if fid.strip()]
    model_name = payload.get("model_name") or job.model_name or "gemini-4-argon"

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=scan_id,
        zip_file_path=None,
        language_flavor=job.language_flavor,
        stage="fix",
        model_name=model_name,
        finding_ids=finding_ids,
    )
    if result.get("status") == ScanStatus.FAILED.value:
        return jsonify(result), 500

    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    result["patches"] = persistence.list_patches(scan_id)
    result["logs"] = persistence.load_log(scan_id)
    return jsonify(result), 200


@scans_bp.route("/<scan_id>/pr", methods=["POST"])
def create_scan_pull_request(scan_id: str):
    """Step 4 endpoint: Creates a GitHub Pull Request via carmona-google with the Fix patches."""
    payload = request.get_json(silent=True) or {}
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    finding_ids = payload.get("finding_ids")
    if isinstance(finding_ids, str):
        finding_ids = [fid.strip() for fid in finding_ids.split(",") if fid.strip()]
    model_name = payload.get("model_name") or job.model_name or "gemini-4-argon"
    github_repo = (payload.get("github_repo") or job.github_repo or "").strip() or None
    github_branch = (payload.get("github_branch") or job.github_branch or "main").strip()
    github_token = (payload.get("github_token") or "").strip() or None

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=scan_id,
        zip_file_path=None,
        language_flavor=job.language_flavor,
        stage="pr",
        model_name=model_name,
        finding_ids=finding_ids,
        github_repo=github_repo,
        github_branch=github_branch,
        github_token=github_token,
    )
    if result.get("status") == ScanStatus.FAILED.value:
        return jsonify(result), 500

    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    result["patches"] = persistence.list_patches(scan_id)
    result["logs"] = persistence.load_log(scan_id)
    return jsonify(result), 200


@scans_bp.route("", methods=["GET"])
def list_scans():
    """Lists recent scan jobs."""
    db_manager = current_app.db_manager
    jobs = db_manager.list_jobs(limit=50)
    results = [job.to_dict() for job in jobs]
    return jsonify({"scans": results})


@scans_bp.route("/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Retrieves full scan status and structured report."""
    from ..core.scanner import DynamicCodeScanner

    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    job_data = job.to_dict()
    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    report = persistence.load_report(scan_id)
    if report and isinstance(report.get("findings"), list):
        for f in report["findings"]:
            if not f.get("description"):
                f["description"] = DynamicCodeScanner.get_vulnerability_description(f)
    patches = persistence.list_patches(scan_id)

    job_data["report"] = report
    job_data["patches"] = patches
    return jsonify(job_data)


@scans_bp.route("/<scan_id>/logs", methods=["GET"])
def get_scan_logs(scan_id: str):
    """Retrieves execution LOG.md."""
    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    log_content = persistence.load_log(scan_id)
    return jsonify({"session_id": scan_id, "logs": log_content})


@scans_bp.route("/import", methods=["POST"])
def import_external_findings():
    """Imports a local external tool JSON file (Wiz Code, SARIF, Snyk, Trivy, etc.) via 'cm import'."""
    storage_dir = Path(current_app.config["STORAGE_DIR"])
    staging_dir = storage_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    target_session_id = (
        request.form.get("target_session_id")
        or (request.get_json(silent=True) or {}).get("target_session_id")
        or ""
    ).strip()
    source_tool = (
        request.form.get("source_tool")
        or (request.get_json(silent=True) or {}).get("source_tool")
        or ""
    ).strip() or None
    model_name = (
        request.form.get("model_name")
        or (request.get_json(silent=True) or {}).get("model_name")
        or current_app.config.get("CODEMENDER_MODEL", "gemini-4-argon")
    )
    language_flavor = request.form.get("language_flavor", "polyglot")

    session_id = target_session_id if target_session_id else f"scan-{uuid.uuid4().hex[:12]}"

    # Accept uploaded JSON file ('json_file', 'findings_file', or 'file') or raw JSON body
    uploaded_json = (
        request.files.get("json_file")
        or request.files.get("findings_file")
        or request.files.get("file")
    )
    if uploaded_json and uploaded_json.filename:
        json_filename = secure_filename(uploaded_json.filename)
        temp_json_path = staging_dir / f"{session_id}_{json_filename}"
        uploaded_json.save(temp_json_path)
    elif request.is_json:
        import json as _json
        json_filename = "imported_payload.json"
        temp_json_path = staging_dir / f"{session_id}_{json_filename}"
        temp_json_path.write_text(_json.dumps(request.get_json()), encoding="utf-8")
    else:
        return jsonify({"error": "No JSON file provided for 'cm import'"}), 400

    # Optional codebase archive (.zip) if creating a new session with source code
    temp_zip_path = None
    uploaded_zip = request.files.get("codebase_file")
    if uploaded_zip and uploaded_zip.filename:
        zip_filename = secure_filename(uploaded_zip.filename)
        temp_zip_path = staging_dir / f"{session_id}_{zip_filename}"
        uploaded_zip.save(temp_zip_path)

    db_manager = current_app.db_manager
    existing_job = db_manager.get_job(session_id)
    if not existing_job:
        display_source = f"cm import ({source_tool or 'External'}): {json_filename}"
        job = ScanJob(
            id=session_id,
            source_filename=display_source,
            language_flavor=language_flavor,
            model_name=model_name,
            status=ScanStatus.PENDING.value,
        )
        db_manager.save_job(job)

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=session_id,
        zip_file_path=temp_zip_path,
        language_flavor=language_flavor,
        stage="import",
        model_name=model_name,
        external_json_path=temp_json_path,
        source_tool=source_tool,
    )
    if result.get("status") == ScanStatus.FAILED.value:
        return jsonify(result), 500

    persistence = PersistenceManager(storage_dir)
    report = persistence.load_report(session_id) or {}
    result["scan_id"] = session_id
    result["stage"] = "IMPORT"
    result["findings_imported"] = report.get("total_vulnerabilities_found", 0)
    result["logs"] = persistence.load_log(session_id)
    result["patches"] = persistence.list_patches(session_id)
    return jsonify(result), 200


@scans_bp.route("/<scan_id>/import", methods=["POST"])
def import_into_scan_session(scan_id: str):
    """Runs 'cm import' on an existing scan session to merge external tool JSON findings."""
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    storage_dir = Path(current_app.config["STORAGE_DIR"])
    staging_dir = storage_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    source_tool = (request.form.get("source_tool") or "").strip() or None
    model_name = request.form.get("model_name") or job.model_name or "gemini-4-argon"

    uploaded_json = (
        request.files.get("json_file")
        or request.files.get("findings_file")
        or request.files.get("file")
    )
    if not uploaded_json or not uploaded_json.filename:
        return jsonify({"error": "No JSON file selected for 'cm import'"}), 400

    json_filename = secure_filename(uploaded_json.filename)
    temp_json_path = staging_dir / f"{scan_id}_{json_filename}"
    uploaded_json.save(temp_json_path)

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=scan_id,
        zip_file_path=None,
        language_flavor=job.language_flavor,
        stage="import",
        model_name=model_name,
        external_json_path=temp_json_path,
        source_tool=source_tool,
    )
    if result.get("status") == ScanStatus.FAILED.value:
        return jsonify(result), 500

    persistence = PersistenceManager(storage_dir)
    report = persistence.load_report(scan_id) or {}
    result["scan_id"] = scan_id
    result["stage"] = "IMPORT"
    result["findings_imported"] = report.get("total_vulnerabilities_found", 0)
    result["logs"] = persistence.load_log(scan_id)
    result["patches"] = persistence.list_patches(scan_id)
    return jsonify(result), 200
