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
    )


@scans_bp.route("", methods=["POST"])
def create_scan():
    """Uploads codebase archive and initiates the requested scan stage ('find' or 'all')."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    language_flavor = request.form.get("language_flavor", "polyglot")
    model_name = request.form.get("model_name") or current_app.config.get("CODEMENDER_MODEL", "gemini-4-argon")
    stage = request.form.get("stage", "all").lower()
    if stage not in ("find", "verify", "fix", "all"):
        stage = "all"

    session_id = f"scan-{uuid.uuid4().hex[:12]}"
    filename = secure_filename(file.filename)

    # Save uploaded file to staging area
    storage_dir = Path(current_app.config["STORAGE_DIR"])
    staging_dir = storage_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    temp_zip_path = staging_dir / f"{session_id}_{filename}"
    file.save(temp_zip_path)

    # Record scan job in database
    db_manager = current_app.db_manager
    job = ScanJob(
        id=session_id,
        source_filename=filename,
        language_flavor=language_flavor,
        model_name=model_name,
        status=ScanStatus.PENDING.value,
    )
    db_manager.save_job(job)

    use_celery = current_app.config.get("USE_CELERY", False)

    if current_app.config.get("TESTING", False) or stage == "find":
        orchestrator = _build_orchestrator()
        orchestrator.execute_scan(
            session_id=session_id,
            zip_file_path=temp_zip_path,
            language_flavor=language_flavor,
            stage=stage,
            model_name=model_name,
        )
    elif use_celery:
        from ..celery_app import execute_scan_task
        execute_scan_task.delay(session_id, str(temp_zip_path), language_flavor)
    else:
        orchestrator = _build_orchestrator()
        thread = threading.Thread(
            target=orchestrator.execute_scan,
            args=(session_id, temp_zip_path, language_flavor, stage, model_name),
            daemon=True,
        )
        thread.start()

    return jsonify({
        "session_id": session_id,
        "status": ScanStatus.PENDING.value,
        "stage": stage.upper(),
        "model_name": model_name,
        "message": f"Scan submitted successfully (stage={stage}, model={model_name}).",
    }), 202


@scans_bp.route("/<scan_id>/stage", methods=["POST"])
def run_scan_stage(scan_id: str):
    """Executes 'find', 'verify', or 'fix' on an existing scan session for selected finding IDs."""
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    payload = request.get_json(silent=True) or {}
    stage = (payload.get("stage") or "verify").lower()
    if stage not in ("find", "verify", "fix", "all"):
        return jsonify({"error": f"Invalid stage '{stage}'. Expected find, verify, fix, or all."}), 400

    finding_ids = payload.get("finding_ids")
    if isinstance(finding_ids, str):
        finding_ids = [fid.strip() for fid in finding_ids.split(",") if fid.strip()]

    model_name = payload.get("model_name") or job.model_name or "gemini-4-argon"

    orchestrator = _build_orchestrator()
    result = orchestrator.execute_scan(
        session_id=scan_id,
        zip_file_path=None,
        language_flavor=job.language_flavor,
        stage=stage,
        model_name=model_name,
        finding_ids=finding_ids,
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
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        return jsonify({"error": f"Scan '{scan_id}' not found"}), 404

    job_data = job.to_dict()
    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    report = persistence.load_report(scan_id)
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
