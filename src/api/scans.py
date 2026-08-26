"""REST API endpoints for scan ingestion and status queries."""

import os
import uuid
import threading
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from ..models.scan_job import ScanJob, ScanStatus
from ..core.persistence import PersistenceManager

scans_bp = Blueprint("scans", __name__, url_prefix="/api/v1/scans")


@scans_bp.route("", methods=["POST"])
def create_scan():
    """Uploads codebase archive and initiates scan."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    language_flavor = request.form.get("language_flavor", "polyglot")
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
        status=ScanStatus.PENDING.value,
    )
    db_manager.save_job(job)

    use_celery = current_app.config.get("USE_CELERY", False)
    backend = current_app.config.get("EXECUTION_BACKEND", "auto")
    namespace = current_app.config.get("K8S_NAMESPACE", "codemender-executors")

    if current_app.config.get("TESTING", False):
        from ..core.orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator(
            db_manager=db_manager,
            storage_dir=storage_dir,
            docker_socket_path=current_app.config.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
            enable_mock_fallback=current_app.config.get("ENABLE_MOCK_FALLBACK", True),
            execution_backend=backend,
            k8s_namespace=namespace,
        )
        orchestrator.execute_scan(session_id, temp_zip_path, language_flavor)
    elif use_celery:
        from ..celery_app import execute_scan_task
        execute_scan_task.delay(session_id, str(temp_zip_path), language_flavor)
    else:
        from ..core.orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator(
            db_manager=db_manager,
            storage_dir=storage_dir,
            docker_socket_path=current_app.config.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
            enable_mock_fallback=current_app.config.get("ENABLE_MOCK_FALLBACK", True),
            execution_backend=backend,
            k8s_namespace=namespace,
        )
        thread = threading.Thread(
            target=orchestrator.execute_scan,
            args=(session_id, temp_zip_path, language_flavor),
            daemon=True,
        )
        thread.start()

    return jsonify({
        "session_id": session_id,
        "status": ScanStatus.PENDING.value,
        "message": "Scan submitted successfully.",
    }), 202


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
