"""Web UI portal routes for interactive CodeMender management."""

from pathlib import Path
from flask import Blueprint, render_template, current_app, abort

from ..core.persistence import PersistenceManager

web_bp = Blueprint("web", __name__)


@web_bp.route("/")
def index():
    """Renders the main dashboard with file uploader and recent scans."""
    db_manager = current_app.db_manager
    jobs = db_manager.list_jobs(limit=20)
    scans_data = [job.to_dict() for job in jobs]
    return render_template("index.html", scans=scans_data)


@web_bp.route("/scans/<scan_id>")
def scan_detail(scan_id: str):
    """Renders scan detail console with live SSE logs and findings."""
    db_manager = current_app.db_manager
    job = db_manager.get_job(scan_id)
    if not job:
        abort(404)

    job_data = job.to_dict()
    persistence = PersistenceManager(Path(current_app.config["STORAGE_DIR"]))
    report = persistence.load_report(scan_id)
    patches = persistence.list_patches(scan_id)
    logs = persistence.load_log(scan_id)

    return render_template(
        "scan_detail.html",
        scan=job_data,
        report=report,
        patches=patches,
        logs=logs,
    )
