"""Server-Sent Events (SSE) endpoints for live execution log streaming."""

import time
import json
from pathlib import Path
from flask import Blueprint, Response, current_app

from ..core.persistence import PersistenceManager
from ..models.scan_job import ScanStatus

events_bp = Blueprint("events", __name__, url_prefix="/api/v1/events")


@events_bp.route("/<scan_id>", methods=["GET"])
def stream_scan_events(scan_id: str):
    """Streams live log lines and job status transitions via SSE."""
    storage_dir = Path(current_app.config["STORAGE_DIR"])
    db_manager = current_app.db_manager
    persistence = PersistenceManager(storage_dir)
    log_file = persistence.get_session_dir(scan_id) / "output" / "LOG.md"

    def event_generator():
        last_pos = 0

        while True:
            job = db_manager.get_job(scan_id)
            current_status = job.status if job else "UNKNOWN"
            current_stage = job.stage if job else "UNKNOWN"

            if log_file.exists():
                with open(log_file, "r", encoding="utf-8") as f:
                    f.seek(last_pos)
                    new_lines = f.read()
                    last_pos = f.tell()

                if new_lines:
                    yield f"event: log\ndata: {json.dumps({'chunk': new_lines})}\n\n"

            yield f"event: status\ndata: {json.dumps({'status': current_status, 'stage': current_stage})}\n\n"

            if current_status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value):
                yield f"event: done\ndata: {json.dumps({'status': current_status})}\n\n"
                break

            time.sleep(0.5)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
