"""Celery application and background worker tasks."""

import os
from celery import Celery
from .config import Config
from .models.scan_job import init_db
from .core.orchestrator import ScanOrchestrator

celery_app = Celery(
    "codemender",
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(name="tasks.execute_scan_task")
def execute_scan_task(session_id: str, zip_path_str: str, language_flavor: str = "polyglot"):
    """Background task executing a CodeMender scan."""
    db_factory = init_db(Config.DATABASE_URI)
    orchestrator = ScanOrchestrator(
        db_session_factory=db_factory,
        storage_dir=Config.STORAGE_DIR,
        docker_socket_path=Config.DOCKER_SOCKET_PATH,
        enable_mock_fallback=Config.ENABLE_MOCK_FALLBACK,
    )
    zip_path = None
    if zip_path_str and os.path.exists(zip_path_str):
        from pathlib import Path
        zip_path = Path(zip_path_str)

    return orchestrator.execute_scan(
        session_id=session_id,
        zip_file_path=zip_path,
        language_flavor=language_flavor,
    )
