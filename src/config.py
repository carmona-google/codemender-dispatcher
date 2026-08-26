"""Configuration settings for CodeMender Dispatcher."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "codemender-dev-secret-key-change-in-prod")
    STORAGE_DIR = Path(os.environ.get("CODEMENDER_STORAGE_DIR", BASE_DIR / "storage" / "sessions"))
    DATABASE_URI = os.environ.get("DATABASE_URI", f"sqlite:///{BASE_DIR / 'storage' / 'codemender.db'}")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL

    # Container & Kubernetes orchestration settings
    EXECUTION_BACKEND = os.environ.get("EXECUTION_BACKEND", "auto")
    K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "codemender-executors")
    EXECUTOR_IMAGE_BASE = os.environ.get("EXECUTOR_IMAGE_BASE", "codemender-executor:polyglot")
    DOCKER_SOCKET_PATH = os.environ.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
    ENABLE_MOCK_FALLBACK = os.environ.get("ENABLE_MOCK_FALLBACK", "true").lower() in ("true", "1", "yes")

    # Pub/Sub ITSM settings
    PUBSUB_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "codemender-prod")
    PUBSUB_TOPIC_ID = os.environ.get("PUBSUB_TOPIC_ID", "codemender-security-events")

    # Upload constraints
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max archive size
    ALLOWED_EXTENSIONS = {"zip", "tar", "gz", "tgz"}


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DATABASE_URI = "sqlite:///:memory:"
    STORAGE_DIR = BASE_DIR / "storage" / "test_sessions"
