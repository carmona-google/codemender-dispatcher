"""Configuration settings for CodeMender Dispatcher."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration."""

    _env_secret = os.environ.get("SECRET_KEY")
    if not _env_secret:
        if os.environ.get("FLASK_ENV") == "production":
            raise RuntimeError("CRITICAL: SECRET_KEY environment variable is required in production.")
        SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-ephemeral-key")
    else:
        SECRET_KEY = _env_secret

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

    # Production safety guardrail: mock fallback defaults to False in production
    _default_mock = "false" if os.environ.get("FLASK_ENV") == "production" else "true"
    ENABLE_MOCK_FALLBACK = os.environ.get("ENABLE_MOCK_FALLBACK", _default_mock).lower() in ("true", "1", "yes")

    # Pub/Sub ITSM settings
    PUBSUB_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "generic-security-project")
    PUBSUB_TOPIC_ID = os.environ.get("PUBSUB_TOPIC_ID", "codemender-security-events")

    # LLM Model configuration
    CODEMENDER_MODEL = os.environ.get("CODEMENDER_MODEL", "gemini-3.7-flash")

    # Upload constraints
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max archive size
    ALLOWED_EXTENSIONS = {"zip", "tar", "gz", "tgz"}


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DATABASE_URI = "sqlite:///:memory:"
    STORAGE_DIR = BASE_DIR / "storage" / "test_sessions"
