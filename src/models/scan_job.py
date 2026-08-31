"""Native SQLite database models and DAO for CodeMender scan sessions."""

import os
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanStage(str, Enum):
    INGESTION = "INGESTION"
    PROVISIONING = "PROVISIONING"
    FIND = "FIND"
    VERIFY = "VERIFY"
    FIX = "FIX"
    REPORTING = "REPORTING"
    TEARDOWN = "TEARDOWN"


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanJob:
    """Represents a CodeMender scan session record."""

    def __init__(
        self,
        id: str,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        status: str = ScanStatus.PENDING.value,
        stage: str = ScanStage.INGESTION.value,
        source_filename: Optional[str] = None,
        language_flavor: str = "polyglot",
        vulnerabilities_found: int = 0,
        vulnerabilities_verified: int = 0,
        patches_applied: int = 0,
        token_usage_json: str = "{}",
        error_message: Optional[str] = None,
    ):
        self.id = id
        self.created_at = created_at or _utc_now_str()
        self.updated_at = updated_at or _utc_now_str()
        self.status = status
        self.stage = stage
        self.source_filename = source_filename
        self.language_flavor = language_flavor
        self.vulnerabilities_found = vulnerabilities_found
        self.vulnerabilities_verified = vulnerabilities_verified
        self.patches_applied = patches_applied
        self.token_usage_json = token_usage_json
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "stage": self.stage,
            "source_filename": self.source_filename,
            "language_flavor": self.language_flavor,
            "vulnerabilities_found": self.vulnerabilities_found,
            "vulnerabilities_verified": self.vulnerabilities_verified,
            "patches_applied": self.patches_applied,
            "token_usage": json.loads(self.token_usage_json or "{}"),
            "error_message": self.error_message,
        }


class DatabaseManager:
    """Thread-safe SQLite database manager."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        if self.db_path.startswith("sqlite:///"):
            self.db_path = self.db_path.replace("sqlite:///", "")
        self.init_schema()

    @contextmanager
    def _get_connection(self):
        """Context manager yielding SQLite connection and guaranteeing deterministic close."""
        if self.db_path != ":memory:":
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_schema(self):
        """Creates tables if they do not exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    source_filename TEXT,
                    language_flavor TEXT NOT NULL,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    vulnerabilities_verified INTEGER DEFAULT 0,
                    patches_applied INTEGER DEFAULT 0,
                    token_usage_json TEXT DEFAULT '{}',
                    error_message TEXT
                )
            """)
            conn.commit()

    def save_job(self, job: ScanJob):
        """Inserts or updates a scan job."""
        job.updated_at = _utc_now_str()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scan_jobs (
                    id, created_at, updated_at, status, stage, source_filename,
                    language_flavor, vulnerabilities_found, vulnerabilities_verified,
                    patches_applied, token_usage_json, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    stage=excluded.stage,
                    source_filename=excluded.source_filename,
                    language_flavor=excluded.language_flavor,
                    vulnerabilities_found=excluded.vulnerabilities_found,
                    vulnerabilities_verified=excluded.vulnerabilities_verified,
                    patches_applied=excluded.patches_applied,
                    token_usage_json=excluded.token_usage_json,
                    error_message=excluded.error_message
            """, (
                job.id, job.created_at, job.updated_at, job.status, job.stage,
                job.source_filename, job.language_flavor, job.vulnerabilities_found,
                job.vulnerabilities_verified, job.patches_applied,
                job.token_usage_json, job.error_message
            ))
            conn.commit()

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Fetches a scan job by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return ScanJob(
                id=row["id"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                status=row["status"],
                stage=row["stage"],
                source_filename=row["source_filename"],
                language_flavor=row["language_flavor"],
                vulnerabilities_found=row["vulnerabilities_found"],
                vulnerabilities_verified=row["vulnerabilities_verified"],
                patches_applied=row["patches_applied"],
                token_usage_json=row["token_usage_json"],
                error_message=row["error_message"],
            )

    def list_jobs(self, limit: int = 50) -> List[ScanJob]:
        """Lists recent scan jobs."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            return [
                ScanJob(
                    id=row["id"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    status=row["status"],
                    stage=row["stage"],
                    source_filename=row["source_filename"],
                    language_flavor=row["language_flavor"],
                    vulnerabilities_found=row["vulnerabilities_found"],
                    vulnerabilities_verified=row["vulnerabilities_verified"],
                    patches_applied=row["patches_applied"],
                    token_usage_json=row["token_usage_json"],
                    error_message=row["error_message"],
                )
                for row in rows
            ]


def init_db(database_uri: str) -> DatabaseManager:
    """Initializes and returns the DatabaseManager."""
    return DatabaseManager(database_uri)
