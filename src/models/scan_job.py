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
    IMPORT = "IMPORT"
    FIND = "FIND"
    VERIFY = "VERIFY"
    FIX = "FIX"
    PULL_REQUEST = "PULL_REQUEST"
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
        model_name: Optional[str] = None,
        vulnerabilities_found: int = 0,
        vulnerabilities_verified: int = 0,
        patches_applied: int = 0,
        token_usage_json: str = "{}",
        error_message: Optional[str] = None,
        github_repo: Optional[str] = None,
        github_branch: Optional[str] = None,
        pr_url: Optional[str] = None,
        pr_number: Optional[int] = None,
    ):
        self.id = id
        self.created_at = created_at or _utc_now_str()
        self.updated_at = updated_at or _utc_now_str()
        self.status = status
        self.stage = stage
        self.source_filename = source_filename
        self.language_flavor = language_flavor
        self.model_name = model_name or os.environ.get("CODEMENDER_MODEL", "gemini-4-argon")
        self.vulnerabilities_found = vulnerabilities_found
        self.vulnerabilities_verified = vulnerabilities_verified
        self.patches_applied = patches_applied
        self.token_usage_json = token_usage_json
        self.error_message = error_message
        self.github_repo = github_repo
        self.github_branch = github_branch
        self.pr_url = pr_url
        self.pr_number = pr_number

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "stage": self.stage,
            "source_filename": self.source_filename,
            "language_flavor": self.language_flavor,
            "model_name": self.model_name,
            "vulnerabilities_found": self.vulnerabilities_found,
            "vulnerabilities_verified": self.vulnerabilities_verified,
            "patches_applied": self.patches_applied,
            "token_usage": json.loads(self.token_usage_json or "{}"),
            "error_message": self.error_message,
            "github_repo": self.github_repo,
            "github_branch": self.github_branch,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
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
        """Creates tables if they do not exist and migrates new columns."""
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
                    model_name TEXT DEFAULT 'gemini-4-argon',
                    vulnerabilities_found INTEGER DEFAULT 0,
                    vulnerabilities_verified INTEGER DEFAULT 0,
                    patches_applied INTEGER DEFAULT 0,
                    token_usage_json TEXT DEFAULT '{}',
                    error_message TEXT,
                    github_repo TEXT,
                    github_branch TEXT,
                    pr_url TEXT,
                    pr_number INTEGER
                )
            """)
            # Ensure backwards compatibility with existing database files
            cols = [row["name"] for row in conn.execute("PRAGMA table_info(scan_jobs)").fetchall()]
            if "model_name" not in cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN model_name TEXT DEFAULT 'gemini-4-argon'")
            if "github_repo" not in cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN github_repo TEXT")
            if "github_branch" not in cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN github_branch TEXT")
            if "pr_url" not in cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN pr_url TEXT")
            if "pr_number" not in cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN pr_number INTEGER")
            conn.commit()

    def save_job(self, job: ScanJob):
        """Inserts or updates a scan job."""
        job.updated_at = _utc_now_str()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scan_jobs (
                    id, created_at, updated_at, status, stage, source_filename,
                    language_flavor, model_name, vulnerabilities_found,
                    vulnerabilities_verified, patches_applied, token_usage_json, error_message,
                    github_repo, github_branch, pr_url, pr_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    stage=excluded.stage,
                    source_filename=excluded.source_filename,
                    language_flavor=excluded.language_flavor,
                    model_name=excluded.model_name,
                    vulnerabilities_found=excluded.vulnerabilities_found,
                    vulnerabilities_verified=excluded.vulnerabilities_verified,
                    patches_applied=excluded.patches_applied,
                    token_usage_json=excluded.token_usage_json,
                    error_message=excluded.error_message,
                    github_repo=excluded.github_repo,
                    github_branch=excluded.github_branch,
                    pr_url=excluded.pr_url,
                    pr_number=excluded.pr_number
            """, (
                job.id, job.created_at, job.updated_at, job.status, job.stage,
                job.source_filename, job.language_flavor, job.model_name,
                job.vulnerabilities_found, job.vulnerabilities_verified,
                job.patches_applied, job.token_usage_json, job.error_message,
                job.github_repo, job.github_branch, job.pr_url, job.pr_number
            ))
            conn.commit()

    def _row_to_job(self, row: sqlite3.Row) -> ScanJob:
        row_keys = row.keys()
        return ScanJob(
            id=row["id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=row["status"],
            stage=row["stage"],
            source_filename=row["source_filename"],
            language_flavor=row["language_flavor"],
            model_name=row["model_name"] if "model_name" in row_keys else "gemini-4-argon",
            vulnerabilities_found=row["vulnerabilities_found"],
            vulnerabilities_verified=row["vulnerabilities_verified"],
            patches_applied=row["patches_applied"],
            token_usage_json=row["token_usage_json"],
            error_message=row["error_message"],
            github_repo=row["github_repo"] if "github_repo" in row_keys else None,
            github_branch=row["github_branch"] if "github_branch" in row_keys else None,
            pr_url=row["pr_url"] if "pr_url" in row_keys else None,
            pr_number=row["pr_number"] if "pr_number" in row_keys else None,
        )

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Fetches a scan job by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_job(row)

    def list_jobs(self, limit: int = 50) -> List[ScanJob]:
        """Lists recent scan jobs."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            return [self._row_to_job(row) for row in rows]


def init_db(database_uri: str) -> DatabaseManager:
    """Initializes and returns the DatabaseManager."""
    return DatabaseManager(database_uri)
