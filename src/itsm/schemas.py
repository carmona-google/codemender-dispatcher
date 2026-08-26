"""Data schemas for Decoupled Event-Driven ITSM integration with Cryptographic Provenance."""

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any


class EventType(str, Enum):
    VULNERABILITY_VERIFIED = "VULNERABILITY_VERIFIED"
    REMEDIATION_PR_CREATED = "REMEDIATION_PR_CREATED"
    REMEDIATION_PR_MERGED = "REMEDIATION_PR_MERGED"
    REMEDIATION_PR_REJECTED = "REMEDIATION_PR_REJECTED"


def compute_provenance_digest(repository_url: str, commit_sha: str, finding_id: str) -> str:
    """Generates an immutable zero-knowledge provenance hash for SIEM correlation."""
    raw = f"{repository_url}:{commit_sha}:{finding_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class VulnerabilityFindingMetadata:
    """Metadata-only representation of a verified vulnerability (Zero Source Code)."""

    finding_id: str
    vulnerability_type: str
    severity: str
    affected_file_path: str
    line_number: int
    verification_status: str
    cve_id: Optional[str] = None
    poc_execution_duration_ms: int = 0
    provenance_digest: Optional[str] = None


@dataclass
class RemediationPRMetadata:
    """Metadata-only representation of a created remediation Pull Request."""

    finding_id: str
    repository_url: str
    target_branch: str
    feature_branch: str
    pull_request_url: str
    files_modified_count: int = 1
    verification_passed: bool = True
    human_review_status: str = "PENDING"  # PENDING, MERGED, REJECTED
    rejection_reason: Optional[str] = None


@dataclass
class CodeMenderSecurityEvent:
    """Platform-agnostic security event published to Google Cloud Pub/Sub."""

    event_id: str
    event_type: EventType
    timestamp_utc: str
    project_id: str
    session_id: str
    finding: VulnerabilityFindingMetadata
    remediation: Optional[RemediationPRMetadata] = None
    token_usage: Dict[str, Any] = field(default_factory=dict)

    def model_dump(self) -> Dict[str, Any]:
        """Serializes dataclass hierarchy to dictionary."""
        data = asdict(self)
        if isinstance(self.event_type, EventType):
            data["event_type"] = self.event_type.value
        return data
