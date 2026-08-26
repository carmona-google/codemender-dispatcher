"""Unit tests for DLP pre-sanitizer with Shannon entropy and Provenance Digest."""

import unittest
from datetime import datetime, timezone

from src.itsm.schemas import (
    CodeMenderSecurityEvent,
    EventType,
    VulnerabilityFindingMetadata,
    compute_provenance_digest,
)
from src.itsm.dlp_filter import DLPFilter
from src.itsm.pubsub_publisher import ITSMPubSubPublisher


class TestDLPFilterV2(unittest.TestCase):
    """Verifies DLPFilter v2.0 entropy detection, provenance digest, and diff prevention."""

    def test_provenance_digest_generation(self):
        digest = compute_provenance_digest(
            repository_url="https://github.com/example/repo",
            commit_sha="a1b2c3d4e5f6",
            finding_id="SEC-FIND-101",
        )
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_valid_vulnerability_event_with_provenance(self):
        digest = compute_provenance_digest("https://github.com/example/repo", "sha123", "SEC-101")
        event = CodeMenderSecurityEvent(
            event_id="evt-001",
            event_type=EventType.VULNERABILITY_VERIFIED,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            project_id="codemender-demo-prod",
            session_id="scan-session-123",
            finding=VulnerabilityFindingMetadata(
                finding_id="SEC-FIND-101",
                vulnerability_type="SQL_INJECTION",
                cve_id="CVE-2024-XXXX",
                severity="CRITICAL",
                affected_file_path="app/db/query_builder.py",
                line_number=42,
                verification_status="VERIFIED_EXPLOITABLE",
                poc_execution_duration_ms=340,
                provenance_digest=digest,
            ),
        )
        publisher = ITSMPubSubPublisher(
            project_id="codemender-demo-prod",
            topic_id="codemender-security-events",
            enable_mock=True,
        )
        msg_id = publisher.publish_event(event)
        self.assertEqual(msg_id, "mock-msg-evt-001")

    def test_shannon_entropy_secret_detection(self):
        high_entropy_token = "K3jF9z!qW8$vL2mP7xR1@tY4#bN6"
        data = {
            "finding_id": "SEC-102",
            "suspicious_token": high_entropy_token,
        }
        with self.assertRaises(ValueError) as ctx:
            DLPFilter.sanitize_event_dict(data)
        self.assertIn("High-entropy secret detected", str(ctx.exception))

    def test_dlp_rejects_unified_diff_in_metadata(self):
        malicious_diff_snippet = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-bad()\n"
            "+good()\n"
        )
        data = {
            "finding_id": "SEC-101",
            "metadata_note": malicious_diff_snippet,
        }
        with self.assertRaises(ValueError) as ctx:
            DLPFilter.sanitize_event_dict(data)
        self.assertIn("DLP Violation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
