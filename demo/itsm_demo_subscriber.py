"""Interactive Live ITSM (Jira & ServiceNow) Bridge & Customer Demo Simulator."""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.itsm.schemas import EventType


class ITSMDemoSubscriber:
    """Simulates enterprise ITSM ingestion (Jira / ServiceNow / Chronicle SIEM)."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        topic_id: Optional[str] = None,
    ):
        self.project_id = project_id or os.environ.get("GCP_PROJECT_ID", "generic-security-project")
        self.topic_id = topic_id or os.environ.get("PUBSUB_TOPIC_ID", "codemender-security-events")
        self.jira_tickets = {}
        self.snow_incidents = {}

    def render_banner(self):
        print("\033[1;36m" + "=" * 80 + "\033[0m")
        print("\033[1;32m  🛡️  CODEMENDER ENTERPRISE ITSM & SIEM INTEGRATION BRIDGE\033[0m")
        print(f"\033[1;34m  GCP Project: \033[0m{self.project_id} | \033[1;34mPub/Sub Topic: \033[0m{self.topic_id}")
        print("\033[1;36m" + "=" * 80 + "\033[0m\n")

    def process_event_payload(self, event_dict: dict):
        event_type = event_dict.get("event_type")
        finding = event_dict.get("finding", {})
        remediation = event_dict.get("remediation", {})
        session_id = event_dict.get("session_id", "N/A")
        provenance = finding.get("provenance_digest", "N/A")

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        print(f"\n\033[1;33m[PUBSUB MESSAGE RECEIVED @ {timestamp}]\033[0m")
        print(f"\033[1mEvent Type:\033[0m \033[1;35m{event_type}\033[0m | \033[1mSession:\033[0m `{session_id}`")
        print(f"\033[1mCryptographic Provenance Digest:\033[0m \033[0;32m{provenance}\033[0m")

        if event_type == EventType.VULNERABILITY_VERIFIED.value:
            finding_id = finding.get("finding_id", "FIND-001")
            jira_key = f"SEC-{abs(hash(finding_id)) % 9000 + 1000}"
            snow_key = f"INC{abs(hash(finding_id)) % 900000 + 100000}"

            self.jira_tickets[finding_id] = jira_key
            self.snow_incidents[finding_id] = snow_key

            print("\n  \033[1;31m🚨 VULNERABILITY VERIFIED IN ISOLATED SANDBOX\033[0m")
            print(f"  • Vulnerability Type: \033[1m{finding.get('vulnerability_type')}\033[0m")
            print(f"  • Severity:           \033[1;31m{finding.get('severity')}\033[0m")
            print(f"  • Affected File:      `{finding.get('affected_file_path')}:{finding.get('line_number')}`")
            print(f"  • PoC Sandbox Result: \033[1;32m{finding.get('verification_status')}\033[0m")

            print("\n  \033[1;34m[ITSM ACTION] Auto-Creating Incident Tickets:\033[0m")
            print(f"    ├─ 🎫 \033[1mJira Security Issue:\033[0m     \033[1;36m{jira_key}\033[0m (Status: \033[1;33mIN PROGRESS\033[0m | Priority: High)")
            print(f"    └─ 📋 \033[1mServiceNow Incident:\033[0m     \033[1;36m{snow_key}\033[0m (State: \033[1;33mAssigned to CodeMender AI\033[0m)")

        elif event_type == EventType.REMEDIATION_PR_CREATED.value:
            finding_id = finding.get("finding_id", "FIND-001")
            jira_key = self.jira_tickets.get(finding_id, "SEC-1042")
            snow_key = self.snow_incidents.get(finding_id, "INC109281")
            pr_url = remediation.get("pull_request_url", "https://github.com/org/repo/pull/42")

            print("\n  \033[1;32m✨ AUTOMATED REMEDIATION PATCH & PR GENERATED\033[0m")
            print(f"  • Companion PR:       \033[1;34m{pr_url}\033[0m")
            print(f"  • Feature Branch:     `{remediation.get('feature_branch')}`")
            print(f"  • Verification Tests: \033[1;32mPASSED (0 breaking changes)\033[0m")

            print("\n  \033[1;34m[ITSM ACTION] Updating Tickets with Peer Review Link:\033[0m")
            print(f"    ├─ 🎫 \033[1mJira Issue {jira_key}:\033[0m     Status -> \033[1;33mPENDING CODE REVIEW\033[0m (PR Linked)")
            print(f"    └─ 📋 \033[1mServiceNow {snow_key}:\033[0m     Work Notes updated with Patch Diff & Provenance")

        elif event_type == EventType.REMEDIATION_PR_MERGED.value:
            finding_id = finding.get("finding_id", "FIND-001")
            jira_key = self.jira_tickets.get(finding_id, "SEC-1042")
            snow_key = self.snow_incidents.get(finding_id, "INC109281")

            print("\n  \033[1;32m🎉 HUMAN PEER REVIEW MERGED: PATCH DEPLOYED\033[0m")
            print(f"  • Review Decision:    \033[1;32mAPPROVED & MERGED TO MAIN\033[0m")

            print("\n  \033[1;34m[ITSM ACTION] Auto-Closing Tickets & SIEM Audit Trail:\033[0m")
            print(f"    ├─ 🎫 \033[1mJira Issue {jira_key}:\033[0m     Status -> \033[1;32mRESOLVED\033[0m (Resolution: Remediated by AI & Human Approved)")
            print(f"    ├─ 📋 \033[1mServiceNow {snow_key}:\033[0m     State -> \033[1;32mCLOSED / RESOLVED\033[0m")
            print(f"    └─ 📜 \033[1mChronicle SIEM:\033[0m         Compliance Audit event logged with SHA-256 fingerprint")

        elif event_type == EventType.REMEDIATION_PR_REJECTED.value:
            finding_id = finding.get("finding_id", "FIND-001")
            jira_key = self.jira_tickets.get(finding_id, "SEC-1042")
            snow_key = self.snow_incidents.get(finding_id, "INC109281")

            print("\n  \033[1;31m❌ HUMAN PEER REVIEW: PR CLOSED WITHOUT MERGE\033[0m")
            print(f"  • Review Decision:    \033[1;31mREJECTED / CLOSED\033[0m")

            print("\n  \033[1;34m[ITSM ACTION] Escalating to Engineering Lead:\033[0m")
            print(f"    ├─ 🎫 \033[1mJira Issue {jira_key}:\033[0m     Status -> \033[1;31mRE-OPENED (Manual Review Required)\033[0m")
            print(f"    └─ 📋 \033[1mServiceNow {snow_key}:\033[0m     Escalated to Application Security Team")

        print("-" * 80)

    def run_live_simulation(self):
        """Simulates a live multi-stage ITSM lifecycle for demonstration."""
        self.render_banner()
        print("\033[1;37mListening for live Google Cloud Pub/Sub events...\033[0m\n")

        # 1. Simulate VULNERABILITY_VERIFIED
        time.sleep(1)
        self.process_event_payload({
            "event_type": "VULNERABILITY_VERIFIED",
            "session_id": "scan-7a89b12c",
            "finding": {
                "finding_id": "SEC-001-426",
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "affected_file_path": "app/db/query_builder.py",
                "line_number": 42,
                "verification_status": "VERIFIED_EXPLOITABLE",
                "provenance_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        })

        # 2. Simulate REMEDIATION_PR_CREATED
        time.sleep(2)
        self.process_event_payload({
            "event_type": "REMEDIATION_PR_CREATED",
            "session_id": "scan-7a89b12c",
            "finding": {
                "finding_id": "SEC-001-426",
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "affected_file_path": "app/db/query_builder.py",
                "line_number": 42,
                "verification_status": "VERIFIED_EXPLOITABLE",
                "provenance_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "remediation": {
                "pull_request_url": "https://github.com/GenericCorp/payment-gateway/pull/204",
                "feature_branch": "codemender/patch-pr-89",
                "target_branch": "main",
                "files_modified_count": 1,
                "verification_passed": True,
            },
        })

        # 3. Simulate Human Feedback: PR Merged
        time.sleep(2)
        self.process_event_payload({
            "event_type": "REMEDIATION_PR_MERGED",
            "session_id": "scan-7a89b12c",
            "finding": {
                "finding_id": "SEC-001-426",
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "affected_file_path": "app/db/query_builder.py",
                "line_number": 42,
                "verification_status": "RESOLVED",
                "provenance_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "remediation": {
                "pull_request_url": "https://github.com/GenericCorp/payment-gateway/pull/204",
                "feature_branch": "codemender/patch-pr-89",
                "target_branch": "main",
                "human_review_status": "MERGED",
            },
        })

        print("\n\033[1;32m✅ ITSM Lifecycle Demonstration Completed Successfully.\033[0m\n")


if __name__ == "__main__":
    subscriber = ITSMDemoSubscriber()
    subscriber.run_live_simulation()
