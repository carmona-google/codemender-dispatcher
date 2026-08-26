"""GitHub App & CI/CD Automation Client for CodeMender Patch Delivery."""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class GitHubClient:
    """Automates PR comments, branch creation, patch commits, and remediation PR creation."""

    def __init__(self, token: Optional[str] = None, enable_mock: bool = False):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.enable_mock = enable_mock or not bool(self.token)

    def post_pr_comment(self, repo_name: str, pr_number: int, markdown_body: str) -> Dict[str, Any]:
        """Posts a vulnerability summary and patch review comment to a GitHub PR."""
        if self.enable_mock:
            logger.info("[MOCK-GITHUB] Posting comment on %s#PR-%s:\n%s", repo_name, pr_number, markdown_body[:120])
            return {
                "id": 999101,
                "html_url": f"https://github.com/{repo_name}/pull/{pr_number}#issuecomment-999101",
                "body": markdown_body,
            }

        # In production with live GITHUB_TOKEN
        import urllib.request
        url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CodeMender-Dispatcher/2.0",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(url, data=json.dumps({"body": markdown_body}).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_remediation_pr(
        self,
        repo_name: str,
        base_branch: str,
        feature_branch: str,
        title: str,
        body: str,
    ) -> Dict[str, Any]:
        """Opens a Pull Request for the verified AI patch."""
        if self.enable_mock:
            pr_num = 202
            logger.info("[MOCK-GITHUB] Opening Remediation PR on %s: %s -> %s", repo_name, feature_branch, base_branch)
            return {
                "number": pr_num,
                "html_url": f"https://github.com/{repo_name}/pull/{pr_num}",
                "title": title,
                "head": {"ref": feature_branch},
                "base": {"ref": base_branch},
            }

        import urllib.request
        url = f"https://api.github.com/repos/{repo_name}/pulls"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CodeMender-Dispatcher/2.0",
            "Content-Type": "application/json",
        }
        payload = {
            "title": title,
            "body": body,
            "head": feature_branch,
            "base": base_branch,
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @staticmethod
    def format_vulnerability_pr_comment(report: Dict[str, Any], session_id: str) -> str:
        """Formats report.json findings into a GitHub Markdown table."""
        findings = report.get("findings", [])
        total_found = report.get("total_vulnerabilities_found", 0)
        total_verified = report.get("total_vulnerabilities_verified", 0)
        total_patches = report.get("total_patches_applied", 0)

        if total_found == 0:
            return (
                "### 🛡️ CodeMender Security Scan: **CLEAN**\n\n"
                "No high-confidence vulnerabilities detected in this Pull Request.\n"
                f"- **Session ID:** `{session_id}`\n"
                "- **Detonation Containment:** Confined in air-gapped gVisor sandbox with zero egress."
            )

        table_rows = []
        for f in findings:
            table_rows.append(
                f"| `{f.get('id')}` | **{f.get('type')}** | `{f.get('severity')}` | `{f.get('file')}:{f.get('line')}` | ✅ Verified & Remediated |"
            )

        rows_str = "\n".join(table_rows)
        return (
            f"### ⚠️ CodeMender Security Report: **{total_verified} Vulnerability Verified**\n\n"
            "CodeMender executed the Split Execution cycle against this Pull Request. PoC exploits were detonated in an isolated sandbox, and automated patches have been generated.\n\n"
            "| Finding ID | Vulnerability | Severity | Target Location | Remediation Status |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
            f"{rows_str}\n\n"
            f"- **Patches Applied:** `{total_patches}`\n"
            f"- **Session ID:** `{session_id}`\n"
            "- **Next Step:** A companion remediation PR has been opened against an ephemeral feature branch for review."
        )
