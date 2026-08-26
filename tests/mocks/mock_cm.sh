#!/usr/bin/env bash
# ==============================================================================
# Mock CodeMender CLI (cm)
# Simulates cm find, cm verify, and cm fix execution loops for local testing.
# ==============================================================================

set -euo pipefail

COMMAND="${1:-}"
shift || true

STATE_DIR="${CODEMENDER_STATE_DIR:-/run/codemender/state}"
OUTPUT_DIR="${CODEMENDER_OUTPUT_DIR:-/workspace/output}"
SESSION_ID="${CODEMENDER_SESSION_ID:-mock-session-001}"

mkdir -p "${STATE_DIR}" "${OUTPUT_DIR}" "${OUTPUT_DIR}/patches"

case "${COMMAND}" in
  find)
    echo "[MOCK-CM] Running 'cm find' - Parsing local AST & streaming targeted metadata..."
    cat <<EOF > "${OUTPUT_DIR}/findings.json"
{
  "scan_id": "${SESSION_ID}",
  "findings": [
    {
      "id": "SEC-FIND-101",
      "type": "SQL_INJECTION",
      "cve": "CVE-2024-XXXX",
      "severity": "CRITICAL",
      "file": "app/db/query_builder.py",
      "line": 42,
      "snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    },
    {
      "id": "SEC-FIND-102",
      "type": "PATH_TRAVERSAL",
      "cve": "CVE-2024-YYYY",
      "severity": "HIGH",
      "file": "app/routes/files.py",
      "line": 88,
      "snippet": "with open(os.path.join(UPLOAD_DIR, filename), 'rb') as f:"
    }
  ]
}
EOF
    echo "[MOCK-CM] 'cm find' completed. Found 2 candidate vulnerabilities."
    ;;

  verify)
    echo "[MOCK-CM] Running 'cm verify' - Detonating AI PoC exploit in isolated sandbox..."
    cat <<EOF > "${OUTPUT_DIR}/verification.json"
{
  "scan_id": "${SESSION_ID}",
  "verified_findings": [
    {
      "finding_id": "SEC-FIND-101",
      "status": "VERIFIED_EXPLOITABLE",
      "poc_output": "Database dump triggered via ' OR '1'='1 payload.",
      "duration_ms": 340
    }
  ]
}
EOF
    echo "[MOCK-CM] 'cm verify' completed. 1 vulnerability verified exploitable."
    ;;

  fix)
    echo "[MOCK-CM] Running 'cm fix' - Generating, applying, and validating fix patch..."
    cat <<'EOF' > "${OUTPUT_DIR}/patches/SEC-FIND-101.diff"
--- a/app/db/query_builder.py
+++ b/app/db/query_builder.py
@@ -40,4 +40,4 @@
 def get_user_by_id(cursor, user_id: str):
-    query = f"SELECT * FROM users WHERE id = {user_id}"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE id = %s"
+    cursor.execute(query, (user_id,))
     return cursor.fetchone()
EOF

    # Generate final consolidated report.json
    cat <<EOF > "${OUTPUT_DIR}/report.json"
{
  "session_id": "${SESSION_ID}",
  "status": "COMPLETED",
  "total_vulnerabilities_found": 2,
  "total_vulnerabilities_verified": 1,
  "total_patches_applied": 1,
  "findings": [
    {
      "id": "SEC-FIND-101",
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "file": "app/db/query_builder.py",
      "line": 42,
      "verified": true,
      "remediated": true,
      "patch_file": "patches/SEC-FIND-101.diff"
    }
  ],
  "token_usage": {
    "prompt_tokens": 1420,
    "completion_tokens": 580,
    "total_tokens": 2000
  }
}
EOF

    # Generate LOG.md
    cat <<EOF > "${OUTPUT_DIR}/LOG.md"
# CodeMender Execution Log
- Session ID: ${SESSION_ID}
- Stage: find -> verify -> fix
- Exploit Detonation: Contained in sandbox
- Patch Verification: Test suite passed with zero regressions.
EOF
    echo "[MOCK-CM] 'cm fix' completed successfully. Final reports written to ${OUTPUT_DIR}."
    ;;

  *)
    echo "Usage: mock_cm.sh {find|verify|fix}"
    exit 1
    ;;
esac
