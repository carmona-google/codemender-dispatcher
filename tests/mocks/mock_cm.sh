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
CM_VERSION="${CODEMENDER_CLI_VERSION:-0.14.0}"
MODEL_NAME="${CODEMENDER_MODEL:-gemini-4-argon}"

mkdir -p "${STATE_DIR}" "${OUTPUT_DIR}" "${OUTPUT_DIR}/patches"

case "${COMMAND}" in
  --version|version)
    echo "cm version ${CM_VERSION}"
    ;;

  import)
    echo "[MOCK-CM] Running 'cm import' (v${CM_VERSION}, model=${MODEL_NAME}) - Ingesting external scanner JSON report..."
    cat <<EOF > "${OUTPUT_DIR}/findings.json"
{
  "scan_id": "${SESSION_ID}",
  "cm_version": "${CM_VERSION}",
  "model_name": "${MODEL_NAME}",
  "findings": [
    {
      "id": "IMP-001-101",
      "type": "SUPPLY_CHAIN_CI_INJECTION",
      "cve": "CVE-2026-109618",
      "severity": "CRITICAL",
      "file": "composer.json",
      "line": 12,
      "snippet": "phpunit/phpunit: ^10.5.0 (vulnerable to CVE-2026-109618)",
      "source_tool": "WIZ_CODE",
      "external_id": "WIZ-VULN-2026-109618-COMPOSER"
    }
  ]
}
EOF
    echo "[MOCK-CM] 'cm import' completed. Normalized 1 external finding."
    ;;

  find)
    echo "[MOCK-CM] Running 'cm find' (v${CM_VERSION}, model=${MODEL_NAME}) - Parsing local AST & streaming targeted metadata..."
    cat <<EOF > "${OUTPUT_DIR}/findings.json"
{
  "scan_id": "${SESSION_ID}",
  "cm_version": "${CM_VERSION}",
  "model_name": "${MODEL_NAME}",
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
    echo "[MOCK-CM] Running 'cm verify' (v${CM_VERSION}, model=${MODEL_NAME}) - Detonating AI PoC exploit in isolated sandbox..."
    cat <<EOF > "${OUTPUT_DIR}/verification.json"
{
  "scan_id": "${SESSION_ID}",
  "cm_version": "${CM_VERSION}",
  "model_name": "${MODEL_NAME}",
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
    echo "[MOCK-CM] Running 'cm fix' (v${CM_VERSION}, model=${MODEL_NAME}) - Generating, applying, and validating fix patch..."
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
  "cm_version": "${CM_VERSION}",
  "model_name": "${MODEL_NAME}",
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
- CLI Version: ${CM_VERSION}
- Active Model: ${MODEL_NAME}
- Stage: find -> verify -> fix
- Exploit Detonation: Contained in sandbox
- Patch Verification: Test suite passed with zero regressions.
EOF
    echo "[MOCK-CM] 'cm fix' completed successfully. Final reports written to ${OUTPUT_DIR}."
    ;;

  *)
    echo "Usage: mock_cm.sh {--version|find|verify|fix}"
    exit 1
    ;;
esac
