#!/usr/bin/env bash
# ==============================================================================
# CodeMender Execution Sandbox Entrypoint
# Orchestrates find -> verify -> fix inside the ephemeral sandbox.
# ==============================================================================

set -euo pipefail

STAGE="${CODEMENDER_STAGE:-all}"
SOURCE_DIR="${CODEMENDER_SOURCE_DIR:-/workspace/source}"
STATE_DIR="${CODEMENDER_STATE_DIR:-/run/codemender/state}"
OUTPUT_DIR="${CODEMENDER_OUTPUT_DIR:-/workspace/output}"
CM_BIN="${CODEMENDER_BIN:-/usr/local/bin/cm}"

mkdir -p "${STATE_DIR}" "${OUTPUT_DIR}" "${OUTPUT_DIR}/patches"
cd "${SOURCE_DIR}"

echo "[CODEMENDER-SANDBOX] Initializing Execution Sandbox for Stage: ${STAGE}"
echo "[CODEMENDER-SANDBOX] Working Directory: $(pwd)"

# Fallback to mock_cm if production binary is absent
if [[ ! -x "${CM_BIN}" ]]; then
  echo "[CODEMENDER-SANDBOX] WARNING: '${CM_BIN}' not found. Falling back to test mock harness."
  CM_BIN="/usr/local/bin/mock_cm.sh"
fi

run_find() {
  echo "[CODEMENDER-SANDBOX] Starting Phase 1: AST Scan & Vulnerability Finding..."
  "${CM_BIN}" find --headless --yes
}

run_verify() {
  echo "[CODEMENDER-SANDBOX] Starting Phase 2: PoC Exploit Sandbox Verification..."
  "${CM_BIN}" verify --headless --yes
}

run_fix() {
  echo "[CODEMENDER-SANDBOX] Starting Phase 3: Patch Generation & Validation..."
  "${CM_BIN}" fix --headless --yes --confirm_writes=false
}

case "${STAGE}" in
  find)
    run_find
    ;;
  verify)
    run_verify
    ;;
  fix)
    run_fix
    ;;
  all)
    run_find
    run_verify
    run_fix
    ;;
  *)
    echo "Unknown stage: ${STAGE}. Expected 'find', 'verify', 'fix', or 'all'."
    exit 1
    ;;
esac

echo "[CODEMENDER-SANDBOX] Cycle complete. Output artifacts staged in ${OUTPUT_DIR}."
