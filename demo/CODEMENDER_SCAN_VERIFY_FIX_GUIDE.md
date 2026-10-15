# CodeMender Scan, Verify & Fix Runbook (`vulnerable-dep-demo`)

This guide provides the end-to-end command sequence to **scan (`cm find`)**, **inspect (`cm report`)**, **verify (`cm verify`)**, and **remediate (`cm fix`)** vulnerabilities in the `vulnerable-dep-demo` repository using **CodeMender**.

---

## 1. Prepare the Repository & Create a Topic Branch

Navigate to the target repository, confirm a clean working tree, and create a dedicated topic branch (never commit directly to `main` or `master`):

```bash
cd /Users/[USERNAME]/Agy/5thSsecurityForum/vulnerable-dep-demo
git status
git checkout -b codemender/remediate-vulnerable-deps
```

---

## 2. Scan the Codebase & Dependencies (`cm find`)

Run CodeMender's (`cm v0.14.0`) discovery phase to parse the Abstract Syntax Tree (AST), dependency manifests, and data flows to identify candidate vulnerabilities:

```bash
# Verify CLI version (0.14.0+)
cm --version

# Interactive mode
cm find --model gemini-4-argon

# Headless / CI mode
cm find -y --model gemini-4-argon
```

---

## 3. Inspect Detected Findings (`cm report`)

List all discovered findings and inspect detailed vulnerability traces, affected files/lines, and conceptual exploit payloads:

```bash
# 1. Display summary table of all findings (ID, Severity, Title)
cm report

# 2. View full markdown report for a specific finding ID
cm report --format md
```

---

## 4. Verify Exploitability in Sandbox (`cm verify`)

Compile the target application and detonate Proof-of-Concept (PoC) payloads inside an isolated sandbox to confirm which candidate findings are genuinely exploitable (filtering out false positives):

```bash
# Interactive verification
cm verify <FINDING_ID> --model gemini-4-argon

# Headless / CI verification
cm verify <FINDING_ID> -y --model gemini-4-argon
```

---

## 5. Generate & Validate Remediation Patches (`cm fix`)

Author contextual code or dependency patches for verified vulnerabilities and automatically re-run the PoC exploit and test suite to ensure the issue is resolved without regressions:

```bash
# Interactive mode (prompts before modifying files)
cm fix <FINDING_ID> --model gemini-4-argon

# Automated write mode
cm fix <FINDING_ID> -y --model gemini-4-argon
```

---

## 6. Local Validation, Commit & Pull Request

Inspect the generated changes, re-verify that the exploit is blocked and unit tests pass, and push the topic branch for peer review:

```bash
# 1. Inspect the applied remediation diff
git diff

# 2. Re-run CodeMender verification & unit tests to confirm zero regressions
cm verify <FINDING_ID> --model gemini-4-argon

# 3. Stage, commit, and push the sanitized branch
git add -u
git commit -m "fix(security): remediate verified vulnerabilities via CodeMender"
git push -u origin codemender/remediate-vulnerable-deps
```

---

## Optional: Run via the CodeMender Dispatcher API

If the **CodeMender Dispatcher** web service is running locally, you can also trigger the full `find -> verify -> fix` pipeline via its REST API:

```bash
# 1. Package the repository into a clean zip archive
zip -r /tmp/vulnerable-dep-demo.zip /Users/[USERNAME]/Agy/5thSsecurityForum/vulnerable-dep-demo \
  -x "*/.git/*" "*/node_modules/*" "*/.venv/*"

# 2. Upload archive to initiate the sandboxed scan
curl -X POST http://localhost:[PORT]/api/v1/scans \
  -F "file=@/tmp/vulnerable-dep-demo.zip" \
  -F "language_flavor=polyglot"

# 3. Retrieve scan status, verified findings, and generated .diff patches
curl -s http://localhost:[PORT]/api/v1/scans/<SESSION_ID> | jq .

# 4. Stream or inspect the execution log (LOG.md)
curl -s http://localhost:[PORT]/api/v1/scans/<SESSION_ID>/logs | jq -r .logs
```

---

## 7. Why CodeMender Outperforms Traditional SAST, SCA & DAST on `vulnerable-dep-demo`

In `vulnerable-dep-demo`, the attack combines a **typosquatted supply-chain payload** (`litellm-proxy-server` inside `malicious_dep/`), **install- and import-time credential harvesting**, **hardcoded fallback secrets**, and a **pinned library CVE** (`cryptography==43.0.1`).

### 7.1 Structural Blind Spots of Traditional Tools

| Tool Category | Blind Spot in `vulnerable-dep-demo` | Concrete Failure Mode in This Repository |
| :--- | :--- | :--- |
| **Traditional SAST** *(Rule/Regex Static Scanners)* | **Lacks semantic intent for supply-chain hooks** | In `malicious_dep/litellm_proxy_server/__init__.py` and `malicious_dep/setup.py`, the payload uses standard Python calls (`os.environ.get()`, `open()`, `json.dumps()`). Because there is no classic SQLi, `eval()`, or shell-injection sink, rule-based SAST treats these as benign file/environment operations while flagging unrelated false positives. |
| **Traditional SCA** *(Trivy / `pip-audit`)* | **Blind to zero-day typosquats, local paths, & reachability** | 1. **Zero-Day / Local Path Evasion:** `requirements.txt` installs `./malicious_dep` from a local path (or, in the real world, a newly published typosquat before advisory DBs index it). Signature-based SCA only flags packages *after* they are added to a known-bad database.<br>2. **Unreachable CVE Noise:** SCA flags `cryptography==43.0.1` in `requirements.txt` as vulnerable, even though `cryptography` is **never imported or invoked** anywhere in `src/myapp/`. |
| **Traditional DAST** *(Black-Box HTTP Scanners)* | **Cannot see install/import-time execution & risks real exfiltration** | 1. **Wrong Execution Stage:** The payload fires during `pip install` (`setup.py`) and at module import (`src/myapp/main.py`) *before* the Flask server even starts listening on `[APP_PORT]`. Probing `GET /` or `POST /complete` over HTTP cannot detect silent background credential harvesting.<br>2. **Live Exfiltration Risk:** Building the app for a standard DAST scan runs `pip install` in an unquarantined runner—allowing a real malicious `setup.py` to immediately exfiltrate CI/CD secrets to its C2 server. |

---

### 7.2 How CodeMender Excels Across All Three Phases

#### A. Semantic Cross-File & Behavioral Intent Detection (`cm find`)
Instead of matching static CVE lists or rigid regex sinks, CodeMender correlates AST data flows and package metadata across the entire repository:
- **Detects Zero-Day Supply-Chain Behavior:** Recognizes that `malicious_dep/setup.py` spoofs `author="LiteLLM"` and `url="https://github.com/BerriAI/litellm"` under the typosquatted name `litellm-proxy-server`, executes top-level hooks on install and import, iterates over 10 sensitive environment variables (`TARGET_ENV_VARS` in `__init__.py`), and stubs out `completion()` with `NotImplementedError`.
- **True Reachability Analysis:** Distinguishes between the actively imported `litellm_proxy_server` (`src/myapp/main.py`) and unused transitive/pinned dependencies like `cryptography==43.0.1`.
- **Catches Hardcoded Fallback Credentials:** Flags seeded credentials in `src/myapp/config.py` and `scripts/install_and_detect.sh`.

#### B. Air-Gapped Sandbox Verification with Zero Blast Radius (`cm verify`)
- **Proves Exploitability Safely:** During `cm verify`, CodeMender runs inside an ephemeral container with **network egress severed (`--network=none`)**, dropped Linux capabilities (`--cap-drop=ALL`), and gVisor kernel isolation.
- **Detonates Install & Import Hooks:** Safely executes `pip install` and `import litellm_proxy_server`, observing the unauthorized filesystem writes (`/tmp/litellm_install_canary.txt` and `/tmp/litellm_canary.txt`) and `os.environ` harvesting—proving the vulnerability with **zero false positives** while guaranteeing that any real outbound C2 traffic is blocked at the network boundary.

#### C. Coordinated Multi-File Remediation (`cm fix`)
SAST, DAST, and SCA stop at generating an alert. Simply removing `litellm-proxy-server` from `requirements.txt` would break `src/myapp/main.py` with an `ImportError`. CodeMender's `cm fix` performs **coordinated, end-to-end repair**:
1. **Dependency Manifest:** Replaces `./malicious_dep` with the legitimate `litellm==1.49.1` and upgrades `cryptography>=43.0.3` in `requirements.txt` (matching `requirements-safe.txt`).
2. **Application Code:** Refactors `src/myapp/main.py` from `import litellm_proxy_server as llm` to `import litellm as llm` so `llm.completion()` works seamlessly.
3. **Secret Sanitization:** Strips hardcoded fallback credentials from `src/myapp/config.py` and `scripts/install_and_detect.sh`.
4. **Post-Patch Verification:** Re-runs sandbox verification to prove that `/tmp/litellm_*canary*.txt` is no longer created and the application starts cleanly with zero regressions.

