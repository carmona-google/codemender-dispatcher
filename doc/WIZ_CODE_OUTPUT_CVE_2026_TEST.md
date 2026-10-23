# Wiz Code & Code-to-Cloud Triage Output: `codemender-cve-2026-test.zip`

This document provides:
1. **Standalone Wiz Code CLI (`wizcli dir scan`) Output** for `/workspace/repos/codemender-cve-2026-test.zip` (covering SCA, Container/Dockerfile, IaC, and Secret scanning).
2. **CodeMender + Wiz Security Graph Code-to-Cloud Triage Output** (following the 4-Phase `code-to-cloud-triage` & `evaluate-codemender-findings` workflow correlating CodeMender's C/PHP AST findings with the AWS ECS + API Gateway cloud assets in Wiz).
3. **Coverage Gap Comparison**: Standalone Wiz Code vs. CodeMender + `gemini-4-argon` + Wiz Security Graph.

---

## Part 1: Standalone Wiz Code CLI Output (`wizcli dir scan`)

### 1.1. Terminal Output (`wizcli dir scan --path ./codemender-cve-2026-test --iac --vulnerabilities --secrets`)

```text
           _            _ _ 
 __      _(_)______ ___| (_)
 \ \ /\ / / |_  / __| | | |
  \ V  V /| |/ / (__| | | |
   \_/\_/ |_/___\___|_|_|_|  v0.48.2 (Wiz Code Unified Scanner)

[i] Target Directory : /workspace/repos/codemender-cve-2026-test
[i] Enabled Scanners : Vulnerabilities (SCA), IaC (Terraform/Dockerfile), Secrets, SAST
[i] Policy Baseline  : Default Vulnerabilities Policy, Default IaC Policy, Default Secrets Policy

==========================================================================================
 1. SOFTWARE COMPOSITION ANALYSIS (SCA) & CONTAINER BASE IMAGE FINDINGS
==========================================================================================
+------------------+----------------+------------------+------------------+----------+-----------------------------------------------+
| PACKAGE / IMAGE  | INSTALLED VER  | FIXED VERSION    | VULNERABILITY ID | SEVERITY | FILE PATH                                     |
+------------------+----------------+------------------+------------------+----------+-----------------------------------------------+
| php (composer)   | 8.2.34         | 8.2.35           | CVE-2026-109618  | CRITICAL | codemender-cve-2026-test/app/composer.json:L7 |
| php (composer)   | 8.2.34         | 8.2.35           | CVE-2026-109619  | CRITICAL | codemender-cve-2026-test/app/composer.json:L7 |
| php (debian-12)  | 8.2.34-fpm     | 8.2.35-fpm       | CVE-2026-109618  | CRITICAL | codemender-cve-2026-test/deploy/Dockerfile:L9 |
| php (debian-12)  | 8.2.34-fpm     | 8.2.35-fpm       | CVE-2026-109619  | CRITICAL | codemender-cve-2026-test/deploy/Dockerfile:L9 |
+------------------+----------------+------------------+------------------+----------+-----------------------------------------------+

==========================================================================================
 2. INFRASTRUCTURE-AS-CODE (IaC) FINDINGS (Terraform & Dockerfile)
==========================================================================================
+-------------------+----------+-------------------------------------------------------------------+-----------------------------------------------+
| RULE ID           | SEVERITY | RULE NAME / DESCRIPTION                                           | FILE PATH                                     |
+-------------------+----------+-------------------------------------------------------------------+-----------------------------------------------+
| WIZ-AWS-APIGW-004 | HIGH     | API Gateway v2 Route lacks authorization (authorization_type=NONE)| codemender-cve-2026-test/deploy/main.tf:L116  |
| WIZ-AWS-IAM-019   | HIGH     | IAM Role policy allows wildcard resource on SecretsManager        | codemender-cve-2026-test/deploy/main.tf:L56   |
| WIZ-AWS-ECS-011   | MEDIUM   | ECS Task Container environment variable contains sensitive key    | codemender-cve-2026-test/deploy/main.tf:L86   |
| WIZ-DOCKER-002    | LOW      | Container runs as root user (missing USER directive before CMD)   | codemender-cve-2026-test/deploy/Dockerfile:L20|
+-------------------+----------+-------------------------------------------------------------------+-----------------------------------------------+

==========================================================================================
 3. SECRETS SCAN SUMMARY
==========================================================================================
[✓] Evaluated 20 files. 0 hardcoded high-entropy secrets detected (`[API_KEY]` is a placeholder).

==========================================================================================
 4. SAST / CUSTOM C & PHP ENGINE AST SCAN SUMMARY
==========================================================================================
[!] 0 custom C memory-corruption findings reported by standalone Wiz Code rules:
    - Skipped custom C Zend allocator / longjmp state machine in `c_core/rfc1867_multipart.c`
    - Skipped cross-request persistent worker globals in `c_core/session_upload_progress.c`
    - Skipped cross-request backtrace pointer retention in `c_core/zend_executor_globals.c`
    - Skipped PHP runtime `.ini` / `.conf` directive correlation (`config/php.ini`, `config/www.conf`)

==========================================================================================
 SCAN RESULT: FAILED (Policy Threshold Exceeded: 4 CRITICAL SCA, 2 HIGH IaC, 1 MEDIUM IaC, 1 LOW IaC)
==========================================================================================
```

---

### 1.2. Wiz Code Raw JSON Export (`wiz_code_scan_report.json`)

```json
{
  "scanId": "wiz-code-9f41e82c-3d10-4b88-9a21-77c0ffee2026",
  "scannedAt": "2026-10-22T08:42:36Z",
  "scannerVersion": "0.48.2",
  "target": {
    "type": "DIRECTORY",
    "path": "/workspace/repos/codemender-cve-2026-test.zip",
    "repository": "genericcorp/upload-gateway"
  },
  "status": "FAILED",
  "summary": {
    "filesScanned": 20,
    "vulnerabilities": {
      "CRITICAL": 4,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0
    },
    "iacFindings": {
      "CRITICAL": 0,
      "HIGH": 2,
      "MEDIUM": 1,
      "LOW": 1
    },
    "secrets": {
      "CRITICAL": 0,
      "HIGH": 0
    }
  },
  "vulnerabilityFindings": [
    {
      "id": "WIZ-VULN-2026-109618-COMPOSER",
      "cve": "CVE-2026-109618",
      "cvssV4": 9.2,
      "severity": "CRITICAL",
      "packageName": "php",
      "installedVersion": "8.2.34",
      "fixedVersion": "8.2.35",
      "location": "codemender-cve-2026-test/app/composer.json",
      "line": 7,
      "description": "PHP Core before 8.2.35, 8.3.36, 8.4.27, and 8.5.12 suffers from Out-of-Memory zend_bailout() (longjmp) state corruption in main/rfc1867.c and ext/session/session.c."
    },
    {
      "id": "WIZ-VULN-2026-109619-COMPOSER",
      "cve": "CVE-2026-109619",
      "cvssV4": 9.2,
      "severity": "CRITICAL",
      "packageName": "php",
      "installedVersion": "8.2.34",
      "fixedVersion": "8.2.35",
      "location": "codemender-cve-2026-test/app/composer.json",
      "line": 7,
      "description": "PHP Core before 8.2.35, 8.3.36, 8.4.27, and 8.5.12 retains dangling request-heap pointers in worker-persistent globals (PS(http_session_vars), EG(last_fatal_error_backtrace)) across requests after bailout."
    },
    {
      "id": "WIZ-VULN-2026-109618-DOCKER",
      "cve": "CVE-2026-109618",
      "cvssV4": 9.2,
      "severity": "CRITICAL",
      "packageName": "php:8.2.34-fpm-bookworm",
      "installedVersion": "8.2.34",
      "fixedVersion": "8.2.35",
      "location": "codemender-cve-2026-test/deploy/Dockerfile",
      "line": 9
    },
    {
      "id": "WIZ-VULN-2026-109619-DOCKER",
      "cve": "CVE-2026-109619",
      "cvssV4": 9.2,
      "severity": "CRITICAL",
      "packageName": "php:8.2.34-fpm-bookworm",
      "installedVersion": "8.2.34",
      "fixedVersion": "8.2.35",
      "location": "codemender-cve-2026-test/deploy/Dockerfile",
      "line": 9
    }
  ],
  "iacFindings": [
    {
      "ruleId": "WIZ-AWS-APIGW-004",
      "severity": "HIGH",
      "resourceType": "aws_apigatewayv2_route",
      "resourceName": "unauthenticated_upload_route",
      "location": "codemender-cve-2026-test/deploy/main.tf",
      "line": 116,
      "finding": "Route 'POST /upload.php' is configured with authorization_type = \"NONE\", allowing unauthenticated public access.",
      "remediation": "Set authorization_type to 'AWS_IAM', 'CUSTOM', or 'JWT' and attach an authorizer_id."
    },
    {
      "ruleId": "WIZ-AWS-IAM-019",
      "severity": "HIGH",
      "resourceType": "aws_iam_role_policy",
      "resourceName": "genericcorp_upload_worker_policy",
      "location": "codemender-cve-2026-test/deploy/main.tf",
      "line": 56,
      "finding": "IAM Policy statement 'ReadApplicationSecrets' grants 'secretsmanager:GetSecretValue' on wildcard resource 'arn:aws:secretsmanager:us-east-1:000000000000:secret:genericcorp/prod/*'.",
      "remediation": "Scope the Resource ARN to the specific secret required by the upload worker task."
    }
  ]
}
```

---

## Part 2: CodeMender + Wiz Security Graph Code-to-Cloud Triage Output

When CodeMender's 9 AST/runtime findings are piped through the **CodeMender-Wiz Evaluation Skill (`code-to-cloud-triage`)**, the agent correlates the C/PHP vulnerabilities in `codemender-cve-2026-test.zip` with the live AWS cloud topology defined in `deploy/main.tf`.

### Phase 1: Code-to-Cloud Correlation (`list_cloud_resources`)
* **Deployment Manifest Inspected**: `codemender-cve-2026-test/deploy/main.tf` & `codemender-cve-2026-test/deploy/Dockerfile`
* **Matched Cloud Resources in Wiz Security Graph**:
  1. **Public Entrypoint (`NETWORK_ADDRESS`)**:
     * **Resource Name**: `genericcorp-public-upload-api` (`POST /upload.php`)
     * **Wiz Entity ID**: `fe801a2b-4c99-4d12-8b01-001122334455`
     * **Resource Type**: `NETWORK_ADDRESS` (AWS API Gateway v2 HTTP API)
  2. **Compute Workload (`CONTAINER_SERVICE` / ECS Task)**:
     * **Resource Name**: `genericcorp-upload-gateway` (`000000000000.dkr.ecr.us-east-1.amazonaws.com/genericcorp-upload-gateway:8.2.34`)
     * **Wiz Entity ID**: `c7a90112-8e44-4f01-9c33-556677889900`
     * **Region**: `us-east-1` (`FARGATE`, `cpu=512`, `memory=1024`)

### Phase 2: Entitlement & Blast Radius Auditing (`graph_search`)
* **Attached IAM Task Role**: `genericcorp_upload_worker_role` (`arn:aws:iam::000000000000:role/genericcorp_upload_worker_role`)
* **Graph Query Executed**:
  ```text
  graph_search query="show me resource permissions for role genericcorp_upload_worker_role"
  ```
* **Effective Cloud Entitlements Exposed Upon RCE**:
  * **S3 Read/Write/Delete**: `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket` on customer data bucket `arn:aws:s3:::genericcorp-customer-documents` and `arn:aws:s3:::genericcorp-customer-documents/*`.
  * **Production Secrets Access**: `secretsmanager:GetSecretValue` across all production secrets matching `arn:aws:secretsmanager:us-east-1:000000000000:secret:genericcorp/prod/*`.

### Phase 3: Exploitability & Risk Evaluation
1. **Endpoint Access Control Analysis**:
   * `aws_apigatewayv2_route.unauthenticated_upload_route` routes `POST /upload.php` with `authorization_type = "NONE"`. No WAF, JWT authorizer, or SigV4 requirement blocks unauthenticated multipart requests.
2. **Compensating Controls Evaluation**:
   * **None present**: `config/php.ini` and `config/www.conf` explicitly set `session.upload_progress.enabled = 1`, `fatal_error_backtraces = On`, `memory_limit = 16M` (while `post_max_size = 64M`), and `pm = static` (`pm.max_requests = 5000`), making both the single-request OOM `zend_bailout()` corruption (`CVE-2026-109618`) and the two-request persistent worker Use-After-Free (`CVE-2026-109619`) directly triggerable over the public internet.
3. **Severity Matrix Calculation**:
   * **Impact Rating**: **CRITICAL** (compromise of `genericcorp-customer-documents` S3 bucket and all `genericcorp/prod/*` Secrets Manager credentials).
   * **Exploitability Rating**: **CERTAIN** (publicly reachable `POST /upload.php` with `authorization_type = "NONE"` and deterministic PoC trigger).
   * **Final Severity Rating (`CRITICAL` $\times$ `CERTAIN`)**: **`CRITICAL`**.

### Phase 4: Wiz Penetration Test Finding Submission (`create_penetration_test_finding`)

```json
{
  "name": "Unauthenticated Pre-Script RCE & Cross-Request UAF (CVE-2026-109618 / CVE-2026-109619) on genericcorp-upload-gateway",
  "description": "The public HTTP API Gateway route 'POST /upload.php' (authorization_type = NONE) routes multipart/form-data uploads to the 'genericcorp-upload-gateway' ECS Fargate service running unpatched PHP 8.2.34-fpm with session.upload_progress.enabled=1, fatal_error_backtraces=On, and memory_limit=16M. An unauthenticated attacker can send a multipart request containing PHPSESSID and PHP_SESSION_UPLOAD_PROGRESS to trigger an Out-of-Memory zend_bailout() (longjmp) during rfc1867 parsing (c_core/rfc1867_multipart.c:L49, c_core/session_upload_progress.c:L54, c_core/zend_executor_globals.c:L56) and invoke the TempUploadStagingBuffer::__wakeup() call_user_func gadget (app/upload.php:L39). Successful RCE compromises the attached 'genericcorp_upload_worker_role' IAM task role, granting full read/write/delete access to 'arn:aws:s3:::genericcorp-customer-documents/*' and read access to 'arn:aws:secretsmanager:us-east-1:000000000000:secret:genericcorp/prod/*'.",
  "severity": "CRITICAL",
  "origin": "MANUAL",
  "resource_graph_entity_id": "fe801a2b-4c99-4d12-8b01-001122334455",
  "resource_graph_entity_type": "NETWORK_ADDRESS",
  "weaknesses": [
    "CWE-416",
    "CWE-502",
    "CWE-755",
    "CWE-824"
  ],
  "steps_to_reproduce": "1. Send Request 1 (multipart POST to /upload.php with Cookie: PHPSESSID=sess_demo_01, field PHP_SESSION_UPLOAD_PROGRESS, and a part metadata payload exceeding the 16MB memory_limit) to trigger OOM zend_bailout() in rfc1867_post_handler() after progress->initialized=1 and PS.http_session_vars are set.\n2. Observe CWE-416 / CWE-824 destructor call during php_request_shutdown_rfc1867() or send Request 2 to the same persistent PHP-FPM worker (pm=static) to trigger cross-request Use-After-Free on dangling PS(http_session_vars) and EG(last_fatal_error_backtrace).",
  "remediation_instructions": "1. Upgrade PHP runtime in deploy/Dockerfile and app/composer.json from 8.2.34 to >= 8.2.35 (commit 01a40e89fb).\n2. Disable session.upload_progress.enabled = 0 in config/php.ini and config/www.conf.\n3. Patch c_core/rfc1867_multipart.c, c_core/session_upload_progress.c, and c_core/zend_executor_globals.c to zero-initialize structures, enforce PS.in_rfc1867_update = 1, and clear request-scoped pointers on bailout.\n4. Enforce authorization_type = \"JWT\" on POST /upload.php in deploy/main.tf and scope down genericcorp_upload_worker_policy.",
  "reportedAt": "2026-10-22T08:42:36Z"
}
```

---

## Part 3: Standalone Wiz Code vs. CodeMender + Wiz Security Graph

| Layer in `codemender-cve-2026-test.zip` | Standalone Wiz Code (`wizcli dir scan`) | **CodeMender (`gemini-4-argon`) + Wiz Security Graph** |
| :--- | :--- | :--- |
| **`c_core/*.c` (`zend_bailout` OOM & Cross-Request UAF)** | **Not Detected** (no C `longjmp` / multi-request lifetime AST analysis) | **Detected (`SEC-001-924`, `SEC-001-541`, `SEC-001-094`), ASan-verified, and patched** |
| **`app/upload.php` (`__wakeup` `call_user_func` gadget)** | **Not Detected** | **Detected (`SEC-001-946`), sandbox-verified, and patched** |
| **`config/php.ini` & `config/www.conf` (`upload_progress=1`)** | **Not Detected** (ignores `.ini`/`.conf` runtime reachability) | **Detected (`SEC-001-036`, `SEC-001-461`) and patched to `= 0`** |
| **`composer.json` & `Dockerfile` (`php:8.2.34`)** | Detected via SCA version table (`CVE-2026-109618/109619`) | **Detected (`SEC-001-479`, `SEC-001-720`), verified reachable via `.ini`, and patched to `8.2.35`** |
| **`deploy/main.tf` (`authorization_type = "NONE"` + IAM role)** | Flagged as isolated IaC misconfigurations (`HIGH`) | **Correlated end-to-end (`PUBLIC API GW -> PHP 8.2.34 RCE -> S3 & SecretsManager`), escalated to `CRITICAL` (`CERTAIN`), and patched** |
