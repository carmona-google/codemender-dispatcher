# Wiz Code vs. CodeMender (`gemini-4-argon`) Detection & Capabilities Comparison

**Target Archive:** `/workspace/repos/codemender-cve-2026-test.zip`  
**Target Vulnerabilities:** `CVE-2026-109618` (PHP Core OOM `zend_bailout()` State Corruption), `CVE-2026-109619` (Cross-Request Stale Global Pointer UAF), PHP POP Gadget Chain, and Cloud IaC Blast Radius.

---

## 1. Executive Summary

When scanning `codemender-cve-2026-test.zip`, **Wiz Code (`wizcli`)** and **CodeMender (`gemini-4-argon`)** operate at fundamentally different layers of the software and infrastructure stack:

- **Wiz Code (`wizcli`)** is a **manifest, SBOM/SCA, and static IaC policy scanner**. It matches known package version strings (`"php": "8.2.34"`, `FROM php:8.2.34-fpm-bookworm`) against vulnerability databases and evaluates static Terraform HCL rules. However, it is completely blind to custom C memory-management bugs, non-local `longjmp` (`zend_bailout()`) control-flow bypasses, PHP object-injection POP gadgets, and cross-file `.ini`/`.conf` runtime exploit preconditions.
- **CodeMender (`gemini-4-argon`)** performs **deep cross-file semantic reasoning across C, PHP, runtime configs, and IaC**, compiles and detonates a multi-request PoC exploit inside an **air-gapped verification sandbox (`cm verify`)**, and authors **9 surgical, regression-tested `.diff` patches (`cm fix`)** across every layer of the stack.

---

## 2. Side-by-Side Detection Matrix (`codemender-cve-2026-test.zip`)

| Target File in Archive | Vulnerability / Security Weakness | Wiz Code (`wizcli`) | Semgrep OSS (SAST) | CodeMender (`gemini-4-argon`) | Technical Reason for the Difference |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **`c_core/rfc1867_multipart.c`** (`:L101`) | **CVE-2026-109618 (Root Cause #1)**: OOM `zend_bailout()` (`longjmp`) skips cleanup of `SG(rfc1867_uploaded_files)` | ❌ **MISSED** | ❌ **MISSED** | ✅ **DETECTED, VERIFIED & PATCHED** | Requires tracing non-local C jumps (`setjmp`/`longjmp`) across custom `emalloc()`/`efree()` arena lifetimes. |
| **`c_core/session_upload_progress.c`** (`:L94`) | **CVE-2026-109618 (Root Cause #2)**: `progress->in_rfc1867_update` stuck `true` + unsafe class instantiation in RFC1867 callback | ❌ **MISSED** | ❌ **MISSED** | ✅ **DETECTED, VERIFIED & PATCHED** | Requires inter-procedural state-machine analysis across C structs and PHP session deserialization internals. |
| **`c_core/zend_executor_globals.c`** (`:L66`) | **CVE-2026-109619 (Root Cause)**: Cross-request Use-After-Free (UAF) via stale `PS(http_session_vars)` & `EG(last_fatal_error_backtrace)` pointers | ❌ **MISSED** | ❌ **MISSED** | ✅ **DETECTED, VERIFIED & PATCHED** | Requires modeling PHP-FPM's multi-request worker lifecycle (`RSHUTDOWN` vs. worker-persistent globals across requests). |
| **`app/upload.php`** (`:L33`) | **PHP Object Injection POP Gadget**: `TempUploadStagingBuffer::__wakeup()` invoking `call_user_func($this->auditHook, ...)` | ❌ **MISSED** | ✅ **DETECTED** *(Pattern)* | ✅ **DETECTED, VERIFIED & PATCHED** | Wiz Code does not perform PHP AST POP-gadget analysis; CodeMender links the `__wakeup()` gadget directly to the C RFC1867 deserialization sink. |
| **`config/php.ini`** (`:L20`) | **Exploit-Chain Preconditions**: `session.upload_progress.enabled = On`, `fatal_error_backtraces = On`, tight `memory_limit = 64M` | ❌ **MISSED** | ❌ **MISSED** | ✅ **DETECTED, VERIFIED & PATCHED** | `.ini` directives appear benign in isolation; only `gemini-4-argon` correlates them as the exact runtime triggers required by CVE-2026-109618/109619. |
| **`config/www.conf`** (`:L24`) | **Cross-Request UAF Multiplier**: `pm.max_requests = 500` keeping corrupted FPM worker alive for 499 subsequent requests | ❌ **MISSED** | ❌ **MISSED** | ✅ **DETECTED, VERIFIED & PATCHED** | Standard FPM pool tuning—not a static rule violation unless correlated with a cross-request heap corruption bug. |
| **`app/composer.json`** (`:L7`) | **SCA Version Match**: `"php": "8.2.34"` (< `8.2.35`) | ✅ **DETECTED** *(SCA)* | ❌ **MISSED** | ✅ **DETECTED, VERIFIED & PATCHED** | Both Wiz Code and CodeMender flag the vulnerable PHP runtime constraint. |
| **`deploy/Dockerfile`** (`:L9`) | **Container Base Image Match**: `FROM php:8.2.34-fpm-bookworm` | ✅ **DETECTED** *(Container SCA)* | ⚠️ **PARTIAL** *(Missing USER)* | ✅ **DETECTED, VERIFIED & PATCHED** | Both Wiz Code and CodeMender flag the vulnerable `8.2.34-fpm-bookworm` image tag and upgrade it to `8.2.35-fpm-bookworm`. |
| **`deploy/main.tf`** (`:L56`, `:L116`) | **Cloud IaC Misconfigurations**: Unauthenticated `POST /upload.php` (`authorization_type = "NONE"`) + wildcard `secretsmanager:GetSecretValue` (`genericcorp/prod/*`) | ✅ **DETECTED** *(IaC Policy)* | ✅ **DETECTED** *(IaC Rules)* | ✅ **DETECTED, VERIFIED & PATCHED** | Wiz flags standalone Terraform rules; CodeMender connects them to the full **Code-to-Cloud kill chain** (public API Gateway $\rightarrow$ PHP-FPM RCE $\rightarrow$ AWS Secrets Manager exfiltration). |

---

## 3. Deep-Dive: The 4 Architectural Differences

```
+-----------------------------------------------------------------------------------+
|                        WIZ CODE (Static SCA + IaC Scanner)                        |
|                                                                                   |
|  [composer.json] ---> Matches "8.2.34" in CVE DB ---> Alert: "Upgrade to 8.2.35"  |
|  [Dockerfile]    ---> Matches "8.2.34" in CVE DB ---> Alert: "Upgrade to 8.2.35"  |
|  [main.tf]       ---> Matches HCL policy rules   ---> Alert: "Fix IAM & APIGW"    |
|  [c_core/*.c]    ---> (Blind to C longjmp / UAF memory lifecycle)                 |
|  [config/*.ini]  ---> (Blind to runtime configuration exploitability)             |
+-----------------------------------------------------------------------------------+
                                         vs.
+-----------------------------------------------------------------------------------+
|                    CODEMENDER + GEMINI-4-ARGON (Agentic SAST/PoC)                 |
|                                                                                   |
|  1. Cross-Layer Semantic Graph (cm find):                                         |
|     [main.tf: APIGW NONE] --> [upload.php: __wakeup()] --> [php.ini: 64M + On]    |
|     --> [rfc1867_multipart.c: OOM longjmp] --> [zend_executor_globals.c: UAF]     |
|                                                                                   |
|  2. Air-Gapped Sandbox Detonation (cm verify):                                    |
|     Compiles C harness with ASan/UBSan (`-fsanitize=address,undefined`),          |
|     triggers Request #1 OOM bailout + Request #2 worker reuse, and proves         |
|     cross-request memory leak (`SECRET_ADMIN_SESSION_TOKEN_9941`, Exit Code 42).  |
|                                                                                   |
|  3. Surgical Multi-Layer Patching (cm fix):                                       |
|     Authors & regression-tests 9 unified `.diff` patches across C, PHP, INI,      |
|     FPM conf, Composer, Dockerfile, and Terraform—verified with 0 regressions.    |
+-----------------------------------------------------------------------------------+
```

### 3.1 Symptom (Version String) vs. Root Cause (C Memory & Control Flow)
- **Wiz Code** relies on **Software Composition Analysis (SCA)**. It inspects [`app/composer.json`](file:///workspace/codemender_dispatcher/doc/wiz_code_scan_report.json#L1-L18) and [`deploy/Dockerfile`](file:///workspace/codemender_dispatcher/doc/wiz_code_scan_report.json#L19-L34) for the literal version string `8.2.34` and looks it up in a vulnerability feed. If you are auditing first-party C/C++ code, maintaining an internal fork of PHP (`c_core/*.c`), or running a patched/backported binary where the version banner hasn't changed, **Wiz Code detects 0 vulnerabilities in the source code**.
- **CodeMender (`gemini-4-argon`)** inspects the C source code directly:
  - In `c_core/rfc1867_multipart.c`, it traces `emalloc(content_length)` and recognizes that when `content_length` exceeds `memory_limit`, `zend_bailout()` executes a non-local `longjmp` that teleports execution out of `rfc1867_post_handler()` before `zend_hash_destroy(SG(rfc1867_uploaded_files))` is reached.
  - In `c_core/zend_executor_globals.c`, it identifies that `php_request_shutdown_vulnerable()` frees the per-request arena without zeroing `PS(http_session_vars)` or `EG(last_fatal_error_backtrace)`.

### 3.2 Cross-Layer Exploitability Correlation (`php.ini` + `www.conf` + `upload.php`)
- **Wiz Code** cannot tell a security team whether `CVE-2026-109618` or `CVE-2026-109619` is actually **exploitable** in their specific environment, because it does not correlate `.ini` or `.conf` files with C/PHP code paths.
- **CodeMender** links four distinct configuration and code layers to prove reachability:
  1. `config/php.ini`: Confirms `session.upload_progress.enabled = On` and `fatal_error_backtraces = On` are active, and `memory_limit = 64M` < `post_max_size = 128M` (creating the exact 64MB–128MB OOM bailout window).
  2. `app/upload.php`: Identifies the `TempUploadStagingBuffer::__wakeup()` POP gadget that executes `call_user_func($this->auditHook, $this->stagingPath)` during pre-script session deserialization.
  3. `config/www.conf`: Identifies `pm.max_requests = 500`, proving that a single PHP-FPM worker process handles 500 sequential HTTP requests—allowing Request $N+1$ (attacker hitting `app/status.php`) to read the dangling pointers left by Request $N$'s OOM bailout.

### 3.3 Static Alert vs. Air-Gapped Sandbox Proof (`cm verify`)
- **Wiz Code** produces a static JSON/CLI alert that requires manual triage by a security engineer to determine if the finding is a false positive.
- **CodeMender (`cm verify`)** eliminates false positives by automatically building and executing the exploit inside an isolated, network-disabled (`--network=none`) sandbox:
  - Compiles `c_core/main_harness.c`, `rfc1867_multipart.c`, `session_upload_progress.c`, and `zend_executor_globals.c` with AddressSanitizer/UBSan.
  - Executes Request #1 (victim session + OOM multipart upload triggering `zend_bailout()`) followed by Request #2 (attacker request on the same worker PID).
  - Records concrete exploit telemetry: `leak_detected=true`, `leaked_marker="SECRET_ADMIN_SESSION_TOKEN_9941"`, and exit code `42`.

### 3.4 Text Advisory vs. Multi-Layer Validated `.diff` Patches (`cm fix`)
- **Wiz Code** tells you *what version to upgrade to* (`Upgrade php to 8.2.35`), which only helps if an upstream package is available and does not fix custom C code, application POP gadgets, or `.ini` runtime settings.
- **CodeMender (`cm fix`)** generates **9 ready-to-apply unified `.diff` patches** and re-runs the sandbox verification harness against the patched code to guarantee zero regressions:
  1. **C Runtime Fixes (`SEC-FIND-001`, `002`, `003`)**: Wraps multipart upload and session progress updates in `zend_try { ... } zend_catch { ... } zend_end_try()` blocks, enforces `allowed_classes = false` during `in_rfc1867_update`, and unconditionally zeroes `PS(http_session_vars)` and `EG(last_fatal_error_backtrace)` during `RSHUTDOWN`.
  2. **PHP Application Fix (`SEC-FIND-004`)**: Removes the dangerous `__wakeup()` magic method and `call_user_func()` sink in `app/upload.php`.
  3. **Immediate Runtime Mitigations (`SEC-FIND-005`, `006`)**: Sets `session.upload_progress.enabled = Off` and `fatal_error_backtraces = Off` in `config/php.ini` and hardens `config/www.conf`—providing a zero-downtime hotfix even before the PHP binary is upgraded.
  4. **Supply-Chain & Container Upgrades (`SEC-FIND-007`, `008`)**: Updates `app/composer.json` and `deploy/Dockerfile` to PHP `8.2.35`.
  5. **Cloud IaC Hardening (`SEC-FIND-009`)**: Enforces `authorization_type = "AWS_IAM"` on `POST /upload.php` and scopes the IAM Secrets Manager policy ARN in `deploy/main.tf`.

---

## 4. How Both Tools Complement Each Other via `cm import`

With the **Import from External Tools (`cm import` / `cm report import`)** workflow in `codemender_dispatcher`:
1. You can ingest **Wiz Code** (`doc/wiz_code_scan_report.json`) or **Semgrep** (`doc/semgrep_scan_report.json`) JSON reports directly into CodeMender.
2. CodeMender normalizes the external SCA/SAST/IaC alerts into candidate findings (`IMP-...`), correlates them with its own deep AST/memory findings (`SEC-FIND-...`), verifies exploitability in the air-gapped sandbox (`cm verify`), and generates validated `.diff` patches (`cm fix`) for every finding.
