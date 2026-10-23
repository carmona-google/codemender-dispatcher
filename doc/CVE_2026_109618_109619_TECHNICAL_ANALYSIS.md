# CodeMender + `gemini-4-argon` Technical Analysis: CVE-2026-109618 & CVE-2026-109619 (`codemender-cve-2026-test.zip`)

## 1. Executive Summary

The `codemender-cve-2026-test.zip` test suite models a multi-layer, polyglot vulnerability chain centered on **CVE-2026-109618** (Out-of-Memory `zend_bailout` State Corruption) and **CVE-2026-109619** (Cross-Request Stale Worker Global State Use-After-Free) in the PHP Core interpreter (`< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`, fixed upstream in commit `01a40e89fb` / `31c0ea7d7ff`, *"Avoid state corruption via bailout"*).

When scanning `codemender-cve-2026-test.zip`, **CodeMender (`cm v0.14.0`) powered by `gemini-4-argon`** discovers, sandbox-verifies, and generates unified `.diff` patches across **all 9 interconnected findings** spanning C engine internals, PHP application gadgets, PHP-FPM runtime configurations, container/dependency manifests, and Terraform cloud infrastructure.

| Finding ID | Vulnerability Type | Severity | File & Line | CVE / CWE Mapping |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-001-924` | `C_OOM_BAILOUT_STATE_CORRUPTION` | **CRITICAL** | `c_core/rfc1867_multipart.c:L49` | CVE-2026-109618 / CWE-416, CWE-755, CWE-824 |
| `SEC-001-541` | `C_CROSS_REQUEST_STALE_GLOBAL_UAF` | **CRITICAL** | `c_core/session_upload_progress.c:L54` | CVE-2026-109618 & CVE-2026-109619 / CWE-416 |
| `SEC-001-094` | `C_CROSS_REQUEST_STALE_GLOBAL_UAF` | **CRITICAL** | `c_core/zend_executor_globals.c:L56` | CVE-2026-109619 / CWE-416 |
| `SEC-001-946` | `PHP_OBJECT_INJECTION_GADGET` | **HIGH** | `app/upload.php:L39` | CVE-2026-109618 / CWE-502 |
| `SEC-001-036` | `PHP_RUNTIME_MISCONFIGURATION` | **HIGH** | `config/php.ini:L34` | CVE-2026-109618 & CVE-2026-109619 |
| `SEC-001-461` | `PHP_RUNTIME_MISCONFIGURATION` | **HIGH** | `config/www.conf:L21` | CVE-2026-109618 & CVE-2026-109619 |
| `SEC-001-479` | `SUPPLY_CHAIN_VULNERABLE_RUNTIME` | **CRITICAL** | `app/composer.json:L7` | CVE-2026-109618 & CVE-2026-109619 |
| `SEC-001-720` | `SUPPLY_CHAIN_VULNERABLE_RUNTIME` | **CRITICAL** | `deploy/Dockerfile:L9` | CVE-2026-109618 & CVE-2026-109619 |
| `SEC-001-623` | `IAC_CLOUD_EXPOSURE_MISCONFIGURATION` | **HIGH** | `deploy/main.tf:L116` | Code-to-Cloud Blast Radius (CWE-284) |

---

## 2. Deep-Dive Technical Analysis of Each Vulnerability

### 2.1. `SEC-001-924` — C OOM Bailout State Corruption (`C_OOM_BAILOUT_STATE_CORRUPTION`)
* **Location**: `codemender-cve-2026-test/c_core/rfc1867_multipart.c` (Line 49)
* **Snippet**: `progress->initialized = 1;`
* **Technical Root Cause**:
  In PHP's Zend Memory Manager (`Zend/zend_alloc.c`), when an engine allocation via `emalloc()` or `erealloc()` exceeds the per-request `memory_limit`, `zend_mm_safe_error()` invokes `zend_bailout()` (`longjmp()`). Unlike standard C `malloc()` which returns `NULL` on failure, `zend_bailout()` immediately unwinds the C call stack back to the top-level request handler (`setjmp`), skipping all remaining statements in the current function.
  In `rfc1867_post_handler()`:
  1. `progress` is allocated via `emalloc(sizeof(php_rfc1867_progress))` without `memset` zero-initialization, and `progress->initialized = 1` is immediately set (`L49`).
  2. `progress->current_file` caches a raw pointer into `file_table` (`L75`), which is then freed during simulated table expansion (`efree(file_table)` at `L79`).
  3. Before `progress->current_file` can be rebound to `new_table`, `emalloc(part_metadata_size)` (`L86`) is called with a user-controlled multipart metadata size.
  4. When `part_metadata_size` triggers an OOM `zend_bailout()`, execution jumps directly to `php_request_shutdown_rfc1867()`, which sees `progress->initialized == 1` and invokes `progress->current_file->destructor(progress->current_file)` (`L118`) on a dangling pointer (CWE-416 Use-After-Free / CWE-824).
* **CodeMender Remediation (`patches/SEC-001-924.diff`)**:
  Zero-initializes `progress` with `memset(progress, 0, sizeof(php_rfc1867_progress))` and defers setting `progress->initialized = 1` until all fallible allocations have completed.

---

### 2.2. `SEC-001-541` — Cross-Request Session Progress Use-After-Free & Pre-Script Unserialization (`C_CROSS_REQUEST_STALE_GLOBAL_UAF`)
* **Location**: `codemender-cve-2026-test/c_core/session_upload_progress.c` (Line 54)
* **Snippet**: `PS.http_session_vars = session_vars;`
* **Technical Root Cause**:
  `php_session_rfc1867_callback()` runs during the **pre-script `rfc1867` multipart upload stage**, *before* PHP compiles or executes the target `.php` script (`RINIT`). Two compounding flaws occur in `php_session_decode_unrestricted()`:
  1. **Cross-Request Dangling Pointer (CVE-2026-109619)**: `PS.http_session_vars` is a **worker-persistent global** (surviving across HTTP requests in a persistent PHP-FPM child process), whereas `session_vars` is allocated in **request-scoped heap memory** (`emalloc`). When `emalloc(part_name_len)` (`L69`) triggers an OOM `zend_bailout()`, the request heap is freed at request teardown, but `PS.session_status` remains `php_session_active` and `PS.http_session_vars` is never cleared. When the next HTTP request hits the same PHP-FPM worker, `php_session_rfc1867_callback()` (`L94-102`) dereferences the freed `PS.http_session_vars->destructor` pointer before `RINIT` can reset session globals.
  2. **Pre-Script Object Deserialization (CVE-2026-109618)**: Prior to upstream commit `01a40e89fb`, `PS.in_rfc1867_update` was not set during multipart progress session decoding (`L60`), allowing the session unserializer to instantiate arbitrary classes and invoke `__wakeup()` / `__destruct()` gadgets before script execution.
* **CodeMender Remediation (`patches/SEC-001-541.diff`)**:
  Enforces `PS.in_rfc1867_update = 1` to block pre-script object unserialization and clears `PS.http_session_vars = NULL` to prevent stale pointer retention across bailout.

---

### 2.3. `SEC-001-094` — Worker-Persistent `EG(last_fatal_error_backtrace)` Use-After-Free (`C_CROSS_REQUEST_STALE_GLOBAL_UAF`)
* **Location**: `codemender-cve-2026-test/c_core/zend_executor_globals.c` (Line 56)
* **Snippet**: `EG.last_fatal_error_backtrace = trace;`
* **Technical Root Cause**:
  When `fatal_error_backtraces = On` is enabled, `zend_record_fatal_error_backtrace()` allocates a `trace` structure on the request heap (`emalloc`) and assigns its address to the worker-persistent Executor Global `EG.last_fatal_error_backtrace` (`L56`) *prior* to allocating `extra_frames = emalloc(trace_alloc_size)` (`L59`). When `emalloc(trace_alloc_size)` triggers an OOM `zend_bailout()` (or when a request terminates via fatal error), `zend_mm_shutdown_request_heap()` frees `trace`, leaving `EG.last_fatal_error_backtrace` as a non-NULL dangling pointer on the persistent worker. On the subsequent request, `zend_early_request_diagnostic_inspect()` (`L71-79`) dereferences `EG.last_fatal_error_backtrace->destructor`, triggering a cross-request Use-After-Free (CWE-416).
* **CodeMender Remediation (`patches/SEC-001-094.diff`)**:
  Prevents storing unvalidated request-scoped trace pointers in `EG.last_fatal_error_backtrace` across fallible allocations and bailout boundaries.

---

### 2.4. `SEC-001-946` — PHP Pre-Script Object Injection Gadget (`PHP_OBJECT_INJECTION_GADGET`)
* **Location**: `codemender-cve-2026-test/app/upload.php` (Line 39)
* **Snippet**: `call_user_func($this->auditHook, $this->stagingPath);`
* **Technical Root Cause**:
  `app/upload.php` overrides `ini_set('memory_limit', '16M')` (`L20`) while accepting large multipart uploads, making OOM bailout deterministically reachable. Furthermore, it defines the `TempUploadStagingBuffer` class whose `__wakeup()` magic method passes attacker-controllable object properties (`$this->auditHook`, `$this->stagingPath`) directly into `call_user_func()`. When combined with unrestricted session decoding in `php_session_rfc1867_callback`, serialized objects in the session store execute arbitrary callables during the upload progress tick.
* **CodeMender Remediation (`patches/SEC-001-946.diff`)**:
  Replaces the `call_user_func()` sink inside `TempUploadStagingBuffer::__wakeup()` with a `BadMethodCallException` guard forbidding pre-script unserialization.

---

### 2.5. `SEC-001-036` & `SEC-001-461` — Vulnerable PHP Runtime & PHP-FPM Pool Configurations (`PHP_RUNTIME_MISCONFIGURATION`)
* **Locations**:
  * `codemender-cve-2026-test/config/php.ini` (Line 34): `session.upload_progress.enabled = 1`
  * `codemender-cve-2026-test/config/www.conf` (Line 21): `php_admin_value[session.upload_progress.enabled] = 1`
* **Technical Root Cause**:
  Both configuration files explicitly enable `session.upload_progress.enabled = 1` and `fatal_error_backtraces = On` / `1` alongside a tight `memory_limit = 16M` (`post_max_size = 64M`) and static persistent PHP-FPM workers (`pm = static`, `pm.max_children = 2`, `pm.max_requests = 5000`). This exact combination is required to reach the pre-script `rfc1867` session callback and reuse the same worker process after an OOM `zend_bailout()`.
* **CodeMender Remediation (`patches/SEC-001-036.diff`, `patches/SEC-001-461.diff`)**:
  Disables `session.upload_progress.enabled = 0` in both `php.ini` and `www.conf`, cutting off the pre-script `rfc1867` attack vector at the configuration layer.

---

### 2.6. `SEC-001-479` & `SEC-001-720` — Unpatched PHP 8.2.34 Runtime Dependency (`SUPPLY_CHAIN_VULNERABLE_RUNTIME`)
* **Locations**:
  * `codemender-cve-2026-test/app/composer.json` (Line 7): `"php": "8.2.34"`
  * `codemender-cve-2026-test/deploy/Dockerfile` (Line 9): `FROM php:8.2.34-fpm-bookworm`
* **Technical Root Cause**:
  Both the application dependency manifest (`composer.json`) and container build manifest (`Dockerfile`) pin **PHP 8.2.34**, which is immediately prior to the patched **PHP 8.2.35** release containing upstream fix `01a40e89fb` (*"Avoid state corruption via bailout"*).
* **CodeMender Remediation (`patches/SEC-001-479.diff`, `patches/SEC-001-720.diff`)**:
  Upgrades the pinned PHP runtime in `composer.json` and `deploy/Dockerfile` from `8.2.34` to `8.2.35`.

---

### 2.7. `SEC-001-623` — Unauthenticated API Gateway Exposure & Over-Privileged Task Role (`IAC_CLOUD_EXPOSURE_MISCONFIGURATION`)
* **Location**: `codemender-cve-2026-test/deploy/main.tf` (Line 116)
* **Snippet**: `authorization_type = "NONE"`
* **Technical Root Cause**:
  In `deploy/main.tf`, the AWS HTTP API Gateway route `POST /upload.php` (`aws_apigatewayv2_route.unauthenticated_upload_route`) is configured with `authorization_type = "NONE"`, exposing the vulnerable multipart upload endpoint to unauthenticated internet traffic. Worse, the backing ECS Fargate task (`genericcorp-upload-gateway:8.2.34`) runs under an IAM task role (`genericcorp_upload_worker_role`) with permissions to read/write/delete objects in `arn:aws:s3:::genericcorp-customer-documents/*` and read production secrets from `arn:aws:secretsmanager:us-east-1:000000000000:secret:genericcorp/prod/*`.
* **CodeMender Remediation (`patches/SEC-001-623.diff`)**:
  Remediates the Terraform route definition from `authorization_type = "NONE"` to `authorization_type = "JWT"`.

---

## 3. Why CodeMender + `gemini-4-argon` Outperforms Traditional AppSec Tools

Traditional security tooling splits analysis into isolated silos—**SAST** (Static Application Security Testing), **SCA** (Software Composition Analysis), and **CSPM / IaC Scanners**. On complex, real-world vulnerabilities like **CVE-2026-109618** and **CVE-2026-109619**, traditional tools fail for several fundamental architectural reasons:

### 3.1. Cross-Layer & Non-Local Control Flow Reasoning (`longjmp` / `setjmp` Lifetimes)
* **Traditional SAST Limitations**: Conventional SAST engines rely on local intraprocedural taint tracking (`source -> sink`) and standard structured control flow graphs. They assume memory allocators return cleanly on failure. In PHP Core's C engine, `emalloc()` does **not** return `NULL` on Out-of-Memory—it calls `zend_bailout()` (`longjmp()`), teleporting execution out of `rfc1867_post_handler()` directly into `php_request_shutdown_rfc1867()`. Furthermore, CVE-2026-109619 spans **two separate HTTP requests** on the same persistent worker process where request-scoped heap memory (`emalloc`) is stored in a worker-persistent global (`PS.http_session_vars` / `EG.last_fatal_error_backtrace`). Traditional SAST tools treat each function or request in isolation and miss cross-request pointer lifetime bugs.
* **CodeMender + `gemini-4-argon` Advantage**: `gemini-4-argon` reasons over **non-local exception paths (`setjmp`/`longjmp`)** and **allocator arena lifetimes (request-scoped vs. worker-persistent globals)**, identifying that assigning a request-heap pointer or setting `progress->initialized = 1` *before* a fallible allocation creates an exploitable dangling pointer on bailout.

### 3.2. Unified Polyglot Correlation Across 5 Stack Layers
* **Traditional Tooling Silos**:
  * A C/C++ static analyzer only sees `c_core/*.c` without knowing whether `session.upload_progress.enabled` is turned on in `php.ini`.
  * A PHP SAST scanner only sees `app/upload.php` without understanding the C-level `rfc1867` pre-script unserialization window.
  * An SCA scanner flags `php:8.2.34` as a low-context CVE advisory among hundreds of unprioritized alerts without knowing if the vulnerable `rfc1867` code path is reachable.
  * An IaC scanner flags `authorization_type = "NONE"` in `main.tf` as a generic informational warning without realizing it exposes an RCE/UAF sink attached to an IAM role with `secretsmanager:GetSecretValue` privileges.
* **CodeMender + `gemini-4-argon` Advantage**: CodeMender correlates all five layers—**C Engine AST + PHP Gadget + INI/FPM Runtime Config + Container/Composer Supply Chain + Terraform Cloud Blast Radius**—into a single coherent attack graph.

### 3.3. Air-Gapped gVisor Sandbox Exploit Verification (`cm verify`) vs. False-Positive Noise
* **Traditional Tooling Limitations**: Traditional SAST and SCA scanners flood engineering teams with unverified theoretical findings (often >60–80% false positives), forcing security engineers to manually triage whether a vulnerability is actually reachable.
* **CodeMender + `gemini-4-argon` Advantage**: CodeMender's **Stage 2 (`cm verify`)** synthesizes targeted, non-weaponized verification harnesses (such as AddressSanitizer + OOM `memory_limit` bailout harnesses and multi-request worker lifecycle monitors) and executes them inside an **air-gapped (`--network=none`, `--cap-drop=ALL`, `pids.max=256`) gVisor (`runsc`) sandbox**, providing deterministic runtime proof (`VERIFIED_EXPLOITABLE`) before a developer ever reviews a ticket.

### 3.4. Automated, Regression-Tested Multi-Layer Remediation (`cm fix`)
* **Traditional Tooling Limitations**: Traditional scanners stop at detection or offer generic text advice ("upgrade dependency" or "sanitize input").
* **CodeMender + `gemini-4-argon` Advantage**: CodeMender's **Stage 3 (`cm fix`)** generates surgical, context-aware unified `.diff` patches across every layer of the stack (`patches/*.diff`)—patching the C memory initialization order, guarding PHP `__wakeup()` deserialization, hardening `php.ini`/`www.conf`, bumping `Dockerfile`/`composer.json` to `8.2.35`, and locking down the Terraform API Gateway route—and re-verifies the patched codebase in the sandbox to guarantee **zero regressions**.

---

## 4. Side-by-Side Comparison Matrix

| Capability | Traditional SAST (e.g., Semgrep / Sonar) | Traditional SCA / Container Scanners | Traditional IaC Scanners (e.g., tfsec / Checkov) | **CodeMender (`cm v0.14.0`) + `gemini-4-argon`** |
| :--- | :--- | :--- | :--- | :--- |
| **Non-Local C `longjmp` / `zend_bailout` State Corruption (CVE-2026-109618)** | Misses (cannot model non-returning allocator `longjmp` into shutdown handler) | Blind to source code | Blind to source code | **Detects, proves with ASan OOM harness, and patches** |
| **Cross-Request Persistent Worker UAF (CVE-2026-109619)** | Misses (analyzes single request/function scope in isolation) | Blind to source code | Blind to source code | **Tracks request-heap vs. worker-global pointer lifetimes across requests** |
| **Config-Dependent Reachability (`php.ini` / `www.conf` + `upload.php`)** | Evaluates `.php` without `.ini` / `.conf` worker state | Ignores runtime `.ini` directives | Ignores application runtime config | **Correlates `session.upload_progress.enabled=1`, `memory_limit=16M`, and `__wakeup()`** |
| **Sandbox PoC Verification (`cm verify`)** | Static heuristics only (high false-positive rate) | Version string matching only | Static HCL rule matching only | **Air-gapped gVisor (`runsc`) sandbox execution with runtime telemetry** |
| **Code-to-Cloud Blast Radius (`main.tf` + ECS IAM Role)** | Blind to cloud infrastructure | Blind to API Gateway & IAM roles | Flags route without knowing backend RCE exploitability | **Links unauthenticated API Gateway route -> PHP 8.2.34 RCE -> S3/SecretsManager IAM role** |
| **Automated Validated Patch Generation (`cm fix`)** | Manual developer remediation required | Version bump PRs only (breaks if unpatched) | Manual HCL edits | **Generates & sandbox-validates unified `.diff` patches across C, PHP, INI, Docker, and Terraform** |
