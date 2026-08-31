# CodeMender Dispatcher: Google SDLC & Security Audit Report

**Date:** 2026-08-31  
**Target Codebase:** `/google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher`  
**Audit Scope:** Source Code (`src/`), Infrastructure as Code (`terraform/`), Kubernetes Manifests (`k8s/`), Dockerfiles (`docker/`), Scripts (`demo/`), and Documentation (`doc/`, `README.md`).

---

## 1. Executive Summary

This audit evaluates the **CodeMender Remote Dispatcher & Execution Sandbox (v2.0)** against Google's Software Development Life Cycle (SDLC) standards, security baselines, and production readiness guidelines.

The architecture strictly implements the **Split Execution Model** and robust physical sandboxing (gVisor on GKE Autopilot with Cilium NetworkPolicies). However, static code analysis identified several areas requiring remediation prior to broad enterprise rollout:
1. **Confidentiality & PII Exposure:** Hardcoded internal/personal GCP Project IDs in demonstration scripts.
2. **Secrets Hygiene:** Static fallback strings used for HMAC state signing and Flask session keys in source code.
3. **Resource Lifecycle Management:** Unclosed SQLite database handles resulting in file descriptor leaks under concurrency.
4. **IaC & Manifest Portability:** Hardcoded project domains (`codemender-prod`) in base Kubernetes manifests.
5. **Operational Guardrails:** Silent fallback to local AST simulation that could mask production infrastructure outages.
6. **Documentation Sanitization:** Workstation-specific Cloudtop paths referenced in developer quickstart guides.

---

## 2. Findings Matrix

| Finding ID | Category | Severity | Component / File | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Confidentiality / PII | 🔴 **High** | `demo/itsm_demo_subscriber.py` | Personal GCP Project ID (`carmona-codelab-ai`) hardcoded in constructor default. |
| **SEC-02** | Secrets Management | 🔴 **High** | `src/config.py`, `src/core/state_packager.py` | Hardcoded fallback HMAC keys and session secrets embedded in source code. |
| **RES-01** | Resource Management | 🟡 **Medium** | `src/models/scan_job.py` | SQLite connection handle leak due to missing explicit connection closure. |
| **IAC-01** | IaC Portability | 🟡 **Medium** | `k8s/base/rbac.yaml`, `src/core/k8s_engine.py` | Base Kubernetes manifests contain static project references (`codemender-prod`). |
| **REL-01** | Production Reliability | 🟡 **Medium** | `src/core/docker_engine.py`, `src/core/k8s_engine.py` | Silent mock fallback active by default without production environment guards. |
| **DOC-01** | Documentation Hygiene | 🟢 **Low** | `README.md`, `DEPLOYMENT_ARGOLIS.md` | Absolute developer workstation paths present in setup commands. |
| **NET-01** | Network Configuration | 🟢 **Low** | `src/config.py` | Hardcoded default Redis connection strings (`redis://localhost:6379/0`). |

---

## 3. Detailed Findings & Remediation Plans

### 3.1 [SEC-01] Hardcoded Personal Project ID in Demo Scripts
- **Severity:** 🔴 High
- **Affected File:** [`demo/itsm_demo_subscriber.py:L19`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/demo/itsm_demo_subscriber.py#L19)
- **Problem:**
  Line 19 hardcodes the personal GCP project ID `carmona-codelab-ai`:
  ```python
  def __init__(self, project_id: str = "carmona-codelab-ai", topic_id: str = "codemender-security-events"):
  ```
- **Risk:**
  Exposes internal account/project identifiers in version control, and causes execution failures when other engineers or automated CI runners execute the script without modifying source code.
- **Remediation:**
  Read dynamically from `os.environ.get("GCP_PROJECT_ID")` and provide CLI argument overrides:
  ```python
  def __init__(self, project_id: Optional[str] = None, topic_id: Optional[str] = None):
      self.project_id = project_id or os.environ.get("GCP_PROJECT_ID", "generic-security-project")
      self.topic_id = topic_id or os.environ.get("PUBSUB_TOPIC_ID", "codemender-security-events")
  ```

---

### 3.2 [SEC-02] Hardcoded Fallback Secrets & Weak Cryptographic Defaults
- **Severity:** 🔴 High
- **Affected Files:**
  - [`src/config.py:L12`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/src/config.py#L12)
  - [`src/core/state_packager.py:L15`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/src/core/state_packager.py#L15)
- **Problem:**
  Static fallback strings are hardcoded into class definitions:
  ```python
  # src/config.py
  SECRET_KEY = os.environ.get("SECRET_KEY", "codemender-dev-secret-key-change-in-prod")

  # src/core/state_packager.py
  def __init__(self, signing_secret: str = "codemender-default-state-key-change-in-prod"):
  ```
- **Risk:**
  If an operator deploys to staging or production without configuring environment variables, predictable signing keys allow attackers to forge HMAC-SHA256 signatures for `~/.codemender` state packages or hijack web session cookies.
- **Remediation:**
  Enforce fail-fast behavior in production mode and dynamically generate high-entropy random keys for ephemeral development:
  ```python
  import os
  import secrets

  class Config:
      _env_secret = os.environ.get("SECRET_KEY")
      if not _env_secret:
          if os.environ.get("FLASK_ENV") == "production":
              raise RuntimeError("CRITICAL: SECRET_KEY environment variable is required in production.")
          SECRET_KEY = secrets.token_hex(32)
      else:
          SECRET_KEY = _env_secret
  ```

---

### 3.3 [RES-01] SQLite Database Connection Handle Leak
- **Severity:** 🟡 Medium
- **Affected File:** [`src/models/scan_job.py:L89-L96`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/src/models/scan_job.py#L89-L96)
- **Problem:**
  In Python's `sqlite3` module, the context manager syntax `with conn:` only manages the database transaction (`COMMIT` / `ROLLBACK`). It **does not close** the underlying connection socket.
  ```python
  def _get_connection(self) -> sqlite3.Connection:
      conn = sqlite3.connect(self.db_path)
      conn.row_factory = sqlite3.Row
      return conn
  ```
- **Risk:**
  Under high concurrent scan volume or long-running worker processes, connections accumulate, exhausting file descriptors and causing `ResourceWarning: unclosed database <sqlite3.Connection>`.
- **Remediation:**
  Refactor `_get_connection` into a generator context manager using `contextlib`:
  ```python
  from contextlib import contextmanager

  class DatabaseManager:
      @contextmanager
      def _get_connection(self):
          if self.db_path != ":memory:":
              db_dir = os.path.dirname(os.path.abspath(self.db_path))
              if db_dir:
                  os.makedirs(db_dir, exist_ok=True)
          conn = sqlite3.connect(self.db_path)
          conn.row_factory = sqlite3.Row
          try:
              yield conn
          finally:
              conn.close()
  ```

---

### 3.4 [IAC-01] Hardcoded Project Domains in Kubernetes & IaC Manifests
- **Severity:** 🟡 Medium
- **Affected Files:**
  - [`k8s/base/rbac.yaml:L7`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/k8s/base/rbac.yaml#L7)
  - [`k8s/base/gvisor-job.yaml:L27`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/k8s/base/gvisor-job.yaml#L27)
  - [`src/core/k8s_engine.py:L49`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/src/core/k8s_engine.py#L49)
  - [`terraform/variables.tf:L4`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/terraform/variables.tf#L4)
- **Problem:**
  Base Kubernetes manifests hardcode the static project `codemender-prod`:
  ```yaml
  annotations:
    iam.gke.io/gcp-service-account: codemender-executor-sa@codemender-prod.iam.gserviceaccount.com
  ```
- **Risk:**
  Breaks Kustomize multi-environment workflows (dev, staging, prod) and creates deployment failure on non-prod clusters.
- **Remediation:**
  Remove environment-specific annotations from `k8s/base/` and manage project identity mapping strictly in `k8s/overlays/gke-autopilot/kustomization.yaml`. In `src/core/k8s_engine.py`, resolve container images dynamically via configuration.

---

### 3.5 [REL-01] Silent Fallback Masking Infrastructure Failures
- **Severity:** 🟡 Medium
- **Affected Files:**
  - [`src/core/docker_engine.py:L52`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/src/core/docker_engine.py#L52)
  - [`src/core/k8s_engine.py:L153`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/src/core/k8s_engine.py#L153)
- **Problem:**
  When `ENABLE_MOCK_FALLBACK` is enabled, any failure to connect to Docker or the Kubernetes cluster triggers an automatic, silent fallback to local AST simulation.
- **Risk:**
  In a production environment, this can conceal Docker daemon crashes, network partition errors, or GKE authentication failures by silently reporting synthetic scan successes.
- **Remediation:**
  Disable mock fallback by default when `FLASK_ENV == "production"`, and emit explicit warning logs whenever fallback mode executes.

---

### 3.6 [DOC-01] Developer Workstation Paths in Documentation
- **Severity:** 🟢 Low
- **Affected Files:**
  - [`README.md:L110`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/README.md#L110)
  - [`DEPLOYMENT_ARGOLIS.md:L72, L127, L162`](file:///google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher/DEPLOYMENT_ARGOLIS.md#L72)
- **Problem:**
  Documentation includes hardcoded paths referencing a specific Google Cloudtop workspace (`/google/src/cloud/carmona/codemender_demo/...`).
- **Remediation:**
  Sanitize all paths to relative project directories (e.g., `cd codemender_dispatcher/terraform`).

---

## 4. Implementation & Validation Roadmap

1. **Step 1: Core Python & Security Hardening**
   - Update `src/config.py` and `src/core/state_packager.py` with fail-fast key validation.
   - Update `src/models/scan_job.py` with `@contextmanager` connection management.
   - Update `demo/itsm_demo_subscriber.py` to use dynamic environment parameters.

2. **Step 2: Manifest & Documentation Sanitization**
   - Sanitize `k8s/base/` manifests and `terraform/variables.tf`.
   - Update `README.md` and `DEPLOYMENT_ARGOLIS.md` with clean relative paths.

3. **Step 3: Verification & Test Execution**
   - Execute full test suite (`python3 -m unittest discover -s tests -p "test_*.py"`).
   - Verify that all 17 tests pass with zero warnings or connection leaks.

4. **Step 4: Git Repository Synchronization**
   - Commit sanitized changes to topic branch `feature/codemender-dispatcher-v2`.
   - Push to both GitHub repositories (`carmona-google` and `cloud-gtm`).
