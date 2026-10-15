# CodeMender Dispatcher: Enterprise SDLC & Security Audit Report

**Date:** 2026-08-31  
**Target Codebase:** `codemender-dispatcher`  
**Audit Scope:** Source Code (`src/`), Infrastructure as Code (`terraform/`), Kubernetes Manifests (`k8s/`), Dockerfiles (`docker/`), Scripts (`demo/`), and Documentation (`doc/`, `README.md`).

---

## 1. Executive Summary

This audit evaluates the **CodeMender Remote Dispatcher & Execution Sandbox (v2.1)** against Software Development Life Cycle (SDLC) standards, security baselines, and production readiness guidelines.

The architecture strictly implements the **Split Execution Model** and robust physical sandboxing (gVisor on GKE Autopilot with Cilium NetworkPolicies). Static code analysis identified and remediated the following areas prior to enterprise rollout:
1. **Confidentiality & PII Exposure:** Generalized GCP Project IDs in demonstration scripts.
2. **Secrets Hygiene:** Environment-enforced HMAC state signing and Flask session keys in source code.
3. **Resource Lifecycle Management:** Context-managed SQLite database handles preventing file descriptor leaks under concurrency.
4. **IaC & Manifest Portability:** Parameterized project domains across base Kubernetes and Terraform manifests.
5. **Operational Guardrails:** Explicit production environment guards for local AST fallback simulation.
6. **Documentation Sanitization:** Generic relative paths across developer quickstart guides.

---

## 2. Findings Matrix

| Finding ID | Category | Severity | Component / File | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Confidentiality / PII | 🔴 **High** | `demo/itsm_demo_subscriber.py` | Specific GCP Project ID (`[PROJECT_ID]`) hardcoded in constructor default. |
| **SEC-02** | Secrets Management | 🔴 **High** | `src/config.py`, `src/core/state_packager.py` | Hardcoded fallback HMAC keys and session secrets embedded in source code. |
| **RES-01** | Resource Management | 🟡 **Medium** | `src/models/scan_job.py` | SQLite connection handle leak due to missing explicit connection closure. |
| **IAC-01** | IaC Portability | 🟡 **Medium** | `k8s/base/rbac.yaml`, `src/core/k8s_engine.py` | Base Kubernetes manifests contain static project references (`codemender-prod`). |
| **REL-01** | Production Reliability | 🟡 **Medium** | `src/core/docker_engine.py`, `src/core/k8s_engine.py` | Silent mock fallback active by default without production environment guards. |
| **DOC-01** | Documentation Hygiene | 🟢 **Low** | `README.md`, `DEPLOYMENT_ARGOLIS.md` | Absolute developer workstation paths present in setup commands. |
| **NET-01** | Network Configuration | 🟢 **Low** | `src/config.py` | Hardcoded default Redis connection strings (`redis://localhost:6379/0`). |

---

## 3. Detailed Findings & Remediation Plans

### 3.1 [SEC-01] Hardcoded Project ID in Demo Scripts
- **Severity:** 🔴 High
- **Affected File:** `demo/itsm_demo_subscriber.py`
- **Problem:**
  Hardcoded specific GCP project ID `[PROJECT_ID]` in constructor defaults.
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
- **Affected Files:** `src/config.py`, `src/core/state_packager.py`
- **Remediation:**
  Enforce fail-fast behavior in production mode and dynamically generate high-entropy random keys for ephemeral development.

---

### 3.3 [RES-01] SQLite Database Connection Handle Leak
- **Severity:** 🟡 Medium
- **Affected File:** `src/models/scan_job.py`
- **Remediation:**
  Refactored `_get_connection` into a generator context manager using `contextlib` with explicit `conn.close()` in `finally`.

---

### 3.4 [IAC-01] Hardcoded Project Domains in Kubernetes & IaC Manifests
- **Severity:** 🟡 Medium
- **Affected Files:** `k8s/base/rbac.yaml`, `k8s/base/gvisor-job.yaml`, `src/core/k8s_engine.py`, `terraform/variables.tf`
- **Remediation:**
  Removed environment-specific annotations from `k8s/base/` and parameterized Terraform variables.

---

### 3.5 [REL-01] Silent Fallback Masking Infrastructure Failures
- **Severity:** 🟡 Medium
- **Affected Files:** `src/core/docker_engine.py`, `src/core/k8s_engine.py`
- **Remediation:**
  Disabled mock fallback by default when `FLASK_ENV == "production"`, and emit explicit warning logs whenever fallback mode executes.

---

### 3.6 [DOC-01] Developer Workstation Paths in Documentation
- **Severity:** 🟢 Low
- **Affected Files:** `README.md`, `DEPLOYMENT_ARGOLIS.md`
- **Remediation:**
  Sanitized all paths to relative project directories (`cd codemender-dispatcher`).
