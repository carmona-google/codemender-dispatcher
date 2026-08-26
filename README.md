# CodeMender Remote Dispatcher & Execution Sandbox (v2.0)

A unified, enterprise-hardened remote-dispatcher system orchestrating the CodeMender CLI within isolated, ephemeral containers on local or customer-managed infrastructure.

---

## 🚀 Key Value Proposition: The Split Execution Model (v2.0)

CodeMender strictly decouples AI cognitive reasoning from physical code execution:
- **Reasoning Engine (Google Cloud)**: Gemini Enterprise Agent Platform / Interactions API. Communicates over outbound-only TLS gRPC streams, receiving only isolated AST metadata, traces, and targeted snippets (Zero Source Code Exfiltration).
- **Dispatcher-Mediated Agent Loop**: The cloud gRPC connection is maintained strictly on the Dispatcher control plane. Ephemeral execution sandboxes operate with **zero network sockets** during PoC exploit detonation.
- **Physical Sandboxes (Local / Customer VPC)**: Confined within ephemeral containers with dropped Linux capabilities (`--cap-drop=ALL`), PID limits (`pids.max=256`), memory cgroups, and gVisor kernel-level isolation.

---

## 🛡️ Key Architectural Enhancements (v2.0)

1. **Two-Phase Container Network Isolation (Phase 4)**:
   - *Phase 1 (Staging & Dependency Fetch)*: Restricted egress to VPC Artifact Registry mirrors via Private Service Connect.
   - *Phase 2 (Air-Gapped PoC Detonation)*: Network namespace severed (`--network=none`), blocking all SSRF, reverse shells, and exfiltration attempts.
2. **GKE Autopilot & gVisor Batch Sandboxing (Phase 4)**:
   - `K8sJobOrchestrator` provisions ephemeral `batch/v1.Job` pods with `runtimeClassName: gvisor`, `seccompProfile: RuntimeDefault`, `runAsNonRoot: true`, and memory-backed tmpfs mounts for `/run/codemender/state`.
3. **Cilium Default-Deny NetworkPolicies & RBAC (Phase 4)**:
   - Blocks lateral movements to RFC1918 subnets and cloud metadata services (`169.254.169.254`).
4. **Control-Plane State Journaling & Signing**:
   - `StatePackager` provides HMAC-SHA256 signature verification for multi-turn session state across distributed pipeline runs.
5. **Context-Aware Semantic Anonymization & Shannon Entropy**:
   - High-entropy secret scanner + AST taint analysis preserves vulnerability syntax (SQL templates, command injection) while masking confidential literals.
6. **Multi-Tier Resource Quotas & Watchdog Controller**:
   - Enforces `pids_limit=256`, 2GB memory ceiling, and a 60-second execution Watchdog timer with SIGKILL escalation.
7. **CI/CD Automation & In-Flight Debouncing (Phase 3)**:
   - Automated PR review comments and companion remediation PR creation (`GitHubClient`).
   - Cancels stale in-flight scans on new PR commits and captures human review feedback (`REMEDIATION_PR_MERGED`, `REMEDIATION_PR_REJECTED`).
8. **Decoupled ITSM & Cryptographic Provenance (Phase 4)**:
   - Emits immutable SHA-256 finding provenance digests (`SHA256(Repo + CommitSHA + FindingID)`) to Google Cloud Pub/Sub topics with Dead-Letter Queues.

---

## 📁 Repository Structure

```
codemender_dispatcher/
├── docker/                     # Sandbox Execution Engine Dockerfiles
│   ├── base/                   # Base hardened container (cm-linux + git)
│   ├── python/                 # Python 3.11 runtime flavor
│   ├── node/                   # Node.js 20 LTS runtime flavor
│   ├── go/                     # Go 1.22 runtime flavor
│   └── polyglot/               # Unified polyglot container (all runtimes)
├── k8s/                        # Phase 4: Kubernetes & GKE Autopilot Manifests
│   ├── base/
│   │   ├── namespace.yaml      # codemender-executors isolated namespace
│   │   ├── network-policy.yaml # Cilium default-deny NetworkPolicies
│   │   ├── rbac.yaml           # Least-privileged ServiceAccount & RoleBinding
│   │   ├── gvisor-job.yaml     # Autopilot gVisor batch Job template
│   │   └── kustomization.yaml  # Base Kustomize configuration
│   └── overlays/
│       └── gke-autopilot/      # Production GKE Autopilot overlay
├── terraform/                  # Phase 4: Infrastructure as Code
│   ├── main.tf
│   ├── gke_autopilot.tf        # Private GKE Autopilot with Datapath V2
│   ├── iam_wif.tf              # Workload Identity Federation & Scoped IAM
│   ├── pubsub.tf               # Cloud Pub/Sub Topic for Decoupled ITSM
│   └── variables.tf
├── src/                        # Dispatcher Control Plane & Web Portal
│   ├── app.py                  # Flask Application Factory
│   ├── config.py               # Configuration & Settings
│   ├── celery_app.py           # Celery Task Queue Configuration
│   ├── api/                    # REST Endpoints
│   │   ├── scans.py            # Codebase Upload & Status APIs
│   │   ├── webhooks.py         # GitHub PR Webhooks & Auto-PR Flow
│   │   └── events.py           # Server-Sent Events (SSE) Live Log Streaming
│   ├── web/                    # Interactive Web Portal Console
│   │   ├── routes.py           # UI Routes
│   │   └── templates/          # Jinja2 + Tailwind HTML Templates
│   ├── core/                   # Orchestration & Persistence
│   │   ├── scanner.py          # Dynamic AST & Static Vulnerability Scanner
│   │   ├── github_client.py    # Automated PR Comments & Remediation PRs
│   │   ├── state_packager.py   # Cryptographic State Package Signer
│   │   ├── k8s_engine.py       # Phase 4: GKE Autopilot gVisor Batch Provisioner
│   │   ├── docker_engine.py    # Ephemeral Container Provisioner + Watchdog
│   │   ├── orchestrator.py     # End-to-End Scan Coordinator
│   │   └── persistence.py      # Session Hydration & Artifact Extractor
│   ├── itsm/                   # Decoupled ITSM Integration
│   │   ├── schemas.py          # Provenance-Enabled Event Schemas
│   │   ├── dlp_filter.py       # Shannon Entropy & DLP Pre-Sanitizer
│   │   └── pubsub_publisher.py # Google Cloud Pub/Sub Publisher
│   └── models/                 # Database Layer
│       └── scan_job.py         # Thread-safe SQLite / PostgreSQL DAO
├── tests/                      # Test Suites & Mocks
│   ├── mocks/
│   │   └── mock_cm.sh          # Deterministic CLI simulation harness
│   ├── unit/
│   │   ├── test_mock_cm.py
│   │   ├── test_dlp_filter.py
│   │   ├── test_state_packager.py
│   │   ├── test_github_client.py
│   │   └── test_k8s_engine.py  # Phase 4: GKE gVisor & Security Specs Test
│   └── integration/
│       ├── test_api_scans.py
│       └── test_webhooks.py
└── requirements.txt
```

---

## 🛠️ Quickstart: Running Locally

### 1. Launch Dispatcher Server
```bash
cd /google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher
PYTHONPATH=. FLASK_APP=src.app flask run --host=0.0.0.0 --port=8080
```
Open `http://localhost:8080` in your browser to test drag-and-drop zip uploads or send GitHub PR webhooks.

### 2. Run Comprehensive Verification Test Suite (Phases 1–4)
```bash
PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py"
```
