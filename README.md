# CodeMender Remote Dispatcher & Execution Sandbox (v2.1)

A unified, enterprise-hardened remote-dispatcher system orchestrating the CodeMender CLI (`cm v0.14.0`, powered by `gemini-4-argon`) within isolated, ephemeral containers on local, customer-managed, or **Argolis Google Cloud** infrastructure.

---

## 🚀 Key Value Proposition: The Split Execution Model (v2.1)

CodeMender strictly decouples AI cognitive reasoning from physical code execution:
- **Reasoning Engine (Google Cloud)**: Gemini Enterprise Agent Platform / Interactions API (`gemini-4-argon` default, with selectable `gemini-3.8-cyber-flash`, `gemini-3.7-flash`, and `gemini-2.5-pro`). Communicates over outbound-only TLS gRPC streams, receiving only isolated AST metadata, traces, and targeted snippets (Zero Source Code Exfiltration).
- **Interactive 3-Stage Pipeline (`cm find -> cm verify -> cm fix`)**: Supports both one-click full remediation and step-by-step interactive discovery (`find`), selective air-gapped PoC exploit verification (`verify`), and verified diff patch generation (`fix`).
- **Physical Sandboxes (GKE Autopilot gVisor / Ephemeral Docker)**: Confined within ephemeral containers with dropped Linux capabilities (`--cap-drop=ALL`), PID limits (`pids.max=256`), memory cgroups, and gVisor kernel-level isolation.

---

## 🛡️ Key Architectural Capabilities

1. **Two-Phase Container Network Isolation**:
   - *Phase 1 (Staging & Dependency Fetch)*: Restricted egress to VPC Artifact Registry mirrors via Private Service Connect.
   - *Phase 2 (Air-Gapped PoC Detonation)*: Network namespace severed (`--network=none`), blocking all SSRF, reverse shells, and exfiltration attempts.
2. **GKE Autopilot & gVisor Batch Sandboxing**:
   - `K8sJobOrchestrator` provisions ephemeral `batch/v1.Job` pods with `runtimeClassName: gvisor`, `seccompProfile: RuntimeDefault`, `runAsNonRoot: true`, and memory-backed tmpfs mounts for `/run/codemender/state`.
3. **Self-Healing Argolis Provisioning & Full Teardown**:
   - Automatically provisions missing GCP projects, billing links, APIs, Org Policy exemptions, and dedicated VPC/Subnetwork/Cloud NAT (`codemender-vpc` / `codemender-subnet`) when Argolis disables the `default` network.
   - Includes `scripts/destroy_argolis.sh` (and `./scripts/deploy_argolis.sh --destroy`) to cleanly tear down and recreate the entire environment at any time.
4. **Multi-Hop AI Supply-Chain Cascade Detection**:
   - Detects `.pth` interpreter startup hooks, poisoned/typosquatted transitive dependencies, unpinned CI/CD GitHub Actions, and hardcoded fallback secrets (`demo/ai-supply-chain-cascade-demo.zip`).
5. **Control-Plane State Journaling & Signing**:
   - `StatePackager` provides HMAC-SHA256 signature verification for multi-turn session state across distributed pipeline runs.
6. **Decoupled ITSM & Cryptographic Provenance**:
   - Emits DLP-sanitized, immutable SHA-256 finding provenance digests (`SHA256(Repo + CommitSHA + FindingID)`) to Google Cloud Pub/Sub topics with Dead-Letter Queues.

---

## 📁 Repository Structure

```
codemender-dispatcher/
├── Dockerfile                      # Dispatcher Control Plane Image (Cloud Run / Gunicorn)
├── DEPLOYMENT_ARGOLIS.md           # Argolis GCP Hybrid Deployment & Teardown Guide
├── scripts/
│   ├── deploy_argolis.sh           # Self-Healing Argolis Deployment CLI Script
│   └── destroy_argolis.sh          # Full Argolis Environment Teardown & Cleanup Script
├── docker/                         # Sandbox Execution Engine Dockerfiles
│   ├── base/                       # Base hardened container (cm v0.14.0 + git)
│   ├── python/                     # Python 3.11 runtime flavor
│   ├── node/                       # Node.js 20 LTS runtime flavor
│   ├── go/                         # Go 1.22 runtime flavor
│   └── polyglot/                   # Unified polyglot container (all runtimes)
├── k8s/                            # Kubernetes & GKE Autopilot Manifests
│   ├── base/
│   │   ├── namespace.yaml          # codemender-executors isolated namespace
│   │   ├── configmap.yaml          # codemender-runtime-config ConfigMap
│   │   ├── network-policy.yaml     # Cilium default-deny NetworkPolicies
│   │   ├── rbac.yaml               # Least-privileged ServiceAccount & RoleBinding
│   │   ├── gvisor-job.yaml         # Autopilot gVisor batch Job template
│   │   └── kustomization.yaml      # Base Kustomize configuration
│   └── overlays/
│       └── gke-autopilot/          # Production GKE Autopilot overlay
├── terraform/                      # Argolis Infrastructure as Code
│   ├── main.tf
│   ├── variables.tf
│   ├── apis_and_org_policies.tf    # Automated GCP APIs & Argolis Org Policy overrides
│   ├── network.tf                  # Dedicated VPC, Subnetwork, Cloud Router & NAT
│   ├── gke_autopilot.tf            # Private GKE Autopilot with Datapath V2
│   ├── cloud_run.tf                # Artifact Registry & Cloud Run Dispatcher service
│   ├── iam_wif.tf                  # Workload Identity Federation & Scoped IAM
│   ├── pubsub.tf                   # Cloud Pub/Sub Topic & DLQ for Decoupled ITSM
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── src/                            # Dispatcher Control Plane & Web Portal
├── demo/                           # Demo Payloads & Runbooks
├── tests/                          # Unit & Integration Test Suites (21 Tests)
└── requirements.txt
```

---

## 🛠️ Quickstart

### 1. Deploy to an Argolis GCP Environment
See [DEPLOYMENT_ARGOLIS.md](DEPLOYMENT_ARGOLIS.md) for full details, or run:
```bash
chmod +x scripts/deploy_argolis.sh scripts/destroy_argolis.sh
./scripts/deploy_argolis.sh \
  --org [YOUR_ARGOLIS_ORG_DOMAIN] \
  --user [YOUR_ARGOLIS_ADMIN_USER] \
  --project [YOUR_ARGOLIS_PROJECT_ID]
```

### 2. Tear Down Environment (To Recreate in the Future)
```bash
./scripts/destroy_argolis.sh \
  --project [YOUR_ARGOLIS_PROJECT_ID] \
  --region us-central1
```

### 3. Launch Dispatcher Server Locally
```bash
PYTHONPATH=. FLASK_APP=src.app flask run --host=0.0.0.0 --port=[PORT]
```

### 4. Run Verification Test Suite
```bash
PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py"
```
