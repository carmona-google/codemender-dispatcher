# 1. Executive Summary

## 1.1 Purpose & Scope 

This document outlines the high-level architecture for a unified, secure remote-dispatcher system for CodeMender. The purpose of this architecture is to provide a scalable, centralized mechanism to orchestrate the CodeMender CLI (cm) within isolated, ephemeral containers hosted entirely on local or customer-managed infrastructure. By abstracting the CLI behind a dispatcher layer, organizations can seamlessly execute the full CodeMender vulnerability lifecycle (scan, verify, and fix) without requiring developers to manually install, configure, or run the tool directly on their host machines.

## 1.2 Supported Use Cases 

This architecture is designed to support two primary operational workflows through a single, unified backend:

* **Use Case A: Interactive Local Web Portal:** A containerized, self-hosted web application that provides a graphical interface for security and development teams. Users can manually upload local code archives, triggering the dispatcher to run the full CodeMender cycle within a local sandbox. Vulnerability findings, generated proof-of-concept exploits, and remediated code patches are subsequently surfaced and managed directly within the website console.  
* **Use Case B: Automated CI/CD Integration:** A headless, event-driven workflow designed to integrate seamlessly into existing CI/CD pipelines (e.g., GitHub Actions, GitLab CI). The dispatcher listens for repository events (such as pull requests), automatically provisions the secure execution environment, runs the CodeMender cycle in non-interactive mode, and pushes secure, validated patches directly back to the source control system.

## 1.3 Key Architectural Value Proposition 

The foundational security principle of this design is CodeMender's "**Split Execution Model.**" This architecture strictly decouples the AI's cognitive reasoning from the physical execution of the code, providing an absolute guarantee against source code exfiltration.

The "heavy lifting"—including file parsing, code compilation, test execution, and the live detonation of proof-of-concept exploits—happens 100% locally within ephemeral, restricted-egress Docker sandboxes on the customer's infrastructure. Google Cloud (e.g., the Gemini Enterprise Agent Platform) acts exclusively as the reasoning engine. The local execution layer communicates with the cloud via secure, outbound-only API calls, transmitting only the isolated snippets and metadata required for the AI to reason. This ensures that the organization benefits from state-of-the-art AI vulnerability remediation while maintaining a zero-trust, zero-upload data security posture.

## 1.4 Client-Side AST Pre-Filtering Engine 

To prevent intellectual property (IP) and secret leakage to the cloud boundary, a strict client-side AST-aware pre-filtering engine is embedded directly within the CodeMender CLI wrapper. Before any AST representation or code context is transmitted over outbound gRPC streams to Gemini Enterprise, the pre-filter parses the AST locally, redacts string literals, removes comments, and replaces potential secrets with cryptographic placeholders.

---

# 2. Core Architectural Principles

## 2.1 Decoupled Orchestration 

To guarantee scalability, security, and separation of concerns, the architecture mandates a strict decoupling between the user-facing trigger systems (the Local Web Portal or CI/CD webhooks) and the actual execution environment. The Dispatcher acts purely as a lightweight control plane: it receives payloads, manages job queues, and provisions resources, but it never executes the CodeMender CLI natively. By delegating all compute-heavy and potentially risky operations to a separate, dedicated execution layer, the frontend remains highly responsive and protected from workload interference or localized exploitation.

## 2.2 Ephemeral Sandboxing 

The most critical security control in this architecture is the enforcement of ephemeral sandboxing. The CodeMender verify phase actively builds the target application and detonates generated proof-of-concept (PoC) exploits to validate vulnerability exploitability. To contain the "blast radius" of these live exploits (e.g., executing a Remote Code Execution or Path Traversal payload), all CodeMender cycles must execute within isolated, short-lived Docker containers. These containers are stripped of unnecessary privileges and subjected to strict network policies (e.g., denying all outbound internet egress to prevent SSRF exfiltration or reverse shells). Once a cycle completes, the container and its execution environment are immediately destroyed, ensuring a pristine and secure baseline for every run.

## 2.3 Stateful Persistence 

CodeMender operates as a stateful agent. The CLI maintains vital session continuity data—including interactions history, encryption keys, vulnerability tracking, and local logs—within a hidden ~/.codemender configuration directory. Because the execution layer relies on ephemeral containers (which are destroyed post-execution), the architecture must implement robust stateful persistence. The Dispatcher manages this by provisioning a local persistent volume or leveraging internal object storage (e.g., an internal MinIO cluster or secure NFS share). Before an ephemeral container begins execution, the previous session state is hydrated into the sandbox; upon completion, the updated state and generated artifacts are securely synchronized back to the persistence layer before the container is torn down.

## 2.4 "Shared-Nothing" State Isolation 

To eliminate cross-run configuration poisoning and session hijacking:

* System configuration files (~/.codemender/config.yaml) are mounted strictly as read-only (:ro).  
* Dynamic session states, SQLite tracking databases, and transient caches are written exclusively to volatile, in-memory tmpfs RAM disks mounted at /run/codemender/state that are destroyed upon container exit.  
* When multi-turn state continuity is required across distributed runs, state packages are cryptographically signed, encrypted with customer-managed keys (CMEK) from Google Cloud Secret Manager, and unpacked exclusively into volatile sandbox memory.

---

# 3. System Components Definitions

## 3.1 The Dispatcher (API/Web Layer) 

The Dispatcher acts as the central control plane and intake routing system, hosted entirely within the customer's internal network (e.g., on a local server or private VPC). It exposes secure REST/GraphQL endpoints that serve the local Web UI and listen for incoming webhooks from CI/CD systems (like GitHub Actions or GitLab).

* **Responsibilities:** It handles user authentication, validates incoming requests, and manages the ingestion of zipped source code archives. Crucially, the Dispatcher manages the job queue and orchestrates the lifecycle of the Execution Engine containers—spinning them up when a scan is requested and tearing them down upon completion.  
* **Security Posture:** The Dispatcher never analyzes, parses, or compiles the code itself. It strictly acts as a highly privileged broker that provisions the isolated environments where the actual work takes place.

## 3.2 The Execution Engine (Compute Layer) 

* The Execution Engine is the physical "muscle" of the CodeMender architecture. It consists of ephemeral, hardened Docker containers dynamically provisioned by the Dispatcher on GKE Autopilot.  
* **Composition:** The base container image is custom-built to include the standalone CodeMender CLI (cm-linux binary), standard version control tools (Git), and the necessary language runtimes/compilers required by the target application (e.g., Node.js, Python, Go, Java).  
* **Execution Flow:** The container mounts the targeted source code and the Persistence Layer, then natively executes the cm find, cm verify, and cm fix commands against the codebase.  
* **Security Posture:** Because the cm verify command actively compiles code and executes AI-generated Proof-of-Concept (PoC) exploits, these containers operate under strict isolation. They drop all unnecessary Linux capabilities and enforce egress firewalls—allowing outbound traffic *only* to the Google Cloud APIs and internal package registries, while completely blocking general internet access to neutralize potentially harmful exploit payloads.

## 3.3 The Persistence Layer (Storage) 

CodeMender requires state continuity to function effectively, but the Execution Engine containers are inherently stateless and destroyed after every run. The Persistence Layer bridges this gap using local, secure storage mechanisms (e.g., internal NFS, attached persistent volumes, or on-premise object storage like MinIO).

* **State Hydration:** It stores the critical ~/.codemender directory, which houses the multi-turn session state, local encryption keys, internal SQLite/JSONL tracking files, and runtime configurations. This state is injected into the Execution Engine at startup, allowing CodeMender to seamlessly string together the find, verify, and fix stages across different container lifecycles.  
* **Artifact Management:** Upon completion of a CodeMender cycle, the Execution Engine writes its output artifacts—such as the final vulnerability reports (report.json or SARIF files), execution logs (LOG.md), and generated code patches (.diff)—to this layer. The Dispatcher then retrieves these artifacts from the storage volume to render them in the Web UI or push them back to the CI/CD pipeline.

## 3.4 The Cloud Boundary (GCP Interactions API) 

This component represents the outbound-only secure bridge connecting the isolated local environment to the Google Cloud reasoning engine. The codebase never crosses this boundary; only targeted metadata and specific code snippets do.

* **The Connection:** The cm-linux binary inside the Execution Engine authenticates (via Google Application Default Credentials, Workload Identity, or scoped API keys) and opens a TLS-encrypted, outbound gRPC connection to the Gemini Enterprise Agent Platform.  
* **The Cloud Architecture:** The traffic is routed to the **Interactions API,** a stateful data plane designed to manage multi-turn agent conversations. Behind this API sits Chiliagon (the CodeMender Orchestrator Agent) and Google DeepMind's core vulnerability models.  
* **The Data Exchange:** The local CLI streams isolated abstract syntax tree (AST) metadata, specific vulnerable code snippets, and the standard output/errors from local test executions. In return, Chiliagon processes this context and streams back agentic "tool call" instructions (e.g., "create this file," "run this bash script," "apply this patch") for the local Execution Engine to perform safely within its sandbox.

## 3.5 Namespace & Network Quarantine

All execution sandboxes running in GKE are isolated in a dedicated, low-privilege codemender-executors namespace. Using **GKE Datapath V2 (Cilium eBPF)**, default-deny egress NetworkPolicies block all traffic to:

* Private RFC1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).  
* The GKE Node Metadata Server (169.254.169.254/32).  
* Outbound connectivity is strictly limited to Kubernetes DNS resolution (UDP port 53).

---

# 4. End-to-End Execution Workflows

## 4.1 Workflow A: Local Web Portal (Manual Upload) 

This workflow describes the synchronous execution path when a developer or security engineer manually interacts with the internal Web UI to scan a codebase.

* **Step 1: Ingestion:** A user authenticates to the internal Web Portal and uploads a compressed archive (e.g., .zip) of their codebase. The Dispatcher receives the archive and securely saves it to a temporary staging volume on the internal network.  
* **Step 2: Provisioning:** The Dispatcher dynamically provisions an ephemeral Docker Sandbox Container on the local compute infrastructure. It mounts the unpacked codebase and injects the necessary CodeMender configuration (including the ~/.codemender state directory from the Persistence Layer).  
* **Step 3: Execution Loop:** The Sandbox Container autonomously executes the CodeMender pipeline natively on the mounted files:  
  * It runs cm find to perform local AST parsing and data-flow scanning, transmitting only metadata to the cloud reasoning engine.  
  * It runs cm verify to detonate AI-generated Proof-of-Concept exploits locally to prove exploitability, strictly blocked from external internet egress.  
  * It runs cm fix to generate, apply, and validate contextual patches directly against the local files.  
* **Step 4: Reporting:** Upon completion, the Sandbox Container writes a structured vulnerability report (e.g., report.json or SARIF format), execution logs, and the generated .diff patches back to the persistent volume. The Dispatcher reads these artifacts and renders them interactively within the Web Console UI for user review.  
* **Step 5: Teardown:** The Dispatcher immediately tears down the Sandbox Container and securely deletes the temporary staging environment, returning the system to a clean state.

## 4.2 Workflow B: CI/CD Automation (Headless) 

This workflow outlines the asynchronous, event-driven path designed for integration into customer-managed version control systems (e.g., GitHub Enterprise, GitLab) and automated CI/CD pipelines.

* **Step 1: Trigger:** A developer opens a Pull Request (PR) or pushes a commit to the internal Source Control System. A webhook is fired to the Dispatcher (or a job is queued directly on a self-hosted CI runner) to initiate the security scan.  
* **Step 2: State Synchronization:** The self-hosted runner or dynamically provisioned Sandbox Container connects to the internal Persistence Layer to pull the latest CodeMender session state (~/.codemender). This ensures the agent maintains context, encryption keys, and configuration history across ephemeral pipeline runs.  
* **Step 3: Headless Execution:** The container executes the full CodeMender cycle in a strict, non-interactive "headless" mode. It utilizes explicit bypass flags (e.g., passing --yes or overriding the config.yaml with confirm_writes: false and human_confirmation: false) to ensure the agent can generate and test patches without hanging the pipeline waiting for manual terminal input.  
* **Step 4: Delivery:** Once the vulnerabilities are identified, verified, and successfully patched locally, the runner structures the outputs. It posts the report.json as a security comment on the PR and pushes the validated .diff code changes as a secure commit back to the target branch. Finally, the runner synchronizes any updated state back to the Persistence Layer before tearing down.

## 4.3 Workflow B: Headless CI/CD Pipeline & Non-Interactive Branch Protection 

1. A Git repository event triggers a headless CodeMender scan.  
2. The headless Execution Engine verifies the exploit within an isolated gVisor sandbox.  
3. **Branch Protection Enforcement:** Headless runners are strictly forbidden from committing or pushing directly to default or protected branches (main/master).  
4. The runner pushes the patch to an ephemeral feature branch (e.g., codemender/patch-sec-101) and submits a Pull Request.  
5. Merging requires passing mandatory CI status checks and non-bypassable human peer-review sign-off.

---

# 5. Security & Threat Model

## 5.1 Exploit Blast Radius Containment 

The most unique threat vector introduced by CodeMender is its active verification phase (cm verify), which autonomously compiles code and detonates AI-generated Proof-of-Concept (PoC) exploits. To mitigate the risk of these exploits exhibiting malicious behavior (e.g., executing arbitrary Remote Code Execution commands or establishing reverse shells), the Execution Engine enforces strict "blast radius" containment.

* **Execution Isolation:** All CodeMender operations execute within highly restricted, ephemeral containers. GKE Sandbox (gVisor) is enabled natively at the workload level via GKE Autopilot. The containers are configured to drop default Linux capabilities and mount the source code directory with least-privilege permissions.  
* **Network Egress Denial:** To prevent Server-Side Request Forgery (SSRF) payloads or reverse shell connections from succeeding, the Docker network namespaces enforce strict egress firewalls. The containers are entirely blocked from accessing the public internet. Outbound traffic is exclusively permitted to the Google Cloud APIs (via Private Service Connect or Private Google Access) and predefined internal package registries required for application compilation.

## 5.2 Authentication & Identity 

Managing authentication for automated systems poses a significant risk of credential leakage. This architecture mitigates the reliance on long-lived, hardcoded API keys by adopting a zero-trust, identity-based authentication model for the Execution Engine.

* **Workload Identity Federation (WIF):** For CI/CD runners and local dispatcher nodes, the architecture leverages GCP Workload Identity Federation or natively attached Service Accounts.  
* **Short-Lived Credentials:** The local execution environments dynamically request short-lived, ephemeral OAuth 2.0 access tokens to authenticate against the Gemini Enterprise Agent Platform.  
* **Scoped Access:** These service identities are granted the principle of least privilege, restricted entirely to the roles/aiplatform.user role required to stream session data to the Interactions API, ensuring that a compromised container cannot pivot into broader GCP administrative access.

## 5.3 Data Privacy Guarantee (Zero Source Code Exfiltration) 

The paramount concern for enterprise customers is the protection of proprietary Intellectual Property (IP). CodeMender's "Split Execution Model" inherently solves the threat of mass source code exfiltration to cloud providers.

* **Decentralized Code Access:** The Gemini reasoning agent operating in Google Cloud is never granted direct access to the customer's version control systems (e.g., GitHub, GitLab). It cannot clone or index the repository.  
* **Targeted Telemetry:** The local CodeMender CLI parses the codebase entirely on-premise. It only transmits highly targeted data—specifically, Abstract Syntax Tree (AST) metadata, diagnostic traces, and isolated lines of vulnerable code—to the cloud-based Interactions API over TLS-encrypted channels.  
* **No Model Training:** Data streamed to the CodeMender API is completely siloed within secure, tenant-specific bounds using robust encryption. Consistent with Google Cloud’s enterprise data privacy commitments, neither the source code snippets nor the generated patches are retained long-term or utilized to train Google's foundation models.

---

# 6. Operational Scalability & Observability

## 6.1 Concurrency Management 

To support enterprise-scale development teams, the architecture must efficiently handle simultaneous scan requests—whether from multiple users uploading archives to the Web Portal or an influx of automated pull request webhooks.

* **Job Queuing System:** The Dispatcher implements a robust asynchronous task queue (e.g., Celery backed by Redis, or native Kubernetes job orchestration) to manage concurrent workloads. Incoming requests are placed into the queue, decoupling the intake from the intensive compute execution.  
* **Resource Pooling & Throttling:** Compute resources are serverless and billed strictly per-pod, where requested resources dictate hard limits, eliminating idle node waste and the need for complex cluster-autoscaler configurations. The Dispatcher dynamic provisions Sandbox Containers up to a defined maximum threshold to manage concurrent execution.  
* **Distributed CI/CD Scaling:** For the headless automation workflow, scaling is naturally delegated to the customer's existing CI/CD runner fleet (e.g., self-hosted GitHub Actions runners or GitLab CI executors). The runner orchestration platform inherently manages its own concurrency and autoscaling limits, horizontally scaling the CodeMender sandboxes across the internal build farm.

## 6.2 Telemetry & Audit Logging 

Observability is critical not only for operational health but also for tracking the Return on Investment (ROI) and API token consumption associated with AI vulnerability remediation.

* **Structured Audit Trails:** Every CodeMender cycle generates comprehensive, structured logs. The Execution Engine outputs detailed diagnostic files (e.g., LOG.md and local JSONL session records) capturing every step of the reasoning and verification process. The Dispatcher aggregates these logs alongside sandbox lifecycle events (provisioning, execution, teardown) into the Persistence Layer, ensuring a complete, immutable audit trail for security and compliance reviews.  
* **Granular Token & Cost Tracking:** CodeMender intricately tracks the Gemini model's token consumption—breaking down input, output, cached, and tool tokens per session. The architecture parses the local JSONL session files output by the CLI to monitor token usage at the user, team, or repository level. The Dispatcher can be configured to enforce strict token budgets, proactively rejecting new scan requests if a specific CI/CD pipeline or department exceeds its allocated cost limits.  
* **Enterprise Observability Integration:** The architecture supports OpenTelemetry (OTel) metrics. Telemetry data—including scan durations, success/failure rates, vulnerability categorization, and cache efficiency ratios—can be exported from the Dispatcher directly into the customer's existing enterprise observability stacks (e.g., Datadog, Splunk, Grafana, or Google Cloud Monitoring) for centralized, real-time analytics.

## 6.3 Dual-Layer Observability & Telemetry Sanitization

To prevent active exploit payloads and unpatched vulnerability signatures from entering searchable enterprise log platforms:

* **Layer 1 (Local AST Tokenizer Sidecar):** Tokenizes log lines, stripping comments and literal variable assignments before shipping.  
* **Layer 2 (Google Cloud Sensitive Data Protection):** All outbound telemetry passes through the Cloud DLP API using pre-configured inspection templates (GOOGLE_CREDENTIALS, AWS_CREDENTIALS, SECURE_SHELL_PRIVATE_KEY, AUTH_TOKEN) prior to indexing in Cloud Logging or Splunk.

---

# 7. Implementation Roadmap

This roadmap outlines the phased approach to building and deploying the unified CodeMender remote execution architecture within the customer's secure perimeter.

## 7.1 Phase 1: Core Containerization (Execution Engine) 

The first phase focuses on building a standardized, reproducible compute environment.

* **Action:** Develop a custom Dockerfile that acts as the baseline Execution Engine.  
* **Requirements:** The image must include the standalone CodeMender binary (cm-linux), standard version control utilities (Git), and the core language runtimes and build tools required to compile the target applications (e.g., Node.js, Python, Go, Java).  
* **Outcome:** A version-controlled Docker image hosted in the customer's internal container registry, ready to be pulled by the Dispatcher for localized execution.

## 7.2 Phase 2: Dispatcher API and Web Portal Development 

The second phase establishes the control plane and user interface for manual interactions.

* **Action:** Develop the Dispatcher backend (e.g., using Python/Flask or Node.js) and the Web UI console.  
* **Requirements:** The backend must expose API endpoints to accept .zip codebase uploads, unpack them into temporary staging directories, and programmatically spawn the Phase 1 Docker containers via the local Docker daemon socket or Kubernetes API. The Web UI must be able to parse and render the resulting report.json and code diffs.  
* **Outcome:** A functional internal web portal where developers can manually upload code, trigger a scan, and view the verified vulnerabilities and AI-generated patches without installing the CLI locally.

## 7.3 Phase 3: CI/CD Webhooks and State Persistence 

The third phase bridges the gap between manual execution and headless automation, ensuring session continuity.

* **Action:** Integrate the Persistence Layer and expand the Dispatcher to handle external system triggers.  
* **Requirements:** Configure a local persistent volume, secure NFS share, or internal object storage. Update the Dispatcher to mount this storage into the ephemeral containers so that the ~/.codemender session state and encryption keys persist across cycles. Add webhook listeners to the Dispatcher API to catch Pull Request events from the internal Git platform, triggering the Execution Engine in headless mode (using --yes and confirm_writes: false).  
* **Outcome:** Automated security patching integrated directly into the CI/CD pipeline, with CodeMender retaining conversational memory and state across automated runs.

## 7.4 Phase 4: Network Hardening and Egress Denial 

The final phase locks down the execution environment to enforce the zero-trust threat model.

* **Action:** Implement strict network boundaries around the Execution Engine containers.  
* **Requirements:** Configure Docker network namespaces, iptables, or Kubernetes NetworkPolicies to drop all outbound internet traffic from the ephemeral sandboxes. Explicitly whitelist outbound TLS traffic only to the Gemini Enterprise Agent Platform APIs (preferably via Private Service Connect over the internal backbone) and internal artifact registries (e.g., internal NPM/PyPI mirrors).  
* **Outcome:** A fully hardened architecture where generated proof-of-concept exploits cannot establish reverse shells or exfiltrate data to external targets, successfully achieving a contained "zero blast radius."

## 7.5 Top Recommendations for GKE Autopilot Migration 

* **Shift Security Baseline Left Immediately:** Instruct the team to halt feature development until Phase 1 deliverables incorporate private GKE Autopilot clusters and zero-trust Kubernetes NetworkPolicies.  
* **Enforce Kernel-Level Sandbox Isolation (gVisor):** Instruct the team to enforce GKE Sandbox at the workload level using Autopilot's native gVisor integration, rather than manually configuring runtime classes.

---

# 8. Decoupled Event-Driven ITSM Integration (Google Cloud Pub/Sub)

## 8.1 Publisher-Side Event-Driven Architecture

To maintain a strict zero-trust posture, the core scanning and detonation pipelines inside the GKE Execution Engine are completely quarantined from direct external network access. Therefore, the Execution Engine cannot publish events directly to external endpoints. Instead, CodeMender utilizes an asynchronous, event-driven model powered by **Google Cloud Pub/Sub** to stream security notifications. The **CodeMender Dispatcher** serves as the sole, authoritative **Publisher** in this architecture. Running within the secure enterprise VPC and leveraging Private Google Access, the Dispatcher listens for task completion events from the quarantined GKE sandboxes via an internal secure gRPC control channel. Upon validating a completed execution phase, the Dispatcher packages the sanitized metadata, signs the event payload, and publishes it securely to a centralized Google Cloud Pub/Sub topic (e.g., `projects/[GCP_PROJECT_ID]/topics/codemender-security-events`). All downstream ticketing platforms (such as Jira Cloud, ServiceNow, or Zendesk) are entirely decoupled from CodeMender's runtime; they consume these events asynchronously, which is outside the scope of this core engine design.

## 8.2 Execution Event Triggers

The CodeMender Dispatcher is configured to publish messages to the Pub/Sub topic on two specific runtime triggers:

* **Vulnerability Verified (VULNERABILITY_VERIFIED):** Triggered immediately after cm verify compiles the target application, successfully detonates a proof-of-concept (PoC) exploit within the gVisor sandbox, and confirms a high-confidence finding. This event alerts downstream systems that a genuine, validated vulnerability exists.  
* **Remediation PR Created (REMEDIATION_PR_CREATED):** Triggered immediately after cm fix successfully generates an optimized code patch, tests the patch to confirm the exploit is blocked, pushes the patch to an isolated, ephemeral feature branch, and opens a Pull Request. This event indicates that a verified fix is pending human peer-review.

## 8.3 Agnostic Event Schema (DLP Enforced)

To prevent the exfiltration of intellectual property (IP), proprietary code, or exploit mechanics to multi-tenant SaaS platforms, the Pub/Sub payload utilizes a strict, platform-agnostic schema. This schema is explicitly limited to metadata. It is programmatically validated by the Dispatcher, and any fields containing unified diff syntax (e.g., git diff markers) or raw source code keywords are immediately dropped at the publisher boundary.

## 8.4 Decoupling & Reliability Benefits

Transitioning the outbound integration layer to an asynchronous, publish-subscribe architecture provides critical operational advantages:

* **SaaS Outage Resilience (Fault Tolerance):** Direct webhook connections are vulnerable to rate-limiting, connection timeouts, or SaaS platform outages (e.g., Atlassian Jira Cloud downtime). Pub/Sub serves as a durable, distributed queue. If downstream ticketing consumers are unavailable, events are buffered reliably on Google Cloud infrastructure for up to 7 days (default retention), guaranteeing zero lost findings.  
* **Ticketing Platform Agnosticism:** The publisher remains completely unaware of which ticketing system, database, or security information and event management (SIEM) tool ultimately consumes the message. This allows enterprise infrastructure teams to switch ITSM platforms (e.g., migrating from ServiceNow to Jira, or multiplexing events to a Splunk SIEM) without modifying CodeMender’s core codebase or redeploying the Dispatcher.  
* **Strict Security Partitioning:** By decoupling ticketing from the core compute sandboxes, the Dispatcher only requires IAM permissions to publish to Pub/Sub (roles/pubsub.publisher). It does not need to store, manage, or rotate third-party SaaS credentials or maintain external state, dramatically reducing the threat surface of the control plane.
