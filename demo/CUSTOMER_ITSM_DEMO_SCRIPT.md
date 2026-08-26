# 🎙️ CodeMender Enterprise Customer Demo Script: ITSM & SIEM Integration

This presentation script guides you through demonstrating **CodeMender's Decoupled ITSM & SIEM Architecture** (Jira, ServiceNow, Chronicle SIEM, and Cloud Pub/Sub) to enterprise CISO / SecOps / Platform Engineering stakeholders.

---

## 🎯 Demo Value Proposition (The Talk Track)

> **"Traditional AppSec tools flood your security team with thousands of unverified static alerts that developers ignore.
> 
> CodeMender is fundamentally different:
> 1. **Zero False Positives:** Every vulnerability is physically proven inside an air-gapped sandbox before an alert is ever created.
> 2. **Zero Source Code Exfiltration:** Code execution happens locally in your VPC under gVisor; only anonymized AST signals reach Gemini.
> 3. **Autonomous End-to-End Resolution:** When a vulnerability is verified, CodeMender automatically creates the Jira / ServiceNow incident, authors the verified fix patch, opens the Pull Request, and auto-resolves the ticket once your developer merges the PR."**

---

## 🏗️ Architectural Overview Slide

```
  +--------------------+       +------------------------------------+       +---------------------+
  |   CodeMender       |       |       Google Cloud Pub/Sub         |       |   Enterprise ITSM   |
  | Ephemeral Sandbox  | ----> |   `codemender-security-events`     | ----> |   - Jira Software   |
  | (Air-Gapped gVisor)|       |   (Decoupled, Event-Driven Bus)    |       |   - ServiceNow ITOM |
  +--------------------+       +------------------------------------+       |   - Chronicle SIEM  |
                                                                            +---------------------+
```

### Key Security Guardrails to Highlight:
- **DLP & Shannon Entropy ($H > 4.5$):** Sensitive credentials, JWTs, and API keys are scrubbed before publishing.
- **Cryptographic Provenance Digest:** Every event carries an immutable SHA-256 fingerprint:  
  $$\text{Provenance} = \text{SHA256}(\text{Repository} + \text{Commit SHA} + \text{Finding ID})$$
- **Bidirectional Closed-Loop Feedback:** Tracks human peer review decisions (`REMEDIATION_PR_MERGED` / `REJECTED`).

---

## 🎬 Step-by-Step Live Demo Execution

### **Act 1: Start the ITSM Event Bus Bridge**
Open a terminal window and run the live ITSM subscriber:

```bash
cd /google/src/cloud/carmona/codemender_demo/google3/experimental/users/carmona/codemender_dispatcher
PYTHONPATH=. python3 demo/itsm_demo_subscriber.py
```

---

### **Act 2: The Live Event Flow (What the Customer Sees)**

#### 1. Sandbox PoC Verification & Incident Ticket Creation
- **Event:** `VULNERABILITY_VERIFIED`
- **What happens:**
  - CodeMender finds an SQL injection in `query_builder.py:L42` and detonates an exploit in the gVisor sandbox.
  - An immutable provenance digest is stamped.
  - **Jira Issue `SEC-1049`** and **ServiceNow Incident `INC009281`** are created automatically with Priority: High.
- **Speaker Note:**  
  *"Notice that your security analysts didn't have to triage this manually. The system proved exploitability in a sandbox and generated the Jira issue with cryptographic audit provenance."*

#### 2. Companion Remediation PR Generated
- **Event:** `REMEDIATION_PR_CREATED`
- **What happens:**
  - CodeMender generates the parameterized fix diff and opens a companion Pull Request (`codemender/patch-pr-89`).
  - **Jira Issue `SEC-1049`** transitions to `PENDING CODE REVIEW` with the PR link embedded.
  - **ServiceNow Incident `INC009281`** Work Notes are populated with the `.diff` and test validation report.
- **Speaker Note:**  
  *"Rather than just complaining about a bug, CodeMender delivers the exact solution as a ready-to-merge Pull Request with 0 breaking changes."*

#### 3. Human Developer Merges PR & Auto-Resolution
- **Event:** `REMEDIATION_PR_MERGED`
- **What happens:**
  - The developer reviews and merges the PR on GitHub.
  - GitHub webhook notifies CodeMender, which publishes `REMEDIATION_PR_MERGED`.
  - **Jira `SEC-1049`** automatically transitions to `RESOLVED`.
  - **ServiceNow `INC009281`** moves to `CLOSED`.
  - **Chronicle SIEM** receives an immutable audit log entry.
- **Speaker Note:**  
  *"The loop is completely closed: from exploit detection to code repair, peer review, and ITSM compliance closure—with zero manual ticket juggling."*

---

## 💡 Key Customer Q&A Cheatsheet

| Customer Question | Recommended Answer |
| :--- | :--- |
| **"Can we connect this to our on-prem Jira / ServiceNow?"** | Yes. The Pub/Sub event bus supports standard Cloud Functions, Cloud Run webhooks, or existing enterprise iPaaS integrations (e.g. MuleSoft, Workato) to push to on-prem or cloud ITSM endpoints. |
| **"What if our developers reject the AI fix?"** | CodeMender catches `pull_request.closed` without merge, emits `REMEDIATION_PR_REJECTED`, re-opens the Jira ticket, and flags it for human application security escalation. |
| **"Does our source code leave our VPC?"** | No. Execution sandboxes run in your VPC under GKE Autopilot (gVisor). Only abstract AST signals pass through outbound gRPC to Gemini. |
