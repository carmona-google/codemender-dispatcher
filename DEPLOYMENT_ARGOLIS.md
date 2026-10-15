# Deploying CodeMender Dispatcher (v2.1) to Argolis GCP

This guide walks through deploying the **CodeMender Split Execution & Remote Dispatcher** platform onto a specific **Argolis Google Cloud environment** using the automated deployment workflow or step-by-step Terraform + Kubernetes manifests.

---

## 🏗️ Hybrid Architecture Provisioned in Argolis

```
+-----------------------------------------------------------------------------------+
| Argolis Organization: [YOUR_ARGOLIS_ORG_DOMAIN]                                   |
| Google Cloud Project: [YOUR_ARGOLIS_PROJECT_ID]                                   |
| Admin User          : [YOUR_ARGOLIS_ADMIN_USER]                                   |
|                                                                                   |
|  +-------------------------------------+  +------------------------------------+  |
|  | Cloud Run Service:                  |  | Artifact Registry:                 |  |
|  | `codemender-dispatcher`             |  | `codemender-repo`                  |  |
|  | (Flask Web UI + 3-Stage REST API)   |  | (Dispatcher & Sandbox Containers)  |  |
|  +-------------------------------------+  +------------------------------------+  |
|                     |                                                             |
|                     v                                                             |
|  +-----------------------------------------------------------------------------+  |
|  | VPC Network (Datapath V2 / Cilium eBPF)                                     |  |
|  |                                                                             |  |
|  |  +-----------------------------------------------------------------------+  |  |
|  |  | GKE Autopilot Cluster (`codemender-sandbox-cluster`)                  |  |  |
|  |  |  - Namespace: `codemender-executors`                                  |  |  |
|  |  |  - ConfigMap: `codemender-runtime-config` (cm v0.14.0 / gemini-4-argon)|  |  |
|  |  |  - Security: gVisor RuntimeClass (`runtimeClassName: gvisor`)         |  |  |
|  |  |  - NetworkPolicy: Cilium Default-Deny (RFC1918 & Metadata blocked)    |  |  |
|  |  |  - Workload Identity Federation (`codemender-executor-ksa`)           |  |  |
|  |  +-----------------------------------------------------------------------+  |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-------------------------------------+  +------------------------------------+  |
|  | Cloud Pub/Sub Topic:                |  | Vertex AI / Gemini Enterprise:     |  |
|  | `codemender-security-events`        |  | Outbound gRPC Interactions API     |  |
|  | (Decoupled ITSM & SIEM Bus + DLQ)   |  | (`gemini-4-argon` / `3.8-cyber`)   |  |
|  +-------------------------------------+  +------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 📋 Prerequisites

1. **Argolis GCP Organization & Project**: Active Argolis account (`[YOUR_ARGOLIS_ADMIN_USER]`) under your Argolis organization (`[YOUR_ARGOLIS_ORG_DOMAIN]`).
2. **Google Cloud SDK (`gcloud`)**:
   ```bash
   gcloud auth login [YOUR_ARGOLIS_ADMIN_USER]
   gcloud auth application-default login
   ```
3. **Terraform**: Version `>= 1.5.0`
4. **Kubectl**: Version `>= 1.28` with `gke-gcloud-auth-plugin`

---

## ⚡ Option A: One-Command Automated Argolis Deployment

Use `scripts/deploy_argolis.sh` to automatically configure your Argolis organization/user/project, enable required GCP APIs, provision Artifact Registry + Pub/Sub + GKE Autopilot, build & deploy the Cloud Run Dispatcher service, and apply the hardened Kubernetes manifests:

```bash
chmod +x scripts/deploy_argolis.sh

# Full Hybrid Deployment (Cloud Run + GKE Autopilot + Pub/Sub)
./scripts/deploy_argolis.sh \
  --org [YOUR_ARGOLIS_ORG_DOMAIN] \
  --user [YOUR_ARGOLIS_ADMIN_USER] \
  --project [YOUR_ARGOLIS_PROJECT_ID] \
  --region us-central1
```

### Additional Flags for Specific Argolis Environments
- `--create-vpc`: Provisions a dedicated `codemender-vpc` and `codemender-subnet` (use if your Argolis project enforces `compute.skipDefaultNetworkCreation` and has no `default` VPC).
- `--manage-org-policies`: Automatically relaxes restrictive project-level Argolis Org Policies (`compute.vmExternalIpAccess`, `compute.requireShieldedVm`, `compute.requireOsLogin`).
- `--create-project`: Creates the project directly under `--org` before provisioning resources.
- `--infra-only`: Provisions only the backend infrastructure (GKE Autopilot + Pub/Sub + Artifact Registry) so you can run the Flask Dispatcher locally.
- `--dry-run`: Generates `terraform.tfvars` and executes `terraform plan` without modifying cloud resources.

---

## 🛠️ Option B: Step-by-Step Manual Deployment

### Step 1: Configure Terraform Variables
Copy the example configuration to a git-ignored `terraform.tfvars` file:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your Argolis environment parameters:
```hcl
org_domain                  = "[YOUR_ARGOLIS_ORG_DOMAIN]"
admin_user                  = "[YOUR_ARGOLIS_ADMIN_USER]"
project_id                  = "[YOUR_ARGOLIS_PROJECT_ID]"
create_project              = false
region                      = "us-central1"
create_vpc                  = false
vpc_network_name            = "default"
vpc_subnetwork_name         = "default"
manage_argolis_org_policies = false
deploy_cloud_run            = true
dispatcher_image            = ""
```

### Step 2: Initialize & Apply Base Infrastructure
```bash
terraform init
terraform plan
terraform apply -auto-approve
```

### Step 3: Build & Deploy Dispatcher to Cloud Run (Optional)
```bash
export PROJECT_ID="[YOUR_ARGOLIS_PROJECT_ID]"
export REGION="us-central1"
export IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/codemender-repo/codemender-dispatcher:latest"

# Build container image in Cloud Build and push to Artifact Registry
gcloud builds submit .. --project="${PROJECT_ID}" --tag="${IMAGE_URI}"

# Deploy Cloud Run service with the built image
terraform apply -auto-approve -var="dispatcher_image=${IMAGE_URI}"
```

### Step 4: Connect `kubectl` & Apply Hardened GKE Autopilot Manifests
```bash
$(terraform output -raw gke_get_credentials_command)

cd ..
kubectl apply -k k8s/overlays/gke-autopilot/

# Verify Namespace, ConfigMap, NetworkPolicies, and ServiceAccount
kubectl get configmap,networkpolicy,serviceaccount -n codemender-executors
```

### Step 5: Run Dispatcher Locally Connected to Argolis (Hybrid Mode)
```bash
export GCP_PROJECT_ID="[YOUR_ARGOLIS_PROJECT_ID]"
export PUBSUB_TOPIC_ID="codemender-security-events"
export K8S_NAMESPACE="codemender-executors"
export CODEMENDER_MODEL="gemini-4-argon"
export CODEMENDER_CLI_VERSION="0.14.0"

PYTHONPATH=. FLASK_APP=src.app flask run --host=0.0.0.0 --port=[PORT]
```

---

## 🧹 Teardown & Clean Up
To destroy all provisioned resources in your Argolis project:

```bash
cd terraform
terraform destroy -auto-approve
```
