# Deploying CodeMender Dispatcher (v2.1) to Argolis GCP

This guide walks through deploying and tearing down the **CodeMender Split Execution & Remote Dispatcher** platform in any **Argolis Google Cloud environment**. The deployment is **self-healing**: if the target GCP project, APIs, Org Policy exemptions, or `default` VPC/subnetwork do not exist, the deployment automatically provisions them.

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
|  | VPC Network: `codemender-vpc` + `codemender-subnet` + Cloud NAT             |  |
|  | (Auto-created when `default` subnetwork is absent in Argolis)               |  |
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

## ⚡ Option A: Self-Healing Automated Argolis Deployment

`scripts/deploy_argolis.sh` automatically checks for and creates any missing resources in the target project:
- **Missing Project & Billing**: If `--project` does not exist yet, creates it under `--org` and links the active billing account.
- **Missing `default` Subnetwork / VPC**: In Argolis projects where `compute.skipDefaultNetworkCreation` prevented creation of the `default` network (causing `Error 404: project does not have a subnetwork named "default"`), the script automatically provisions `codemender-vpc`, `codemender-subnet`, `codemender-router`, and `codemender-nat`.
- **Argolis Org Policies & Default SA IAM**: Automatically relaxes project-level VM/Shielded/OS-Login constraints and grants Cloud Build permissions to the default Compute Service Account.
- **Per-Project Terraform Workspaces**: Isolates Terraform state per project ID so you can deploy to multiple Argolis projects seamlessly.

```bash
chmod +x scripts/deploy_argolis.sh scripts/destroy_argolis.sh

# Full Self-Healing Hybrid Deployment (Cloud Run + GKE Autopilot + Pub/Sub)
./scripts/deploy_argolis.sh \
  --org [YOUR_ARGOLIS_ORG_DOMAIN] \
  --user [YOUR_ARGOLIS_ADMIN_USER] \
  --project [YOUR_ARGOLIS_PROJECT_ID] \
  --region us-central1
```

---

## 🧹 Teardown & Clean Recreation Workflow

To completely delete all provisioned CodeMender infrastructure (disabling GKE deletion protection, removing Kubernetes namespaces, destroying Cloud Run, GKE Autopilot, Artifact Registry, Pub/Sub, custom VPC/Subnet/NAT, and Service Accounts) so you can recreate the environment cleanly in the future:

```bash
# Option 1: Using the dedicated teardown script
./scripts/destroy_argolis.sh \
  --project [YOUR_ARGOLIS_PROJECT_ID] \
  --region us-central1

# Option 2: Using the --destroy flag on deploy_argolis.sh
./scripts/deploy_argolis.sh \
  --project [YOUR_ARGOLIS_PROJECT_ID] \
  --region us-central1 \
  --destroy

# Option 3: Delete all resources AND delete the GCP project itself
./scripts/destroy_argolis.sh \
  --project [YOUR_ARGOLIS_PROJECT_ID] \
  --delete-project
```

After running the teardown script, you can re-run `./scripts/deploy_argolis.sh --org [YOUR_ARGOLIS_ORG_DOMAIN] --user [YOUR_ARGOLIS_ADMIN_USER] --project [YOUR_ARGOLIS_PROJECT_ID]` at any time to recreate the entire stack from scratch.

---

## 🛠️ Option B: Step-by-Step Manual Terraform Deployment

### Step 1: Configure Terraform Variables
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` (note `create_vpc = true` is enabled by default for Argolis projects without a `default` network):
```hcl
org_domain                  = "[YOUR_ARGOLIS_ORG_DOMAIN]"
admin_user                  = "[YOUR_ARGOLIS_ADMIN_USER]"
project_id                  = "[YOUR_ARGOLIS_PROJECT_ID]"
create_project              = false
region                      = "us-central1"
create_vpc                  = true
vpc_network_name            = "default"
vpc_subnetwork_name         = "default"
gke_deletion_protection     = false
manage_argolis_org_policies = true
deploy_cloud_run            = true
dispatcher_image            = ""
```

### Step 2: Initialize & Apply Infrastructure
```bash
terraform init
terraform workspace select -or-create [YOUR_ARGOLIS_PROJECT_ID]
terraform apply -auto-approve
```

### Step 3: Build & Deploy Dispatcher to Cloud Run
```bash
export PROJECT_ID="[YOUR_ARGOLIS_PROJECT_ID]"
export REGION="us-central1"
export IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/codemender-repo/codemender-dispatcher:latest"

gcloud builds submit .. --project="${PROJECT_ID}" --tag="${IMAGE_URI}"
terraform apply -auto-approve -var="dispatcher_image=${IMAGE_URI}"
```

### Step 4: Connect `kubectl` & Apply Hardened GKE Autopilot Manifests
```bash
$(terraform output -raw gke_get_credentials_command)
cd ..
kubectl apply -k k8s/overlays/gke-autopilot/
```
