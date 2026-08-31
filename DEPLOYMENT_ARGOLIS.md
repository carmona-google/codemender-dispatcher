# Deploying CodeMender to Argolis GCP with Terraform

This guide walks through deploying the complete **CodeMender Split Execution & Remote Dispatcher** platform onto your **Argolis Google Cloud environment**.

---

## 🏗️ Architecture Provisioned in Argolis

```
+-----------------------------------------------------------------------------------+
| Google Cloud Argolis Project                                                      |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | VPC Network: default (Datapath V2 / Cilium eBPF)                            |  |
|  |                                                                             |  |
|  |  +-----------------------------------------------------------------------+  |  |
|  |  | GKE Autopilot Cluster (codemender-sandbox-cluster)                     |  |  |
|  |  |  - Namespace: codemender-executors                                    |  |  |
|  |  |  - Security: gVisor RuntimeClass (`runtimeClassName: gvisor`)           |  |  |
|  |  |  - NetworkPolicy: Cilium Default-Deny (RFC1918 & Metadata blocked)   |  |  |
|  |  |  - Workload Identity Federation (codemender-executor-ksa)              |  |  |
|  |  +-----------------------------------------------------------------------+  |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-------------------------------------+  +------------------------------------+  |
|  | Cloud Pub/Sub Topic:                |  | Vertex AI / Gemini Enterprise:     |  |
|  | `codemender-security-events`        |  | Outbound gRPC Interactions API     |  |
|  | (Decoupled ITSM & SIEM Bus)         |  | (Zero Source Code Exfiltration)    |  |
|  +-------------------------------------+  +------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 📋 Prerequisites in Argolis

1. **Active Argolis GCP Project**: Ensure you have Project Owner / Editor permissions.
2. **Google Cloud SDK (`gcloud`)**: Authenticated to your user account:
   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```
3. **Terraform**: Version `>= 1.5.0`
4. **Kubectl**: Version `>= 1.28`

---

## 🚀 Step-by-Step Deployment

### Step 1: Enable Google Cloud APIs in Argolis
Run the following command to activate all required APIs in your Argolis project:

```bash
export PROJECT_ID="[YOUR_ARGOLIS_PROJECT_ID]"
gcloud config set project ${PROJECT_ID}

gcloud services enable \
    container.googleapis.com \
    aiplatform.googleapis.com \
    pubsub.googleapis.com \
    artifactregistry.googleapis.com \
    iamcredentials.googleapis.com \
    cloudresourcemanager.googleapis.com
```

---

### Step 2: Configure Terraform Variables
Navigate to the `terraform/` directory and configure `terraform.tfvars`:

```bash
cd codemender_dispatcher/terraform

cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
project_id          = "[YOUR_ARGOLIS_PROJECT_ID]"
region              = "us-central1"
vpc_network_name    = "default"
vpc_subnetwork_name = "default"
```

---

### Step 3: Initialize and Apply Terraform Infrastructure

```bash
# 1. Initialize Terraform Providers
terraform init

# 2. Review Execution Plan
terraform plan

# 3. Provision Resources in Argolis
terraform apply -auto-approve
```

Upon completion, Terraform will output:
- `gke_cluster_name`: `codemender-sandbox-cluster`
- `gke_get_credentials_command`: `gcloud container clusters get-credentials ...`
- `pubsub_topic_id`: `projects/[ARGOLIS_PROJECT_ID]/topics/codemender-security-events`
- `dispatcher_service_account_email`: `codemender-dispatcher-sa@[ARGOLIS_PROJECT_ID].iam.gserviceaccount.com`
- `executor_service_account_email`: `codemender-executor-sa@[ARGOLIS_PROJECT_ID].iam.gserviceaccount.com`

---

### Step 4: Connect `kubectl` to GKE Autopilot
Authenticate your local/cloudtop terminal with the new GKE cluster:

```bash
$(terraform output -raw gke_get_credentials_command)
```

Verify the cluster connection:
```bash
kubectl get nodes
```

---

### Step 5: Apply Kubernetes Hardened Namespace & NetworkPolicies
Apply the base and overlay Kustomize configurations to deploy the `codemender-executors` namespace with Cilium default-deny NetworkPolicies and gVisor specs:

```bash
cd codemender_dispatcher

kubectl apply -k k8s/overlays/gke-autopilot/
```

Verify the namespace and policies:
```bash
kubectl get namespaces
kubectl get networkpolicies -n codemender-executors
kubectl get serviceaccounts -n codemender-executors
```

---

### Step 6: Run Dispatcher Control Plane Connected to Argolis

Configure your environment variables and start the Dispatcher:

```bash
export PUBSUB_PROJECT_ID="${PROJECT_ID}"
export PUBSUB_TOPIC_ID="codemender-security-events"
export K8S_NAMESPACE="codemender-executors"
export STORAGE_DIR="./storage"

PYTHONPATH=. FLASK_APP=src.app flask run --host=0.0.0.0 --port=8080
```

Access the Web Portal at `http://localhost:8080` to orchestrate scans directly against your Argolis GKE Autopilot cluster and Cloud Pub/Sub bus!

---

## 🧹 Teardown & Clean Up
To destroy all provisioned resources in your Argolis project:

```bash
cd codemender_dispatcher/terraform
terraform destroy -auto-approve
```
