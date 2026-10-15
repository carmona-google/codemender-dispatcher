#!/usr/bin/env bash
# ==============================================================================
# CodeMender Dispatcher (v2.1) — Self-Healing Argolis GCP Deployment Script
# ==============================================================================
# Automatically creates any missing resources in the target Argolis environment
# (Project, Billing link, APIs, Org Policies, Dedicated VPC/Subnetwork/NAT when
# 'default' subnetwork is absent, Artifact Registry, Pub/Sub, GKE Autopilot,
# and Cloud Run) or destroys the environment when --destroy is passed.
#
# Usage:
#   ./scripts/deploy_argolis.sh \
#     --org [YOUR_ARGOLIS_ORG_DOMAIN] \
#     --user [YOUR_ARGOLIS_ADMIN_USER] \
#     --project [YOUR_ARGOLIS_PROJECT_ID] \
#     [--region us-central1] \
#     [--create-vpc | --use-existing-vpc] \
#     [--manage-org-policies] \
#     [--skip-image-build] \
#     [--infra-only] \
#     [--dry-run] \
#     [--destroy]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform"

ORG_DOMAIN="${ARGOLIS_ORG_DOMAIN:-[YOUR_ARGOLIS_ORG_DOMAIN]}"
ADMIN_USER="${ARGOLIS_ADMIN_USER:-[YOUR_ARGOLIS_ADMIN_USER]}"
PROJECT_ID="${ARGOLIS_PROJECT_ID:-[YOUR_ARGOLIS_PROJECT_ID]}"
REGION="${ARGOLIS_REGION:-us-central1}"
CREATE_PROJECT="false"
CREATE_VPC="auto"
MANAGE_ORG_POLICIES="true"
DEPLOY_CLOUD_RUN="true"
SKIP_IMAGE_BUILD="false"
DRY_RUN="false"
DESTROY_MODE="false"
DELETE_PROJECT="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --org)
      ORG_DOMAIN="$2"
      shift 2
      ;;
    --user)
      ADMIN_USER="$2"
      shift 2
      ;;
    --project)
      PROJECT_ID="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    --create-project)
      CREATE_PROJECT="true"
      shift
      ;;
    --create-vpc)
      CREATE_VPC="true"
      shift
      ;;
    --use-existing-vpc)
      CREATE_VPC="false"
      shift
      ;;
    --manage-org-policies)
      MANAGE_ORG_POLICIES="true"
      shift
      ;;
    --no-org-policies)
      MANAGE_ORG_POLICIES="false"
      shift
      ;;
    --infra-only)
      DEPLOY_CLOUD_RUN="false"
      SKIP_IMAGE_BUILD="true"
      shift
      ;;
    --skip-image-build)
      SKIP_IMAGE_BUILD="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --destroy)
      DESTROY_MODE="true"
      shift
      ;;
    --delete-project)
      DESTROY_MODE="true"
      DELETE_PROJECT="true"
      shift
      ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ "${PROJECT_ID}" == "[YOUR_ARGOLIS_PROJECT_ID]" || -z "${PROJECT_ID}" ]]; then
  echo "ERROR: Please provide a target Argolis Project ID via --project <PROJECT_ID>."
  exit 1
fi

# Delegate to destroy_argolis.sh when --destroy is passed
if [[ "${DESTROY_MODE}" == "true" ]]; then
  DESTROY_ARGS=(--project "${PROJECT_ID}" --region "${REGION}" --org "${ORG_DOMAIN}" --user "${ADMIN_USER}")
  if [[ "${DELETE_PROJECT}" == "true" ]]; then
    DESTROY_ARGS+=(--delete-project)
  fi
  exec "${SCRIPT_DIR}/destroy_argolis.sh" "${DESTROY_ARGS[@]}"
fi

echo "=============================================================================="
echo " CodeMender Remote Dispatcher — Self-Healing Argolis Deployment"
echo "------------------------------------------------------------------------------"
echo " Organization : ${ORG_DOMAIN}"
echo " Admin User   : ${ADMIN_USER}"
echo " Project ID   : ${PROJECT_ID}"
echo " Region       : ${REGION}"
echo " Cloud Run    : ${DEPLOY_CLOUD_RUN}"
echo " Dry Run      : ${DRY_RUN}"
echo "=============================================================================="

# 1. Verify gcloud authentication and ensure target project exists
if [[ "${ADMIN_USER}" != "[YOUR_ARGOLIS_ADMIN_USER]" ]]; then
  echo "[1/6] Setting active gcloud account to ${ADMIN_USER}..."
  gcloud config set account "${ADMIN_USER}" >/dev/null
fi

echo "[1/6] Checking if project '${PROJECT_ID}' exists..."
if ! gcloud projects describe "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Project '${PROJECT_ID}' does not exist. Creating it now..."
  ORG_ID=""
  if [[ "${ORG_DOMAIN}" != "[YOUR_ARGOLIS_ORG_DOMAIN]" && -n "${ORG_DOMAIN}" ]]; then
    ORG_ID="$(gcloud organizations list --filter="DISPLAY_NAME=${ORG_DOMAIN}" --format="value(ID)" | head -n 1 || true)"
  fi
  if [[ -n "${ORG_ID}" ]]; then
    gcloud projects create "${PROJECT_ID}" --name="${PROJECT_ID}" --organization="${ORG_ID}"
  else
    gcloud projects create "${PROJECT_ID}" --name="${PROJECT_ID}"
  fi

  BILLING_ACCOUNT="$(gcloud billing accounts list --filter="open=true" --format="value(ACCOUNT_ID)" | head -n 1 || true)"
  if [[ -n "${BILLING_ACCOUNT}" ]]; then
    echo "  -> Linking active billing account '${BILLING_ACCOUNT}' to '${PROJECT_ID}'..."
    gcloud billing projects link "${PROJECT_ID}" --billing-account="${BILLING_ACCOUNT}" >/dev/null
  fi
fi

gcloud config set project "${PROJECT_ID}" >/dev/null

# Enable core bootstrap APIs so network/subnet discovery succeeds even on brand-new projects
if [[ "${DRY_RUN}" == "false" ]]; then
  echo "[1/6] Ensuring bootstrap APIs (serviceusage, compute, cloudresourcemanager, orgpolicy) are enabled..."
  gcloud services enable \
    serviceusage.googleapis.com \
    cloudresourcemanager.googleapis.com \
    compute.googleapis.com \
    orgpolicy.googleapis.com \
    --project="${PROJECT_ID}" >/dev/null
fi

# Auto-detect whether the 'default' subnetwork exists in REGION
if [[ "${CREATE_VPC}" == "auto" ]]; then
  if gcloud compute networks subnets describe default --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "[1/6] Detected existing 'default' subnetwork in ${REGION}. Using existing 'default' VPC."
    CREATE_VPC="false"
  else
    echo "[1/6] Subnetwork 'default' not found in ${PROJECT_ID} (${REGION}). Will provision dedicated 'codemender-vpc' & 'codemender-subnet'."
    CREATE_VPC="true"
  fi
fi

# Determine GKE deletion protection (preserve true only if cluster already exists with deletionProtection=true)
GKE_DELETION_PROTECTION="false"
EXISTING_DP="$(gcloud container clusters describe codemender-sandbox-cluster --region="${REGION}" --project="${PROJECT_ID}" --format="value(deletionProtection)" 2>/dev/null || true)"
if [[ "${EXISTING_DP}" == "True" || "${EXISTING_DP}" == "true" ]]; then
  GKE_DELETION_PROTECTION="true"
fi

IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/codemender-repo/codemender-dispatcher:latest"
TF_IMAGE_VAR=""
if [[ "${DEPLOY_CLOUD_RUN}" == "true" && "${SKIP_IMAGE_BUILD}" == "true" ]]; then
  TF_IMAGE_VAR="${IMAGE_URI}"
fi

# 2. Generate git-ignored terraform/terraform.tfvars
echo "[2/6] Writing git-ignored ${TF_DIR}/terraform.tfvars (create_vpc=${CREATE_VPC})..."
cat <<EOF > "${TF_DIR}/terraform.tfvars"
org_domain                  = "${ORG_DOMAIN}"
admin_user                  = "${ADMIN_USER}"
project_id                  = "${PROJECT_ID}"
create_project              = false
region                      = "${REGION}"
create_vpc                  = ${CREATE_VPC}
vpc_network_name            = "default"
vpc_subnetwork_name         = "default"
gke_deletion_protection     = ${GKE_DELETION_PROTECTION}
manage_argolis_org_policies = ${MANAGE_ORG_POLICIES}
deploy_cloud_run            = ${DEPLOY_CLOUD_RUN}
dispatcher_image            = "${TF_IMAGE_VAR}"
EOF

# 3. Initialize Terraform & Isolate State per Project
echo "[3/6] Initializing Terraform in ${TF_DIR}..."
terraform -chdir="${TF_DIR}" init -input=false

# Isolate state per project if default state belongs to a different project
DEFAULT_STATE_PROJECT="$(terraform -chdir="${TF_DIR}" output -raw pubsub_topic_id 2>/dev/null | awk -F'/' '{print $2}' || true)"
if [[ -n "${DEFAULT_STATE_PROJECT}" && "${DEFAULT_STATE_PROJECT}" != "${PROJECT_ID}" ]]; then
  echo "[3/6] Isolating Terraform state in workspace '${PROJECT_ID}'..."
  terraform -chdir="${TF_DIR}" workspace select -or-create "${PROJECT_ID}"
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[3/6] Running Terraform Plan (dry-run mode)..."
  terraform -chdir="${TF_DIR}" plan -input=false
  echo "Dry-run complete."
  exit 0
fi

echo "[3/6] Provisioning Argolis Infrastructure (APIs, Org Policies, VPC/Subnet/NAT, Artifact Registry, Pub/Sub, IAM/WIF, GKE Autopilot)..."
terraform -chdir="${TF_DIR}" apply -auto-approve -input=false

# 4. Build & Push Dispatcher Container Image to Artifact Registry and Deploy Cloud Run
if [[ "${DEPLOY_CLOUD_RUN}" == "true" ]]; then
  if [[ "${SKIP_IMAGE_BUILD}" == "false" ]]; then
    echo "[4/6] Building and pushing Dispatcher container image via Cloud Build: ${IMAGE_URI}..."
    gcloud builds submit "${REPO_ROOT}" \
      --project="${PROJECT_ID}" \
      --tag="${IMAGE_URI}" \
      --quiet
  fi

  echo "[4/6] Deploying CodeMender Dispatcher service to Cloud Run..."
  terraform -chdir="${TF_DIR}" apply -auto-approve -input=false \
    -var="dispatcher_image=${IMAGE_URI}"
else
  echo "[4/6] Skipping Cloud Run deployment (--infra-only)."
fi

# 5. Configure kubectl & Apply GKE Autopilot Hardened Manifests
echo "[5/6] Authenticating kubectl with GKE Autopilot cluster..."
gcloud container clusters get-credentials codemender-sandbox-cluster \
  --region "${REGION}" \
  --project "${PROJECT_ID}"

echo "[5/6] Applying hardened Kubernetes Namespace, ConfigMap, RBAC, and Cilium NetworkPolicies..."
kubectl apply -k "${REPO_ROOT}/k8s/overlays/gke-autopilot/"

# 6. Write git-ignored .env for local hybrid control-plane execution
echo "[6/6] Generating local .env configuration..."
cat <<EOF > "${REPO_ROOT}/.env"
GCP_PROJECT_ID=${PROJECT_ID}
PUBSUB_TOPIC_ID=codemender-security-events
K8S_NAMESPACE=codemender-executors
CODEMENDER_MODEL=gemini-4-argon
CODEMENDER_CLI_VERSION=0.14.0
EXECUTION_BACKEND=auto
EOF

echo "=============================================================================="
echo " Deployment Complete!"
echo "------------------------------------------------------------------------------"
terraform -chdir="${TF_DIR}" output
echo "=============================================================================="
