#!/usr/bin/env bash
# ==============================================================================
# CodeMender Dispatcher (v2.1) — Automated Argolis GCP Deployment Script
# ==============================================================================
# Usage:
#   ./scripts/deploy_argolis.sh \
#     --org [YOUR_ARGOLIS_ORG_DOMAIN] \
#     --user [YOUR_ARGOLIS_ADMIN_USER] \
#     --project [YOUR_ARGOLIS_PROJECT_ID] \
#     [--region us-central1] \
#     [--create-vpc] \
#     [--manage-org-policies] \
#     [--skip-image-build] \
#     [--dry-run]
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
CREATE_VPC="false"
MANAGE_ORG_POLICIES="false"
DEPLOY_CLOUD_RUN="true"
SKIP_IMAGE_BUILD="false"
DRY_RUN="false"

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
    --manage-org-policies)
      MANAGE_ORG_POLICIES="true"
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

echo "=============================================================================="
echo " CodeMender Remote Dispatcher — Argolis Deployment"
echo "------------------------------------------------------------------------------"
echo " Organization : ${ORG_DOMAIN}"
echo " Admin User   : ${ADMIN_USER}"
echo " Project ID   : ${PROJECT_ID}"
echo " Region       : ${REGION}"
echo " Cloud Run    : ${DEPLOY_CLOUD_RUN}"
echo " Dry Run      : ${DRY_RUN}"
echo "=============================================================================="

# 1. Verify gcloud authentication and configure active project
if [[ "${ADMIN_USER}" != "[YOUR_ARGOLIS_ADMIN_USER]" ]]; then
  echo "[1/6] Setting active gcloud account to ${ADMIN_USER}..."
  gcloud config set account "${ADMIN_USER}" >/dev/null
fi

echo "[1/6] Setting active gcloud project to ${PROJECT_ID}..."
gcloud config set project "${PROJECT_ID}" >/dev/null

IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/codemender-repo/codemender-dispatcher:latest"
TF_IMAGE_VAR=""
if [[ "${DEPLOY_CLOUD_RUN}" == "true" && "${SKIP_IMAGE_BUILD}" == "true" ]]; then
  TF_IMAGE_VAR="${IMAGE_URI}"
fi

# 2. Generate git-ignored terraform/terraform.tfvars
echo "[2/6] Writing git-ignored ${TF_DIR}/terraform.tfvars..."
cat <<EOF > "${TF_DIR}/terraform.tfvars"
org_domain                  = "${ORG_DOMAIN}"
admin_user                  = "${ADMIN_USER}"
project_id                  = "${PROJECT_ID}"
create_project              = ${CREATE_PROJECT}
region                      = "${REGION}"
create_vpc                  = ${CREATE_VPC}
vpc_network_name            = "default"
vpc_subnetwork_name         = "default"
manage_argolis_org_policies = ${MANAGE_ORG_POLICIES}
deploy_cloud_run            = ${DEPLOY_CLOUD_RUN}
dispatcher_image            = "${TF_IMAGE_VAR}"
EOF

# 3. Initialize and Plan/Apply Terraform Base Infrastructure
echo "[3/6] Initializing Terraform in ${TF_DIR}..."
terraform -chdir="${TF_DIR}" init -input=false

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[3/6] Running Terraform Plan (dry-run mode)..."
  terraform -chdir="${TF_DIR}" plan -input=false
  echo "Dry-run complete."
  exit 0
fi

echo "[3/6] Provisioning Argolis Infrastructure (APIs, Artifact Registry, Pub/Sub, IAM/WIF, GKE Autopilot)..."
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
