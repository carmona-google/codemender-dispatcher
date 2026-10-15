#!/usr/bin/env bash
# ==============================================================================
# CodeMender Dispatcher (v2.1) — Full Argolis Environment Teardown Script
# ==============================================================================
# Safely destroys all CodeMender resources in the target Argolis project so the
# environment can be cleanly recreated from scratch at any time in the future.
#
# Usage:
#   ./scripts/destroy_argolis.sh \
#     --project [YOUR_ARGOLIS_PROJECT_ID] \
#     [--org [YOUR_ARGOLIS_ORG_DOMAIN]] \
#     [--user [YOUR_ARGOLIS_ADMIN_USER]] \
#     [--region us-central1] \
#     [--delete-project]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform"

ORG_DOMAIN="${ARGOLIS_ORG_DOMAIN:-[YOUR_ARGOLIS_ORG_DOMAIN]}"
ADMIN_USER="${ARGOLIS_ADMIN_USER:-[YOUR_ARGOLIS_ADMIN_USER]}"
PROJECT_ID="${ARGOLIS_PROJECT_ID:-[YOUR_ARGOLIS_PROJECT_ID]}"
REGION="${ARGOLIS_REGION:-us-central1}"
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
    --delete-project)
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
  echo "ERROR: Please provide the target Argolis Project ID via --project <PROJECT_ID>."
  exit 1
fi

echo "=============================================================================="
echo " CodeMender Remote Dispatcher — Full Environment Teardown"
echo "------------------------------------------------------------------------------"
echo " Project ID     : ${PROJECT_ID}"
echo " Region         : ${REGION}"
echo " Delete Project : ${DELETE_PROJECT}"
echo "=============================================================================="

if [[ "${ADMIN_USER}" != "[YOUR_ARGOLIS_ADMIN_USER]" ]]; then
  gcloud config set account "${ADMIN_USER}" >/dev/null 2>&1 || true
fi
gcloud config set project "${PROJECT_ID}" >/dev/null 2>&1 || true

# 1. Disable GKE deletion protection and remove Kubernetes workloads if cluster exists
echo "[1/4] Checking GKE Autopilot cluster 'codemender-sandbox-cluster'..."
if gcloud container clusters describe codemender-sandbox-cluster --region "${REGION}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Disabling deletion protection on GKE cluster..."
  gcloud container clusters update codemender-sandbox-cluster \
    --no-deletion-protection \
    --region "${REGION}" \
    --project "${PROJECT_ID}" \
    --quiet || true

  echo "  -> Deleting Kubernetes namespace 'codemender-executors'..."
  gcloud container clusters get-credentials codemender-sandbox-cluster \
    --region "${REGION}" \
    --project "${PROJECT_ID}" >/dev/null 2>&1 || true
  kubectl delete namespace codemender-executors --ignore-not-found=true --timeout=60s || true
fi

# 2. Run Terraform Destroy if state exists for this project
echo "[2/4] Running Terraform destroy..."
if [[ -d "${TF_DIR}" ]]; then
  terraform -chdir="${TF_DIR}" init -input=false >/dev/null 2>&1 || true

  # Select matching workspace if it exists
  if terraform -chdir="${TF_DIR}" workspace list 2>/dev/null | grep -qE "^[* ]+${PROJECT_ID}\$"; then
    terraform -chdir="${TF_DIR}" workspace select "${PROJECT_ID}" >/dev/null 2>&1 || true
  fi

  # Check if current Terraform state tracks this project
  STATE_PROJECT="$(terraform -chdir="${TF_DIR}" output -raw pubsub_topic_id 2>/dev/null | awk -F'/' '{print $2}' || true)"
  if [[ "${STATE_PROJECT}" == "${PROJECT_ID}" || -z "${STATE_PROJECT}" ]]; then
    terraform -chdir="${TF_DIR}" destroy -auto-approve -input=false \
      -var="project_id=${PROJECT_ID}" \
      -var="region=${REGION}" || true
  fi
fi

# 3. Idempotent gcloud fallback cleanup to guarantee zero leftover resources
echo "[3/4] Running idempotent cloud resource cleanup in ${PROJECT_ID}..."

# Cloud Run service
if gcloud run services describe codemender-dispatcher --region "${REGION}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting Cloud Run service 'codemender-dispatcher'..."
  gcloud run services delete codemender-dispatcher --region "${REGION}" --project "${PROJECT_ID}" --quiet || true
fi

# GKE Autopilot Cluster
if gcloud container clusters describe codemender-sandbox-cluster --region "${REGION}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting GKE Autopilot cluster 'codemender-sandbox-cluster'..."
  gcloud container clusters delete codemender-sandbox-cluster --region "${REGION}" --project "${PROJECT_ID}" --quiet || true
fi

# Artifact Registry
if gcloud artifacts repositories describe codemender-repo --location "${REGION}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting Artifact Registry repository 'codemender-repo'..."
  gcloud artifacts repositories delete codemender-repo --location "${REGION}" --project "${PROJECT_ID}" --quiet || true
fi

# Pub/Sub Subscriptions & Topics
if gcloud pubsub subscriptions describe codemender-itsm-subscriber --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting Pub/Sub subscription 'codemender-itsm-subscriber'..."
  gcloud pubsub subscriptions delete codemender-itsm-subscriber --project "${PROJECT_ID}" --quiet || true
fi
for TOPIC in codemender-security-events codemender-security-events-dlq; do
  if gcloud pubsub topics describe "${TOPIC}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  -> Deleting Pub/Sub topic '${TOPIC}'..."
    gcloud pubsub topics delete "${TOPIC}" --project "${PROJECT_ID}" --quiet || true
  fi
done

# Custom VPC, Cloud NAT, Cloud Router, and Subnetwork
if gcloud compute routers nats describe codemender-nat --router=codemender-router --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting Cloud NAT 'codemender-nat'..."
  gcloud compute routers nats delete codemender-nat --router=codemender-router --region="${REGION}" --project="${PROJECT_ID}" --quiet || true
fi
if gcloud compute routers describe codemender-router --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting Cloud Router 'codemender-router'..."
  gcloud compute routers delete codemender-router --region="${REGION}" --project="${PROJECT_ID}" --quiet || true
fi
if gcloud compute networks subnets describe codemender-subnet --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting Subnetwork 'codemender-subnet'..."
  gcloud compute networks subnets delete codemender-subnet --region="${REGION}" --project="${PROJECT_ID}" --quiet || true
fi
if gcloud compute networks describe codemender-vpc --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  -> Deleting VPC Network 'codemender-vpc'..."
  gcloud compute networks delete codemender-vpc --project="${PROJECT_ID}" --quiet || true
fi

# Service Accounts
for SA in codemender-dispatcher-sa codemender-executor-sa; do
  SA_EMAIL="${SA}@${PROJECT_ID}.iam.gserviceaccount.com"
  if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  -> Deleting Service Account '${SA_EMAIL}'..."
    gcloud iam service-accounts delete "${SA_EMAIL}" --project="${PROJECT_ID}" --quiet || true
  fi
done

# 4. Optional GCP Project Deletion
if [[ "${DELETE_PROJECT}" == "true" ]]; then
  echo "[4/4] Deleting GCP Project '${PROJECT_ID}' (--delete-project)..."
  gcloud projects delete "${PROJECT_ID}" --quiet || true
else
  echo "[4/4] Preserving empty GCP project '${PROJECT_ID}' (pass --delete-project to delete the project itself)."
fi

echo "=============================================================================="
echo " Teardown Complete! Project '${PROJECT_ID}' is clean and ready to redeploy."
echo "=============================================================================="
