# ==============================================================================
# Workload Identity Federation (WIF) & Least-Privileged IAM
# ==============================================================================

data "google_project" "current" {
  project_id = local.effective_project_id
  depends_on = [google_project_service.enabled_apis]
}

# Argolis Guardrail: When `iam.automaticIamGrantsForDefaultServiceAccounts` is
# enforced in Argolis, the default Compute Engine service account used by Cloud
# Build lacks permissions to read source tarballs from GCS, write build logs, or
# push images to Artifact Registry. Grant least-privileged build roles:
resource "google_project_iam_member" "cloudbuild_compute_sa_roles" {
  for_each = toset([
    "roles/storage.objectAdmin",
    "roles/logging.logWriter",
    "roles/artifactregistry.writer",
  ])
  project = local.effective_project_id
  role    = each.key
  member  = "serviceAccount:${data.google_project.current.number}-compute@developer.gserviceaccount.com"
}

# Service Account for Dispatcher
resource "google_service_account" "codemender_dispatcher_sa" {
  account_id   = "codemender-dispatcher-sa"
  display_name = "CodeMender Dispatcher Control Plane Service Account"

  depends_on = [google_project_service.enabled_apis]
}

# Grant Pub/Sub Publisher role strictly to the Dispatcher
resource "google_pubsub_topic_iam_member" "dispatcher_pubsub_publisher" {
  topic  = google_pubsub_topic.codemender_security_events.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.codemender_dispatcher_sa.email}"
}

# Grant GKE Developer role to Dispatcher so Cloud Run can dispatch ephemeral gVisor batch jobs
resource "google_project_iam_member" "dispatcher_gke_developer" {
  project = local.effective_project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.codemender_dispatcher_sa.email}"
}

# Grant Vertex AI / Gemini Enterprise access to Dispatcher
resource "google_project_iam_member" "dispatcher_aiplatform_user" {
  project = local.effective_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.codemender_dispatcher_sa.email}"
}

# Service Account for Execution Engine Sandbox
resource "google_service_account" "codemender_executor_sa" {
  account_id   = "codemender-executor-sa"
  display_name = "CodeMender Ephemeral Executor Service Account"

  depends_on = [google_project_service.enabled_apis]
}

# Grant Vertex AI / Gemini Enterprise access to Executor
resource "google_project_iam_member" "executor_aiplatform_user" {
  project = local.effective_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.codemender_executor_sa.email}"
}

# GKE Workload Identity User Binding
resource "google_service_account_iam_member" "executor_k8s_wif_binding" {
  service_account_id = google_service_account.codemender_executor_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.effective_project_id}.svc.id.goog[codemender-executors/codemender-executor-ksa]"

  depends_on = [google_container_cluster.codemender_cluster]
}
