# ==============================================================================
# Workload Identity Federation (WIF) & Least-Privileged IAM
# ==============================================================================

# Service Account for Dispatcher
resource "google_service_account" "codemender_dispatcher_sa" {
  account_id   = "codemender-dispatcher-sa"
  display_name = "CodeMender Dispatcher Control Plane Service Account"
}

# Grant Pub/Sub Publisher role strictly to the Dispatcher
resource "google_pubsub_topic_iam_member" "dispatcher_pubsub_publisher" {
  topic  = google_pubsub_topic.codemender_security_events.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.codemender_dispatcher_sa.email}"
}

# Service Account for Execution Engine Sandbox
resource "google_service_account" "codemender_executor_sa" {
  account_id   = "codemender-executor-sa"
  display_name = "CodeMender Ephemeral Executor Service Account"
}

# Grant Vertex AI / Gemini Enterprise access to Executor
resource "google_project_iam_member" "executor_aiplatform_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.codemender_executor_sa.email}"
}

# GKE Workload Identity User Binding
resource "google_service_account_iam_member" "executor_k8s_wif_binding" {
  service_account_id = google_service_account.codemender_executor_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[codemender-executors/codemender-executor-ksa]"
}
