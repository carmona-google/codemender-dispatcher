output "gke_cluster_name" {
  description = "GKE Autopilot Cluster Name"
  value       = google_container_cluster.codemender_cluster.name
}

output "gke_cluster_location" {
  description = "GKE Autopilot Cluster Location / Region"
  value       = google_container_cluster.codemender_cluster.location
}

output "gke_get_credentials_command" {
  description = "Command to authenticate kubectl with the GKE Autopilot cluster"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.codemender_cluster.name} --region ${google_container_cluster.codemender_cluster.location} --project ${local.effective_project_id}"
}

output "artifact_registry_repo_url" {
  description = "Artifact Registry Docker repository URL"
  value       = "${var.region}-docker.pkg.dev/${local.effective_project_id}/${google_artifact_registry_repository.codemender_repo.repository_id}"
}

output "cloud_run_dispatcher_url" {
  description = "HTTPS endpoint URL for the CodeMender Dispatcher Cloud Run service (if deployed)"
  value       = length(google_cloud_run_v2_service.codemender_dispatcher) > 0 ? google_cloud_run_v2_service.codemender_dispatcher[0].uri : "Not deployed (set dispatcher_image to deploy Cloud Run)"
}

output "pubsub_topic_id" {
  description = "Google Cloud Pub/Sub Security Events Topic"
  value       = google_pubsub_topic.codemender_security_events.id
}

output "dispatcher_service_account_email" {
  description = "Service Account email for Dispatcher control plane"
  value       = google_service_account.codemender_dispatcher_sa.email
}

output "executor_service_account_email" {
  description = "Service Account email for Ephemeral Executor sandbox (WIF)"
  value       = google_service_account.codemender_executor_sa.email
}
