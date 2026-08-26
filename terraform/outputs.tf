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
  value       = "gcloud container clusters get-credentials ${google_container_cluster.codemender_cluster.name} --region ${google_container_cluster.codemender_cluster.location} --project ${var.project_id}"
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
