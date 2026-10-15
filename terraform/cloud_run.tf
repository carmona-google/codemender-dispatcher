# ==============================================================================
# Artifact Registry & Cloud Run Service for CodeMender Dispatcher Control Plane
# ==============================================================================

resource "google_artifact_registry_repository" "codemender_repo" {
  project       = local.effective_project_id
  location      = var.region
  repository_id = "codemender-repo"
  description   = "Container repository for CodeMender Dispatcher and Ephemeral Sandbox images"
  format        = "DOCKER"

  depends_on = [google_project_service.enabled_apis]
}

resource "google_cloud_run_v2_service" "codemender_dispatcher" {
  count    = var.deploy_cloud_run && var.dispatcher_image != "" ? 1 : 0
  project  = local.effective_project_id
  name     = "codemender-dispatcher"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.codemender_dispatcher_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = var.dispatcher_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = local.effective_project_id
      }
      env {
        name  = "PUBSUB_TOPIC_ID"
        value = google_pubsub_topic.codemender_security_events.name
      }
      env {
        name  = "K8S_NAMESPACE"
        value = "codemender-executors"
      }
      env {
        name  = "CODEMENDER_MODEL"
        value = "gemini-4-argon"
      }
      env {
        name  = "CODEMENDER_CLI_VERSION"
        value = "0.14.0"
      }
      env {
        name  = "EXECUTION_BACKEND"
        value = "auto"
      }
    }
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_artifact_registry_repository.codemender_repo,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "admin_invoker" {
  count    = var.deploy_cloud_run && var.dispatcher_image != "" && !startswith(var.admin_user, "[") ? 1 : 0
  project  = local.effective_project_id
  location = var.region
  name     = google_cloud_run_v2_service.codemender_dispatcher[0].name
  role     = "roles/run.invoker"
  member   = "user:${var.admin_user}"
}
