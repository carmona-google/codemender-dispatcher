# ==============================================================================
# Google Cloud Pub/Sub Topic & Subscriptions for Decoupled ITSM
# ==============================================================================

resource "google_pubsub_topic" "codemender_security_events" {
  name = "codemender-security-events"

  message_retention_duration = "604800s" # 7 Days retention

  labels = {
    app       = "codemender"
    component = "itsm-event-bus"
  }
}

# Dead Letter Topic
resource "google_pubsub_topic" "codemender_dead_letter" {
  name = "codemender-security-events-dlq"
}

# Example Subscription with Dead Letter Policy
resource "google_pubsub_subscription" "itsm_sync_subscription" {
  name  = "codemender-itsm-subscriber"
  topic = google_pubsub_topic.codemender_security_events.name

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.codemender_dead_letter.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}
