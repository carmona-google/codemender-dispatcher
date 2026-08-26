"""Google Cloud Pub/Sub event publisher with DLP sanitization."""

import json
import logging
from typing import Optional

from .schemas import CodeMenderSecurityEvent
from .dlp_filter import DLPFilter

logger = logging.getLogger(__name__)

try:
    from google.cloud import pubsub_v1
    GCP_PUBSUB_AVAILABLE = True
except ImportError:
    GCP_PUBSUB_AVAILABLE = False


class ITSMPubSubPublisher:
    """Publishes sanitized security findings and PR notifications to Cloud Pub/Sub."""

    def __init__(self, project_id: str, topic_id: str, enable_mock: bool = False):
        self.project_id = project_id
        self.topic_id = topic_id
        self.enable_mock = enable_mock
        self.publisher = None
        self.topic_path = None

        if GCP_PUBSUB_AVAILABLE and not enable_mock:
            try:
                self.publisher = pubsub_v1.PublisherClient()
                self.topic_path = self.publisher.topic_path(project_id, topic_id)
            except Exception as e:
                logger.warning("Failed to initialize GCP Pub/Sub client (%s). Fallback to mock active.", e)
                self.publisher = None

    def publish_event(self, event: CodeMenderSecurityEvent) -> str:
        """Sanitizes and publishes event payload."""
        # 1. Convert Pydantic model to dictionary
        raw_dict = event.model_dump()

        # 2. Enforce local DLP Sanitization
        sanitized_dict = DLPFilter.sanitize_event_dict(raw_dict)
        payload_bytes = json.dumps(sanitized_dict).encode("utf-8")

        # 3. Publish to Pub/Sub or Mock Buffer
        if self.publisher is not None and self.topic_path is not None:
            future = self.publisher.publish(
                self.topic_path,
                data=payload_bytes,
                event_type=event.event_type.value,
                session_id=event.session_id,
            )
            message_id = future.result()
            logger.info("Published Pub/Sub event %s for session %s", message_id, event.session_id)
            return message_id
        else:
            logger.info("[MOCK-PUBSUB] Event '%s' published for session '%s'", event.event_type.value, event.session_id)
            return f"mock-msg-{event.event_id}"
