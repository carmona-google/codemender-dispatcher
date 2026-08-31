variable "project_id" {
  type        = string
  description = "Google Cloud Project ID (e.g., your-argolis-project-id)"
}

variable "region" {
  type        = string
  description = "Google Cloud Region"
  default     = "us-central1"
}

variable "vpc_network_name" {
  type        = string
  description = "Name of the VPC Network"
  default     = "default"
}

variable "vpc_subnetwork_name" {
  type        = string
  description = "Name of the VPC Subnetwork"
  default     = "default"
}
