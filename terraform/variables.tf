variable "org_domain" {
  type        = string
  description = "Argolis Google Cloud Organization domain (e.g., [YOUR_ARGOLIS_ORG_DOMAIN])"
  default     = "[YOUR_ARGOLIS_ORG_DOMAIN]"
}

variable "admin_user" {
  type        = string
  description = "Argolis administrator user email (e.g., [YOUR_ARGOLIS_ADMIN_USER])"
  default     = "[YOUR_ARGOLIS_ADMIN_USER]"
}

variable "project_id" {
  type        = string
  description = "Google Cloud Project ID (e.g., [YOUR_ARGOLIS_PROJECT_ID])"
}

variable "create_project" {
  type        = bool
  description = "Whether to create a new GCP project under the Argolis organization"
  default     = false
}

variable "billing_account" {
  type        = string
  description = "Billing Account ID (required only when create_project = true)"
  default     = ""
}

variable "region" {
  type        = string
  description = "Google Cloud Region for GKE Autopilot, Cloud Run, and Artifact Registry"
  default     = "us-central1"
}

variable "create_vpc" {
  type        = bool
  description = "Whether to provision a dedicated VPC network, subnetwork, and Cloud NAT (recommended for Argolis projects where default network is absent)"
  default     = true
}

variable "vpc_network_name" {
  type        = string
  description = "Name of the existing VPC Network when create_vpc = false"
  default     = "default"
}

variable "vpc_subnetwork_name" {
  type        = string
  description = "Name of the existing VPC Subnetwork when create_vpc = false"
  default     = "default"
}

variable "gke_deletion_protection" {
  type        = bool
  description = "Whether to enable GKE deletion protection (set to false to allow clean terraform destroy and environment recreation)"
  default     = false
}

variable "manage_argolis_org_policies" {
  type        = bool
  description = "Whether to relax restrictive default Argolis Organization Policies at the project level"
  default     = true
}

variable "deploy_cloud_run" {
  type        = bool
  description = "Whether to deploy the CodeMender Dispatcher control plane to Cloud Run"
  default     = true
}

variable "dispatcher_image" {
  type        = string
  description = "Container image URI for the CodeMender Dispatcher Cloud Run service"
  default     = ""
}
