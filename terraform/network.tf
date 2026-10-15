# ==============================================================================
# Optional Dedicated VPC & Subnetwork for Argolis Environments
# ==============================================================================

resource "google_compute_network" "codemender_vpc" {
  count                   = var.create_vpc ? 1 : 0
  project                 = local.effective_project_id
  name                    = "codemender-vpc"
  auto_create_subnetworks = false

  depends_on = [google_project_service.enabled_apis]
}

resource "google_compute_subnetwork" "codemender_subnet" {
  count                    = var.create_vpc ? 1 : 0
  project                  = local.effective_project_id
  name                     = "codemender-subnet"
  ip_cidr_range            = "10.10.0.0/20"
  region                   = var.region
  network                  = google_compute_network.codemender_vpc[0].id
  private_ip_google_access = true
}

locals {
  effective_network    = var.create_vpc ? google_compute_network.codemender_vpc[0].name : var.vpc_network_name
  effective_subnetwork = var.create_vpc ? google_compute_subnetwork.codemender_subnet[0].name : var.vpc_subnetwork_name
}
