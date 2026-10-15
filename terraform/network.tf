# ==============================================================================
# Dedicated VPC, Subnetwork, Cloud Router & Cloud NAT for Argolis Environments
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

resource "google_compute_router" "codemender_router" {
  count   = var.create_vpc ? 1 : 0
  project = local.effective_project_id
  name    = "codemender-router"
  region  = var.region
  network = google_compute_network.codemender_vpc[0].id
}

resource "google_compute_router_nat" "codemender_nat" {
  count                              = var.create_vpc ? 1 : 0
  project                            = local.effective_project_id
  name                               = "codemender-nat"
  router                             = google_compute_router.codemender_router[0].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

locals {
  effective_network    = var.create_vpc ? google_compute_network.codemender_vpc[0].name : var.vpc_network_name
  effective_subnetwork = var.create_vpc ? google_compute_subnetwork.codemender_subnet[0].name : var.vpc_subnetwork_name
}
