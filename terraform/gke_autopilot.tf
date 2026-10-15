# ==============================================================================
# Private GKE Autopilot Cluster with Datapath V2 (Cilium eBPF)
# ==============================================================================

resource "google_container_cluster" "codemender_cluster" {
  name     = "codemender-sandbox-cluster"
  location = var.region

  enable_autopilot    = true
  deletion_protection = var.gke_deletion_protection

  network    = local.effective_network
  subnetwork = local.effective_subnetwork

  ip_allocation_policy {}

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  datapath_provider = "ADVANCED_DATAPATH" # Enables Cilium eBPF for NetworkPolicies

  addons_config {
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_compute_subnetwork.codemender_subnet,
    google_compute_router_nat.codemender_nat,
  ]
}
