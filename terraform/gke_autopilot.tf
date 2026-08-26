# ==============================================================================
# Private GKE Autopilot Cluster with Datapath V2 (Cilium eBPF)
# ==============================================================================

resource "google_container_cluster" "codemender_cluster" {
  name     = "codemender-sandbox-cluster"
  location = var.region

  enable_autopilot = true

  network    = var.vpc_network_name
  subnetwork = var.vpc_subnetwork_name

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
}
