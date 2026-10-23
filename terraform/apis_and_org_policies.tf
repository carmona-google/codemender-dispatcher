# ==============================================================================
# Argolis Project Bootstrap, API Activation & Organization Policy Overrides
# ==============================================================================

data "google_organization" "argolis_org" {
  count  = var.create_project ? 1 : 0
  domain = var.org_domain
}

resource "google_project" "codemender_project" {
  count           = var.create_project ? 1 : 0
  name            = var.project_id
  project_id      = var.project_id
  org_id          = data.google_organization.argolis_org[0].org_id
  billing_account = var.billing_account != "" ? var.billing_account : null
}

locals {
  effective_project_id = var.create_project ? google_project.codemender_project[0].project_id : var.project_id

  required_apis = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "aiplatform.googleapis.com",
    "pubsub.googleapis.com",
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "orgpolicy.googleapis.com",
  ])
}

resource "google_project_service" "enabled_apis" {
  for_each           = local.required_apis
  project            = local.effective_project_id
  service            = each.key
  disable_on_destroy = false
}

# Argolis Organization Policy relaxations at the project scope
resource "google_project_organization_policy" "allow_all_domains" {
  count      = var.manage_argolis_org_policies ? 1 : 0
  project    = local.effective_project_id
  constraint = "iam.allowedPolicyMemberDomains"

  list_policy {
    allow {
      all = true
    }
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_project_organization_policy" "allow_vm_external_ip" {
  count      = var.manage_argolis_org_policies ? 1 : 0
  project    = local.effective_project_id
  constraint = "compute.vmExternalIpAccess"

  list_policy {
    allow {
      all = true
    }
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_project_organization_policy" "disable_require_shielded_vm" {
  count      = var.manage_argolis_org_policies ? 1 : 0
  project    = local.effective_project_id
  constraint = "compute.requireShieldedVm"

  boolean_policy {
    enforced = false
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_project_organization_policy" "disable_require_os_login" {
  count      = var.manage_argolis_org_policies ? 1 : 0
  project    = local.effective_project_id
  constraint = "compute.requireOsLogin"

  boolean_policy {
    enforced = false
  }

  depends_on = [google_project_service.enabled_apis]
}
