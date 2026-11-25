# =============================================================================
# Optional Reference Blueprint: Multi-VPC Scaling via NCC Star Hub
# =============================================================================
# For enterprise organizations with dozens of workload VPCs, avoid deploying a
# separate Secure Web Proxy in every VPC. Instead:
#   1. Attach your central Egress / Security Transit VPC (hosting SWP + PSC) to
#      the NCC "center" group.
#   2. Attach workload VPCs to the NCC "edge" group (edge spokes cannot talk to
#      each other directly, only through the center transit VPC).
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.40.0, < 7.0.0"
    }
  }
}

variable "project_id" {
  description = "Host project ID for the centralized Network Connectivity Center hub."
  type        = string
}

variable "egress_transit_vpc_uri" {
  description = "Self-link URI of the central Security/Egress VPC hosting Secure Web Proxy."
  type        = string
}

variable "workload_spoke_vpc_uris" {
  description = "Map of spoke names to workload VPC self-link URIs to attach to the NCC edge group."
  type        = map(string)
}

resource "google_network_connectivity_hub" "ai_egress_star_hub" {
  name            = "ai-egress-star-hub"
  project         = var.project_id
  description     = "Centralized Star-topology NCC Hub for multi-VPC Shadow AI egress governance."
  policy_mode     = "PRESET"
  preset_topology = "STAR"
}

resource "google_network_connectivity_group" "center_group" {
  name    = "center"
  project = var.project_id
  hub     = google_network_connectivity_hub.ai_egress_star_hub.id

  auto_accept {
    auto_accept_projects = [var.project_id]
  }
}

resource "google_network_connectivity_group" "edge_group" {
  name    = "edge"
  project = var.project_id
  hub     = google_network_connectivity_hub.ai_egress_star_hub.id

  auto_accept {
    auto_accept_projects = [var.project_id]
  }
}

# Center spoke: Security / Egress Transit VPC hosting Secure Web Proxy
resource "google_network_connectivity_spoke" "egress_transit_center" {
  name        = "egress-transit-center-spoke"
  project     = var.project_id
  location    = "global"
  description = "Central egress VPC hosting Secure Web Proxy and PSC endpoints."
  hub         = google_network_connectivity_hub.ai_egress_star_hub.id
  group       = google_network_connectivity_group.center_group.id

  linked_vpc_network {
    uri = var.egress_transit_vpc_uri
  }
}

# Edge spokes: Isolated workload VPCs
resource "google_network_connectivity_spoke" "workload_edge_spokes" {
  for_each    = var.workload_spoke_vpc_uris
  name        = "workload-edge-${each.key}"
  project     = var.project_id
  location    = "global"
  description = "Workload VPC spoke governed via central NCC egress hub."
  hub         = google_network_connectivity_hub.ai_egress_star_hub.id
  group       = google_network_connectivity_group.edge_group.id

  linked_vpc_network {
    uri = each.value
  }
}
