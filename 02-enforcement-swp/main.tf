locals {
  enforcement_apis = [
    "networkservices.googleapis.com",
    "networksecurity.googleapis.com",
    "certificatemanager.googleapis.com",
    "networkconnectivity.googleapis.com",
  ]
}

resource "google_project_service" "enforcement_apis" {
  for_each           = toset(local.enforcement_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

data "google_compute_network" "workload_vpc" {
  name    = var.vpc_name
  project = var.project_id
}

data "google_compute_subnetwork" "workload_subnet" {
  name    = var.workload_subnet_name
  region  = var.region
  project = var.project_id
}

# 1. Required Regional Proxy-Only Subnet for Secure Web Proxy
resource "google_compute_subnetwork" "swp_proxy_subnet" {
  name          = "${var.vpc_name}-swp-proxy-subnet"
  project       = var.project_id
  region        = var.region
  network       = data.google_compute_network.workload_vpc.id
  ip_cidr_range = var.proxy_only_subnet_cidr
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

# 2. Sandbox Self-Managed Certificate for SWP Gateway initialization
# In production, replace with an enterprise CA-signed certificate via Certificate Manager.
resource "tls_private_key" "swp_sandbox_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "swp_sandbox_cert" {
  private_key_pem = tls_private_key.swp_sandbox_key.private_key_pem

  subject {
    common_name  = "swp-ai-egress.internal"
    organization = "Sandbox AI Egress Governance"
  }

  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "google_certificate_manager_certificate" "swp_cert" {
  name        = "ai-egress-swp-cert"
  project     = var.project_id
  location    = var.region
  description = "Regional certificate attached to the Secure Web Proxy gateway."

  self_managed {
    pem_certificate = tls_self_signed_cert.swp_sandbox_cert.cert_pem
    pem_private_key = tls_private_key.swp_sandbox_key.private_key_pem
  }

  depends_on = [google_project_service.enforcement_apis]
}

# 3. Secure Web Proxy Gateway in NEXT_HOP_ROUTING_MODE (zero client proxy configuration)
resource "google_network_services_gateway" "ai_swp_next_hop" {
  name                                 = "ai-egress-swp-nexthop"
  project                              = var.project_id
  location                             = var.region
  type                                 = "SECURE_WEB_GATEWAY"
  routing_mode                         = "NEXT_HOP_ROUTING_MODE"
  scope                                = "ai-egress-scope"
  ports                                = [443]
  addresses                            = [var.swp_gateway_ip]
  network                              = data.google_compute_network.workload_vpc.id
  subnetwork                           = data.google_compute_subnetwork.workload_subnet.id
  gateway_security_policy              = google_network_security_gateway_security_policy.ai_egress_policy.id
  certificate_urls                     = [google_certificate_manager_certificate.swp_cert.id]
  delete_swg_autogen_router_on_destroy = true

  depends_on = [
    google_project_service.enforcement_apis,
    google_compute_subnetwork.swp_proxy_subnet,
  ]
}

# 4. Policy-Based Route Bypasses (DEFAULT_ROUTING)
# Critical safeguard: prevent internal VPC/PSC, IAP SSH, Metadata Server, and
# restricted.googleapis.com VIP traffic from being hijacked into Secure Web Proxy.
locals {
  pbr_bypass_destinations = {
    rfc1918-10         = { cidr = "10.0.0.0/8", priority = 100, desc = "Keep internal VPC and PSC (10.10.254.10) on default VPC routing" }
    iap-forwarding     = { cidr = "35.235.240.0/20", priority = 110, desc = "Preserve IAP SSH / TCP forwarding return traffic" }
    metadata-server    = { cidr = "169.254.169.254/32", priority = 120, desc = "Keep GCE metadata server traffic local" }
    restricted-gapis   = { cidr = "199.36.153.4/30", priority = 130, desc = "Keep restricted.googleapis.com VIP off SWP" }
  }
}

resource "google_network_connectivity_policy_based_route" "bypass_internal_and_iap" {
  for_each    = local.pbr_bypass_destinations
  name        = "pbr-bypass-${each.key}"
  project     = var.project_id
  description = each.value.desc
  network     = data.google_compute_network.workload_vpc.id
  priority    = each.value.priority

  filter {
    protocol_version = "IPV4"
    ip_protocol      = "ALL"
    src_range        = var.workload_subnet_cidr
    dest_range       = each.value.cidr
  }

  next_hop_other_routes = "DEFAULT_ROUTING"

  virtual_machine {
    tags = [var.governed_vm_tag]
  }

  depends_on = [google_project_service.enforcement_apis]
}

# 5. Transparent Egress Steering PBR -> Secure Web Proxy
resource "google_network_connectivity_policy_based_route" "steer_egress_to_swp" {
  name        = "pbr-steer-ai-egress-to-swp"
  project     = var.project_id
  description = "Transparently routes outbound TCP internet traffic from governed workloads to Secure Web Proxy."
  network     = data.google_compute_network.workload_vpc.id
  priority    = 500

  filter {
    protocol_version = "IPV4"
    ip_protocol      = "TCP"
    src_range        = var.workload_subnet_cidr
    dest_range       = "0.0.0.0/0"
  }

  next_hop_ilb_ip = google_network_services_gateway.ai_swp_next_hop.addresses[0]

  virtual_machine {
    tags = [var.governed_vm_tag]
  }

  depends_on = [
    google_network_services_gateway.ai_swp_next_hop,
    google_network_connectivity_policy_based_route.bypass_internal_and_iap,
  ]
}

# 6. Firewall Guard: Block outbound UDP/443 (QUIC/HTTP3) on governed workloads
# Forces modern clients to negotiate HTTPS over TCP/443 through SWP instead of bypassing on UDP.
resource "google_compute_firewall" "deny_quic_egress_bypass" {
  name               = "${var.vpc_name}-deny-quic-egress"
  project            = var.project_id
  network            = data.google_compute_network.workload_vpc.id
  direction          = "EGRESS"
  priority           = 900
  target_tags        = [var.governed_vm_tag]
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "udp"
    ports    = ["443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
