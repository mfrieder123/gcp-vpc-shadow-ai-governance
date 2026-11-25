locals {
  required_apis = [
    "compute.googleapis.com",
    "dns.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "bigquery.googleapis.com",
    "networkmanagement.googleapis.com",
    "aiplatform.googleapis.com",
  ]
}

# 1. Enable required Google Cloud APIs
resource "google_project_service" "discovery_apis" {
  for_each           = toset(local.required_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# 2. Workload VPC & Subnet with full-metadata VPC Flow Logs
resource "google_compute_network" "workload_vpc" {
  name                    = var.vpc_name
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.discovery_apis]
}

resource "google_compute_subnetwork" "workload_subnet" {
  name                     = var.workload_subnet_name
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.workload_vpc.id
  ip_cidr_range            = var.workload_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_MIN"
    flow_sampling        = var.flow_sampling
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# 3. Cloud DNS Query Logging Policy attached to the workload VPC
resource "google_dns_policy" "vpc_dns_logging" {
  name           = "${var.vpc_name}-dns-logging"
  project        = var.project_id
  description    = "Captures outbound DNS queries for VPC-layer Shadow AI discovery."
  enable_logging = true

  networks {
    network_url = google_compute_network.workload_vpc.id
  }

  depends_on = [google_project_service.discovery_apis]
}

# 4. Dedicated Log Analytics Bucket + Linked BigQuery Dataset + Log Sink
# Using a dedicated bucket avoids mutating the project's _Default bucket.
resource "google_logging_project_bucket_config" "shadow_ai_audit_bucket" {
  project          = var.project_id
  location         = "global"
  bucket_id        = "shadow_ai_audit"
  retention_days   = var.log_retention_days
  enable_analytics = true
  description      = "Log Analytics bucket storing Cloud DNS query logs and VPC Flow Logs for Shadow AI audits."

  depends_on = [google_project_service.discovery_apis]
}

resource "google_logging_linked_dataset" "shadow_ai_audit_bq" {
  link_id     = "shadow_ai_audit_logs"
  bucket      = google_logging_project_bucket_config.shadow_ai_audit_bucket.id
  description = "BigQuery linked dataset exposing the shadow_ai_audit Log Analytics bucket."
}

resource "google_logging_project_sink" "shadow_ai_telemetry_sink" {
  name        = "shadow-ai-dns-and-flow-sink"
  project     = var.project_id
  destination = "logging.googleapis.com/${google_logging_project_bucket_config.shadow_ai_audit_bucket.id}"
  filter      = <<-EOT
    logName="projects/${var.project_id}/logs/dns.googleapis.com%2Fdns_queries" OR
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
  EOT

  unique_writer_identity = true
}

# 5. Optional Sandbox Cloud NAT (allows private no-external-IP test VMs to run Phase 1 baseline)
resource "google_compute_router" "sandbox_router" {
  count   = var.enable_sandbox_nat ? 1 : 0
  name    = "${var.vpc_name}-sandbox-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.workload_vpc.id
}

resource "google_compute_router_nat" "sandbox_nat" {
  count                              = var.enable_sandbox_nat ? 1 : 0
  name                               = "${var.vpc_name}-sandbox-nat"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.sandbox_router[0].name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
