# The Golden Path: Private Service Connect (PSC) for Google APIs (vpc-sc bundle)
# Keeps Vertex AI / Model Garden / Gemini traffic completely private inside the VPC
# and ready for VPC Service Controls perimeter enforcement.

resource "google_compute_global_address" "psc_vpc_sc_ip" {
  name         = "psc-vpc-sc-ip"
  project      = var.project_id
  address_type = "INTERNAL"
  purpose      = "PRIVATE_SERVICE_CONNECT"
  network      = data.google_compute_network.workload_vpc.id
  address      = var.psc_google_apis_ip
}

# Note: Google API PSC forwarding rule names MUST be 1-20 lowercase alphanumeric chars (no hyphens).
resource "google_compute_global_forwarding_rule" "psc_vpc_sc" {
  name                  = "pscvpcscai"
  project               = var.project_id
  network               = data.google_compute_network.workload_vpc.id
  ip_address            = google_compute_global_address.psc_vpc_sc_ip.id
  target                = "vpc-sc"
  load_balancing_scheme = ""
}

# Private Cloud DNS Zone routing *.googleapis.com -> internal PSC IP
# Note on generativelanguage.googleapis.com (Consumer AI Studio):
#   Because *.googleapis.com resolves to the internal vpc-sc PSC IP (10.10.254.10),
#   generativelanguage.googleapis.com traffic stays off SWP and is governed by
#   VPC Service Controls (blocking personal/external-project API keys at the perimeter,
#   or blocked completely when the API is disabled via Service Usage / Org Policy).
#   Keeping generativelanguage.googleapis.com in SWP's blocked_shadow_ai_domains list
#   provides defense-in-depth for any VPC not using this Private Cloud DNS zone.
resource "google_dns_managed_zone" "private_googleapis" {
  name        = "private-googleapis-zone"
  project     = var.project_id
  dns_name    = "googleapis.com."
  description = "Routes Google APIs privately to the internal vpc-sc PSC endpoint."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = data.google_compute_network.workload_vpc.id
    }
  }
}

resource "google_dns_record_set" "googleapis_wildcard" {
  name         = "*.${google_dns_managed_zone.private_googleapis.dns_name}"
  project      = var.project_id
  managed_zone = google_dns_managed_zone.private_googleapis.name
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.psc_vpc_sc_ip.address]
}

resource "google_dns_record_set" "googleapis_apex" {
  name         = google_dns_managed_zone.private_googleapis.dns_name
  project      = var.project_id
  managed_zone = google_dns_managed_zone.private_googleapis.name
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.psc_vpc_sc_ip.address]
}
