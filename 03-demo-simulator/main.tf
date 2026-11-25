# Security-Hardened Demo Simulator VM (compatible with strict Organization Policies):
# - Zero external IP (passes compute.vmExternalIpAccess org policy)
# - IAP-only SSH firewall rule (35.235.240.0/20) + OS Login
# - Shielded VM enabled
# - Dedicated least-privilege Service Account with Vertex AI User role

data "google_compute_network" "workload_vpc" {
  name    = var.vpc_name
  project = var.project_id
}

data "google_compute_subnetwork" "workload_subnet" {
  name    = var.workload_subnet_name
  region  = var.region
  project = var.project_id
}

resource "google_service_account" "simulator_sa" {
  account_id   = "shadow-ai-sim-sa"
  project      = var.project_id
  display_name = "Shadow AI Governance Demo Simulator SA"
}

resource "google_project_iam_member" "simulator_vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.simulator_sa.email}"
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name          = "${var.vpc_name}-allow-iap-ssh"
  project       = var.project_id
  network       = data.google_compute_network.workload_vpc.id
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["shadow-ai-simulator"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_instance" "simulator_vm" {
  name         = "shadow-ai-simulator-vm"
  project      = var.project_id
  zone         = var.zone
  machine_type = "e2-micro"

  tags = concat(
    ["shadow-ai-simulator"],
    var.enable_swp_tag ? [var.governed_vm_tag] : []
  )

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
    }
  }

  # Private-only NIC (no access_config block -> zero external IP)
  network_interface {
    subnetwork = data.google_compute_subnetwork.workload_subnet.id
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  service_account {
    email  = google_service_account.simulator_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    enable-oslogin    = "TRUE"
    demo-project-id   = var.project_id
    demo-region       = var.region
    demo-gemini-model = var.gemini_model_id
    simulator-py      = file("${path.module}/simulate_shadow_ai.py")
    verify-sh         = file("${path.module}/verify.sh")
  }

  metadata_startup_script = <<-EOT
    #!/usr/bin/env bash
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq dnsutils curl python3 >/dev/null
    mkdir -p /opt/shadow-ai-demo
    curl -fsS -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/simulator-py \
      > /opt/shadow-ai-demo/simulate_shadow_ai.py
    curl -fsS -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/verify-sh \
      > /opt/shadow-ai-demo/verify.sh
    chmod +x /opt/shadow-ai-demo/simulate_shadow_ai.py /opt/shadow-ai-demo/verify.sh
  EOT

  allow_stopping_for_update = true
}
