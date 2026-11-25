output "simulator_vm_name" {
  description = "Name of the simulator GCE VM."
  value       = google_compute_instance.simulator_vm.name
}

output "simulator_internal_ip" {
  description = "Internal VPC IP address of the simulator VM (look for this IP in Phase 1 SQL output)."
  value       = google_compute_instance.simulator_vm.network_interface[0].network_ip
}

output "iap_ssh_command" {
  description = "Command to connect privately via IAP SSH and run the verification harness."
  value       = "gcloud compute ssh ${google_compute_instance.simulator_vm.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap"
}

output "remote_verify_command" {
  description = "One-liner to run the verification script directly over IAP SSH."
  value       = "gcloud compute ssh ${google_compute_instance.simulator_vm.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap --command='bash /opt/shadow-ai-demo/verify.sh'"
}
