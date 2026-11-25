output "swp_gateway_ip" {
  description = "Internal next-hop IP address of the Secure Web Proxy gateway."
  value       = google_network_services_gateway.ai_swp_next_hop.addresses[0]
}

output "swp_enforcement_mode" {
  description = "Active enforcement profile on the Shadow AI URL list (ALLOW = Canary, DENY = Enforced)."
  value       = var.swp_enforcement_mode
}

output "psc_google_apis_ip" {
  description = "Internal Private Service Connect IP serving *.googleapis.com (vpc-sc bundle)."
  value       = google_compute_global_address.psc_vpc_sc_ip.address
}

output "swp_security_policy_id" {
  description = "Resource ID of the Secure Web Proxy GatewaySecurityPolicy."
  value       = google_network_security_gateway_security_policy.ai_egress_policy.id
}
