output "vpc_name" {
  description = "Name of the workload VPC network."
  value       = google_compute_network.workload_vpc.name
}

output "vpc_id" {
  description = "Resource ID of the workload VPC network."
  value       = google_compute_network.workload_vpc.id
}

output "workload_subnet_name" {
  description = "Name of the workload subnetwork."
  value       = google_compute_subnetwork.workload_subnet.name
}

output "workload_subnet_cidr" {
  description = "CIDR block of the workload subnetwork."
  value       = google_compute_subnetwork.workload_subnet.ip_cidr_range
}

output "log_analytics_view_path" {
  description = "Log Analytics SQL table path for the dedicated shadow_ai_audit bucket."
  value       = "${var.project_id}.global.shadow_ai_audit._AllLogs"
}

output "bigquery_linked_dataset" {
  description = "BigQuery linked dataset path for scheduled queries and Looker/BI dashboards."
  value       = "${var.project_id}.shadow_ai_audit_logs._AllLogs"
}
