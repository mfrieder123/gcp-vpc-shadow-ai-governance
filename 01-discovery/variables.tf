variable "project_id" {
  description = "Google Cloud project ID for Shadow AI VPC discovery."
  type        = string
}

variable "region" {
  description = "Google Cloud region for the workload subnet and optional sandbox Cloud NAT."
  type        = string
  default     = "us-central1"
}

variable "vpc_name" {
  description = "Name of the workload VPC network to create."
  type        = string
  default     = "ai-workloads-vpc"
}

variable "workload_subnet_name" {
  description = "Name of the workload subnetwork where VPC Flow Logs are enabled."
  type        = string
  default     = "ai-workloads-subnet"
}

variable "workload_subnet_cidr" {
  description = "Primary CIDR range for the workload subnetwork."
  type        = string
  default     = "10.10.0.0/20"
}

variable "flow_sampling" {
  description = "VPC Flow Logs sampling rate (0.0 to 1.0). Use 0.5 for steady-state cost efficiency or 1.0 during focused audits."
  type        = number
  default     = 0.5

  validation {
    condition     = var.flow_sampling >= 0.0 && var.flow_sampling <= 1.0
    error_message = "flow_sampling must be between 0.0 and 1.0."
  }
}

variable "log_retention_days" {
  description = "Retention period (in days) for the dedicated Shadow AI Log Analytics bucket."
  type        = number
  default     = 30
}

variable "enable_sandbox_nat" {
  description = "When true, provisions a Cloud Router + Cloud NAT so private sandbox VMs (no external IP) can demonstrate Phase 1 ungoverned egress before SWP is deployed."
  type        = bool
  default     = true
}

variable "notification_channels" {
  description = "Optional list of Cloud Monitoring notification channel resource names for Shadow AI alerts."
  type        = list(string)
  default     = []
}
