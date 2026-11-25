variable "project_id" {
  description = "Google Cloud project ID for the sandbox simulator VM."
  type        = string
}

variable "region" {
  description = "Google Cloud region matching 01-discovery and 02-enforcement-swp."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Compute Engine zone for the simulator VM."
  type        = string
  default     = "us-central1-a"
}

variable "vpc_name" {
  description = "Workload VPC name created in 01-discovery."
  type        = string
  default     = "ai-workloads-vpc"
}

variable "workload_subnet_name" {
  description = "Workload subnet name created in 01-discovery."
  type        = string
  default     = "ai-workloads-subnet"
}

variable "enable_swp_tag" {
  description = "Set false for Phase 1 ungoverned baseline; set true for Phase 2/3 transparent steering into Secure Web Proxy."
  type        = bool
  default     = false
}

variable "governed_vm_tag" {
  description = "Network tag matching the Policy-Based Route in 02-enforcement-swp."
  type        = string
  default     = "governed-ai-egress"
}

variable "gemini_model_id" {
  description = "Public GA Vertex AI Gemini model ID used by the Golden Path verification test."
  type        = string
  default     = "gemini-2.5-flash"
}
