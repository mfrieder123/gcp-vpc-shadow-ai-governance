variable "project_id" {
  description = "Google Cloud project ID where Secure Web Proxy and PSC are deployed."
  type        = string
}

variable "region" {
  description = "Google Cloud region for the regional Secure Web Proxy gateway."
  type        = string
  default     = "us-central1"
}

variable "vpc_name" {
  description = "Existing workload VPC name created in 01-discovery."
  type        = string
  default     = "ai-workloads-vpc"
}

variable "workload_subnet_name" {
  description = "Existing workload subnet name created in 01-discovery."
  type        = string
  default     = "ai-workloads-subnet"
}

variable "workload_subnet_cidr" {
  description = "Primary CIDR of the workload subnet steered into SWP."
  type        = string
  default     = "10.10.0.0/20"
}

variable "proxy_only_subnet_cidr" {
  description = "CIDR block for the required REGIONAL_MANAGED_PROXY subnet (minimum /23 recommended)."
  type        = string
  default     = "10.129.0.0/23"
}

variable "swp_gateway_ip" {
  description = "Static internal IP inside workload_subnet_cidr assigned to the Secure Web Proxy gateway."
  type        = string
  default     = "10.10.0.250"
}

variable "psc_google_apis_ip" {
  description = "Global internal IP for the Private Service Connect endpoint targeting the vpc-sc Google APIs bundle."
  type        = string
  default     = "10.10.254.10"
}

variable "swp_enforcement_mode" {
  description = "Controls Shadow AI rule enforcement: 'ALLOW' for Phase 2 canary audit mode, 'DENY' for Phase 3 active blocking."
  type        = string
  default     = "ALLOW"

  validation {
    condition     = contains(["ALLOW", "DENY"], var.swp_enforcement_mode)
    error_message = "swp_enforcement_mode must be either 'ALLOW' (Phase 2 canary) or 'DENY' (Phase 3 enforcement)."
  }
}

variable "governed_vm_tag" {
  description = "Network tag on VMs/nodes whose outbound TCP egress is steered transparently through SWP."
  type        = string
  default     = "governed-ai-egress"
}

variable "approved_external_ai_domains" {
  description = "External AI/MCP partner hostnames explicitly permitted by Security."
  type        = list(string)
  default = [
    "mcp.approved-partner.example.com",
  ]
}

variable "blocked_shadow_ai_domains" {
  description = "External LLM APIs, consumer AI Studio, and model hubs subject to Shadow AI governance."
  type        = list(string)
  default = [
    "api.openai.com",
    "*.openai.com",
    "api.anthropic.com",
    "api.deepseek.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.groq.com",
    "openrouter.ai",
    "huggingface.co",
    "*.hf.co",
    "registry.ollama.ai",
    "generativelanguage.googleapis.com",
  ]
}
