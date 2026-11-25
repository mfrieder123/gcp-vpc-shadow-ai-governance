# Reusable URL Lists & Secure Web Proxy Gateway Security Policy Rules

resource "google_network_security_url_lists" "approved_external_ai" {
  name        = "approved-external-ai-mcp"
  project     = var.project_id
  location    = var.region
  description = "External AI/MCP partner domains formally vetted and approved by Security."
  values      = var.approved_external_ai_domains

  depends_on = [google_project_service.enforcement_apis]
}

resource "google_network_security_url_lists" "blocked_shadow_ai" {
  name        = "blocked-shadow-ai-domains"
  project     = var.project_id
  location    = var.region
  description = "Unapproved external LLM APIs, consumer AI Studio, and external model hubs."
  values      = var.blocked_shadow_ai_domains

  depends_on = [google_project_service.enforcement_apis]
}

resource "google_network_security_gateway_security_policy" "ai_egress_policy" {
  name        = "ai-egress-governance-policy"
  project     = var.project_id
  location    = var.region
  description = "Layer-7 SNI/Host egress governance policy for AI workloads."

  depends_on = [google_project_service.enforcement_apis]
}

# Priority 100: Explicitly ALLOW approved external partner AI / MCP endpoints
resource "google_network_security_gateway_security_policy_rule" "allow_approved_ai" {
  name                    = "allow-approved-external-ai"
  project                 = var.project_id
  location                = var.region
  gateway_security_policy = google_network_security_gateway_security_policy.ai_egress_policy.name
  enabled                 = true
  priority                = 100
  description             = "Permits approved external AI/MCP partner endpoints."
  session_matcher         = "inUrlList(host(), '${google_network_security_url_lists.approved_external_ai.id}')"
  basic_profile           = "ALLOW"
}

# Priority 200: Shadow AI rule — set swp_enforcement_mode = "ALLOW" in Phase 2 (Canary), "DENY" in Phase 3 (Enforce)
resource "google_network_security_gateway_security_policy_rule" "govern_shadow_ai" {
  name                    = "deny-shadow-ai-egress"
  project                 = var.project_id
  location                = var.region
  gateway_security_policy = google_network_security_gateway_security_policy.ai_egress_policy.name
  enabled                 = true
  priority                = 200
  description             = "Audits (Phase 2 ALLOW) or blocks (Phase 3 DENY) unapproved external AI/LLM/model-hub domains."
  session_matcher         = "inUrlList(host(), '${google_network_security_url_lists.blocked_shadow_ai.id}')"
  basic_profile           = var.swp_enforcement_mode
}

# Priority 900: Permit remaining general HTTPS traffic (replace with explicit allowlist in strict zero-trust envs)
resource "google_network_security_gateway_security_policy_rule" "allow_general_https" {
  name                    = "allow-general-https"
  project                 = var.project_id
  location                = var.region
  gateway_security_policy = google_network_security_gateway_security_policy.ai_egress_policy.name
  enabled                 = true
  priority                = 900
  description             = "Permits non-AI standard HTTPS traffic while logging SNI hostnames."
  session_matcher         = "host() != ''"
  basic_profile           = "ALLOW"
}
