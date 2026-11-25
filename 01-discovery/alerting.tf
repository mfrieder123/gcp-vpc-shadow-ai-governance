# Phase 2: Automated Shadow AI Alerting via Cloud Logging Metric + Cloud Monitoring Alert Policy

resource "google_logging_metric" "shadow_ai_dns_queries" {
  name        = "shadow_ai_dns_queries"
  project     = var.project_id
  description = "Counts outbound VPC DNS lookups matching unapproved external LLM APIs, consumer AI Studio, or model hubs."

  filter = <<-EOT
    logName="projects/${var.project_id}/logs/dns.googleapis.com%2Fdns_queries"
    jsonPayload.responseCode="NOERROR"
    jsonPayload.queryName=~"(api\\.openai\\.com|api\\.anthropic\\.com|api\\.deepseek\\.com|api\\.mistral\\.ai|api\\.cohere\\.ai|openrouter\\.ai|generativelanguage\\.googleapis\\.com|huggingface\\.co|registry\\.ollama\\.ai)\\.$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "queried_domain"
      value_type  = "STRING"
      description = "External AI domain queried from inside the VPC."
    }

    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Internal VPC IP address of the workload issuing the DNS query."
    }
  }

  label_extractors = {
    "queried_domain" = "EXTRACT(jsonPayload.queryName)"
    "source_ip"      = "EXTRACT(jsonPayload.sourceIP)"
  }

  depends_on = [google_project_service.discovery_apis]
}

resource "google_monitoring_alert_policy" "shadow_ai_egress_alert" {
  display_name = "Shadow AI DNS Lookup Detected in VPC"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ### Shadow AI DNS Lookup Detected

      A workload inside VPC `${var.vpc_name}` resolved an external AI or consumer LLM domain.

      **Recommended Triage Steps:**
      1. Open **Log Analytics** and run `01-discovery/sql/02_correlate_dns_and_flows.sql` to identify the exact GCE VM or GKE pod and outbound byte volume.
      2. Contact the workload owner to confirm whether this traffic can migrate to governed **Vertex AI / Model Garden** via the Private Service Connect Golden Path.
      3. If an external partner AI/MCP endpoint is legitimately required, add it to `approved-external-ai-mcp` in `02-enforcement-swp/url_lists_and_policies.tf` via PR review.
    EOT
  }

  conditions {
    display_name = "Shadow AI DNS query rate > 0"

    condition_threshold {
      filter          = "resource.type=\"dns_query\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.shadow_ai_dns_queries.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.queried_domain", "metric.label.source_ip"]
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  notification_channels = var.notification_channels
}
