-- =============================================================================
-- Query 1: Fast Shadow AI Domain Inventory (Cloud DNS Query Logs)
-- =============================================================================
-- Run in Cloud Logging -> Log Analytics (or BigQuery via linked dataset).
-- Replace `YOUR_PROJECT_ID.global.shadow_ai_audit._AllLogs` with:
--   - `YOUR_PROJECT_ID.global.shadow_ai_audit._AllLogs` (created by 01-discovery)
--   - OR `YOUR_PROJECT_ID.global._Default._AllLogs` (existing Google Cloud projects)
-- =============================================================================

WITH shadow_ai_catalog AS (
  SELECT domain, category, risk_level FROM UNNEST([
    -- External LLM APIs (unapproved for unmonitored VPC egress)
    STRUCT('api.openai.com.' AS domain, 'External LLM API' AS category, 'HIGH' AS risk_level),
    STRUCT('api.anthropic.com.', 'External LLM API', 'HIGH'),
    STRUCT('api.deepseek.com.', 'External LLM API', 'CRITICAL'),
    STRUCT('api.mistral.ai.', 'External LLM API', 'HIGH'),
    STRUCT('api.cohere.ai.', 'External LLM API', 'HIGH'),
    STRUCT('api.groq.com.', 'External LLM API', 'HIGH'),
    STRUCT('api.together.xyz.', 'External LLM API', 'HIGH'),
    STRUCT('openrouter.ai.', 'External AI Aggregator', 'HIGH'),
    -- Consumer Google AI Studio (potential personal API key bypass outside Vertex AI)
    STRUCT('generativelanguage.googleapis.com.', 'Consumer AI Studio API', 'HIGH'),
    -- External Model & Weight Hubs
    STRUCT('huggingface.co.', 'Model Weight Hub', 'MEDIUM'),
    STRUCT('cdn-lfs.hf.co.', 'Model Weight Hub', 'MEDIUM'),
    STRUCT('registry.ollama.ai.', 'Model Weight Hub', 'MEDIUM'),
    -- Third-Party AI Coding / Search / Agent Endpoints
    STRUCT('api.cursor.sh.', 'External AI Code Assistant', 'MEDIUM'),
    STRUCT('api.perplexity.ai.', 'External AI Search API', 'HIGH')
  ])
)
SELECT
  c.risk_level,
  c.category,
  JSON_VALUE(l.json_payload.queryName) AS queried_domain,
  JSON_VALUE(l.json_payload.sourceIP) AS source_ip,
  COUNT(*) AS dns_queries,
  MIN(l.timestamp) AS first_seen,
  MAX(l.timestamp) AS last_seen
FROM `YOUR_PROJECT_ID.global.shadow_ai_audit._AllLogs` AS l
JOIN shadow_ai_catalog AS c
  ON LOWER(JSON_VALUE(l.json_payload.queryName)) = c.domain
  OR ENDS_WITH(LOWER(JSON_VALUE(l.json_payload.queryName)), CONCAT('.', c.domain))
WHERE
  l.log_id = 'dns.googleapis.com/dns_queries'
  AND l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND JSON_VALUE(l.json_payload.responseCode) = 'NOERROR'
GROUP BY 1, 2, 3, 4
ORDER BY
  CASE c.risk_level
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    ELSE 4
  END,
  dns_queries DESC;
