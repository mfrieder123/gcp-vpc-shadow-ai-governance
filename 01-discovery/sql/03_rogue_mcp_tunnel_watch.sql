-- =============================================================================
-- Query 3: Rogue Remote MCP Server & Tunneling Endpoint Watch
-- =============================================================================
-- Remote Model Context Protocol (MCP) servers often run on developer tunnels,
-- serverless edge domains, or unvetted custom subdomains (e.g., mcp.*).
-- This query flags suspicious tunnel/edge lookups and mcp.* external domains.
-- =============================================================================

WITH suspicious_mcp_patterns AS (
  SELECT suffix, classification FROM UNNEST([
    STRUCT('.ngrok-free.app.' AS suffix, 'Developer Tunnel (Potential Rogue MCP)' AS classification),
    STRUCT('.ngrok.io.', 'Developer Tunnel (Potential Rogue MCP)'),
    STRUCT('.trycloudflare.com.', 'Developer Tunnel (Potential Rogue MCP)'),
    STRUCT('.loca.lt.', 'Developer Tunnel (Potential Rogue MCP)'),
    STRUCT('.workers.dev.', 'Unvetted Edge Worker (Review for MCP/Proxy)'),
    STRUCT('.vercel.app.', 'Unvetted Serverless App (Review for MCP/AI)')
  ])
),
dns_events AS (
  SELECT
    timestamp,
    JSON_VALUE(json_payload.sourceIP) AS source_ip,
    LOWER(JSON_VALUE(json_payload.queryName)) AS query_name
  FROM `YOUR_PROJECT_ID.global.shadow_ai_audit._AllLogs`
  WHERE
    log_id = 'dns.googleapis.com/dns_queries'
    AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
    AND JSON_VALUE(json_payload.responseCode) = 'NOERROR'
)
SELECT
  COALESCE(p.classification, 'External MCP Subdomain Pattern') AS finding_type,
  d.query_name,
  d.source_ip,
  COUNT(*) AS dns_lookups,
  MIN(d.timestamp) AS first_seen,
  MAX(d.timestamp) AS last_seen
FROM dns_events AS d
LEFT JOIN suspicious_mcp_patterns AS p
  ON ENDS_WITH(d.query_name, p.suffix)
WHERE
  p.suffix IS NOT NULL
  OR REGEXP_CONTAINS(d.query_name, r'(^|\.)mcp[.-]')
GROUP BY 1, 2, 3
ORDER BY dns_lookups DESC;
