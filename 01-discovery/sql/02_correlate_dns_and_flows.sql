-- =============================================================================
-- Query 2: Correlate Shadow AI DNS Resolutions with VPC Flow Outbound Bytes
-- =============================================================================
-- Solves the Shared CDN IP Problem:
--   Joins Cloud DNS query resolutions (`rdata`) to VPC Flow Logs (`dest_ip`)
--   within a 15-minute window to attribute outbound MB to exact GCE VMs or
--   GKE clusters/namespaces/workloads.
-- =============================================================================

WITH shadow_ai_catalog AS (
  SELECT domain, category, risk_level FROM UNNEST([
    STRUCT('api.openai.com.' AS domain, 'External LLM API' AS category, 'HIGH' AS risk_level),
    STRUCT('api.anthropic.com.', 'External LLM API', 'HIGH'),
    STRUCT('api.deepseek.com.', 'External LLM API', 'CRITICAL'),
    STRUCT('api.mistral.ai.', 'External LLM API', 'HIGH'),
    STRUCT('api.cohere.ai.', 'External LLM API', 'HIGH'),
    STRUCT('openrouter.ai.', 'External AI Aggregator', 'HIGH'),
    STRUCT('generativelanguage.googleapis.com.', 'Consumer AI Studio API', 'HIGH'),
    STRUCT('huggingface.co.', 'Model Weight Hub', 'MEDIUM'),
    STRUCT('cdn-lfs.hf.co.', 'Model Weight Hub', 'MEDIUM'),
    STRUCT('registry.ollama.ai.', 'Model Weight Hub', 'MEDIUM')
  ])
),
dns_resolutions AS (
  SELECT
    l.timestamp AS dns_ts,
    JSON_VALUE(l.json_payload.sourceIP) AS src_ip,
    JSON_VALUE(l.json_payload.queryName) AS queried_domain,
    c.category,
    c.risk_level,
    resolved_ip
  FROM `YOUR_PROJECT_ID.global.shadow_ai_audit._AllLogs` AS l
  JOIN shadow_ai_catalog AS c
    ON LOWER(JSON_VALUE(l.json_payload.queryName)) = c.domain
    OR ENDS_WITH(LOWER(JSON_VALUE(l.json_payload.queryName)), CONCAT('.', c.domain)),
  UNNEST(REGEXP_EXTRACT_ALL(JSON_VALUE(l.json_payload.rdata), r'\b(?:\d{1,3}\.){3}\d{1,3}\b')) AS resolved_ip
  WHERE
    l.log_id = 'dns.googleapis.com/dns_queries'
    AND l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
    AND JSON_VALUE(l.json_payload.queryType) = 'A'
    AND JSON_VALUE(l.json_payload.responseCode) = 'NOERROR'
),
egress_flows AS (
  SELECT
    timestamp AS flow_ts,
    JSON_VALUE(json_payload.connection.src_ip) AS src_ip,
    JSON_VALUE(json_payload.connection.dest_ip) AS dest_ip,
    CAST(JSON_VALUE(json_payload.bytes_sent) AS INT64) AS bytes_sent,
    JSON_VALUE(json_payload.src_instance.vm_name) AS vm_name,
    JSON_VALUE(json_payload.src_instance.zone) AS vm_zone,
    JSON_VALUE(json_payload.src_gke_details.cluster.cluster_name) AS gke_cluster,
    JSON_VALUE(json_payload.src_gke_details.pod.pod_namespace) AS gke_namespace,
    JSON_VALUE(json_payload.src_gke_details.pod.workload.workload_name) AS gke_workload
  FROM `YOUR_PROJECT_ID.global.shadow_ai_audit._AllLogs`
  WHERE
    log_id = 'compute.googleapis.com/vpc_flows'
    AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
    AND JSON_VALUE(json_payload.reporter) = 'SRC'
    AND JSON_VALUE(json_payload.connection.dest_port) = '443'
)
SELECT
  d.risk_level,
  d.category,
  d.queried_domain,
  COALESCE(f.gke_cluster, 'GCE') AS runtime_platform,
  COALESCE(f.gke_namespace, f.vm_zone, 'unknown') AS namespace_or_zone,
  COALESCE(f.gke_workload, f.vm_name, f.src_ip) AS source_workload,
  COUNT(DISTINCT f.flow_ts) AS observed_flows,
  ROUND(SUM(f.bytes_sent) / (1024 * 1024), 2) AS total_mb_sent
FROM egress_flows AS f
JOIN dns_resolutions AS d
  ON f.src_ip = d.src_ip
  AND f.dest_ip = d.resolved_ip
  AND f.flow_ts BETWEEN d.dns_ts AND TIMESTAMP_ADD(d.dns_ts, INTERVAL 15 MINUTE)
GROUP BY 1, 2, 3, 4, 5, 6
ORDER BY total_mb_sent DESC;
