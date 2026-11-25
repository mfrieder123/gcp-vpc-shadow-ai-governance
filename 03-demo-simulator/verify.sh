#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(curl -fsS -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/demo-project-id 2>/dev/null || true)}"
REGION="${REGION:-$(curl -fsS -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/demo-region 2>/dev/null || echo 'us-central1')}"

echo "====================================================================="
echo " Shadow AI VPC Governance — End-to-End Verification"
echo " Project: ${PROJECT_ID:-<unset>} | Region: ${REGION}"
echo "====================================================================="

echo ""
echo "[1/3] Checking DNS resolution for Vertex AI endpoint (PSC Golden Path check):"
dig +short "${REGION}-aiplatform.googleapis.com" || true

echo ""
echo "[2/3] Running Shadow AI & Golden Path traffic simulator:"
python3 /opt/shadow-ai-demo/simulate_shadow_ai.py

echo "[3/3] Next steps — inspect telemetry from your workstation:"
cat <<EOF
  # Check recent Shadow AI Cloud DNS query logs (Phase 1):
  gcloud logging read \\
    'logName="projects/${PROJECT_ID:-YOUR_PROJECT_ID}/logs/dns.googleapis.com%2Fdns_queries" AND jsonPayload.queryName=~"(openai|anthropic|huggingface|generativelanguage)"' \\
    --project="${PROJECT_ID:-YOUR_PROJECT_ID}" --limit=10 --format="table(timestamp,jsonPayload.sourceIP,jsonPayload.queryName,jsonPayload.responseCode)"

  # Check Secure Web Proxy L7 policy decisions (Phase 2/3):
  gcloud logging read \\
    'resource.type="networkservices.googleapis.com/Gateway"' \\
    --project="${PROJECT_ID:-YOUR_PROJECT_ID}" --limit=10 --format="table(timestamp,jsonPayload.enforcedGatewaySecurityPolicy.matchedRule,jsonPayload.enforcedGatewaySecurityPolicy.matchedAction,httpRequest.requestUrl)"
EOF
