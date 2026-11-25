# Shadow AI Discovery & Egress Governance at the VPC Layer on Google Cloud

> **Disclaimer (Non-Production Sample):** This repository contains non-production reference architectures, example Terraform configurations, Log Analytics SQL queries, and demonstration scripts provided **AS-IS** under the Apache 2.0 license without warranty or SLA. Always review and validate configurations in an isolated sandbox environment before adapting them to production.

This repository is the companion implementation to the Medium guide:
**"Catching and Governing Shadow AI at the VPC Layer on Google Cloud (Without Breaking Developers)"**.

It implements a **3-phase, native Google Cloud networking architecture** to discover, alert on, and govern VPC-originated Shadow AI (external LLM APIs, personal consumer AI Studio keys, external model hubs, and unvetted remote MCP servers) while steering teams onto a fast, private **Golden Path** to **Vertex AI**, **Model Garden**, and **Gemini Enterprise**.

---

## Repository Structure

```text
gcp-vpc-shadow-ai-governance/
├── docs/
│   └── medium-article.md              # Full companion Medium article (ready for medium.com/google-cloud)
├── 01-discovery/                      # Phase 1 & 2: Zero-risk observability & alerting
│   ├── main.tf                        # APIs, VPC/Subnet (VPC Flow Logs), Cloud DNS logging, Log Analytics bucket + linked BQ dataset
│   ├── alerting.tf                    # Log-based metric & Cloud Monitoring alert on Shadow AI DNS hits
│   ├── variables.tf / outputs.tf / versions.tf / terraform.tfvars.example
│   └── sql/
│       ├── 01_shadow_ai_dns_inventory.sql    # Fast Shadow AI domain inventory across 4 risk tiers
│       ├── 02_correlate_dns_and_flows.sql    # Correlates DNS rdata with VPC Flow bytes_sent & GKE/VM metadata
│       └── 03_rogue_mcp_tunnel_watch.sql     # Detects unvetted remote MCP / tunneling / serverless edge endpoints
├── 02-enforcement-swp/                # Phase 3: Transparent L7 egress governance + Private Golden Path
│   ├── main.tf                        # Proxy-only subnet, SWP (NEXT_HOP_ROUTING_MODE), PBRs with safe DEFAULT_ROUTING bypasses, QUIC guard
│   ├── url_lists_and_policies.tf      # Reusable google_network_security_url_lists + ALLOW/DENY CEL rules
│   ├── golden_path_psc.tf             # Private Service Connect (target = "vpc-sc") + Private Cloud DNS for *.googleapis.com
│   ├── variables.tf / outputs.tf / versions.tf / terraform.tfvars.example
│   └── ncc_hub_example/
│       └── main.tf                    # Reference pattern scaling centralized SWP across multi-VPC orgs via NCC Star Hub
└── 03-demo-simulator/                 # 10-minute live demo VM & verification harness (zero external IP, IAP SSH)
    ├── main.tf / variables.tf / outputs.tf / versions.tf / terraform.tfvars.example
    ├── simulate_shadow_ai.py          # Zero-dependency Python 3 simulator testing external LLMs, AI Studio, Model Hubs & Vertex PSC
    └── verify.sh                      # End-to-end verification script (dig PSC check + simulator + gcloud log inspection)
```

---

## Prerequisites

- A non-production Google Cloud project (designed for strict Organization Policies—all VMs deploy with **zero external IPs**, Shielded VM enabled, least-privilege Service Accounts, and **IAP SSH**).
- [Terraform](https://developer.hashicorp.com/terraform/install) `>= 1.5` and `gcloud` CLI authenticated via `gcloud auth application-default login`.
- IAM roles in the sandbox project: `roles/owner` (or combined `roles/compute.networkAdmin`, `roles/dns.admin`, `roles/networkservices.admin`, `roles/networksecurity.admin`, `roles/certificatemanager.owner`, `roles/logging.admin`, `roles/monitoring.admin`, `roles/iam.serviceAccountAdmin`).

---

## Quickstart: 10-Minute Live Demo Flow (Phase 1 → Phase 2 → Phase 3)

### Step 1 — Deploy Phase 1 Discovery (`01-discovery/`)

```bash
cd 01-discovery
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your sandbox project_id and region
terraform init
terraform apply
```

This creates:
- A custom VPC and workload subnet with **VPC Flow Logs** (`INCLUDE_ALL_METADATA`) and **Cloud DNS Query Logging** enabled.
- A dedicated **`shadow-ai-audit` Log Analytics bucket** (`enable_analytics = true`) + log sink + BigQuery linked dataset (without mutating your `_Default` bucket).
- A Cloud Logging metric and Cloud Monitoring alert policy for Shadow AI DNS hits.
- An optional sandbox Cloud NAT (`enable_sandbox_nat = true`) so private test VMs can reach the internet during Phase 1 observation.

### Step 2 — Deploy the Test Simulator VM (`03-demo-simulator/`)

```bash
cd ../03-demo-simulator
cp terraform.tfvars.example terraform.tfvars
# Keep enable_swp_tag = false for Phase 1 (ungoverned baseline)
terraform init
terraform apply
```

Connect via the IAP SSH command printed in `terraform output iap_ssh_command` and run the verification script:

```bash
bash /opt/shadow-ai-demo/verify.sh
```

Wait 2–3 minutes for logs to land, then open **Cloud Logging → Log Analytics** (or BigQuery) and run:
1. `01-discovery/sql/01_shadow_ai_dns_inventory.sql`
2. `01-discovery/sql/02_correlate_dns_and_flows.sql`
3. `01-discovery/sql/03_rogue_mcp_tunnel_watch.sql`

You will see the test VM's outbound Shadow AI DNS lookups and correlated outbound byte volume appear immediately.

### Step 3 — Deploy Phase 2 Canary Enforcement (`02-enforcement-swp/`)

Deploy **Secure Web Proxy** in `NEXT_HOP_ROUTING_MODE` + the **Private Service Connect (`vpc-sc`) Golden Path**, starting with `swp_enforcement_mode = "ALLOW"` (canary audit mode):

```bash
cd ../02-enforcement-swp
cp terraform.tfvars.example terraform.tfvars
# Start with swp_enforcement_mode = "ALLOW" to validate L7 visibility safely
terraform init
terraform apply
```

Next, attach the `governed-ai-egress` network tag to the simulator VM (`enable_swp_tag = true` in `03-demo-simulator/terraform.tfvars` and `terraform apply`) and re-run `verify.sh`. Traffic now flows transparently through Secure Web Proxy with zero proxy environment variables on the VM, while `*.googleapis.com` resolves privately to the internal PSC IP (`10.10.254.10`).

### Step 4 — Flip to Phase 3 Hard Enforcement (`DENY`)

In `02-enforcement-swp/terraform.tfvars`, change one variable:

```hcl
swp_enforcement_mode = "DENY"
```

Apply and re-run `verify.sh` on the simulator VM:
- **External LLM APIs & Model Hubs** (`api.openai.com`, `api.anthropic.com`, `huggingface.co`) → **BLOCKED at Layer 7** by Secure Web Proxy (`deny-shadow-ai-egress`).
- **Consumer AI Studio** (`generativelanguage.googleapis.com`) → **BLOCKED** (and when wrapped in a VPC-SC perimeter, personal/external API keys are blocked at the API boundary as well).
- **Governed Vertex AI (`*-aiplatform.googleapis.com`)** → **SUCCEEDS privately** over the internal PSC endpoint (`10.10.254.10`) without touching Cloud NAT or Secure Web Proxy.

---

## Clean Teardown

Destroy in reverse order. Note that `02-enforcement-swp/main.tf` sets `delete_swg_autogen_router_on_destroy = true` on the Secure Web Proxy gateway so the auto-provisioned SWP Cloud Router cleans up automatically:

```bash
cd 03-demo-simulator && terraform destroy
cd ../02-enforcement-swp && terraform destroy
cd ../01-discovery && terraform destroy
```

---

## Key Production Safeguards Included

- **Safe Policy-Based Route (PBR) Bypasses (`next_hop_other_routes = "DEFAULT_ROUTING"`):** Higher-priority PBR bypass rules protect RFC 1918 traffic (`10.0.0.0/8`, including the internal PSC IP), **IAP SSH (`35.235.240.0/20`)**, the **GCE Metadata Server (`169.254.169.254/32`)**, and `restricted.googleapis.com` VIPs (`199.36.153.4/30`) from ever being hijacked into Secure Web Proxy.
- **QUIC (UDP/443) Egress Guard:** Because `NEXT_HOP_ROUTING_MODE` handles HTTP(S)/TCP traffic, a companion VPC firewall rule denies outbound UDP/443 on governed workloads so HTTP/3 clients cleanly negotiate HTTPS over TCP/443 through SWP instead of silently dropping or bypassing inspection.
- **Enterprise & Regulated Org-Policy Ready:** Zero external IPs on VMs, Shielded VM (`enable_secure_boot`, `enable_vtpm`, `enable_integrity_monitoring`), OS Login, IAP-only SSH, and dedicated least-privilege Service Accounts.
