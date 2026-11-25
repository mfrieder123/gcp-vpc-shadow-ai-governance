#!/usr/bin/env python3
"""Shadow AI VPC Governance Simulator (Zero-Dependency Python 3).

Fires harmless HTTPS checks from inside a Google Cloud VPC to demonstrate:
  - Phase 1 (Observe): External LLM/Model Hub DNS lookups + egress flows appear
    in Cloud DNS Query Logs and VPC Flow Logs.
  - Phase 2 (Canary): Traffic traverses Secure Web Proxy (ALLOW + L7 SNI logs).
  - Phase 3 (Enforce): Unapproved Shadow AI endpoints are blocked at L7 by SWP,
    while governed Vertex AI succeeds privately over the PSC Golden Path.

No sensitive data or external API keys are required or transmitted.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1"
METADATA_HEADERS = {"Metadata-Flavor": "Google"}
TIMEOUT_SECONDS = 5


def fetch_metadata(path: str, default: str = "") -> str:
    """Reads an attribute or token from the GCE metadata server."""
    req = urllib.request.Request(f"{METADATA_BASE}/{path}", headers=METADATA_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return default


def resolve_host(hostname: str) -> str:
    """Resolves a hostname via VPC Cloud DNS (generates dns_queries log)."""
    try:
        return socket.gethostbyname(hostname)
    except OSError as exc:
        return f"DNS_ERR({exc.strerror or exc})"


def probe_external_endpoint(name: str, hostname: str, url: str) -> dict[str, str]:
    """Issues a harmless HTTPS probe to verify reachability vs. SWP L7 block."""
    resolved_ip = resolve_host(hostname)
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "shadow-ai-vpc-demo/1.0"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {
                "target": name,
                "host": hostname,
                "resolved_ip": resolved_ip,
                "status": f"REACHABLE (HTTP {resp.status}, {elapsed_ms}ms)",
            }
    except urllib.error.HTTPError as exc:
        # An HTTP 401/403/404 from the remote API confirms network reachability
        # (expected because no external API key is sent); SWP blocks terminate
        # the TLS/TCP connection or return 403 from the proxy layer.
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "target": name,
            "host": hostname,
            "resolved_ip": resolved_ip,
            "status": f"REACHABLE_API_RESPONSE (HTTP {exc.code}, {elapsed_ms}ms)",
        }
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        reason = getattr(exc, "reason", exc)
        return {
            "target": name,
            "host": hostname,
            "resolved_ip": resolved_ip,
            "status": f"BLOCKED / UNREACHABLE ({type(reason).__name__}, {elapsed_ms}ms)",
        }


def probe_vertex_golden_path(project_id: str, region: str, model_id: str) -> dict[str, str]:
    """Calls governed Vertex AI Gemini endpoint using VM workload identity."""
    hostname = f"{region}-aiplatform.googleapis.com"
    resolved_ip = resolve_host(hostname)

    if not project_id:
        return {
            "target": "Vertex AI Golden Path",
            "host": hostname,
            "resolved_ip": resolved_ip,
            "status": "SKIPPED (PROJECT_ID not set)",
        }

    token_json = fetch_metadata("instance/service-accounts/default/token")
    if not token_json:
        return {
            "target": "Vertex AI Golden Path",
            "host": hostname,
            "resolved_ip": resolved_ip,
            "status": "SKIPPED (no GCE metadata token available)",
        }

    access_token = json.loads(token_json)["access_token"]
    url = (
        f"https://{hostname}/v1/projects/{project_id}/locations/{region}"
        f"/publishers/google/models/{model_id}:generateContent"
    )
    payload = json.dumps(
        {"contents": [{"role": "user", "parts": [{"text": "Reply with OK only."}]}]}
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            body = json.loads(resp.read().decode("utf-8"))
            text = (
                body.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
                .strip()
            )
            return {
                "target": f"Vertex AI Golden Path ({model_id})",
                "host": hostname,
                "resolved_ip": resolved_ip,
                "status": f"ALLOWED_PRIVATE_OK (HTTP {resp.status}, {elapsed_ms}ms, reply='{text[:20]}')",
            }
    except urllib.error.HTTPError as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "target": f"Vertex AI Golden Path ({model_id})",
            "host": hostname,
            "resolved_ip": resolved_ip,
            "status": f"HTTP_ERROR (HTTP {exc.code}, {elapsed_ms}ms)",
        }
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "target": f"Vertex AI Golden Path ({model_id})",
            "host": hostname,
            "resolved_ip": resolved_ip,
            "status": f"FAILED ({type(exc).__name__}: {exc}, {elapsed_ms}ms)",
        }


def main() -> int:
    project_id = os.environ.get("PROJECT_ID") or fetch_metadata("instance/attributes/demo-project-id")
    region = os.environ.get("REGION") or fetch_metadata("instance/attributes/demo-region", "us-central1")
    model_id = os.environ.get("GEMINI_MODEL") or fetch_metadata(
        "instance/attributes/demo-gemini-model", "gemini-2.5-flash"
    )

    external_targets = [
        ("Shadow AI — OpenAI API", "api.openai.com", "https://api.openai.com/v1/models"),
        ("Shadow AI — Anthropic API", "api.anthropic.com", "https://api.anthropic.com/v1/messages"),
        ("Shadow AI — Model Hub", "huggingface.co", "https://huggingface.co/"),
        (
            "Shadow AI — Consumer AI Studio",
            "generativelanguage.googleapis.com",
            "https://generativelanguage.googleapis.com/v1beta/models",
        ),
        ("Control — Standard Web", "example.com", "https://example.com/"),
    ]

    results = [probe_external_endpoint(name, host, url) for name, host, url in external_targets]
    results.append(probe_vertex_golden_path(project_id, region, model_id))

    print("\n=== Shadow AI VPC Governance Verification Results ===")
    print(f"{'TARGET':<38} | {'RESOLVED IP':<16} | {'RESULT'}")
    print("-" * 105)
    for row in results:
        print(f"{row['target']:<38} | {row['resolved_ip']:<16} | {row['status']}")
    print("-" * 105)
    print("Note: Private RFC 1918 IP (e.g., 10.10.254.10) on *.googleapis.com confirms PSC Golden Path.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
