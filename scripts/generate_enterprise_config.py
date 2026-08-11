#!/usr/bin/env python3
"""Generate non-secret enterprise MCP configuration files."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

TOOLS = [
    "service_status",
    "get_schema",
    "security_summary",
    "top_talkers",
    "detect_port_scans",
    "detect_brute_force",
    "detect_large_egress",
    "investigate_ip",
    "collection_health",
    "query_aws_vpc_flow",
]


def guid(value: str, label: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{label} must be a GUID.") from exc


def https_url(value: str, label: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{label} must be an HTTPS URL.")
    return value.rstrip("/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--workspace-resource-id", required=True)
    parser.add_argument("--mcp-audience", required=True)
    parser.add_argument("--mcp-url", required=True)
    parser.add_argument("--security-analyst-group-id", required=True)
    parser.add_argument(
        "--network-mode",
        choices=("external-https", "internal", "private-link-apim"),
        required=True,
    )
    parser.add_argument("--audit-destination", required=True)
    parser.add_argument("--openclaw-origin", required=True)
    parser.add_argument("--managed-identity-principal-id")
    parser.add_argument("--output-dir", default=".enterprise-config")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        tenant_id = guid(args.tenant_id, "tenant ID")
        subscription_id = guid(args.subscription_id, "subscription ID")
        workspace_id = guid(args.workspace_id, "workspace customer ID")
        analyst_group_id = guid(args.security_analyst_group_id, "Security Analyst group ID")
        principal_id = (
            guid(args.managed_identity_principal_id, "managed identity principal ID")
            if args.managed_identity_principal_id
            else None
        )
        mcp_url = https_url(args.mcp_url, "MCP URL")
        openclaw_origin = https_url(args.openclaw_origin, "OpenClaw origin")
        expected_prefix = f"/subscriptions/{subscription_id}/"
        if not args.workspace_resource_id.lower().startswith(expected_prefix.lower()):
            raise ValueError("workspace resource ID does not belong to the supplied subscription.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    policy_path = output_dir / "access-policy.json"
    env_path = output_dir / "server.env"

    policy = {
        "defaultRole": None,
        "roles": {
            "security_analyst": {
                "tools": TOOLS,
                "maxTimespanHours": 720,
                "maxRows": 2000,
                "allowCustomKql": True,
            }
        },
        "groupRoleMappings": {analyst_group_id: "security_analyst"},
        "roleClaimMappings": {"AWSVPCFlow.SecurityAnalyst": "security_analyst"},
    }
    policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")

    values = {
        "AWS_VPC_FLOW_WORKSPACE_ID": workspace_id,
        "AWS_VPC_FLOW_SUBSCRIPTION_ID": subscription_id,
        "AWS_VPC_FLOW_AZURE_AUTH_MODE": "managed-identity",
        "AWS_VPC_FLOW_MCP_AUTH_MODE": "entra",
        "AWS_VPC_FLOW_MCP_TENANT_ID": tenant_id,
        "AWS_VPC_FLOW_MCP_AUDIENCE": args.mcp_audience,
        "AWS_VPC_FLOW_MCP_SCOPE": "aws_vpc_flow.read",
        "AWS_VPC_FLOW_MCP_SERVER_URL": mcp_url,
        "AWS_VPC_FLOW_ACCESS_POLICY": str(policy_path),
        "AWS_VPC_FLOW_SECURITY_ANALYST_GROUP_ID": analyst_group_id,
        "AWS_VPC_FLOW_NETWORK_MODE": args.network_mode,
        "AWS_VPC_FLOW_AUDIT_DESTINATION": args.audit_destination,
        "AWS_VPC_FLOW_ALLOWED_HOSTS": urlparse(mcp_url).netloc,
        "AWS_VPC_FLOW_ALLOWED_ORIGINS": openclaw_origin,
    }
    if principal_id:
        values["AWS_VPC_FLOW_MANAGED_IDENTITY_PRINCIPAL_ID"] = principal_id
    env_path.write_text(
        "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "outputDirectory": str(output_dir),
                "policyFile": str(policy_path),
                "environmentFile": str(env_path),
                "readyForPermissionAssignment": principal_id is not None,
                "secretHandling": (
                    "Generated files contain identifiers and policy, but no secrets. "
                    "Keep them in the enterprise deployment pipeline and out of Git."
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
