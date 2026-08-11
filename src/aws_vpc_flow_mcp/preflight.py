from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from typing import Any

from .config import ConfigurationError, Settings


def question(key: str, prompt: str, required: bool = True) -> dict[str, Any]:
    return {"key": key, "prompt": prompt, "required": required}


def collect(mode: str) -> dict[str, Any]:
    questions: list[dict[str, Any]] = []
    checks: dict[str, Any] = {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "pythonSupported": sys.version_info >= (3, 10),
        "uvAvailable": shutil.which("uv") is not None,
        "openclawAvailable": shutil.which("openclaw") is not None,
        "azureCliAvailable": shutil.which("az") is not None,
    }

    if mode in {"local", "server"} and not (
        os.getenv("AWS_VPC_FLOW_WORKSPACE_ID") or os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
    ):
        questions.append(
            question(
                "workspace_id",
                "Provide the Log Analytics workspace customer ID containing AWSVPCFlow.",
            )
        )

    if mode == "local" and not os.getenv("AWS_VPC_FLOW_LOCAL_AUTH_METHOD"):
        questions.append(
            question(
                "local_identity",
                "Choose Azure authentication: az login, managed identity, "
                "service principal, or a pre-acquired token.",
            )
        )

    if mode == "server":
        if os.getenv("AWS_VPC_FLOW_MCP_AUTH_MODE", "local") != "entra":
            questions.append(
                question(
                    "mcp_auth_mode",
                    "Confirm Entra authentication for the enterprise HTTP MCP server.",
                )
            )
        for key, env_name, prompt in (
            (
                "tenant_id",
                "AWS_VPC_FLOW_MCP_TENANT_ID",
                "Provide the Microsoft Entra tenant ID.",
            ),
            (
                "mcp_audience",
                "AWS_VPC_FLOW_MCP_AUDIENCE",
                "Provide the MCP API application ID URI or audience.",
            ),
            (
                "mcp_server_url",
                "AWS_VPC_FLOW_MCP_SERVER_URL",
                "Provide the final HTTPS MCP resource URL, including /mcp.",
            ),
        ):
            if not os.getenv(env_name):
                questions.append(question(key, prompt))
        for key, env_name, prompt in (
            (
                "managed_identity",
                "AWS_VPC_FLOW_MANAGED_IDENTITY_PRINCIPAL_ID",
                "Provide the MCP workload managed identity principal ID after deployment "
                "and grant it AWSVPCFlow table query permission.",
            ),
            (
                "access_groups",
                "AWS_VPC_FLOW_SECURITY_ANALYST_GROUP_ID",
                "Provide the approved Security Analyst group object ID or "
                "AWSVPCFlow.SecurityAnalyst App Role.",
            ),
            (
                "network_mode",
                "AWS_VPC_FLOW_NETWORK_MODE",
                "Choose public HTTPS, internal ingress, or Private Link/APIM.",
            ),
            (
                "audit_destination",
                "AWS_VPC_FLOW_AUDIT_DESTINATION",
                "Choose the enterprise audit destination and retention policy.",
            ),
        ):
            if not os.getenv(env_name):
                questions.append(question(key, prompt))

    if mode == "remote-client":
        if not os.getenv("AWS_VPC_FLOW_MCP_URL"):
            questions.append(
                question(
                    "mcp_url",
                    "Provide the enterprise AWS VPC Flow MCP HTTPS URL.",
                )
            )
        if not os.getenv("AWS_VPC_FLOW_MCP_SCOPE"):
            questions.append(
                question(
                    "oauth_scope",
                    "Confirm the MCP delegated OAuth scope, normally aws_vpc_flow.read.",
                )
            )
        if not (
            os.getenv("AWS_VPC_FLOW_OPENCLAW_AUTH_PROFILE")
            or os.getenv("AWS_VPC_FLOW_MCP_SUPPORTS_DYNAMIC_CLIENT_REGISTRATION")
        ):
            questions.append(
                question(
                    "oauth_profile",
                    "Provide an OpenClaw enterprise OAuth auth profile ID, or "
                    "confirm that the MCP authorization server supports dynamic "
                    "client registration.",
                )
            )
        if not os.getenv("AWS_VPC_FLOW_APPROVED_AGENT_IDS"):
            questions.append(
                question(
                    "agent_allowlist",
                    "Choose which OpenClaw agents may use this Skill and MCP tools.",
                )
            )

    settings_error = None
    try:
        Settings.from_env(require_workspace=mode in {"local", "server"})
    except ConfigurationError as exc:
        settings_error = str(exc)

    return {
        "mode": mode,
        "ready": not questions and settings_error is None,
        "checks": checks,
        "configurationError": settings_error,
        "questions": questions,
        "secretHandling": (
            "Never request or store client secrets in chat or repository files. "
            "Use managed identity, Key Vault, or an OpenClaw auth profile."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List missing prerequisites for the AWSVPCFlow Skill and MCP."
    )
    parser.add_argument(
        "--mode",
        choices=("local", "server", "remote-client"),
        required=True,
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = collect(args.mode)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Mode: {result['mode']}")
        print(f"Ready: {'yes' if result['ready'] else 'no'}")
        if result["configurationError"]:
            print(f"Configuration: {result['configurationError']}")
        if result["questions"]:
            print("\nRequired questions:")
            for item in result["questions"]:
                marker = "*" if item["required"] else "-"
                print(f"{marker} {item['prompt']}")
        print(f"\nSecurity: {result['secretHandling']}")
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
