#!/usr/bin/env python3
"""Generate or apply an OpenClaw MCP registry entry without handling secrets."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_vpc_flow_mcp.env_file import EnvironmentFileError, apply_environment_file

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


def local_definition(args: argparse.Namespace) -> dict:
    project = str(Path(args.project_dir).expanduser().resolve())
    env = {
        "AWS_VPC_FLOW_WORKSPACE_ID": args.workspace_id,
        "AWS_VPC_FLOW_MCP_AUTH_MODE": "local",
        "AWS_VPC_FLOW_LOCAL_ROLE": "security_analyst",
        "AWS_VPC_FLOW_AZURE_AUTH_MODE": args.azure_auth_mode,
    }
    if args.subscription_id:
        env["AWS_VPC_FLOW_SUBSCRIPTION_ID"] = args.subscription_id
    return {
        "command": "uv",
        "args": [
            "run",
            "--project",
            project,
            "aws-vpc-flow-mcp",
            "--transport",
            "stdio",
        ],
        "cwd": project,
        "env": env,
        "requestTimeoutMs": 60000,
        "connectionTimeoutMs": 15000,
        "supportsParallelToolCalls": True,
        "toolFilter": {"include": TOOLS},
    }


def remote_definition(args: argparse.Namespace) -> dict:
    oauth = {"scope": args.scope}
    if args.auth_profile:
        oauth["authProfileId"] = args.auth_profile
    return {
        "url": args.url,
        "transport": "streamable-http",
        "auth": "oauth",
        "oauth": oauth,
        "requestTimeoutMs": 60000,
        "connectionTimeoutMs": 10000,
        "supportsParallelToolCalls": True,
        "toolFilter": {"include": TOOLS},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("local", "remote"))
    parser.add_argument("--env-file")
    parser.add_argument("--name", default="aws-vpc-flow")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")

    parser.add_argument("--project-dir", default=str(Path(__file__).parents[1]))
    parser.add_argument("--workspace-id")
    parser.add_argument("--subscription-id")
    parser.add_argument(
        "--azure-auth-mode",
        choices=("default", "azure-cli", "managed-identity", "environment"),
    )

    parser.add_argument("--url")
    parser.add_argument("--scope")
    parser.add_argument("--auth-profile")
    parser.add_argument(
        "--agents",
        help="Comma-separated OpenClaw Agent IDs approved to use this Skill.",
    )
    return parser.parse_args()


def populate_from_environment(args: argparse.Namespace) -> None:
    args.mode = args.mode or os.getenv("AWS_VPC_FLOW_CONNECTION_MODE")
    args.workspace_id = (
        args.workspace_id
        or os.getenv("AWS_VPC_FLOW_WORKSPACE_ID")
        or os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
    )
    args.subscription_id = (
        args.subscription_id
        or os.getenv("AWS_VPC_FLOW_SUBSCRIPTION_ID")
        or os.getenv("AZURE_SUBSCRIPTION_ID")
    )
    args.azure_auth_mode = (
        args.azure_auth_mode or os.getenv("AWS_VPC_FLOW_AZURE_AUTH_MODE") or "azure-cli"
    )
    args.url = (
        args.url or os.getenv("AWS_VPC_FLOW_MCP_URL") or os.getenv("AWS_VPC_FLOW_MCP_SERVER_URL")
    )
    args.scope = args.scope or os.getenv("AWS_VPC_FLOW_MCP_SCOPE") or "aws_vpc_flow.read"
    args.auth_profile = args.auth_profile or os.getenv("AWS_VPC_FLOW_OPENCLAW_AUTH_PROFILE")
    args.agents = args.agents or os.getenv("AWS_VPC_FLOW_APPROVED_AGENT_IDS")


def main() -> int:
    args = parse_args()
    if args.env_file:
        try:
            apply_environment_file(Path(args.env_file).expanduser())
        except (OSError, EnvironmentFileError) as exc:
            print(f"error: could not load --env-file: {exc}", file=sys.stderr)
            return 2
    populate_from_environment(args)
    if args.mode not in {"local", "remote"}:
        print(
            "error: set --mode or AWS_VPC_FLOW_CONNECTION_MODE to local or remote",
            file=sys.stderr,
        )
        return 2
    if args.mode == "local":
        if not args.workspace_id:
            print("error: --workspace-id is required for local mode", file=sys.stderr)
            return 2
        definition = local_definition(args)
    else:
        if not args.url:
            print("error: --url is required for remote mode", file=sys.stderr)
            return 2
        if not args.url.startswith("https://"):
            print("error: enterprise remote MCP URLs must use HTTPS", file=sys.stderr)
            return 2
        definition = remote_definition(args)

    command = ["openclaw", "mcp", "set", args.name, json.dumps(definition)]
    follow_up = (
        [
            f"openclaw mcp login {args.name}",
            f"openclaw mcp doctor {args.name} --probe",
        ]
        if args.mode == "remote"
        else [f"openclaw mcp doctor {args.name} --probe"]
    )
    output = {
        "definition": definition,
        "command": command,
        "followUp": follow_up,
        "agentSkillAllowlist": {
            agent_id.strip(): ["azure-la-aws-vpc-flow"]
            for agent_id in (args.agents or "").split(",")
            if agent_id.strip()
        },
        "secretHandling": (
            "No client secret or bearer token is accepted by this script. "
            "Use managed identity or an OpenClaw OAuth auth profile."
        ),
    }
    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print("Configuration:")
        print(json.dumps(definition, indent=2))
        print("\nApply command:")
        print(" ".join(json.dumps(part) for part in command))
        print("\nFollow-up:")
        for item in follow_up:
            print(item)

    if args.apply:
        if shutil.which("openclaw") is None:
            print("error: openclaw command was not found", file=sys.stderr)
            return 2
        subprocess.run(command, check=True)
        print("OpenClaw MCP definition saved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
