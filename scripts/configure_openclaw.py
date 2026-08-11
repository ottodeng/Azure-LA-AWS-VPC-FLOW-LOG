#!/usr/bin/env python3
"""Generate or apply an OpenClaw MCP registry entry without handling secrets."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

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
        "AWS_VPC_FLOW_AZURE_AUTH_MODE": "azure-cli",
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
    parser.add_argument("--mode", choices=("local", "remote"), required=True)
    parser.add_argument("--name", default="aws-vpc-flow")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")

    parser.add_argument("--project-dir", default=str(Path(__file__).parents[1]))
    parser.add_argument("--workspace-id")
    parser.add_argument("--subscription-id")

    parser.add_argument("--url")
    parser.add_argument("--scope", default="aws_vpc_flow.read")
    parser.add_argument("--auth-profile")
    parser.add_argument(
        "--agents",
        help="Comma-separated OpenClaw Agent IDs approved to use this Skill.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
