#!/usr/bin/env python3
"""Create an Azure Log Analytics/DCR test environment for AWSVPCFlow."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


STREAM = "Custom-AWSVPCFlowRaw"
OUTPUT_STREAM = "Microsoft-AWSVPCFlow"
DCR_API_VERSION = "2023-03-11"
SOLUTION_COMMIT = "abb823c93b286cfe47c0e6210d09eff283127e1d"
SOLUTION_TEMPLATE_URL = (
    "https://raw.githubusercontent.com/Azure/Azure-Sentinel/"
    f"{SOLUTION_COMMIT}/Solutions/AWS%20VPC%20Flow%20Logs/Package/mainTemplate.json"
)

SOURCE_COLUMNS = [
    ("TimeGenerated", "datetime"),
    ("AccountId", "string"),
    ("Action", "string"),
    ("AzId", "string"),
    ("Bytes", "long"),
    ("DstAddr", "string"),
    ("DstPort", "int"),
    ("End", "datetime"),
    ("FlowDirection", "string"),
    ("InstanceId", "string"),
    ("InterfaceId", "string"),
    ("LogStatus", "string"),
    ("Packets", "int"),
    ("PktDstAddr", "string"),
    ("PktDstAwsService", "string"),
    ("PktSrcAddr", "string"),
    ("PktSrcAwsService", "string"),
    ("Protocol", "int"),
    ("Region", "string"),
    ("SrcAddr", "string"),
    ("SrcPort", "int"),
    ("Start", "datetime"),
    ("SubnetId", "string"),
    ("TcpFlags", "int"),
    ("TrafficPath", "string"),
    ("TrafficType", "string"),
    ("Version", "int"),
    ("VpcId", "string"),
]


class DeployError(RuntimeError):
    pass


def run(command: list[str], *, parse_json: bool = False) -> Any:
    print("+ " + " ".join(shlex.quote(part) for part in command), file=sys.stderr)
    try:
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=180
        )
    except FileNotFoundError as exc:
        raise DeployError(f"Command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout).strip()
        raise DeployError(f"Command failed: {detail}") from exc
    if parse_json:
        return json.loads(result.stdout)
    return result.stdout.strip()


def az(*args: str, parse_json: bool = False) -> Any:
    return run(["az", *args], parse_json=parse_json)


def dcr_body(location: str, workspace_resource_id: str) -> dict[str, Any]:
    return {
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": {
                STREAM: {
                    "columns": [
                        {"name": name, "type": column_type}
                        for name, column_type in SOURCE_COLUMNS
                    ]
                }
            },
            "destinations": {
                "logAnalytics": [
                    {
                        "workspaceResourceId": workspace_resource_id,
                        "name": "destination-log-analytics",
                    }
                ]
            },
            "dataFlows": [
                {
                    "streams": [STREAM],
                    "destinations": ["destination-log-analytics"],
                    "transformKql": "source",
                    "outputStream": OUTPUT_STREAM,
                }
            ],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", default="rg-awsvpcflow-skill-demo")
    parser.add_argument("--location", default="eastus")
    parser.add_argument("--workspace-name")
    parser.add_argument("--dcr-name", default="dcr-aws-vpc-flow-skill-dev")
    parser.add_argument("--env-file", default=".azure-env")
    parser.add_argument(
        "--skip-role-assignment",
        action="store_true",
        help="Do not grant the signed-in user Monitoring Metrics Publisher on the DCR.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace_name = args.workspace_name or f"law-awsvpcflow-{args.subscription[:8]}"
    try:
        az(
            "account",
            "get-access-token",
            "--subscription",
            args.subscription,
            "--resource",
            "https://management.azure.com/",
            "--query",
            "expiresOn",
            "-o",
            "tsv",
        )
        for namespace in (
            "Microsoft.OperationalInsights",
            "Microsoft.OperationsManagement",
            "Microsoft.Insights",
            "Microsoft.SecurityInsights",
        ):
            az(
                "provider",
                "register",
                "--subscription",
                args.subscription,
                "--namespace",
                namespace,
                "--wait",
            )
        az(
            "group",
            "create",
            "--subscription",
            args.subscription,
            "--name",
            args.resource_group,
            "--location",
            args.location,
            "-o",
            "none",
        )
        workspace = az(
            "monitor",
            "log-analytics",
            "workspace",
            "create",
            "--subscription",
            args.subscription,
            "--resource-group",
            args.resource_group,
            "--workspace-name",
            workspace_name,
            "--location",
            args.location,
            "--retention-time",
            "30",
            "-o",
            "json",
            parse_json=True,
        )
        workspace_resource_id = workspace["id"]
        workspace_customer_id = workspace["customerId"]

        # AWSVPCFlow is a Microsoft SecurityInsights table. Onboarding makes the
        # workspace ready for Sentinel solution tables and connector data.
        onboarding_url = (
            f"{workspace_resource_id}/providers/Microsoft.SecurityInsights/"
            "onboardingStates/default?api-version=2024-03-01"
        )
        az(
            "rest",
            "--method",
            "put",
            "--url",
            onboarding_url,
            "--body",
            json.dumps({"properties": {"customerManagedKey": False}}),
            "-o",
            "none",
        )

        # Install Microsoft's pinned AWS VPC Flow Logs solution package. The
        # package registers the standard AWSVPCFlow table for this workspace.
        with tempfile.NamedTemporaryFile(suffix=".json") as template_file:
            with urllib.request.urlopen(
                SOLUTION_TEMPLATE_URL, timeout=60
            ) as response:
                template_file.write(response.read())
                template_file.flush()
            az(
                "deployment",
                "group",
                "create",
                "--subscription",
                args.subscription,
                "--resource-group",
                args.resource_group,
                "--name",
                "deploy-aws-vpc-flow-solution",
                "--template-file",
                template_file.name,
                "--parameters",
                f"workspace={workspace_name}",
                f"workspace-location={args.location}",
                f"resourceGroupName={args.resource_group}",
                f"subscription={args.subscription}",
                "-o",
                "none",
            )

        az(
            "monitor",
            "log-analytics",
            "workspace",
            "table",
            "show",
            "--subscription",
            args.subscription,
            "--resource-group",
            args.resource_group,
            "--workspace-name",
            workspace_name,
            "--name",
            "AWSVPCFlow",
            "--query",
            "name",
            "-o",
            "tsv",
        )

        dcr_url = (
            f"/subscriptions/{args.subscription}/resourceGroups/{args.resource_group}"
            f"/providers/Microsoft.Insights/dataCollectionRules/{args.dcr_name}"
            f"?api-version={DCR_API_VERSION}"
        )
        dcr = az(
            "rest",
            "--method",
            "put",
            "--url",
            dcr_url,
            "--body",
            json.dumps(dcr_body(args.location, workspace_resource_id)),
            "-o",
            "json",
            parse_json=True,
        )
        dcr_id = dcr["id"]
        immutable_id = dcr["properties"]["immutableId"]
        ingestion_endpoint = dcr["properties"].get("endpoints", {}).get("logsIngestion")
        if not ingestion_endpoint:
            raise DeployError("The direct DCR did not return a logs ingestion endpoint.")

        if not args.skip_role_assignment:
            principal_id = az("ad", "signed-in-user", "show", "--query", "id", "-o", "tsv")
            existing_role = az(
                "role",
                "assignment",
                "list",
                "--subscription",
                args.subscription,
                "--assignee-object-id",
                principal_id,
                "--scope",
                dcr_id,
                "--query",
                "[?roleDefinitionName=='Monitoring Metrics Publisher'] | [0].id",
                "-o",
                "tsv",
            )
            if not existing_role:
                az(
                    "role",
                    "assignment",
                    "create",
                    "--subscription",
                    args.subscription,
                    "--assignee-object-id",
                    principal_id,
                    "--assignee-principal-type",
                    "User",
                    "--role",
                    "Monitoring Metrics Publisher",
                    "--scope",
                    dcr_id,
                    "-o",
                    "none",
                )

        env_lines = [
            f"export AZURE_SUBSCRIPTION_ID={shlex.quote(args.subscription)}",
            f"export AZURE_LOG_ANALYTICS_WORKSPACE_ID={shlex.quote(workspace_customer_id)}",
            f"export AZURE_LOG_ANALYTICS_WORKSPACE_RESOURCE_ID={shlex.quote(workspace_resource_id)}",
            f"export AZURE_LOGS_INGESTION_ENDPOINT={shlex.quote(ingestion_endpoint)}",
            f"export AZURE_DCR_IMMUTABLE_ID={shlex.quote(immutable_id)}",
            f"export AZURE_DCR_STREAM={shlex.quote(STREAM)}",
        ]
        Path(args.env_file).write_text("\n".join(env_lines) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "resourceGroup": args.resource_group,
                    "workspaceName": workspace_name,
                    "workspaceId": workspace_customer_id,
                    "workspaceResourceId": workspace_resource_id,
                    "dcrName": args.dcr_name,
                    "dcrImmutableId": immutable_id,
                    "logsIngestionEndpoint": ingestion_endpoint,
                    "solutionSourceCommit": SOLUTION_COMMIT,
                    "envFile": args.env_file,
                },
                indent=2,
            )
        )
        return 0
    except (DeployError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
