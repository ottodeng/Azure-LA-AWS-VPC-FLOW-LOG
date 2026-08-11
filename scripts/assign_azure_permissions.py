#!/usr/bin/env python3
"""Create and assign a table-scoped AWSVPCFlow query role."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile

ROLE_NAME = "AWSVPCFlow Table Reader"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--workspace-resource-id", required=True)
    parser.add_argument("--principal-object-id", required=True)
    parser.add_argument("--role-name", default=ROLE_NAME)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def run(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
    return result.stdout.strip()


def main() -> int:
    args = parse_args()
    expected_prefix = f"/subscriptions/{args.subscription}/"
    if not args.workspace_resource_id.lower().startswith(expected_prefix.lower()):
        print(
            "error: workspace resource ID does not belong to the supplied subscription",
            file=sys.stderr,
        )
        return 2

    definition = {
        "Name": args.role_name,
        "IsCustom": True,
        "Description": (
            "Read-only query access to the AWSVPCFlow table in an assigned Log Analytics workspace."
        ),
        "Actions": [
            "Microsoft.OperationalInsights/workspaces/read",
            "Microsoft.OperationalInsights/workspaces/api/query/action",
            "Microsoft.OperationalInsights/workspaces/analytics/query/action",
        ],
        "NotActions": [],
        "DataActions": ["Microsoft.OperationalInsights/workspaces/query/AWSVPCFlow/read"],
        "NotDataActions": [],
        "AssignableScopes": [f"/subscriptions/{args.subscription}"],
    }
    print(json.dumps(definition, indent=2))
    print("\nAssignment:")
    print(
        json.dumps(
            {
                "principalObjectId": args.principal_object_id,
                "scope": args.workspace_resource_id,
                "role": args.role_name,
            },
            indent=2,
        )
    )
    if not args.apply:
        print("\nDry run only. Re-run with --apply after review.")
        return 0

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
        json.dump(definition, handle)
        handle.flush()
        existing = run(
            [
                "az",
                "role",
                "definition",
                "list",
                "--subscription",
                args.subscription,
                "--name",
                args.role_name,
                "--query",
                "[0].name",
                "-o",
                "tsv",
            ]
        )
        action = "update" if existing else "create"
        run(
            [
                "az",
                "role",
                "definition",
                action,
                "--subscription",
                args.subscription,
                "--role-definition",
                handle.name,
            ]
        )
    run(
        [
            "az",
            "role",
            "assignment",
            "create",
            "--subscription",
            args.subscription,
            "--assignee-object-id",
            args.principal_object_id,
            "--assignee-principal-type",
            "ServicePrincipal",
            "--role",
            args.role_name,
            "--scope",
            args.workspace_resource_id,
        ]
    )
    print("Role definition and workspace assignment completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
