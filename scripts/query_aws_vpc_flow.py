#!/usr/bin/env python3
"""Run guarded, read-only KQL against the AWSVPCFlow Log Analytics table."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any


LOGS_ENDPOINT = "https://api.loganalytics.azure.com/v1/workspaces/{workspace_id}/query"
TOKEN_RESOURCES = (
    "https://api.loganalytics.azure.com",
    "https://api.loganalytics.io",
)
ALLOWED_TABLE = "AWSVPCFlow"
BLOCKED_PATTERNS = {
    "cross-workspace function": r"\b(workspace|app|resource)\s*\(",
    "cross-cluster function": r"\b(cluster|database)\s*\(",
    "external data access": r"\b(externaldata|external_table)\b",
    "cross-table operator": r"\b(union|join|lookup|search|find)\b",
    "plugin invocation": r"\bevaluate\b",
    "multiple KQL statements": r";",
    "Kusto management command": r"(?m)^\s*\.",
}


class QueryError(RuntimeError):
    pass


def validate_query(query: str) -> str:
    normalized = query.strip()
    if not normalized:
        raise QueryError("KQL query is empty.")
    without_comments = re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL)
    without_comments = re.sub(r"(?m)//.*$", "", without_comments).lstrip()
    if not re.match(
        rf"(?i){re.escape(ALLOWED_TABLE)}(?:\s|\|)", without_comments
    ):
        raise QueryError(f"KQL must start from the {ALLOWED_TABLE} table.")
    for label, pattern in BLOCKED_PATTERNS.items():
        if re.search(pattern, normalized, re.IGNORECASE):
            raise QueryError(f"KQL contains a blocked {label}.")
    return normalized


def get_access_token(subscription_id: str | None) -> str:
    supplied = os.getenv("AZURE_LOG_ANALYTICS_TOKEN")
    if supplied:
        return supplied

    errors: list[str] = []
    for resource in TOKEN_RESOURCES:
        command = [
            "az",
            "account",
            "get-access-token",
            "--resource",
            resource,
            "--query",
            "accessToken",
            "-o",
            "tsv",
        ]
        if subscription_id:
            command[3:3] = ["--subscription", subscription_id]
        try:
            result = subprocess.run(
                command, check=True, capture_output=True, text=True, timeout=30
            )
        except FileNotFoundError as exc:
            raise QueryError(
                "Azure CLI was not found. Install `az` or set AZURE_LOG_ANALYTICS_TOKEN."
            ) from exc
        except subprocess.CalledProcessError as exc:
            errors.append((exc.stderr or exc.stdout).strip())
            continue
        token = result.stdout.strip()
        if token:
            return token
        errors.append(f"Azure CLI returned an empty token for {resource}.")
    raise QueryError("Azure authentication failed: " + " | ".join(errors))


def query_logs(
    workspace_id: str,
    query: str,
    timespan: str,
    subscription_id: str | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    token = get_access_token(subscription_id)
    body = json.dumps({"query": query, "timespan": timespan}).encode("utf-8")
    request = urllib.request.Request(
        LOGS_ENDPOINT.format(workspace_id=workspace_id),
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise QueryError(f"Log Analytics returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise QueryError(f"Could not reach Log Analytics: {exc.reason}") from exc


def normalized_result(
    payload: dict[str, Any],
    query: str,
    timespan: str,
    max_rows: int,
) -> dict[str, Any]:
    result_tables: list[dict[str, Any]] = []
    truncated = False
    for table in payload.get("tables", []):
        columns = [column["name"] for column in table.get("columns", [])]
        rows = table.get("rows", [])
        if len(rows) > max_rows:
            rows = rows[:max_rows]
            truncated = True
        result_tables.append(
            {
                "name": table.get("name", "PrimaryResult"),
                "columns": columns,
                "rows": [dict(zip(columns, row)) for row in rows],
            }
        )
    return {
        "table": ALLOWED_TABLE,
        "query": query,
        "timespan": timespan,
        "truncated": truncated,
        "tables": result_tables,
    }


def markdown_escape(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", r"\|").replace("\n", " ")


def format_markdown(result: dict[str, Any]) -> str:
    sections: list[str] = []
    for table in result["tables"]:
        columns = table["columns"]
        rows = table["rows"]
        sections.append(f"### {table['name']}")
        if not columns:
            sections.append("_No columns returned._")
            continue
        sections.append("| " + " | ".join(columns) + " |")
        sections.append("| " + " | ".join(["---"] * len(columns)) + " |")
        for row in rows:
            sections.append(
                "| "
                + " | ".join(markdown_escape(row.get(column)) for column in columns)
                + " |"
            )
        if not rows:
            sections.append(f"| {' | '.join([''] * len(columns))} |")
    if result["truncated"]:
        sections.append("\n_Result output was truncated by the local row limit._")
    return "\n".join(sections)


def format_plain_table(result: dict[str, Any]) -> str:
    lines: list[str] = []
    for table in result["tables"]:
        columns = table["columns"]
        rows = table["rows"]
        lines.append(f"[{table['name']}]")
        lines.append("\t".join(columns))
        for row in rows:
            lines.append("\t".join(str(row.get(column, "")) for column in columns))
    if result["truncated"]:
        lines.append("[output truncated]")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query AWSVPCFlow through the read-only Log Analytics API."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--query", help="KQL query text.")
    source.add_argument("--query-file", help="Path to a UTF-8 KQL file.")
    parser.add_argument(
        "--workspace-id",
        default=os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID"),
        help="Log Analytics workspace customer ID GUID.",
    )
    parser.add_argument(
        "--subscription",
        default=os.getenv("AZURE_SUBSCRIPTION_ID"),
        help="Subscription used by Azure CLI token acquisition.",
    )
    parser.add_argument(
        "--timespan",
        default="PT24H",
        help="ISO 8601 query timespan, for example PT1H, PT24H, or P7D.",
    )
    parser.add_argument("--max-rows", type=int, default=200)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument(
        "--format", choices=("json", "markdown", "table"), default="json"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Validate and print KQL without calling Azure."
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        query = args.query
        if args.query_file:
            with open(args.query_file, encoding="utf-8") as handle:
                query = handle.read()
        query = validate_query(query or "")
        if args.max_rows < 1 or args.max_rows > 5000:
            raise QueryError("--max-rows must be between 1 and 5000.")
        if args.timeout < 1 or args.timeout > 300:
            raise QueryError("--timeout must be between 1 and 300 seconds.")
        if args.dry_run:
            print(query)
            return 0
        if not args.workspace_id:
            raise QueryError(
                "Set AZURE_LOG_ANALYTICS_WORKSPACE_ID or pass --workspace-id."
            )
        payload = query_logs(
            args.workspace_id,
            query,
            args.timespan,
            args.subscription,
            args.timeout,
        )
        result = normalized_result(payload, query, args.timespan, args.max_rows)
        if args.format == "json":
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.format == "markdown":
            print(format_markdown(result))
        else:
            print(format_plain_table(result))
        return 0
    except (OSError, QueryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
