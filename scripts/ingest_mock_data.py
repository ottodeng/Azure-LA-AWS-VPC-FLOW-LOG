#!/usr/bin/env python3
"""Upload JSON records through an Azure Monitor Logs Ingestion DCR."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

TOKEN_RESOURCE = "https://monitor.azure.com/"
API_VERSION = "2023-01-01"


class IngestionError(RuntimeError):
    pass


def az_token(subscription_id: str | None) -> str:
    command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        TOKEN_RESOURCE,
        "--query",
        "accessToken",
        "-o",
        "tsv",
    ]
    if subscription_id:
        command[3:3] = ["--subscription", subscription_id]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise IngestionError(f"Could not acquire Azure Monitor token: {detail}") from exc
    return result.stdout.strip()


def post_batch(url: str, token: str, rows: list[dict[str, Any]]) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(rows, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.status not in (200, 204):
                raise IngestionError(f"Unexpected ingestion status {response.status}.")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise IngestionError(f"Ingestion returned HTTP {exc.code}: {detail}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="mock-data.json")
    parser.add_argument("--endpoint", default=os.getenv("AZURE_LOGS_INGESTION_ENDPOINT"))
    parser.add_argument("--dcr-immutable-id", default=os.getenv("AZURE_DCR_IMMUTABLE_ID"))
    parser.add_argument("--stream", default=os.getenv("AZURE_DCR_STREAM", "Custom-AWSVPCFlowRaw"))
    parser.add_argument("--subscription", default=os.getenv("AZURE_SUBSCRIPTION_ID"))
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--wait-between-batches", type=float, default=1.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not args.endpoint or not args.dcr_immutable_id:
            raise IngestionError("Set AZURE_LOGS_INGESTION_ENDPOINT and AZURE_DCR_IMMUTABLE_ID.")
        rows = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if not isinstance(rows, list) or not rows:
            raise IngestionError("Input must be a non-empty JSON array.")
        if args.batch_size < 1 or args.batch_size > 1000:
            raise IngestionError("--batch-size must be between 1 and 1000.")
        endpoint = args.endpoint.rstrip("/")
        stream = urllib.parse.quote(args.stream, safe="-_")
        url = (
            f"{endpoint}/dataCollectionRules/{args.dcr_immutable_id}"
            f"/streams/{stream}?api-version={API_VERSION}"
        )
        token = az_token(args.subscription)
        sent = 0
        for start in range(0, len(rows), args.batch_size):
            batch = rows[start : start + args.batch_size]
            post_batch(url, token, batch)
            sent += len(batch)
            print(f"ingested {sent}/{len(rows)}", file=sys.stderr)
            if sent < len(rows):
                time.sleep(args.wait_between_batches)
        print(json.dumps({"ingested": sent, "stream": args.stream}))
        return 0
    except (OSError, ValueError, IngestionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
