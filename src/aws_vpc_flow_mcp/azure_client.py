from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from .config import Settings


class LogsQueryError(RuntimeError):
    pass


class AzureLogsClient:
    def __init__(self, settings: Settings, credential: Any | None = None) -> None:
        self.settings = settings
        self._credential = credential
        self._token_lock = threading.Lock()
        self._cached_token: str | None = None
        self._cached_token_expires_on = 0

    def _build_credential(self) -> Any:
        from azure.identity import (
            AzureCliCredential,
            DefaultAzureCredential,
            EnvironmentCredential,
            ManagedIdentityCredential,
        )

        mode = self.settings.azure_auth_mode
        if mode == "azure-cli":
            return AzureCliCredential()
        if mode == "managed-identity":
            return ManagedIdentityCredential()
        if mode == "environment":
            return EnvironmentCredential()
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)

    def _get_token(self) -> str:
        supplied = os.getenv("AZURE_LOG_ANALYTICS_TOKEN")
        if supplied:
            return supplied
        with self._token_lock:
            if (
                self._cached_token is not None
                and self._cached_token_expires_on > int(time.time()) + 300
            ):
                return self._cached_token
            if self._credential is None:
                self._credential = self._build_credential()
            errors: list[str] = []
            for scope in self.settings.token_scopes:
                try:
                    access_token = self._credential.get_token(scope)
                    self._cached_token = access_token.token
                    self._cached_token_expires_on = access_token.expires_on
                    return access_token.token
                except Exception as exc:  # Azure credentials expose multiple error types.
                    errors.append(f"{scope}: {type(exc).__name__}")
            raise LogsQueryError("Could not acquire a Log Analytics token: " + ", ".join(errors))

    async def query(self, query: str, timespan: str, max_rows: int) -> dict[str, Any]:
        return await asyncio.to_thread(self._query_sync, query, timespan, max_rows)

    def _query_sync(self, query: str, timespan: str, max_rows: int) -> dict[str, Any]:
        workspace_id = self.settings.require_workspace()
        token = self._get_token()
        effective_query = f"{query.rstrip()}\n| take {max_rows}"
        url = f"{self.settings.query_endpoint}/v1/workspaces/{workspace_id}/query"
        request = urllib.request.Request(
            url,
            data=json.dumps({"query": effective_query, "timespan": timespan}).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.settings.query_timeout_seconds
            ) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise LogsQueryError(f"Log Analytics returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise LogsQueryError(f"Could not reach Log Analytics: {exc.reason}") from exc

        tables: list[dict[str, Any]] = []
        truncated = False
        row_count = 0
        for table in payload.get("tables", []):
            columns = [column["name"] for column in table.get("columns", [])]
            rows = table.get("rows", [])
            row_count += len(rows)
            if len(rows) > max_rows:
                rows = rows[:max_rows]
                truncated = True
            tables.append(
                {
                    "name": table.get("name", "PrimaryResult"),
                    "columns": columns,
                    "rows": [dict(zip(columns, row, strict=False)) for row in rows],
                }
            )
        return {
            "query": effective_query,
            "timespan": timespan,
            "truncated": truncated,
            "rowCount": row_count,
            "tables": tables,
        }
