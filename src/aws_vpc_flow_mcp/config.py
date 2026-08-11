from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID


class ConfigurationError(ValueError):
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    value = default if raw is None else int(raw)
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _csv(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    workspace_id: str | None
    subscription_id: str | None
    table_name: str
    query_endpoint: str
    token_scopes: tuple[str, ...]
    azure_auth_mode: str
    default_timespan_hours: int
    max_timespan_hours: int
    max_rows: int
    query_timeout_seconds: int
    access_policy_path: Path | None
    access_policy_json: str | None
    audit_log_path: Path | None
    audit_include_upn: bool
    local_role: str
    auth_mode: str
    tenant_id: str | None
    mcp_audience: str | None
    mcp_scope: str
    mcp_server_url: str | None
    mcp_issuer_url: str | None
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    allow_insecure_remote_http: bool
    log_level: str

    @classmethod
    def from_env(cls, *, require_workspace: bool = True) -> Settings:
        workspace_id = os.getenv("AWS_VPC_FLOW_WORKSPACE_ID") or os.getenv(
            "AZURE_LOG_ANALYTICS_WORKSPACE_ID"
        )
        if require_workspace and not workspace_id:
            raise ConfigurationError(
                "Set AWS_VPC_FLOW_WORKSPACE_ID to the Log Analytics workspace customer ID."
            )
        if workspace_id:
            try:
                UUID(workspace_id)
            except ValueError as exc:
                raise ConfigurationError(
                    "AWS_VPC_FLOW_WORKSPACE_ID must be a workspace customer ID GUID."
                ) from exc

        table_name = os.getenv("AWS_VPC_FLOW_TABLE", "AWSVPCFlow")
        if table_name != "AWSVPCFlow":
            raise ConfigurationError("AWS_VPC_FLOW_TABLE must be exactly AWSVPCFlow.")

        auth_mode = os.getenv("AWS_VPC_FLOW_MCP_AUTH_MODE", "local").strip().lower()
        if auth_mode not in {"local", "entra"}:
            raise ConfigurationError("AWS_VPC_FLOW_MCP_AUTH_MODE must be local or entra.")

        tenant_id = os.getenv("AWS_VPC_FLOW_MCP_TENANT_ID") or os.getenv("AZURE_TENANT_ID")
        audience = os.getenv("AWS_VPC_FLOW_MCP_AUDIENCE")
        server_url = os.getenv("AWS_VPC_FLOW_MCP_SERVER_URL")
        issuer_url = os.getenv("AWS_VPC_FLOW_MCP_ISSUER_URL")
        if auth_mode == "entra":
            missing = [
                name
                for name, value in (
                    ("AWS_VPC_FLOW_MCP_TENANT_ID", tenant_id),
                    ("AWS_VPC_FLOW_MCP_AUDIENCE", audience),
                    ("AWS_VPC_FLOW_MCP_SERVER_URL", server_url),
                )
                if not value
            ]
            if missing:
                raise ConfigurationError("Entra MCP authentication requires: " + ", ".join(missing))
            if issuer_url is None:
                issuer_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

        policy_raw = os.getenv("AWS_VPC_FLOW_ACCESS_POLICY")
        audit_raw = os.getenv("AWS_VPC_FLOW_AUDIT_LOG")
        scopes = _csv("AWS_VPC_FLOW_TOKEN_SCOPES") or (
            "https://api.loganalytics.io/.default",
            "https://api.loganalytics.azure.com/.default",
        )
        azure_auth_mode = os.getenv("AWS_VPC_FLOW_AZURE_AUTH_MODE", "default").lower()
        if azure_auth_mode not in {
            "default",
            "azure-cli",
            "managed-identity",
            "environment",
        }:
            raise ConfigurationError(
                "AWS_VPC_FLOW_AZURE_AUTH_MODE must be default, azure-cli, "
                "managed-identity, or environment."
            )

        return cls(
            workspace_id=workspace_id,
            subscription_id=os.getenv("AWS_VPC_FLOW_SUBSCRIPTION_ID")
            or os.getenv("AZURE_SUBSCRIPTION_ID"),
            table_name=table_name,
            query_endpoint=os.getenv(
                "AWS_VPC_FLOW_QUERY_ENDPOINT", "https://api.loganalytics.azure.com"
            ).rstrip("/"),
            token_scopes=scopes,
            azure_auth_mode=azure_auth_mode,
            default_timespan_hours=_env_int("AWS_VPC_FLOW_DEFAULT_TIMESPAN_HOURS", 24, 1, 24 * 30),
            max_timespan_hours=_env_int("AWS_VPC_FLOW_MAX_TIMESPAN_HOURS", 24 * 30, 1, 24 * 365),
            max_rows=_env_int("AWS_VPC_FLOW_MAX_ROWS", 2000, 1, 5000),
            query_timeout_seconds=_env_int("AWS_VPC_FLOW_QUERY_TIMEOUT_SECONDS", 60, 1, 300),
            access_policy_path=Path(policy_raw).expanduser() if policy_raw else None,
            access_policy_json=os.getenv("AWS_VPC_FLOW_ACCESS_POLICY_JSON"),
            audit_log_path=Path(audit_raw).expanduser() if audit_raw else None,
            audit_include_upn=_env_bool("AWS_VPC_FLOW_AUDIT_INCLUDE_UPN"),
            local_role=os.getenv("AWS_VPC_FLOW_LOCAL_ROLE", "security_analyst"),
            auth_mode=auth_mode,
            tenant_id=tenant_id,
            mcp_audience=audience,
            mcp_scope=os.getenv("AWS_VPC_FLOW_MCP_SCOPE", "aws_vpc_flow.read"),
            mcp_server_url=server_url,
            mcp_issuer_url=issuer_url,
            allowed_hosts=_csv("AWS_VPC_FLOW_ALLOWED_HOSTS"),
            allowed_origins=_csv("AWS_VPC_FLOW_ALLOWED_ORIGINS"),
            allow_insecure_remote_http=_env_bool("AWS_VPC_FLOW_ALLOW_INSECURE_REMOTE_HTTP"),
            log_level=os.getenv("AWS_VPC_FLOW_LOG_LEVEL", "INFO").upper(),
        )

    def require_workspace(self) -> str:
        if not self.workspace_id:
            raise ConfigurationError("AWS_VPC_FLOW_WORKSPACE_ID is required before querying logs.")
        return self.workspace_id
