from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from mcp.server.auth.middleware.auth_context import get_access_token

from .access import AccessPolicy, Principal, RolePolicy
from .audit import AuditLogger
from .azure_client import AzureLogsClient
from .config import Settings
from .query_policy import (
    QueryPolicyError,
    hours_to_timespan,
    validate_kql,
    validate_limit,
    validate_timespan,
)

T = TypeVar("T")

SCHEMA = [
    {"name": "TimeGenerated", "type": "datetime"},
    {"name": "AccountId", "type": "string"},
    {"name": "Action", "type": "string"},
    {"name": "AzId", "type": "string"},
    {"name": "Bytes", "type": "long"},
    {"name": "DstAddr", "type": "string"},
    {"name": "DstPort", "type": "int"},
    {"name": "End", "type": "datetime"},
    {"name": "FlowDirection", "type": "string"},
    {"name": "InstanceId", "type": "string"},
    {"name": "InterfaceId", "type": "string"},
    {"name": "LogStatus", "type": "string"},
    {"name": "Packets", "type": "int"},
    {"name": "PktDstAddr", "type": "string"},
    {"name": "PktDstAwsService", "type": "string"},
    {"name": "PktSrcAddr", "type": "string"},
    {"name": "PktSrcAwsService", "type": "string"},
    {"name": "Protocol", "type": "int"},
    {"name": "Region", "type": "string"},
    {"name": "SrcAddr", "type": "string"},
    {"name": "SrcPort", "type": "int"},
    {"name": "Start", "type": "datetime"},
    {"name": "SubnetId", "type": "string"},
    {"name": "TcpFlags", "type": "int"},
    {"name": "TrafficPath", "type": "string"},
    {"name": "TrafficType", "type": "string"},
    {"name": "Version", "type": "int"},
    {"name": "VpcId", "type": "string"},
]


def current_principal() -> Principal:
    token = get_access_token()
    if token is None:
        return Principal(subject="local", client_id="local")
    claims = token.claims or {}
    groups = claims.get("groups", [])
    roles = claims.get("roles", [])
    return Principal(
        subject=token.subject or "unknown",
        client_id=token.client_id,
        groups=tuple(str(group) for group in groups) if isinstance(groups, list) else (),
        role_claims=tuple(str(role) for role in roles) if isinstance(roles, list) else (),
        upn=str(claims.get("preferred_username") or claims.get("upn") or "") or None,
    )


class ToolService:
    def __init__(
        self,
        settings: Settings,
        policy: AccessPolicy | None = None,
        client: AzureLogsClient | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.settings = settings
        self.policy = policy or AccessPolicy.load(
            settings.access_policy_path, settings.access_policy_json
        )
        self.client = client or AzureLogsClient(settings)
        self.audit = audit or AuditLogger(
            settings.audit_log_path,
            settings.workspace_id,
            settings.audit_include_upn,
        )

    def _authorize(self, tool: str) -> tuple[Principal, str, RolePolicy]:
        principal = current_principal()
        role_name, role = self.policy.authorize(
            principal, tool, local_role=self.settings.local_role
        )
        return principal, role_name, role

    async def _execute(
        self,
        tool: str,
        operation: Callable[[RolePolicy], Awaitable[T]],
        *,
        query_for_audit: str | None = None,
    ) -> T:
        principal, role_name, role = self._authorize(tool)
        started = time.monotonic()
        try:
            result = await operation(role)
            duration = int((time.monotonic() - started) * 1000)
            row_count = _result_row_count(result)
            self.audit.record(
                principal=principal,
                role=role_name,
                tool=tool,
                status="success",
                duration_ms=duration,
                row_count=row_count,
                query=query_for_audit or _result_queries(result),
            )
            return result
        except Exception as exc:
            duration = int((time.monotonic() - started) * 1000)
            self.audit.record(
                principal=principal,
                role=role_name,
                tool=tool,
                status="error",
                duration_ms=duration,
                query=query_for_audit,
                error_type=type(exc).__name__,
            )
            raise

    def _limits(self, role: RolePolicy) -> tuple[int, int]:
        return (
            min(role.max_timespan_hours, self.settings.max_timespan_hours),
            min(role.max_rows, self.settings.max_rows),
        )

    async def service_status(self) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            return {
                "service": "azure-la-aws-vpc-flow",
                "ready": bool(self.settings.workspace_id),
                "table": self.settings.table_name,
                "authenticationMode": self.settings.auth_mode,
                "maxTimespanHours": max_hours,
                "maxRows": max_rows,
                "accessPolicy": self.policy.public_summary(),
            }

        return await self._execute("service_status", operation)

    async def get_schema(self) -> dict[str, Any]:
        async def operation(_: RolePolicy) -> dict[str, Any]:
            return {"table": "AWSVPCFlow", "columns": SCHEMA}

        return await self._execute("get_schema", operation)

    async def security_summary(self, hours: int = 24) -> dict[str, Any]:
        queries = {
            "rejectedSources": """
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where Action =~ "REJECT"
| summarize Rejects=count(), DistinctPorts=dcount(DstPort),
    DistinctTargets=dcount(DstAddr) by SrcAddr
| where Rejects >= 10
| top 20 by Rejects desc
""",
            "largeEgress": """
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where FlowDirection =~ "egress" and Action =~ "ACCEPT"
| summarize Bytes=sum(Bytes), Packets=sum(Packets), Flows=count()
    by SrcAddr, DstAddr, DstPort
| where Bytes >= 100000000
| top 20 by Bytes desc
""",
            "lateralMovement": """
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where SrcAddr startswith "10." and DstAddr startswith "10."
| where DstPort in (22, 3389, 445) and Action =~ "ACCEPT"
| summarize Connections=count(), Targets=dcount(DstAddr),
    Ports=make_set(DstPort), Bytes=sum(Bytes) by SrcAddr
| where Targets >= 5
| top 20 by Targets desc
""",
            "collectionHealth": """
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| summarize Records=count() by LogStatus
| order by Records desc
""",
        }

        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            rendered = {
                name: validate_kql(template.format(hours=hours))
                for name, template in queries.items()
            }
            results = await asyncio.gather(
                *(self.client.query(query, timespan, max_rows) for query in rendered.values())
            )
            return {
                "hours": hours,
                "detectors": {name: result for name, result in zip(rendered, results, strict=True)},
            }

        return await self._execute("security_summary", operation)

    async def top_talkers(
        self, hours: int = 24, limit: int = 20, direction: str = "all"
    ) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            bounded_limit = validate_limit(limit, min(max_rows, 100))
            normalized_direction = direction.lower()
            if normalized_direction not in {"all", "ingress", "egress"}:
                raise QueryPolicyError("direction must be all, ingress, or egress.")
            direction_clause = (
                ""
                if normalized_direction == "all"
                else f'| where FlowDirection =~ "{normalized_direction}"'
            )
            query = validate_kql(
                f"""
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
{direction_clause}
| summarize Bytes=sum(Bytes), Packets=sum(Packets), Flows=count()
    by SrcAddr, DstAddr
| top {bounded_limit} by Bytes desc
"""
            )
            return await self.client.query(query, timespan, bounded_limit)

        return await self._execute("top_talkers", operation)

    async def detect_port_scans(
        self, hours: int = 1, min_distinct_ports: int = 20
    ) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            if not 2 <= min_distinct_ports <= 65535:
                raise QueryPolicyError("min_distinct_ports must be between 2 and 65535.")
            query = validate_kql(
                f"""
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where Action =~ "REJECT"
| summarize Attempts=count(), DistinctPorts=dcount(DstPort),
    DistinctTargets=dcount(DstAddr) by SrcAddr, bin(TimeGenerated, 5m)
| where DistinctPorts >= {min_distinct_ports}
| order by Attempts desc
"""
            )
            return await self.client.query(query, timespan, max_rows)

        return await self._execute("detect_port_scans", operation)

    async def detect_brute_force(
        self, hours: int = 6, ports: str = "22,3389", min_rejects: int = 20
    ) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            parsed_ports = sorted(
                {int(value.strip()) for value in ports.split(",") if value.strip()}
            )
            if not parsed_ports or any(port < 1 or port > 65535 for port in parsed_ports):
                raise QueryPolicyError("ports must contain valid TCP/UDP port numbers.")
            if min_rejects < 1:
                raise QueryPolicyError("min_rejects must be at least 1.")
            port_list = ",".join(str(port) for port in parsed_ports)
            query = validate_kql(
                f"""
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where DstPort in ({port_list})
| summarize Attempts=count(), Rejects=countif(Action =~ "REJECT"),
    Accepts=countif(Action =~ "ACCEPT"), FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated) by SrcAddr, DstAddr, DstPort
| where Rejects >= {min_rejects}
| order by Rejects desc
"""
            )
            return await self.client.query(query, timespan, max_rows)

        return await self._execute("detect_brute_force", operation)

    async def detect_large_egress(
        self, hours: int = 24, min_bytes: int = 100_000_000
    ) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            if min_bytes < 1:
                raise QueryPolicyError("min_bytes must be at least 1.")
            query = validate_kql(
                f"""
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where FlowDirection =~ "egress" and Action =~ "ACCEPT"
| summarize Bytes=sum(Bytes), Packets=sum(Packets), Flows=count(),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
    by SrcAddr, DstAddr, DstPort
| where Bytes >= {min_bytes}
| order by Bytes desc
"""
            )
            return await self.client.query(query, timespan, max_rows)

        return await self._execute("detect_large_egress", operation)

    async def investigate_ip(self, ip: str, hours: int = 24, limit: int = 100) -> dict[str, Any]:
        address = str(ipaddress.ip_address(ip))

        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            bounded_limit = validate_limit(limit, max_rows)
            query = validate_kql(
                f"""
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| where SrcAddr == "{address}" or DstAddr == "{address}"
    or PktSrcAddr == "{address}" or PktDstAddr == "{address}"
| project TimeGenerated, Action, FlowDirection, SrcAddr, SrcPort,
    DstAddr, DstPort, Protocol, Packets, Bytes, InstanceId,
    InterfaceId, VpcId, SubnetId, LogStatus
| order by TimeGenerated desc
| take {bounded_limit}
"""
            )
            return await self.client.query(query, timespan, bounded_limit)

        return await self._execute("investigate_ip", operation)

    async def collection_health(self, hours: int = 24) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            max_hours, max_rows = self._limits(role)
            timespan = hours_to_timespan(hours, max_hours)
            query = validate_kql(
                f"""
AWSVPCFlow
| where TimeGenerated >= ago({hours}h)
| summarize Records=count() by LogStatus, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
"""
            )
            return await self.client.query(query, timespan, max_rows)

        return await self._execute("collection_health", operation)

    async def query_aws_vpc_flow(
        self, kql: str, timespan: str = "PT24H", max_rows: int = 200
    ) -> dict[str, Any]:
        async def operation(role: RolePolicy) -> dict[str, Any]:
            if not role.allow_custom_kql:
                raise QueryPolicyError("Custom KQL is not enabled for this role.")
            max_hours, role_max_rows = self._limits(role)
            validated_query = validate_kql(kql)
            validated_timespan = validate_timespan(timespan, max_hours)
            validated_rows = validate_limit(max_rows, role_max_rows)
            return await self.client.query(validated_query, validated_timespan, validated_rows)

        return await self._execute("query_aws_vpc_flow", operation, query_for_audit=kql)


def _result_row_count(result: Any) -> int:
    if isinstance(result, dict):
        if isinstance(result.get("rowCount"), int):
            return result["rowCount"]
        return sum(_result_row_count(value) for value in result.values())
    if isinstance(result, list):
        return sum(_result_row_count(value) for value in result)
    return 0


def _result_queries(result: Any) -> str | None:
    queries: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            query = value.get("query")
            if isinstance(query, str):
                queries.append(query)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(result)
    return "\n".join(queries) if queries else None
