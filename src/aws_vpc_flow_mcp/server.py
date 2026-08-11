from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from mcp.server import MCPServer
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import __version__
from .auth import EntraTokenVerifier
from .config import ConfigurationError, Settings
from .runtime import get_service, set_service
from .service import ToolService


def build_server(settings: Settings) -> MCPServer[Any]:
    auth_kwargs: dict[str, Any] = {}
    if settings.auth_mode == "entra":
        assert settings.mcp_issuer_url
        assert settings.mcp_server_url
        assert settings.mcp_audience
        auth_kwargs = {
            "token_verifier": EntraTokenVerifier(settings.mcp_issuer_url, settings.mcp_audience),
            "auth": AuthSettings(
                issuer_url=AnyHttpUrl(settings.mcp_issuer_url),
                resource_server_url=AnyHttpUrl(settings.mcp_server_url),
                required_scopes=[settings.mcp_scope],
            ),
        }

    server = MCPServer(
        name="azure-la-aws-vpc-flow",
        title="Azure Log Analytics AWS VPC Flow",
        description="Read-only enterprise analysis tools for AWSVPCFlow.",
        instructions=(
            "Use structured detection tools first. Use query_aws_vpc_flow only "
            "for authorized advanced analysis. Never claim a result that is not "
            "present in the returned Log Analytics evidence."
        ),
        version=__version__,
        log_level=settings.log_level,  # type: ignore[arg-type]
        **auth_kwargs,
    )
    set_service(ToolService(settings))

    @server.tool()
    async def service_status() -> dict[str, Any]:
        """Check configuration readiness and the caller's effective limits."""
        return await get_service().service_status()

    @server.tool()
    async def get_schema() -> dict[str, Any]:
        """Return the supported AWSVPCFlow columns and KQL types."""
        return await get_service().get_schema()

    @server.tool()
    async def security_summary(hours: int = 24) -> dict[str, Any]:
        """Run the primary read-only risk detectors for a time range."""
        return await get_service().security_summary(hours)

    @server.tool()
    async def top_talkers(
        hours: int = 24, limit: int = 20, direction: str = "all"
    ) -> dict[str, Any]:
        """Find source/destination pairs transferring the most bytes."""
        return await get_service().top_talkers(hours, limit, direction)

    @server.tool()
    async def detect_port_scans(hours: int = 1, min_distinct_ports: int = 20) -> dict[str, Any]:
        """Find rejected traffic that touches many destination ports."""
        return await get_service().detect_port_scans(hours, min_distinct_ports)

    @server.tool()
    async def detect_brute_force(
        hours: int = 6, ports: str = "22,3389", min_rejects: int = 20
    ) -> dict[str, Any]:
        """Find repeated SSH/RDP failures and any accepted traffic."""
        return await get_service().detect_brute_force(hours, ports, min_rejects)

    @server.tool()
    async def detect_large_egress(hours: int = 24, min_bytes: int = 100_000_000) -> dict[str, Any]:
        """Find large accepted egress transfers."""
        return await get_service().detect_large_egress(hours, min_bytes)

    @server.tool()
    async def investigate_ip(ip: str, hours: int = 24, limit: int = 100) -> dict[str, Any]:
        """Return recent AWSVPCFlow activity involving an IP address."""
        return await get_service().investigate_ip(ip, hours, limit)

    @server.tool()
    async def collection_health(hours: int = 24) -> dict[str, Any]:
        """Summarize OK, NODATA, and SKIPDATA collection status."""
        return await get_service().collection_health(hours)

    @server.tool()
    async def query_aws_vpc_flow(
        kql: str, timespan: str = "PT24H", max_rows: int = 200
    ) -> dict[str, Any]:
        """Run advanced guarded KQL; restricted to authorized analyst roles."""
        return await get_service().query_aws_vpc_flow(kql, timespan, max_rows)

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok" if settings.workspace_id else "configuration-required",
                "service": "azure-la-aws-vpc-flow",
                "version": __version__,
            }
        )

    return server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the AWSVPCFlow MCP server.")
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--path", default="/mcp")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        settings = Settings.from_env(require_workspace=False)
        if args.transport == "stdio" and settings.auth_mode == "entra":
            raise ConfigurationError("Entra authentication requires streamable-http transport.")
        is_loopback = args.host in {"127.0.0.1", "localhost", "::1"}
        if (
            args.transport == "streamable-http"
            and settings.auth_mode == "local"
            and not is_loopback
            and not settings.allow_insecure_remote_http
        ):
            raise ConfigurationError(
                "Refusing unauthenticated remote HTTP. Configure Entra auth or "
                "set AWS_VPC_FLOW_ALLOW_INSECURE_REMOTE_HTTP=true for an isolated test."
            )
        server = build_server(settings)
        if args.transport == "stdio":
            server.run(transport="stdio")
            return 0

        transport_security = None
        if settings.allowed_hosts or settings.allowed_origins:
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=list(settings.allowed_hosts),
                allowed_origins=list(settings.allowed_origins),
            )
        logging.getLogger(__name__).info(
            "Starting MCP server: %s",
            json.dumps(
                {
                    "host": args.host,
                    "port": args.port,
                    "path": args.path,
                    "authMode": settings.auth_mode,
                }
            ),
        )
        server.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            streamable_http_path=args.path,
            stateless_http=True,
            json_response=True,
            transport_security=transport_security,
        )
        return 0
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


mcp = build_server(Settings.from_env(require_workspace=False))


if __name__ == "__main__":
    raise SystemExit(main())
