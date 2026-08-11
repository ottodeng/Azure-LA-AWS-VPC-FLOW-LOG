import pytest

from aws_vpc_flow_mcp.config import Settings
from aws_vpc_flow_mcp.server import build_server


@pytest.mark.asyncio
async def test_server_exposes_read_only_tool_surface(monkeypatch):
    monkeypatch.setenv(
        "AWS_VPC_FLOW_WORKSPACE_ID",
        "11111111-1111-4111-8111-111111111111",
    )
    monkeypatch.setenv("AWS_VPC_FLOW_MCP_AUTH_MODE", "local")
    server = build_server(Settings.from_env())
    tools = {tool.name for tool in await server.list_tools()}
    assert tools == {
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
    }
