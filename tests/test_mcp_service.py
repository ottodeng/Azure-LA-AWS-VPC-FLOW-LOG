import pytest

from aws_vpc_flow_mcp.access import AccessPolicy
from aws_vpc_flow_mcp.audit import AuditLogger
from aws_vpc_flow_mcp.config import Settings
from aws_vpc_flow_mcp.service import ToolService


class FakeClient:
    def __init__(self):
        self.calls = []

    async def query(self, query, timespan, max_rows):
        self.calls.append((query, timespan, max_rows))
        return {
            "query": query,
            "timespan": timespan,
            "truncated": False,
            "rowCount": 1,
            "tables": [
                {
                    "name": "PrimaryResult",
                    "columns": ["Count"],
                    "rows": [{"Count": 1}],
                }
            ],
        }


def settings(monkeypatch):
    monkeypatch.setenv(
        "AWS_VPC_FLOW_WORKSPACE_ID",
        "11111111-1111-4111-8111-111111111111",
    )
    monkeypatch.setenv("AWS_VPC_FLOW_MCP_AUTH_MODE", "local")
    return Settings.from_env()


@pytest.mark.asyncio
async def test_security_summary_runs_structured_detectors(monkeypatch):
    fake = FakeClient()
    service = ToolService(
        settings(monkeypatch),
        policy=AccessPolicy.default(),
        client=fake,
        audit=AuditLogger(None, None),
    )
    result = await service.security_summary(24)
    assert len(fake.calls) == 4
    assert set(result["detectors"]) == {
        "rejectedSources",
        "largeEgress",
        "lateralMovement",
        "collectionHealth",
    }


@pytest.mark.asyncio
async def test_custom_kql_is_available_to_local_security_analyst(monkeypatch):
    fake = FakeClient()
    service = ToolService(
        settings(monkeypatch),
        policy=AccessPolicy.default(),
        client=fake,
        audit=AuditLogger(None, None),
    )
    result = await service.query_aws_vpc_flow(
        "AWSVPCFlow | where TimeGenerated >= ago(1h) | take 10",
        "PT1H",
        10,
    )
    assert result["rowCount"] == 1
    assert fake.calls[0][2] == 10
