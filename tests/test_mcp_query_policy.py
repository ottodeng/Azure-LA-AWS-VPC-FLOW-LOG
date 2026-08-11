import pytest

from aws_vpc_flow_mcp.query_policy import (
    QueryPolicyError,
    validate_kql,
    validate_timespan,
)


def test_guard_accepts_single_table_pipeline():
    query = "AWSVPCFlow | where TimeGenerated >= ago(1h) | take 10"
    assert validate_kql(query) == query


@pytest.mark.parametrize(
    "query",
    [
        "Heartbeat | take 10",
        "AWSVPCFlow | join (Heartbeat) on TenantId",
        "AWSVPCFlow | union Heartbeat",
        'AWSVPCFlow | extend x=externaldata(v:string)["https://example"]',
        "AWSVPCFlow | take 1; Heartbeat | take 1",
        ".show tables\nAWSVPCFlow | take 1",
        "AWSVPCFlow | where TimeGenerated >= ago(1h) | extend x=toscalar(Heartbeat | count)",
        "AWSVPCFlow | where TimeGenerated >= ago(1h) | render timechart",
        "AWSVPCFlow | take 10",
    ],
)
def test_guard_rejects_unsafe_queries(query):
    with pytest.raises(QueryPolicyError):
        validate_kql(query)


def test_timespan_is_role_bounded():
    assert validate_timespan("P7D", 24 * 7) == "P7D"
    with pytest.raises(QueryPolicyError):
        validate_timespan("P8D", 24 * 7)
