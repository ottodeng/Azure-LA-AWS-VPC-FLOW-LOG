from aws_vpc_flow_mcp.access import Principal
from aws_vpc_flow_mcp.audit import AuditLogger


def test_audit_hashes_workspace_and_query(tmp_path):
    path = tmp_path / "audit.jsonl"
    workspace = "11111111-1111-4111-8111-111111111111"
    query = "AWSVPCFlow | take 1"
    audit = AuditLogger(path, workspace)
    audit.record(
        principal=Principal(subject="analyst-object-id", client_id="openclaw"),
        role="security_analyst",
        tool="query_aws_vpc_flow",
        status="success",
        duration_ms=10,
        row_count=1,
        query=query,
    )
    text = path.read_text()
    assert workspace not in text
    assert query not in text
    assert "querySha256" in text
    assert "workspaceSha256" in text
