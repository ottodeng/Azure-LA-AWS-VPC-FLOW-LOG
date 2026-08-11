import pytest

from aws_vpc_flow_mcp.config import ConfigurationError, Settings


def test_settings_accept_workspace_alias(monkeypatch):
    monkeypatch.setenv(
        "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
        "11111111-1111-4111-8111-111111111111",
    )
    settings = Settings.from_env()
    assert settings.workspace_id == "11111111-1111-4111-8111-111111111111"
    assert settings.table_name == "AWSVPCFlow"


def test_settings_reject_nonstandard_table(monkeypatch):
    monkeypatch.setenv(
        "AWS_VPC_FLOW_WORKSPACE_ID",
        "11111111-1111-4111-8111-111111111111",
    )
    monkeypatch.setenv("AWS_VPC_FLOW_TABLE", "OtherTable")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_entra_mode_requires_identity_metadata(monkeypatch):
    monkeypatch.setenv(
        "AWS_VPC_FLOW_WORKSPACE_ID",
        "11111111-1111-4111-8111-111111111111",
    )
    monkeypatch.setenv("AWS_VPC_FLOW_MCP_AUTH_MODE", "entra")
    with pytest.raises(ConfigurationError, match="MCP_TENANT_ID"):
        Settings.from_env()
