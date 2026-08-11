import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aws_vpc_flow_mcp.env_file import EnvironmentFileError, read_environment_file


def test_environment_file_reads_identifiers_and_comments(tmp_path: Path):
    path = tmp_path / "openclaw.env"
    path.write_text(
        """
# customer-supplied identifiers
AWS_VPC_FLOW_CONNECTION_MODE=local
export AWS_VPC_FLOW_WORKSPACE_ID="11111111-1111-4111-8111-111111111111"
AWS_VPC_FLOW_APPROVED_AGENT_IDS=security-agent # inline comment
"""
    )
    assert read_environment_file(path) == {
        "AWS_VPC_FLOW_CONNECTION_MODE": "local",
        "AWS_VPC_FLOW_WORKSPACE_ID": "11111111-1111-4111-8111-111111111111",
        "AWS_VPC_FLOW_APPROVED_AGENT_IDS": "security-agent",
    }


@pytest.mark.parametrize(
    "key",
    [
        "AZURE_LOG_ANALYTICS_TOKEN",
        "CLIENT_SECRET",
        "ACCOUNT_PASSWORD",
        "CERTIFICATE_PRIVATE_KEY",
    ],
)
def test_environment_file_rejects_secret_bearing_keys(tmp_path: Path, key: str):
    path = tmp_path / "openclaw.env"
    path.write_text(f"{key}=do-not-store-this-here\n")
    with pytest.raises(EnvironmentFileError, match="secret-bearing keys"):
        read_environment_file(path)


def test_openclaw_configuration_reads_env_file(tmp_path: Path):
    path = tmp_path / "openclaw.env"
    path.write_text(
        """
AWS_VPC_FLOW_CONNECTION_MODE=local
AWS_VPC_FLOW_WORKSPACE_ID=11111111-1111-4111-8111-111111111111
AWS_VPC_FLOW_SUBSCRIPTION_ID=11111111-1111-4111-8111-111111111111
AWS_VPC_FLOW_AZURE_AUTH_MODE=azure-cli
"""
    )
    root = Path(__file__).parents[1]
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_VPC_FLOW_", "AZURE_LOG_ANALYTICS_", "AZURE_SUBSCRIPTION_"))
    }
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/configure_openclaw.py"),
            "--env-file",
            str(path),
            "--json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    output = json.loads(result.stdout)
    assert output["definition"]["env"]["AWS_VPC_FLOW_WORKSPACE_ID"].startswith("11111111-")
    assert output["definition"]["env"]["AWS_VPC_FLOW_AZURE_AUTH_MODE"] == "azure-cli"


def test_preflight_reads_mode_and_identifiers_from_env_file(tmp_path: Path):
    path = tmp_path / "openclaw.env"
    path.write_text(
        """
AWS_VPC_FLOW_CONNECTION_MODE=local
AWS_VPC_FLOW_WORKSPACE_ID=11111111-1111-4111-8111-111111111111
AWS_VPC_FLOW_AZURE_AUTH_MODE=azure-cli
"""
    )
    root = Path(__file__).parents[1]
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_VPC_FLOW_", "AZURE_LOG_ANALYTICS_", "AZURE_SUBSCRIPTION_"))
    }
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/preflight.py"),
            "--env-file",
            str(path),
            "--json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    output = json.loads(result.stdout)
    assert output["mode"] == "local"
    assert output["ready"] is True
