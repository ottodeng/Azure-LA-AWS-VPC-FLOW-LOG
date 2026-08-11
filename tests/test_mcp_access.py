import json

import pytest

from aws_vpc_flow_mcp.access import AccessDenied, AccessPolicy, Principal


def test_unmapped_enterprise_principal_is_denied():
    policy = AccessPolicy.default()
    with pytest.raises(AccessDenied):
        policy.authorize(
            Principal(subject="analyst-object-id", client_id="openclaw"),
            "security_summary",
        )


def test_security_analyst_app_role_is_allowed():
    policy = AccessPolicy.default()
    role_name, role = policy.authorize(
        Principal(
            subject="analyst-object-id",
            client_id="openclaw",
            role_claims=("AWSVPCFlow.SecurityAnalyst",),
        ),
        "query_aws_vpc_flow",
    )
    assert role_name == "security_analyst"
    assert role.allow_custom_kql


def test_local_mode_uses_security_analyst():
    policy = AccessPolicy.default()
    role_name, _ = policy.authorize(
        Principal(subject="local", client_id="local"),
        "security_summary",
        local_role="security_analyst",
    )
    assert role_name == "security_analyst"


def test_policy_rejects_default_access(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "defaultRole": "security_analyst",
                "roles": {
                    "security_analyst": {
                        "tools": ["security_summary"],
                        "maxTimespanHours": 24,
                        "maxRows": 100,
                        "allowCustomKql": False,
                    }
                },
            }
        )
    )
    with pytest.raises(ValueError, match="defaultRole must be null"):
        AccessPolicy.load(policy_path)


def test_policy_rejects_non_analyst_role(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "defaultRole": None,
                "roles": {
                    "security_analyst": {
                        "tools": ["security_summary"],
                        "maxTimespanHours": 24,
                        "maxRows": 100,
                        "allowCustomKql": False,
                    },
                    "employee": {
                        "tools": ["service_status"],
                        "maxTimespanHours": 1,
                        "maxRows": 10,
                        "allowCustomKql": False,
                    },
                },
            }
        )
    )
    with pytest.raises(ValueError, match="Only the security_analyst role"):
        AccessPolicy.load(policy_path)
