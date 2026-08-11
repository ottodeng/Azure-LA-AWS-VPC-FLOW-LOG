# Enterprise identity and permissions

## Identity layers

Use two separate identities:

1. Security Analyst identity authenticates from OpenClaw to the MCP endpoint.
2. MCP workload managed identity queries Log Analytics.

The MCP server records the analyst subject, client ID, effective role, tool,
query hash, duration, row count, and outcome. It never records bearer tokens.

## Entra application

Create an API App Registration for the MCP endpoint:

- Single tenant.
- Application ID URI used as `AWS_VPC_FLOW_MCP_AUDIENCE`.
- Delegated scope `aws_vpc_flow.read`.
- Optional App Roles:
  - `AWSVPCFlow.SecurityAnalyst`

Grant the OpenClaw enterprise OAuth client permission to the delegated scope
and complete administrator consent when required.

Prefer the `AWSVPCFlow.SecurityAnalyst` App Role when possible. If Entra group
claims are used, configure the application to emit only approved security
groups so tokens do not fall into group-overage behavior.

Prefer an OpenClaw-managed OAuth auth profile. Never commit client secrets.

## Log Analytics permission

Grant the MCP managed identity only:

- Workspace metadata read.
- Log Analytics API query action.
- `AWSVPCFlow` table query data action.

Review the dry run:

```bash
python3 scripts/assign_azure_permissions.py \
  --subscription "<subscription-id>" \
  --workspace-resource-id "<workspace-resource-id>" \
  --principal-object-id "<mcp-managed-identity-object-id>"
```

Apply after administrator approval:

```bash
python3 scripts/assign_azure_permissions.py \
  --subscription "<subscription-id>" \
  --workspace-resource-id "<workspace-resource-id>" \
  --principal-object-id "<mcp-managed-identity-object-id>" \
  --apply
```

The script creates the custom `AWSVPCFlow Table Reader` role and assigns it
only at the selected workspace.

## Security Analyst role

Only `security_analyst` is supported:

- Structured tools plus guarded custom KQL.
- Maximum 30-day range in the example policy.
- Maximum 2,000 returned rows.

Unmapped authenticated users are denied by default.
Do not add a general employee role or set `defaultRole`. The server validates
this fail-closed requirement when it loads the policy.

Copy `config/access-policy.example.json` to a secure deployment configuration
and replace placeholders with approved Entra group object IDs. Group IDs are
configuration, not credentials, but should still be managed through the
enterprise deployment pipeline.
