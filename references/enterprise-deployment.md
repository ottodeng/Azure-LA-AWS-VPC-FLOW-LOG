# Enterprise MCP deployment

## Components

- OpenClaw Skill from this repository.
- Streamable HTTP MCP server.
- Microsoft Entra bearer authentication.
- MCP system-assigned managed identity.
- Existing Log Analytics workspace containing `AWSVPCFlow`.
- Access policy mapping the approved Security Analyst group/App Role.
- Central audit collection.

## Build the image

```bash
docker build -t "<registry>/aws-vpc-flow-mcp:<version>" .
docker push "<registry>/aws-vpc-flow-mcp:<version>"
```

Do not place Azure credentials or access-policy secrets in the image.

## Prepare access policy

Copy:

```text
config/access-policy.example.json
```

Replace only the Security Analyst group/App Role placeholder. Pass the resulting JSON through
the deployment pipeline. Do not commit customer-specific values.

Alternatively, generate an ignored local configuration bundle with
`scripts/generate_enterprise_config.py`.

## Deploy to Azure Container Apps

```bash
az deployment group create \
  --subscription "<subscription-id>" \
  --resource-group "<mcp-resource-group>" \
  --template-file infra/main.bicep \
  --parameters \
    image="<registry>/aws-vpc-flow-mcp:<version>" \
    awsVpcFlowWorkspaceId="<workspace-customer-id>" \
    tenantId="<tenant-id>" \
    mcpAudience="api://<mcp-api-application-id>" \
    accessPolicyJson="$(cat <secure-policy-file>)" \
    openClawOrigin="https://<openclaw-host>" \
    externalIngress=false
```

Read the deployment outputs:

- `mcpUrl`
- `managedIdentityPrincipalId`

Grant the managed identity table-level permission by following
`references/permissions.md`.

## Configure OpenClaw

```bash
python3 scripts/configure_openclaw.py \
  --mode remote \
  --url "<mcp-url>" \
  --scope "aws_vpc_flow.read" \
  --auth-profile "<enterprise-auth-profile-id>" \
  --agents "<approved-agent-ids>" \
  --apply

openclaw mcp login aws-vpc-flow
openclaw mcp doctor aws-vpc-flow --probe
```

The direct Entra resource-server configuration expects an enterprise
OpenClaw OAuth auth profile. Do not rely on dynamic client registration unless
the authorization layer in front of the MCP endpoint explicitly provides it.

Use OpenClaw Agent Skill allowlists so only approved Agents can load
`azure-la-aws-vpc-flow`.

## Production requirements

- HTTPS only.
- Entra authentication enabled.
- At least one always-ready replica when interactive latency matters.
- Private ingress or APIM when required by policy.
- Azure Monitor Private Link for the Log Analytics path when required.
- Central audit collection and alerting on denied or high-volume queries.
- Rate limits and query-window limits appropriate to security analysts.
- No customer IDs, group IDs, URLs, or credentials committed to this public
  repository.
