# OpenClaw onboarding

Use this checklist before allowing an Agent to query enterprise logs.

## First decision

Ask:

> Does the organization already have an HTTPS AWS VPC Flow MCP endpoint, or
> should this repository be used to deploy one?

Do not ask for a client secret, bearer token, certificate private key, or Azure
credential in chat.

## Connect an existing enterprise MCP endpoint

Collect:

1. MCP HTTPS URL, including `/mcp`.
2. Delegated OAuth scope, normally `aws_vpc_flow.read`.
3. Existing OpenClaw OAuth auth profile ID. If none exists, confirm that the
   MCP authorization server supports dynamic client registration.
4. OpenClaw Agent IDs that may use this Skill.
5. Whether advanced `query_aws_vpc_flow` should be visible to those Agents.

Configure:

```bash
python3 "{baseDir}/scripts/configure_openclaw.py" \
  --mode remote \
  --url "<https-mcp-url>" \
  --scope "aws_vpc_flow.read" \
  --agents "<approved-agent-ids>" \
  --apply

openclaw mcp login aws-vpc-flow
openclaw mcp doctor aws-vpc-flow --probe
```

For the Entra resource-server deployment in this repository, use
`--auth-profile "<profile-id>"`. Omit it only when the upstream authorization
server explicitly supports MCP dynamic client registration.

Confirm that the probe exposes the expected read-only tools.

Restrict Skill visibility to approved security-analysis Agents. When editing
an existing OpenClaw allowlist, preserve its current Skill entries:

```json5
{
  agents: {
    entries: {
      "security-agent": {
        skills: ["azure-la-aws-vpc-flow"]
      }
    }
  }
}
```

A non-empty per-Agent Skill list is the final allowlist, not an additive list.

## Deploy an enterprise MCP endpoint

Collect:

1. Entra tenant ID.
2. Azure subscription and deployment resource group.
3. Azure region and container image location.
4. Existing Log Analytics workspace name, resource group, resource ID, and
   customer ID.
5. Confirmation that the table is exactly `AWSVPCFlow`.
6. MCP API App Registration audience and delegated scope.
7. Security Analyst group object ID or `AWSVPCFlow.SecurityAnalyst` App Role.
8. Ingress choice: internal, external HTTPS, or private endpoint/APIM.
9. Audit destination and retention requirement.
10. OpenClaw origin/hostname and Agent allowlist.

Then read:

- `references/enterprise-deployment.md`
- `references/permissions.md`
- `config/access-policy.example.json`

Run server preflight:

```bash
python3 "{baseDir}/scripts/preflight.py" --mode server
```

Do not continue until required questions are answered and permission changes
are approved by an Azure administrator.

Generate non-secret, Git-ignored deployment configuration after collecting the
approved identifiers:

```bash
python3 "{baseDir}/scripts/generate_enterprise_config.py" \
  --tenant-id "<tenant-id>" \
  --subscription-id "<subscription-id>" \
  --workspace-id "<workspace-customer-id>" \
  --workspace-resource-id "<workspace-resource-id>" \
  --mcp-audience "api://<mcp-api-application-id>" \
  --mcp-url "https://<mcp-host>/mcp" \
  --security-analyst-group-id "<group-object-id>" \
  --network-mode internal \
  --audit-destination "<audit-destination>" \
  --openclaw-origin "https://<openclaw-host>"
```

## Local evaluation fallback

Use only for development or a single trusted OpenClaw host.

Collect:

1. Workspace customer ID.
2. Azure authentication method.
3. Confirmation that local testing may use `security_analyst` privileges.

```bash
python3 "{baseDir}/scripts/configure_openclaw.py" \
  --mode local \
  --workspace-id "<workspace-customer-id>" \
  --apply

openclaw mcp doctor aws-vpc-flow --probe
```

Local mode keeps Azure credentials on the OpenClaw host and is not the
recommended enterprise architecture.
