---
name: azure-la-aws-vpc-flow
description: Enterprise onboarding and read-only analysis of Azure Log Analytics AWSVPCFlow through a secured MCP server or local fallback.
---

# Azure Log Analytics AWS VPC Flow

Use natural language to analyze `AWSVPCFlow`. Prefer the centralized enterprise
MCP server. Use the local CLI/MCP fallback only when the user explicitly
chooses local evaluation.

## Mandatory onboarding gate

Before querying, determine which mode applies:

1. Existing enterprise MCP endpoint.
2. New enterprise MCP deployment.
3. Local development fallback.

Run the relevant preflight:

```bash
python3 "{baseDir}/scripts/preflight.py" --mode remote-client
python3 "{baseDir}/scripts/preflight.py" --mode server
python3 "{baseDir}/scripts/preflight.py" --mode local
```

Read `references/onboarding.md` and ask only for missing information.

Never ask the user to paste a client secret, bearer token, certificate private
key, Azure credential file, or OpenClaw OAuth database value into chat.

Prefer customer-owned configuration:

```bash
mkdir -p "{baseDir}/.enterprise-config"
cp "{baseDir}/config/openclaw.env.example" \
  "{baseDir}/.enterprise-config/openclaw.env"
```

Ask the customer administrator to fill the ignored file. Treat Azure and Entra
identifiers as sensitive metadata even though they are not credentials. Do not
copy their values into chat, reports, logs, or committed files.

## Existing enterprise MCP

Collect:

- HTTPS MCP URL including `/mcp`.
- Delegated OAuth scope.
- Existing OpenClaw auth profile ID, or confirmation that the authorization
  server supports dynamic client registration.
- Approved OpenClaw Agent IDs.
- Whether those Agents may use advanced custom KQL.

Configure:

```bash
python3 "{baseDir}/scripts/configure_openclaw.py" \
  --env-file "{baseDir}/.enterprise-config/openclaw.env" \
  --apply

openclaw mcp login aws-vpc-flow
openclaw mcp doctor aws-vpc-flow --probe
```

Do not query until `doctor --probe` succeeds and lists the expected tools.

## New enterprise MCP deployment

Read:

- `references/enterprise-deployment.md`
- `references/permissions.md`
- `config/access-policy.example.json`

Collect:

- Entra tenant ID.
- Azure subscription, region, and MCP deployment resource group.
- Existing Log Analytics workspace resource ID and customer ID.
- Confirmation that the table is exactly `AWSVPCFlow`.
- Container registry/image destination.
- MCP API audience and delegated OAuth scope.
- Security Analyst group ID or `AWSVPCFlow.SecurityAnalyst` App Role.
- Network exposure and audit-retention requirements.
- OpenClaw origin and approved Agent IDs.

Present the deployment and permission plan before applying Azure or Entra
changes. Require administrator approval for role definitions, assignments,
App Registration changes, and ingress changes.

After the user supplies the approved identifiers, generate ignored local
configuration with `scripts/generate_enterprise_config.py`. Never place its
output under version control.

Never write customer values into this repository.

## Local fallback

Collect the workspace customer ID and authentication method, then configure:

```bash
python3 "{baseDir}/scripts/configure_openclaw.py" \
  --env-file "{baseDir}/.enterprise-config/openclaw.env" \
  --apply

openclaw mcp doctor aws-vpc-flow --probe
```

Local mode places Azure authentication on the OpenClaw host and is not the
recommended enterprise deployment.

## Tool selection

Use structured tools before custom KQL:

- Broad risk request: `security_summary`
- Heavy traffic: `top_talkers`
- Port scanning: `detect_port_scans`
- SSH/RDP attempts: `detect_brute_force`
- Large outbound transfers: `detect_large_egress`
- Specific address: `investigate_ip`
- Connector health: `collection_health`
- Schema: `get_schema`

Use `query_aws_vpc_flow` only when:

- Structured tools cannot answer the question.
- The caller is authorized as `security_analyst`.
- The query starts from `AWSVPCFlow`.

## Response requirements

- State the queried time range.
- Distinguish evidence from inference.
- Include severity and concrete records or aggregates.
- Include KQL when the tool returns it.
- State that flow behavior alone does not prove compromise.
- Recommend the next read-only investigation.
- Never fabricate missing results.

## Safety

- Query only `AWSVPCFlow`.
- Provision access only for approved Security Analysts; do not create a
  general employee role or default authenticated-user access.
- Do not bypass MCP role or tool restrictions.
- Do not switch to local execution silently when enterprise MCP fails.
- Do not expose workspace IDs, group IDs, account IDs, IP addresses, or audit
  data beyond the user's authorized scope.
- Do not perform deployment, permission, or Entra changes without explicit
  approval.
