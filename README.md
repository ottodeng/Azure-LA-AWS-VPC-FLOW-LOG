# Enterprise AWS VPC Flow Log Skill for OpenClaw

[中文](README.zh-CN.md)

An OpenClaw Skill plus a secured MCP server for natural-language analysis of
the Azure Log Analytics `AWSVPCFlow` table.

## Architecture

```text
Security Analyst → OpenClaw Agent → Skill → Enterprise MCP → AWSVPCFlow
                                               ├─ Entra authorization
                                               ├─ tool policy
                                               ├─ guarded KQL
                                               └─ audit
```

The OpenClaw host does not need Azure credentials when using the enterprise
MCP endpoint. The MCP workload uses managed identity and table-level query
permission.

## Install the Skill

```bash
openclaw skills install git:ottodeng/Azure-LA-AWS-VPC-FLOW-LOG@main
```

On first use, the Skill determines whether to:

1. Connect to an existing enterprise MCP endpoint.
2. Deploy a new enterprise MCP endpoint.
3. Use local development fallback.

It asks for missing non-secret prerequisites before changing configuration.
It never asks users to paste secrets or bearer tokens into chat.

## Customer configuration file

Use a customer-owned, Git-ignored environment file instead of putting Azure
identifiers in chat or reports:

```bash
mkdir -p .enterprise-config
cp config/openclaw.env.example .enterprise-config/openclaw.env
```

The customer fills in `.enterprise-config/openclaw.env`. Workspace,
subscription, tenant, group, Agent, and endpoint identifiers are not passwords,
but they are sensitive environment metadata and should not be committed to the
public repository.

The file parser rejects keys containing `SECRET`, `TOKEN`, `PASSWORD`, or
`PRIVATE_KEY`.

## Connect an existing MCP endpoint

Required:

- HTTPS MCP URL ending in `/mcp`
- OAuth scope, normally `aws_vpc_flow.read`
- Enterprise OpenClaw auth profile, unless the authorization server supports
  dynamic client registration
- Approved OpenClaw Agent IDs

```bash
python3 scripts/configure_openclaw.py \
  --env-file .enterprise-config/openclaw.env \
  --apply

openclaw mcp login aws-vpc-flow
openclaw mcp doctor aws-vpc-flow --probe
```

## Deploy the MCP server

The repository includes:

- Python MCP SDK v2 server
- Streamable HTTP and stdio transports
- Microsoft Entra JWT validation
- Managed identity access to Log Analytics
- Security Analyst-only access policy
- Structured analysis tools
- Guarded analyst-only custom KQL
- JSON audit events
- Dockerfile
- Azure Container Apps Bicep
- Table-level Azure permission script

Start with:

- [`references/onboarding.md`](references/onboarding.md)
- [`references/enterprise-deployment.md`](references/enterprise-deployment.md)
- [`references/permissions.md`](references/permissions.md)

```bash
uv sync --python 3.12
python3 scripts/preflight.py --mode server
```

## MCP tools

| Tool | Purpose |
| --- | --- |
| `service_status` | Configuration and caller limits |
| `get_schema` | Supported `AWSVPCFlow` columns |
| `security_summary` | Primary security-risk detectors |
| `top_talkers` | Largest source/destination flows |
| `detect_port_scans` | High distinct-port rejection activity |
| `detect_brute_force` | SSH/RDP failures and accepted traffic |
| `detect_large_egress` | Large accepted outbound transfers |
| `investigate_ip` | Timeline for one IP address |
| `collection_health` | `OK`, `NODATA`, and `SKIPDATA` |
| `query_aws_vpc_flow` | Analyst-only guarded custom KQL |

## Example prompts

```text
What are the most important security risks in the last 24 hours?
Find port scans in the last hour.
Show brute-force attempts followed by accepted SSH or RDP traffic.
Find outbound transfers larger than 100 MB.
Investigate all recent activity involving 10.20.3.25.
Check for NODATA or SKIPDATA.
```

## Access model

Only `security_analyst` is supported:

- Structured tools plus guarded custom KQL
- Example maximum 30-day window
- Example maximum 2,000 rows

Authenticated users without the approved Entra group or App Role are denied.
The server rejects policies that add a general employee role or default access.

Map Entra groups or App Roles in
[`config/access-policy.example.json`](config/access-policy.example.json).

## Local fallback

For development only:

```bash
python3 scripts/configure_openclaw.py \
  --env-file .enterprise-config/openclaw.env \
  --apply

openclaw mcp doctor aws-vpc-flow --probe
```

Local mode requires Python 3.10+, `uv`, and an Azure identity on the OpenClaw
host.

## Synthetic data

`samples/aws-vpc-flow-sample.json` contains 5,110 synthetic records. It has no
live Azure identifiers or credentials. Integrity data is in
`samples/manifest.json`.

## Security

- Read-only Log Analytics query path
- Exact `AWSVPCFlow` table
- Server-side role and tool authorization
- Query time/row limits
- Cross-workspace and unsafe KQL blocking
- Token-free audit events
- No customer configuration committed to the public repository

## Key files

- [`SKILL.md`](SKILL.md)
- [`references/onboarding.md`](references/onboarding.md)
- [`references/enterprise-deployment.md`](references/enterprise-deployment.md)
- [`references/permissions.md`](references/permissions.md)
- [`references/query-patterns.md`](references/query-patterns.md)
- [`infra/main.bicep`](infra/main.bicep)
