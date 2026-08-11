# Setup and deployment

## Install in OpenClaw

Install directly from the Git repository:

```bash
openclaw skills install git:ottodeng/Azure-LA-AWS-VPC-FLOW-LOG@main
```

OpenClaw Git installs expect `SKILL.md` at the repository root.

## Runtime requirements

- Python 3.9 or newer.
- Azure CLI on `PATH`, unless `AZURE_LOG_ANALYTICS_TOKEN` is supplied.
- `AZURE_LOG_ANALYTICS_WORKSPACE_ID`: Log Analytics workspace customer ID.
- Optional `AZURE_SUBSCRIPTION_ID`: subscription used for Azure CLI token
  acquisition.

The runtime identity needs **Log Analytics Reader** on the target workspace.
Scope the role to the individual workspace rather than the subscription or
resource group when practical. This is the recommended minimum built-in role
for this Skill.

## Authentication options

### Interactive developer

```bash
az login
az account set --subscription <subscription-id>
export AZURE_SUBSCRIPTION_ID=<subscription-id>
export AZURE_LOG_ANALYTICS_WORKSPACE_ID=<workspace-customer-id>
```

### Azure VM managed identity

Enable a system-assigned or user-assigned identity, grant it **Log Analytics
Reader** on the workspace, then:

```bash
az login --identity
```

For a user-assigned identity:

```bash
az login --identity --client-id <managed-identity-client-id>
```

This is the recommended production configuration because it has no stored
client secret.

### Service principal

Grant the service principal **Log Analytics Reader** on the workspace:

```bash
az login --service-principal \
  --username <client-id> \
  --password <client-secret-or-certificate> \
  --tenant <tenant-id>
```

Keep credentials outside the repository and OpenClaw conversation history.

### Pre-acquired token

Set `AZURE_LOG_ANALYTICS_TOKEN` to a bearer token whose audience is
`https://api.loganalytics.azure.com` or the compatibility audience
`https://api.loganalytics.io`. This is useful for wrappers that already manage
token refresh; short-lived static tokens are not recommended.

## Query test

```bash
python3 scripts/query_aws_vpc_flow.py \
  --query 'AWSVPCFlow | where TimeGenerated >= ago(1h) | take 10' \
  --format markdown
```

The script rejects queries that omit `AWSVPCFlow` or use cross-workspace,
cross-cluster, external-data, or management-command syntax.

## Create the Azure Mock environment

The deployment identity needs permission to create a resource group, Log
Analytics workspace, Sentinel onboarding state, DCR, and role assignment.

```bash
python3 scripts/deploy_mock_azure.py \
  --subscription <subscription-id>
source .azure-env
python3 scripts/generate_mock_data.py --scale 1
python3 scripts/ingest_mock_data.py
```

The deployment uses a direct DCR and the standard output stream
`Microsoft-AWSVPCFlow`, so the resulting query table is exactly
`AWSVPCFlow`. It installs Microsoft's AWS VPC Flow Logs Solution 3.0.0 from a
pinned Azure-Sentinel repository commit before creating the DCR.

Azure ingestion role propagation can take several minutes. Retry ingestion if
the first attempt returns HTTP 403 immediately after deployment.

The default generated data contains 730 deterministic records. Increase
`--scale` to create a larger dataset. The repository sample uses `--scale 7`
and contains 5,110 records.

| Scenario | Records |
| --- | ---: |
| Normal web traffic | 320 × scale |
| Port scan | 80 × scale |
| SSH brute force | 55 × scale |
| RDP brute force | 45 × scale |
| DNS spike | 70 × scale |
| Large outbound transfer | 12 × scale |
| Lateral movement | 18 × scale |
| ICMP sweep | 40 × scale |
| Periodic beaconing | 48 × scale |
| Unusual admin egress | 20 × scale |
| `NODATA` / `SKIPDATA` | 12 × scale |
| IPv6 | 10 × scale |

## Cleanup

The default test resource group is isolated:

```bash
az group delete \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --name "<mock-resource-group>"
```

Do not delete a customer workspace or resource group when cleaning up a test.

## Official references

- AWSVPCFlow schema:
  `https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsvpcflow`
- Logs Ingestion API:
  `https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview`
- Logs Query API:
  `https://learn.microsoft.com/azure/azure-monitor/logs/api/overview`
