# Azure Log Analytics AWS VPC Flow Log Skill

[中文](README.zh-CN.md)

OpenClaw skill for querying the Azure Log Analytics `AWSVPCFlow` table with
natural language and guarded read-only KQL.

## Capabilities

- Summarize accepted and rejected traffic.
- Find top IPs, ports, protocols, VPCs, subnets, instances, and interfaces.
- Detect port scans, ICMP sweeps, SSH/RDP brute force, and lateral movement.
- Detect large outbound transfers, administrative-port egress, and beaconing.
- Check `NODATA` and `SKIPDATA` collection-health events.
- Investigate a specific IP, resource, or time range.
- Return KQL, evidence, severity, uncertainty, and recommended actions.

## Install

```bash
openclaw skills install git:ottodeng/Azure-LA-AWS-VPC-FLOW-LOG@main
```

## Requirements

- Python 3.9+
- Azure CLI `az`, or `AZURE_LOG_ANALYTICS_TOKEN`
- A Log Analytics workspace containing `AWSVPCFlow`
- Workspace-scoped **Log Analytics Reader**

```bash
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_LOG_ANALYTICS_WORKSPACE_ID="<workspace-customer-id>"
```

Supported authentication: interactive Azure CLI login, managed identity,
service principal, or a pre-acquired Log Analytics token. See
[`references/setup.md`](references/setup.md).

## Example prompts

```text
What are the most important security risks in the last 24 hours?
Find source IPs that scanned many ports in the last hour.
Show brute-force attempts followed by accepted SSH or RDP traffic.
Find outbound transfers larger than 100 MB.
Check for NODATA or SKIPDATA events.
Investigate all recent activity involving 10.20.3.25.
```

## Agent workflow

1. Read `SKILL.md`.
2. Read `references/schema.md` when field definitions are needed.
3. Read `references/query-patterns.md` for detection patterns.
4. Generate KQL starting from `AWSVPCFlow`.
5. Add an explicit `TimeGenerated` filter and bounded output.
6. Run:

   ```bash
   python3 "{baseDir}/scripts/query_aws_vpc_flow.py" \
     --query '<KQL>' \
     --timespan PT24H \
     --format markdown
   ```

7. Return the KQL and evidence. Never fabricate results.

## Direct query

```bash
python3 scripts/query_aws_vpc_flow.py \
  --query 'AWSVPCFlow | where TimeGenerated >= ago(1h) | take 10' \
  --timespan PT1H \
  --format markdown
```

Output formats: `json`, `markdown`, and `table`.

## Synthetic dataset

`samples/aws-vpc-flow-sample.json` contains 5,110 synthetic records covering
normal traffic, scans, brute force, exfiltration, DNS spikes, lateral movement,
beaconing, collection failures, and IPv6.

`samples/manifest.json` contains scenario counts and SHA-256. The sample has no
live Azure identifiers or credentials and uses documentation IP ranges.

Regenerate it:

```bash
python3 scripts/generate_mock_data.py \
  --scale 7 \
  --seed 20260811 \
  --now 2026-08-11T03:00:00Z \
  --output samples/aws-vpc-flow-sample.json \
  --manifest samples/manifest.json
```

## Create a test workspace

```bash
python3 scripts/deploy_mock_azure.py \
  --subscription "<subscription-id>" \
  --resource-group "<mock-resource-group>"

source .azure-env

python3 scripts/ingest_mock_data.py \
  --input samples/aws-vpc-flow-sample.json
```

This creates a workspace, enables Sentinel, installs the official AWS VPC Flow
Logs solution, registers `AWSVPCFlow`, and creates a direct ingestion DCR.

## Safety

- Query access is read-only.
- KQL must start from `AWSVPCFlow`.
- Cross-workspace, external-data, join, union, plugin, management-command, and
  multi-statement queries are rejected.
- Do not commit tokens or secrets.
- `.azure-env` and root-level generated Mock files are ignored.

## References

- [`SKILL.md`](SKILL.md)
- [`references/schema.md`](references/schema.md)
- [`references/query-patterns.md`](references/query-patterns.md)
- [`references/setup.md`](references/setup.md)
- [Microsoft AWSVPCFlow schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsvpcflow)
