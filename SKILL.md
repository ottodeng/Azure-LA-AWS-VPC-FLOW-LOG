---
name: azure-la-aws-vpc-flow
description: Query and analyze the AWSVPCFlow table in Azure Log Analytics using natural-language requests and guarded read-only KQL.
---

# Azure Log Analytics AWS VPC Flow

Translate the user's request into KQL, run it against `AWSVPCFlow`, and explain
the result. Never invent query results.

## Workflow

1. Read `references/schema.md` when column meaning or type is relevant.
2. Read `references/query-patterns.md` for anomaly-detection patterns.
3. Convert the request to KQL that starts from `AWSVPCFlow`.
4. Add an explicit `TimeGenerated` filter. Use the user's range, or the last
   24 hours when no range is given.
5. Keep result sets small with `top`, `take`, or aggregation.
6. Execute:

   ```bash
   python3 "{baseDir}/scripts/query_aws_vpc_flow.py" \
     --query '<KQL>' \
     --timespan PT24H \
     --format markdown
   ```

7. Show the KQL, summarize the evidence, call out uncertainty, and suggest the
   next read-only query when useful.

## Safety rules

- Query only `AWSVPCFlow`.
- Use only the Azure Log Analytics query endpoint. It is read-only.
- Do not use cross-workspace, cross-cluster, external-data, or management
  commands.
- Do not run deployment or ingestion scripts unless the user explicitly asks.
- Do not expose access tokens, client secrets, tenant secrets, or raw Azure CLI
  credential files.
- Treat IP addresses, account IDs, instance IDs, and interface IDs as sensitive.
- If authentication or configuration is missing, read `references/setup.md`
  and report the exact missing variable or Azure role.

## Common requests

- Rejected traffic, top rejected sources, or rejected destination ports.
- Port scans, ICMP sweeps, SSH/RDP brute-force behavior, or lateral movement.
- Unusually large outbound transfers or traffic spikes.
- Periodic beaconing or unusual administrative-port egress.
- Unexpected public destinations or AWS service destinations.
- Top talkers, protocols, VPCs, subnets, instances, and interfaces.
- `NODATA` or `SKIPDATA` collection-health problems.
- A timeline for a source IP, destination IP, instance, or interface.

For local test-resource deployment and Mock ingestion, follow
`references/setup.md`. A 5,110-record synthetic dataset is available at
`samples/aws-vpc-flow-sample.json`.
