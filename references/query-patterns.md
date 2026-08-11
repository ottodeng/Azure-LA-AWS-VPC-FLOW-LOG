# Read-only KQL patterns

Always begin with `AWSVPCFlow` and include a `TimeGenerated` filter.

## Rejected traffic

```kusto
AWSVPCFlow
| where TimeGenerated >= ago(24h)
| where Action =~ "REJECT"
| summarize Rejects=count(), Destinations=dcount(DstAddr),
    Ports=dcount(DstPort) by SrcAddr
| top 20 by Rejects desc
```

## Port scans

```kusto
AWSVPCFlow
| where TimeGenerated >= ago(1h)
| where Action =~ "REJECT"
| summarize Attempts=count(), DistinctPorts=dcount(DstPort),
    DistinctTargets=dcount(DstAddr) by SrcAddr, bin(TimeGenerated, 5m)
| where DistinctPorts >= 20 or DistinctTargets >= 20
| order by Attempts desc
```

## SSH or RDP brute force

```kusto
AWSVPCFlow
| where TimeGenerated >= ago(6h)
| where DstPort in (22, 3389)
| summarize Attempts=count(), Rejects=countif(Action =~ "REJECT"),
    Accepts=countif(Action =~ "ACCEPT") by SrcAddr, DstAddr, DstPort
| where Rejects >= 20
| order by Rejects desc
```

## Large outbound transfers

```kusto
AWSVPCFlow
| where TimeGenerated >= ago(24h)
| where FlowDirection =~ "egress" and Action =~ "ACCEPT"
| summarize Bytes=sum(Bytes), Packets=sum(Packets), Flows=count()
    by SrcAddr, DstAddr, DstPort
| where Bytes >= 100000000
| order by Bytes desc
```

## Collection health

```kusto
AWSVPCFlow
| where TimeGenerated >= ago(24h)
| summarize Records=count() by LogStatus, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

## Top talkers

```kusto
AWSVPCFlow
| where TimeGenerated >= ago(24h)
| summarize Bytes=sum(Bytes), Packets=sum(Packets), Flows=count() by SrcAddr
| top 20 by Bytes desc
```

## Investigation guidance

- A scan signal is behavioral, not proof of compromise.
- Correlate accepted traffic after many rejects.
- Compare traffic against a historical baseline before calling it anomalous.
- `NODATA` means no network traffic was recorded during the interval.
- `SKIPDATA` indicates records were skipped, commonly because of capacity or
  delivery constraints; investigate connector and AWS delivery health.
- Explain protocol numbers and byte sizes in human-readable terms.
