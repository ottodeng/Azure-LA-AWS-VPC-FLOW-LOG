# AWSVPCFlow schema

The Microsoft Sentinel AWS VPC Flow Logs connector writes to `AWSVPCFlow`.
Use the exact field names and KQL types below.

| Column | KQL type | Meaning |
| --- | --- | --- |
| `TimeGenerated` | datetime | Record timestamp in UTC |
| `AccountId` | string | AWS account ID |
| `Action` | string | Usually `ACCEPT` or `REJECT` |
| `AzId` | string | AWS Availability Zone ID |
| `Bytes` | long | Bytes transferred |
| `DstAddr` | string | Destination address |
| `DstPort` | int | Destination port |
| `End` | datetime | End of flow aggregation interval |
| `FlowDirection` | string | `ingress` or `egress` relative to the interface |
| `InstanceId` | string | Associated EC2 instance |
| `InterfaceId` | string | AWS network interface ID |
| `LogStatus` | string | `OK`, `NODATA`, or `SKIPDATA` |
| `Packets` | int | Packets transferred |
| `PktDstAddr` | string | Original packet destination |
| `PktDstAwsService` | string | AWS service for packet destination, when known |
| `PktSrcAddr` | string | Original packet source |
| `PktSrcAwsService` | string | AWS service for packet source, when known |
| `Protocol` | int | IANA protocol number; TCP=6, UDP=17, ICMP=1 |
| `Region` | string | AWS region |
| `SrcAddr` | string | Source address |
| `SrcPort` | int | Source port |
| `Start` | datetime | Start of flow aggregation interval |
| `SubnetId` | string | AWS subnet ID |
| `TcpFlags` | int | TCP flags bitmask |
| `TrafficPath` | string | Egress traffic path |
| `TrafficType` | string | `IPv4`, `IPv6`, or `EFA` |
| `Version` | int | AWS VPC Flow Logs version |
| `VpcId` | string | AWS VPC ID |

Optional ECS columns can also exist:

`EcsClusterArn`, `EcsClusterName`, `EcsContainerId`,
`EcsContainerInstanceArn`, `EcsContainerInstanceId`,
`EcsSecondContainerId`, `EcsServiceName`, `EcsTaskArn`,
`EcsTaskDefinitionArn`, and `EcsTaskId`.

Azure-managed columns such as `_BilledSize`, `_IsBillable`, `SourceSystem`,
`TenantId`, and `Type` are available for querying but should not be supplied by
Mock ingestion.

Official reference:
`https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsvpcflow`
