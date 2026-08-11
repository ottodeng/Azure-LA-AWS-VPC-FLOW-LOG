# Azure Log Analytics AWS VPC Flow Log Skill

[English](README.md)

面向 OpenClaw 的 Skill，用自然语言和受限的只读 KQL 查询 Azure Log
Analytics 标准表 `AWSVPCFlow`。

## 能力

- 汇总允许和拒绝的流量。
- 查询 Top IP、端口、协议、VPC、Subnet、Instance 和 Interface。
- 检测端口扫描、ICMP 扫描、SSH/RDP 暴力破解和横向移动。
- 检测大流量外传、管理端口外联和周期性 Beaconing。
- 检查 `NODATA`、`SKIPDATA` 等采集健康问题。
- 调查指定 IP、资源或时间范围。
- 返回 KQL、证据、风险等级、不确定性和处理建议。

## 安装

```bash
openclaw skills install git:ottodeng/Azure-LA-AWS-VPC-FLOW-LOG@main
```

## 要求

- Python 3.9+
- Azure CLI `az`，或 `AZURE_LOG_ANALYTICS_TOKEN`
- 包含 `AWSVPCFlow` 的 Log Analytics Workspace
- Workspace 级别的 **Log Analytics Reader**

```bash
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_LOG_ANALYTICS_WORKSPACE_ID="<workspace-customer-id>"
```

支持 Azure CLI 交互登录、Managed Identity、Service Principal 和预获取
Token。详细配置见 [`references/setup.md`](references/setup.md)。

## 自然语言示例

```text
帮我分析过去 24 小时有哪些重要安全风险。
检查最近一小时有没有来源 IP 扫描大量端口。
找出暴力破解后又出现成功 SSH 或 RDP 连接的情况。
找出超过 100 MB 的出口流量。
检查是否出现 NODATA 或 SKIPDATA。
调查 10.20.3.25 最近的全部活动。
```

## Agent 工作流

1. 读取 `SKILL.md`。
2. 需要字段定义时读取 `references/schema.md`。
3. 需要检测模式时读取 `references/query-patterns.md`。
4. 生成从 `AWSVPCFlow` 开始的 KQL。
5. 添加明确的 `TimeGenerated` 条件并限制输出。
6. 执行：

   ```bash
   python3 "{baseDir}/scripts/query_aws_vpc_flow.py" \
     --query '<KQL>' \
     --timespan PT24H \
     --format markdown
   ```

7. 返回 KQL 和查询证据，不得伪造结果。

## 直接查询

```bash
python3 scripts/query_aws_vpc_flow.py \
  --query 'AWSVPCFlow | where TimeGenerated >= ago(1h) | take 10' \
  --timespan PT1H \
  --format markdown
```

支持 `json`、`markdown` 和 `table` 输出。

## 合成数据

`samples/aws-vpc-flow-sample.json` 包含 5,110 条合成记录，覆盖正常流量、
扫描、暴力破解、外传、DNS 突增、横向移动、Beaconing、采集异常和 IPv6。

`samples/manifest.json` 包含场景数量和 SHA-256。样例不包含真实 Azure 标识
或凭据，公网地址使用文档保留地址段。

重新生成：

```bash
python3 scripts/generate_mock_data.py \
  --scale 7 \
  --seed 20260811 \
  --now 2026-08-11T03:00:00Z \
  --output samples/aws-vpc-flow-sample.json \
  --manifest samples/manifest.json
```

## 创建测试 Workspace

```bash
python3 scripts/deploy_mock_azure.py \
  --subscription "<subscription-id>" \
  --resource-group "<mock-resource-group>"

source .azure-env

python3 scripts/ingest_mock_data.py \
  --input samples/aws-vpc-flow-sample.json
```

脚本会创建 Workspace、启用 Sentinel、安装官方 AWS VPC Flow Logs Solution、
注册 `AWSVPCFlow` 并创建 Direct DCR。

## 安全边界

- 查询接口只读。
- KQL 必须从 `AWSVPCFlow` 开始。
- 阻止跨 Workspace、外部数据、Join、Union、Plugin、Management Command
  和多语句查询。
- 不要提交 Token 或 Secret。
- `.azure-env` 和根目录生成的 Mock 文件默认忽略。

## 参考

- [`SKILL.md`](SKILL.md)
- [`references/schema.md`](references/schema.md)
- [`references/query-patterns.md`](references/query-patterns.md)
- [`references/setup.md`](references/setup.md)
- [Microsoft AWSVPCFlow 表结构](https://learn.microsoft.com/azure/azure-monitor/reference/tables/awsvpcflow)
