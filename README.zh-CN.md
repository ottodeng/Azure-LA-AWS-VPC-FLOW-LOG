# 面向 OpenClaw 的企业 AWS VPC Flow Log Skill

[English](README.md)

通过 OpenClaw Skill 和受保护的 MCP Server，用自然语言分析 Azure Log
Analytics 标准表 `AWSVPCFlow`。

## 架构

```text
安全分析员 → OpenClaw Agent → Skill → 企业 MCP → AWSVPCFlow
                                         ├─ Entra 身份认证
                                         ├─ 工具权限
                                         ├─ KQL 安全策略
                                         └─ 审计
```

企业模式下，OpenClaw 主机不保存 Azure 查询凭据。MCP 工作负载使用 Managed
Identity 和表级查询权限。

## 安装 Skill

```bash
openclaw skills install git:ottodeng/Azure-LA-AWS-VPC-FLOW-LOG@main
```

首次使用时，Skill 会判断：

1. 连接已有企业 MCP。
2. 部署新的企业 MCP。
3. 使用本地开发回退模式。

Skill 会先询问缺少的非敏感前置条件，不会要求用户在对话中粘贴 Secret 或
Bearer Token。

## 连接已有 MCP

需要：

- 以 `/mcp` 结尾的 HTTPS URL
- OAuth Scope，通常为 `aws_vpc_flow.read`
- OpenClaw 企业 Auth Profile；只有授权服务器支持动态客户端注册时才可省略
- 允许使用的 OpenClaw Agent ID

```bash
python3 scripts/configure_openclaw.py \
  --mode remote \
  --url "<https-mcp-url>" \
  --scope "aws_vpc_flow.read" \
  --agents "<approved-agent-ids>" \
  --apply

openclaw mcp login aws-vpc-flow
openclaw mcp doctor aws-vpc-flow --probe
```

## 部署 MCP Server

仓库包含：

- Python MCP SDK v2 Server
- Streamable HTTP 和 stdio
- Microsoft Entra JWT 验证
- Managed Identity 查询 Log Analytics
- 仅安全分析员可访问的权限策略
- 结构化分析工具
- 仅分析员可用的受限自定义 KQL
- JSON 审计事件
- Dockerfile
- Azure Container Apps Bicep
- 表级 Azure 权限脚本

从以下文档开始：

- [`references/onboarding.md`](references/onboarding.md)
- [`references/enterprise-deployment.md`](references/enterprise-deployment.md)
- [`references/permissions.md`](references/permissions.md)

```bash
uv sync --python 3.12
python3 scripts/preflight.py --mode server
```

## MCP 工具

| Tool | 用途 |
| --- | --- |
| `service_status` | 配置状态和调用者限制 |
| `get_schema` | `AWSVPCFlow` 字段 |
| `security_summary` | 综合安全风险 |
| `top_talkers` | 最大流量来源和目标 |
| `detect_port_scans` | 端口扫描 |
| `detect_brute_force` | SSH/RDP 暴力破解 |
| `detect_large_egress` | 大流量出口 |
| `investigate_ip` | 指定 IP 时间线 |
| `collection_health` | `OK`、`NODATA`、`SKIPDATA` |
| `query_aws_vpc_flow` | 仅分析员可用的受限 KQL |

## 自然语言示例

```text
帮我分析过去 24 小时最重要的安全风险。
检查最近一小时有没有端口扫描。
找出暴力破解后又出现成功 SSH 或 RDP 连接的情况。
找出超过 100 MB 的出口流量。
调查 10.20.3.25 最近的全部活动。
检查是否出现 NODATA 或 SKIPDATA。
```

## 权限模型

只支持 `security_analyst`：

- 可使用结构化工具和受限自定义 KQL
- 示例策略最多查询 30 天
- 示例策略最多返回 2,000 行

没有映射到指定 Entra Group 或 App Role 的用户默认拒绝访问。
服务端会拒绝普通员工角色或默认放行策略。

通过 [`config/access-policy.example.json`](config/access-policy.example.json)
映射 Entra Group 或 App Role。

## 本地回退

仅用于开发：

```bash
python3 scripts/configure_openclaw.py \
  --mode local \
  --workspace-id "<workspace-customer-id>" \
  --apply

openclaw mcp doctor aws-vpc-flow --probe
```

本地模式要求 OpenClaw 主机安装 Python 3.10+、`uv` 并具备 Azure 身份。

## 合成数据

`samples/aws-vpc-flow-sample.json` 包含 5,110 条合成记录，不包含真实 Azure
标识或凭据。完整性信息见 `samples/manifest.json`。

## 安全

- Log Analytics 只读查询
- 固定 `AWSVPCFlow` 表
- 服务端角色和工具权限
- 查询时间和行数限制
- 阻止跨 Workspace 和不安全 KQL
- 审计中不记录 Token
- 公开仓库不提交客户配置

## 关键文件

- [`SKILL.md`](SKILL.md)
- [`references/onboarding.md`](references/onboarding.md)
- [`references/enterprise-deployment.md`](references/enterprise-deployment.md)
- [`references/permissions.md`](references/permissions.md)
- [`references/query-patterns.md`](references/query-patterns.md)
- [`infra/main.bicep`](infra/main.bicep)
