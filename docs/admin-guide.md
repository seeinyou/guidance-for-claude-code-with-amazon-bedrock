# CCWB 管理员指南 / CCWB Admin Guide

---

# 中文版

## 架构概览

CCWB (Claude Code with Bedrock) 通过 Amazon Bedrock 为企业提供 Claude Code 访问能力，包含以下核心组件：

- **credential-process**: CLI 工具，处理 OIDC 认证 -> 调用 TVM 获取短期 AWS 凭证
- **TVM (Token Vending Machine) Lambda**: 服务端签发 Bedrock 作用域凭证，同步执行配额检查（fail-closed），封禁用户时拒发凭证
- **Bedrock 用量管道**: Bedrock Model Invocation Logging -> S3 -> SQS -> `bedrock_usage_stream` Lambda -> DynamoDB（`#BEDROCK` 用量记录），30 分钟级别由 `bedrock_usage_reconciler` 做对账
- **Landing page**: ALB + Lambda 门户，按操作系统分组的下载卡片（Linux 提供 Portable / Slim 双变体）
- **Admin panel**: 同一 ALB 下的独立 Lambda，管理配额策略、定价、管理员、用户启用/禁用
- **OTLP pipeline（可选）**: otel-helper -> credential-process (JWT) -> OTEL collector -> CloudWatch -> MetricsAggregator Lambda -> DynamoDB（仅用于聚合行为指标，不用于配额/费用）
- **Dashboard**: CloudWatch 仪表盘，展示 DynamoDB 预计算指标

**重要变化**: 费用与用量来源已从 OTEL 切换到 Bedrock Model Invocation Logging。Admin panel 的 Users 表、配额判定使用 `USER#…#MONTH#…#BEDROCK` / `DAY#…#BEDROCK` 记录。详细架构见 [cost-management.md](cost-management.md)。

## 配额管理

### 策略类型

| 类型 | DynamoDB Key | 说明 |
|------|-------------|------|
| `user` | `POLICY#user#email@example.com` | 针对单个用户的策略 |
| `group` | `POLICY#group#group-name` | 针对用户组的策略 |
| `default` | `POLICY#default` | 无特定策略用户的兜底策略 |
| `org` | `POLICY#org#global` | 组织级上限，在用户级检查之前执行 |

### 限额维度

- `monthly_token_limit` / `daily_token_limit` -- token 数量限制
- `monthly_cost_limit` / `daily_cost_limit` -- 费用限制 (USD)
- 费用限制依赖 BedrockPricing DynamoDB 表中的定价数据

### 策略生效逻辑

配额检查按以下顺序执行，**先匹配先生效**：

```
1. 组织级检查 (org)      ← 最先检查，超限则所有用户被阻止
   ↓ 通过
2. 用户解锁检查 (unblock) ← 管理员临时解锁，有效期内跳过后续限额检查
   ↓ 无解锁
3. 策略解析（优先级）：
   3a. 用户策略 (user)    ← 精确匹配用户邮箱，最高优先
   3b. 组策略 (group)     ← 匹配用户所属组，多组取最严格
   3c. 默认策略 (default) ← 兜底
   3d. 无策略             ← 无限制
   ↓
4. 执行模式判断
   - alert 模式：记录告警，允许访问
   - block 模式：进入限额检查
   ↓
5. 限额检查（按序，首个超限即阻止）：
   5a. 月 token 限额
   5b. 月费用限额
   5c. 日 token 限额
   5d. 日费用限额
   ↓ 全部通过
6. 允许访问
```

**组策略最严格选择规则**：当用户属于多个组时，按元组排序取最小值：
`(monthly_token_limit, monthly_cost_limit, daily_token_limit, daily_cost_limit)`
未设置的维度视为无限大 (∞)，不影响排序。

**日/月边界时区**：所有日限额重置和月限额切换使用 **UTC+8** 时区。

**重要设计决策**：
- 解锁 (unblock) **不会**覆盖组织级限额。即使管理员解锁了某用户，如果组织总量超限，该用户仍然被阻止。
- 限额检查顺序固定：月 token → 月费用 → 日 token → 日费用。首个超限即返回阻止，不会继续检查后续维度。

**组策略是人均限额，非共享池**：
- 组策略 `POLICY#group#engineering` 设置 monthly=200M 表示：engineering 组中每个用户各自有 200M 上限
- 不存在组级聚合（无 `GROUP#engineering` 汇总记录）——不支持"engineering 组共享 1B tokens"的场景
- 组级共享池需要额外开发聚合器逻辑

**组信息来源**：
- 配额检查时：从 JWT claims 实时提取（`groups`, `cognito:groups`, `custom:department`）
- 聚合器中：仅在 `ENABLE_FINEGRAINED_QUOTAS=true` 时从 OTEL 日志解析并存入 DynamoDB（当前未启用）
- OTEL 遥测目前不包含组信息——聚合器的组数据查询依赖 credential provider 发送组 claims 到日志（尚未实现）

**多组织**：
- 仅支持单一组织 (`ORG#global`)
- 无多租户/多部门独立组织级限额
- 如需部门级上限，可用 group 策略（人均限额）近似替代

#### 示例

**示例 1：多层策略解析**

策略配置：
- `POLICY#default#default`: monthly=100M tokens, enforcement=block
- `POLICY#group#engineering`: monthly=200M tokens, daily=$20, enforcement=block
- `POLICY#user#alice@corp.com`: monthly=500M tokens, enforcement=alert

| 用户 | 所属组 | 生效策略 | 原因 |
|------|--------|---------|------|
| alice@corp.com | engineering | user 策略 (500M, alert) | 用户策略优先级最高 |
| bob@corp.com | engineering | group 策略 (200M, $20/日) | 无用户策略，匹配组策略 |
| charlie@corp.com | (无) | default 策略 (100M) | 无用户/组策略，使用默认 |
| dana@corp.com | (无) | 无策略 = 无限制 | 若 default 策略不存在 |

**示例 2：多组策略取最严格**

组策略：
- `POLICY#group#engineering`: monthly=200M tokens, monthly_cost=$100
- `POLICY#group#contractor`: monthly=300M tokens, monthly_cost=$50

用户 bob 同时属于 engineering 和 contractor 两个组。

比较元组：
- engineering: `(200M, $100, ∞, ∞)`
- contractor: `(300M, $50, ∞, ∞)`

engineering 的 token 限额更低 (200M < 300M)，所以 **engineering 策略生效**。

> 注意：虽然 contractor 的费用限额更严格 ($50 < $100)，但元组比较从第一个维度开始，200M < 300M 已决定结果。

**示例 3：组织级限额阻止所有人**

配置：
- `POLICY#org#global`: monthly=1B tokens, enforcement=block
- `POLICY#user#alice@corp.com`: monthly=500M, enforcement=block（alice 已被管理员解锁 7 天）

当前组织总用量：1.1B tokens

结果：
- alice 被阻止 ← 组织级限额先于解锁检查
- 所有其他用户也被阻止

**示例 4：日限额重置（UTC+8）**

- 日限额：10M tokens/天
- 用户在 UTC 15:50（UTC+8 23:50）已使用 9.5M tokens
- UTC 16:00（UTC+8 00:00）：日限额重置为 0，新的一天开始
- 用户可以继续使用

**示例 5：token 和费用限额同时生效**

策略：monthly=200M tokens, monthly_cost=$50, enforcement=block

场景 A：用户消耗 210M tokens，费用 $30
→ 被阻止，原因：`monthly_exceeded`（token 先超限）

场景 B：用户消耗 100M tokens，费用 $55（使用大量 Opus 输出）
→ 被阻止，原因：`monthly_cost_exceeded`（费用先超限）

场景 C：用户消耗 150M tokens，费用 $40
→ 允许访问（两个维度都未超限）

### 执行模式

- `block` -- 超限后拒绝发放 AWS 凭证
- `alert` -- 记录告警但允许访问（目前仅 org 级别支持）

### 配额检查频率

- 由 `config.json` 中的 `quota_check_interval` 控制（单位：分钟）
- 默认值：30（每 30 分钟检查一次）
- 设为 0：每次请求都检查（适合测试，每次请求增加约 100ms 延迟）
- 未设置 / 无 `quota_api_endpoint`：不执行配额检查
- 检查是同步的 -- 在 credential-process 发放凭证前执行
- 首次认证始终检查配额，不受间隔设置影响
- 缓存凭证路径：按间隔重新检查，未到检查时间则直接输出凭证

### 用户体验

- 用量达 80%+：黄色终端横幅 + 浏览器弹窗，显示 token 和费用的进度条
- 用量达 100%：红色终端横幅 + 浏览器弹窗，明确标注 "COST LIMIT" 或 "TOKEN LIMIT"
- 日限额在 UTC+8 午夜重置，月限额在 UTC+8 月初重置

## 定价表管理

- DynamoDB 表：`BedrockPricing`（主键：`model_id`）
- 字段：`input_per_1m`, `output_per_1m`, `cache_read_per_1m`, `cache_write_per_1m`
- 定价查找链：精确 model_id 匹配 -> 部分匹配 -> DEFAULT 兜底
- Admin panel 的 Pricing 标签页支持增删改查
- CLI 命令：`ccwb quota:set-pricing --defaults` 可初始化标准模型定价

**重要 -- Claude 4.6 模型 ID 没有 `:0` 后缀：**

| 模型 | model_id |
|------|----------|
| Opus 4.6 | `anthropic.claude-opus-4-6-v1` |
| Sonnet 4.6 | `anthropic.claude-sonnet-4-6` |
| 旧版模型 | 保留 `:0`，如 `anthropic.claude-opus-4-20250514-v1:0` |

跨区域前缀：`global.`（如 `global.anthropic.claude-opus-4-6-v1`）

## 管理员面板

- 访问地址：`https://<portal-domain>/admin`
- 认证：基于 JWT，要求邮箱在 `ADMIN_EMAILS` 环境变量、DDB 管理员列表或 Cognito 组中
- 标签页：Users, Policies, Pricing, Admins
- 管理员列表存储在 DynamoDB（QuotaPolicies 表，PK=`ADMIN#email`）
- 冷启动引导：如果 DDB 中无管理员记录，从 `ADMIN_EMAILS` 环境变量初始化
- 无法通过门户移除最后一个管理员（保护机制）
- `/api/me` -- 所有用户可用（无需管理员权限），在门户上显示管理员标识

## 监控指标

- MetricsAggregator Lambda 每 5 分钟运行一次
- `AGGREGATION_WINDOW` 环境变量控制 CloudWatch Logs Insights 查询窗口（默认 15 分钟，大于运行间隔以应对索引延迟）
- 写入目标：CloudWatch Metrics（命名空间：ClaudeCode）+ DynamoDB（ClaudeCodeMetrics 表）
- OTLP collector 要求：端口 80（ALB 不监听 4318），5 个 OTEL 环境变量全部设置
- otel-helper 读取 `AWS_PROFILE` 环境变量以定位正确的 credential-process 配置

## 部署要点

- ALB 目标组必须启用 multi-value headers（`lambda.multi_value_headers.enabled: true`）
- 启用 multi-value 后，所有 Lambda 响应必须使用 `multiValueHeaders`（而非 `headers`）
- 所有 Lambda 请求头读取必须同时检查 `multiValueHeaders` 和 `headers`
- Cognito 注销需重定向到：`https://<cognito-domain>/logout?client_id=<id>&logout_uri=<uri>`
- Landing page 和 Admin panel 共享同一 ALB，通过路径路由（`/admin/*` -> admin Lambda）

## DynamoDB 表

| 表 | 用途 | Key Schema |
|---|------|------------|
| QuotaPolicies | 策略 + 管理员列表 | pk=`POLICY#type#id` 或 `ADMIN#email`, sk=`CURRENT` 或 `ADMIN` |
| UserQuotaMetrics | 用户级用量 | pk=`USER#email`, sk=`MONTH#YYYY-MM` |
| BedrockPricing | 模型定价 | pk=`model_id` |
| ClaudeCodeMetrics | 聚合指标 | pk=various, sk=timestamp |

## 常见运维问题

| 现象 | 原因 / 解决 |
|------|------------|
| Admin panel 显示 0 用户 | 检查 Bedrock Model Invocation Logging 是否开启、S3 前缀是否匹配 `bedrock_usage_stream` 监听的前缀（见 `docs/wps-bedrock-logging-prefix-mismatch.md`） |
| 用户有活动但 Admin panel 空 | `bedrock_usage_reconciler` 每 30 分钟才对账；查看 `StreamLambdaErrorAlarm` / DLQ 深度 |
| TVM 请求 5xx | 查 `tvm` Lambda 日志；常见为 `BedrockUserRole` 信任关系或 `DynamoDB` PROFILE 读取失败（fail-closed） |
| 用户费用显示 $0 | 检查 `BedrockPricing` 表中 model ID（Claude 4.6 无 `:0` 后缀） |
| Multi-value header 导致 401 | Lambda 从 `headers` 读取（启用 multi-value 后为空），应改为 `multiValueHeaders` |
| 登录触发文件下载 | Lambda 响应使用了 `headers` 而非 `multiValueHeaders` |
| Docker 环境变量未生效 | 使用 `docker compose up -d`（而非 `restart`）以重建容器 |
| Windows 解压后 `ModuleNotFoundError: No module named 'jaraco'` | 客户端用了旧的没有显式目录条目的 zip，请重新打包分发（这次 branch 已修复） |

---

# English Version

## Architecture Overview

CCWB (Claude Code with Bedrock) enables enterprise Claude Code access via Amazon Bedrock. Core components:

- **credential-process**: CLI tool that handles OIDC auth and calls the TVM for short-lived AWS credentials
- **TVM (Token Vending Machine) Lambda**: issues Bedrock-scoped credentials server-side, runs a synchronous fail-closed quota check, and denies disabled users
- **Bedrock usage pipeline**: Bedrock Model Invocation Logging -> S3 -> SQS -> `bedrock_usage_stream` Lambda -> DynamoDB (`#BEDROCK` usage records), reconciled every 30 minutes by `bedrock_usage_reconciler`
- **Landing page**: ALB + Lambda portal with per-OS grouped download cards (Linux exposes both Portable and Slim variants)
- **Admin panel**: separate Lambda on the same ALB for managing quotas, policies, pricing, admins, and enable/disable of users
- **OTLP pipeline (optional)**: otel-helper -> credential-process (JWT) -> OTEL collector -> CloudWatch -> MetricsAggregator Lambda -> DynamoDB (behavioral metrics only — not used for quota/cost)
- **Dashboard**: CloudWatch dashboard displaying pre-computed metrics from DynamoDB

**Important change**: cost and usage data now come from Bedrock Model Invocation Logging. The admin panel Users table and quota checks read `USER#…#MONTH#…#BEDROCK` / `DAY#…#BEDROCK` records. See [cost-management.md](cost-management.md) for the full architecture.

## Quota Management

### Policy Types

| Type | DynamoDB Key | Description |
|------|-------------|-------------|
| `user` | `POLICY#user#email@example.com` | Per-user policy |
| `group` | `POLICY#group#group-name` | Per-group policy |
| `default` | `POLICY#default` | Fallback for users with no specific policy |
| `org` | `POLICY#org#global` | Org-wide ceiling, checked BEFORE per-user checks |

### Limit Dimensions

- `monthly_token_limit` / `daily_token_limit` -- token count limits
- `monthly_cost_limit` / `daily_cost_limit` -- cost-based limits (USD)
- Cost limits use pricing data from the BedrockPricing DynamoDB table

### Policy Resolution Logic

Quota checks execute in this order -- **first match wins**:

```
1. Org-wide check (org)       ← checked first; if exceeded, ALL users blocked
   ↓ pass
2. Unblock check              ← admin temporary unblock; if active, skip limit checks
   ↓ no unblock
3. Policy resolution (priority):
   3a. User policy (user)     ← exact email match, highest priority
   3b. Group policy (group)   ← match user's groups, pick most restrictive
   3c. Default policy         ← fallback
   3d. No policy              ← unlimited access
   ↓
4. Enforcement mode
   - alert: log warning, allow access
   - block: proceed to limit checks
   ↓
5. Limit checks (in order, first exceeded = blocked):
   5a. Monthly token limit
   5b. Monthly cost limit
   5c. Daily token limit
   5d. Daily cost limit
   ↓ all pass
6. Access granted
```

**Group policy "most restrictive" rule**: When a user belongs to multiple groups, policies are compared by tuple:
`(monthly_token_limit, monthly_cost_limit, daily_token_limit, daily_cost_limit)`
Unset dimensions are treated as infinity (∞) and do not affect ordering.

**Day/month boundary timezone**: All daily resets and monthly rollovers use **UTC+8**.

**Key design decisions**:
- Unblock does **NOT** override org-wide limits. Even if an admin unblocks a user, if the org total exceeds its ceiling, the user remains blocked.
- Limit check order is fixed: monthly tokens → monthly cost → daily tokens → daily cost. First exceeded limit returns a block; subsequent dimensions are not checked.

**Group policies are per-user limits, NOT shared pools**:
- A group policy `POLICY#group#engineering` with monthly=200M means: each user in the engineering group gets their own 200M cap
- There is no group-level aggregate (`GROUP#engineering` summary record) — "engineering shares 1B tokens" is not supported
- Shared group pools would require additional aggregator logic

**Group info sources**:
- At quota check time: extracted from JWT claims in real-time (`groups`, `cognito:groups`, `custom:department`)
- In the aggregator: only parsed from OTEL logs when `ENABLE_FINEGRAINED_QUOTAS=true` (currently disabled)
- OTEL telemetry does not currently emit group claims — the aggregator's group query depends on the credential provider sending group info to logs (not yet implemented)

**Multi-org**:
- Only a single org is supported (`ORG#global`)
- No multi-tenant or per-department org-level limits
- For department-level caps, use group policies (per-user limits) as an approximation

#### Examples

**Example 1: Multi-layer policy resolution**

Policies configured:
- `POLICY#default#default`: monthly=100M tokens, enforcement=block
- `POLICY#group#engineering`: monthly=200M tokens, daily_cost=$20, enforcement=block
- `POLICY#user#alice@corp.com`: monthly=500M tokens, enforcement=alert

| User | Groups | Effective Policy | Reason |
|------|--------|-----------------|--------|
| alice@corp.com | engineering | user policy (500M, alert) | User policy has highest priority |
| bob@corp.com | engineering | group policy (200M, $20/day) | No user policy, matches group |
| charlie@corp.com | (none) | default policy (100M) | No user/group policy, uses default |
| dana@corp.com | (none) | no policy = unlimited | If default policy doesn't exist |

**Example 2: Most restrictive group selection**

Group policies:
- `POLICY#group#engineering`: monthly=200M tokens, monthly_cost=$100
- `POLICY#group#contractor`: monthly=300M tokens, monthly_cost=$50

User bob belongs to both engineering and contractor.

Comparison tuples:
- engineering: `(200M, $100, ∞, ∞)`
- contractor: `(300M, $50, ∞, ∞)`

engineering has a lower token limit (200M < 300M), so **engineering policy applies**.

> Note: Although contractor has a stricter cost limit ($50 < $100), tuple comparison starts from the first dimension -- 200M < 300M decides the result.

**Example 3: Org limit blocks everyone**

Config:
- `POLICY#org#global`: monthly=1B tokens, enforcement=block
- `POLICY#user#alice@corp.com`: monthly=500M, enforcement=block (alice unblocked by admin for 7 days)

Current org total: 1.1B tokens

Result:
- alice is blocked ← org check runs before unblock check
- all other users are also blocked

**Example 4: Daily reset (UTC+8)**

- Daily limit: 10M tokens/day
- User has used 9.5M tokens at UTC 15:50 (UTC+8 23:50)
- UTC 16:00 (UTC+8 00:00): daily counter resets to 0, new day begins
- User can resume usage

**Example 5: Token and cost limits together**

Policy: monthly=200M tokens, monthly_cost=$50, enforcement=block

Scenario A: User consumed 210M tokens, cost $30
→ Blocked, reason: `monthly_exceeded` (tokens exceeded first)

Scenario B: User consumed 100M tokens, cost $55 (heavy Opus output)
→ Blocked, reason: `monthly_cost_exceeded` (cost exceeded first)

Scenario C: User consumed 150M tokens, cost $40
→ Allowed (neither dimension exceeded)

### Enforcement Modes

- `block` -- deny AWS credentials when limit is exceeded
- `alert` -- log warning but allow access (org-level only for now)

### Quota Check Frequency

- Controlled by `quota_check_interval` in `config.json` (minutes)
- Default: 30 (check every 30 minutes)
- Set to 0: check every request (useful for testing, adds ~100ms latency per request)
- Unset / no `quota_api_endpoint`: no quota enforcement
- Check is synchronous -- happens in credential-process before issuing credentials
- First authentication always checks quota regardless of interval setting
- Cached credentials path: rechecks on interval, outputs credentials immediately if not due

### User Experience

- Warning at 80%+ usage: yellow terminal banner + browser popup with progress bars showing token AND cost usage
- Block at 100%: red terminal banner + browser popup, clearly labeled "COST LIMIT" or "TOKEN LIMIT"
- Daily limits reset at midnight UTC+8, monthly limits reset at month boundary (UTC+8)

## Pricing Table Management

- DynamoDB table: `BedrockPricing` (primary key: `model_id`)
- Fields: `input_per_1m`, `output_per_1m`, `cache_read_per_1m`, `cache_write_per_1m`
- Pricing lookup chain: exact model_id match -> partial match -> DEFAULT fallback
- Admin panel has a Pricing tab for CRUD operations
- CLI: `ccwb quota:set-pricing --defaults` seeds standard model pricing

**IMPORTANT -- Claude 4.6 model IDs have NO `:0` suffix:**

| Model | model_id |
|-------|----------|
| Opus 4.6 | `anthropic.claude-opus-4-6-v1` |
| Sonnet 4.6 | `anthropic.claude-sonnet-4-6` |
| Older models | Keep `:0`, e.g. `anthropic.claude-opus-4-20250514-v1:0` |

Cross-region prefix: `global.` (e.g. `global.anthropic.claude-opus-4-6-v1`)

## Admin Panel

- Access: `https://<portal-domain>/admin`
- Auth: JWT-based, requires email in `ADMIN_EMAILS` env var, DDB admin list, or Cognito group
- Tabs: Users, Policies, Pricing, Admins
- Admin list stored in DynamoDB (QuotaPolicies table, PK=`ADMIN#email`)
- Bootstrap: on cold start, if no admins exist in DDB, seeds from `ADMIN_EMAILS` env var
- Cannot remove last admin via portal (guard rail)
- `/api/me` -- available to ALL users (no admin check), shows admin badge on portal

## Monitoring and Metrics

- MetricsAggregator Lambda runs every 5 minutes
- `AGGREGATION_WINDOW` env var controls CloudWatch Logs Insights query window (default 15 min, wider than run interval to handle indexing lag)
- Writes to: CloudWatch Metrics (namespace: ClaudeCode) + DynamoDB (ClaudeCodeMetrics table)
- OTLP collector requires: port 80 (ALB does not listen on 4318), all 5 OTEL env vars set
- otel-helper reads `AWS_PROFILE` env var to locate the correct credential-process profile

## Deployment Notes

- ALB target groups MUST have multi-value headers enabled (`lambda.multi_value_headers.enabled: true` in TargetGroupAttributes)
- When multi-value is enabled, all Lambda responses must use `multiValueHeaders` (not `headers`)
- All Lambda request header reads must check both `multiValueHeaders` and `headers`
- Cognito logout requires redirect to: `https://<cognito-domain>/logout?client_id=<id>&logout_uri=<uri>`
- Landing page and admin panel share the same ALB, routed by path (`/admin/*` -> admin Lambda)

## DynamoDB Tables

| Table | Purpose | Key Schema |
|-------|---------|------------|
| QuotaPolicies | Policies + admin list | pk=`POLICY#type#id` or `ADMIN#email`, sk=`CURRENT` or `ADMIN` |
| UserQuotaMetrics | Per-user usage | pk=`USER#email`, sk=`MONTH#YYYY-MM` |
| BedrockPricing | Model pricing | pk=`model_id` |
| ClaudeCodeMetrics | Aggregated metrics | pk=various, sk=timestamp |

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| Admin panel shows 0 users | Confirm Bedrock Model Invocation Logging is enabled and the S3 prefix matches what `bedrock_usage_stream` watches (see `docs/wps-bedrock-logging-prefix-mismatch.md`) |
| Users active but admin panel empty | The reconciler runs every 30 min; check `StreamLambdaErrorAlarm` and DLQ depth |
| TVM returns 5xx | Inspect `tvm` Lambda logs; common causes are `BedrockUserRole` trust policy issues or DynamoDB PROFILE lookup failures (fail-closed) |
| User cost shows $0 | Check BedrockPricing table has correct model IDs (Claude 4.6 has no `:0` suffix) |
| Multi-value header 401 | Lambda reading from `headers` dict (empty when multi-value enabled) instead of `multiValueHeaders` |
| Login triggers file download | Lambda response using `headers` instead of `multiValueHeaders` |
| Docker env not applied | Use `docker compose up -d` (not `restart`) to pick up env changes |
| Windows `ModuleNotFoundError: No module named 'jaraco'` | Client extracted an old zip without explicit directory entries; re-package and redistribute (fixed on this branch) |
