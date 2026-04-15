# 设计：成本管理加固

> 状态：草稿 → 待实施
> 日期：2026-04-12
> 作者：binc

## 1. 问题陈述

配额/成本管理系统存在若干漏洞和缺口：

### 1a. OTEL 流水线单点故障

用量追踪完全依赖客户端 OTEL 流水线：

```
otel-helper（客户端二进制）
  → HTTP 请求头携带 user.email
    → OTEL Collector（ECS）
      → CloudWatch Logs
        → metrics_aggregator Lambda
          → DynamoDB（USER#{email}，MONTH#{YYYY-MM}）
            → quota_check Lambda 读取用量 → 执行限额
```

如果 `otel-helper` 缺失（被杀毒软件删除、用户篡改、安装失败）：
1. OTEL 请求缺少 `x-user-email` 请求头
2. `metrics_aggregator` 按 `user.email` 过滤查询——没有该字段的记录被静默丢弃
3. DynamoDB 显示零用量 → quota_check 始终放行
4. `update_org_aggregate()` 汇总 USER# 记录 → 组织总量也被低估

### 1b. 客户端可绕过配额检查

当前架构中，客户端通过 Cognito Identity Pool 直接获取 AWS 凭证（`GetCredentialsForIdentity`），配额检查（`quota_check` Lambda）仅是 credential-process 中的一个可选步骤。用户可以：
1. 篡改 credential-process，跳过配额检查步骤
2. 直接调用 `GetCredentialsForIdentity`（只需 id_token，无需通过配额检查）
3. 获取的 Cognito 凭证直接拥有 Bedrock 权限

管理员禁用用户后，需等待已签发的 AWS 凭证过期（Cognito Identity Pool 约 1 小时）才能生效。在此窗口期内，用户仍持有有效的 Bedrock 凭证。

### 1c. 无持久化用户注册表

`first_seen` 按月存储在 DynamoDB 中（`SK=MONTH#YYYY-MM`），而非全局用户属性。当月不活跃的用户不会出现在管理面板中。历史 `first_seen` 会随 TTL 丢失。

### 1d. 无用户访问控制

管理面板中没有禁用/启用单个用户访问的机制。配额策略控制的是"用多少"，而非"能否"访问系统。

---

## 2. 设计目标

1. **任何单一客户端组件都不应能够禁用配额执行**
2. 以服务端用量追踪作为最终依据
3. 管理员禁用用户后，最长在当前 session 过期后生效（服务端控制 session 时长，默认 1 小时，可动态缩短）
4. 完整的用户注册表，包含首次激活时间
5. 对用户体验影响最小（不额外弹出浏览器登录窗口）
6. 兼容 Windows 和 macOS 客户端，以及 Cognito + OIDC 联合认证

---

## 3. 前提条件

- **Bedrock 模型调用日志：已启用**
  - 目标：**S3 Bucket**（客户当前配置）
  - S3 bucket 名称存储在部署配置中，不硬编码
  - 内容日志已启用，用于审计目的

---

## 4. 方案设计

### 第零层：Token Vending Machine（TVM）架构

#### 0. TVM 架构概述

将凭证签发从"客户端直接获取"改为"服务端代理签发"模式，使客户端在不通过配额检查的情况下**无法获取 Bedrock 凭证**。

**核心变更：**

1. Cognito Identity Pool 的 auth role 做 scope-down：只允许调用 TVM Lambda（`lambda:InvokeFunctionUrl`），**不给任何 Bedrock 权限**
2. 客户端调用 TVM Lambda（携带 id_token + otel-helper-status）
3. TVM Lambda 内部：验证 JWT → upsert PROFILE → 检查 profile.status → 检查配额 → 通过后调 `sts:AssumeRole` 签发 Bedrock 凭证
4. 客户端拿到 Bedrock 凭证

**新流程：**
```
credential-process → OIDC 认证 → id_token
  → TVM Lambda（id_token + otel-helper-status）
    → 验证 JWT + upsert PROFILE + 配额检查
    → sts:AssumeRole(RoleSessionName=ccwb-{email}) → Bedrock 凭证
  → 返回凭证给客户端
```

**关键收益：**
- **客户端无法绕过配额检查** — Cognito 凭证本身没有 Bedrock 权限
- **服务端完全控制 session 时长** — 可动态调整 `DurationSeconds`（如快超额时缩短到 15 分钟）
- **天然 fail-closed** — 拿不到 TVM Lambda 响应就拿不到凭证，去掉 `quota_fail_mode` 概念
- **配额检查和凭证签发合并** — TVM Lambda = quota_check + credential issuance（一次请求）
- **email 直接编入 ARN** — Bedrock 调用日志天然可追溯到用户，不再需要 IDENTITY# 映射表

**RoleSessionName 设计：**

```python
sts.assume_role(
    RoleArn="arn:aws:iam::123456789012:role/BedrockUserRole",
    RoleSessionName=f"ccwb-{email}",  # 服务端控制，email 中的 @ 和 . 合法
    DurationSeconds=3600,
)
```

Bedrock 调用日志的 `identity.arn` 变为：
```
arn:aws:sts::123456789012:assumed-role/BedrockUserRole/ccwb-user@example.com
```

**RoleSessionName 限制：** 最长 64 字符，只允许 `[\w+=,.@-]`，email 中的 `@` 和 `.` 合法，但长 email 需截断（前缀 `ccwb-` 占 5 字符，email 部分最长 59 字符）。

**IAM 配置：**

| 角色 | 权限 | 说明 |
|------|------|------|
| Cognito Identity Pool auth role | `lambda:InvokeFunctionUrl`（仅 TVM Lambda） | Scope-down，无 Bedrock 权限 |
| TVM Lambda execution role | `sts:AssumeRole`（BedrockUserRole）、`dynamodb:*`（UserQuotaMetrics/QuotaPolicies）、`cognito-idp:RevokeToken` | TVM Lambda 执行所需 |
| BedrockUserRole | `bedrock:InvokeModel*` | Trust policy 信任 TVM Lambda execution role |

---

### 第一层：credential-process 加固（客户端）

#### 1A. otel-helper 哈希校验

在调用 TVM Lambda 前，验证 `otel-helper` 二进制文件的 SHA256 哈希是否与预期值匹配。状态通过 `X-OTEL-Helper-Status` 请求头上报给 TVM Lambda，由服务端决定是否阻断。

**工作原理：**
1. `package` 命令在构建后计算 otel-helper 二进制的 SHA256
2. 哈希值写入 `config.json` 的 `otel_helper_hash` 字段
3. credential-process 将磁盘上二进制文件的哈希与配置值进行比对

```python
def _check_otel_helper_integrity(self):
    """通过 SHA256 哈希验证 otel-helper 二进制完整性。"""
    expected_hash = self.config.get("otel_helper_hash")
    if not expected_hash:
        print("ERROR: otel_helper_hash not configured. Package is incomplete.", file=sys.stderr)
        print("Please reinstall or contact your administrator.", file=sys.stderr)
        sys.exit(1)

    import hashlib, platform
    if platform.system() == "Windows":
        helper_path = Path.home() / "claude-code-with-bedrock" / "otel-helper.exe"
    else:
        helper_path = Path.home() / "claude-code-with-bedrock" / "otel-helper"

    if not helper_path.exists():
        print("ERROR: otel-helper not found. Usage tracking is required.", file=sys.stderr)
        print("Please reinstall or contact your administrator.", file=sys.stderr)
        sys.exit(1)

    actual_hash = hashlib.sha256(helper_path.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        print("ERROR: otel-helper integrity check failed (tampered or corrupted).", file=sys.stderr)
        print("Please reinstall or contact your administrator.", file=sys.stderr)
        sys.exit(1)

    return True
```

**配置项：**
- `otel_helper_hash`：SHA256 十六进制字符串，由 `package` 命令写入

**修改文件：**
- `source/credential_provider/__main__.py` — 新增方法，在 `run()` 中签发凭证前调用
- `source/claude_code_with_bedrock/cli/commands/package.py` — 打包时计算哈希并写入 config.json

#### 1B. 在 TVM 请求中上报 otel-helper 状态

调用 TVM Lambda 时，通过请求头携带 helper 完整性状态：

```python
headers["X-OTEL-Helper-Status"] = "valid" | "missing" | "hash-mismatch" | "unchecked"
```

TVM Lambda 记录该状态，并可通过 `REQUIRE_OTEL_HELPER` 环境变量选择性强制执行（状态不为 `"valid"` 时拒绝签发凭证）。

**修改文件：**
- `source/credential_provider/__main__.py` — 在 TVM Lambda 请求中添加请求头
- `deployment/infrastructure/lambda-functions/tvm/index.py` — 解析请求头、记录日志、可选强制执行

#### 1C. 刷新令牌支持（静默凭证续期）

**问题：** 当前 credential-process 仅缓存 id_token 用于静默续期。id_token 有效期 60 分钟，每次续期都需要浏览器登录。

**方案：** 保存并使用 Cognito refresh_token（有效期 12 小时），无需浏览器即可获取新的 id_token，用于调用 TVM Lambda。

**当前令牌有效期（Cognito User Pool）：**

| 令牌 | 有效期 | 用途 |
|------|--------|------|
| id_token | 60 分钟 | 用户身份，用于 STS/Cognito 凭证交换 |
| access_token | 10 分钟 | API 访问（credential-process 不使用） |
| refresh_token | 720 分钟（12 小时） | 无需浏览器即可换取新 id_token |

**当前流程（每约 1 小时弹出浏览器）：**
```
Bedrock 凭证过期（TVM 控制，默认 1 小时）
  → credential-process：id_token 也已过期（60 分钟）
    → 静默续期失败 → 弹出浏览器 🌐
```

**新流程（每约 12 小时弹出浏览器）：**
```
Bedrock 凭证过期（TVM 控制，默认 1 小时）
  → credential-process：id_token 已过期（60 分钟）
    → 尝试 refresh_token → 调用 Cognito /oauth2/token 端点
      → 获取新 id_token（无需浏览器）✓
      → 调用 TVM Lambda（id_token + otel-helper-status）
        → TVM：验证 JWT + 配额检查 + AssumeRole → Bedrock 凭证
  → refresh_token 过期（12 小时）
    → 弹出浏览器 🌐
```

**令牌刷新请求：**
```
POST https://{cognito_domain}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token={cached_refresh_token}
&client_id={client_id}
```

此方式对 Cognito 原生用户和 Cognito + OIDC 联合用户（如 portal.kwps.cn）均适用。refresh_token 由 Cognito 签发，而非外部 IdP——刷新时只与 Cognito 通信。

**实现步骤：**
1. 初始 OIDC 令牌交换时保存 refresh_token（与 id_token 一同保存）
2. 新增 `_try_refresh_token()` 方法，在 id_token 过期但 refresh_token 有效时调用
3. 将 refresh_token 存储在 keyring（Windows/macOS）或 session 文件（Linux）中
4. 刷新流程在签发凭证前包含配额检查

**TVM 模式下无需定期重检**

在 TVM 模式下，每次 Bedrock 凭证过期（由服务端 `DurationSeconds` 控制）都需要重新调用 TVM Lambda，TVM Lambda 天然包含配额检查。不再需要 `_should_recheck_quota()` 和 `quota_check_interval` 机制。

若 id_token 过期，使用 refresh_token 获取新 id_token 后调用 TVM Lambda。若两个令牌均已过期，清除缓存凭证以强制重新登录。

**用户工作日凭证刷新时间线：**
```
09:00  浏览器登录（第 1 次）🌐
09:00  → id_token（60 分钟）+ refresh_token（12 小时）→ TVM Lambda → Bedrock 凭证（1 小时）
10:00  Bedrock 凭证过期 → refresh_token → 新 id_token → TVM Lambda → 新 Bedrock 凭证（静默）
11:00  同上（静默）
...
21:00  refresh_token 过期 → 浏览器登录（第 2 次）🌐
...
```

**修改文件：**
- `source/credential_provider/__main__.py`：
  - `authenticate_oidc()` — 从令牌响应中保存 refresh_token
  - 新增 `_try_refresh_token()` — 使用 refresh_token 调用 Cognito /oauth2/token
  - `_try_silent_refresh()` — 先尝试缓存的 id_token，再尝试 refresh_token，获取 id_token 后调用 TVM Lambda
  - refresh_token 存储在 keyring 或 session 文件中（与 id_token 类似）

---

### 第二层：服务端用量追踪 + 用户注册表（核心修复）

#### 2A. 启用 Bedrock 模型调用日志（新部署）

现有部署已启用此功能。对于新部署，添加 CloudFormation Custom Resource 自动启用。

**新增文件：**
- `deployment/infrastructure/lambda-functions/bedrock_logging_config/index.py` — Custom Resource Lambda
  - 调用 `bedrock.put_model_invocation_logging_configuration()`
  - Log group 名称来自 CloudFormation 参数

**修改文件：**
- `deployment/infrastructure/quota-monitoring.yaml` — 添加 Log Group、Custom Resource、IAM 角色

#### 2B. 用户档案注册表

**问题：** `first_seen` 按月存储，随 TTL 丢失。没有完整用户列表，也没有用于访问控制的 status 字段。

**方案：** TVM Lambda 在签发 Bedrock 凭证时自动 upsert `USER#{email} SK=PROFILE` 记录。email 从 JWT 中提取，无需额外的身份映射请求头。

> **与旧方案的关键区别：** 不再需要 `IDENTITY#{cognito_identity_id}` 映射表和 `X-Cognito-Identity-Id` / `X-Cognito-Sub` 请求头。TVM 的 `RoleSessionName` 直接编码 email，Bedrock 调用日志可从 ARN 直接解析用户身份。

**DynamoDB 创建/更新的记录：**

```
用户档案（持久化注册表）：
PK=USER#{email}, SK=PROFILE
{
    first_activated: "2026-03-15T10:30:00Z",  ← if_not_exists，永不覆盖
    last_seen: "2026-04-12T10:00:00Z",        ← 每次 TVM 请求时更新
    status: "active",                           ← active / disabled
    sub: "abc-123",
    groups: ["engineering"]
}
```

- `first_activated` 使用 DynamoDB `if_not_exists()` — 仅在首次认证时写入
- `status` 默认为 `"active"`，由管理员通过管理面板修改

**用户档案与配额策略的关系：**

| 概念 | 记录 | 用途 |
|------|------|------|
| **用户档案** | `USER#{email}, SK=PROFILE` | 账户级访问控制（是谁、何时加入、是否启用） |
| **配额策略** | `POLICY#user#{email}` | 用量限制（能用多少） |

**credential-process 执行顺序（无缓存凭证）：**
```
1. OIDC 认证 → id_token + refresh_token
2. 调用 TVM Lambda（id_token + X-OTEL-Helper-Status）：
   TVM Lambda 内部：
   a. 验证 JWT → 提取 email
   b. upsert PROFILE 记录
   c. 检查 profile.status → 已禁用？→ 立即拒绝 + 撤销 refresh_token
   d. 检查组织限额 → 组织超限？→ 拒绝所有用户
   e. 解析配额策略（用户→组→默认）→ 检查用量 MAX(OTEL, Bedrock) → 允许/拒绝
   f. sts:AssumeRole(RoleSessionName=ccwb-{email}) → Bedrock 凭证
3. 返回 Bedrock 凭证给客户端
```

被禁用的用户无论配额策略如何都会被阻断。活跃用户仍受配额限制约束。

**credential-process 执行顺序（Bedrock 凭证过期）：**
```
1. id_token 过期 → refresh_token → 新 id_token
2. 调用 TVM Lambda（同上 a-f）
3. 返回新 Bedrock 凭证
```

**修改文件：**
- `deployment/infrastructure/lambda-functions/tvm/index.py` — TVM Lambda 中实现 `_upsert_profile()` 和 `profile.status` 检查
- `deployment/infrastructure/quota-monitoring.yaml` — TVM Lambda 资源、IAM 角色、BedrockUserRole

#### 2C. Bedrock 用量追踪（S3 事件驱动 + 对账器）

客户的 Bedrock 模型调用日志输出到 S3（而非 CloudWatch Logs），因此采用 S3 事件驱动架构。两种模式协作：流式处理为主，定时兜底为辅。

**2C-1. 近实时流式处理（主）— S3 Event → SQS → Lambda**

```
Bedrock 模型调用日志
  → S3 Bucket（调用日志 JSON 文件）
    → S3 Event Notification（s3:ObjectCreated:*）
      → SQS Queue（缓冲 + 重试 + DLQ）
        → bedrock_usage_stream Lambda（批量处理，近实时）
          → 解析 JSON：从 ARN 的 RoleSessionName 提取 email、模型、输入/输出 token 数
              → 按定价配置计算成本
                → DynamoDB 原子更新：ADD token/成本到 USER#{email} MONTH#YYYY-MM#BEDROCK
```

**为什么用 S3 Event + SQS 而不是定时轮询 S3：**

| | S3 Event → SQS → Lambda | 定时 ListObjects + GetObject |
|---|---|---|
| 延迟 | 秒级（S3 event 通常几秒内触发） | 取决于轮询间隔（分钟级） |
| 大数据量 | SQS 自动批量 + Lambda 并发扩展 | 单次 ListObjects 分页 + 串行处理 |
| 可靠性 | SQS 重试 + DLQ 保证不丢消息 | 轮询失败 = 整个窗口丢失 |
| 去重 | S3 event 保证每个 object 至少一次（需幂等处理） | 需自行维护已处理 marker |
| 成本 | SQS 免费额度 100 万请求/月，极低 | S3 ListObjects 按请求计费 |

**CloudFormation 配置：**

```yaml
# SQS Queue（缓冲层）
BedrockLogQueue:
  Type: AWS::SQS::Queue
  Properties:
    VisibilityTimeout: 300  # Lambda 超时的 5 倍
    MessageRetentionPeriod: 86400  # 24 小时
    RedrivePolicy:
      deadLetterTargetArn: !GetAtt BedrockLogDLQ.Arn
      maxReceiveCount: 3

# DLQ（处理失败的消息）
BedrockLogDLQ:
  Type: AWS::SQS::Queue
  Properties:
    MessageRetentionPeriod: 1209600  # 14 天

# SQS Policy（允许 S3 发送消息）
BedrockLogQueuePolicy:
  Type: AWS::SQS::QueuePolicy
  Properties:
    Queues: [!Ref BedrockLogQueue]
    PolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: s3.amazonaws.com
          Action: sqs:SendMessage
          Resource: !GetAtt BedrockLogQueue.Arn
          Condition:
            ArnLike:
              aws:SourceArn: !Sub 'arn:aws:s3:::${BedrockLogBucketName}'
```

> **注意：** S3 Event Notification 需要在客户的 Bedrock log S3 bucket 上配置。如果该 bucket 不在本 CloudFormation stack 管理范围内，需手动或通过 Custom Resource 配置 `s3:PutBucketNotificationConfiguration`。

**SQS → Lambda 批量触发配置：**

S3 Event Notification 本身是每个文件触发一条 SQS 消息，但 Lambda SQS Event Source Mapping 支持**批量消费**：

```yaml
BedrockUsageStreamEventSource:
  Type: AWS::Lambda::EventSourceMapping
  Properties:
    EventSourceArn: !GetAtt BedrockLogQueue.Arn
    FunctionName: !Ref BedrockUsageStreamFunction
    BatchSize: 100                        # 一次最多拉取 100 条消息
    MaximumBatchingWindowInSeconds: 60    # 或等待 60 秒凑批（取先到者）
    FunctionResponseTypes:
      - ReportBatchItemFailures          # 部分失败不影响整批
```

这样 Lambda 不会每个文件调用一次，而是每 60 秒（或凑满 100 条消息）调用一次，批量处理。

> `MaximumBatchingWindowInSeconds: 60` 意味着最大延迟从"秒级"变为"约 60 秒"，但 Lambda 调用次数大幅减少。可根据需要调整（0 = 不等待，立即触发；最大 300 秒）。

**Lambda 处理逻辑（bedrock_usage_stream）：**
- 从 SQS event 批量获取多个 S3 object key
- `s3.get_object()` 读取调用日志 JSON
- Bedrock 调用日志格式：每个文件包含一次调用的完整记录（含 `modelId`、`inputTokenCount`、`outputTokenCount`、IAM 身份）
- 解析 IAM principal → 从 RoleSessionName 提取 email（格式：`assumed-role/BedrockUserRole/ccwb-user@example.com`，去掉 `ccwb-` 前缀即得 email）
- DynamoDB `UpdateItem` + `ADD` 原子累加（并发安全，无竞态）
- 无法从 ARN 解析 email 的记录 → 记录警告并跳过（非 TVM 签发的 Bedrock 调用）
- **关于 SQS 重复投递：** SQS 标准队列为至少一次投递，极少数情况下同一条消息会被投递两次，导致 `ADD` 重复累加。**不做严格去重**——维护已处理 key 集合会增加每条消息一次额外 DynamoDB 读写，成本和复杂度不值得。`MAX(OTEL, Bedrock)` 策略天然吸收轻微的 Bedrock 侧偏高。

**2C-2. 定时对账器（兜底）— EventBridge Schedule**

即使有流式处理，仍需定时对账器处理：
- 进入 DLQ 的 SQS 投递失败记录
- 数据完整性校验

```
EventBridge（每 30 分钟）
  → bedrock_usage_reconciler Lambda
    → S3 ListObjectsV2（prefix = 日期目录，时间窗口 = 最近 35 分钟）
      → 对每个 object：检查是否已处理（DynamoDB processed marker）
        → 未处理的：GetObject → 解析（从 ARN 提取 email）→ 聚合 → 写入 DynamoDB
      → 处理 DLQ 中的消息（重新解析）
```

**对账器防超时设计：**
- 只 list 最近 35 分钟的 S3 objects（按 key prefix 过滤，不扫描全部）
- Bedrock log S3 key 格式通常为 `AWSLogs/{account}/BedrockModelInvocationLogs/{region}/{yyyy/MM/dd/HH}/...`
- 使用 `last_reconciled_timestamp` 水位线避免重复处理
- Lambda 超时设置 5 分钟
- 失败不阻塞流式处理，下次自动覆盖

**关键设计决策：高水位线策略**

```
每用户每月的 DynamoDB 记录：
  PK=USER#{email}, SK=MONTH#2026-04           ← OTEL 来源（现有）
  PK=USER#{email}, SK=MONTH#2026-04#BEDROCK   ← Bedrock 日志来源（新增）
```

`quota_check` 读取两条记录，取 `MAX(otel_usage, bedrock_usage)`：

```python
def get_user_usage(email: str) -> dict:
    month_sk = f"MONTH#{month_prefix}"
    otel_usage = _get_usage_record(email, month_sk)
    bedrock_usage = _get_usage_record(email, f"{month_sk}#BEDROCK")

    return {
        "total_tokens": max(otel_usage["total_tokens"], bedrock_usage["total_tokens"]),
        "daily_tokens": max(otel_usage["daily_tokens"], bedrock_usage["daily_tokens"]),
        "estimated_cost": max(otel_usage["estimated_cost"], bedrock_usage["estimated_cost"]),
        "daily_cost": max(otel_usage["daily_cost"], bedrock_usage["daily_cost"]),
        "input_tokens": max(otel_usage["input_tokens"], bedrock_usage["input_tokens"]),
        "output_tokens": max(otel_usage["output_tokens"], bedrock_usage["output_tokens"]),
        "cache_tokens": max(otel_usage["cache_tokens"], bedrock_usage["cache_tokens"]),
    }
```

**为什么用 MAX 而不是 SUM：** 两个来源追踪的是同一用量。SUM 会重复计算。MAX 无论哪个来源可用都能给出正确值。

**组织聚合**同样使用高水位线：对每个用户取 `MAX(otel, bedrock)` 后求和。

**定价配置：**

对账器和流式 Lambda 都需要模型定价来计算成本：

| 来源 | 说明 |
|------|------|
| DynamoDB `PRICING#{model_id}` | 管理员可配置，优先级最高 |
| Lambda 环境变量 `DEFAULT_PRICING_JSON` | 部署时写入的默认值 |
| 兜底 | 未知模型 → 使用最贵模型的价格（宁多算不少算） |

管理面板提供定价管理 UI。新模型上线前需更新定价表，否则按兜底价格计费。

**新增文件：**
- `deployment/infrastructure/lambda-functions/bedrock_usage_stream/index.py` — 流式处理 Lambda
- `deployment/infrastructure/lambda-functions/bedrock_usage_reconciler/index.py` — 定时兜底 Lambda

**修改文件：**
- `deployment/infrastructure/lambda-functions/quota_check/index.py` — `get_user_usage()` 双源读取
- `deployment/infrastructure/quota-monitoring.yaml` — SQS Queue + DLQ、流式 Lambda、对账器 Lambda、IAM 角色、EventBridge schedule

#### 2D. 管理面板：用户管理

扩展管理面板，展示完整用户列表并支持禁用/启用用户。

**用户列表** — 从 `PROFILE` 记录读取，而非 `MONTH#` 记录：
- 显示所有历史用户，不仅限于当月活跃用户
- 准确的 `first_activated` 日期（非按月的 `first_seen`）
- `status` 列（active/disabled）
- `last_seen` 列

**禁用/启用** — 新增 API 端点：
```
POST /admin/user/disable  {email: "user@example.com"}
POST /admin/user/enable   {email: "user@example.com"}
```
设置 `PROFILE.status = disabled/active`。禁用后 TVM Lambda 不再签发新 Bedrock 凭证，现有凭证到期后（由服务端 `DurationSeconds` 控制）自动失效。

**UI 改动（Users 标签页）：**

- 用户列表表格新增列：`Status`（显示 active/disabled 徽标）、`First Activated`、`Last Seen`
- 每行用户增加操作按钮：
  - active 用户 → 显示 `Disable` 按钮（红色/警告色）
  - disabled 用户 → 显示 `Enable` 按钮（绿色）+ 行样式置灰
- 点击 Disable/Enable 弹出确认对话框（防误操作），确认后调用对应 API
- 操作成功后刷新用户列表，状态实时更新
- 支持按 status 筛选（All / Active / Disabled）

**修改文件：**
- `deployment/infrastructure/lambda-functions/landing_page_admin/index.py`：
  - `api_list_users()` — 从 PROFILE 记录读取，支持 status 过滤
  - 新增 `api_disable_user()`、`api_enable_user()` 处理器
  - UI：Users 标签页表格改造 + Disable/Enable 按钮 + 确认对话框

---

### 第三层：异常检测与告警

#### 3A. 遥测缺口检测

定期检查（添加到 `quota_monitor` Lambda）：
- 从 DynamoDB `MONTH#YYYY-MM#BEDROCK` 记录获取活跃用户（Bedrock 来源）
- 从 DynamoDB `MONTH#YYYY-MM` 记录获取活跃用户（OTEL 来源）
- 出现在 Bedrock 但不在 OTEL 中的用户 → "遥测缺口"
- 发布 SNS 告警，包含受影响用户列表

#### 3B. 用量差异告警

在对账器 Lambda 中：
- 若某用户 `bedrock_usage > otel_usage * 1.2` → SNS 告警
- 每用户发布 CloudWatch 自定义指标 `TelemetryDiscrepancy`

#### 3C. 流水线健康监控

流式 Lambda 和对账器是成本追踪的最后防线，需要监控自身健康：

- **流式 Lambda 报错** → CloudWatch Alarm（Errors 指标 > 0 持续 5 分钟）→ SNS
- **对账器心跳** → 每次成功运行写入 `PK=SYSTEM#reconciler, last_run=timestamp` → `quota_monitor` 检查心跳，超过 45 分钟未更新 → 告警
- **TVM Lambda 健康** → CloudWatch Alarm 监控 TVM Lambda 错误率和延迟
- **DynamoDB 限流** → CloudWatch Alarm 监控 `ThrottledRequests` 指标

---

## 5. 加固后的数据流

```
                    ┌─── OTEL 流水线（现有）────────────────────────────┐
Claude Code ───────►│ otel-helper → Collector → CW Logs → aggregator   │──► DynamoDB USER#{email} MONTH#YYYY-MM
    │               └───────────────────────────────────────────────────┘
    │
    │               ┌─── Bedrock 调用日志（服务端）──────────────────────────────────────┐
    │               │ S3 Bucket（调用日志）                                              │
    ├──► Bedrock ──►│   ├─► S3 Event → SQS → 流式 Lambda（近实时，从 ARN 解析 email）  │──► DynamoDB USER#{email} MONTH#YYYY-MM#BEDROCK
    │               │   └─► 对账器 Lambda（每 30 分钟，回填 + DLQ）                     │
    │               └───────────────────────────────────────────────────────────────────┘
    │
    │               ┌─── credential-process（TVM 模式）──────────────────┐
    └──► cred-proc ►│ 哈希校验 → refresh_token → id_token               │
                    │ → TVM Lambda（id_token + otel-helper-status）──────│──► DynamoDB USER#PROFILE
                    │   （验证 JWT + upsert PROFILE + 配额检查           │
                    │    + sts:AssumeRole → Bedrock 凭证）              │
                    └───────────────────────────────────────────────────┘
                                        │
                                        ▼
                              TVM Lambda
                       1. 验证 JWT → 提取 email
                       2. upsert USER#PROFILE
                       3. 检查 profile.status（是否已禁用？）
                       4. 检查组织限额
                       5. 解析策略 → MAX(OTEL, Bedrock) 用量
                       6. sts:AssumeRole(RoleSessionName=ccwb-{email}) → Bedrock 凭证
```

## 6. 凭证刷新时间线

```
TVM Lambda 配置：DurationSeconds=3600（可动态调整）
Cognito 配置：id_token=60 分钟，refresh_token=12 小时

09:00  浏览器登录 🌐 → id_token + refresh_token
09:00  → TVM Lambda（id_token）→ Bedrock 凭证（1 小时）
10:00  Bedrock 凭证过期 → refresh_token → 新 id_token → TVM Lambda → 新 Bedrock 凭证（静默 ✓）
11:00  静默 ✓
  ...
18:00  静默 ✓
19:00  refresh_token 过期 → 浏览器登录 🌐
  ...

管理员在 14:30 禁用用户：
15:00  Bedrock 凭证过期 → refresh_token → 新 id_token → TVM Lambda → 拒绝 🚫
       （最大延迟：当前 session 剩余时长，由服务端 DurationSeconds 控制）
```

---

## 7. 可配置时间参数

### 系统管理员视角（服务端 / 部署配置）

管理员通过 AWS Console、CloudFormation 参数或部署配置修改这些值，影响全部用户。

| 参数 | 当前值 | 配置位置 | 影响范围 | 说明 |
|------|--------|----------|----------|------|
| **Cognito refresh_token 有效期** | 12 小时（720 分钟） | Cognito User Pool App Client | 用户多久需要重新浏览器登录 | `aws cognito-idp update-user-pool-client --refresh-token-validity 720` |
| **Cognito id_token 有效期** | 60 分钟 | Cognito User Pool App Client | id_token 过期后触发 refresh_token 续期 | 最小 5 分钟，最大 24 小时 |
| **TVM session duration (DurationSeconds)** | 3600 秒（1 小时） | TVM Lambda 环境变量 `TVM_SESSION_DURATION` | Bedrock 凭证有效期；过期后触发 credential-process 重新调用 TVM Lambda | 服务端控制，可动态缩短（如快超额时改为 900 秒） |
| **OTEL metrics_aggregator 聚合间隔** | 5 分钟 | CloudFormation 参数 `AggregationInterval` | OTEL 用量多久写入 DynamoDB | `metrics-aggregation.yaml` |
| **配额监控检查间隔** | 15 分钟 | CloudFormation `ScheduleExpression` | 多久检查一次组织限额和告警 | `quota-monitoring.yaml` |
| **Bedrock 用量流式批量窗口** | 60 秒 | CloudFormation `MaximumBatchingWindowInSeconds` | S3 日志到 DynamoDB 的最大延迟 | 0=立即（每条触发），最大 300 秒 |
| **Bedrock 用量对账器间隔** | 30 分钟 | CloudFormation EventBridge `ScheduleExpression` | 兜底对账器运行频率 | `quota-monitoring.yaml` |
| **SQS 消息保留** | 24 小时 | CloudFormation `MessageRetentionPeriod` | 未处理的 S3 event 消息保留多久 | 超时后消息丢失，由对账器兜底 |
| **DLQ 消息保留** | 14 天 | CloudFormation `MessageRetentionPeriod` | 处理失败的消息保留多久 | 供对账器重试或人工排查 |
| **DynamoDB 用量记录 TTL** | 月末 +30 天 | `metrics_aggregator/index.py` | 历史用量数据保留多久 | 过期后自动删除 |
| **配额告警记录 TTL** | 60 天 | `quota_monitor/index.py` | 告警历史保留多久 | |
| **对账器心跳告警阈值** | 45 分钟 | Lambda 环境变量 | 对账器多久没跑视为异常 | 应大于对账器间隔 |
| **TVM Lambda 超时** | 10 秒 | CloudFormation `Timeout` | 单次 TVM 请求超时（含 STS AssumeRole） | |
| **组织策略缓存 TTL** | 60 秒 | `tvm/index.py` 硬编码 | 组织限额在 Lambda 内存中缓存多久 | 减少 DynamoDB 读取 |

### 终端用户视角（客户端 / config.json）

用户通过 `config.json`（管理员分发）配置这些值。**用户不应自行修改**——由管理员打包分发。

| 参数 | 当前值 | 配置位置 | 用户感知 | 说明 |
|------|--------|----------|----------|------|
| **tvm_endpoint** | — | `config.json` | TVM Lambda Function URL 或 API Gateway 端点 | credential-process 调用此端点获取 Bedrock 凭证 |
| **tvm_request_timeout** | 5 秒 | `config.json` | TVM Lambda 请求超时 | TVM 不可达时天然 fail-closed |
| **otel_helper_hash** | — | `config.json` | otel-helper 二进制的 SHA256 哈希 | 由 `package` 命令自动生成 |

### 时间参数关系图

```
用户视角（一个工作日）：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
09:00              10:00              11:00         ...         21:00
  │                  │                  │                        │
  🌐 浏览器登录      ⚡ 静默续期         ⚡ 静默续期              🌐 浏览器登录
  │                  │                  │                        │
  ├─ refresh_token ──┼──────────────────┼────────── 12 小时 ─────┤
  ├─ id_token ─ 60 分钟  ← refresh_token 续期                    │
  ├─ Bedrock 凭证 ─ 1 小时 ← TVM Lambda 签发（服务端控制时长）    │
  │                  │                  │                        │
  └─ TVM Lambda ─────┘  ← 每次 Bedrock 凭证过期时调用（天然配额检查）│

管理员视角（服务端处理流水线）：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bedrock API 调用
  → S3 调用日志（Bedrock 写入，几秒）
    → S3 Event → SQS → 等待批量窗口（≤60 秒）
      → 流式 Lambda 处理（从 ARN 解析 email）→ DynamoDB BEDROCK 记录更新
        → 下次 TVM Lambda 配额检查读到最新用量

OTEL 流水线（并行）：
  → otel-helper → Collector → CW Logs
    → metrics_aggregator（每 5 分钟）→ DynamoDB OTEL 记录更新

对账器（兜底）：
  → 每 30 分钟扫描 S3 → 补漏 + 处理 DLQ

关键延迟链：
  Bedrock 调用 → DynamoDB 更新：≤60 秒（流式）或 ≤30 分钟（对账器兜底）
  DynamoDB 更新 → 配额生效：  ≤1 小时（下次 Bedrock 凭证过期触发 TVM Lambda）
  管理员禁用用户 → 生效：      ≤当前 session 剩余时长（服务端控制 DurationSeconds）
  管理员修改配额 → 生效：      ≤当前 session 剩余时长
```

### 调优建议

| 场景 | 调整 | 影响 |
|------|------|------|
| 需要更快响应管理员禁用操作 | 缩短 TVM `DurationSeconds`（如 900 秒 = 15 分钟） | Bedrock 凭证更频繁过期，TVM Lambda 调用增加 |
| 需要减少 Lambda 调用成本 | 增大流式 Lambda `MaximumBatchingWindowInSeconds`（如 60-300 秒） | Bedrock 用量更新延迟增加 |
| 用户抱怨每天登录两次 | 增大 Cognito refresh_token 有效期（如 24 小时） | 安全窗口不变（由 DurationSeconds 控制） |
| 组织超限需要更快触发 | 缩短 TVM `DurationSeconds` + 缩小配额监控检查间隔 | Lambda 成本增加 |
| Bedrock 日志量很大 | 增大流式 Lambda `BatchSize`（最大 10000） | 单次 Lambda 处理更多消息，内存需调大 |

---

## 8. 实施阶段

### 第一阶段：客户端加固 + TVM + 刷新令牌（5-6 天）

| 条目 | 文件 | 描述 |
|------|------|------|
| 0 | 新增：`tvm/index.py`、`quota-monitoring.yaml` | TVM Lambda + BedrockUserRole + Function URL |
| 0 | `bedrock-auth-*.yaml` / `cognito-*.yaml` | Cognito Identity Pool auth role scope-down |
| 1A | `credential_provider/__main__.py`、`package.py` | otel-helper SHA256 哈希校验 |
| 1B | `credential_provider/__main__.py`、`tvm/index.py` | 在 TVM 请求中上报 helper 状态 |
| 1C | `credential_provider/__main__.py` | 刷新令牌支持 |
| — | `credential_provider/__main__.py`、`config.py` | 替换 quota_check + GetCredentialsForIdentity 为 TVM 调用 |

**交付物：** TVM 架构上线；客户端无法绕过配额；otel-helper 状态上报；凭证静默刷新约 12 小时。

### 第二阶段：Bedrock 日志配置（1-2 天）

| 条目 | 文件 | 描述 |
|------|------|------|
| 2A | 新增：`bedrock_logging_config/index.py`、`quota-monitoring.yaml` | 启用 Bedrock 日志（新部署） |

**交付物：** 新部署自动启用 Bedrock 模型调用日志。

### 第三阶段：Bedrock 用量追踪 + 管理 UI（4-5 天）

| 条目 | 文件 | 描述 |
|------|------|------|
| 2C-1 | 新增：`bedrock_usage_stream/index.py`、`quota-monitoring.yaml` | S3 Event → SQS → 流式 Lambda（从 ARN 解析 email） |
| 2C-2 | 新增：`bedrock_usage_reconciler/index.py`、`quota-monitoring.yaml` | 定时兜底对账器（每 30 分钟）+ DLQ 处理 |
| 2C | `tvm/index.py` | 双源读取（高水位线） |
| 2C | `quota-monitoring.yaml` | 定价配置（DynamoDB PRICING# 记录） |
| 2D | `landing_page_admin/index.py` | 从 PROFILE 记录读取用户列表；禁用/启用 UI；定价管理 |

**交付物：** 即使没有 OTEL 也能执行配额（近实时）。管理员可查看所有用户、禁用访问、管理定价。**漏洞已关闭。**

### 第四阶段：告警 + 监控（2-3 天）

| 条目 | 文件 | 描述 |
|------|------|------|
| 3A | `quota_monitor/index.py` | 遥测缺口检测（Bedrock vs OTEL） |
| 3B | `bedrock_usage_reconciler/index.py` | 用量差异告警 |
| 3C | `quota-monitoring.yaml` | 流式 Lambda + 对账器 + TVM Lambda 健康监控 |

**交付物：** 主动告警，覆盖遥测损坏/篡改和处理流水线健康状况。

---

## 9. 残余风险

| 风险 | 严重程度 | 缓解措施 |
|------|----------|----------|
| 已签发 Bedrock 凭证在 session 过期前仍有效 | 低 | 窗口由服务端 `DurationSeconds` 控制（默认 1 小时），可动态缩短 |
| TVM Lambda 成为单点 | 中 | 每次凭证签发都要过 Lambda；需监控可用性、冷启动延迟；可配置 Provisioned Concurrency |
| TVM Lambda 不可用时所有用户无法获取 Bedrock 凭证 | 中 | fail-closed by design，但需要 CloudWatch Alarm 监控；Lambda 本身有 AWS SLA |
| Bedrock 日志是账户级别的 | 低 | 流式 Lambda 按 IAM role ARN 前缀过滤（`BedrockUserRole`），忽略非 TVM 签发的调用 |
| 跨区域复杂性 | 中 | 每个启用的 Bedrock region 可能有独立 S3 prefix 或 bucket，需配置对应的 Event Notification |
| 每次构建哈希变化 | 低 | `package` 命令自动生成；通过 config.json 分发 |
| refresh_token 存储在客户端 | 低 | 与 id_token 安全级别相同；keyring/session 文件带权限控制 |
| RoleSessionName 长度限制（64 字符） | 低 | `ccwb-` 前缀 5 字符 + email 最长 59 字符；超长 email 需截断，截断后仍可通过 PROFILE 记录关联 |
| 模型定价不准确或未更新 | 低 | 未知模型 → 回退到最贵价格；管理面板提供定价管理 |
| SQS 消息处理失败 | 低 | SQS 重试 3 次 → DLQ（保留 14 天）；对账器 Lambda 每 30 分钟重新处理 DLQ |
| S3 Event Notification 配置权限 | 中 | 客户的 Bedrock log S3 bucket 可能不在本 stack 管理范围，需手动配置或 Custom Resource |

> **注意：** TVM 模式下，credential-process 篡改不再是风险——Cognito Identity Pool 的 auth role 被 scope-down，不持有 Bedrock 权限。客户端必须通过 TVM Lambda 才能获取 Bedrock 凭证。"服务端凭证代理"选项已通过 TVM 架构实现。

---

## 10. 已做决策

| 问题 | 决策 | 理由 |
|------|------|------|
| 凭证签发模式 | TVM（服务端 AssumeRole） | 客户端无法绕过配额检查；fail-closed by design |
| otel-helper 校验方式 | SHA256 哈希，客户端检查 + TVM 上报 | 可靠；由 `package` 自动生成；TVM 可选择性强制执行 |
| 执行模式 | 哈希不匹配时客户端警告，TVM 可配置阻断 | 通过 `REQUIRE_OTEL_HELPER` 环境变量控制 |
| Bedrock 日志存储 | S3（客户当前配置） | 不改为 CW Logs，不增加双写成本 |
| Bedrock 用量追踪 | S3 Event → SQS → Lambda（主）+ 对账器 30 分钟（兜底） | 流式处理秒级延迟；SQS 保证可靠投递；对账器补漏 + 处理 DLQ |
| 新部署 Bedrock 日志 | 必须启用（CloudFormation Custom Resource） | 服务端追踪必须启用此功能 |
| 凭证刷新机制 | Cognito refresh_token（12 小时） | 避免每小时弹出浏览器；兼容 OIDC 联合认证 |
| 用户禁用机制 | PROFILE 记录中的 profile.status | 与配额策略分离；TVM 签发前检查 |
| Cognito Identity Pool auth role | scope-down：只允许 `lambda:InvokeFunctionUrl`（TVM Lambda） | 不再直接持有 Bedrock 权限；强制所有请求经过 TVM |
| BedrockUserRole | 由 TVM Lambda execution role 信任，授予 `bedrock:InvokeModel*` | TVM 通过 `sts:AssumeRole` 签发 Bedrock 凭证 |
| TVM session 时长 | 默认 3600 秒（1 小时），可动态调整 | 服务端控制凭证有效期，缩短生效窗口 |
| Cognito refresh_token 有效期 | 12 小时（720 分钟） | 覆盖完整工作日，只需一次浏览器登录；从默认 10 小时改为 12 小时 |
| 阶段优先级 | 第一阶段优先（客户端加固 + TVM + 刷新令牌） | 最快见效；TVM 从根本上解决绕过问题；立即改善用户体验 |

---

## 11. 部署检查清单

> **上次更新：** 2026-04-14（feat/cost-management-hardening 分支）
> **实现状态：** 代码完成 + auth/quota 栈已部署；客户端打包和 Cognito auth role scope-down 待完成

### 与原设计的差异说明

| 原设计 | 实际实现 | 原因 |
|--------|----------|------|
| `get_user_usage()` 双源 `MAX(OTEL, BEDROCK)` | 单源 `BEDROCK` only | Bedrock 调用日志为唯一可信来源（AWS 管理、防篡改），简化架构 |
| TVM 通过 Lambda Function URL 暴露 | TVM 通过现有 API Gateway HTTP API `/tvm` 路由暴露 | 复用现有 JWT Authorizer，无需额外配置 |
| `_revoke_refresh_token(sub)` 在 TVM 中实现 | 未实现 | 延迟到后续迭代；TVM 拒绝签发凭证已足够阻断 |
| 禁用用户时撤销 refresh_token | 未实现 | 同上；禁用后 TVM 拒绝 = 下次凭证过期后自动失效 |
| otel-helper 哈希不匹配时 `sys.exit(1)` | 仅打印警告，继续执行 | 状态上报给 TVM 由服务端决策；`REQUIRE_OTEL_HELPER` 控制是否阻断 |
| Cognito auth role scope-down（移除 Bedrock 权限）| 延迟执行 | 必须在 TVM 部署且端到端验证后再执行，否则现有用户立即断连 |
| TVM 自适应 session 时长 | 已实现（含 `aws:EpochTime` session policy） | 增强：服务端通过 session policy 强制过期，客户端无法绕过 |

### 第一阶段部署检查清单

**代码变更：**
- [x] `credential_provider/__main__.py` — `_check_otel_helper_integrity()` 方法已添加（line 540）
- [x] `credential_provider/__main__.py` — `run()` 中哈希检查在 TVM 调用之前，状态存入 `self.otel_helper_status`（line 1704）
- [x] `credential_provider/__main__.py` — `_call_tvm()` 方法已实现，携带 `X-OTEL-Helper-Status` 请求头（line 575）
- [x] `credential_provider/__main__.py` — 移除 `_check_quota()`、`_should_recheck_quota()`、`_should_check_quota()`、`_handle_quota_blocked()`、`_handle_quota_warning()`、`_get_last_quota_check_time()`、`_save_quota_check_timestamp()` 共 7 个旧方法
- [ ] `credential_provider/__main__.py` — 移除 `get_aws_credentials_cognito()` 和 `GetCredentialsForIdentity` 调用（保留为非 TVM 部署的回退路径，待 TVM 全量验证后移除）
- [x] `credential_provider/__main__.py` — `_try_refresh_token()` 方法已实现（line 629）
- [x] `credential_provider/__main__.py` — `_try_silent_refresh()` 重构：先尝试缓存 id_token → 再尝试 refresh_token → 调用 TVM（line 1665）
- [x] `credential_provider/__main__.py` — `run()` 重构：otel 检查 → 缓存 → 静默刷新(TVM) → 浏览器认证 → TVM（line 1700）
- [x] `credential_provider/__main__.py` — refresh_token 存储：`_save_refresh_token()`、`_get_cached_refresh_token()`、`_clear_cached_refresh_token()`（line 677-730）
- [x] `credential_provider/__main__.py` — `authenticate_oidc()` 保存 refresh_token（line 1112）
- [x] `credential_provider/__main__.py` — `clear_cached_credentials()` 清理 refresh_token（line 522-536）
- [x] `config.py` — `quota_api_endpoint` 改为 `tvm_endpoint`；新增 `tvm_request_timeout`；新增 `otel_helper_hash`；移除 `quota_fail_mode`、`quota_check_interval`
- [x] `package.py` — 打包时计算 otel-helper SHA256 哈希写入 config.json；`_create_config()` 包含 `tvm_endpoint` 和 `otel_helper_hash`
- [x] `tvm/index.py` — TVM Lambda handler 已创建（验证 JWT、upsert PROFILE、检查配额、自适应 session 时长、AssumeRole + session policy）
- [x] `tvm/index.py` — `_upsert_profile(email, claims)` 方法已实现（if_not_exists first_activated）
- [x] `tvm/index.py` — `_assume_role_for_user(email, effective_seconds)` 方法已实现（RoleSessionName=`ccwb-{email}`，session policy 含 `aws:EpochTime` 条件）
- [x] `tvm/index.py` — `_compute_session_duration(usage, policy)` 自适应 session 时长（<80%→900s, 80-90%→300s, 90-95%→120s, >=95%→60s）
- [ ] ~~`tvm/index.py` — `_revoke_refresh_token(sub)` 方法~~（延迟到后续迭代）
- [x] `tvm/index.py` — 解析并记录 `X-OTEL-Helper-Status` 请求头，可通过 `REQUIRE_OTEL_HELPER` 强制执行

**单元测试（198 passed / 1 pre-existing failure）：**
- [x] `test_silent_refresh.py` — 更新为 TVM 流程（16 个测试覆盖 _try_silent_refresh、_call_tvm、_check_otel_helper_integrity）
- [x] `test_session_policy_epoch.py` — 自适应 session 时长测试（7 个测试覆盖所有阈值等级）

**客户端打包 & 分发：**
- [ ] 运行 `poetry run ccwb package` — 确认 `config.json` 中包含 `otel_helper_hash` 和 `tvm_endpoint`
- [ ] Windows 和 macOS 二进制都已重新打包
- [ ] 新 config.json 分发到所有用户

**Cognito 配置：**
- [x] Cognito User Pool App Client — `RefreshTokenValidity` 改为 720 分钟（12 小时）
  - **注意：** `cognito-user-pool-setup.yaml` 由 `ccwb init` 管理，不受 `ccwb deploy auth` 控制。`deploy auth` 部署的是 `bedrock-auth-*.yaml`（仅引用 User Pool ID，不管理 App Client 设置）。
  - **CloudFormation 模板已更新**（line 128），但已部署的 App Client 不会自动更新。需手动执行：
    ```bash
    aws cognito-idp update-user-pool-client \
      --user-pool-id us-east-1_5ab7rnjpx \
      --client-id 5qhgkijsjosi7mfrdtnrrpn09h \
      --refresh-token-validity 720 \
      --token-validity-units RefreshToken=minutes
    ```
  - **验证命令：**
    ```bash
    aws cognito-idp describe-user-pool-client \
      --user-pool-id us-east-1_5ab7rnjpx \
      --client-id 5qhgkijsjosi7mfrdtnrrpn09h \
      --query 'UserPoolClient.RefreshTokenValidity'
    ```
- [ ] 验证：`describe-user-pool-client` 确认 RefreshTokenValidity=720（验收测试发现仍为 600，需手动更新）

**IAM & Cognito Identity Pool 配置：**
- [ ] **[待完成 - 必须最后执行]** Cognito Identity Pool auth role — scope-down，移除直接 Bedrock 权限
  - **前置条件：** TVM 端到端验证完成 + 客户端重新打包分发后才可执行
  - **风险：** 过早执行会导致所有现有用户（尚未更新客户端的）立即无法访问 Bedrock
- [x] BedrockUserRole 已创建 — trust policy 信任 TVMLambdaRole（`quota-monitoring.yaml` line 391）
- [x] BedrockUserRole — 授予 `bedrock:InvokeModel*`、`bedrock:Converse*` 权限
- [x] TVMLambdaRole — 授予 DynamoDB 读写权限
- [x] TVMAssumeRolePolicy — 授予 `sts:AssumeRole`（on BedrockUserRole）— 独立 Policy 资源避免循环依赖

**服务端部署：**
- [x] `poetry run ccwb deploy auth` — 部署 Cognito RefreshTokenValidity 变更（2026-04-14）
- [x] `poetry run ccwb deploy quota` — 部署 TVM Lambda + BedrockUserRole + API Gateway `/tvm` 路由（2026-04-14）
  - TVM 端点：`https://9wsagf2rs1.execute-api.us-east-1.amazonaws.com`

**验证测试：**
- [ ] 删除 otel-helper → 运行 credential-process → 应警告 "otel-helper not found"，TVM 收到 `X-OTEL-Helper-Status: missing`
- [ ] 替换 otel-helper 为假文件 → 运行 → 应警告 "hash mismatch"，TVM 收到 `hash-mismatch`
- [ ] 正常流程 → TVM 返回 Bedrock 凭证 → 调用 Bedrock 成功
- [ ] 正常流程 → 确认 refresh_token 保存成功
- [ ] 等 id_token 过期（60 分钟）→ 确认 refresh_token 自动续期 → TVM 签发新 Bedrock 凭证（无浏览器弹窗）
- [ ] 等 refresh_token 过期（12 小时）→ 确认弹出浏览器重新登录
- [ ] 检查 TVM Lambda 日志：确认 `X-OTEL-Helper-Status` 出现
- [ ] 检查 DynamoDB：确认 `USER#{email}, SK=PROFILE` 记录已创建，`first_activated` 和 `last_seen` 有值
- [ ] **[Cognito scope-down 后]** 直接用 Cognito Identity Pool 凭证调用 Bedrock → 应被 IAM 拒绝

### 第二阶段部署检查清单

**代码变更：**
- [x] `bedrock_logging_config/index.py` — Custom Resource Lambda 已创建（检查现有配置 → 按需创建 S3 bucket → 启用 Bedrock 日志）

**服务端部署：**
- [x] `poetry run ccwb deploy quota` — Custom Resource 已随 quota 栈一起部署（2026-04-14）
- [x] 确认 Bedrock 模型调用日志已启用 — Custom Resource 检测到已有 bucket `data-us-east-1-022346938362`
- [x] 确认 S3 bucket 已识别 — `data-us-east-1-022346938362`，prefix `bedrock-raw/`

**Bedrock 日志验证：**
- [x] S3 中有持续写入的调用日志文件（路径：`bedrock-raw/AWSLogs/022346938362/BedrockModelInvocationLogs/us-east-1/YYYY/MM/DD/HH/*.json.gz`）
- [ ] 确认日志中包含 IAM principal ARN（TVM 模式下格式：`assumed-role/BedrockUserRole/ccwb-user@example.com`）— 需 TVM 客户端上线后验证
- [x] 确认日志中包含 token 用量数据（已验证：`input.inputTokenCount`、`output.outputTokenCount`、`input.cacheReadInputTokenCount` 等字段存在）

### 第三阶段部署检查清单

**代码变更：**
- [x] `bedrock_usage_stream/index.py` — 流式处理 Lambda 已创建（从 ARN RoleSessionName 解析 email，三步条件式 daily reset，PROCESSED# marker + TTL 48h）
- [x] `bedrock_usage_reconciler/index.py` — 定时对账器 Lambda 已创建（S3 扫描 35 分钟窗口，BatchGetItem 检查 marker，DLQ drain，心跳写入）
- [x] `tvm/index.py` — `get_user_usage()` 读取 `MONTH#YYYY-MM#BEDROCK` 单源（Bedrock 调用日志为唯一可信来源）
  - **设计变更：** 原设计为双源 `MAX(OTEL, BEDROCK)`，实际实现简化为 BEDROCK 单源
- [x] `landing_page_admin/index.py` — 用户列表从 PROFILE 记录读取，支持 `?status=` 过滤
- [x] `landing_page_admin/index.py` — 禁用/启用按钮和 API（`POST /api/user/disable`、`POST /api/user/enable`）
  - **设计变更：** 禁用时不调用 `cognito-idp:RevokeToken`（延迟实现）；TVM 拒绝签发已足够阻断
- [x] `landing_page_admin/index.py` — 定价管理 UI（已有实现，无需修改）
- [x] `quota-monitoring.yaml` — SQS Queue + DLQ + QueuePolicy + 流式 Lambda + Event Source Mapping + 对账器 Lambda + EventBridge 30min + IAM 角色（共 23 个新资源）

**DynamoDB 初始化：**
- [x] 确认 `BedrockPricing` 表中已有 8 条定价记录 + 1 条 DEFAULT 兜底（验收测试 2026-04-14 确认）
  ```
  anthropic.claude-opus-4-6-v1           → $15/$75 per 1M tokens
  anthropic.claude-sonnet-4-6            → $3/$15
  anthropic.claude-haiku-4-5-20251001-v1:0 → $0.80/$4
  DEFAULT                                → $3/$15（兜底定价）
  ... 共 8 条模型记录
  ```
- [ ] 确认流式 Lambda 和对账器 Lambda 的 `DEFAULT_PRICING_JSON` 环境变量已配置（当前未设置，依赖 DynamoDB 查询 + 硬编码兜底）

**服务端部署：**
- [x] `poetry run ccwb deploy quota` — SQS Queue + DLQ、Lambda、EventBridge 已随 quota 栈一起部署（2026-04-14）
- [x] S3 Event Notification 已由 `bedrock_logging_config` Custom Resource 自动配置（2026-04-14）
  - Bucket: `data-us-east-1-022346938362`
  - Filter: `bedrock-raw/AWSLogs/022346938362/BedrockModelInvocationLogs/`
  - Target: `arn:aws:sqs:us-east-1:022346938362:claude-code-bedrock-log-queue`
  - **注意：** Custom Resource 需要 `s3:GetBucketNotification` 和 `s3:PutBucketNotification` IAM 权限（注意：IAM action 名与 boto3 方法名不同）
  - **注意：** CloudFormation 仅在 Custom Resource Properties 变更时重新触发。如需强制重新配置，在 Properties 中添加 `ForceUpdate` 字段并修改值
- [x] SQS Queue Policy 允许 S3 bucket 发送消息（CloudFormation 配置）
- [x] 流式 Lambda 有 `s3:GetObject` 权限（IAM Policy 授予 `arn:aws:s3:::*`）

**跨区域（如果使用多个 Bedrock region）：**
- [ ] 确认每个 region 的 Bedrock 日志是写入同一个 S3 bucket（不同 prefix）还是不同 bucket
- [ ] 如果是不同 bucket，每个 bucket 都需要配置 Event Notification → SQS
- [ ] 确认流式 Lambda 有权限读取所有相关 bucket

**验证测试：**
- [ ] 发送 Bedrock 请求 → 等待 S3 日志写入 → 60 秒内检查 SQS 收到消息 → 检查 `USER#{email}, SK=MONTH#YYYY-MM#BEDROCK` 有值
- [ ] 删除 otel-helper → 发送 Bedrock 请求 → 确认 BEDROCK 记录仍然更新（Bedrock 日志基于 ARN，不依赖客户端）
- [ ] 确认流式 Lambda 从 `assumed-role/BedrockUserRole/ccwb-user@example.com` 正确解析出 email
- [ ] 确认非 TVM 调用（IAM user ARN）被正确跳过（PROCESSED# marker 仍写入，但无 USER# 更新）
- [ ] 等对账器运行（30 分钟）→ 确认心跳写入 `SYSTEM#reconciler`、DLQ 被排空
- [ ] 管理面板 → 用户列表显示所有历史用户（含 first_activated、last_seen、status）
- [ ] 管理面板 → 禁用用户 → 确认 `PROFILE.status = disabled`
- [ ] 管理面板 → 重新启用用户 → 确认恢复访问
- [ ] 管理面板 → 定价页面显示所有模型价格，可编辑保存

**客户端重新打包分发：**
- [ ] 重新打包（哈希更新）并分发给所有用户

### 第四阶段部署检查清单

**服务端部署：**
- [x] CloudWatch Alarms 已创建 — 验收测试确认 3 个 Alarm 均存在（2026-04-14）：
  - `claude-code-bedrock-stream-errors` (AWS/Lambda Errors)
  - `claude-code-reconciler-errors` (AWS/Lambda Errors)
  - `claude-code-dynamodb-throttled` (AWS/DynamoDB ThrottledRequests)
  - 状态：`INSUFFICIENT_DATA`（正常 — 尚无错误数据点）
- [x] SNS Topic 存在 — `arn:aws:sns:us-east-1:022346938362:claude-code-quota-alerts`
- [ ] SNS Topic 需配置订阅目标（当前 0 个订阅 — 告警会触发但无人收到）
- [ ] quota_monitor Lambda 包含遥测缺口检测逻辑 — 待后续迭代实现
- [ ] quota_monitor Lambda 检查对账器心跳 — 待后续迭代实现

**验证测试：**
- [ ] 模拟流式 Lambda 报错 → 确认 CloudWatch Alarm 触发 → SNS 通知到达
- [ ] 停止对账器 EventBridge rule → 等 45 分钟 → 确认心跳告警触发
- [ ] 删除 otel-helper + 使用 Bedrock → 确认遥测缺口告警触发（用户出现在 BEDROCK 但不在 OTEL）

### 全量上线后总体验证

- [ ] **端到端正常路径：** 用户正常使用 → Bedrock 调用日志 → 流式 Lambda → DynamoDB BEDROCK 记录更新 → TVM 配额检查读到最新用量
- [ ] **OTEL 缺失路径：** 删除 otel-helper → credential-process 警告（哈希校验），TVM 收到 `missing` 状态；Bedrock 调用日志仍正常追踪
- [ ] **绕过 credential-process 路径：** 提取已签发的 Bedrock 凭证直接使用 → Bedrock 流式 Lambda 从 ARN 解析 email 秒级记录 → 下次 TVM 签发时体现真实用量
- [ ] **[Cognito scope-down 后] Cognito 凭证直接调 Bedrock：** 应被 IAM 拒绝（auth role 无 Bedrock 权限，只能调 TVM Lambda）
- [ ] **管理员禁用用户：** 禁用 → TVM 拒绝签发新 Bedrock 凭证；已签发凭证在 session 过期后失效（自适应时长：接近配额时最短 60 秒）
- [ ] **组织配额超限：** → TVM 读取 `ORG#global MONTH#YYYY-MM#BEDROCK` → 拒绝签发，所有用户被阻断
- [ ] **TVM Lambda 不可达：** → fail-closed，无法获取 Bedrock 凭证
- [ ] **自适应 session 时长：** 接近配额时 session 缩短（80%→5min, 90%→2min, 95%→1min），通过 `aws:EpochTime` session policy 服务端强制
- [ ] **全部告警通道：** SNS 通知正常到达管理员
