# Claude Code with Bedrock (CCWB) 用户指南

CCWB 让开发者通过组织的身份提供商 (Cognito/OIDC) 使用 Amazon Bedrock 后端的 Claude Code。

---

## 安装与配置

管理员通过 Portal 分发一个安装包（按操作系统分组的下载卡片，Linux 同时提供 Portable 和 Slim 两个变体），其中包含 `config.json` 配置文件（含 profile 名称、TVM 端点、身份提供商域名、client_id、区域等信息）。

**安装包类型：**

| 变体 | 内置 Python | 下载大小 | 说明 |
|------|------------|---------|------|
| Windows / macOS / Linux **Portable** | ✅ | 35 – 130 MB | 解压即用，无需系统 Python |
| Linux **Slim** | ❌ | ~30 MB | 使用系统 Python 3.9+，Ubuntu 22.04 / Debian 11 / AL2023 已验证 |

**安装步骤：**

1. 解压安装包（Windows 用 File Explorer 直接解压即可；`install.bat` 会自动处理依赖）
2. 运行安装脚本：
   ```bash
   ./install.sh    # Linux / macOS
   install.bat     # Windows（双击或命令行都行）
   ```
3. 安装脚本会自动完成：
   - 在 `~/.aws/config` 中配置 credential-process
   - 在 `~/.claude/settings.json` 中配置 Claude Code 设置

**config.json 关键字段：**

| 字段 | 说明 |
|------|------|
| `selected_model` | 默认模型，例如 `global.anthropic.claude-opus-4-6-v1` |
| `tvm_endpoint` | Token Vending Machine 端点，凭据签发走这里 |
| `tvm_request_timeout` | TVM 请求超时（秒），默认 10 |
| `quota_check_interval` | 配额检查间隔（分钟）。默认 30。`0` = 每次请求都检查（仅用于测试，会增加延迟） |
| `otel_helper_hash` | otel-helper 完整性校验（SHA256），打包时自动写入 |

---

## 登录认证

- 首次运行时，浏览器会自动打开 Cognito/OIDC 登录页面
- 输入凭据后，OAuth 回调到 `localhost:8400` 完成认证
- 凭据缓存在 `~/.aws/credentials`，Token 过期前无需重新登录
- 强制重新登录：
  ```bash
  credential-process --clear-cache
  ```

---

## 日常使用

直接运行 `claude` 即可，认证过程完全透明。

**模型选择：**

- 默认使用 `config.json` 中的 `selected_model`
- 可通过环境变量覆盖：
  ```bash
  export ANTHROPIC_MODEL=global.anthropic.claude-opus-4-6-v1
  ```

**AWS Profile：**

`AWS_PROFILE` 必须与 CCWB 的 profile 名称一致，例如：

```bash
export AWS_PROFILE=claude-bedrock-ccwb
```

---

## 配额与限额

组织可以设置 Token 限额（月/日）和费用限额（月/日）。credential-process 在签发 AWS 凭据前会同步检查配额。

**检查频率（由 `quota_check_interval` 控制）：**

| 值 | 行为 |
|----|------|
| `30`（默认） | 每 30 分钟检查一次，推荐生产环境使用 |
| `0` | 每次请求都检查，仅用于测试 |

非检查周期内，直接使用缓存凭据，零开销。

**警告（黄色）** -- 用量达到 80% 以上：

- 终端显示黄色警告
- 浏览器弹出页面，显示用量进度条
- 访问**不会**被阻断

**阻断（红色）** -- 超出限额：

- 终端显示 "ACCESS BLOCKED"
- 浏览器显示红色阻断页面
- 不签发 AWS 凭据，退出码为 1
- 页面明确显示是 TOKEN LIMIT 还是 COST LIMIT 触发的阻断
- 同时显示 Token 用量和费用用量的进度条
- 日限额在 UTC 午夜重置
- 月限额在月初重置

**解除阻断：** 联系管理员。

---

## Docker 环境

```bash
# 启动
docker compose up -d

# 进入容器
docker compose exec claude-bedrock bash
```

- 端口 8400 映射到宿主机，用于 OAuth 回调 -- 在**宿主机**浏览器中打开认证 URL
- 凭据通过 named volumes 持久化，重启不丢失
- 环境变量变更后必须用 `docker compose up -d` 重建容器（`docker compose restart` 不会生效）

**遥测配置（可选）：**

```bash
OTLP_ENDPOINT=http://your-collector:80   # ALB 后端必须显式指定 :80
CLAUDE_CODE_ENABLE_TELEMETRY=1
OTEL_METRICS_EXPORTER=otlp
OTEL_LOGS_EXPORTER=otlp
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

---

## 常见问题

| 问题 | 解决方法 |
|------|----------|
| "Access blocked" | 配额超限，联系管理员 |
| 浏览器未自动打开 | 从终端复制 URL 手动打开 |
| "Authentication timeout" | 端口 8400 被占用，停止 Docker 或其他占用该端口的进程 |
| 注销登录 | 访问 Portal 注销页面（清除 Cognito 会话），或 `credential-process --clear-cache`（仅清除本地缓存） |
| 模型不对 | 检查 `ANTHROPIC_MODEL` 环境变量或 `config.json` 中的 `selected_model` |

---
---

# Claude Code with Bedrock (CCWB) User Guide

CCWB lets developers use Claude Code backed by Amazon Bedrock through your organization's identity provider (Cognito/OIDC).

---

## Installation & Setup

Your administrator publishes packages through a Portal with per-OS
download cards. Linux has two variants (Portable, Slim) side-by-side on
the same card. Each package contains a `config.json` file (profile name,
TVM endpoint, identity provider domain, client_id, region, etc.).

**Package variants:**

| Variant | Bundled Python | Download | Notes |
|---------|----------------|----------|-------|
| Windows / macOS / Linux **Portable** | ✅ | 35 – 130 MB | Self-contained, no system Python required |
| Linux **Slim** | ❌ | ~30 MB | Uses system Python 3.9+; verified on Ubuntu 22.04, Debian 11, AL2023 |

**Installation steps:**

1. Extract the package (Windows File Explorer's built-in "Extract All" works)
2. Run the installer:
   ```bash
   ./install.sh    # Linux / macOS
   install.bat     # Windows (double-click or from the terminal)
   ```
3. The installer automatically:
   - Configures credential-process in `~/.aws/config`
   - Configures Claude Code settings in `~/.claude/settings.json`

**Key config.json fields:**

| Field | Description |
|-------|-------------|
| `selected_model` | Default model, e.g. `global.anthropic.claude-opus-4-6-v1` |
| `tvm_endpoint` | Token Vending Machine endpoint; credentials are issued here |
| `tvm_request_timeout` | TVM request timeout in seconds (default 10) |
| `quota_check_interval` | Quota check interval in minutes. Default 30. `0` = check every request (testing only, adds latency) |
| `otel_helper_hash` | SHA256 of the packaged otel-helper (written at package time) |

---

## Authentication

- On first run, a browser opens to the Cognito/OIDC login page
- Enter your credentials; OAuth callback completes via `localhost:8400`
- Credentials are cached in `~/.aws/credentials` -- no re-login until token expires
- Force re-login:
  ```bash
  credential-process --clear-cache
  ```

---

## Daily Usage

Just run `claude` -- everything is transparent.

**Model selection:**

- Defaults to `selected_model` in `config.json`
- Override with an environment variable:
  ```bash
  export ANTHROPIC_MODEL=global.anthropic.claude-opus-4-6-v1
  ```

**AWS Profile:**

`AWS_PROFILE` must match the CCWB profile name, e.g.:

```bash
export AWS_PROFILE=claude-bedrock-ccwb
```

---

## Quota & Limits

Your organization may set token limits (monthly/daily) and cost limits (monthly/daily). The credential-process checks quota synchronously before issuing AWS credentials.

**Check frequency (controlled by `quota_check_interval`):**

| Value | Behavior |
|-------|----------|
| `30` (default) | Check every 30 minutes, recommended for production |
| `0` | Check every request, testing only |

Between checks, cached credentials are used directly with zero overhead.

**Warning (yellow)** -- usage reaches 80%+:

- Terminal shows a yellow warning
- Browser popup displays progress bars for usage
- Access is **not** blocked

**Blocked (red)** -- limit exceeded:

- Terminal shows "ACCESS BLOCKED"
- Browser shows a red block page
- No AWS credentials issued; exit code 1
- The page clearly shows whether TOKEN LIMIT or COST LIMIT triggered the block
- Progress bars show both token usage and cost usage (when applicable)
- Daily limits reset at UTC midnight
- Monthly limits reset at month boundary

**To get unblocked:** contact your administrator.

---

## Docker Environment

```bash
# Start
docker compose up -d

# Enter the container
docker compose exec claude-bedrock bash
```

- Port 8400 is published for OAuth callback -- open the auth URL in your **host** browser
- Credentials persist across restarts via named volumes
- After changing environment variables, use `docker compose up -d` to recreate the container (`docker compose restart` does not pick up env changes)

**Telemetry configuration (optional):**

```bash
OTLP_ENDPOINT=http://your-collector:80   # Must include :80 explicitly when behind ALB
CLAUDE_CODE_ENABLE_TELEMETRY=1
OTEL_METRICS_EXPORTER=otlp
OTEL_LOGS_EXPORTER=otlp
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Access blocked" | Quota exceeded, contact your administrator |
| Browser does not open | Copy the URL from terminal and open it manually |
| "Authentication timeout" | Port 8400 is in use; stop Docker or any other process using that port |
| Logout | Visit the Portal logout page (clears Cognito session), or run `credential-process --clear-cache` (clears local cache only) |
| Wrong model | Check `ANTHROPIC_MODEL` env var or `selected_model` in config.json |
