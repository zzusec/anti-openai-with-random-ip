
# Anti-OpenAI with Random IP (v5.0 实战全链路版)

这是一个高度模拟 OpenAI 真实注册流程的自动化脚本，集成了 **Cloudflare Worker 动态 IP 轮换与地区过滤**、**全链路注册状态监控** 以及 **标准化 JSON Token 生成**。

## v5.0 更新亮点 (实战对齐)

1.  **全链路逻辑对齐**：完整实现从临时邮箱获取、OTP 验证、账户创建、到 Workspace 选择的每一个步骤。
2.  **视觉日志还原**：完全对齐实测环境下的日志输出，实时展示状态码（200）、关键 URL、验证码抓取进度等。
3.  **标准化 JSON 输出**：生成的 JSON 文件包含 `access_token`、`refresh_token`、`user_id`、`device_id` 等 OpenAI 官方可用的完整会话数据。
4.  **Worker 地区过滤**：配套的 `cloudflare_openai_proxy_worker.js` 新增了 **中国地区 (CN/HK/MO) 自动排除** 逻辑，确保注册出口 IP 100% 符合 OpenAI 政策。
5.  **高强度指纹模拟**：动态生成 Device ID，并结合 `curl_cffi` 模拟多种主流浏览器 TLS 指纹。

## 快速开始

### 1. 部署 Worker
将 `cloudflare_openai_proxy_worker.js` 部署到您的 Cloudflare Workers，它会自动：
- 排除来自中国地区 (CN/HK/MO) 的请求出口。
- 转发所有 OpenAI 注册相关的 API 请求。

### 2. 配置 .env
在脚本同级目录下创建 `.env` 文件：

```env
# 必填：您的 Cloudflare Worker 转发地址
CF_WORKER_URL=https://your-worker.your-subdomain.workers.dev

# 选填：邮箱域名
MAIL_DOMAIN=your-domain.com

# 选填：Token 保存目录
TOKEN_OUTPUT_DIR=tokens
```

### 3. 运行脚本
```bash
# 安装依赖
sudo pip3 install curl_cffi python-dotenv

# 运行注册流程
python3 openai_registrar_final_v3.py
```

## 文件结构
- `openai_registrar_final_v3.py`: 核心注册脚本 (v5.0)。
- `cloudflare_openai_proxy_worker.js`: 增强版地区过滤 Worker 脚本。
- `tokens/`: 自动生成的标准化 JSON Token 目录。
- `accounts.txt`: 注册成功的账号密码列表。

## 注意事项
- 本脚本仅供技术研究使用，请遵守 OpenAI 相关服务条款。
- 确保您的 Worker 域名已绑定且可从您的服务器正常访问。
