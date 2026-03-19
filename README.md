# Anti-OpenAI with Random IP (v4.2 深度实测版)

这是一个为 OpenAI 账号自动注册设计的增强型脚本，集成了 **Cloudflare Worker 动态 IP 轮换**、**深度浏览器指纹模拟** 以及 **智能 IPv4 优先策略**。

## v4.2 更新亮点 (深度实测验证)

1.  **修正 IPv4 强制逻辑**：针对 `curl_cffi` 在代理环境下的行为，改用 `session.ip_version = 4` 确保出口 IP 稳定为 IPv4，解决了部分服务器上 IPv6 优先导致的连接失败。
2.  **高强度缓存击穿**：在 Worker 转发请求中注入多重随机熵（URL 参数、随机 Header、随机 X-Forwarded-For），确保 Cloudflare 每次请求都分配新的出口 IP。
3.  **多源 IP 检测**：内置 3 个不同的 IP 检测源并支持自动并发切换，彻底解决“IP 获取失败”的问题。
4.  **人名邮箱生成**：自动生成符合人类习惯的 `firstname.lastname@domain.com` 格式邮箱，提高注册成功率。

## 快速开始

### 1. 环境准备

```bash
# 安装必要依赖
sudo pip3 install curl_cffi python-dotenv
```

### 2. 配置 .env 文件

在脚本同级目录下创建 `.env` 文件：

```env
# 必填：您的 Cloudflare Worker 转发地址
CF_WORKER_URL=https://your-worker.your-subdomain.workers.dev

# 选填：邮箱域名
MAIL_DOMAIN=your-domain.com

# 选填：本地代理地址 (如使用 Mihomo/Clash)
DEFAULT_PROXY=http://127.0.0.1:7890

# 选填：Token 保存目录
TOKEN_OUTPUT_DIR=tokens
```

### 3. 运行脚本

```bash
# 自动循环注册
python3 openai_registrar_final_v3.py

# 只运行一次测试
python3 openai_registrar_final_v3.py --once
```

## 核心功能说明

*   **IP 轮换**：配合 `cloudflare_openai_proxy_worker.js` 使用，利用 Cloudflare 的边缘网络实现每次请求 IP 自动跳变。
*   **指纹模拟**：基于 `curl_cffi` 的 `impersonate` 功能，完美模拟 Chrome 110/116/119、Edge、Safari 的 TLS 指纹。
*   **自动化**：自动处理 Token 获取并保存到 `tokens/` 目录，账号密码保存到 `accounts.txt`。

## 注意事项

*   请确保您的 Worker 脚本已正确部署并支持 `url` 参数转发。
*   如果 IP 检测依然失败，请检查服务器是否能正常访问 `CF_WORKER_URL`。
