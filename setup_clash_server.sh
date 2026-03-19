#!/bin/bash

# ==========================================================
# Ubuntu Server 全自动代理部署脚本 (Mihomo/Clash Meta) - 终极智能版
# 1. 自动转换：支持 V2Ray/SS/SSR 订阅自动转为 Clash YAML
# 2. 深度容错：解决 YAML 语法冲突（如 DIRECT 重名问题）
# 3. 稳定运行：自动处理依赖，确保代理 100% 可用
# ==========================================================

# 1. 基础环境准备
echo "[*] 正在安装必要依赖 (wget, gzip, curl, sed, base64)..."
apt-get update && apt-get install -y wget gzip curl coreutils

# 2. 安装 Mihomo 核心
if [ ! -f "/usr/local/bin/mihomo" ]; then
    VERSION="v1.19.21"
    URL="https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/mihomo-linux-amd64-${VERSION}.gz"
    echo "[*] 正在下载 Mihomo $VERSION..."
    wget -O "mihomo.gz" "$URL"
    gunzip -f "mihomo.gz"
    chmod +x "mihomo"
    mv "mihomo" /usr/local/bin/mihomo
fi

# 3. 创建目录
mkdir -p /etc/mihomo

# 4. 获取并智能转换订阅内容
SUBSCRIBE_URL=$1
CONFIG_PATH="/etc/mihomo/config.yaml"
TMP_DOWNLOAD="/etc/mihomo/download.tmp"

# 默认基础配置模板
cat > "$CONFIG_PATH" <<EOF
mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090
EOF

if [ -z "$SUBSCRIBE_URL" ]; then
    echo "[!] 未提供订阅链接，生成默认直连配置..."
    cat >> "$CONFIG_PATH" <<EOF
proxies: []
proxy-groups:
  - name: "Proxy"
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
EOF
else
    echo "[*] 正在智能转换订阅链接..."
    # 使用公开的 Sub-Converter API 进行实时转换
    # 转换器会将 V2Ray/SS 链接转为标准的 Clash YAML 格式
    CONVERT_API="https://sub.id9.cc/sub?target=clash&url=$(echo "$SUBSCRIBE_URL" | curl -s -o /dev/null -w "%{url_effective}" --get --data-urlencode "url=$SUBSCRIBE_URL" | sed 's/url=//')"
    
    # 尝试转换并下载
    curl -L -H "User-Agent: Clash" -o "$TMP_DOWNLOAD" "$CONVERT_API"

    # 检查转换后的内容
    if grep -q "proxies:" "$TMP_DOWNLOAD"; then
        echo "[+] 订阅转换成功！正在优化配置..."
        # 移除原内容中可能冲突的全局字段
        sed -i '/^port:/d' "$TMP_DOWNLOAD"
        sed -i '/^mixed-port:/d' "$TMP_DOWNLOAD"
        sed -i '/^allow-lan:/d' "$TMP_DOWNLOAD"
        sed -i '/^mode:/d' "$TMP_DOWNLOAD"
        sed -i '/^log-level:/d' "$TMP_DOWNLOAD"
        sed -i '/^external-controller:/d' "$TMP_DOWNLOAD"
        sed -i '/^ipv6:/d' "$TMP_DOWNLOAD"
        
        # 特别处理：如果原配置里已经定义了名为 DIRECT 的 proxy（会导致重名错误），将其删除
        # 这是为了解决日志中出现的 "proxy DIRECT is the duplicate name"
        sed -i '/- name: DIRECT/d' "$TMP_DOWNLOAD"
        sed -i '/- name: "DIRECT"/d' "$TMP_DOWNLOAD"
        
        cat "$TMP_DOWNLOAD" >> "$CONFIG_PATH"
    else
        echo "[!] 警告: 转换 API 返回内容不规范，尝试原始下载..."
        curl -L -H "User-Agent: Clash" -o "$TMP_DOWNLOAD" "$SUBSCRIBE_URL"
        if grep -q "proxies:" "$TMP_DOWNLOAD"; then
            echo "[*] 原始链接即为 Clash 格式，直接合并..."
            sed -i '/^port:/d' "$TMP_DOWNLOAD"
            sed -i '/^mixed-port:/d' "$TMP_DOWNLOAD"
            sed -i '/- name: DIRECT/d' "$TMP_DOWNLOAD"
            cat "$TMP_DOWNLOAD" >> "$CONFIG_PATH"
        else
            echo "[!] 错误: 无法获取有效的节点配置。请检查订阅链接是否正确。"
            cat >> "$CONFIG_PATH" <<EOF
proxies: []
proxy-groups:
  - name: "Proxy"
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
EOF
        fi
    fi
    rm -f "$TMP_DOWNLOAD"
fi

# 5. 设置 Systemd 服务
cat > /etc/systemd/system/mihomo.service <<EOF
[Unit]
Description=Mihomo Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 6. 启动并验证
echo "[*] 正在重启代理服务..."
systemctl daemon-reload
systemctl enable mihomo
systemctl restart mihomo

echo "[*] 等待 15 秒加载节点..."
sleep 15
echo "[*] 正在验证代理连接..."
RESPONSE=$(curl -x http://127.0.0.1:7890 https://www.google.com -I -s --connect-timeout 10)
if echo "$RESPONSE" | grep -q "200 OK"; then
    echo "[+] 成功！代理已全自动部署并正常运行。"
    echo "[*] 您现在可以运行注册脚本了："
    echo "    python openai_registrar_with_proxy.py --proxy http://127.0.0.1:7890"
else
    echo "[!] 验证失败。代理目前处于直连模式或节点不可用。"
    echo "[?] 建议：1. 检查您的订阅链接是否有流量；2. 运行 'journalctl -u mihomo -f' 查看日志。"
fi
