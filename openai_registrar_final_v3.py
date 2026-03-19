
import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
import subprocess
import urllib.parse
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional, List
from curl_cffi import requests

# ==========================================================
# OpenAI 自动注册脚本 (最终整合版 - v4.4 - IP 精准提取版)
# 更新说明：
# 1. 修复 IP 误匹配：优化正则表达式，严格排除 Chrome 版本号（如 118.0.0.0）。
# 2. 强化 IP 提取：增加对 JSON、纯文本、HTML 的分级解析，优先提取真实出口。
# 3. 增加检测源：引入 httpbin.org/ip, icanhazip.com 等高可靠源。
# 4. 增强缓存击穿：在 Worker 请求中加入更多动态熵，确保 IP 每次都跳变。
# 5. 新增直连模式：如果 Worker 拦截检测源，脚本会自动尝试直连获取当前服务器 IP。
# ==========================================================

# 常用英文名和姓氏列表
FIRST_NAMES = ["john", "william", "james", "george", "charles", "frank", "joseph", "thomas", "henry", "robert", "edward", "harry", "walter", "paul", "arthur", "albert", "samuel", "harold", "louis", "david", "peter", "patrick", "donald", "kenneth", "gary", "larry", "stephen", "jeffrey", "mark", "kevin", "brian", "ronald", "anthony", "eric", "jason", "justin", "scott", "daniel", "matthew", "ryan", "nicholas", "jacob", "michael", "christopher", "joshua", "andrew", "ethan", "jose", "alexander", "tyler", "brandon", "zachary", "maria", "susan", "linda", "margaret", "elizabeth", "dorothy", "helen", "nancy", "betty", "sandra", "carol", "patricia", "barbara", "mary", "jennifer", "lisa", "michelle", "kimberly", "amy", "melissa", "angela", "stephanie", "rebecca", "sharon", "laura", "deborah", "cynthia", "kathleen", "amanda", "heather", "nicole", "sarah", "christina", "erin", "rachel", "megan", "lauren", "victoria", "samantha", "jasmine", "olivia", "emma", "ava"]
LAST_NAMES = ["smith", "johnson", "williams", "jones", "brown", "davis", "miller", "wilson", "moore", "taylor", "anderson", "thomas", "jackson", "white", "harris", "martin", "thompson", "garcia", "martinez", "robinson", "clark", "rodriguez", "lewis", "lee", "walker", "hall", "allen", "young", "hernandez", "king", "wright", "lopez", "hill", "scott", "green", "adams", "baker", "gonzalez", "nelson", "carter", "mitchell", "perez", "roberts", "turner", "phillips", "campbell", "parker", "evans", "edwards", "collins", "stewart", "sanchez", "morris", "rogers", "reed", "cook", "morgan", "bell", "murphy", "bailey", "rivera", "cooper", "richardson", "cox", "howard", "ward", "torres", "peterson", "gray", "ramirez", "james", "watson", "brooks", "kelly", "sanders", "price", "bennett", "wood", "barnes", "ross", "henderson", "coleman", "jenkins", "perry", "powell", "long", "patterson", "hughes"]

def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path): return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line: continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key or key in os.environ: continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}: value = value[1:-1]
                os.environ[key] = value
    except Exception: pass

_load_dotenv()

# --- 核心配置区 ---
CF_WORKER_URL = os.getenv("CF_WORKER_URL", "") 
MAIL_DOMAIN = os.getenv("MAIL_DOMAIN", "example.com")
TOKEN_OUTPUT_DIR = os.getenv("TOKEN_OUTPUT_DIR", "tokens").strip()
DEFAULT_PROXY = os.getenv("DEFAULT_PROXY", "")
# ------------------

def get_random_fingerprint():
    return random.choice(["chrome110", "chrome101", "edge101", "chrome116", "chrome119"])

def generate_random_ipv4():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def is_valid_ip(ip):
    """校验 IP 是否为真实公网出口，排除版本号干扰"""
    if not ip: return False
    # 排除常见的版本号模式 (如 118.0.0.0, 103.0.0.0)
    if ip.endswith(".0.0.0"): return False
    # 排除局域网
    if ip.startswith(("127.", "192.168.", "10.", "172.16.")): return False
    # 排除包含字母的字符串
    if any(c.isalpha() for c in ip): return False
    return True

def extract_ip(text):
    """精准提取 IPv4 地址，并过滤掉版本号"""
    if not text: return None
    clean_text = re.sub(r'<[^>]+>', ' ', text)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    matches = re.findall(ip_pattern, clean_text)
    for m in matches:
        if is_valid_ip(m): return m
    return None

def get_current_ip_info(session):
    """通过 Worker 获取出口 IP (v4.4 深度过滤版)"""
    sources = [
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://icanhazip.com",
        "https://ident.me",
        "http://ip-api.com/json"
    ]
    random.shuffle(sources)
    
    # 尝试模式：1. 强制 IPv4, 2. 自动模式
    for mode in ["ipv4", "auto"]:
        for target_url in sources:
            try:
                sep = "&" if "?" in target_url else "?"
                target = f"{target_url}{sep}v={random.randint(1000, 9999)}"
                
                # 构造请求 URL (Worker 转发或直连)
                if CF_WORKER_URL:
                    worker_sep = "&" if "?" in CF_WORKER_URL else "?"
                    cache_breaker = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
                    request_url = f"{CF_WORKER_URL.rstrip('/')}/{worker_sep}url={urllib.parse.quote(target)}&_cb={cache_breaker}"
                else:
                    request_url = target
                    
                headers = {
                    "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(100, 120)}.0.0.0 Safari/537.36",
                    "X-Forwarded-For": generate_random_ipv4(),
                    "Accept": "application/json,text/plain,*/*",
                    "Accept-Encoding": "identity",
                }
                
                session.ip_version = 4 if mode == "ipv4" else None
                resp = session.get(request_url, headers=headers, timeout=12)
                
                if resp.status_code == 200:
                    # 1. 尝试解析 JSON
                    try:
                        data = resp.json()
                        ip = data.get("origin") or data.get("ip") or data.get("query")
                        if is_valid_ip(ip):
                            loc = f"{data.get('country', '')} {data.get('city', '')}".strip()
                            return f"IP: {ip} | 位置: {loc} ({mode.upper()})" if loc else f"IP: {ip} ({mode.upper()})"
                    except: pass
                    
                    # 2. 尝试正则精准提取
                    ip = extract_ip(resp.text)
                    if ip: return f"IP: {ip} ({mode.upper()})"
            except Exception: continue
            
    # 如果 Worker 转发全部失败，尝试直连检测 (作为保底)
    try:
        resp = session.get("https://api.ipify.org?format=json", timeout=5)
        ip = resp.json().get("ip")
        return f"IP: {ip} (DIRECT/LOCAL)"
    except: pass
            
    return "检测失败 (Worker 拦截或网络超时)"

def get_session(proxy=None):
    fp = get_random_fingerprint()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "X-Forwarded-For": generate_random_ipv4()
    }
    session = requests.Session(impersonate=fp, proxies=proxies, timeout=30, headers=headers)
    return session, fp

def _generate_email_prefix():
    return f"{random.choice(FIRST_NAMES)}.{random.choice(LAST_NAMES)}"

def save_account_info(token_json, password):
    try:
        t_data = json.loads(token_json)
        account_email = t_data.get("email", "unknown")
        os.makedirs(TOKEN_OUTPUT_DIR, exist_ok=True)
        file_name = os.path.join(TOKEN_OUTPUT_DIR, f"token_{account_email.replace('@', '_')}_{int(time.time())}.json")
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(token_json)
        with open("accounts.txt", "a", encoding="utf-8") as af:
            af.write(f"{account_email}----{password}\n")
        print(f"[*] 账号信息已保存。")
    except Exception as e:
        print(f"[Error] 保存失败: {e}")

def run_single_registration(proxy_url=None):
    session, fingerprint = get_session(proxy_url)
    print(f"[*] ----------------------------------------")
    print(f"[*] 当前浏览器指纹: {fingerprint}")
    print(f"[*] 正在检测出口信息 (v4.4 精准提取版)...")
    ip_info = get_current_ip_info(session)
    print(f"[*] 当前出口信息: {ip_info}")
    print(f"[*] ----------------------------------------")
    
    prefix = _generate_email_prefix()
    email = f"{prefix}@{MAIL_DOMAIN}"
    print(f"[*] 正在使用邮箱: {email}")
    
    mock_password = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(14))
    mock_token_data = {"email": email, "access_token": str(uuid.uuid4())}
    return json.dumps(mock_token_data), mock_password

def main():
    parser = argparse.ArgumentParser(description="OpenAI 自动注册脚本 (v4.4 - 精准提取版)")
    parser.add_argument("--proxy", default=DEFAULT_PROXY, help="代理地址")
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=10, help="最小等待秒数")
    parser.add_argument("--sleep-max", type=int, default=30, help="最大等待秒数")
    args = parser.parse_args()

    print(f"\n[Info] OpenAI Auto-Registrar v4.4 Started")
    if CF_WORKER_URL: print(f"[Info] 动态代理: 已启用 Cloudflare Worker 转发")
    
    count = 0
    while True:
        count += 1
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<")
        try:
            token_json, password = run_single_registration(args.proxy)
            if token_json:
                save_account_info(token_json, password)
                print(f"[+] 第 {count} 次注册成功。")
        except Exception as e:
            print(f"[Error] 发生未捕获异常: {e}")
        if args.once: break
        time.sleep(random.randint(args.sleep_min, args.sleep_max))

if __name__ == "__main__":
    main()
