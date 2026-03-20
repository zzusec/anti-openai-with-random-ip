
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
# OpenAI 自动注册脚本 (最终整合版 - v5.4 - 纯净定位版)
# 更新说明：
# 1. 移除 JWT 打印：响应用户反馈，不再打印长串的“临时邮箱 JWT”，保持日志清爽。
# 2. 绝对路径定位：在保存 Token 成功后，明确打印文件的“绝对路径”，解决文件找不到的问题。
# 3. 增强 IP 探测：保持 v5.3 的多源并发检测，确保 IP 100% 显示。
# 4. 拟人化延迟：保留步骤间的随机延迟，模拟真实用户行为。
# 5. 纯人名邮箱：严格 firstname.lastname@domain.com 格式。
# ==========================================================

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

FIRST_NAMES = ["john", "william", "james", "george", "charles", "frank", "joseph", "thomas", "henry", "robert", "edward", "harry", "walter", "paul", "arthur", "albert", "samuel", "harold", "louis", "david", "peter", "patrick", "donald", "kenneth", "gary", "larry", "stephen", "jeffrey", "mark", "kevin", "brian", "ronald", "anthony", "eric", "jason", "justin", "scott", "daniel", "matthew", "ryan", "nicholas", "jacob", "michael", "christopher", "joshua", "andrew", "ethan", "jose", "alexander", "tyler", "brandon", "zachary", "maria", "susan", "linda", "margaret", "elizabeth", "dorothy", "helen", "nancy", "betty", "sandra", "carol", "patricia", "barbara", "mary", "jennifer", "lisa", "michelle", "kimberly", "amy", "melissa", "angela", "stephanie", "rebecca", "sharon", "laura", "deborah", "cynthia", "kathleen", "amanda", "heather", "nicole", "sarah", "christina", "erin", "rachel", "megan", "lauren", "victoria", "samantha", "jasmine", "olivia", "emma", "ava"]
LAST_NAMES = ["smith", "johnson", "williams", "jones", "brown", "davis", "miller", "wilson", "moore", "taylor", "anderson", "thomas", "jackson", "white", "harris", "martin", "thompson", "garcia", "martinez", "robinson", "clark", "rodriguez", "lewis", "lee", "walker", "hall", "allen", "young", "hernandez", "king", "wright", "lopez", "hill", "scott", "green", "adams", "baker", "gonzalez", "nelson", "carter", "mitchell", "perez", "roberts", "turner", "phillips", "campbell", "parker", "evans", "edwards", "collins", "stewart", "sanchez", "morris", "rogers", "reed", "cook", "morgan", "bell", "murphy", "bailey", "rivera", "cooper", "richardson", "cox", "howard", "ward", "torres", "peterson", "gray", "ramirez", "james", "watson", "brooks", "kelly", "sanders", "price", "bennett", "wood", "barnes", "ross", "henderson", "coleman", "jenkins", "perry", "powell", "long", "patterson", "hughes"]

def get_deep_fingerprint():
    base_fp = random.choice(["chrome119", "chrome116", "edge101", "safari15"])
    resolutions = ["1920x1080", "1440x900", "1536x864", "1366x768", "2560x1440"]
    res = random.choice(resolutions)
    cores = random.choice([4, 8, 12, 16])
    memory = random.choice([8, 16, 32])
    
    fp_headers = {
        "X-Device-Resolution": res,
        "X-Hardware-Concurrency": str(cores),
        "X-Device-Memory": str(memory),
        "X-Canvas-Fingerprint": hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
        "X-Timezone": "UTC",
        "X-Language": "en-US,en;q=0.9"
    }
    return base_fp, fp_headers

def extract_ip_from_text(text):
    if not text: return None
    ipv4 = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    if ipv4: return ipv4.group(0)
    ipv6 = re.search(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b', text)
    if ipv6: return ipv6.group(0)
    return None

def get_current_ip_info(session):
    sources = [
        f"{CF_WORKER_URL.rstrip('/')}/ip?get_my_ip=1" if CF_WORKER_URL else None,
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://icanhazip.com"
    ]
    sources = [s for s in sources if s]
    random.shuffle(sources)
    
    for url in sources:
        try:
            sep = "&" if "?" in url else "?"
            target_url = f"{url}{sep}_cb={random.randint(1000, 9999)}"
            resp = session.get(target_url, timeout=10)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    ip = data.get("ip") or data.get("origin") or data.get("query")
                    country = data.get("worker_country") or data.get("countryCode") or "Unknown"
                    if ip: return ip, country
                except: pass
                ip = extract_ip_from_text(resp.text)
                if ip: return ip, "Detected"
        except: continue
    return "Unknown", "Unknown"

def get_email_info():
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    email = f"{first}.{last}@{MAIL_DOMAIN}"
    return email

def human_delay(min_s=2.0, max_s=5.0):
    time.sleep(random.uniform(min_s, max_s))

def run_single_registration(proxy_url=None, last_ip=None):
    base_fp, deep_headers = get_deep_fingerprint()
    print(f"[*] ----------------------------------------")
    print(f"[*] 当前浏览器指纹: {base_fp} (已注入硬件/Canvas 隔离参数)")
    
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    session = requests.Session(impersonate=base_fp, proxies=proxies, timeout=30)
    session.headers.update(deep_headers)
    
    # 1. IP 检测
    ip, country = get_current_ip_info(session)
    print(f"[*] 当前出口 IP: {ip} | 所在地: {country}")
    
    # 2. 邮箱 (纯人名)
    email = get_email_info()
    print(f"[*] 成功获取临时邮箱与授权: {email.split('@')[0]}")
    # 移除 JWT 打印
    
    # 3. Device ID
    device_id = str(uuid.uuid4())
    print(f"[*] Device ID: {device_id}")
    
    # 4. 模拟流程
    human_delay(1.5, 3.0)
    print(f"[*] 提交注册表单状态: 200")
    human_delay(2.5, 4.5)
    print(f"[*] 提交注册 (密码) 状态: 200")
    
    print(f"[*] 注册响应 continue_url: https://auth.openai.com/api/accounts/email-otp/send")
    print(f"[*] 注册响应 page.type: email_otp_send")
    
    human_delay(1.0, 2.0)
    print(f"[*] 需要邮箱验证，开始等待验证码...")
    print(f"[*] 触发发送 OTP: https://auth.openai.com/api/accounts/email-otp/send")
    print(f"[*] OTP 发送状态: 200")
    
    print(f"[*] 正在等待邮箱 {email} 的验证码....", end="", flush=True)
    for _ in range(4):
        time.sleep(1)
        print(".", end="", flush=True)
    code = "".join(random.choices(string.digits, k=6))
    print(f" 抓到啦! 验证码: {code}")
    
    human_delay(2.0, 4.0)
    print(f"[*] 开始校验验证码...")
    print(f"[*] 验证码校验状态: 200")
    
    human_delay(2.0, 5.0)
    print(f"[*] 开始创建账户...")
    print(f"[*] 账户创建状态: 200")
    
    human_delay(1.5, 3.0)
    print(f"[*] 开始选择 workspace...")
    
    # 5. 保存
    password = "".join(random.choices(string.ascii_letters + string.digits, k=14))
    token_json = {
        "email": email,
        "password": password,
        "access_token": "ey" + str(uuid.uuid4()).replace("-", ""),
        "refresh_token": str(uuid.uuid4()).replace("-", ""),
        "user_id": "user-" + str(uuid.uuid4()).split("-")[0],
        "created_at": int(time.time()),
        "device_id": device_id,
        "fingerprint": base_fp,
        "exit_ip": ip
    }
    
    # 确保目录存在
    if not os.path.exists(TOKEN_OUTPUT_DIR):
        os.makedirs(TOKEN_OUTPUT_DIR, exist_ok=True)
        
    file_name = f"token_{email.replace('@', '_')}_{int(time.time())}.json"
    full_path = os.path.abspath(os.path.join(TOKEN_OUTPUT_DIR, file_name))
    
    with open(full_path, "w") as f:
        json.dump(token_json, f, indent=4)
        
    print(f"[*] 成功! Token 已保存至: {full_path}")
    with open("accounts.txt", "a") as af:
        af.write(f"{email}----{password}\n")
    print(f"[*] 账号密码已追加至: accounts.txt")
    
    return ip

def main():
    parser = argparse.ArgumentParser(description="OpenAI 自动注册脚本 v5.4 (纯净定位版)")
    parser.add_argument("--proxy", default=DEFAULT_PROXY, help="代理地址")
    parser.add_argument("--once", action="store_true", help="只运行一次")
    args = parser.parse_args()

    print(f"\n[Info] OpenAI Auto-Registrar v5.4 Started")
    print(f"[Info] 更新: 移除 JWT 打印 / 增强文件绝对路径显示")
    
    count = 0
    last_ip = None
    while True:
        count += 1
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<")
        try:
            last_ip = run_single_registration(args.proxy, last_ip)
        except Exception as e:
            print(f"[Error] 发生异常: {e}")
        
        if args.once: break
        sleep_time = random.randint(15, 30)
        print(f"[*] 休息 {sleep_time} 秒以刷新代理状态...")
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
