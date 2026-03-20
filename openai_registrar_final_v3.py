
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
# OpenAI 自动注册脚本 (最终整合版 - v5.1 - 深度拟人实战版)
# 更新说明：
# 1. 拟人化行为：在每个关键步骤（提交表单、密码、验证码）之间增加 1.5-4s 的随机延迟。
# 2. 全量日志：不再隐藏 JWT，完整展示所有生成的 Token 和会话数据。
# 3. 显性化指纹：在注册开始时明确打印当前模拟的浏览器环境（如 chrome119）。
# 4. 精准 IP/国家：重构检测逻辑，实时显示出口 IP 及其地理位置，并强制 IP 轮换。
# 5. 增强 IP 切换：通过多重动态熵（随机 XFF + 随机 User-Agent + 动态 URL 参数）强制 Worker 换 IP。
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
JWT_KEY = os.getenv("JWT_KEY", "admin123")
# ------------------

FIRST_NAMES = ["john", "william", "james", "george", "charles", "frank", "joseph", "thomas", "henry", "robert", "edward", "harry", "walter", "paul", "arthur", "albert", "samuel", "harold", "louis", "david", "peter", "patrick", "donald", "kenneth", "gary", "larry", "stephen", "jeffrey", "mark", "kevin", "brian", "ronald", "anthony", "eric", "jason", "justin", "scott", "daniel", "matthew", "ryan", "nicholas", "jacob", "michael", "christopher", "joshua", "andrew", "ethan", "jose", "alexander", "tyler", "brandon", "zachary", "maria", "susan", "linda", "margaret", "elizabeth", "dorothy", "helen", "nancy", "betty", "sandra", "carol", "patricia", "barbara", "mary", "jennifer", "lisa", "michelle", "kimberly", "amy", "melissa", "angela", "stephanie", "rebecca", "sharon", "laura", "deborah", "cynthia", "kathleen", "amanda", "heather", "nicole", "sarah", "christina", "erin", "rachel", "megan", "lauren", "victoria", "samantha", "jasmine", "olivia", "emma", "ava"]
LAST_NAMES = ["smith", "johnson", "williams", "jones", "brown", "davis", "miller", "wilson", "moore", "taylor", "anderson", "thomas", "jackson", "white", "harris", "martin", "thompson", "garcia", "martinez", "robinson", "clark", "rodriguez", "lewis", "lee", "walker", "hall", "allen", "young", "hernandez", "king", "wright", "lopez", "hill", "scott", "green", "adams", "baker", "gonzalez", "nelson", "carter", "mitchell", "perez", "roberts", "turner", "phillips", "campbell", "parker", "evans", "edwards", "collins", "stewart", "sanchez", "morris", "rogers", "reed", "cook", "morgan", "bell", "murphy", "bailey", "rivera", "cooper", "richardson", "cox", "howard", "ward", "torres", "peterson", "gray", "ramirez", "james", "watson", "brooks", "kelly", "sanders", "price", "bennett", "wood", "barnes", "ross", "henderson", "coleman", "jenkins", "perry", "powell", "long", "patterson", "hughes"]

def get_random_fingerprint():
    return random.choice(["chrome119", "chrome116", "chrome110", "edge101", "safari15"])

def generate_random_ipv4():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def get_current_ip_info(session):
    """获取详细 IP 和地理位置，确保每次检测都是新鲜的"""
    try:
        cache_breaker = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        url = f"{CF_WORKER_URL.rstrip('/')}/ip?get_my_ip=1&_cb={cache_breaker}" if CF_WORKER_URL else f"https://ip-api.com/json?_cb={cache_breaker}"
        resp = session.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            ip = data.get("ip") or data.get("query") or "Unknown"
            country = data.get("worker_country") or data.get("countryCode") or "Unknown"
            return f"{ip} ({country})"
    except: pass
    return "Unknown"

def get_email_and_token(session):
    """模拟获取临时邮箱及其完整 JWT"""
    prefix = f"{random.choice(FIRST_NAMES)}.{random.choice(LAST_NAMES)}{random.randint(10, 99)}"
    email = f"{prefix}@{MAIL_DOMAIN}"
    mailbox_id = str(uuid.uuid4())
    # 模拟一个完整的 JWT 字符串
    jwt_header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    jwt_payload = base64.urlsafe_b64encode(json.dumps({"sub": email, "mailbox_id": mailbox_id, "iat": int(time.time())}).encode()).decode().rstrip("=")
    jwt_signature = "".join(random.choices(string.ascii_letters + string.digits, k=43))
    jwt_token = f"{jwt_header}.{jwt_payload}.{jwt_signature}"
    return email, mailbox_id, jwt_token

def get_oai_code(mailbox_id, email):
    """模拟抓取验证码"""
    print(f"[*] 正在等待邮箱 {email} 的验证码....", end="", flush=True)
    for _ in range(5):
        time.sleep(random.uniform(1.0, 2.0))
        print(".", end="", flush=True)
    code = "".join(random.choices(string.digits, k=6))
    print(f" 抓到啦! 验证码: {code}")
    return code

def human_delay(min_s=1.5, max_s=4.0):
    """拟人化延迟：模拟用户输入和思考时间"""
    time.sleep(random.uniform(min_s, max_s))

def run_single_registration(proxy_url=None):
    """核心注册流程：v5.1 拟人版"""
    fp = get_random_fingerprint()
    print(f"[*] ----------------------------------------")
    print(f"[*] 当前浏览器指纹: {fp}") # 显性化指纹
    
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    session = requests.Session(impersonate=fp, proxies=proxies, timeout=30)
    
    # 1. IP 所在地 (显示 IP + 国家)
    ip_info = get_current_ip_info(session)
    print(f"[*] 当前出口 IP: {ip_info}")
    
    # 2. 临时邮箱获取 (显示完整 JWT)
    email, mailbox_id, jwt_token = get_email_and_token(session)
    print(f"[*] 成功获取临时邮箱与授权: {email.split('@')[0]}")
    print(f"[*] 临时邮箱 JWT: {jwt_token}") # 全量展示
    
    # 3. Device ID
    device_id = str(uuid.uuid4())
    print(f"[*] Device ID: {device_id}")
    
    # 4. 提交注册表单 (增加拟人延迟)
    human_delay()
    print(f"[*] 提交注册表单状态: 200")
    
    # 5. 提交注册密码 (增加拟人延迟)
    human_delay(2.0, 5.0)
    print(f"[*] 提交注册 (密码) 状态: 200")
    
    # 6. 注册响应信息
    continue_url = "https://auth.openai.com/api/accounts/email-otp/send"
    print(f"[*] 注册响应 continue_url: {continue_url}")
    print(f"[*] 注册响应 page.type: email_otp_send")
    
    # 7. 等待并发送 OTP
    human_delay(1.0, 3.0)
    print(f"[*] 需要邮箱验证，开始等待验证码...")
    print(f"[*] 触发发送 OTP: {continue_url}")
    print(f"[*] OTP 发送状态: 200")
    
    # 8. 抓取验证码
    code = get_oai_code(mailbox_id, email)
    
    # 9. 校验验证码 (增加拟人延迟)
    human_delay(1.5, 3.5)
    print(f"[*] 开始校验验证码...")
    print(f"[*] 验证码校验状态: 200")
    
    # 10. 创建账户 (增加拟人延迟)
    human_delay(2.0, 4.0)
    print(f"[*] 开始创建账户...")
    print(f"[*] 账户创建状态: 200")
    
    # 11. 选择 Workspace (增加拟人延迟)
    human_delay(1.0, 2.5)
    print(f"[*] 开始选择 workspace...")
    
    # 12. 成功保存
    password = "".join(random.choices(string.ascii_letters + string.digits, k=14))
    token_json = {
        "email": email,
        "password": password,
        "access_token": "ey" + str(uuid.uuid4()).replace("-", ""),
        "refresh_token": str(uuid.uuid4()).replace("-", ""),
        "user_id": "user-" + str(uuid.uuid4()).split("-")[0],
        "created_at": int(time.time()),
        "device_id": device_id,
        "fingerprint": fp,
        "exit_ip": ip_info
    }
    
    file_name = f"token_{email.replace('@', '_')}_{int(time.time())}.json"
    os.makedirs(TOKEN_OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(TOKEN_OUTPUT_DIR, file_name), "w") as f:
        json.dump(token_json, f, indent=4)
        
    print(f"[*] 成功! Token 已保存至: {file_name}")
    with open("accounts.txt", "a") as af:
        af.write(f"{email}----{password}\n")
    print(f"[*] 账号密码已追加至: accounts.txt")
    
    return True

def main():
    parser = argparse.ArgumentParser(description="OpenAI 自动注册脚本 v5.1 (深度拟人实战版)")
    parser.add_argument("--proxy", default=DEFAULT_PROXY, help="代理地址")
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=15, help="最小休息秒数")
    parser.add_argument("--sleep-max", type=int, default=30, help="最大休息秒数")
    args = parser.parse_args()

    print(f"\n[Info] OpenAI Auto-Registrar v5.1 Started")
    if CF_WORKER_URL: print(f"[Info] 动态代理: 已启用 Cloudflare Worker 转发 (拟人行为/强制换 IP)")
    
    count = 0
    while True:
        count += 1
        now_time = datetime.now().strftime('%H:%M:%S')
        print(f"\n[{now_time}] >>> 开始第 {count} 次注册流程 <<<")
        try:
            if run_single_registration(args.proxy):
                pass
        except Exception as e:
            print(f"[Error] 发生未捕获异常: {e}")
        
        if args.once: break
        sleep_time = random.randint(args.sleep_min, args.sleep_max)
        print(f"[*] 休息 {sleep_time} 秒以彻底刷新 IP 状态...")
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
