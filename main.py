import tls_client
import random
import sys
import time
import platform
import os
import hashlib
from datetime import datetime
from colorama import Fore
import string
import logging
import threading
import json
import requests
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
import warnings
from fake_useragent import UserAgent
warnings.filterwarnings('ignore')

Joined_Tokens = 0


def current_time():
    current_time = Fore.LIGHTMAGENTA_EX + f"[{datetime.now().strftime('%H:%M:%S')}]" + Style.RESET_ALL
    return current_time

if sys.version_info.minor < 10:
    print(f"{current_time()} {Fore.RED}[Security] Python 3.10 or higher is recommended. (The Bypass for joining will not work on 3.10+)")
    print(f"{current_time()} {Fore.RED}[Security] You are using Python {sys.version_info.major}.{sys.version_info.minor}")

banner = '''
 ▄▄▄██▀▀▀▒█████   ██▓ ███▄    █ ▓█████  ██▀███  
   ▒██  ▒██▒  ██▒▓██▒ ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
   ░██  ▒██░  ██▒▒██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
▓██▄██▓ ▒██   ██░░██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
 ▓███▒  ░ ████▓▒░░██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
 ▒▓▒▒░  ░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
 ▒ ░▒░    ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
 ░ ░ ░  ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░     ░░   ░ 
 ░   ░      ░ ░   ░           ░    ░  ░   ░       By @the_isadami | guns.lol/isadami '''
print(banner)
print("")  
print(f"{current_time()} {Fore.YELLOW} [INFO] | Loading...")
API_KEY = input(f"{current_time()} {Fore.YELLOW} [INFO] | Enter Your Hcoptcha API Key (hcoptcha.online): ")

def getchecksum():
    md5_hash = hashlib.md5()
    with open(''.join(sys.argv), "rb") as file:
        md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest



class DiscordJoinerPY:

    def __init__(self):
        self.client = tls_client.Session(
            client_identifier="chrome112",
            random_tls_extension_order=True
        )
        self.tokens = []
        self.proxies = []
        self.max_threads = os.cpu_count()
        self.num_threads = self.get_num_threads()
        self.check()

    def get_num_threads(self):
        while True:
            self.num_threads = input(f"{current_time()} {Fore.YELLOW} [INFO] | Enter The Number Of Threads To Use: ")
            if self.checknum(self.num_threads):
                return int(self.num_threads)
            else:
                print(f"{current_time()} {Fore.RED}[ERROR] | Please input a valid number!")

    def checknum(self, input_val):
        try:
            int(input_val)
            return True
        except ValueError:
            return False


    def headers(self, token: str, captcha_key=None, captcha_rqtoken=None):
        user_agent = UserAgent().random
        headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': user_agent,
            'x-context-properties': 'eyJsb2NhdGlvbiI6IkpvaW4gR3VpbGQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6IjExMDQzNzg1NDMwNzg2Mzc1OTEiLCJsb2NhdGlvbl9jaGFubmVsX2lkIjoiMTEwNzI4NDk3MTkwMDYzMzIzMCIsImxvY2F0aW9uX2NoYW5uZWxfdHlwZSI6MH0=',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-GB',
        }
        
        if captcha_key and captcha_rqtoken:
            headers['x-captcha-rqtoken'] = captcha_rqtoken
            headers['x-captcha-key'] = captcha_key

        try:
            xsp_value = self.build_xsp()
            if xsp_value:
                headers['x-super-properties'] = xsp_value
            else:
                logging.warning('Failed to build x-super-properties. Using default headers.')
        except Exception as e:
            logging.error(f'Error building x-super-properties: {e}')
        
        return headers

    def build_xsp(self):
        sec_ch_ua = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'

        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

        accept_language = "en-US,en;q=0.9"

        client_identifier = 'chrome_120'

        browser_version = '120.0.0.0'

        build_number = 301920

        data = {
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": user_agent,
            "browser_version": browser_version,
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": build_number,
            "client_event_source": None,
            "design_id": 0
        }
        return base64.b64encode(json.dumps(data, separators=(',', ':')).encode()).decode()

    def get_cookies(self):
        cookies = {}
        try:
            response = self.client.get('https://discord.com')
            for cookie in response.cookies:
                if cookie.name.startswith('__') and cookie.name.endswith('uid'):
                    cookies[cookie.name] = cookie.value
            return cookies
        
        except Exception as e:
            logging.info('Failed to obtain cookies ({})'.format(e))
            return cookies

    def accept_invite(self, token: str, invite: str, proxy_: str, retry=False, captcha_key=None, captcha_rqtoken=None):
        payload = {
            'session_id': ''.join(random.choice(string.ascii_lowercase) + random.choice(string.digits) for _ in range(16))
        }

        proxy = {
            "http": "http://{}".format(proxy_),
            "https": "https://{}".format(proxy_)
        } if proxy_ else None

        try:
            response = self.client.post(
                url='https://discord.com/api/v9/invites/{}'.format(invite),
                headers=self.headers(token=token, captcha_key=captcha_key, captcha_rqtoken=captcha_rqtoken),
                json=payload,
                cookies=self.get_cookies(),
                proxy=proxy
            )
            response_json = response.json()
            if response.status_code == 200:
                global Joined_Tokens
                Joined_Tokens += 1
                print(f"{current_time()} {Fore.GREEN} [SUCCESS] | Joined Token! {token} (discord.gg/{invite})")
            elif response.status_code == 401 and response_json['message'] == "401: Unauthorized":
                print(f"{current_time()} {Fore.RED} [ERROR] | Invalid Token! {token}")
            elif response.status_code == 403 and response_json['message'] == "You need to verify your account in order to perform this action.":
                print(f"{current_time()} {Fore.RED} [ERROR] | Locked Token! {token}")
            elif response.status_code == 400 and 'captcha_key' in response_json:
                print(f"{current_time()} {Fore.LIGHTYELLOW_EX} [ERROR] | Captcha Detected! {token}")
                print(f"{current_time()} {Fore.YELLOW} [INFO] | Solving Captcha... {token}")
                
                if not retry:
                    captcha_token, captcha_key = self.solve_hcaptcha(response_json["captcha_sitekey"], response_json["captcha_rqdata"])
                    if captcha_token:
                        self.accept_invite(token, invite, proxy_, retry=True, captcha_key=captcha_key, captcha_rqtoken=response_json['captcha_rqtoken'])
            elif response_json['message'] == "404: Not Found":
                print(f"{current_time()} {Fore.RED} [ERROR] | Unknown Invite! ({invite})")
            else:
                print(f"{current_time()} {Fore.RED} [ERROR] | Invalid Response! ({response_json})")
        except Exception as error:
            print(f"{current_time()} {Fore.RED} [ERROR] | {error}")

    def solve_hcaptcha(self, sitekey, rqdata):
        url = "https://discord.com/channels/@me"

        task_payload = {
            "task_type": "hcaptchaEnterprise",
            "api_key": API_KEY,
            "data": {
                "sitekey": sitekey,
                "url": url,
                "proxy": "qApyLuHskt1u55LvAdmicZSoE2WeJ5:4Lg0J2ttGsbAbjDC@residential.flashproxy.io:8082",
                "rqdata": rqdata
            }
        }

        try:
            response = requests.post("https://api.hcoptcha.online/api/createTask", json=task_payload)
            data = response.json()
            error = data.get("error")
            if error:
                message, unknown = data.get("message", "Unknown")
                print(f"{current_time()} {Fore.RED} [ERROR] | Failed To Solve Captcha | {message} - {unknown}")
                return None, None
            task_id = data["task_id"]
        except:
            print(f"{current_time()} {Fore.RED} [ERROR] | Failed To Solve Captcha")
            return None, None

        # Get Result
        payload = {
            "api_key": API_KEY,
            "task_id": task_id
        }
        while True:
            try:
                response = requests.post("https://api.hcoptcha.online/api/getTaskData", json=payload)
                data = response.json()
                if data.get("error"):
                    message, unknown = data.get("message", "Unknown")
                    print(f"{current_time()} {Fore.RED} [ERROR] | Failed Get Task Status | {message} - {unknown}")
                    return None, None
                task = data['task']
                if task["state"] == "completed":
                    print(f"{current_time()} {Fore.GREEN} [SUCCESS] | Solved Captcha:", task["captcha_key"][:40])
                    return True, task["captcha_key"]
                elif task['state'] == "error":
                    print(f"{current_time()} {Fore.RED} [ERROR] | Failed To Solve Captcha | {response.text}")
                    return None, None
                
                time.sleep(2)
            except Exception as e:
                print(f"{current_time()} {Fore.RED} [ERROR] | Failed Get Task Status | {e}")
                return None, None

    def check(self):
        folder_path = "input"
        file_path = os.path.join(folder_path, "tokens.txt")

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        if not os.path.exists(file_path):
            for file_name in ['proxies.txt', 'tokens.txt']:
                file_path = os.path.join(folder_path, file_name)
                if not os.path.exists(file_path):
                    with open(file_path, "w") as file:
                        file.write("Delete! proxies: ip:port:host:pass")

        self.load_tokens()

    def load_tokens(self):
        try:
            with open("./input/tokens.txt", "r") as file:
                for line in file:
                    content = line.replace("\n",  "")
                    self.tokens.append(content)

                self.start()
        except Exception as error:
            print(f"{current_time()} {Fore.RED} [ERROR] | {error}")

    def load_proxies(self):
        try:
            with open("./input/proxies.txt", "r") as file:
                for line in file:
                    content = line.replace("\n",  "")
                    self.proxies.append(content)
        except Exception as error:
            print(f"{current_time()} {Fore.RED} [ERROR] | {error}")

    def start(self):
        self.iterator = iter(self.proxies)
        self.load_proxies()
        
        invite = input(f"{current_time()} {Fore.YELLOW} [INFO] | discord.gg/")
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = []
            for token in self.tokens:
                try:
                    if self.proxies == [] or self.proxies[0] == "/// Remove this line":
                        proxy = None
                    else:
                        proxy = next(self.iterator, None)
                        if proxy is None:  
                            self.iterator = iter(self.proxies)
                            proxy = next(self.iterator, None)
                        print(f"{current_time()} {Fore.YELLOW} [INFO] | Loaded Proxy: {proxy}")

                    futures.append(executor.submit(self.accept_invite, token, invite, proxy))
                except Exception as error:
                    print(f"{current_time()} {Fore.RED} [ERROR] | Failed Loading Proxy: {proxy} ({error})")

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.info(f"{current_time()} {Fore.RED} [ERROR] | Thread error: {e}")
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"{current_time()} {Fore.YELLOW} [INFO] Done, Joined {Joined_Tokens} Tokens ({elapsed_time} Seconds)")
        os.system("pause")




if __name__ == '__main__':
    try:
        DiscordJoinerPY()
    except KeyboardInterrupt:
        pass 

    print("") 
    os.system("pause")  