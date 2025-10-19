#!/usr/bin/python

version = "1.1"

import os
import shutil
import json
import re
import requests
import hmac
import random
import binascii
import urllib
import hashlib
import io
import urllib.parse
import time
import sys
import urllib.request
import zipfile
import webbrowser
import platform
import subprocess
import stat
import datetime
import threading
import termios
import tty
from urllib3.util.url import Url
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import init, Fore, Style
from PIL import Image

init(autoreset=True)

# --- Color Definitions ---
cg = Style.BRIGHT + Fore.GREEN
cgg = Style.DIM
cr = Fore.RED
crr = Style.BRIGHT + Fore.RED
cres = Style.RESET_ALL
cy = Style.BRIGHT + Fore.YELLOW
cb = Style.BRIGHT + Fore.CYAN
p_ = cg + "\n" + "_"*56 +"\n"

# --- Global Variables ---
session = requests.Session()
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"}
ssecurity = ""
nonce_val = ""
location_url = ""

def get_pip_command():
    if shutil.which("pip3"):
        return "pip3"
    elif shutil.which("pip"):
        return "pip"
    else:
        raise EnvironmentError("Could not find 'pip' or 'pip3' in your system!")

def install_dependencies():
    for lib in ['Cryptodome', 'urllib3', 'requests', 'colorama', 'Pillow']:
        try:
            __import__(lib) if lib != 'Pillow' else __import__('PIL')
        except ImportError:
            prefix = os.getenv("PREFIX", "")
            pip_cmd = get_pip_command()
            if lib == 'Cryptodome':
                if "com.termux" in prefix:
                    cmd = 'pkg install python-pycryptodomex'
                else:
                    cmd = f'{pip_cmd} install pycryptodomex'
            elif lib == 'Pillow':
                cmd = f'{pip_cmd} install Pillow'
            else:
                cmd = f'{pip_cmd} install {lib}'
            print(f"{cy}Installing {lib}...{cres}")
            os.system(cmd)

install_dependencies()

def check_for_update():
    try:
        response = requests.get("https://raw.githubusercontent.com/offici5l/MiUnlockTool/main/MiUnlockTool.py", timeout=3)
        response.raise_for_status()
        match = re.search(r'version\s*=\s*[\'"]([^\'"]+)[\'"]', response.text)
        if match:
            cloud_version = match.group(1)
            if version < cloud_version:
                print(f"\n{cy}New version {cloud_version} is available!{cres}")
    except Exception:
        pass

if '1' not in sys.argv:
    print(cgg + f"\n[V{version}] MiUnlockTool Linux{cres}")
    check_for_update()

print(p_)

# --- Safe Input Function with Keyboard Navigation Error Handling ---
def safe_input(prompt):
    """
    Safe input function that handles special characters from arrow keys
    and other control characters that might appear when typing in terminal.
    """
    print(prompt, end='', flush=True)
    
    # Save original terminal settings
    try:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
    except:
        # If unable to configure terminal (e.g., on Windows), use regular input
        return input()
    
    try:
        # Set terminal to raw mode
        tty.setraw(sys.stdin.fileno())
        
        input_text = ""
        while True:
            char = sys.stdin.read(1)
            
            # Handle special characters
            if char == '\x03':  # Ctrl+C
                print("^C")
                raise KeyboardInterrupt
            elif char == '\x1b':  # Start of escape sequence (like arrow keys)
                # Read next 2 characters to complete escape sequence
                next_chars = sys.stdin.read(2)
                if next_chars == '[A':  # Up arrow
                    continue
                elif next_chars == '[B':  # Down arrow
                    continue
                elif next_chars == '[C':  # Right arrow
                    continue
                elif next_chars == '[D':  # Left arrow
                    continue
                else:
                    continue  # Ignore other escape sequences
            elif char == '\r' or char == '\n':  # Enter
                print()  # Move to new line
                break
            elif ord(char) == 127:  # Backspace
                if input_text:
                    input_text = input_text[:-1]
                    # Delete character from display
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif char.isprintable():
                input_text += char
                sys.stdout.write(char)
                sys.stdout.flush()
        
        return input_text
    finally:
        # Restore original terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

# --- Fastboot/Platform-Tools Setup ---
s = platform.system()
if s == "Linux" and os.path.exists("/data/data/com.termux"):
    up = os.path.join(os.getenv("PREFIX", ""), "bin", "miunlock")
    try:
        if "fastboot version" not in os.popen("fastboot --version").read():
            raise Exception
    except:
        os.system("curl https://raw.githubusercontent.com/offici5l/MiUnlockTool/main/.install | bash")
        exit()
    if not os.path.exists(up):
        shutil.copy(__file__, up)
        os.system(f"chmod +x {up}")
        print(f"\nuse command: {cg}miunlock{cres}\n")
        exit()
    if not os.path.exists("/data/data/com.termux.api"):
        print("\ncom.termux.api app is not installed\nPlease install it first\n")
        exit()
    cmd = "fastboot"
else:
    if s == "Linux" and shutil.which("fastboot") is not None:
        cmd = "fastboot"
    else:
        dir = os.path.dirname(__file__)
        fp = os.path.join(dir, "platform-tools")
        if not os.path.exists(fp):
            print("\ndownloading platform-tools...\n")
            url = f"https://dl.google.com/android/repository/platform-tools-latest-{s}.zip"
            cd = os.path.join(os.path.dirname(__file__))
            fp = os.path.join(cd, os.path.basename(url))
            urllib.request.urlretrieve(url, fp)
            with zipfile.ZipFile(fp, 'r') as zip_ref:
                zip_ref.extractall(cd)
            os.remove(fp)
        pt = os.path.join(os.path.dirname(__file__), "platform-tools")
        cmd = os.path.join(pt, "fastboot")
        if s == "Linux" or s == "Darwin":
            st = os.stat(cmd)
            os.chmod(cmd, st.st_mode | stat.S_IEXEC)

# --- Data File Setup ---
config_dir = os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config"))
data_dir = os.path.join(config_dir, "miunlocktool")
os.makedirs(data_dir, exist_ok=True)
datafile = os.path.join(data_dir, "miunlockdata.json")

def save_data(data):
    with open(datafile, "w") as file:
        json.dump(data, file, indent=2)

def load_data():
    if os.path.exists(datafile):
        try:
            with open(datafile, "r") as file:
                return json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}

# --- New Login Logic ---
def get_browser_session():
    """Guides user to get session data from browser"""
    global ssecurity, nonce_val, location_url
    
    print(f"\n{cr}No valid session found or session has expired.{cres}")
    print(f"{cy}We need to create a new session using your browser.{cres}\n")
    
    data = load_data()
    if "user" not in data:
        data["user"] = safe_input("Xiaomi Account (Id/Email/Phone): ")
        save_data(data)
    if "pwd" not in data:
        data["pwd"] = safe_input("Password: ")
        save_data(data)
    
    # Fixed login URL as requested
    login_url = 'https://account.xiaomi.com/pass/serviceLogin?sid=unlockApi&checkSafeAddress=true&passive=false&hidden=false'
    
    print(f"\n{cg}Step 1: Login in Browser{cres}")
    print(f"Please follow these steps carefully:")
    print(f"1. Open your browser and visit the following link:")
    print(f"   {cy}{login_url}{cres}")
    print(f"2. Sign in to your Xiaomi account.")
    print(f"3. If there's a captcha, complete it.")
    print(f"4. After successful login, the page will be redirected.")
    print(f"5. Keep the browser tab open after login.")
    
    print(f"\n{cg}Step 2: Copy Cookies from Browser{cres}")
    print(f"Now we need to extract session data from your browser.")
    print(f"1. In the browser tab where you logged in, press F12 to open Developer Tools.")
    print(f"2. Go to the 'Network' tab.")
    print(f"3. Copy this link {login_url} to browser")
    print(f"4. Look for ServiceLogin?sid ")
    print(f"5. In the 'Headers' section, look for request header -> 'Cookie'.")
    print(f"6. Copy the ENTIRE cookie string and paste it below.\n")
    
    cookie_string = safe_input(f"{cgg}Paste the ENTIRE cookie string here:\n{cres}>> ").strip()
    
    if not cookie_string:
        print(f"{cr}Cookie string cannot be empty.{cres}")
        return False
        
    # Parse cookie string
    cookies = {}
    for item in cookie_string.split(';'):
        if '=' in item:
            key, value = item.strip().split('=', 1)
            cookies[key] = value
    
    # Extract required cookies
    required_cookies = ["passToken", "serviceToken", "userId", "deviceId"]
    missing_cookies = []
    
    for cookie in required_cookies:
        if cookie in cookies:
            data[cookie] = cookies[cookie]
        else:
            missing_cookies.append(cookie)
    
    if missing_cookies:
        print(f"{cr}Required cookies missing: {', '.join(missing_cookies)}{cres}")
        print(f"{cy}Make sure you copied the ENTIRE cookie string.{cres}")
        return False
        
    # Extract deviceId as wb_id
    data["wb_id"] = data.get("deviceId", "")
    
    # Get nonce and _ssign from redirect URL
    print(f"\n{cgg}Now we need the redirect URL to get nonce and _ssign values.{cres}")
    print(f"If you're still on the page after login, check the address bar.")
    print(f"If not, you can find it in the Network tab as a request to 'unlock.update.miui.com/sts'")
    redirect_url = safe_input(f"\n{cgg}Please copy the redirect URL or leave empty if not available:\n{cres}>> ").strip()
    
    if redirect_url and "unlock.update.miui.com/sts" in redirect_url:
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)
        data["nonce"] = params.get('nonce', [None])[0]
        data["_ssign"] = params.get('_ssign', [None])[0]
    else:
        # If no redirect URL, we'll try to get nonce and _ssign later
        data["nonce"] = None
        data["_ssign"] = None
    
    save_data(data)
    
    print(f"\n{cg}Step 3: Validating Session...{cres}")
    
    # Make sure all required data is present before continuing
    if not all([data.get("wb_id"), data.get("passToken"), data.get("serviceToken"), data.get("userId")]):
        print(f"{cr}Session data is incomplete. Cannot continue.{cres}")
        return False
    
    session.cookies.set('deviceId', data["wb_id"], domain='.account.xiaomi.com')
    session.cookies.set('passToken', data["passToken"], domain='.account.xiaomi.com')
    session.cookies.set('serviceToken', data["serviceToken"], domain='.xiaomi.com')
    session.cookies.set('userId', data["userId"], domain='.account.xiaomi.com')
    
    try:
        resp = session.get(
            "https://account.xiaomi.com/pass/serviceLogin?sid=unlockApi&_json=true&passive=true&hidden=true",
            headers=headers
        )
        result = json.loads(resp.text.replace("&&&START&&&", ""))
        
        if "ssecurity" in result and "location" in result:
            ssecurity = result["ssecurity"]
            nonce_val = result["nonce"]
            location_url = result["location"]
            
            # Update nonce and _ssign if they were missing
            if not data.get("nonce"):
                data["nonce"] = nonce_val
            if not data.get("_ssign"):
                # Try to extract _ssign from location URL
                parsed = urlparse(location_url)
                params = parse_qs(parsed.query)
                data["_ssign"] = params.get('_ssign', [None])[0]
            
            data["login"] = "ok"
            data["uid"] = result["userId"]
            save_data(data)
            
            print(f"{cg}✓ Session created and validated successfully!{cres}")
            return True
        else:
            print(f"{cr}Session validation failed. Server response:{cres}")
            print(json.dumps(result, indent=2))
            for key in ["wb_id", "passToken", "serviceToken", "userId", "nonce", "_ssign", "login"]:
                data.pop(key, None)
            save_data(data)
            return False
            
    except Exception as e:
        print(f"{cr}An error occurred during validation: {e}{cres}")
        return False

def validate_saved_session():
    """Checks if the saved session is still active"""
    global ssecurity, nonce_val, location_url
    
    data = load_data()
    required_keys = ["wb_id", "passToken", "serviceToken", "userId", "login"]
    
    if not all(key in data for key in required_keys) or data.get("login") != "ok":
        return False
        
    print(f"{cgg}Found saved session for uid: {data.get('uid')}. Validating...{cres}")
    
    session.cookies.set('deviceId', data["wb_id"], domain='.account.xiaomi.com')
    session.cookies.set('passToken', data["passToken"], domain='.account.xiaomi.com')
    session.cookies.set('serviceToken', data["serviceToken"], domain='.xiaomi.com')
    session.cookies.set('userId', data["userId"], domain='.account.xiaomi.com')
    
    try:
        resp = session.get(
            "https://account.xiaomi.com/pass/serviceLogin?sid=unlockApi&_json=true&passive=true&hidden=true",
            headers=headers
        )
        result = json.loads(resp.text.replace("&&&START&&&", ""))
        
        if "ssecurity" in result and "location" in result:
            ssecurity = result["ssecurity"]
            nonce_val = result["nonce"]
            location_url = result["location"]
            print(f"{cg}✓ Saved session is valid!{cres}")
            return True
        else:
            print(f"{cr}Saved session has expired or is invalid.{cres}")
            data["login"] = "invalid"
            save_data(data)
            return False
    except Exception as e:
        print(f"{cr}Error validating saved session: {e}{cres}")
        return False

def prepare_unlock_session():
    """
    Prepares the session for the unlock API by visiting the 'location' URL.
    This is a crucial step to get the correct serviceToken for the unlock server.
    """
    global ssecurity, nonce_val
    
    print(f"{cgg}Preparing session for unlock API...{cres}")
    if not ssecurity or not nonce_val or not location_url:
        print(f"{cr}Missing ssecurity, nonce, or location URL. Cannot prepare session.{cres}")
        return False

    try:
        client_sign = b64encode(hashlib.sha1(f"nonce={nonce_val}".encode("utf-8") + b"&" + ssecurity.encode("utf-8")).digest())
        full_location_url = location_url + "&clientSign=" + urllib.parse.quote_plus(client_sign)
        
        response = session.get(full_location_url, headers=headers)
        
        # The response to this request sets the correct cookies for the unlock server
        if 'serviceToken' in session.cookies:
            print(f"{cg}✓ Unlock session prepared successfully!{cres}")
            return True
        else:
            print(f"{cr}Failed to get serviceToken for unlock server.{cres}")
            print(f"Response status: {response.status_code}")
            print(f"Response headers: {response.headers}")
            return False
            
    except Exception as e:
        print(f"{cr}An error occurred while preparing unlock session: {e}{cres}")
        return False

# --- Main Execution Flow ---
if not validate_saved_session():
    if not get_browser_session():
        print(f"\n{crr}Failed to establish a valid session. Exiting.{cres}")
        exit(1)

# After getting a valid base session, prepare it for the unlock API
if not prepare_unlock_session():
    print(f"\n{crr}Failed to prepare session for unlock. Exiting.{cres}")
    exit(1)

data = load_data()
print(f"\n{cg}AccountInfo:{cres}\nid: {data['uid']}")

# --- Region and Unlock Server Setup ---
region = json.loads(requests.get("https://account.xiaomi.com/pass/user/login/region?", headers=headers, cookies={'passToken': data['passToken'], 'userId': str(data['userId']), 'deviceId': data['wb_id']}).text.replace("&&&START&&&", ""))['data']['region']
print(f"region: {region}")

region_config = json.loads(requests.get("https://account.xiaomi.com/pass2/config?key=register").text.replace("&&&START&&&", ""))['regionConfig']
for key, value in region_config.items():
    if 'region.codes' in value and region in value['region.codes']:
        region = value['name'].lower()
        break

for arg in sys.argv:
    if arg.lower() in ['global', 'india', 'russia', 'china', 'europe']:
        region = arg
        break

g = "unlock.update.intl.miui.com"
if region == "china": url = g.replace("intl.", "")
elif region == "india": url = f"in-{g}"
elif region == "russia": url = f"ru-{g}"
elif region == "europe": url = f"eu-{g}"
else: url = g

# --- Fastboot Device Detection ---
def read_stream(stream, output_list, process, restart_flag):
    try:
        for line in iter(stream.readline, ''):
            line = line.strip()
            output_list.append(line)
            if "No permission" in line or "< waiting for any device >" in line:
                process.terminate()
                print(f'\r< waiting for any device >', end='', flush=True)
                restart_flag[0] = True
                return
    finally:
        stream.close()

def CheckB(cmd, var_name, *fastboot_args):
    while True:
        process = subprocess.Popen([cmd] + list(fastboot_args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)
        stdout_lines, stderr_lines, restart_flag = [], [], [False]
        threading.Thread(target=read_stream, args=(process.stdout, stdout_lines, process, restart_flag)).start()
        threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, process, restart_flag)).start()
        try:
            process.wait()
        except subprocess.SubprocessError as e:
            print(f"Error while executing process: {e}")
            return None
        if restart_flag[0]:
            time.sleep(2)
            sys.stdout.write('\r\033[K')
            continue
        print(f"\rFetching '{var_name}' — please wait...", end='', flush=True)
        lines = [line.split(f"{var_name}:")[1].strip() for line in stderr_lines + stdout_lines if f"{var_name}:" in line]
        if len(lines) > 1: return "".join(lines)
        return lines[0] if lines else None

[print(char, end='', flush=True) or time.sleep(0.01) for char in "\nEnsure you're in Bootloader mode (fastboot mode)\n\n"]

unlocked, product, SoC, token = None, None, None, None
while unlocked is None or product is None or SoC is None or token is None:
    if unlocked is None: unlocked = CheckB(cmd, "unlocked", "getvar", "unlocked")
    if product is None: product = CheckB(cmd, "product", "getvar", "product")
    if token is None:
        token = CheckB(cmd, "token", "oem", "get_token")
        if token: SoC = "Mediatek"
        else:
            token = CheckB(cmd, "token", "getvar", "token")
            if token: SoC = "Qualcomm"

sys.stdout.write('\r\033[K')
print(f"\n{cg}DeviceInfo:{cres}\nunlocked: {unlocked}\nSoC: {SoC}\nproduct: {product}\ntoken: {token}\n")

# --- Unlock Data Preparation ---
class RetrieveEncryptData:
    def add_nonce(self):
        try:
            r = RetrieveEncryptData("/api/v2/nonce", {"r":''.join(random.choices(list("abcdefghijklmnopqrstuvwxyz"), k=16)), "sid":"miui_unlocktool_client"}).run()
            self.params[b"nonce"] = r["nonce"].encode("utf-8")
            self.params[b"sid"] = b"miui_unlocktool_client"
            return self
        except Exception as e:
            print(f"{cr}Failed to get nonce: {e}{cres}")
            raise

    def __init__(self, path, params):
        self.path = path
        self.params = {k.encode("utf-8"): v.encode("utf-8") if isinstance(v, str) else b64encode(json.dumps(v).encode("utf-8")) if not isinstance(v, bytes) else v for k, v in params.items()}

    def getp(self, sep):
        return b'POST'+sep+self.path.encode("utf-8")+sep+b"&".join([k+b"="+v for k,v in self.params.items()])

    def run(self):
        self.params[b"sign"] = binascii.hexlify(hmac.digest(b'2tBeoEyJTunmWUGq7bQH2Abn0k2NhhurOaqBfyxCuLVgn4AVj7swcawe53uDUno', self.getp(b"\n"), "sha1"))
        
        # Encrypt parameters
        for k, v in self.params.items():
            self.params[k] = b64encode(AES.new(b64decode(ssecurity), AES.MODE_CBC, b"0102030405060708").encrypt(v + (16 - len(v) % 16) * bytes([16 - len(v) % 16])))
        
        self.params[b"signature"] = b64encode(hashlib.sha1(self.getp(b"&")+b"&"+ssecurity.encode("utf-8")).digest())
        
        try:
            response_text = session.post(Url(scheme="https", host=url, path=self.path).url, data=self.params, headers=headers, cookies=session.cookies.get_dict()).text
            
            # Check if response is a plain error message
            if not response_text or response_text.startswith('{'):
                print(f"{cr}Server returned a plain text error:{cres}")
                print(response_text)
                raise Exception("Server error during API call.")

            decrypted_bytes = AES.new(b64decode(ssecurity), AES.MODE_CBC, b"0102030405060708").decrypt(b64decode(response_text))
            
            # The lambda function removes PKCS#7 padding
            padding_len = decrypted_bytes[-1]
            if not (1 <= padding_len <= 16):
                 raise ValueError("Invalid padding")
            decrypted_data = decrypted_bytes[:-padding_len]
            
            final_decoded_text = b64decode(decrypted_data)
            return json.loads(final_decoded_text)
            
        except (binascii.Error, ValueError, json.JSONDecodeError, IndexError) as e:
            print(f"{cr}Failed to decrypt or parse server response.{cres}")
            print(f"Error: {e}")
            print(f"Raw response from server: {response_text[:200]}...") # Print first 200 chars
            raise
        except Exception as e:
            print(f"{cr}An unexpected error occurred in RetrieveEncryptData.run(): {e}{cres}")
            raise

print(p_)

c = RetrieveEncryptData("/api/v2/unlock/device/clear", {"data":{"product":product}}).add_nonce().run()
cleanOrNot = c['cleanOrNot']
if cleanOrNot == 1: print(f"\n{crr}This device clears user data when it is unlocked{cres}\n")
elif cleanOrNot == -1: print(f"\n{cg}Unlocking the device does not clear user data{cres}\n") 
print(Style.BRIGHT + Fore.CYAN + c['notice'] + cres)

choice = safe_input(f"\n{cg}Press Enter to Unlock\n{cgg}( or type q and press Enter to quit){cres}")
if choice.lower() == 'q':
    print("\nExiting...\n")
    exit() 

print(p_)

r = RetrieveEncryptData("/api/v3/ahaUnlock", {"appId":"1", "data":{"clientId":"2", "clientVersion":"7.6.727.43", "language":"en", "operate":"unlock", "pcId":hashlib.md5(data['wb_id'].encode("utf-8")).hexdigest(), "product":product, "region":"","deviceInfo":{"boardVersion":"","product":product, "socId":"","deviceName":""}, "deviceToken":token}}).add_nonce().run()

if "code" in r and r["code"] == 0:
    ed = io.BytesIO(bytes.fromhex(r["encryptData"]))
    with open("encryptData", "wb") as edfile:
        edfile.write(ed.getvalue())
    CheckB(cmd, "serialno", "getvar", "serialno")
    sys.stdout.write('\r\033[K')
    try:
        result_stage = subprocess.run([cmd, "stage", "encryptData"], check=True, capture_output=True, text=True)
        result_unlock = subprocess.run([cmd, "oem", "unlock"], check=True, capture_output=True, text=True)
        print(f"\n{cg}Unlock successful{cgg}\n")
        os.remove("encryptData")
    except subprocess.CalledProcessError as e:
        print("Error message:", e.stderr)
elif "descEN" in r:
    print(f"\ncode {r['code']}\n\n{r['descEN']}")
    if r["code"] == 20036:
        print("\nYou can unlock (repeat this process) on:", (datetime.datetime.now().replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=r["data"]["waitHour"])).strftime("%Y-%m-%d %H:%M"))
    else:
        print(f"{cgg}\nhttps://offici5l.github.io/MiUnlockTool/error_codes\n{cres}")
else:
    for key, value in r.items():
        print(f"\n{key}: {value}")

print(p_)

if not os.path.exists("/data/data/com.termux"):
    input("\nPress Enter to exit ...")