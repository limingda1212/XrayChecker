import argparse
import tempfile
import sys
import os
import shutil
import logging
import random
import time
import json
import socket
import subprocess
import platform
import base64
import requests
import psutil
import re
import stat
from datetime import datetime
from http.client import BadStatusLine, RemoteDisconnected
import urllib.parse
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace
from threading import Lock, Semaphore

from data.default_datas import *



# --- REALITY / FLOW 验证 ---
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")  # base64url publicKey
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")  # shortId (hex, 最多32字符)

FLOW_ALIASES = {
    "xtls-rprx-visi": "xtls-rprx-vision",
}

FLOW_ALLOWED = {
    "",
    "xtls-rprx-vision",
}
# ------------------------------



# ------------ 加密 ------------
# Xray Shadowsocks：官方支持的加密方法（更新于2026-01-05）
SS_ALLOWED_METHODS = {
    # Shadowsocks 2022
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",

    # AEAD (旧版)
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",

    # 无加密
    "none",
    "plain",
}
# 不支持的旧方法（仅供参考）：
# aes-128-cfb, aes-192-cfb, aes-256-cfb, aes-128-ctr, aes-256-ctr,
# camellia-128-cfb, camellia-256-cfb, rc4-md5, bf-cfb 等
# ------------------------------



# ------------------------------
# 禁用 InsecureRequestWarning 来忽略 SSL 证书验证警告。
# 实现抑制基于此库的requests等库的警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ------------------------------



# ---------- 聚合器模块 ----------
try:
    import aggregator

    AGGREGATOR_AVAILABLE = True
except ImportError:
    AGGREGATOR_AVAILABLE = False
# ------------------------------



# ------------ 设置 ------------
# 配置文件
CONFIG_FILE = "./data/config.json"
SOURCES_FILE = "./data/sources.json"

# 加载sources.json，若不存在则创建默认
def load_sources():
    """加载sources.json，若不存在则创建默认"""
    if os.path.exists(SOURCES_FILE):
        try:
            with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print(f"加载 {SOURCES_FILE} 时出错：{e}")

    # 没有代理源就创建,代理源示例
    try:
        with open(SOURCES_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_SOURCES_DATA, f, indent=4)
        print(f"已创建默认 {SOURCES_FILE}")
    except Exception as e:
        print(f"创建 {SOURCES_FILE} 时出错：{e}")

    return DEFAULT_SOURCES_DATA

# 加载config.json，若不存在则创建默认
def load_config():
    """加载config.json，若不存在则创建默认"""
    loaded_sources = load_sources()

    if not os.path.exists(CONFIG_FILE):
        try:
            config_to_write = DEFAULT_CONFIG.copy()
            del config_to_write["sources"]

            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_to_write, f, indent=4)
            print(f"已创建默认 {CONFIG_FILE}")
        except:
            pass
        cfg = DEFAULT_CONFIG.copy()
        cfg["sources"] = loaded_sources
        return cfg

    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            user_config = json.load(f)

        config = DEFAULT_CONFIG.copy()
        config.update(user_config)

        config["sources"] = loaded_sources

        has_new_keys = False
        keys_to_check = [k for k in DEFAULT_CONFIG.keys() if k != "sources"]

        for key in keys_to_check:
            if key not in user_config:
                has_new_keys = True
                break

        if has_new_keys:
            try:
                print(f">> 更新 {CONFIG_FILE}：添加新参数...")
                save_cfg = config.copy()
                if "sources" in save_cfg: del save_cfg["sources"]

                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(save_cfg, f, indent=4)
            except Exception as e:
                print(f"警告：无法更新配置文件：{e}")

        return config
    except Exception as e:
        print(f"加载配置文件时出错：{e}")
        cfg = DEFAULT_CONFIG.copy()
        cfg["sources"] = loaded_sources
        return cfg

# 加载设置
GLOBAL_CFG = load_config()
# ------------------------------



# ------------ 其他 -------------
# 协议提示
PROTO_HINTS = ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "ss://")

# BASE64字符
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

# 正则表达式公用提取模板
URL_FINDER = re.compile(
    r'(?:vless|vmess|trojan|hysteria2|hy2)://[^\s"\'<>]+|(?<![A-Za-z0-9+])ss://[^\s"\'<>]+',
    re.IGNORECASE
)
# ------------------------------



# ------- rich终端样式定义 -------
# rich库向终端写入富文本（带颜色和样式），以及显示高级内容
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.prompt import Prompt, Confirm
    from rich.logging import RichHandler
    from rich import box
    from rich.text import Text

    console = Console()
except ImportError:
    print("请安装rich库：pip install rich")
    sys.exit(1)

class Fore:
    """前景色样式标签"""
    CYAN = "[cyan]"
    GREEN = "[green]"
    RED = "[red]"
    YELLOW = "[yellow]"
    MAGENTA = "[magenta]"
    BLUE = "[blue]"
    WHITE = "[white]"
    LIGHTBLACK_EX = "[dim]"
    LIGHTGREEN_EX = "[bold green]"
    LIGHTRED_EX = "[bold red]"
    RESET = "[/]"

class Style:
    BRIGHT = "[bold]"
    RESET_ALL = "[/]"
# ------------------------------



# 规范化URL：移除BOM、不可见字符
def clean_url(url):
    """
    规范化URL：移除BOM、不可见字符，
    解码HTML实体（&amp; → &）和URL编码（%26 → &）。
    进行两次解码以处理嵌套转义（如 &amp%3B 或 %26amp%3B）。
    """
    url = url.strip()
    url = url.replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')

    url = html.unescape(url)
    url = urllib.parse.unquote(url)

    url = html.unescape(url)
    url = urllib.parse.unquote(url)

    return url


# 单元测试,检查VLESS/REALITY参数解码是否正确。
def _self_test_clean_url():
    """
    clean_url()的单元测试：检查VLESS/REALITY参数解码是否正确。
    运行方式：python v2rayChecker.py --self-test

    Returns:
        bool: 所有测试通过返回True
    """
    test_cases = [
        # (输入字符串, 清理后预期包含的子串)
        ("vless://test@host:443?security=reality&amp;pbk=ABC&amp;sid=123", "security=reality&pbk=ABC&sid=123"),
        ("vless://test@host:443?security=reality&amp%3Bpbk=ABC", "security=reality&pbk=ABC"),
        ("vless://test@host:443?security=reality%26amp%3Bpbk=ABC", "security=reality&pbk=ABC"),
        ("vless://test@host:443?flow=xtls-rprx-vision&type=tcp", "flow=xtls-rprx-vision&type=tcp"),
    ]

    passed = 0
    for raw, expected in test_cases:
        cleaned = clean_url(raw)
        if "?" in cleaned:
            query = cleaned.split("?", 1)[1]
            params = urllib.parse.parse_qs(query)
            has_separate_keys = "security" in params or "pbk" in params or "flow" in params
            if has_separate_keys or expected in cleaned:
                passed += 1
                safe_print(f"[green]✓ 通过[/]：{raw[:60]}...")
            else:
                safe_print(f"[red]✗ 失败[/]：{raw[:60]}...")
                safe_print(f"[dim]  得到：{cleaned[:100]}[/]")
        else:
            passed += 1

    safe_print(f"\n[bold]自测：{passed}/{len(test_cases)} 通过[/]")
    return passed == len(test_cases)


# 智能日志器，同时输出到控制台和文件
class SmartLogger:
    """智能日志器，同时输出到控制台和文件"""

    def __init__(self, filename="./data/checker_history.log"):
        self.filename = filename
        self.lock = Lock()
        try:
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(
                    f"\n{'-' * 30} 新会话 "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {'-' * 30}\n"
                )
        except Exception as e:
            console.print(f"[bold red]创建日志文件失败：{e}[/]")

    def log(self, msg, style=None):
        with self.lock:
            console.print(msg, style=style, highlight=False)

            try:
                text_obj = Text.from_markup(str(msg))
                clean_msg = text_obj.plain.strip()

                if clean_msg:
                    timestamp = datetime.now().strftime("[%H:%M:%S]")
                    log_line = f"{timestamp} {clean_msg}\n"

                    with open(self.filename, 'a', encoding='utf-8') as f:
                        f.write(log_line)
            except Exception:
                pass

MAIN_LOGGER = SmartLogger("./data/checker_history.log")
logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO, datefmt='%H:%M:%S')

# 安全打印到控制台并写入日志
def safe_print(msg):
    """安全打印到控制台并写入日志"""
    MAIN_LOGGER.log(msg)


TEMP_DIR = tempfile.mkdtemp()
OS_SYSTEM = platform.system().lower()
CORE_PATH = ""
CTRL_C = False


# ------------------------------ 核心功能 ------------------------------
# 检查本地端口是否已被占用
def is_port_in_use(port):
    """检查本地端口是否已被占用"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False

# 未用 - 等待核心启动（端口监听）
def wait_for_core_start(port, max_wait):
    """等待核心启动（端口监听）"""
    start_time = time.time()
    while time.time() - start_time < max_wait:
        if is_port_in_use(port):
            return True
        time.sleep(0.05)
    return False

# 将列表分割成n个子列表
def split_list(lst, n):
    """将列表分割成n个子列表"""
    if n <= 0: return []
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

# 尝试解码可能为base64的文本，提取其中的代理链接
def try_decode_base64(text):
    """尝试解码可能为base64的文本，提取其中的代理链接"""
    raw = text.strip()
    if not raw:
        return raw

    if any(marker in raw for marker in PROTO_HINTS):
        return raw

    compact = re.sub(r'\s+', '', raw)
    if not compact or not set(compact) <= BASE64_CHARS:
        return raw

    missing_padding = len(compact) % 4
    if missing_padding:
        compact += "=" * (4 - missing_padding)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(compact).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if any(marker in decoded for marker in PROTO_HINTS):
            return decoded
    return raw

# 生成给定文本的可能变体（原始/解码后）
def _payload_variants(blob):
    """生成给定文本的可能变体（原始/解码后）"""
    clean_blob = blob.strip()
    if not clean_blob:
        return set()

    variants = {clean_blob}

    decoded_blob = try_decode_base64(clean_blob)

    if decoded_blob and decoded_blob != clean_blob:
        variants.add(decoded_blob)
    for line in clean_blob.splitlines():
        line = line.strip()
        if not line:
            continue
        maybe_decoded = try_decode_base64(line)
        if maybe_decoded and maybe_decoded != line:
            variants.add(maybe_decoded)

    return variants

# 从文本中提取所有代理链接
def parse_content(text):
    """从文本中提取所有代理链接"""
    unique_links = set()
    raw_hits = 0

    for payload in _payload_variants(text):
        matches = URL_FINDER.findall(payload)
        raw_hits += len(matches)
        for item in matches:
            cleaned = clean_url(item.rstrip(';,)]}'))
            if cleaned and len(cleaned) > 15:
                unique_links.add(cleaned)

    return list(unique_links), raw_hits or len(unique_links)

# 下载URL内容并提取代理链接
def fetch_url(url):
    """下载URL内容并提取代理链接"""
    try:
        safe_print(f"{Fore.CYAN}>> 正在下载URL：{url}{Style.RESET_ALL}")
        resp = requests.get(url, timeout=15, verify=False)
        if resp.status_code == 200:
            links, count = parse_content(resp.text)
            return links
        else:
            safe_print(f"{Fore.RED}>> 下载失败：HTTP {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        safe_print(f"{Fore.RED}>> URL错误：{e}{Style.RESET_ALL}")
    return []

# 解析VLESS链接
def parse_vless(url):
    """解析VLESS链接"""
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None

        main_part = url
        tag = "vless"
        if '#' in url:
            parts = url.split('#', 1)
            main_part = parts[0]
            tag = urllib.parse.unquote(parts[1]).strip()

        if '¬' in main_part: main_part = main_part.split('¬')[0]

        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main_part)
        if not match: return None

        uuid = match.group(1).strip()
        address = match.group(2).strip()
        port = int(match.group(3))

        params = {}
        if '?' in main_part:
            query = main_part.split('?', 1)[1]
            query = re.split(r'[^\w\-\=\&\%(\.)]', query)[0]
            params = urllib.parse.parse_qs(query)

        def get_p(key, default=""):
            val = params.get(key, [default])
            v = val[0].strip()
            return re.sub(r'[^\x20-\x7E]', '', v) if v else default

        net_type = get_p("type", "tcp").lower()
        net_type = re.sub(r"[^a-z0-9]", "", net_type)
        if net_type in ["http", "h2"]:
            net_type = "xhttp"
        elif net_type == "httpupgrade":
            net_type = "xhttp"

        flow = get_p("flow", "").lower().strip()
        flow = FLOW_ALIASES.get(flow, flow)

        if flow in ["none", "xtls-rprx-direct", "xtls-rprx-origin",
                    "xtls-rprx-splice", "xtls-rprx-direct-udp443"]:
            flow = ""

        if flow not in FLOW_ALLOWED:
            flow = ""

        security = get_p("security", "none").lower()
        if security not in ["tls", "reality", "none", "auto"]:
            security = "none"

        if flow and security not in ["tls", "reality"]:
            if GLOBAL_CFG.get("debug_mode"):
                safe_print(f"[yellow][调试] 丢弃 flow={flow}，security={security}（flow需要tls/reality）[/]")
            flow = ""

        pbk = get_p("pbk", "")
        # 验证：严格检查X25519公钥（base64url → 32字节）
        if pbk:
            try:
                missing_padding = len(pbk) % 4
                pbk_padded = pbk + '=' * (4 - missing_padding) if missing_padding else pbk

                decoded = base64.urlsafe_b64decode(pbk_padded)

                if len(decoded) != 32:
                    if GLOBAL_CFG.get("debug_mode"):
                        safe_print(f"[yellow][调试] 丢弃无效PBK（长度{len(decoded)}!=32）：{pbk}[/]")
                    pbk = ""
            except Exception as e:
                if GLOBAL_CFG.get("debug_mode"):
                    safe_print(f"[yellow][调试] 丢弃无效PBK（解码错误）：{pbk} ({e})[/]")
                pbk = ""

        if pbk and security == "tls":
            security = "reality"

        sid = get_p("sid", "")
        # 验证ShortId：必须是hex且偶数长度
        if sid:
            sid = re.sub(r"[^0-9a-fA-F]", "", sid)
            if len(sid) % 2 != 0:
                if GLOBAL_CFG.get("debug_mode"):
                    safe_print(f"[yellow][调试] 修正奇数SID长度 {len(sid)}：{sid} -> 0{sid}[/]")
                sid = "0" + sid

            if not REALITY_SID_RE.match(sid):
                sid = ""

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": address,
            "port": port,
            "encryption": get_p("encryption", "none"),
            "type": net_type,
            "security": security,
            "path": urllib.parse.unquote(get_p("path", "")),
            "host": get_p("host", ""),
            "sni": get_p("sni", ""),
            "fp": get_p("fp", ""),
            "alpn": get_p("alpn", ""),
            "serviceName": get_p("serviceName", ""),
            "mode": get_p("mode", ""),
            "pbk": pbk,
            "sid": sid,
            "flow": flow,
            "headerType": get_p("headerType", ""),
            "tag": tag
        }
    except Exception as e:
        return None

# 解析VMess链接
def parse_vmess(url):
    """解析VMess链接"""
    try:
        url = clean_url(url)
        if not url.startswith("vmess://"): return None

        if '@' in url:
            if '#' in url:
                main_part, tag = url.split('#', 1)
                tag = urllib.parse.unquote(tag).strip()
            else:
                main_part = url
                tag = "vmess"

            match = re.search(r'vmess://([^@]+)@([^:]+):(\d+)', main_part)
            if match:
                uuid = match.group(1).strip()
                address = match.group(2).strip()
                port = int(match.group(3))

                params = {}
                if '?' in main_part:
                    query = main_part.split('?', 1)[1]
                    params = urllib.parse.parse_qs(query)

                def get_p(key, default=""):
                    val = params.get(key, [default])
                    return val[0] if val else default

                try:
                    aid = int(get_p("aid", "0"))
                except:
                    aid = 0

                raw_path = get_p("path", "")
                final_path = urllib.parse.unquote(raw_path)

                net_type = get_p("type", "tcp").lower()
                if net_type in ["http", "h2", "httpupgrade"]:
                    net_type = "xhttp"

                return {
                    "protocol": "vmess",
                    "uuid": uuid,
                    "address": address,
                    "port": int(port),
                    "type": net_type,
                    "security": get_p("security", "none"),
                    "path": final_path,
                    "host": get_p("host", ""),
                    "sni": get_p("sni", ""),
                    "fp": get_p("fp", ""),
                    "alpn": get_p("alpn", ""),
                    "serviceName": get_p("serviceName", ""),
                    "aid": aid,
                    "scy": get_p("encryption", "auto"),
                    "tag": tag
                }

        content = url[8:]
        if '#' in content:
            b64, tag = content.rsplit('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            b64 = content
            tag = "vmess"

        missing_padding = len(b64) % 4
        if missing_padding: b64 += '=' * (4 - missing_padding)

        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)

            net_type = data.get("net", "tcp")
            if net_type in ["http", "h2", "httpupgrade"]:
                net_type = "xhttp"

            return {
                "protocol": "vmess",
                "uuid": data.get("id"),
                "address": data.get("add"),
                "port": int(data.get("port", 0)),
                "aid": int(data.get("aid", 0)),
                "type": net_type,
                "security": data.get("tls", "") if data.get("tls") else "none",
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "sni": data.get("sni", ""),
                "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""),
                "scy": data.get("scy", "auto"),
                "tag": data.get("ps", tag)
            }
        except:
            pass

        return None
    except Exception as e:
        safe_print(f"{Fore.RED}[VMESS错误] {e}{Style.RESET_ALL}")
        return None

# 解析Trojan链接
def parse_trojan(url):
    """解析Trojan链接"""
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "trojan"

        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            return None

        return {
            "protocol": "trojan",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": int(parsed.port),
            "security": params.get("security", ["tls"])[0],
            "sni": params.get("sni", [""])[0] or params.get("peer", [""])[0],
            "type": params.get("type", ["tcp"])[0],
            "path": params.get("path", [""])[0],
            "host": params.get("host", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except:
        return None

# 解析Shadowsocks链接
def parse_ss(url):
    """解析Shadowsocks链接"""
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "ss"

        parsed = urllib.parse.urlparse(url_clean)

        if '@' in url_clean:
            userinfo = parsed.username
            try:
                if userinfo and ':' not in userinfo:
                    missing_padding = len(userinfo) % 4
                    if missing_padding: userinfo += '=' * (4 - missing_padding)
                    decoded_info = base64.b64decode(userinfo).decode('utf-8')
                else:
                    decoded_info = userinfo
            except:
                decoded_info = userinfo

            if not decoded_info or ':' not in decoded_info: return None
            method, password = decoded_info.split(':', 1)
            address = parsed.hostname
            port = parsed.port
        else:
            b64 = url_clean.replace("ss://", "")
            missing_padding = len(b64) % 4
            if missing_padding: b64 += '=' * (4 - missing_padding)
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' not in decoded: return None
            method_pass, addr_port = decoded.rsplit('@', 1)
            method, password = method_pass.split(':', 1)
            address, port = addr_port.rsplit(':', 1)

        if not address or not port: return None

        method_lower = method.lower().strip()

        # 别名处理
        if method_lower == "chacha20-poly1305":
            method_lower = "chacha20-ietf-poly1305"
        elif method_lower == "xchacha20-poly1305":
            method_lower = "xchacha20-ietf-poly1305"

        # 验证：仅支持Xray允许的加密方式
        # CFB/CTR/OFB流密码会导致Exit 23！
        if method_lower not in SS_ALLOWED_METHODS:
            if GLOBAL_CFG.get("debug_mode"):
                safe_print(f"[yellow][调试] 丢弃SS链接：不支持的加密方法 '{method}'（仅允许AEAD）[/]")
            return None

        return {
            "protocol": "shadowsocks",
            "address": address,
            "port": int(port),
            "method": method_lower,
            "password": password,
            "tag": urllib.parse.unquote(tag).strip()
        }
    except:
        return None

# 解析Hysteria2链接
def parse_hysteria2(url):
    """解析Hysteria2链接"""
    try:
        url = url.replace("hy2://", "hysteria2://")
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "hy2"

        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            return None

        return {
            "protocol": "hysteria2",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": int(parsed.port),
            "sni": params.get("sni", [""])[0],
            "insecure": params.get("insecure", ["0"])[0] == "1",
            "obfs": params.get("obfs", ["none"])[0],
            "obfs_password": params.get("obfs-password", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except:
        return None

# 从链接中提取标签（备注）
def get_proxy_tag(url):
    """从链接中提取标签（备注）"""
    tag = "proxy"
    try:
        url = clean_url(url)
        if '#' in url:
            _, raw_tag = url.rsplit('#', 1)
            tag = urllib.parse.unquote(raw_tag).strip()
        elif url.startswith("vmess"):
            res = parse_vmess(url)
            if res: tag = res.get('tag', 'vmess')
    except:
        pass

    tag = re.sub(r'[^\w\-\.]', '_', tag)
    return tag if tag else "proxy"

# 验证UUID格式
def is_valid_uuid(uuid_str):
    """验证UUID格式"""
    if not uuid_str: return False
    pattern = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    return bool(pattern.match(str(uuid_str)))

# 验证端口号
def is_valid_port(port):
    """验证端口号"""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except:
        return False

# 生成Xray出站配置结构
def get_outbound_structure(proxy_url, tag):
    """生成Xray出站配置结构"""
    safe_print(f"[outbound] ▶️ 开始处理: {proxy_url[:80]}...")  if GLOBAL_CFG.get("debug_mode") else 0

    try:
        proxy_url = clean_url(proxy_url)
        proxy_conf = None

        if proxy_url.startswith("vless://"):
            proxy_conf = parse_vless(proxy_url)
        elif proxy_url.startswith("vmess://"):
            proxy_conf = parse_vmess(proxy_url)
        elif proxy_url.startswith("trojan://"):
            proxy_conf = parse_trojan(proxy_url)
        elif proxy_url.startswith("ss://"):
            proxy_conf = parse_ss(proxy_url)
        elif proxy_url.startswith("hy"):
            proxy_conf = parse_hysteria2(proxy_url)

        # if not proxy_conf or not proxy_conf.get("address"): return None
        # if not is_valid_port(proxy_conf.get("port")): return None
        #
        # if proxy_conf["protocol"] in ["vless", "vmess"]:
        #     if not is_valid_uuid(proxy_conf.get("uuid")): return None
        # 上方代码改成调试版
        if not proxy_conf:
            safe_print(f"[outbound] ❌ proxy_conf 为空，解析失败") if GLOBAL_CFG.get("debug_mode") else 0
            return None
        if not proxy_conf.get("address"):
            safe_print(f"[outbound] ❌ 无address，conf={proxy_conf}") if GLOBAL_CFG.get("debug_mode") else 0
            return None
        if not is_valid_port(proxy_conf.get("port")):
            safe_print(f"[outbound] ❌ 端口无效: {proxy_conf.get('port')}") if GLOBAL_CFG.get("debug_mode") else 0
            return None

        if proxy_conf["protocol"] in ["vless", "vmess"]:
            if not is_valid_uuid(proxy_conf.get("uuid")):
                safe_print(f"[outbound] ❌ UUID无效: {proxy_conf.get('uuid')}") if GLOBAL_CFG.get("debug_mode") else 0
                return None

        net_type = proxy_conf.get("type", "tcp").lower()
        header_type = proxy_conf.get("headerType", "").lower()

        if net_type == "http" or header_type == "http":
            return None

        streamSettings = {}
        security = proxy_conf.get("security", "none").lower()

        original_net_type = net_type
        if net_type in ["ws", "websocket"]:
            net_type = "xhttp"
        elif net_type in ["grpc", "gun"]:
            net_type = "xhttp"
        elif net_type in ["http", "h2"]:
            net_type = "xhttp"
        elif net_type == "httpupgrade":
            net_type = "xhttp"
        elif net_type not in ["tcp", "kcp", "quic", "xhttp"]:
            net_type = "tcp"

        if proxy_conf["protocol"] in ["vless", "vmess", "trojan"]:
            if security == "auto":
                security = "none"

            streamSettings = {
                "network": net_type,
                "security": security
            }

            alpn_val = None
            raw_alpn = proxy_conf.get("alpn")
            if raw_alpn:
                if isinstance(raw_alpn, list):
                    alpn_val = raw_alpn
                elif isinstance(raw_alpn, str):
                    alpn_val = raw_alpn.split(",")

            tls_settings = {
                "serverName": proxy_conf.get("sni") or proxy_conf.get("host") or "",
                "allowInsecure": True,
                "fingerprint": proxy_conf.get("fp", "chrome")
            }

            if alpn_val:
                tls_settings["alpn"] = alpn_val

            if security == "tls":
                streamSettings["tlsSettings"] = tls_settings
            elif security == "reality":
                if not proxy_conf.get("pbk"):
                    return None
                s_id = proxy_conf.get("sid", "")
                if len(s_id) % 2 != 0:
                    s_id = ""
                streamSettings["realitySettings"] = {
                    "publicKey": proxy_conf.get("pbk"),
                    "shortId": s_id,
                    "serverName": tls_settings["serverName"],
                    "fingerprint": tls_settings["fingerprint"],
                    "spiderX": "/"
                }

            path = proxy_conf.get("path") or "/"
            host = proxy_conf.get("host") or ""

            if net_type == "xhttp":
                mode = "auto"
                if original_net_type in ["grpc", "gun"]:
                    mode = "stream-up"
                    if not path or path == "/":
                        path = proxy_conf.get("serviceName") or "/"

                streamSettings["xhttpSettings"] = {
                    "path": path,
                    "host": host,
                    "mode": mode
                }
            elif net_type == "tcp":
                if proxy_conf.get("headerType") and proxy_conf.get("headerType").lower() != "none":
                    return None
            elif net_type == "kcp":
                streamSettings["kcpSettings"] = {
                    "header": {"type": proxy_conf.get("headerType") or "none"}
                }
            elif net_type == "quic":
                streamSettings["quicSettings"] = {
                    "security": proxy_conf.get("quicSecurity") or "none",
                    "key": proxy_conf.get("key") or "",
                    "header": {"type": proxy_conf.get("headerType") or "none"}
                }

        outbound = {
            "protocol": proxy_conf["protocol"],
            "tag": tag,
            "streamSettings": streamSettings
        }

        if proxy_conf["protocol"] == "shadowsocks":
            method = proxy_conf["method"].lower()
            if "chacha20-ietf" in method and "poly1305" not in method:
                method = "chacha20-ietf-poly1305"
            outbound["settings"] = {
                "servers": [{
                    "address": proxy_conf["address"],
                    "port": int(proxy_conf["port"]),
                    "method": method,
                    "password": proxy_conf["password"]
                }]
            }
            outbound.pop("streamSettings", None)

        elif proxy_conf["protocol"] == "trojan":
            outbound["settings"] = {
                "servers": [{
                    "address": proxy_conf["address"],
                    "port": int(proxy_conf["port"]),
                    "password": proxy_conf["uuid"]
                }]
            }

        elif proxy_conf["protocol"] == "hysteria2":
            hy2_settings = {
                "address": proxy_conf["address"],
                "port": int(proxy_conf["port"]),
                "users": [{"password": proxy_conf["uuid"]}]
            }
            if proxy_conf.get("obfs") and proxy_conf.get("obfs") != "none":
                hy2_settings["obfs"] = {
                    "type": proxy_conf["obfs"],
                    "password": proxy_conf.get("obfs_password", "")
                }
            outbound["settings"] = {"vnext": [hy2_settings]}
            outbound["streamSettings"] = {
                "security": "tls",
                "tlsSettings": {
                    "serverName": proxy_conf.get("sni", ""),
                    "allowInsecure": True,
                    "fingerprint": "chrome"
                }
            }
            if alpn_val:
                outbound["streamSettings"]["tlsSettings"]["alpn"] = alpn_val
        else:
            vnext_user = {
                "id": proxy_conf["uuid"],
                "alterId": proxy_conf.get("aid", 0),
                "encryption": "none"
            }
            if proxy_conf["protocol"] == "vless" and proxy_conf.get("flow"):
                vnext_user["flow"] = proxy_conf.get("flow")

            outbound["settings"] = {
                "vnext": [{
                    "address": proxy_conf["address"],
                    "port": int(proxy_conf["port"]),
                    "users": [vnext_user]
                }]
            }
        safe_print(f"[outbound] ✅ 成功构建 outbound，tag={tag}") if GLOBAL_CFG.get("debug_mode") else 0
        return outbound

    except Exception as e:
        safe_print(f"[outbound] ❌ 异常: {e}")  if GLOBAL_CFG.get("debug_mode") else 0
        return None

# 为一批代理创建Xray配置文件
def create_batch_config_file(proxy_list, start_port, work_dir):
    """为一批代理创建Xray配置文件"""
    inbounds = []
    outbounds = []
    rules = []
    valid_proxies = []

    for i, url in enumerate(proxy_list):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = f"out_{port}"

        out_struct = get_outbound_structure(url, out_tag)
        if not out_struct:
            continue

        if "streamSettings" in out_struct:
            ss = out_struct["streamSettings"]
            net = ss.get("network", "")

            if net == "xhttp":
                ss.pop("wsSettings", None)
                ss.pop("grpcSettings", None)
                ss.pop("httpSettings", None)
                ss.pop("h2Settings", None)
                ss.pop("httpupgradeSettings", None)

        inbounds.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "tag": in_tag,
            "settings": {"udp": False}
        })

        outbounds.append(out_struct)
        rules.append({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag
        })
        valid_proxies.append((url, port))

    if not outbounds:
        return None, None, "无有效代理"

    full_config = {
        "log": {"loglevel": "warning"},  # warning便于诊断，none会隐藏错误
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        }
    }

    config_path = os.path.join(work_dir, f"batch_{start_port}.json")
    with open(config_path, 'w') as f:
        json.dump(full_config, f, indent=2)

    return config_path, valid_proxies, None

# 保存失败的批处理配置和错误日志
def save_failed_batch(config_path, error_output, exit_code):
    """保存失败的批处理配置和错误日志"""
    try:
        failed_dir = os.path.join(os.getcwd(), "failed_batches")
        os.makedirs(failed_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(config_path).replace(".json", "")

        dest_json = os.path.join(failed_dir, f"{base_name}_{timestamp}.json")
        shutil.copy2(config_path, dest_json)

        log_path = os.path.join(failed_dir, f"{base_name}_{timestamp}.log.txt")
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"退出代码：{exit_code}\n")
            f.write(f"时间戳：{timestamp}\n")
            f.write(f"配置文件：{config_path}\n")
            f.write("-" * 50 + "\n")
            f.write(error_output or "未捕获输出")

        safe_print(f"[yellow]📁 调试文件已保存至：{failed_dir}[/]")
        safe_print(f"[dim]   重现命令：xray run -test -c \"{dest_json}\"[/]")

        return dest_json, log_path
    except Exception as e:
        safe_print(f"[red]保存调试工件失败：{e}[/]")
        return None, None

# 启动Xray核心
def run_core(core_path, config_path):
    """启动Xray核心"""
    if platform.system() != "Windows":
        try:
            st = os.stat(core_path)
            os.chmod(core_path, st.st_mode | stat.S_IXEXEC)
        except Exception as e:
            pass
    cmd = [core_path, "run", "-c", config_path] if "xray" in core_path.lower() else [core_path, "-c", config_path]
    startupinfo = None
    if OS_SYSTEM == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            startupinfo=startupinfo,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
    except Exception as e:
        safe_print(f"[bold red]核心启动错误：{e}[/]")
        return None

# 杀死核心进程及其子进程
def kill_core(proc):
    """杀死核心进程及其子进程"""
    if not proc:
        return

    try:
        if psutil.pid_exists(proc.pid):
            parent = psutil.Process(proc.pid)
            # 杀死子进程
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except:
                    pass
            parent.kill()
        else:
            if OS_SYSTEM == "windows":
                subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)],
                               capture_output=True)
    except:
        pass

    try:
        proc.terminate()
        proc.wait(timeout=1.0)
    except:
        try:
            proc.kill()
        except:
            pass

# 通过SOCKS5代理测试连通性
def check_connection(local_port, domain, timeout):
    """通过SOCKS5代理测试连通性，并记录失败原因"""

    # 不要忘了安装requests的socks支持,上次调试了整整2天才找到问题
    try:
        import socks  # 仅用于检测依赖是否存在
    except ImportError:
        safe_print("[bold red]错误：未安装 PySocks，无法使用 SOCKS5 代理。请运行: pip install pysocks[/]")
        return False, "Missing PySocks"

    proxies = {
        'http': f'socks5://127.0.0.1:{local_port}',
        'https': f'socks5://127.0.0.1:{local_port}'
    }
    try:
        start = time.time()
        resp = requests.get(domain, proxies=proxies, timeout=timeout, verify=False)
        end = time.time()
        if resp.status_code < 400:
            safe_print(f"[check] ✅ 端口{local_port} 延迟{round((end - start) * 1000)}ms") if GLOBAL_CFG.get("debug_mode") else 0
            return round((end - start) * 1000), None
        else:
            safe_print(f"[check] ❌ 端口{local_port} HTTP {resp.status_code}") if GLOBAL_CFG.get("debug_mode") else 0
            return False, f"HTTP {resp.status_code}"

    # 调试模式输出
    except requests.exceptions.ConnectTimeout:
        safe_print(f"[check] ❌ 端口{local_port} 连接超时") if GLOBAL_CFG.get("debug_mode") else 0
        return False, "连接超时"
    except requests.exceptions.ReadTimeout:
        safe_print(f"[check] ❌ 端口{local_port} 读取超时") if GLOBAL_CFG.get("debug_mode") else 0
        return False, "读取超时"
    except (BadStatusLine, RemoteDisconnected):
        safe_print(f"[check] ❌ 端口{local_port} 握手失败") if GLOBAL_CFG.get("debug_mode") else 0
        return False, "握手失败"
    except requests.exceptions.ConnectionError as e:
        safe_print(f"[check] ❌ 端口{local_port} 连接错误: {e}") if GLOBAL_CFG.get("debug_mode") else 0
        return False, f"连接错误: {e}"
    except Exception as e:
        safe_print(f"[check] ❌ 端口{local_port} 未知异常: {e}") if GLOBAL_CFG.get("debug_mode") else 0
        return False, str(e)

# 通过代理测试下载速度
def check_speed_download(local_port, url_file, timeout=10, conn_timeout=5, max_mb=5, min_kb=1):
    """通过代理测试下载速度"""
    targets = GLOBAL_CFG.get("speed_targets", [])

    pool = [url_file] + targets if url_file else list(targets)
    if not url_file: random.shuffle(pool)

    pool = [u for u in pool if u]
    if not pool: return 0.0

    proxies = {
        'http': f'socks5://127.0.0.1:{local_port}',
        'https': f'socks5://127.0.0.1:{local_port}'
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }

    limit_bytes = max_mb * 1024 * 1024

    for target_url in pool:
        try:
            with requests.get(target_url, proxies=proxies, headers=headers, stream=True,
                              timeout=(conn_timeout, timeout), verify=False) as r:

                if r.status_code >= 400:
                    continue

                start_time = time.time()
                total_bytes = 0

                for chunk in r.iter_content(chunk_size=32768):
                    if chunk:
                        total_bytes += len(chunk)

                    curr_time = time.time()
                    if (curr_time - start_time) > timeout or total_bytes >= limit_bytes:
                        break

                duration = time.time() - start_time
                if duration <= 0.1: duration = 0.1

                if total_bytes < (min_kb * 1024):
                    if duration > (timeout * 0.8):
                        return 0.0
                    continue

                speed_bps = total_bytes / duration
                speed_mbps = speed_bps / 125000

                return round(speed_mbps, 2)

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError):
            continue
        except Exception:
            pass

# 处理一批代理的完整检查流程
def Checker(proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill,
            checkSpeed=False, speedUrl="", sortBy="ping", speedCfg=None,
            speedSemaphore=None, maxInternalThreads=50,
            progress=None, task_id=None):
    """处理一批代理的完整检查流程"""

    current_live_results = []
    if speedCfg is None: speedCfg = {}

    configPath, valid_mapping, err = create_batch_config_file(proxyList, localPortStart, TEMP_DIR)
    if err or not valid_mapping:
        return current_live_results

    proc = run_core(CORE_PATH, configPath)
    if not proc:
        safe_print(f"[bold red][批处理错误] 无法创建核心进程！[/]")
        return current_live_results

    core_started = False
    start_time = time.time()
    max_wait = max(t2exec, 5.0)
    while (time.time() - start_time) < max_wait:
        poll_result = proc.poll()
        if poll_result is not None:
            exitcode = proc.returncode
            if exitcode == 0: break

            try:
                out_data, _ = proc.communicate(timeout=1)
                if out_data:
                    error_msg = out_data.strip()[-2000:]
            except Exception as e:
                error_msg = f"读取错误输出失败：{e}"

            safe_print(f"[bold red]批处理失败[/] [yellow]核心未启动 (Exit: {exitcode})[/]")
            safe_print(f"[dim]错误信息：{error_msg[:300]}[/]")

            save_failed_batch(configPath, error_msg, exitcode)

            kill_core(proc)
            return current_live_results
        if is_port_in_use(valid_mapping[0][1]):
            core_started = True
            break
        time.sleep(0.1)

    if core_started:
        time.sleep(0.3)

    if not core_started:
        exitcode = proc.poll()
        error_msg = "未知错误"
        try:
            if proc.stdout:
                err_lines = []
                for line in proc.stdout:
                    err_lines.append(line.strip())
                    if len(err_lines) > 50:
                        break
                if err_lines:
                    error_msg = "\n".join(err_lines[-20:])
        except:
            try:
                proc.wait(timeout=0.5)
                error_msg = "核心静默失败"
            except:
                error_msg = "核心超时"

        safe_print(f"[bold red]批处理失败[/] [yellow]核心未启动 (Exit: {exitcode})[/]")
        safe_print(f"[dim]错误信息：{error_msg[:300]}[/]")

        save_failed_batch(configPath, error_msg, exitcode)

        exit_code = proc.poll()

        kill_core(proc)
        return current_live_results

    def check_single_port(item):
        if CTRL_C: return None
        target_url, target_port = item

        proxy_speed = 0.0

        conf = None
        try:
            if target_url.startswith("vless://"):
                conf = parse_vless(target_url)
            elif target_url.startswith("vmess://"):
                conf = parse_vmess(target_url)
            elif target_url.startswith("ss://"):
                conf = parse_ss(target_url)
            elif target_url.startswith("trojan://"):
                conf = parse_trojan(target_url)
        except:
            pass

        addr_info = f"{conf['address']}:{conf['port']}" if conf else "未知"
        proxy_tag = get_proxy_tag(target_url)

        ping_res, error_reason = check_connection(target_port, testDomain, timeOut)

        if ping_res:
            if checkSpeed:
                with (speedSemaphore if speedSemaphore else Lock()):
                    proxy_speed = check_speed_download(target_port, speedUrl, **speedCfg)
                sp_color = "green" if proxy_speed > 15 else "yellow" if proxy_speed > 5 else "red"
                safe_print(
                    f"[green][存活][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms | [{sp_color}]{proxy_speed:>5} Mbps[/] | {proxy_tag}")
            else:
                safe_print(f"[green][存活][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms | {proxy_tag}")

            if progress and task_id is not None:
                progress.advance(task_id, 1)
            return (target_url, ping_res, proxy_speed)

        else:
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            return None

    max_workers = min(len(valid_mapping), maxInternalThreads)
    with ThreadPoolExecutor(max_workers=max_workers) as inner_exec:
        raw_results = list(inner_exec.map(check_single_port, valid_mapping))

    current_live_results = [r for r in raw_results if r is not None]

    kill_core(proc)
    time.sleep(t2kill)
    try:
        if os.path.exists(configPath):
            os.remove(configPath)
    except:
        pass

    return current_live_results

# 运行主要执行逻辑
def run_logic(args):
    """主要执行逻辑"""
    global CORE_PATH, CTRL_C

    # ctrl + c 停止
    def signal_handler(sig, frame):
        global CTRL_C
        CTRL_C = True
        safe_print("[bold red]CTRL+C - 正在停止...[/]")
        kill_all_cores_manual()
        sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, signal_handler)

    CORE_PATH = shutil.which(args.core)
    if not CORE_PATH:
        # 常见核心路径
        candidates = ["xray.exe", "xray", "v2ray.exe", "v2ray", "bin/xray.exe", "bin/xray"]
        for c in candidates:
            if os.path.exists(c):
                CORE_PATH = os.path.abspath(c)
                break

    if not CORE_PATH:
        safe_print(f"[bold red]\\n[错误] 未找到核心 (xray/v2ray)！[/]")
        safe_print(f"[dim]请手动下载：https://github.com/XTLS/Xray-core/releases[/]")
        return

    safe_print(f"[dim]检测到核心：{CORE_PATH}[/]")

    safe_print(f"[yellow]>> 清理残留的核心进程...[/]")
    killed_count = 0
    target_names = [os.path.basename(CORE_PATH).lower(), "xray.exe", "v2ray.exe", "xray", "v2ray"]
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in target_names:
                proc.kill()
                killed_count += 1
        except:
            pass

    if killed_count > 0: safe_print(f"[green]>> 已终止 {killed_count} 个旧进程[/]")
    time.sleep(0.5)

    lines = set()
    total_found_raw = 0

    # 如果有传递的文件
    if args.file:
        fpath = args.file.strip('"')
        if os.path.exists(fpath):
            safe_print(f"[cyan]>> 读取文件：{fpath}[/]")
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                parsed, count = parse_content(f.read())
                total_found_raw += count
                lines.update(parsed)

    # 如果有传递的url
    if args.url:
        links = fetch_url(args.url)
        lines.update(links)

    # 如果使用聚合器
    if AGGREGATOR_AVAILABLE and getattr(args, 'agg', False):
        sources_map = GLOBAL_CFG.get("sources", {})
        cats = args.agg_cats if args.agg_cats else list(sources_map.keys())
        kws = args.agg_filter if args.agg_filter else []
        try:
            agg_links = aggregator.get_aggregated_links(sources_map, cats, kws, log_func=safe_print, console=console)
            lines.update(agg_links)
        except:
            pass

    if hasattr(args, 'direct_list') and args.direct_list:
        parsed_agg, _ = parse_content("\n".join(args.direct_list))
        lines.update(parsed_agg)

    if args.reuse and os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            parsed, count = parse_content(f.read())
            lines.update(parsed)

    full = list(lines)
    if not full:
        safe_print(f"[bold red]没有待检查的代理。[/]")
        return

    p_per_batch = GLOBAL_CFG.get("proxies_per_batch", 50)
    needed_cores = (len(full) + p_per_batch - 1) // p_per_batch
    threads = min(args.threads, needed_cores)
    if threads < 1: threads = 1

    chunks = list(split_list(full, threads))
    ports = []
    curr_p = args.lport
    for chunk in chunks:
        ports.append(curr_p)
        curr_p += len(chunk) + 10

    results = []

    speed_config_map = {
        "timeout": GLOBAL_CFG.get("speed_download_timeout", 10),
        "conn_timeout": GLOBAL_CFG.get("speed_connect_timeout", 5),
        "max_mb": GLOBAL_CFG.get("speed_max_mb", 5),
        "min_kb": GLOBAL_CFG.get("speed_min_kb", 1)
    }
    speed_semaphore = Semaphore(GLOBAL_CFG.get("speed_check_threads", 3))

    progress_columns = [
        SpinnerColumn(style="bold yellow"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
    ]

    console.print(f"\n[magenta]启动 {threads} 个核心（批次）检查 {len(full)} 个代理...[/]")

    with Progress(*progress_columns, console=console, transient=False) as progress:
        task_id = progress.add_task("[cyan]正在检查代理...", total=len(full))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for i in range(len(chunks)):
                ft = executor.submit(
                    Checker, chunks[i], ports[i], args.domain, args.timeout,
                    args.t2exec, args.t2kill, args.speed_check, args.speed_test_url, args.sort_by,
                    speed_config_map, speed_semaphore,
                    GLOBAL_CFG.get("max_internal_threads", 50),
                    progress, task_id
                )
                futures.append(ft)

            try:
                for f in as_completed(futures):
                    chunk_result = f.result()
                    if chunk_result:
                        results.extend(chunk_result)
            except KeyboardInterrupt:
                CTRL_C = True
                executor.shutdown(wait=False)

    if args.sort_by == "speed":
        results.sort(key=lambda x: x[2], reverse=True)
    else:
        results.sort(key=lambda x: x[1])

    with open(args.output, 'a', encoding='utf-8') as f:
        for r in results:
            f.write(r[0] + '\n')

    if results:
        table = Table(title=f"结果（前15个，共{len(results)}）", box=box.ROUNDED)
        table.add_column("延迟", justify="right", style="green")
        if args.speed_check:
            table.add_column("速度 (Mbps)", justify="right", style="bold cyan")
        table.add_column("标签/协议", justify="left", overflow="fold")

        for r in results[:15]:
            tag_display = get_proxy_tag(r[0])
            if len(tag_display) > 50: tag_display = tag_display[:47] + "..."
            if args.speed_check:
                table.add_row(f"{r[1]} ms", f"{r[2]}", tag_display)
            else:
                table.add_row(f"{r[1]} ms", tag_display)
        console.print(table)

    safe_print(f"\n[bold green]完成！有效代理数：{len(results)}。结果已保存至：{args.output}[/]")

# 手动杀死所有核心进程
def kill_all_cores_manual():
    """手动杀死所有核心进程"""
    killed_count = 0
    target_names = ["xray.exe", "v2ray.exe", "xray", "v2ray"]

    safe_print("[yellow]>> 强制重置所有核心...[/]")

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and any(name in proc.info['name'].lower() for name in target_names):
                proc.kill()
                killed_count += 1
                safe_print(f"[green]✓ 已终止 PID {proc.info['pid']}[/]")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if OS_SYSTEM == "windows":
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", "xray.exe", "/T"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                killed_count += result.stdout.count("SUCCESS")
        except:
            pass

    for port in range(10000, 11000):
        if is_port_in_use(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    s.connect(('127.0.0.1', port))
            except:
                pass

    time.sleep(1.0)
    remaining = 0
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and any(name in proc.info['name'].lower() for name in target_names):
                remaining += 1
        except:
            pass

    safe_print(f"[bold green]✓ 重置完成：已终止 {killed_count} 个核心[/]")
    if remaining > 0:
        safe_print(f"[yellow]⚠ 剩余 {remaining} 个进程（3秒后自动重试）[/]")
        time.sleep(3)
        kill_all_cores_manual()
    else:
        safe_print("[bold green]✅ 全部清理完毕！[/]")

# 交互式主菜单
def interactive_menu():
    """交互式菜单"""
    while True:

        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
        table.add_column("序号", style="cyan", width=4, justify="center")
        table.add_column("操作", style="white")
        table.add_column("描述", style="dim")

        table.add_row("1", "文件", "从.txt文件加载代理")
        table.add_row("2", "链接", "从URL加载代理")
        table.add_row("3", "重新检查", f"重新检查 {GLOBAL_CFG['output_file']}")

        if AGGREGATOR_AVAILABLE:
            table.add_row("4", "聚合器", "从url集合批量下载数据、合并并检查")

        table.add_row("5", "重置核心", "杀死所有xray进程")
        table.add_row("0", "退出", "关闭程序")

        console.print(table)

        valid_choices = ["0", "1", "2", "3", "4", "5", "6"] if AGGREGATOR_AVAILABLE else ["0", "1", "2", "3", "5", "6"]
        ch = Prompt.ask("[bold yellow]>[/] 请选择操作", choices=valid_choices)

        # 退出
        if ch == '0':
            sys.exit()

        # 选项传递(默认)
        defaults = {
            "file": None, "url": None, "reuse": False,
            "domain": GLOBAL_CFG['test_domain'],
            "timeout": GLOBAL_CFG['timeout'],
            "lport": GLOBAL_CFG['local_port_start'],
            "threads": GLOBAL_CFG['threads'],
            "core": GLOBAL_CFG['core_path'],
            "t2exec": GLOBAL_CFG['core_startup_timeout'],
            "t2kill": GLOBAL_CFG['core_kill_delay'],
            "output": GLOBAL_CFG['output_file'],
            "shuffle": GLOBAL_CFG['shuffle'],
            "number": None,
            "direct_list": None,
            "speed_check": GLOBAL_CFG['check_speed'],
            "speed_test_url": GLOBAL_CFG['speed_test_url'],
            "sort_by": GLOBAL_CFG['sort_by'],
            "menu": True
        }

        # 文件加载
        if ch == '1':
            defaults["file"] = Prompt.ask("[cyan][?][/] 文件路径").strip('"')
            if not defaults["file"]: continue

        # 网址加载
        elif ch == '2':
            defaults["url"] = Prompt.ask("[cyan][?][/] URL链接").strip()
            if not defaults["url"]: continue

        # 重新检查
        elif ch == '3':
            defaults["reuse"] = True

        # 聚合器 = 收集 + 清洗 + 地理标记
        elif ch == '4' and AGGREGATOR_AVAILABLE:
            console.print(
                Panel(f"可用类别：[green]{', '.join(GLOBAL_CFG.get('sources', {}).keys())}[/]", title="聚合器"))
            cats = Prompt.ask("请输入类别（空格分隔）", default="1 2").split()
            kws = Prompt.ask("过滤关键词（空格分隔）", default="").split()

            sources_map = GLOBAL_CFG.get("sources", {})
            try:
                raw_links = aggregator.get_aggregated_links(sources_map, cats, kws, console=console)
                if not raw_links:
                    safe_print("[bold red]聚合器未找到任何内容。[/]")
                    time.sleep(2)
                    continue
                defaults["direct_list"] = raw_links
            except Exception as e:
                safe_print(f"[bold red]聚合器错误：{e}[/]")
                continue
        # 聚合器收集清洗完后将会执行检查是否可用

        elif ch == '5':
            kill_all_cores_manual()
            continue

        if Confirm.ask("是否启用速度测试？", default=False):
            defaults["speed_check"] = True
            defaults["sort_by"] = "speed"
        else:
            defaults["speed_check"] = False
            defaults["sort_by"] = "ping"

        args = SimpleNamespace(**defaults)

        safe_print("\n[yellow]>>> 正在初始化检查...[/]")
        time.sleep(0.5)

        try:
            run_logic(args)
        except Exception as e:
            safe_print(f"[bold red]严重错误：{e}[/]")
            # traceback处理和调试程序中的异常。它可以提取、格式化并打印异常的详细信息，包括错误发生的位置和调用栈信息，从而帮助开发者快速定位问题。
            import traceback
            error_data = traceback.format_exc()
            MAIN_LOGGER.log(f"崩溃报告：\n{error_data}")

            traceback.print_exc()

        Prompt.ask("\n[bold]按Enter返回菜单...[/]", password=False)

# 主入口
def main():
    """主入口"""
    parser = argparse.ArgumentParser(description="命令行参数传递")
    parser.add_argument("-m", "--menu", action="store_true")
    parser.add_argument("-f", "--file")
    parser.add_argument("-u", "--url")
    parser.add_argument("--reuse", action="store_true")

    parser.add_argument("-t", "--timeout", type=int, default=GLOBAL_CFG['timeout'])
    parser.add_argument("-l", "--lport", type=int, default=GLOBAL_CFG['local_port_start'])
    parser.add_argument("-T", "--threads", type=int, default=GLOBAL_CFG['threads'])
    parser.add_argument("-c", "--core", default=GLOBAL_CFG['core_path'])
    parser.add_argument("--t2exec", type=float, default=GLOBAL_CFG['core_startup_timeout'])
    parser.add_argument("--t2kill", type=float, default=GLOBAL_CFG['core_kill_delay'])
    parser.add_argument("-o", "--output", default=GLOBAL_CFG['output_file'])
    parser.add_argument("-d", "--domain", default=GLOBAL_CFG['test_domain'])
    parser.add_argument("-s", "--shuffle", action='store_true', default=GLOBAL_CFG['shuffle'])
    parser.add_argument("-n", "--number", type=int)
    parser.add_argument("--agg", action="store_true", help="启动聚合器")
    parser.add_argument("--agg-cats", nargs='+', help="聚合器类别（如：1 2）")
    parser.add_argument("--agg-filter", nargs='+', help="过滤关键词（如：vless reality）")
    parser.add_argument("--speed", action="store_true", dest="speed_check", help="启用速度测试")
    parser.add_argument("--sort", choices=["ping", "speed"], default=GLOBAL_CFG['sort_by'], dest="sort_by",help="排序方式")
    parser.add_argument("--speed-url", default=GLOBAL_CFG['speed_test_url'], dest="speed_test_url")
    parser.add_argument("--self-test", action="store_true", help="运行URL解析自测")
    parser.add_argument("--debug", action="store_true", help="Debug模式（proxies_per_batch=1, threads=1）")

    # 列表的第一个元素 sys.argv[0] 永远是脚本文件名，其余元素是用户传入的参数。
    # 当没有其他参数传递,只有一个文件名
    if len(sys.argv) == 1:
        # 进入主菜单
        interactive_menu()

    # 有参数传递
    else:
        # 获取传递的参数
        args = parser.parse_args()

        # getattr 是一个内置函数，用于动态获取对象的属性值。它提供了一种灵活的方式来访问对象的属性，尤其是在属性名不确定或需要动态决定的情况下。
        # 查找传入的参数又没有self_test,有则触发URL解析自测
        # 运行方式：python v2rayChecker.py --self-test
        if getattr(args, 'self_test', False):
            print("正在运行URL解析自测...")
            success = _self_test_clean_url()
            sys.exit(0 if success else 1)

        # 调试模式
        if getattr(args, 'debug', False):
            GLOBAL_CFG['debug_mode'] = True
            GLOBAL_CFG['proxies_per_batch'] = 1
            GLOBAL_CFG['threads'] = 1
            safe_print(f"[yellow][调试模式] proxies_per_batch=1, threads=1[/]")

        # 当有-m时启动主菜单
        if args.menu:
            interactive_menu()

        # 只要在执行脚本时传递了至少一个有效参数，并且这些参数不包含 --menu 或 --self-test，就调用 run_logic(args) 执行正常任务。
        else:
            # 正常任务执行,跳过交互终端,直接通过参数执行
            run_logic(args)


if __name__ == '__main__':
    try:
        # 主程序入口
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}退出。{Style.RESET_ALL}")
    finally:
        try:
            # 递归删除临时目录
            shutil.rmtree(TEMP_DIR)
        except:
            pass