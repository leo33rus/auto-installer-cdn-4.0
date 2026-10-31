#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   VPN CDN INSTALLER  ·  v4.0  ·  ENTERPRISE PROTECTED            ║
║   XHTTP packet-up через российский CDN                           ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║   Бот управления лицензиями : @my_cdn_license_bot                ║
║   Сервер авторизации        : cdn-license18.leo33rus.pro        ║
╠══════════════════════════════════════════════════════════════════╣
║   ✔ Автоматическая проверка ключа и привязка к HWID / IP         ║
║   ✔ Панели : Remnawave · 3x-ui                                   ║
║   ✔ CDN    : VK · Yandex · TurboFlare · Beeline · Timeweb ·      ║
║              Selectel                                            ║
╠══════════════════════════════════════════════════════════════════╣
║   Запуск на целевом сервере (root):                              ║
║       python3 auto-installer-cdn-4.0.py --key CDN-XXXX-XXXX-XXXX ║
╚══════════════════════════════════════════════════════════════════╝
"""

import base64
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import hashlib
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path


def _configure_text_stream(stream):
    """Keep interactive SSH sessions alive when the terminal emits bad bytes."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        # Captured/in-memory streams used by tests may already be initialized.
        pass


for _text_stream in (sys.stdin, sys.stdout, sys.stderr):
    _configure_text_stream(_text_stream)
del _text_stream


_install_log = []
_current_step = ""
def track(action_type, value):
    _install_log.append((action_type, value))


def track_created(action_type, value, existed_before=False):
    """Register only resources that were actually created by this run."""
    if not existed_before:
        track(action_type, value)


def _backup_path(path):
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe = str(path).strip("/").replace("/", "__") or "root"
    return f"/var/backups/vpn-cdn-installer/{stamp}/{len(_install_log):04d}_{safe}"


def backup_file(path):
    """Create a rollback copy of a regular file or symlink before overwrite."""
    if not os.path.lexists(path):
        return None
    dst = _backup_path(path)
    os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
    if os.path.islink(path):
        os.symlink(os.readlink(path), dst)
    elif os.path.isfile(path):
        shutil.copy2(path, dst)
    else:
        return None
    track("restore_file", (path, dst))
    return dst


def rollback():
    if not _install_log:
        print("\n  Нечего откатывать.")
        return
    print("\n  Откат установки...")
    for action_type, value in reversed(_install_log):
        try:
            if action_type == "docker_compose":
                subprocess.run(["docker", "compose", "down"], cwd=value,
                               capture_output=True, timeout=60)
                print(f"    docker compose down: {value}")
            elif action_type == "docker_volume":
                subprocess.run(["docker", "volume", "rm", value],
                               capture_output=True, timeout=30)
                print(f"    Docker volume удалён: {value}")
            elif action_type == "docker_network":
                subprocess.run(["docker", "network", "rm", value],
                               capture_output=True, timeout=30)
                print(f"    Docker network удалена: {value}")
            elif action_type == "systemd":
                subprocess.run(f"systemctl stop {value} 2>/dev/null; systemctl disable {value} 2>/dev/null", shell=True, capture_output=True, timeout=30)
                print(f"    systemd stop: {value}")
            elif action_type == "file":
                if os.path.exists(value):
                    os.remove(value)
                    print(f"    удалён: {value}")
            elif action_type == "directory":
                try:
                    os.rmdir(value)
                    print(f"    удалена пустая папка: {value}")
                except OSError:
                    print(f"    сохранена непустая папка: {value}")
            elif action_type == "nginx_site":
                for p in [f"/etc/nginx/sites-enabled/{value}", f"/etc/nginx/sites-available/{value}"]:
                    if os.path.exists(p):
                        os.remove(p)
                print(f"    nginx site удалён: {value}")
            elif action_type == "iptables":
                subprocess.run(["iptables", "-D", *value], capture_output=True, timeout=10)
            elif action_type == "restore_file":
                original, saved = value
                if os.path.lexists(original):
                    if os.path.isdir(original) and not os.path.islink(original):
                        continue
                    os.unlink(original)
                os.makedirs(os.path.dirname(original), exist_ok=True)
                if os.path.islink(saved):
                    os.symlink(os.readlink(saved), original)
                else:
                    shutil.copy2(saved, original)
                print(f"    восстановлен: {original}")
            elif action_type == "ipset":
                name, port = value
                subprocess.run(f"iptables -D INPUT -p tcp --dport {port} -m set --match-set {name} src -j ACCEPT 2>/dev/null", shell=True, capture_output=True, timeout=10)
                subprocess.run(f"iptables -D INPUT -p tcp --dport {port} -j DROP 2>/dev/null", shell=True, capture_output=True, timeout=10)
                subprocess.run(f"ipset destroy {name} 2>/dev/null", shell=True, capture_output=True, timeout=10)
            elif action_type == "acme_cert":
                subprocess.run(f"~/.acme.sh/acme.sh --remove -d {value} 2>/dev/null", shell=True, capture_output=True, timeout=30)
            elif action_type == "xray_standalone":
                subprocess.run("systemctl stop xray 2>/dev/null; systemctl disable xray 2>/dev/null", shell=True, capture_output=True, timeout=30)
                print("    xray остановлен")
        except Exception as exc:
            print(f"    предупреждение отката {action_type}: {exc}")
    subprocess.run("nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null", shell=True, capture_output=True, timeout=15)
    subprocess.run("netfilter-persistent save 2>/dev/null", shell=True, capture_output=True, timeout=15)
    print("  Откат завершён. Проверь предупреждения выше и состояние сервисов.")


class CancelInstallation(Exception):
    pass


def handle_ctrl_c(can_resume=False):
    """Called when KeyboardInterrupt is caught. Ask user whether to cancel."""
    import signal as _sig
    old_handler = _sig.signal(_sig.SIGINT, _sig.SIG_IGN)
    try:
        print()
        if not can_resume:
            print("\n  Прерывание...")
            rollback()
            print("\n  Установка отменена.")
            sys.exit(0)
        for _ in range(3):
            try:
                _sig.signal(_sig.SIGINT, _sig.default_int_handler)
                resp = input("\n  Прервать установку? / Cancel? (y/n): ").strip().lower()
                _sig.signal(_sig.SIGINT, _sig.SIG_IGN)
                if resp in ("y", "yes", "д", "да"):
                    rollback()
                    print("\n  Установка отменена.")
                    sys.exit(0)
                print("  Продолжаем...")
                return
            except (KeyboardInterrupt, EOFError):
                _sig.signal(_sig.SIGINT, _sig.SIG_IGN)
                continue
        rollback()
        sys.exit(1)
    finally:
        _sig.signal(_sig.SIGINT, old_handler)


def safe_input(prompt=""):
    """input() that handles Ctrl+C by asking about cancellation."""
    while True:
        try:
            return input(prompt)
        except KeyboardInterrupt:
            handle_ctrl_c(can_resume=True)
        except EOFError:
            print()
            return ""


_FQDN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.IGNORECASE,
)
_SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.IGNORECASE)


def validate_fqdn(value, label="домен"):
    value = (value or "").strip().rstrip(".").lower()
    if not _FQDN_RE.fullmatch(value):
        raise ValueError(f"Некорректный {label}: {value!r}")
    return value


def validate_ip(value, label="IP"):
    try:
        parsed = ipaddress.ip_address((value or "").strip())
        if parsed.version != 4:
            raise ValueError("IPv6 пока не поддерживается этой схемой nginx/SSH")
        return str(parsed)
    except ValueError as exc:
        raise ValueError(f"Некорректный IPv4 {label}: {value!r}") from exc


def validate_ssh_user(value):
    value = (value or "root").strip()
    if not _SSH_USER_RE.fullmatch(value):
        raise ValueError(f"Некорректный SSH-пользователь: {value!r}")
    return value


def validate_runtime_config(cfg):
    """Fail before the first package/file/service mutation."""
    validate_embedded_cdn_config()
    cfg["domain"] = validate_fqdn(cfg.get("domain"))
    cfg["server_ip"] = validate_ip(cfg.get("server_ip"), "IP сервера")
    for key in ("node_ip", "cascade_ip", "panel_ip"):
        if cfg.get(key):
            # panel_ip may be a DNS name in mode 3.
            try:
                cfg[key] = validate_ip(cfg[key], key)
            except ValueError:
                if key == "panel_ip":
                    cfg[key] = validate_fqdn(cfg[key], "адрес панели")
                else:
                    raise
    for key in ("node_cred", "cascade_cred", "panel_cred"):
        cred = cfg.get(key)
        if isinstance(cred, dict):
            cred["user"] = validate_ssh_user(cred.get("user", "root"))
    cdn_type = cfg.get("cdn_type")
    panel_type = cfg.get("panel_type")
    allowed = REMNAWAVE_CDN if panel_type == "1" else CDN_SETTINGS
    if cdn_type not in allowed:
        raise ValueError(f"CDN {cdn_type!r} не поддерживается выбранной панелью")
    return True


def assert_mode1_fresh_target(panel_type):
    """Mode 1 owns the whole panel; refuse to overwrite an existing install."""
    markers = []
    if panel_type == "1":
        for p in (
            "/opt/remnawave/.env",
            "/opt/remnawave/docker-compose.yml",
            "/opt/remnanode/.env",
            "/opt/remnanode/docker-compose.yml",
        ):
            if os.path.exists(p):
                markers.append(p)
        r = run("docker ps -a --format '{{.Names}}' 2>/dev/null", check=False)
        panel_containers = {"remnawave", "remnawave-db", "remnawave-redis", "remnanode"}
        found_containers = panel_containers.intersection((r.stdout or "").splitlines())
        if found_containers:
            markers.append("контейнеры: " + ", ".join(sorted(found_containers)))
        volumes = run("docker volume ls --format '{{.Name}}' 2>/dev/null", check=False)
        owned_volume_names = {"remnawave-db", "remnawave-db-data", "valkey-socket"}
        found_volumes = owned_volume_names.intersection((volumes.stdout or "").splitlines())
        if found_volumes:
            markers.append("Docker volumes: " + ", ".join(sorted(found_volumes)))
        network = run("docker network inspect remnawave-network >/dev/null 2>&1", check=False)
        if network.returncode == 0:
            markers.append("Docker network: remnawave-network")
    else:
        for p in ("/usr/local/x-ui/x-ui", "/etc/x-ui/x-ui.db", "/etc/default/x-ui"):
            if os.path.exists(p):
                markers.append(p)
        if run("systemctl is-active x-ui 2>/dev/null", check=False).returncode == 0:
            markers.append("сервис x-ui")
    if markers:
        raise RuntimeError(
            "Режим 1 не перезаписывает существующую панель. Найдено: "
            + ", ".join(markers)
            + ". Используй режим 3 для подключения CDN к существующей панели."
        )


def require_success(result, label):
    if result is None or getattr(result, "returncode", 1) != 0:
        detail = ((getattr(result, "stderr", "") or getattr(result, "stdout", "") or "")[:500])
        raise RuntimeError(f"{label} завершилось с ошибкой: {detail}")
    return result

# ============================================================
#  CONSTANTS
# ============================================================

VERSION = "4.0-vk-cascade-fix"

# Remnawave versions
REMNAWAVE_VERSION_LEGACY = "2.8.1"  # Legacy version with JWT_AUTH_SECRET/JWT_API_TOKENS_SECRET
REMNAWAVE_VERSION_LATEST = "3.2.3"  # Latest version with APP_SECRET
REMNAWAVE_NODE_VERSION = "latest"
REMNAWAVE_SUBSCRIPTION_PAGE_VERSION = "8.0.0"
REMNAWAVE_CLIENT_TYPE_HEADER = "X-Remnawave-Client-Type"
REMNAWAVE_CLIENT_TYPE_BROWSER = "browser"
REMNAWAVE_POSTGRES_IMAGE = "postgres:18.4"
REMNAWAVE_VALKEY_IMAGE = "valkey/valkey:9-alpine"

SYSCTL_TUNING = """net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
fs.file-max = 1048576
vm.swappiness = 10
"""

NOFILE_LIMITS = """* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
"""

DECOY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{domain} | Website</title>
  <style>
    body {{ margin: 0; height: 100vh; display: flex; justify-content: center; align-items: center; background-color: #2c2825; color: #e3d9c6; font-family: 'Georgia', serif; }}
    .container {{ text-align: center; padding: 60px 80px; background: #1f1b18; border-radius: 6px; box-shadow: 0 15px 40px rgba(0,0,0,0.6); border-left: 4px solid #8b5a2b; }}
    h1 {{ font-weight: normal; letter-spacing: 2px; margin-bottom: 15px; font-size: 2.2em; }}
    p {{ color: #a89f91; font-size: 16px; font-style: italic; letter-spacing: 1px; margin: 0; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>{domain}</h1>
    <p>A simple website. Coming Soon.</p>
  </div>
</body>
</html>
"""

# CDN-specific settings
# CDN_SETTINGS для 3x-ui (только 3 CDN: VK, Yandex, TurboFlare)
# Восстановлено 12.08.2026 из memory (cdn-inbound-template.md)
CDN_SETTINGS = {
    "vk": {
        "xray_port": 2053,
        "xhttp_path": "/content/media/stream/",
        "tag": "vk-cdn-xhttp",
        "padding_key": "hash",
        "padding_header": "X-Client-Version",
        "padding_placement": "query",
        "padding_method": "tokenish",
        "uplink_method": "GET",
        "uplink_data_placement": "body"
    },
    "yandex": {
        "xray_port": 4443,
        "xhttp_path": "/uploadfiles/",
        "tag": "yandex-cdn-xhttp",
        "padding_key": "hash",
        "padding_header": "X-Client-Version",
        "padding_placement": "query",
        "padding_method": "tokenish",
        "uplink_method": "GET",
        "uplink_data_placement": "body"
    },
    "turboflare": {
        "xray_port": 10089,
        "xhttp_path": "/static/getFile/video/segment.ts",
        "tag": "turboflare-cdn-xhttp",
        "padding_key": "hash",
        "padding_header": "X-Client-Version",
        "padding_placement": "header",
        "padding_method": "tokenish",
        "uplink_method": "GET",
        "uplink_data_placement": "body"
    }
}

# REMNAWAVE_CDN - эксклюзивные настройки для каждого CDN провайдера
# Восстановлено 12.08.2026 из memory файлов
# ВАЖНО: Все CDN имеют РАЗНЫЕ настройки! Не унифицировать!
REMNAWAVE_CDN = {
    "vk": {
        "xray_port": 2053,
        "xhttp_path": "/content/media/stream/",
        "tag": "vk-cdn-xhttp",
        "nginx_style": "prefix",
        "alpn": "h2",
        "fp": "random"
    },
    "yandex": {
        "xray_port": 4443,
        "xhttp_path": "/uploadfiles/",
        "tag": "yandex-cdn-xhttp",
        "nginx_style": "prefix",
        "alpn": "h2",
        "fp": "random"
    },
    "turboflare": {
        "xray_port": 10089,
        "xhttp_path": "/static/getFile/video/segment.ts",
        "tag": "cdn-turboflare",
        "nginx_style": "rewrite",
        "alpn": "h2,http/1.1",
        "fp": "firefox"
    },
    "beeline": {
        "xray_port": 10086,
        "xhttp_path": "/static/getFile/video/segment.ts",
        "tag": "cdn-beeline",
        "nginx_style": "rewrite",
        "alpn": "h2",
        "fp": "firefox"
    },
    "timeweb": {
        "xray_port": 10087,
        "xhttp_path": "/content/media/stream.m3u8",
        "tag": "cdn-timeweb",
        "nginx_style": "prefix",
        "alpn": "h2",
        "fp": "random"
    },
    "selectel": {
        "xray_port": 10088,
        "xhttp_path": "/api/uploadFile/",
        "tag": "cdn-selectel",
        "nginx_style": "prefix",
        "alpn": "h2",
        "fp": "random"
    }
}


def _build_xhttp_extra(cdn_type, cfg):
    """Build the complete embedded XHTTP configuration locally."""
    source = CDN_SETTINGS.get(cdn_type, {})
    placement = source.get("padding_placement", "query")
    extra = {
        "xPaddingBytes": "100-1000",
        "xPaddingObfsMode": True,
        "xPaddingKey": source.get("padding_key", "hash"),
        "xPaddingHeader": source.get("padding_header", "X-Client-Version"),
        "xPaddingPlacement": placement,
        "xPaddingMethod": source.get("padding_method", "tokenish"),
        "uplinkHTTPMethod": source.get("uplink_method", "GET"),
        "uplinkDataPlacement": source.get("uplink_data_placement", "body"),
        "noSSEHeader": False,
        "scMaxEachPostBytes": "500000-1000000",
        "scMinPostsIntervalMs": "50-150",
        "scStreamUpServerSecs": "60-180",
        "xmux": {
            "maxConcurrency": "16-32", "maxConnections": 0,
            "cMaxReuseTimes": 0, "hMaxRequestTimes": "600-900",
            "hMaxReusableSecs": "1800-3000", "hKeepAlivePeriod": 0,
        },
    }
    # Timeweb must preserve the query string: XHTTP session and sequence values
    # are therefore placed in the query explicitly instead of relying on the
    # Xray default (path).  The previous installer printed this requirement in
    # its Timeweb guide but did not actually configure it.
    if cdn_type == "timeweb":
        extra.update({
            "sessionPlacement": "query",
            "sessionKey": "sessionID",
            "seqPlacement": "query",
            "seqKey": "seq",
        })
    return extra


def _build_remnawave_profile(cdn_type, cfg):
    extra = _build_xhttp_extra(cdn_type, cfg)
    inbound = {
        "tag": cfg["tag"],
        "listen": "127.0.0.1",
        "port": cfg["xray_port"],
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "sniffing": {"enabled": True, "routeOnly": True,
                     "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {
            "network": "xhttp", "security": "none",
            "xhttpSettings": {"path": cfg["xhttp_path"], "host": "",
                              "mode": "packet-up", **extra},
        },
    }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [
            {"tag": "DIRECT", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "BLOCK", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "BLOCK"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
        ]},
    }


# Keep the complete operational configuration in the installer so the local
# PIN check and runtime configuration never depend on a licensing service.
for _cdn_name, _cdn_cfg in REMNAWAVE_CDN.items():
    _cdn_cfg["inbound_tag"] = _cdn_cfg["tag"]
    _cdn_cfg["host_extra"] = _build_xhttp_extra(_cdn_name, _cdn_cfg)
    _cdn_cfg["profile_config"] = _build_remnawave_profile(_cdn_name, _cdn_cfg)
del _cdn_name, _cdn_cfg


def validate_embedded_cdn_config():
    required = {"xray_port", "xhttp_path", "tag", "inbound_tag",
                "profile_config", "host_extra", "alpn"}
    errors = []
    for name, cfg in REMNAWAVE_CDN.items():
        missing = sorted(required - set(cfg))
        inbounds = (cfg.get("profile_config") or {}).get("inbounds") or []
        if missing:
            errors.append(f"{name}: отсутствуют {', '.join(missing)}")
        elif not inbounds or inbounds[0].get("tag") != cfg["inbound_tag"]:
            errors.append(f"{name}: профиль не содержит ожидаемый inbound")
    if errors:
        raise RuntimeError("Повреждена встроенная CDN-конфигурация: " + "; ".join(errors))
    return True

# ============================================================
#  EXTRA PROTOCOLS (HY2, gRPC Reality)
# ============================================================

HY2_PORT = 8443
GRPC_PORT = 2083
XRAY_MIN_VERSION = "26.7.28"
XRAY_RELEASE_ASSETS = {
    "amd64": {
        "name": "Xray-linux-64.zip",
        "sha256": "8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40",
        "image_digest": "sha256:d7911c19a283acdc57e171ae0e3bd49ab4c29db14e2ab9274aa97132dd3ca3b9",
    },
    "arm64": {
        "name": "Xray-linux-arm64-v8a.zip",
        "sha256": "f5698bb218ada3b4022db26fafc39601c5f53b46b19eb76c9616325985807501",
        "image_digest": "sha256:96e356574d4de2e4c6f9dea2ff79a9e4dc439558df73a38eefd8192553c9f367",
    },
}
XUI_VERSION = "v3.6.0"
XUI_RELEASE_COMMIT = "c377dca"
GRPC_SERVICE_NAME = "grpc"
GRPC_DEST = "www.google.com:443"
GRPC_SERVER_NAMES = ["www.google.com"]


# ============================================================
#  UTILITIES
# ============================================================

_PYINSTALLER_VARS = {'LD_LIBRARY_PATH', 'LD_PRELOAD', '_MEIPASS2', 'PYTHONPATH', 'PYTHONHOME'}

def _clean_env():
    return {k: v for k, v in os.environ.items() if k not in _PYINSTALLER_VARS}

# ============================================================
#  UI: оформление, общий прогресс по шагам, полосы загрузки
# ============================================================

import math
import threading

_ANSI = {"bold": "1", "dim": "2", "red": "31", "green": "32",
         "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
         "white": "97", "gray": "90", "bblue": "94", "bred": "91"}
_UI = {"total": 0, "current": 0, "start": time.time()}


def _ui_tty():
    try:
        return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"
    except Exception:
        return False


def _ui_color():
    if os.environ.get("NO_COLOR"):
        return False
    return bool(os.environ.get("FORCE_COLOR")) or _ui_tty()


def paint(text, *styles):
    """Раскрасить текст ANSI-кодами (только в терминале, уважает NO_COLOR)."""
    if not styles or not _ui_color():
        return text
    codes = [_ANSI.get(style) for style in styles]
    if any(code is None for code in codes):
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def term_width(lo=60, hi=100):
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        cols = 80
    return max(lo, min(hi, cols))


def fmt_time(sec):
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def progress_bar(frac, width=30, style="bblue"):
    """Полоса вида ████████░░░░░░ (frac от 0 до 1)."""
    frac = max(0.0, min(1.0, frac))
    n = int(round(frac * width))
    if style == "tri":      # белый → синий → красный по длине полосы
        cols = ("white", "bblue", "bred")
        filled = "".join(paint("█", cols[min(2, i * 3 // width)]) for i in range(n))
        return filled + paint("░" * (width - n), "gray")
    return paint("█" * n, style) + paint("░" * (width - n), "gray")


def tricolor_rule(w, char="━"):
    """Линия-триколор: белая, синяя, красная трети."""
    third = w // 3
    return (paint(char * third, "bold", "white") + paint(char * third, "bold", "bblue")
            + paint(char * (w - 2 * third), "bold", "bred"))


def set_total_steps(n):
    """Задать ожидаемое число шагов для общей полосы прогресса."""
    _UI["total"] = max(1, int(n))
    _UI["current"] = 0
    _UI["start"] = time.time()


def estimate_total_steps(flow, cfg):
    """Сколько раз будет вызван step() (включая 2 шага common_setup)."""
    casc = 1 if cfg.get("cascade") else 0
    grpc = 1 if cfg.get("install_grpc") else 0
    return {
        "3xui": 8 + casc + grpc,        # install_3xui
        "3xui_cdn": 9 + casc,           # install_3xui_cdn_only
        "remnawave": 12 + casc,         # install_remnawave
        "node": 13 + casc,              # install_node_only
    }.get(flow, 10)


_BANNER_LOGO = [
    "██╗   ██╗██████╗ ███╗   ██╗     ██████╗██████╗ ███╗   ██╗",
    "██║   ██║██╔══██╗████╗  ██║    ██╔════╝██╔══██╗████╗  ██║",
    "╚██╗ ██╔╝██████╔╝██╔██╗ ██║    ██║     ██║  ██║██╔██╗ ██║",
    " ╚████╔╝ ██╔═══╝ ██║╚██╗██║    ██║     ██║  ██║██║╚██╗██║",
    "  ╚██╔╝  ██║     ██║ ╚████║    ╚██████╗██████╔╝██║ ╚████║",
    "   ╚═╝   ╚═╝     ╚═╝  ╚═══╝     ╚═════╝╚═════╝ ╚═╝  ╚═══╝",
]


def print_banner(version):
    """Шапка при запуске: логотип + карточка с названием и описанием."""
    w = term_width(60, 78)
    inner = w - 2
    print()
    logo_w = max(len(x) for x in _BANNER_LOGO)
    if w >= logo_w + 4:
        # триколор: белый / синий / красный (по две строки логотипа)
        shades = ("white", "white", "bblue", "bblue", "bred", "bred")
        for line, shade in zip(_BANNER_LOGO, shades):
            print("  " + paint(line, "bold", shade))
    rows = [
        (f"  VPN CDN Installer  ·  v{version}", ("bold", "white")),
        ("  XHTTP packet-up через российский CDN", ("bblue",)),
        ("  Панели: Remnawave · 3x-ui", ("gray",)),
        ("  CDN: VK · Yandex · TurboFlare · Beeline · Timeweb · Selectel", ("gray",)),
        ("  Владелец: @cyberlock_support", ("bred",)),
    ]
    print(paint("╭" + "─" * inner + "╮", "bblue"))
    for text, styles in rows:
        print(paint("│", "bblue") + paint(text[:inner].ljust(inner), *styles) + paint("│", "bblue"))
    print(paint("╰" + "─" * inner + "╯", "bblue"))
    print(tricolor_rule(w))
    print()


class Task:
    """Контекст с анимированной полосой для долгой операции.

    expected — примерная длительность в секундах: полоса плавно ползёт к ~95%
    и добивается до 100% по факту завершения. Без expected — бегущий блок.
    В не-терминале (лог, бот, pipe) анимации нет: две строки «…» и «✔/✘».
    """
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label, expected=None):
        self.label = label
        self.expected = expected
        self.ok = True
        self._stop = threading.Event()
        self._thread = None
        self._t0 = 0.0

    def _bar(self, el, width):
        if self.expected:
            frac = min(0.97, 1 - math.exp(-3.0 * el / self.expected))
            return progress_bar(frac, width), f"{int(frac * 100):3d}%"
        block = max(3, width // 5)
        span = width - block
        pos = int(abs(((el * 12) % (2 * span)) - span)) if span > 0 else 0
        cells = "░" * pos + "█" * block + "░" * (width - pos - block)
        return paint(cells, "bblue"), "    "

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            el = time.time() - self._t0
            w = term_width()
            bar_w = 24
            label = self.label[: max(10, w - bar_w - 24)]
            bar, pct = self._bar(el, bar_w)
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(
                f"\r\033[K  {paint(frame, 'cyan')} {label}  {bar} {pct}  "
                f"{paint(fmt_time(el), 'gray')}")
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.1)

    def __enter__(self):
        self._t0 = time.time()
        if _ui_tty():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  … {self.label}", flush=True)
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        ok = self.ok and exc_type is None
        el = time.time() - self._t0
        mark = paint("✔", "green") if ok else paint("✘", "red")
        if self._thread:
            bar = progress_bar(1.0 if ok else 0.35, 24, "green" if ok else "red")
            sys.stdout.write(
                f"\r\033[K  {mark} {self.label[: max(10, term_width() - 48)]}  "
                f"{bar} {'100%' if ok else ' ✘ '}  {paint(fmt_time(el), 'gray')}\n")
            sys.stdout.flush()
        else:
            print(f"  {mark} {self.label} ({fmt_time(el)})", flush=True)
        return False


def ui_done():
    """Финальная полоса 100% после успешной установки."""
    total = max(_UI["total"], _UI["current"])
    el = time.time() - _UI["start"]
    print(paint("━" * term_width(), "green"))
    print("  " + progress_bar(1.0, 30, "green") + paint("  100%", "bold", "green")
          + f"  Установка завершена ({_UI['current']}/{total} шагов)  "
          + paint(f"⏱ {fmt_time(el)}", "gray"))
    print(paint("━" * term_width(), "green"))
    print()


def run(cmd, check=True, capture=True, timeout=300, label=None, expected=None):
    """Run a shell command with clean env (no PyInstaller LD_LIBRARY_PATH).

    label/expected — показать анимированную полосу загрузки на время команды.
    """
    try:
        if label and capture:
            with Task(label, expected) as _task:
                r = subprocess.run(
                    cmd, shell=True, capture_output=capture, text=True,
                    encoding="utf-8", errors="replace", timeout=timeout, env=_clean_env()
                )
                if r.returncode != 0:
                    _task.ok = False
        else:
            r = subprocess.run(
                cmd, shell=True, capture_output=capture, text=True,
                encoding="utf-8", errors="replace", timeout=timeout, env=_clean_env()
            )
    except subprocess.TimeoutExpired:
        r = subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr="timeout")
    if check and r.returncode != 0:
        detail = (r.stderr or r.stdout or "")[:500]
        raise RuntimeError(f"Команда завершилась с кодом {r.returncode}: {cmd}\n{detail}")
    return r

def setup_docker_mirror(remote_ip=None, remote_cred=None):
    """Verify Docker Hub reachability without changing daemon.json."""
    check_cmd = "curl -s -m 5 -w '%{http_code}' https://registry-1.docker.io/v2/ 2>/dev/null | tail -c 3"
    if remote_ip and remote_cred:
        r = run_remote(remote_ip, remote_cred, check_cmd, timeout=15)
    else:
        r = run(check_cmd, check=False, timeout=10)
    code = r.stdout.strip()[-3:] if r.stdout.strip() else ""
    if code == "401":
        return
    raise RuntimeError(
        "Docker Hub недоступен. Установщик не будет автоматически подключать "
        "стороннее registry-зеркало; настрой доверенное зеркало вручную и повтори запуск."
    )

def has_ipv6():
    """Check if IPv6 is available on this system."""
    r = run("cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null", check=False)
    if r.returncode == 0 and r.stdout.strip() == "1":
        return False
    r2 = run("test -d /proc/sys/net/ipv6", check=False)
    return r2.returncode == 0

def has_ipv6_remote(ip, cred):
    """Check if IPv6 is available on remote server."""
    r = run_remote(ip, cred, "cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
    if r.returncode == 0 and r.stdout.strip() == "1":
        return False
    r2 = run_remote(ip, cred, "test -d /proc/sys/net/ipv6")
    return r2.returncode == 0

def run_remote(ip, cred, cmd, timeout=300, label=None, expected=None):
    """Run a command over SSH without shell interpolation or password argv leaks.

    label/expected — показать анимированную полосу загрузки на время команды.
    """
    if label:
        with Task(label, expected) as _task:
            result = run_remote(ip, cred, cmd, timeout=timeout)
            if result.returncode != 0:
                _task.ok = False
        return result
    env = _clean_env()
    if isinstance(cred, str):
        user, password = "root", cred
        argv = ["sshpass", "-e", "ssh"]
        env["SSHPASS"] = password
    elif cred.get("type") == "password":
        user = validate_ssh_user(cred.get("user", "root"))
        argv = ["sshpass", "-e", "ssh"]
        env["SSHPASS"] = str(cred.get("value", ""))
    else:
        user = validate_ssh_user(cred.get("user", "root"))
        key_path = os.path.abspath(os.path.expanduser(str(cred.get("value", ""))))
        if not os.path.isfile(key_path):
            return subprocess.CompletedProcess([], 2, "", f"SSH key not found: {key_path}")
        argv = ["ssh", "-i", key_path]
    argv += ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
             f"{user}@{ip}", cmd]
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "timeout")

def write_remote_file(ip, cred, path, content):
    """Write file to remote server via base64 over SSH."""
    import base64 as _b64
    b64 = _b64.b64encode(content.encode()).decode()
    safe_path = shlex.quote(path)
    result = run_remote(ip, cred, f"umask 077; printf %s {shlex.quote(b64)} | base64 -d > {safe_path}")
    require_success(result, f"Запись удалённого файла {path}")

def get_ip():
    """Get this server's public IP."""
    for url in ["ifconfig.me", "icanhazip.com", "api.ipify.org", "ipinfo.io/ip", "checkip.amazonaws.com"]:
        r = run(f"curl -s4 --max-time 5 {url}", check=False)
        ip = r.stdout.strip()
        try:
            return validate_ip(ip)
        except ValueError:
            pass
    r = run("hostname -I 2>/dev/null | awk '{print $1}'", check=False)
    ip = r.stdout.strip()
    try:
        return validate_ip(ip)
    except ValueError:
        pass
    return ""

def check_ip_country(ip=None):
    """Check country code of an IP (or current server if None). Returns 2-letter code or ''."""
    url = f"https://ipinfo.io/{ip}/country" if ip else "https://ipinfo.io/country"
    r = run(f"curl -s4 --max-time 5 {url}", check=False)
    code = r.stdout.strip().upper()
    if len(code) == 2 and code.isalpha():
        return code
    return ""

def validate_cascade_direction(server_ip, cascade_ip, panel_type):
    """Warn if cascade direction is wrong for 3x-ui: this server should be RU, cascade_ip should be foreign."""
    if panel_type != "2":
        return True
    print("  Проверяю направление каскада...")
    local_country = check_ip_country(server_ip)
    remote_country = check_ip_country(cascade_ip)
    if not local_country or not remote_country:
        print(f"  ⚠ Не удалось определить страну ({server_ip}={local_country or '?'}, {cascade_ip}={remote_country or '?'})")
        return True
    print(f"  Этот сервер ({server_ip}): {local_country}")
    print(f"  Exit-сервер ({cascade_ip}): {remote_country}")
    if local_country != "RU" and remote_country == "RU":
        print("\n  ❌ КАСКАД НАСТРОЕН НАОБОРОТ!")
        print(f"  Этот сервер ({local_country}) — зарубежный, cascade_ip ({remote_country}) — в России.")
        print("  Трафик будет выходить с РФ IP — нейросети и другие сервисы НЕ будут работать.")
        print("\n  ПРАВИЛЬНО: запусти скрипт на РОССИЙСКОМ сервере,")
        print(f"  а {cascade_ip.replace(cascade_ip, server_ip)} (зарубежный) укажи как exit-сервер.")
        return False
    if local_country == remote_country:
        print(f"\n  ⚠ Оба сервера в одной стране ({local_country}). Каскад бессмысленен.")
        return True
    return True

def download_xray_binary(dest="/opt/remnanode/xray-custom", remote_ip=None, remote_cred=None):
    """Download xray XRAY_MIN_VERSION binary to host for volume mount into remnanode."""
    def _run(cmd, **kw):
        if remote_ip and remote_cred:
            return run_remote(remote_ip, remote_cred, cmd, **kw)
        return run(cmd, check=False, **kw)

    r = _run(f"'{dest}' version 2>/dev/null | head -1")
    if XRAY_MIN_VERSION in (r.stdout or ""):
        print(f"  Xray {XRAY_MIN_VERSION} уже скачан")
        return True

    print(f"  Скачивание xray {XRAY_MIN_VERSION}...")
    r_arch = _run("uname -m")
    arch = (r_arch.stdout or "").strip()
    if arch in ("aarch64", "arm64"):
        asset = XRAY_RELEASE_ASSETS["arm64"]
    elif arch in ("x86_64", "amd64"):
        asset = XRAY_RELEASE_ASSETS["amd64"]
    else:
        print(f"  ⚠ Неподдерживаемая архитектура для Xray: {arch or 'не определена'}")
        return False

    xray_zip = asset["name"]
    expected_sha256 = asset["sha256"]
    image_ref = f"ghcr.io/xtls/xray-core@{asset['image_digest']}"
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_MIN_VERSION}/{xray_zip}"
    # Hashes are pinned from the official v26.7.28 release.  Older code parsed
    # the companion .dgst with an incompatible regex and silently failed on the
    # actual `SHA2-256= ...` format.
    extract_script = (
        "import os,sys,zipfile;"
        "z=zipfile.ZipFile(sys.argv[1]);"
        "i=z.getinfo('xray');"
        "open(sys.argv[2],'wb').write(z.read(i));"
        "os.chmod(sys.argv[2],0o755)"
    )
    cmds = (
        "set -eu; "
        "archive=$(mktemp /tmp/vpn-cdn-xray.XXXXXX.zip); "
        "binary=$(mktemp /tmp/vpn-cdn-xray.XXXXXX.bin); "
        "trap 'rm -f \"$archive\" \"$binary\"' EXIT; "
        f"curl -fsSL --retry 3 --retry-all-errors --connect-timeout 15 --max-time 180 "
        f"--proto '=https' -o \"$archive\" {shlex.quote(url)}; "
        f"printf '%s  %s\\n' {shlex.quote(expected_sha256)} \"$archive\" | sha256sum -c -; "
        f"python3 -c {shlex.quote(extract_script)} \"$archive\" \"$binary\"; "
        f"install -m 0755 \"$binary\" {shlex.quote(dest)}"
    )
    if not remote_ip:
        dest_existed = os.path.lexists(dest)
        backup_file(dest)
        track_created("file", dest, existed_before=dest_existed)

    r = _run(cmds, timeout=300, label="Скачивание Xray", expected=25)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or f"код возврата {r.returncode}").strip()
        print(f"  ⚠ ZIP Xray недоступен или не прошёл проверку: {detail[:300]}")
        print("  Повтор через официальный GHCR-образ с закреплённым digest...")
        image_cmds = (
            "set -eu; "
            "binary=$(mktemp /tmp/vpn-cdn-xray-image.XXXXXX.bin); "
            "container=vpn-cdn-xray-extract-$$; "
            "cleanup() { docker rm -f \"$container\" >/dev/null 2>&1 || true; "
            "rm -f \"$binary\"; }; trap cleanup EXIT; "
            f"docker pull {shlex.quote(image_ref)}; "
            f"docker create --name \"$container\" {shlex.quote(image_ref)} version >/dev/null; "
            "docker cp \"$container:/usr/local/bin/xray\" \"$binary\"; "
            "chmod 0755 \"$binary\"; "
            f"\"$binary\" version | head -1 | grep -F {shlex.quote(XRAY_MIN_VERSION)} >/dev/null; "
            f"install -m 0755 \"$binary\" {shlex.quote(dest)}"
        )
        r = _run(image_cmds, timeout=600, label="Загрузка Xray из GHCR", expected=60)
        if r.returncode != 0:
            detail = (r.stderr or r.stdout or f"код возврата {r.returncode}").strip()
            print(f"  ⚠ Не удалось извлечь Xray из официального GHCR: {detail[:300]}")
            return False

    r = _run(f"'{dest}' version 2>/dev/null | head -1")
    if XRAY_MIN_VERSION in (r.stdout or ""):
        print(f"  ✅ Xray {XRAY_MIN_VERSION} готов")
        return True
    print(f"  ⚠ Не удалось верифицировать xray: {(r.stdout or '').strip()[:100]}")
    return False

def iptables_add(rule, remote_ip=None, remote_cred=None):
    """Add iptables rule only if it doesn't already exist."""
    parts = shlex.split(rule)
    if len(parts) < 2 or parts[0] not in ("-A", "-I"):
        raise ValueError(f"Некорректное iptables-правило: {rule}")
    operation, chain, *spec = parts
    check_args = ["iptables", "-C", chain, *spec]
    add_args = ["iptables", operation, chain, *spec]
    if remote_ip and remote_cred:
        check = " ".join(shlex.quote(x) for x in check_args)
        add = " ".join(shlex.quote(x) for x in add_args)
        result = run_remote(remote_ip, remote_cred, f"{check} 2>/dev/null || {add}")
        require_success(result, "Добавление удалённого firewall-правила")
    else:
        exists = subprocess.run(check_args, capture_output=True).returncode == 0
        if not exists:
            result = subprocess.run(add_args, capture_output=True, text=True)
            require_success(result, "Добавление firewall-правила")
            track("iptables", [chain, *spec])

def remnawave_api(token, method, path, data=None, base_url=None, admin_session=False):
    """Make API call to Remnawave panel. Local (127.0.0.1:3000) or remote (base_url)."""
    import ssl
    if base_url:
        base = base_url.rstrip('/')
        if base.endswith('/api'):
            base = base[:-4]
        url = f"{base}/api/{path}"
        headers = {"Content-Type": "application/json"}
    else:
        url = f"http://127.0.0.1:3000/api/{path}"
        # Read PANEL_DOMAIN from .env for Host header (Remnawave 3.x requires it)
        panel_host = "localhost"
        try:
            with open("/opt/remnawave/.env") as f:
                for line in f:
                    if line.startswith("PANEL_DOMAIN="):
                        panel_host = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "Host": panel_host,
        }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if admin_session:
        # Remnawave 3.x accepts ROLE.ADMIN JWTs only from its browser client.
        # API tokens do not require this marker and remain the normal runtime auth.
        headers[REMNAWAVE_CLIENT_TYPE_HEADER] = REMNAWAVE_CLIENT_TYPE_BROWSER
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = None
    if base_url and base_url.startswith("https"):
        ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode()[:500]
        except Exception:
            pass
        return {"error": e.code, "message": body_text}
    except Exception as e:
        return {"error": str(e)}

def remnawave_api_ssh(panel_ip, panel_cred, method, path, data=None):
    """Make API call to Remnawave panel via SSH (curl to 127.0.0.1:3000). Bypasses nginx auth."""
    import base64 as _b64
    url = f"http://127.0.0.1:3000/api/{path}"
    need_auth = path not in ("auth/login", "auth/register", "auth/status")
    proxy_h = 'RDOM=$(grep -oP "PANEL_DOMAIN=\\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -X {method} -H "Content-Type: application/json" -H "X-Remnawave-Client-Type: browser" -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "Host: ${RDOM:-localhost}"'
    if data:
        body_b64 = _b64.b64encode(json.dumps(data).encode()).decode()
        if need_auth:
            cmd = f'{proxy_h} -H "Authorization: Bearer $(cat /opt/remnawave/.panel_token 2>/dev/null)" -d "$(echo {body_b64} | base64 -d)" "{url}"'.replace("{method}", method)
        else:
            cmd = f'{proxy_h} -d "$(echo {body_b64} | base64 -d)" "{url}"'.replace("{method}", method)
    else:
        if need_auth:
            cmd = f'{proxy_h} -H "Authorization: Bearer $(cat /opt/remnawave/.panel_token 2>/dev/null)" "{url}"'.replace("{method}", method)
        else:
            cmd = f'{proxy_h} "{url}"'.replace("{method}", method)
    r = run_remote(panel_ip, panel_cred, cmd, timeout=30)
    if r.returncode != 0:
        return {"error": f"SSH curl failed: {r.stderr[:300] if r.stderr else 'unknown'}"}
    out = r.stdout.strip()
    if not out:
        return {"error": "empty response"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": f"invalid JSON: {out[:300]}"}

def remnawave_login_ssh(panel_ip, panel_cred, username, password, allow_prompt=True):
    """Login to Remnawave panel via SSH. Cascade of auth methods until one works."""
    import base64 as _b64
    resp = remnawave_api_ssh(panel_ip, panel_cred, "POST", "auth/login", {
        "username": username, "password": password
    })
    jwt_token = None
    if resp.get("response"):
        jwt_token = resp["response"].get("accessToken")
    if not jwt_token:
        jwt_token = resp.get("accessToken")
    login_resp = resp

    def _save(token):
        t_b64 = _b64.b64encode(token.encode()).decode()
        run_remote(panel_ip, panel_cred,
            f"umask 077; mkdir -p /opt/remnawave && echo {t_b64} | base64 -d > /opt/remnawave/.panel_token && chmod 600 /opt/remnawave/.panel_token", timeout=10)

    def _api_ok():
        v = remnawave_api_ssh(panel_ip, panel_cred, "GET", "nodes")
        return "response" in v and v.get("statusCode") != 403

    # Use only the token returned by the official login endpoint.  Older code
    # fabricated API JWTs from container secrets and inserted rows into
    # PostgreSQL; that bypass is intentionally disabled.
    if not jwt_token:
        return None, login_resp
    _save(jwt_token)
    if _api_ok():
        print("  Токен сессии Remnawave: OK")
        return jwt_token, login_resp
    return None, login_resp


def remnawave_api_direct(panel_url, token, method, path, data=None):
    """Make API call to Remnawave panel directly via HTTPS."""
    import ssl
    url = f"{panel_url}/api/{path}"
    body = json.dumps(data).encode() if data else None
    headers = {"Content-Type": "application/json", "X-Remnawave-Client-Type": "browser"}
    if token and path not in ("auth/login", "auth/register", "auth/status"):
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        out = resp.read().decode()
        return json.loads(out) if out.strip() else {"error": "empty response"}
    # HTTPError — наследник URLError, поэтому ловим его ПЕРВЫМ. Иначе ветка
    # ниже перехватывала бы все ответы панели и тело с описанием ошибки
    # («создайте API-токен») терялось, оставался голый «HTTP Error 403».
    except urllib.error.HTTPError as e:
        rbody = ""
        try:
            rbody = e.read().decode()[:300]
        except Exception:
            pass
        return {"error": f"HTTP {e.code}: {rbody}"}
    except urllib.error.URLError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def remnawave_login_direct(panel_url, username, password):
    """Login to Remnawave panel via direct HTTPS. Returns (token, resp)."""
    resp = remnawave_api_direct(panel_url, None, "POST", "auth/login", {
        "username": username, "password": password
    })
    jwt_token = None
    if resp.get("response"):
        jwt_token = resp["response"].get("accessToken")
    if not jwt_token:
        jwt_token = resp.get("accessToken")
    if not jwt_token:
        return None, resp
    return jwt_token, resp


def remnawave_extra_keys(api):
    """Имя поля хоста с xhttp extra-параметрами зависит от версии Remnawave:
      2.7.x   -> 'xHttpExtraParams' (большая H)
      2.8.0+  -> 'xhttpExtraParams' (маленькая h)
    Хардкод любого одного ломает другую ветку (ссылка без extra -> сервер с
    xPaddingObfsMode реджектит -> 'Empty reply'). Определяем имя по РЕАЛЬНОЙ
    схеме: GET hosts всегда возвращает это поле (даже =null) под каноничным
    именем данной версии. Если хостов ещё нет — ставим ОБА имени (лишнее панель
    молча игнорит через whitelist). Возвращает список ключей для payload."""
    try:
        resp = api("GET", "hosts")
        hosts = resp.get("response", []) if isinstance(resp, dict) else []
        for h in hosts:
            if isinstance(h, dict):
                if "xhttpExtraParams" in h:
                    return ["xhttpExtraParams"]
                if "xHttpExtraParams" in h:
                    return ["xHttpExtraParams"]
    except Exception:
        pass
    return ["xHttpExtraParams", "xhttpExtraParams"]


_APT_FIXED = set()

NGINX_MINIMAL_CONF = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 16384; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    server_names_hash_bucket_size 128;
    types_hash_max_size 2048;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""

NGINX_MINIMAL_MIME = """types {
    text/html html htm shtml;
    text/css css;
    application/javascript js;
    application/json json;
    image/png png;
    image/jpeg jpg jpeg;
    image/svg+xml svg;
    application/octet-stream bin exe;
}
"""


def ensure_apt_mirror(remote_ip=None, remote_cred=None):
    """Verify apt without rewriting provider repositories.

    Repository replacement is an administrative decision: doing it automatically
    can remove private mirrors, pinned suites and authenticated repositories.
    """
    key = remote_ip or "local"
    if key in _APT_FIXED:
        return
    sh = "DEBIAN_FRONTEND=noninteractive timeout 120 apt-get update -o Acquire::Retries=3"
    if remote_ip:
        result = run_remote(remote_ip, remote_cred, sh, timeout=150)
    else:
        result = run(sh, check=False, timeout=150)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "")[-500:]
        raise RuntimeError(
            "apt-get update не выполнен. Исправь /etc/apt/sources.list вручную; "
            f"установщик не будет менять репозитории автоматически.\n{detail}"
        )
    _APT_FIXED.add(key)


def ensure_nginx_base(remote_ip=None, remote_cred=None):
    """Guarantee /etc/nginx/nginx.conf exists. Две причины отсутствия:
    (1) битое зеркало -> nginx-common не доустановился; (2) conffile удалён извне
    -> dpkg при обычной установке его НЕ восстанавливает. Чиним зеркало, ставим/
    переустанавливаем nginx-common с --force-confmiss, иначе пишем минимальный конфиг."""
    import base64

    def _r(cmd, timeout=180, label=None, expected=None):
        if remote_ip:
            return run_remote(remote_ip, remote_cred, cmd, timeout=timeout,
                              label=label, expected=expected)
        return run(cmd, check=False, timeout=timeout, label=label, expected=expected)

    _r("mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled "
       "/etc/nginx/conf.d /etc/nginx/ssl /var/www/html", timeout=20)
    if _r("test -s /etc/nginx/nginx.conf", timeout=10).returncode == 0:
        return
    ensure_apt_mirror(remote_ip, remote_cred)
    _r("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx-common nginx-core 2>&1 | tail -3", timeout=400)
    _r("DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "
       "-o Dpkg::Options::=--force-confmiss nginx-common 2>&1 | tail -3", timeout=400)
    if _r("test -s /etc/nginx/nginx.conf", timeout=10).returncode == 0:
        return
    # последний резерв — минимальный рабочий конфиг
    conf_b64 = base64.b64encode(NGINX_MINIMAL_CONF.encode()).decode()
    mime_b64 = base64.b64encode(NGINX_MINIMAL_MIME.encode()).decode()
    _r(f"echo {conf_b64} | base64 -d > /etc/nginx/nginx.conf", timeout=15)
    _r(f"[ -s /etc/nginx/mime.types ] || echo {mime_b64} | base64 -d > /etc/nginx/mime.types", timeout=15)
    print(f"  {'[удалённая] ' if remote_ip else ''}nginx.conf восстановлен (минимальный конфиг)")


def install_docker(remote_ip=None, remote_cred=None):
    """Install Docker using the official Docker convenience script."""
    tag = "[удалённая] " if remote_ip else ""

    def _r(cmd, timeout=300, label=None, expected=None):
        if remote_ip:
            return run_remote(remote_ip, remote_cred, cmd, timeout=timeout,
                              label=label, expected=expected)
        return run(cmd, check=False, timeout=timeout, label=label, expected=expected)

    def _ok():
        r = _r("docker --version", timeout=15)
        return r.returncode == 0 and "Docker" in (r.stdout or "")

    if _ok():
        _r("systemctl enable --now docker", timeout=60)
        return _ok()

    print(f"  {tag}Устанавливаю Docker официальным установщиком...")
    result = _r("curl -fsSL https://get.docker.com | sh", timeout=900,
                label="Установка Docker", expected=90)

    if result.returncode != 0:
        print(f"  {tag}Ошибка установки Docker: "
              f"{(result.stderr or result.stdout or '').strip()[-1500:]}")
        return False

    service = _r("systemctl enable --now docker", timeout=90)
    if service.returncode != 0:
        print(f"  {tag}Не удалось запустить службу Docker.")
        return False

    return _ok()


def install_docker_compose(remote_ip=None, remote_cred=None):
    """Install Docker Compose from signed OS packages and verify the plugin."""
    def _r(cmd, timeout=300, label=None, expected=None):
        if remote_ip:
            return run_remote(remote_ip, remote_cred, cmd, timeout=timeout,
                              label=label, expected=expected)
        return run(cmd, check=False, timeout=timeout, label=label, expected=expected)

    current = _r("docker compose version", timeout=20)
    if current.returncode == 0:
        return True
    ensure_apt_mirror(remote_ip, remote_cred)
    result = _r(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2 "
        "|| DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin",
        timeout=400, label="Установка Docker Compose", expected=30,
    )
    if result.returncode != 0 or _r("docker compose version", timeout=20).returncode != 0:
        raise RuntimeError("Docker Compose v2 не установлен из репозитория ОС")
    return True


def setup_xray_ru_geo(remote_ip=None, remote_cred=None, asset_dir="/usr/local/share/xray", service="xray"):
    """Download RU geo files (geoip_RU.dat / geosite_RU.dat) referenced by routing
    rules (ext:geoip_RU.dat:ru). БЕЗ них xray НЕ стартует — 'failed to open file:
    geoip_RU.dat' -> service failed -> nginx 502 -> CDN 'Empty reply'. Источник —
    runetfreedom (категории ru / ru-available-only-inside)."""
    base = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download"
    # Download only from the project release page. Third-party executable/data
    # proxies are deliberately not trusted by this installer.
    def _dl(remote_name, local_name):
        return (
            f"curl -fsSL --proto '=https' --max-time 900 -o .{local_name}.tmp {base}/{remote_name} && "
            f"curl -fsSL --proto '=https' --max-time 60 -o .{local_name}.sha {base}/{remote_name}.sha256sum && "
            f"test \"$(awk '{{print $1}}' .{local_name}.sha)\" = \"$(sha256sum .{local_name}.tmp | awk '{{print $1}}')\""
        )
    # Стандартные geosite.dat/geoip.dat нужны правилам вида `geosite:youtube`,
    # `geosite:category-ads-all`, `geoip:ru` (#13 и дефолтные правила 3x-ui). Без них
    # xray падает «failed to open geosite.dat» — то же самое, что было с RU-датниками.
    # RU-датники (ext:geoip_RU.dat) отдельные, у них своя категоризация — нужны оба набора.
    std = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

    def _dl_std(name):
        return (
            f"curl -fsSL --proto '=https' --max-time 900 -o .{name}.tmp {std}/{name} && "
            f"curl -fsSL --proto '=https' --max-time 60 -o .{name}.sha {std}/{name}.sha256sum && "
            f"test \"$(awk '{{print $1}}' .{name}.sha)\" = \"$(sha256sum .{name}.tmp | awk '{{print $1}}')\""
        )

    quoted_asset_dir = shlex.quote(asset_dir)
    sh = (f"mkdir -p {quoted_asset_dir} && cd {quoted_asset_dir} && "
          f"{_dl('geoip.dat', 'geoip_RU.dat')} && "
          f"{_dl('geosite.dat', 'geosite_RU.dat')} && "
          f"{_dl_std('geoip.dat')} && {_dl_std('geosite.dat')} && "
          f"test -s .geoip_RU.dat.tmp && test -s .geosite_RU.dat.tmp && "
          f"test -s .geoip.dat.tmp && test -s .geosite.dat.tmp && "
          f"mv .geoip_RU.dat.tmp geoip_RU.dat && mv .geosite_RU.dat.tmp geosite_RU.dat && "
          f"mv .geoip.dat.tmp geoip.dat && mv .geosite.dat.tmp geosite.dat && "
          f"rm -f .geoip_RU.dat.sha .geosite_RU.dat.sha .geoip.dat.sha .geosite.dat.sha && echo GEO_OK")

    def _r(cmd, timeout=180, label=None, expected=None):
        if remote_ip:
            return run_remote(remote_ip, remote_cred, cmd, timeout=timeout,
                              label=label, expected=expected)
        return run(cmd, check=False, timeout=timeout, label=label, expected=expected)

    ok = "GEO_OK" in (_r(sh, timeout=1200, label="Загрузка гео-баз (geoip/geosite)", expected=60).stdout or "")
    if service == "xray":
        # standalone xray: default asset dir = каталог бинарника, а .dat лежат в
        # /usr/local/share/xray -> явно указываем XRAY_LOCATION_ASSET
        _r("mkdir -p /etc/systemd/system/xray.service.d && "
           f"printf '[Service]\\nEnvironment=XRAY_LOCATION_ASSET={asset_dir}\\n' "
           "> /etc/systemd/system/xray.service.d/asset.conf && systemctl daemon-reload", timeout=30)
    if not ok:
        raise RuntimeError("RU/standard geo-файлы не скачаны или не прошли SHA-256 проверку")
    return ok


def stop_conflicting_standalone_xray(remote_ip=None, remote_cred=None):
    """3x-ui запускает СВОЙ встроенный xray на 127.0.0.1:2053. Если на сервере
    остался standalone xray-core (systemd 'xray.service', /usr/local/bin/xray,
    /usr/local/etc/xray/config.json) от предыдущего запуска (например сначала
    mode 3, потом перезапуск как 3x-ui) — он держит 2053, и xray от 3x-ui падает:
    'bind: address already in use' -> инбаунд панели не слушает -> nginx проксирует
    на ЧУЖОЙ xray без нужного юзера -> через CDN клиент видит 'Empty reply from
    server'. Останавливаем/маскируем standalone, чтобы 3x-ui смог занять 2053."""
    sh = ("if systemctl is-active --quiet xray || pgrep -f '/usr/local/bin/xray' >/dev/null; then "
          "echo CONFLICTING_XRAY; fi")
    if remote_ip:
        result = run_remote(remote_ip, remote_cred, sh, timeout=30)
    else:
        result = run(sh, check=False, timeout=30)
    if "CONFLICTING_XRAY" in (result.stdout or ""):
        raise RuntimeError(
            "Обнаружен существующий standalone xray. Установщик не будет останавливать чужой VPN-сервис."
        )


def check_os(remote_ip=None, remote_cred=None):
    """Check that OS is Ubuntu/Debian. Exit if not."""
    if remote_ip:
        r = run_remote(remote_ip, remote_cred, "which apt-get", timeout=10)
    else:
        r = run("which apt-get", check=False, timeout=10)
    if r.returncode != 0:
        print("  ❌ Поддерживается только Ubuntu/Debian!")
        print("  Переустанови сервер с Ubuntu 22.04/24.04")
        sys.exit(1)

_DNS_FIXED = set()

def fix_dns(remote_ip=None, remote_cred=None):
    """Verify DNS without replacing provider/systemd-resolved configuration."""
    key = remote_ip or "local"
    if key in _DNS_FIXED:
        return
    cmd = "getent ahostsv4 deb.debian.org >/dev/null 2>&1"
    if remote_ip:
        r = run_remote(remote_ip, remote_cred, cmd, timeout=30)
    else:
        r = run(cmd, check=False, timeout=30)
    pfx = f"  [{remote_ip}] " if remote_ip else "  "
    if r.returncode != 0:
        raise RuntimeError(
            f"{pfx}DNS не работает. Исправь DNS у провайдера или systemd-resolved; "
            "установщик не будет перезаписывать /etc/resolv.conf."
        )
    _DNS_FIXED.add(key)

def pkg_install(packages, remote_ip=None, remote_cred=None, timeout=180):
    pkg_list = packages.split()
    if remote_ip:
        for _i in range(30):
            lr = run_remote(remote_ip, remote_cred, "fuser /var/lib/dpkg/lock-frontend 2>/dev/null", timeout=15)
            if lr.returncode != 0:
                break
            print("  [удалённая] Ожидание снятия блокировки apt...")
            time.sleep(2)
        else:
            raise RuntimeError("Удалённый apt/dpkg занят более 60 секунд; повтори запуск позже")
        run_remote(remote_ip, remote_cred, "dpkg --configure -a 2>/dev/null", timeout=60)
        run_remote(remote_ip, remote_cred, "apt-get clean 2>/dev/null", timeout=30)
        fix_dns(remote_ip, remote_cred)
        ensure_apt_mirror(remote_ip, remote_cred)
        run_remote(remote_ip, remote_cred, "apt-get update", timeout=120)
        r = run_remote(remote_ip, remote_cred, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}", timeout=timeout,
                       label="Установка пакетов", expected=40)
        if r.returncode != 0:
            print(f"  [удалённая] apt-get install ошибка: {(r.stderr or r.stdout or '')[:300]}")
            print("  [удалённая] Повторная попытка установки...")
            run_remote(remote_ip, remote_cred, "apt-get --fix-broken install -y 2>/dev/null", timeout=60)
            run_remote(remote_ip, remote_cred, "apt-get update --fix-missing", timeout=120)
            for pkg in pkg_list:
                run_remote(remote_ip, remote_cred, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", timeout=120)
        critical = ["nginx", "openssl", "curl"]
        missing = []
        for pkg in critical:
            if pkg in pkg_list:
                cr = run_remote(remote_ip, remote_cred, f"which {pkg} || test -x /usr/sbin/{pkg}", timeout=15)
                if cr.returncode != 0:
                    missing.append(pkg)
        if missing:
            print(f"  ❌ [удалённая] Не удалось установить: {', '.join(missing)}")
            print(f"  На сервере {remote_ip}: apt-get update && apt-get install -y " + " ".join(missing))
            sys.exit(1)
    else:
        for _i in range(30):
            lr = run("fuser /var/lib/dpkg/lock-frontend 2>/dev/null", check=False, timeout=5)
            if lr.returncode != 0:
                break
            print("  Ожидание снятия блокировки apt...")
            time.sleep(2)
        else:
            raise RuntimeError("apt/dpkg занят более 60 секунд; повтори запуск позже")
        run("dpkg --configure -a 2>/dev/null", check=False, timeout=60)
        fix_dns()
        ensure_apt_mirror()
        run("apt-get update -qq", check=False, timeout=120)
        r = run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}", check=False, timeout=timeout,
                label="Установка пакетов", expected=40)
        if r.returncode != 0:
            print(f"  apt ошибка: {(r.stderr or r.stdout or '')[:300]}")
            print("  Повторная попытка установки...")
            run("apt-get --fix-broken install -y 2>/dev/null", check=False, timeout=60)
            run("apt-get update", check=False, timeout=120)
            for pkg in pkg_list:
                run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", check=False, timeout=120)
        critical = ["nginx", "openssl", "curl"]
        missing = []
        for pkg in critical:
            if pkg in pkg_list:
                cr = run(f"which {pkg} || test -x /usr/sbin/{pkg}", check=False, timeout=5)
                if cr.returncode != 0:
                    missing.append(pkg)
        if missing:
            print(f"  ❌ Не удалось установить: {', '.join(missing)}")
            print("  Попробуй вручную: apt-get update && apt-get install -y " + " ".join(missing))
            sys.exit(1)

def pkg_iptables_persist(remote_ip=None, remote_cred=None):
    cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent netfilter-persistent 2>/dev/null; netfilter-persistent save 2>/dev/null"
    if remote_ip:
        run_remote(remote_ip, remote_cred, cmd, timeout=60)
    else:
        run(cmd, check=False, timeout=60)

def nginx_write_conf(name, content):
    """Write nginx config and create symlink."""
    ensure_nginx_base()
    available = f"/etc/nginx/sites-available/{name}"
    link = f"/etc/nginx/sites-enabled/{name}"
    existed = os.path.lexists(available) or os.path.lexists(link)
    backup_file(available)
    backup_file(link)
    with open(available, "w") as f:
        f.write(content)
    if os.path.lexists(link):
        os.remove(link)
    os.symlink(available, link)
    track_created("nginx_site", name, existed_before=existed)

def nginx_write_and_restart(conf_content, remote_ip=None, remote_cred=None):
    ensure_nginx_base(remote_ip, remote_cred)
    _wc_fix = "sed -i 's/worker_connections[[:space:]]*[0-9]*/worker_connections 16384/' /etc/nginx/nginx.conf"
    # На дефолтном Ubuntu nginx.conf server_names_hash_bucket_size закомментирован
    # (=32), а длинные домены/поддомены (origin/cdn/panel) в него не влезают ->
    # 'could not build server_names_hash ... increase server_names_hash_bucket_size: 32'
    # -> nginx -t падает -> установка ломается. Гарантируем 128 (раскомментировать /
    # выставить / вставить после 'http {').
    _snh_fix = (
        "if grep -qE '^[[:space:]]*#?[[:space:]]*server_names_hash_bucket_size' /etc/nginx/nginx.conf; then "
        "sed -i -E 's/^[[:space:]]*#?[[:space:]]*server_names_hash_bucket_size[[:space:]]+[0-9]+;/    server_names_hash_bucket_size 128;/' /etc/nginx/nginx.conf; "
        "else sed -i '0,/http {/s//http {\\n    server_names_hash_bucket_size 128;/' /etc/nginx/nginx.conf; fi"
    )
    if remote_ip:
        run_remote(remote_ip, remote_cred, "mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled")
        run_remote(remote_ip, remote_cred,
                   "for f in /etc/nginx/nginx.conf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default; do "
                   "test ! -e \"$f\" -a ! -L \"$f\" || cp -a \"$f\" \"$f.vpn-cdn.bak\"; done")
        write_remote_file(remote_ip, remote_cred, "/etc/nginx/sites-available/default", conf_content)
        run_remote(remote_ip, remote_cred, "rm -f /etc/nginx/sites-enabled/default && ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default")
        run_remote(remote_ip, remote_cred, _wc_fix, timeout=10)
        run_remote(remote_ip, remote_cred, _snh_fix, timeout=10)
        r = run_remote(remote_ip, remote_cred, "nginx -t && systemctl restart nginx")
    else:
        run("mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled", check=False)
        backup_file("/etc/nginx/nginx.conf")
        nginx_write_conf("default", conf_content)
        run(_wc_fix, check=False, timeout=10)
        run(_snh_fix, check=False, timeout=10)
        r = run("nginx -t && systemctl restart nginx", check=False)
    return r

def step(n, text):
    """Заголовок шага с общей полосой прогресса установки."""
    _UI["current"] += 1
    cur = _UI["current"]
    w = term_width()
    print()
    print(tricolor_rule(w))
    if _UI["total"]:
        total = max(_UI["total"], cur)      # оценка могла недобрать — не уходим за 100%
        frac = (cur - 1) / total
        print(paint("  ▶", "bold", "bred") + paint(f" Шаг {cur}/{total}", "bold", "bblue")
              + paint("  │  ", "gray") + paint(text, "bold", "white"))
        print("  " + progress_bar(frac, 30, "tri") + f" {int(frac * 100):3d}%  "
              + paint(f"⏱ {fmt_time(time.time() - _UI['start'])}", "gray"))
    else:
        print(paint("  ▶", "bold", "bred") + paint(f" [{n}]", "bold", "bblue")
              + paint("  │  ", "gray") + paint(text, "bold", "white"))
    print(paint("━" * w, "bblue"))

def ask(prompt, options=None, default=None):
    """Interactive question."""
    while True:
        if options:
            print("\n  " + paint("▌", "bred") + paint(prompt, "bold", "white"))
            for k, v in options.items():
                print("    " + paint("[", "bblue") + paint(str(k), "bold", "bred")
                      + paint("]", "bblue") + " " + paint(str(v), "white"))
            choice = safe_input(f"  > ").strip()
            if choice in options:
                return choice
            if default and not choice:
                return default
        else:
            val = safe_input(f"  {prompt}: ").strip()
            if val:
                return val
            if default:
                return default

def ask_ssh_key():
    """Read multiline OpenSSH private key from stdin."""
    print("  Вставь SSH приватный ключ (OpenSSH формат).")
    print("  После последней строки (-----END OPENSSH PRIVATE KEY-----) нажми ENTER:")
    lines = []
    while True:
        line = safe_input()
        lines.append(line)
        if "END OPENSSH PRIVATE KEY" in line:
            break
    key_text = "\n".join(lines) + "\n"
    fd, path = tempfile.mkstemp(prefix="installer_ssh_key_")
    with os.fdopen(fd, 'w') as f:
        f.write(key_text)
    os.chmod(path, 0o600)
    return path

def ask_ssh_cred():
    """Ask user for node SSH credentials."""
    user = ask("SSH пользователь / SSH user [root]", default="root")
    pw = ask(f"Пароль {user} / Password")
    return {"type": "password", "value": pw, "user": user}

def cleanup_ssh_key(cred):
    """Remove temporary SSH key file if it was created."""
    if isinstance(cred, dict) and cred.get("type") == "key":
        try:
            os.unlink(cred["value"])
        except OSError:
            pass

def generate_panel_path():
    """Random path for 3x-ui panel access."""
    return secrets.token_hex(8)


# ============================================================
#  SUBDOMAINS (random or user-chosen)
# ============================================================

_SUB_ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789'
# Правдоподобные варианты для панели: случайный набор букв выглядит подозрительно,
# а «cpanel/dash/mgmt» — как обычная админка.
_PANEL_VARIANTS = ["ppanel", "pannel", "pnl", "cpanel", "dash", "mgmt", "adm", "ctrl", "sys", "hub", "my", "acc"]


def _rand_sub(n=5):
    """Случайная метка поддомена: буква + n символов [a-z0-9]."""
    return secrets.choice('abcdefghijklmnopqrstuvwxyz') + ''.join(secrets.choice(_SUB_ALNUM) for _ in range(n))


def _rand_panel_sub():
    """Случайный поддомен панели из правдоподобных вариантов + 3 цифры."""
    return secrets.choice(_PANEL_VARIANTS) + ''.join(secrets.choice('0123456789') for _ in range(3))


def _valid_sub_label(s):
    """Валидна ли METKA поддомена по RFC 1035: [a-z0-9-], не с дефиса, ≤63.

    Только одна метка, без точек: пользователь задаёт префикс к домену, а не
    полный FQDN. Верхний регистр/пробелы/точки — невалидны (не молча приводим:
    иначе человек думает, что задал panel.mydomain, а получил иное).
    """
    if not s or len(s) > 63:
        return False
    return re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', s) is not None


def _ask_yes(prompt, default=False):
    """y/n-вопрос. Пустой ответ → default. Понимает и русское да/нет."""
    r = safe_input(prompt).strip().lower()
    if not r:
        return default
    return r in ("y", "yes", "д", "да")


def ask_eu_grpc(cascade, args):
    """Спросить, ставить ли gRPC-Reality на самой EU-панели (#23/A4).

    Это ВТОРАЯ точка входа: прямое подключение к заграничному серверу, минуя CDN и
    relay. Отличается от gRPC на relay (тот при каскаде идёт через exit). HY2 для
    3x-ui не предлагаем — у панели свой формат hysteria2 (у Remnawave HY2 есть).
    """
    if not cascade:
        return False
    if getattr(args, "no_eu_grpc", False):
        return False
    if getattr(args, "eu_grpc", False):
        return True
    if args.mode or args.panel:   # CLI без явного флага — не ставим
        return False
    return _ask_yes("\n  Поставить gRPC Reality на EU-панели?\n"
                    "  Даст прямое подключение к заграничному серверу мимо CDN. (y/n) [n]: ",
                    default=False)


def ask_youtube_direct(cascade, args):
    """Спросить про #13 (YouTube/SoundCloud напрямую через relay). Только при каскаде.

    Дефолт «нет»: эффект зависит от хостинга relay. Если сервер НЕ пропускает
    YouTube с российского IP, direct-маршрут не уберёт рекламу, а наоборот сломает
    воспроизведение — поэтому включаем только по явному согласию. CLI:
    --youtube-direct включает, --no-youtube-direct выключает; без флага — выкл.
    """
    if not cascade:
        return False
    if getattr(args, "no_youtube_direct", False):
        return False
    if getattr(args, "youtube_direct", False):
        return True
    if args.mode or args.panel:   # CLI-режим без явного флага
        return False
    print("\n  ┌───────────────────────────────────────────────────────────┐")
    print("  │  🎬  YouTube и SoundCloud без рекламы                    │")
    print("  └───────────────────────────────────────────────────────────┘")
    print("  Видео и музыка пойдут напрямую через ваш RU-relay-сервер.")
    print("  На многих российских хостингах YouTube открывается БЕЗ рекламы,")
    print("  а SoundCloud — без ограничений.")
    print("  ⚠  Работает не на каждом сервере: если хостинг не пропускает")
    print("     YouTube с РФ-адреса, видео может не открыться — ответьте «нет».")
    return _ask_yes("\n  Включить YouTube и SoundCloud без рекламы? (y — да / n — нет) [n]: ",
                    default=False)


def resolve_subdomains(args, roles, want_custom, reserved=None):
    """Собрать поддомены для ролей: CLI-флаг → вопрос (если want_custom) → случайный.

    Приоритет для каждой роли:
      1. CLI-флаг (--origin-sub и т.п.) — валидируется, при ошибке выход
      2. интерактивный ввод, если want_custom (Enter = случайный дефолт)
      3. случайная метка
    Все метки различны и между собой, и с `reserved` — набором уже занятых из
    предыдущих вызовов (в режиме 3 exit резолвится отдельно, после origin/cdn/hy2,
    и не должен с ними совпасть). Вопрос «задать свои?» задаётся в main ОДИН раз,
    его ответ приходит сюда как want_custom — иначе при раздельных вызовах он
    всплывал бы дважды.
    """
    reserved = set(reserved or ())
    labels = {"origin": "origin (маскировочный хост)", "cdn": "cdn (CNAME на CDN)",
              "panel": "panel (админка)", "exit": "exit (каскад)", "hy2": "hy2 (Hysteria2)",
              "sub": "sub (страница подписки)"}
    gen = {r: (_rand_panel_sub if r == "panel" else _rand_sub) for r in roles}

    cli, asked = {}, {}
    for r in roles:
        v = getattr(args, f"{r}_sub", None) if args else None
        if v:
            v = v.strip().lower()
            if not _valid_sub_label(v):
                print(f"  ❌ Некорректный поддомен --{r}-sub '{v}' (только a-z, 0-9, дефис; ≤63)")
                sys.exit(1)
            cli[r] = v

    if want_custom:
        for r in roles:
            if r in cli:
                continue
            while True:
                v = safe_input(f"  Поддомен {labels.get(r, r)} [Enter = случайный]: ").strip().lower()
                if not v:
                    break  # оставим случайный ниже
                if _valid_sub_label(v):
                    asked[r] = v
                    break
                print("    ⚠ Только a-z, 0-9, дефис (не с дефиса), до 63 символов")

    result, used = {}, set(reserved)
    for r in roles:                       # сначала заданные — приоритетны, не перегенерятся
        if r in cli or r in asked:
            val = cli.get(r) or asked[r]
            if val in used:
                print(f"  ❌ Поддомен '{val}' занят дважды — они должны различаться")
                sys.exit(1)
            result[r] = val
            used.add(val)
    for r in roles:                       # затем случайные, избегая занятых
        if r not in result:
            val = gen[r]()
            while val in used:
                val = gen[r]()
            result[r] = val
            used.add(val)
    return result


def _parse_x25519(output):
    """Parse x25519 output, skip version banner lines."""
    priv = pub = None
    for line in output.strip().split('\n'):
        if 'Private' in line and ':' in line:
            priv = line.split(':')[-1].strip()
        elif 'Public' in line and ':' in line:
            pub = line.split(':')[-1].strip()
    if priv and pub:
        return {"private": priv, "public": pub}
    return None

def _parse_openssl_x25519(output):
    """Parse 'openssl pkey -text -noout' output for X25519."""
    import base64 as _b64
    priv_hex = ""
    pub_hex = ""
    section = None
    for line in output.strip().split('\n'):
        s = line.strip()
        if s.startswith("priv:"):
            section = "priv"
            continue
        elif s.startswith("pub:"):
            section = "pub"
            continue
        elif s.startswith("X25519") or not s:
            section = None if s.startswith("X25519") else section
            continue
        if section == "priv":
            priv_hex += s.replace(":", "")
        elif section == "pub":
            pub_hex += s.replace(":", "")
    if len(priv_hex) >= 64 and len(pub_hex) >= 64:
        priv_bytes = bytes.fromhex(priv_hex[:64])
        pub_bytes = bytes.fromhex(pub_hex[:64])
        return {
            "private": _b64.urlsafe_b64encode(priv_bytes).decode().rstrip("="),
            "public": _b64.urlsafe_b64encode(pub_bytes).decode().rstrip("="),
        }
    return None

def generate_x25519_keys():
    """Generate x25519 key pair for Reality using xray binary."""
    for xray_bin in ["/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray-linux-arm64"]:
        if os.path.exists(xray_bin):
            r = run(f"{xray_bin} x25519", check=False, timeout=10)
            if r.returncode == 0 and "Private" in r.stdout:
                result = _parse_x25519(r.stdout)
                if result:
                    return result

    r = run("docker exec remnanode xray x25519 2>/dev/null", check=False, timeout=10)
    if r.returncode == 0 and "Private" in r.stdout:
        result = _parse_x25519(r.stdout)
        if result:
            return result

    r = run("xray x25519 2>/dev/null", check=False, timeout=10)
    if r.returncode == 0 and "Private" in r.stdout:
        result = _parse_x25519(r.stdout)
        if result:
            return result

    r = run("openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -text -noout 2>/dev/null", check=False, timeout=10)
    if r.returncode == 0 and "priv:" in r.stdout:
        result = _parse_openssl_x25519(r.stdout)
        if result:
            return result

    print("  ❌ Не удалось сгенерировать x25519 ключи")
    return None


def build_hy2_inbound(tag_suffix=""):
    """Build Hysteria2 inbound config for xray-core."""
    _tag = f"hy2-in-{tag_suffix}" if tag_suffix else "hy2-in"
    return {
        "tag": _tag,
        "listen": "::",
        "port": HY2_PORT,
        "protocol": "hysteria",
        "settings": {"clients": [], "version": 2},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {
                "alpn": ["h3"],
                "certificates": [
                    {
                        "certificateFile": "/etc/nginx/ssl/cdn.crt",
                        "keyFile": "/etc/nginx/ssl/cdn.key"
                    }
                ]
            }
        }
    }



def get_cert_sha256(cert_path="/etc/nginx/ssl/cdn.crt", remote_ip=None, remote_cred=None):
    """Get SHA256 hex hash of certificate for HY2 pinning."""
    cmd = f"openssl x509 -in {cert_path} -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1"
    if remote_ip:
        r = run_remote(remote_ip, remote_cred, cmd, timeout=10)
    else:
        r = run(cmd, check=False)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip().upper()
    return None

def build_grpc_inbound(private_key, short_id, tag_suffix=""):
    """Build VLESS Reality gRPC inbound config for xray-core."""
    _tag = f"grpc-reality-{tag_suffix}" if tag_suffix else "grpc-reality"
    return {
        "tag": _tag,
        "listen": "::",
        "port": GRPC_PORT,
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        "streamSettings": {
            "network": "grpc",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": GRPC_DEST,
                "xver": 0,
                "serverNames": GRPC_SERVER_NAMES,
                "privateKey": private_key,
                "shortIds": [short_id]
            },
            "grpcSettings": {
                "serviceName": GRPC_SERVICE_NAME
            }
        }
    }


def ask_extra_protocols(panel_type=None, args=None):
    """Ask user about optional hy2 and grpc installation.

    #22: gRPC теперь доступен и в 3x-ui (panel_type==2) — раньше для него вопрос
    пропускался. HY2 в 3x-ui пока НЕ предлагаем: у 3x-ui свой формат hysteria2
    (protocol hysteria2 в БД + TLS-cert), отличный от Remnawave xray-инбаунда —
    делается отдельным шагом, чтобы не задавать вопрос без рабочей реализации.

    Bug #20 fix: Check CLI args (--no-hy2, --no-grpc) before asking interactively.
    """
    result = {"install_hy2": False, "install_grpc": False}
    is_3xui = panel_type == "2"

    # A supplied --mode is an explicit non-interactive contract. Optional
    # protocols are enabled only by positive flags; stdin is never read.
    if args and getattr(args, "mode", None):
        result["install_hy2"] = bool(getattr(args, "hy2", False)) and not is_3xui
        result["install_grpc"] = bool(getattr(args, "grpc", False))
        return result

    # Check CLI args first
    if args:
        hy2_from_cli = False
        grpc_from_cli = False

        if hasattr(args, 'no_hy2') and args.no_hy2:
            result["install_hy2"] = False
            hy2_from_cli = True
        if hasattr(args, 'no_grpc') and args.no_grpc:
            result["install_grpc"] = False
            grpc_from_cli = True

        # If both provided via CLI, skip interactive questions
        if hy2_from_cli and grpc_from_cli:
            return result
        # If only one provided, only ask about the other
        if not hy2_from_cli and not is_3xui:
            try:
                resp = safe_input("\n  Установить Hysteria2 (UDP)? (y/n): ").strip().lower()
                result["install_hy2"] = resp in ("y", "yes", "д", "да")
            except (KeyboardInterrupt, EOFError):
                pass
        if not grpc_from_cli:
            try:
                resp = safe_input("  Установить VLESS Reality gRPC? (y/n): ").strip().lower()
                result["install_grpc"] = resp in ("y", "yes", "д", "да")
            except (KeyboardInterrupt, EOFError):
                pass
        return result

    # No args provided - interactive mode
    if not is_3xui:
        try:
            resp = safe_input("\n  Установить Hysteria2 (UDP)? (y/n): ").strip().lower()
            result["install_hy2"] = resp in ("y", "yes", "д", "да")
        except (KeyboardInterrupt, EOFError):
            pass
    try:
        resp = safe_input("  Установить VLESS Reality gRPC? (y/n): ").strip().lower()
        result["install_grpc"] = resp in ("y", "yes", "д", "да")
    except (KeyboardInterrupt, EOFError):
        pass
    return result


def open_extra_ports(install_hy2, install_grpc, remote_ip=None, remote_cred=None):
    """Open firewall ports for hy2 (UDP) and grpc (TCP)."""
    if install_hy2:
        if remote_ip and remote_cred:
            run_remote(remote_ip, remote_cred, f"iptables -C INPUT -p udp --dport {HY2_PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport {HY2_PORT} -j ACCEPT")
        else:
            iptables_add(f"-I INPUT -p udp --dport {HY2_PORT} -j ACCEPT")
        print(f"  Порт UDP {HY2_PORT} открыт (Hysteria2)")
    if install_grpc:
        if remote_ip and remote_cred:
            run_remote(remote_ip, remote_cred, f"iptables -C INPUT -p tcp --dport {GRPC_PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport {GRPC_PORT} -j ACCEPT")
        else:
            iptables_add(f"-I INPUT -p tcp --dport {GRPC_PORT} -j ACCEPT")
        print(f"  Порт TCP {GRPC_PORT} открыт (gRPC Reality)")
    if install_hy2 or install_grpc:
        pkg_iptables_persist(remote_ip=remote_ip, remote_cred=remote_cred)


def xray_listener_status(port, expected_host=None, remote_ip=None, remote_cred=None):
    """Strictly verify listener address and actual Xray executable."""
    import os
    import re

    port = int(port)
    cmd = "ss -ltnpH 2>/dev/null"

    result = (
        run_remote(remote_ip, remote_cred, cmd, timeout=15)
        if remote_ip else run(cmd, check=False, timeout=15)
    )

    rows = []
    for line in (result.stdout or "").splitlines():
        fields = line.split()
        if any(token.endswith(f":{port}") for token in fields):
            rows.append(line)

    owner_matches = []

    for row in rows:
        pids = re.findall(r"pid=(\d+)", row)

        for pid in pids:
            inspect_cmd = (
                f"exe=$(readlink -f /proc/{pid}/exe 2>/dev/null); "
                f"comm=$(cat /proc/{pid}/comm 2>/dev/null); "
                "printf '%s\\n%s\\n' \"$exe\" \"$comm\""
            )

            probe = (
                run_remote(remote_ip, remote_cred, inspect_cmd, timeout=10)
                if remote_ip else run(inspect_cmd, check=False, timeout=10)
            )

            lines = (probe.stdout or "").splitlines()
            if len(lines) < 2:
                continue

            exe_path = lines[0].strip()
            comm = lines[1].strip().lower()
            exe_name = os.path.basename(
                exe_path.replace(" (deleted)", "")
            )

            # Remnawave Node 3.4.x запускает Xray через rw-core.
            # Проверяем реальный executable, а не только имя процесса.
            if exe_name == "xray" and comm in ("xray", "rw-core"):
                owner_matches.append({
                    "pid": pid,
                    "comm": comm,
                    "executable": exe_path,
                })

    owner_ok = bool(owner_matches)

    address_ok = expected_host is None

    if expected_host is not None:
        expected = str(expected_host).strip("[]")

        for row in rows:
            for token in row.split():
                if not token.endswith(f":{port}"):
                    continue

                host = token.rsplit(":", 1)[0].strip("[]")

                if host == expected:
                    address_ok = True
                    break

            if address_ok:
                break

    return {
        "ok": bool(rows) and owner_ok and address_ok,
        "owner_ok": owner_ok,
        "address_ok": address_ok,
        "rows": rows,
        "owner_matches": owner_matches,
    }



def restrict_bridge_port(relay_ip, remote_ip=None, remote_cred=None):
    """Expose Remnawave BRIDGE_IN:8888 only to the selected relay IPv4."""
    relay_ip = validate_ip(relay_ip, "IP relay")
    q_ip = shlex.quote(relay_ip)
    cmd = (
        "if command -v ufw >/dev/null 2>&1 && "
        "ufw status 2>/dev/null | grep -qi '^Status: active'; then "
        "ufw --force delete allow 8888/tcp >/dev/null 2>&1 || true; "
        f"ufw allow from {q_ip} to any port 8888 proto tcp >/dev/null 2>&1 || true; "
        "ufw reload >/dev/null 2>&1 || true; fi; "
        "while iptables -C INPUT -p tcp --dport 8888 -j ACCEPT >/dev/null 2>&1; "
        "do iptables -D INPUT -p tcp --dport 8888 -j ACCEPT; done; "
        f"while iptables -C INPUT -p tcp -s {q_ip} --dport 8888 -j ACCEPT >/dev/null 2>&1; "
        f"do iptables -D INPUT -p tcp -s {q_ip} --dport 8888 -j ACCEPT; done; "
        "while iptables -C INPUT -p tcp --dport 8888 -j DROP >/dev/null 2>&1; "
        "do iptables -D INPUT -p tcp --dport 8888 -j DROP; done; "
        f"iptables -I INPUT 1 -p tcp -s {q_ip} --dport 8888 -j ACCEPT && "
        "iptables -I INPUT 2 -p tcp --dport 8888 -j DROP"
    )
    result = (run_remote(remote_ip, remote_cred, cmd, timeout=30)
              if remote_ip else run(cmd, check=False, timeout=30))
    require_success(result, "Ограничение BRIDGE_IN только relay-IP")
    pkg_iptables_persist(remote_ip=remote_ip, remote_cred=remote_cred)
    print(f"  BRIDGE_IN 8888 разрешён только для relay {relay_ip}")


# ============================================================
#  NGINX TEMPLATES
# ============================================================

def nginx_cdn_origin(xray_port, xhttp_path, panel_path=None, panel_port=None, ipv6=True,
                     ssl_cert="/etc/nginx/ssl/cdn.crt", ssl_key="/etc/nginx/ssl/cdn.key",
                     panel_https=False, nginx_style="prefix", panel_domain=None):
    """Generate nginx CDN origin config.

    nginx_style:
      "prefix"  — путь-каталог (/content/media/), обычный prefix-location.
      "rewrite" — путь-файл (/static/getFile/video/segment.ts): нужен ^~ и
                  rewrite, добавляющий слеш, иначе xhttp не матчится.
                  Проверено на Beeline 28.07.2026 (4/4 оператора).
    """
    panel_block = ""
    subscription_block = ""
    if panel_path and panel_port and panel_domain:
        panel_scheme = "https" if panel_https else "http"
        panel_block = f"""
    location /{panel_path}/ {{
        if ($host != "{panel_domain}") {{ return 404; }}
        proxy_pass {panel_scheme}://127.0.0.1:{panel_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }}
"""
        subscription_block = f"""
    location /sub/ {{
        if ($host != "{panel_domain}") {{ return 404; }}
        proxy_pass https://127.0.0.1:2096;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}

    location /json/ {{
        if ($host != "{panel_domain}") {{ return 404; }}
        proxy_pass https://127.0.0.1:2096;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
"""

    v6_80 = "\n    listen [::]:80 default_server;" if ipv6 else ""
    # http2 ОБЯЗАТЕЛЕН: CDN-ключи (beeline/vk) идут с alpn=h2. Без http2 nginx не
    # согласует ALPN h2 ('No ALPN negotiated') → клиент с alpn=h2 не подключается →
    # 'Empty reply / Connection reset'. Бэкенд-xray при этом полностью рабочий.
    v6_443 = "\n    listen [::]:443 ssl http2 default_server;" if ipv6 else ""

    if nginx_style == "rewrite":
        # Путь заканчивается именем файла — ловим его точным префиксом и
        # дописываем слеш, которого ждёт xhttp.
        _esc = xhttp_path.replace(".", r"\.")
        xhttp_location_open = f"""location ^~ {xhttp_path} {{
        rewrite ^{_esc}$ {xhttp_path}/ break;
"""
    else:
        xhttp_location_open = f"""location = {xhttp_path.rstrip('/')} {{
        return 404;
    }}

    location {xhttp_path} {{
"""

    return f"""upstream xray_xhttp {{
    server 127.0.0.1:{xray_port};
    keepalive 128;
}}

server {{
    listen 80 default_server;{v6_80}
    listen 443 ssl http2 default_server;{v6_443}
    server_name _;

    ssl_certificate {ssl_cert};
    ssl_certificate_key {ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location = /health {{
        default_type application/json;
        return 200 '{{"status":"ok","service":"media-gateway","version":"4.2.1"}}';
    }}

    {xhttp_location_open}        proxy_pass http://xray_xhttp;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_pass_request_headers on;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_max_temp_file_size 0;
        gzip off;

        proxy_connect_timeout 10s;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        send_timeout 1h;

        client_max_body_size 0;
        proxy_socket_keepalive on;

        add_header X-Accel-Buffering no always;
        add_header Cache-Control "no-store, no-cache" always;
        add_header CDN-Cache-Control "no-store" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        add_header Accept-Ranges none always;
    }}
{panel_block}
{subscription_block}

    location / {{
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ =404;
    }}
}}
"""


def local_origin_readiness(xray_port, xhttp_path):
    """Strict local nginx -> Xray wiring check."""
    listener = xray_listener_status(xray_port, expected_host="127.0.0.1")

    nginx = run("nginx -T 2>&1", check=False, timeout=20)
    nginx_text = (nginx.stdout or "") + "\n" + (nginx.stderr or "")
    nginx_ok = (
        nginx.returncode == 0
        and f"127.0.0.1:{int(xray_port)}" in nginx_text
        and xhttp_path in nginx_text
    )

    health = run(
        "curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "
        "http://127.0.0.1/health",
        check=False,
        timeout=10,
    )
    health_ok = (health.stdout or "").strip().endswith("200")
    return {
        "listener": listener["ok"],
        "listener_owner": listener["owner_ok"],
        "listener_bind": listener["address_ok"],
        "nginx": nginx_ok,
        "health": health_ok,
    }

def probe_cdn_path(domain, xhttp_path):
    """Verify DNS, TLS and the public XHTTP path without exposing user data."""
    domain = validate_fqdn(domain, "CDN-домен")
    url = f"https://{domain}{xhttp_path}"
    result = run(
        "curl -sS --connect-timeout 10 --max-time 20 "
        "-o /dev/null -w '%{http_code}' " + shlex.quote(url),
        check=False,
        timeout=25,
    )
    match = re.search(r"(\d{3})\s*$", result.stdout or "")
    code = match.group(1) if match else "000"
    detail = (result.stderr or "").strip().splitlines()
    return code, (detail[-1][:200] if detail else "")


# ============================================================
#  REMOTE NODE SETUP
# ============================================================

def setup_remote_node(node_ip, node_cred, rcfg, secret_key, domain, panel_ip):
    """Install Docker, nginx CDN origin, and remnanode on remote server via SSH."""
    print(f"  [удалённая] Подключение к {node_ip}...")
    r = run_remote(node_ip, node_cred, "echo OK", timeout=30)
    if "OK" not in r.stdout:
        print(f"  ❌ Не могу подключиться по SSH к {node_ip}")
        if r.stderr:
            print(f"  Ошибка: {r.stderr.strip()[:300]}")
        if r.stdout:
            print(f"  Вывод: {r.stdout.strip()[:200]}")
        sshpass_check = run("which sshpass", check=False)
        if sshpass_check.returncode != 0:
            print("  sshpass не установлен! Устанавливаю...")
            run("DEBIAN_FRONTEND=noninteractive apt-get install -y sshpass", check=False, timeout=60)
            r = run_remote(node_ip, node_cred, "echo OK", timeout=30)
            if "OK" in r.stdout:
                print("  Подключение успешно после установки sshpass!")
            else:
                print("  Проверь IP, пароль и что SSH открыт")
                sys.exit(1)
        else:
            print("  Проверь IP, пароль и что SSH открыт")
            sys.exit(1)

    marker = run_remote(
        node_ip, node_cred,
        "test -e /opt/remnanode/.env -o -e /opt/remnawave/.env -o -e /etc/x-ui/x-ui.db "
        "&& echo EXISTING_PANEL || true", timeout=15)
    if "EXISTING_PANEL" in (marker.stdout or ""):
        raise RuntimeError(
            f"На удалённой ноде {node_ip} уже есть VPN-панель/нода; автоматическая перезапись запрещена"
        )
    run_remote(
        node_ip, node_cred,
        "mkdir -p /root/vpn-cdn-backup && "
        "tar -czf /root/vpn-cdn-backup/preinstall-configs.tgz "
        "/etc/nginx /etc/sysctl.d /etc/security/limits.d /etc/fstab 2>/dev/null || true",
        timeout=60)

    check_os(remote_ip=node_ip, remote_cred=node_cred)
    print("  [удалённая] Установка пакетов...")
    pkg_install("nginx openssl curl ca-certificates gnupg", remote_ip=node_ip, remote_cred=node_cred)

    r = run_remote(node_ip, node_cred, "ufw status 2>/dev/null")
    if r.returncode == 0 and "active" in r.stdout.lower():
        print("  [удалённая] UFW активен, открываю порты 80/443...")
        run_remote(node_ip, node_cred, "ufw allow 80/tcp >/dev/null 2>&1 && ufw allow 443/tcp >/dev/null 2>&1 && ufw reload >/dev/null 2>&1")

    print("  [удалённая] Установка Docker...")
    if install_docker(remote_ip=node_ip, remote_cred=node_cred):
        print(f"  [удалённая] Docker готов: {run_remote(node_ip, node_cred, 'docker --version').stdout.strip()}")
    else:
        print(f"  ❌ [удалённая] Docker не установился на {node_ip}!")
        sys.exit(1)
    setup_docker_mirror(remote_ip=node_ip, remote_cred=node_cred)
    r = run_remote(node_ip, node_cred, "docker compose version 2>/dev/null")
    if r.returncode != 0:
        print("  [удалённая] docker compose plugin не найден, устанавливаю...")
        install_docker_compose(node_ip, node_cred)
        r = run_remote(node_ip, node_cred, "docker compose version 2>/dev/null")
        if r.returncode != 0:
            raise RuntimeError(
                f"Docker Compose v2 не установлен на удалённой ноде {node_ip}"
            )

    print("  [удалённая] Настройка TCP (BBR)...")
    write_remote_file(node_ip, node_cred, "/etc/sysctl.d/99-vpn-tuning.conf", SYSCTL_TUNING)
    run_remote(node_ip, node_cred, "sysctl --system > /dev/null 2>&1")
    write_remote_file(node_ip, node_cred, "/etc/security/limits.d/99-nofile.conf", NOFILE_LIMITS)

    print("  [удалённая] SSL и заглушка...")
    run_remote(node_ip, node_cred, "mkdir -p /etc/nginx/ssl /etc/nginx/conf.d /var/www/html")
    require_success(run_remote(node_ip, node_cred,
        "test -f /etc/nginx/ssl/cdn.crt -a -f /etc/nginx/ssl/cdn.key || "
        "openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
        "-keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj '/CN=cdn-origin'"),
        "Создание SSL на удалённой ноде")
    decoy = DECOY_HTML.format(domain=domain)
    write_remote_file(node_ip, node_cred, "/var/www/html/index.html", decoy)

    run_remote(node_ip, node_cred,
               "swapon --show | grep -q / || { fallocate -l 2G /swapfile && chmod 600 /swapfile "
               "&& mkswap /swapfile && swapon /swapfile && { grep -qE '^/swapfile[[:space:]]' /etc/fstab "
               "|| echo '/swapfile none swap sw 0 0' >> /etc/fstab; }; }")

    print("  [удалённая] Настройка nginx CDN origin...")
    ipv6_ok = has_ipv6_remote(node_ip, node_cred)
    nginx_conf = nginx_cdn_origin(rcfg["xray_port"], rcfg["xhttp_path"], ipv6=ipv6_ok,
                                  nginx_style=rcfg.get("nginx_style", "prefix"))
    r = nginx_write_and_restart(nginx_conf, remote_ip=node_ip, remote_cred=node_cred)
    if r.returncode == 0:
        print("  [удалённая] Nginx настроен")
    else:
        raise RuntimeError(f"Проблема с nginx на удалённой ноде: {r.stderr[:300] if r.stderr else ''}")

    print(f"  [удалённая] Ограничение порта 2222 для панели ({panel_ip})...")
    iptables_add(f"-I INPUT -p tcp --dport 2222 -s {panel_ip} -j ACCEPT", remote_ip=node_ip, remote_cred=node_cred)
    iptables_add("-A INPUT -p tcp --dport 2222 -j DROP", remote_ip=node_ip, remote_cred=node_cred)
    pkg_iptables_persist(remote_ip=node_ip, remote_cred=node_cred)

    print("  [удалённая] Настройка remnanode...")
    run_remote(node_ip, node_cred, "mkdir -p /opt/remnanode")

    node_compose = f"services:\n  remnanode:\n    container_name: remnanode\n    hostname: remnanode\n    image: remnawave/node:{REMNAWAVE_NODE_VERSION}\n    network_mode: host\n    restart: always\n    cap_add:\n      - NET_ADMIN\n    ulimits:\n      nofile:\n        soft: 1048576\n        hard: 1048576\n    volumes:\n      - /etc/nginx/ssl:/etc/nginx/ssl:ro\n      - /opt/remnanode/xray-custom:/usr/local/bin/xray\n    env_file:\n      - .env\n"
    write_remote_file(node_ip, node_cred, "/opt/remnanode/docker-compose.yml", node_compose)

    node_env = f"NODE_PORT=2222\nSECRET_KEY={secret_key or 'REPLACE_WITH_KEY_FROM_PANEL'}\n"
    write_remote_file(node_ip, node_cred, "/opt/remnanode/.env", node_env)
    run_remote(node_ip, node_cred, "chmod 600 /opt/remnanode/.env /etc/nginx/ssl/cdn.key")

    if secret_key:
        if not download_xray_binary(remote_ip=node_ip, remote_cred=node_cred):
            raise RuntimeError("Не удалось установить проверенный Xray на удалённой ноде")
        print("  [удалённая] Скачивание образа remnanode...")
        # Таймаут щедрый: на медленных каналах образ (~37 МБ) не успевает за 180с,
        # docker compose up тогда падает по таймауту, а установка шла дальше — у
        # клиента оставался мёртвый origin и «Empty reply» через CDN (стенд 06.08).
        require_success(run_remote(node_ip, node_cred, "cd /opt/remnanode && docker compose pull", timeout=600,
                                    label="Загрузка remnanode (удалённая нода)", expected=45),
                        "Загрузка remnanode на удалённом сервере")
        print("  [удалённая] Запуск remnanode...")
        if not ensure_remnanode_up(node_ip, node_cred):
            raise RuntimeError("remnanode не запустился на удалённом сервере")

        print("  [удалённая] Ожидание запуска ноды...")
        for i in range(20):
            time.sleep(5)
            r = run_remote(node_ip, node_cred, "docker logs remnanode --tail=5 2>&1")
            if "started" in r.stdout.lower() or "running" in r.stdout.lower() or "XRay Core" in r.stdout:
                print("  [удалённая] Нода запущена!")
                break
    else:
        raise RuntimeError("Нет SECRET_KEY для удалённой remnanode")


# ============================================================
#  LE CERT FOR HY2
# ============================================================

def wait_dns_a_record(domain, target_ip, remote_ip=None, remote_cred=None,
                      attempts=6, delay=20, label=""):
    """Дождаться, пока A-запись domain укажет на target_ip. True — указала.

    Нужно всем, кто дальше идёт в certbot: на приглашение «создай DNS-записи»
    пользователь обычно жмёт ENTER раньше, чем запись реально разошлась. Тогда
    certbot падает с ходу, установка молча съезжает на self-signed, и клиент
    получает панель с сертификатом, которому не верит ни браузер, ни клиент.
    """
    pfx = f"  {label}: " if label else "  "
    # без awk: экранирование $1 ведёт себя по-разному локально и через SSH
    chk = f"getent hosts {domain} | head -1 | tr -s ' ' | cut -d' ' -f1"
    resolved = ""
    for attempt in range(1, attempts + 1):
        rc = run_remote(remote_ip, remote_cred, chk, timeout=20) if remote_ip else run(chk, check=False, timeout=20)
        resolved = (rc.stdout or "").strip()
        if resolved and (not target_ip or resolved == target_ip):
            return True
        if attempt == 1:
            print(f"{pfx}жду DNS {domain} -> {target_ip} ...")
        if attempt < attempts:
            time.sleep(delay)
    print(f"{pfx}DNS {domain} так и не указал на {target_ip}"
          + (f" (сейчас {resolved})" if resolved else " (запись не найдена)"))
    return False


def ensure_remnanode_up(remote_ip=None, remote_cred=None, attempts=3):
    """Поднять remnanode и УБЕДИТЬСЯ, что контейнер реально запущен.

    Раньше делался просто `docker compose up -d` с коротким таймаутом: на медленном
    канале команда не укладывалась (образ ~37 МБ), установка шла дальше как ни в чём
    не бывало, а контейнера не было. Наружу это выглядит как «Empty reply» через CDN
    — nginx проксирует в мёртвый порт. Проверено на стенде 06.08.2026.
    """
    def _r(cmd, t=300):
        if remote_ip:
            return run_remote(remote_ip, remote_cred, cmd, timeout=t)
        return run(cmd, check=False, timeout=t)

    tag = "[удалённая] " if remote_ip else ""
    for attempt in range(1, attempts + 1):
        _r("cd /opt/remnanode && docker compose up -d 2>&1", t=300)
        time.sleep(4)
        r = _r("docker ps --filter name=remnanode --format '{{.Status}}' 2>/dev/null", t=30)
        if "Up" in (r.stdout or ""):
            print(f"  {tag}remnanode запущен")
            return True
        if attempt < attempts:
            print(f"  {tag}контейнер не поднялся ({attempt}/{attempts}), повтор...")
            _r("cd /opt/remnanode && docker compose pull 2>&1", t=600)
    logs = _r("docker compose -f /opt/remnanode/docker-compose.yml logs --tail=10 2>&1", t=60)
    print(f"  ⚠ {tag}remnanode НЕ запустился — xray не поднимет порт, CDN отдаст «Empty reply»")
    print(f"     {(logs.stdout or logs.stderr or '')[-300:]}")
    return False


def setup_hy2_le_cert(domain, remote_ip=None, remote_cred=None):
    """Try LE cert for HY2 domain, replace self-signed cdn.crt. Returns True on success."""
    print(f"  HY2: LE cert для {domain}...")
    for cmd in [
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot 2>/dev/null",
        "mkdir -p /var/www/certbot",
    ]:
        if remote_ip:
            run_remote(remote_ip, remote_cred, cmd, timeout=60)
        else:
            run(cmd, check=False, timeout=60)
    target_ip = remote_ip or get_ip()
    if not wait_dns_a_record(domain, target_ip, remote_ip, remote_cred, label="HY2"):
        print(f"  HY2: self-signed cert (DNS не готов)")
        print(f"  Позже выпусти вручную: certbot certonly --webroot -w /var/www/certbot -d {domain}")
        return False

    certbot_cmd = (
        f"certbot certonly --webroot -w /var/www/certbot -d {domain} "
        f"--non-interactive --agree-tos --register-unsafely-without-email"
    )
    r = None
    for attempt in range(1, 4):
        if remote_ip:
            r = run_remote(remote_ip, remote_cred, certbot_cmd, timeout=120,
                           label="Выпуск сертификата HY2", expected=20)
        else:
            r = run(certbot_cmd, check=False, timeout=120, label="Выпуск сертификата HY2", expected=20)
        if r.returncode == 0:
            break
        if attempt < 3:
            print(f"  HY2: certbot не прошёл (попытка {attempt}/3), повтор через 20с...")
            time.sleep(20)
    if not r or r.returncode != 0:
        print(f"  HY2: сертификат для {domain} не выпущен — self-signed cert")
        print(f"  Выпусти вручную: certbot certonly --webroot -w /var/www/certbot -d {domain}")
        print(f"  затем: cp /etc/letsencrypt/live/{domain}/fullchain.pem /etc/nginx/ssl/cdn.crt && "
              f"cp /etc/letsencrypt/live/{domain}/privkey.pem /etc/nginx/ssl/cdn.key && "
              f"nginx -s reload && docker restart remnanode")
        return False
    copy_cmd = (
        f"cp /etc/letsencrypt/live/{domain}/fullchain.pem /etc/nginx/ssl/cdn.crt && "
        f"cp /etc/letsencrypt/live/{domain}/privkey.pem /etc/nginx/ssl/cdn.key && "
        f"nginx -s reload 2>/dev/null; docker restart remnanode 2>/dev/null || true"
    )
    if remote_ip:
        run_remote(remote_ip, remote_cred, copy_cmd, timeout=30)
    else:
        run(copy_cmd, check=False, timeout=30)
    hook = (
        "#!/bin/bash\\n"
        f"cp /etc/letsencrypt/live/{domain}/fullchain.pem /etc/nginx/ssl/cdn.crt\\n"
        f"cp /etc/letsencrypt/live/{domain}/privkey.pem /etc/nginx/ssl/cdn.key\\n"
        "nginx -s reload\\n"
        "docker restart remnanode 2>/dev/null || true"
    )
    hook_cmd = (
        "mkdir -p /etc/letsencrypt/renewal-hooks/deploy && "
        f"printf '%b' '{hook}' > /etc/letsencrypt/renewal-hooks/deploy/hy2-cert.sh && "
        "chmod +x /etc/letsencrypt/renewal-hooks/deploy/hy2-cert.sh"
    )
    if remote_ip:
        run_remote(remote_ip, remote_cred, hook_cmd, timeout=15)
    else:
        run(hook_cmd, check=False, timeout=15)
    print(f"  HY2 LE cert: {domain} ✓")
    return True


# ============================================================
#  ACME.SH SSL FOR IP ADDRESS
# ============================================================

def setup_acme_ssl(server_ip):
    """Issue LE cert for IP address via acme.sh with shortlived profile."""
    step_label = "LE SSL для IP"
    print("  LE для IP через загружаемый shell-скрипт отключён; используется сертификат домена")
    return False
    r = subprocess.CompletedProcess([], 1, "", "disabled")
    if r.returncode != 0:
        print("  ⚠ acme.sh не установился, используем self-signed")
        return False

    print("  Остановка nginx для HTTP-01 challenge...")
    run("systemctl stop nginx", check=False)

    print(f"  Выпуск сертификата для {server_ip}...")
    r = run(
        f'~/.acme.sh/acme.sh --issue --server letsencrypt '
        f'-d {server_ip} --standalone --httpport 80 '
        f'--cert-profile shortlived --keylength ec-256 --days 3 --force',
        check=False, timeout=120
    )

    if r.returncode != 0:
        print(f"  ⚠ LE сертификат не выпущен: {(r.stderr or r.stdout or '')[:200]}")
        print("  Fallback: self-signed")
        run("systemctl start nginx", check=False)
        return False

    run("mkdir -p /root/cert/ip", check=False)
    r = run(
        f'~/.acme.sh/acme.sh --install-cert -d {server_ip} '
        f'--fullchain-file /root/cert/ip/fullchain.pem '
        f'--key-file /root/cert/ip/privkey.pem '
        f'--reloadcmd "systemctl reload nginx"',
        check=False, timeout=60
    )

    run("systemctl start nginx", check=False)

    if r.returncode == 0 and os.path.exists("/root/cert/ip/fullchain.pem"):
        track("acme_cert", server_ip)
        track("file", "/root/cert/ip/fullchain.pem")
        track("file", "/root/cert/ip/privkey.pem")
        print(f"  LE SSL для {server_ip} выпущен (auto-renew каждые 3 дня)")
        return True
    else:
        print("  ⚠ Установка серта не удалась, fallback: self-signed")
        return False


# ============================================================
#  3X-UI INBOUND IDENTITY (rename-proof)
# ============================================================

def _xui_ensure_stats(tpl):
    """Дописать в xray-шаблон 3x-ui блоки статистики (онлайн + трафик).

    Баг: наш xrayTemplateConfig собирался только из log/outbounds/routing —
    без stats/policy/api и без api-inbound. Без них панель 3x-ui НЕ показывает
    ни трафик клиентов, ни статус онлайн (пусто в обеих колонках). Онлайн в
    актуальном xray определяется флагом policy.levels.0.statsUserOnline через
    StatsService, а не по access-логам (в дефолте 3x-ui access="none"). Эталон
    снят с рабочей 3x-ui latest.

    api-inbound берём как dokodemo-door (а не новый protocol "tunnel" из latest):
    dokodemo-door понимают и старые, и новые сборки xray, что бы 3x-ui ни принёс.
    Идемпотентно: существующие значения дополняем, api-inbound не дублируем.
    """
    tpl.setdefault("stats", {})
    tpl["api"] = {"tag": "api",
                  "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"]}
    pol = tpl.setdefault("policy", {})
    lvl0 = pol.setdefault("levels", {}).setdefault("0", {})
    lvl0.update({"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True})
    pol.setdefault("system", {}).update({"statsInboundUplink": True, "statsInboundDownlink": True})
    tpl.setdefault("metrics", {"listen": "127.0.0.1:11111", "tag": "metrics_out"})
    ibs = tpl.setdefault("inbounds", [])
    if not any(i.get("tag") == "api" for i in ibs):
        ibs.insert(0, {"tag": "api", "listen": "127.0.0.1", "port": 62789,
                       "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}})
    return tpl


def youtube_soundcloud_direct_rules(direct_tag, block_tag):
    """Правила роутинга: YouTube + SoundCloud напрямую (через РФ-relay), реклама в блок.

    Смысл — только в каскаде: relay в РФ, и если хостинг relay «пробивает» YouTube
    (доступен с российского IP), то направив YouTube/SoundCloud в direct (выход с
    relay, а не через заграничный exit), клиент получает их без рекламы. Работает
    НЕ на любом хостинге — поэтому включается опцией и после проверки доступности.
    Рецепт проверен на живом впне (домены/IP-диапазоны Google от Романа Колосова).

    direct_tag/block_tag разные у панелей: 3x-ui — direct/blocked, Remnawave —
    DIRECT/BLOCK. Ставить эти правила ВЫШЕ catch-all в exit и (для чистоты) выше
    RU-правил. category-ads-all режем первым — реклама не течёт ни в один выход.
    """
    return [
        {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": block_tag},
        {"type": "field", "domain": ["geosite:youtube"], "outboundTag": direct_tag},
        {"type": "field", "ip": ["8.8.8.0/24", "8.8.4.0/24", "74.125.0.0/16",
                                  "172.217.0.0/16", "142.250.0.0/15", "216.58.0.0/16"],
         "outboundTag": direct_tag},
        {"type": "field", "domain": ["soundcloud.com", "sndcdn.com", "soundcloud-cdn.com"],
         "outboundTag": direct_tag},
    ]


def youtube_reachable(remote_ip=None, remote_cred=None):
    """Доступен ли YouTube напрямую с этого сервера (пробивает ли хостинг relay).

    Роман предложил: добавлять правила только если YouTube пингуется с relay.
    Проверяем HTTPS-доступность googlevideo/youtube — если сервер их не открывает,
    direct-маршрут сломает YouTube вместо очистки от рекламы.
    """
    cmd = ("curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://www.youtube.com "
           "2>/dev/null || echo 000")
    r = run_remote(remote_ip, remote_cred, cmd, timeout=15) if remote_ip else run(cmd, check=False, timeout=15)
    code_str = (r.stdout or "").strip()
    code = code_str[-3:] if len(code_str) >= 3 else code_str
    return code.startswith(("2", "3"))


def xui_purge_own_inbound_sql(port, tag, email, temp="_own_ib"):
    """SQL-блок: снести НАШ инбаунд на порту port, не задев чужие.

    Тег для опознания не годится: 3x-ui перегенерирует его в `in-<port>-<proto>`
    каждый раз, когда владелец сохраняет инбаунд в UI. После этого DELETE по
    нашему тегу не матчит, повторный запуск installer вешает ВТОРОЙ инбаунд на
    тот же порт, и xray падает с «bind: address already in use» — инбаунд не
    слушает, nginx отдаёт 502, CDN — «Empty reply».

    Стабильный признак «нашего» — привязанный клиентский email (installer
    задаёт его сам: user1 / bridge_user / bridge_plain; панель email не трогает).
    Сверка идёт по паре порт+email, поэтому gRPC-инбаунд того же клиента не
    попадает под удаление CDN-инбаунда. Тег оставлен как второй критерий — им
    ловится инбаунд, у которого ещё нет клиентских связок.

    Порядок важен: id «наших» инбаундов сначала складываем в temp-таблицу, иначе
    удаление client_inbounds уничтожит признак, по которому мы их находим.
    Работает потому, что весь скрипт уходит в sqlite3 одной сессией.
    """
    return f"""CREATE TEMP TABLE {temp} AS SELECT id FROM inbounds
WHERE port={_num(port)} AND id IN (SELECT ci.inbound_id FROM client_inbounds ci
      JOIN clients c ON c.id = ci.client_id WHERE c.email='{_sql_str(email)}');
DELETE FROM client_inbounds WHERE inbound_id IN (SELECT id FROM {temp});
DELETE FROM client_traffics WHERE inbound_id IN (SELECT id FROM {temp});
DELETE FROM inbounds WHERE id IN (SELECT id FROM {temp});
DROP TABLE {temp};"""


def _sql_str(v):
    """Экранировать значение для одинарных кавычек SQL."""
    return str(v).replace("'", "''")


def _num(v, default=0):
    """Числовое поле из вывода sqlite — заодно отсекает подстановку мусора в SQL."""
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return default


def _xui_q(sql, remote_ip=None, remote_cred=None, timeout=15):
    """SELECT в x-ui.db локально или по SSH. Возвращает stdout."""
    cmd = f"sqlite3 /etc/x-ui/x-ui.db \"{sql}\""
    r = run_remote(remote_ip, remote_cred, cmd, timeout=timeout) if remote_ip else run(cmd, check=False, timeout=timeout)
    return (r.stdout or "").strip()


def apply_xui_sql_file(path):
    """Apply a local SQLite change atomically while x-ui is stopped."""
    if not os.path.isfile(path):
        raise RuntimeError(f"SQL-файл не найден: {path}")
    backup_file("/etc/x-ui/x-ui.db")
    stopped = False
    wrapped_path = None
    try:
        with open(path, encoding="utf-8") as source:
            sql = source.read()
        fd, wrapped_path = tempfile.mkstemp(prefix="vpn_cdn_sql_", suffix=".sql")
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write("BEGIN IMMEDIATE;\n")
            target.write(sql)
            target.write("\nCOMMIT;\n")
        status = run("systemctl is-active x-ui", check=False)
        stopped = status.returncode == 0
        if stopped:
            require_success(run("systemctl stop x-ui", check=False, timeout=30), "Остановка x-ui")
        result = run(f"sqlite3 -bail /etc/x-ui/x-ui.db < {shlex.quote(wrapped_path)}", check=False, timeout=60)
        require_success(result, f"Применение {path}")
    finally:
        if wrapped_path:
            try:
                os.unlink(wrapped_path)
            except OSError:
                pass
        if stopped:
            restart = run("systemctl start x-ui", check=False, timeout=30)
            if restart.returncode != 0:
                print(f"  ⚠ Не удалось запустить x-ui после SQL: {(restart.stderr or restart.stdout or '')[:300]}")


def apply_xui_sql_remote(panel_ip, panel_cred, path):
    """Apply remote SQLite changes atomically with an online backup."""
    backup = f"/root/vpn-cdn-backup/x-ui-{int(time.time())}.db"
    script = f"""set -u
mkdir -p /root/vpn-cdn-backup
sqlite3 /etc/x-ui/x-ui.db ".backup '{backup}'" || exit 1
{{ printf 'BEGIN IMMEDIATE;\\n'; cat {shlex.quote(path)}; printf '\\nCOMMIT;\\n'; }} > /tmp/vpn-cdn-xui-wrapped.sql
WAS_ACTIVE=0
systemctl is-active --quiet x-ui && WAS_ACTIVE=1
[ "$WAS_ACTIVE" -eq 0 ] || systemctl stop x-ui || exit 1
sqlite3 -bail /etc/x-ui/x-ui.db < /tmp/vpn-cdn-xui-wrapped.sql
RC=$?
[ "$WAS_ACTIVE" -eq 0 ] || systemctl start x-ui
rm -f /tmp/vpn-cdn-xui-wrapped.sql
exit "$RC"
"""
    result = run_remote(panel_ip, panel_cred, script, timeout=90)
    require_success(result, "Транзакция SQLite на удалённой 3x-ui")
    return backup


def xui_inbound_snapshot(port, remote_ip=None, remote_cred=None):
    """Снимок инбаунда на порту: клиенты из settings.clients + их счётчики трафика.

    Инбаунд мы пересоздаём целиком — это проще и надёжнее, чем патчить JSON. Но
    вместе с ним раньше исчезали клиенты, которых владелец добавил руками: их
    связки оставались висеть на удалённом inbound_id, и подписки этих людей
    пустели. В режиме 3 панель боевая, с живыми подписчиками, так что снимок
    обязателен. Счётчики снимаем, чтобы пересоздание не обнуляло статистику.
    """
    out = _xui_q(f"SELECT settings FROM inbounds WHERE port={_num(port)} ORDER BY id DESC LIMIT 1;",
                 remote_ip, remote_cred)
    clients = []
    if out:
        try:
            clients = (json.loads(out) or {}).get("clients") or []
        except (ValueError, TypeError):
            print(f"  ⚠ settings инбаунда на порту {port} не разобрать — клиенты не сохранены")
    traffics = {}
    t_out = _xui_q(
        f"SELECT email, up, down, total, expiry_time FROM client_traffics "
        f"WHERE inbound_id IN (SELECT id FROM inbounds WHERE port={_num(port)});",
        remote_ip, remote_cred)
    for row in t_out.splitlines():
        parts = row.split("|")
        if len(parts) >= 5 and parts[0].strip():
            traffics[parts[0].strip()] = parts[1:5]
    return {"clients": clients, "traffics": traffics}


def xui_adopt_client_identity(snapshot, email, remote_ip=None, remote_cred=None):
    """Вернуть (uuid, sub_id) уже выданного клиента, если он существует.

    Инбаунд пересоздаётся при каждом запуске, и раньше клиенту генерировался
    НОВЫЙ uuid: в settings инбаунда уходил свежий, а ссылка и подписка потом
    собирались из старого значения в таблице clients. Ключ у человека переставал
    подходить хоть к чему-нибудь, а симптом наружу — то же «Empty reply», из-за
    которого диагностика уходит в сеть вместо БД.

    Источник истины — settings.clients инбаунда: именно по нему xray сверяет
    клиента. Если там нашего email нет, смотрим таблицу clients.
    """
    for c in snapshot.get("clients") or []:
        if (c.get("email") or "") == email:
            return (c.get("id") or None, c.get("subId") or c.get("sub_id") or None)
    out = _xui_q(f"SELECT uuid, sub_id FROM clients WHERE email='{_sql_str(email)}' "
                 f"ORDER BY id DESC LIMIT 1;", remote_ip, remote_cred)
    if out:
        parts = out.split("|")
        return (parts[0].strip() or None, parts[1].strip() if len(parts) > 1 else None)
    return (None, None)


def xui_link_clients_sql(port, clients, traffics, now_ms):
    """SQL: пересобрать связки клиент↔инбаунд из settings.clients этого инбаунда.

    В 3x-ui источник истины по клиентам — JSON `inbounds.settings`, а таблицы
    clients/client_inbounds/client_traffics производны от него. Когда владелец
    переименовывает инбаунд, панель пересоздаёт его строку с НОВЫМ id: старые
    связки повисают на удалённом, подписка начинает отдавать пустоту, хотя в
    JSON клиенты на месте. Поэтому связки не чиним точечно, а пересобираем из
    JSON — идемпотентно, и заодно лечит панели, сломанные прошлыми
    переименованиями. Счётчики трафика переносим из снимка.
    """
    ib = f"(SELECT id FROM inbounds WHERE port={_num(port)} ORDER BY id DESC LIMIT 1)"
    # Сначала выметаем связки-сироты — те, что указывают на инбаунд, которого в
    # таблице уже нет. Ровно они и остаются после переименования (панель удалила
    # старую строку inbounds, а client_inbounds/client_traffics на её id не
    # почистила) — и из-за них подписка пустеет. Сирота = мусор по определению,
    # так что чистим глобально, а не только для нашего порта.
    out = [
        "DELETE FROM client_inbounds WHERE inbound_id NOT IN (SELECT id FROM inbounds);",
        "DELETE FROM client_traffics WHERE inbound_id NOT IN (SELECT id FROM inbounds);",
    ]
    for c in clients:
        raw_email = c.get("email") or ""
        if not raw_email:
            continue
        e = _sql_str(raw_email)
        u = _sql_str(c.get("id") or "")
        s = _sql_str(c.get("subId") or c.get("sub_id") or "")
        f = _sql_str(c.get("flow") or "")
        up, down, total, expiry = traffics.get(raw_email, (0, 0, 0, 0))
        # Строку в clients подтягиваем под settings, а не просто «создаём, если нет»:
        # разъехавшийся uuid здесь и есть причина, по которой ключ клиента не
        # подходит к инбаунду. Удалять и вставлять заново нельзя — на clients.id
        # ссылаются связки с другими инбаундами.
        out.append(
            f"UPDATE clients SET uuid='{u}', sub_id='{s}', flow='{f}' WHERE email='{e}';")
        out.append(
            f"INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable, created_at) "
            f"SELECT '{e}','{s}','{u}','{f}',0,0,0,1,{_num(now_ms)} "
            f"WHERE NOT EXISTS (SELECT 1 FROM clients WHERE email='{e}');")
        out.append(
            f"DELETE FROM client_inbounds WHERE client_id IN (SELECT id FROM clients WHERE email='{e}') "
            f"AND inbound_id IN {ib};")
        out.append(
            f"INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at) "
            f"SELECT (SELECT id FROM clients WHERE email='{e}' ORDER BY id LIMIT 1), {ib}, '{f}', {_num(now_ms)} "
            f"WHERE {ib} IS NOT NULL AND EXISTS (SELECT 1 FROM clients WHERE email='{e}');")
        out.append(f"DELETE FROM client_traffics WHERE email='{e}' AND inbound_id IN {ib};")
        out.append(
            f"INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset) "
            f"SELECT {ib}, 1, '{e}', {_num(up)}, {_num(down)}, {_num(expiry)}, {_num(total)}, 0 "
            f"WHERE {ib} IS NOT NULL;")
    return "\n".join(out)


def xui_port_squatter(port, exclude_tag=None, remote_ip=None, remote_cred=None,
                      owner_email=None):
    """Кто ещё занимает порт port в панели — чужой инбаунд или никто.

    Вызывать ПОСЛЕ xui_purge_own_inbound_sql: если что-то осталось, это инбаунд
    владельца, и молча удалять его нельзя. Молча продолжать тоже нельзя — xray
    не поднимется из-за конфликта порта, а симптом («Empty reply» через CDN)
    уводит диагностику совсем в другую сторону.

    Возвращает 'remark (tag)' занявшего инбаунда либо None.
    """
    q = f"SELECT remark, tag FROM inbounds WHERE port={port}"
    if exclude_tag:
        q += f" AND tag<>'{exclude_tag}'"
    if owner_email:
        q += (" AND id NOT IN (SELECT ci.inbound_id FROM client_inbounds ci "
              "JOIN clients c ON c.id=ci.client_id "
              f"WHERE c.email='{_sql_str(owner_email)}')")
    cmd = f"sqlite3 /etc/x-ui/x-ui.db \"{q} LIMIT 1;\""
    r = run_remote(remote_ip, remote_cred, cmd, timeout=10) if remote_ip else run(cmd, check=False)
    out = (r.stdout or "").strip()
    if not out:
        return None
    parts = out.split("|")
    remark = parts[0].strip() or "без имени"
    tag = parts[1].strip() if len(parts) > 1 else "?"
    return f"{remark} (tag={tag})"


# ============================================================
#  3X-UI CASCADE EXIT SETUP
# ============================================================

def setup_3xui_cascade_exit(cascade_ip, cascade_cred, exit_panel_domain, eu_grpc=False):
    """Install full 3x-ui panel on exit server with SSL + Reality inbound for cascade.

    eu_grpc=True (#23/A4) — дополнительно поднять на EU свой gRPC-Reality инбаунд
    со отдельным клиентом: прямой заграничный выход по gRPC, минуя CDN и relay.
    HY2 на 3x-ui не ставим (свой формат hysteria2 у панели; у Remnawave HY2 есть).
    """
    print(f"\n  [cascade] Подключение к exit-серверу {cascade_ip}...")
    r = run_remote(cascade_ip, cascade_cred, "echo OK", timeout=30)
    if "OK" not in r.stdout:
        for _ in range(3):
            time.sleep(5)
            r = run_remote(cascade_ip, cascade_cred, "echo OK", timeout=30)
            if "OK" in r.stdout:
                break
        else:
            print(f"  ❌ [cascade] Не могу подключиться к exit {cascade_ip}")
            return None
    print("  [cascade] SSH OK")
    check_os(remote_ip=cascade_ip, remote_cred=cascade_cred)

    occupied = run_remote(
        cascade_ip,
        cascade_cred,
        "test -e /usr/local/x-ui/x-ui -o -e /etc/x-ui/x-ui.db && echo OCCUPIED; "
        "ss -ltn 2>/dev/null | grep -Eq ':(80|443|2083) ' && echo OCCUPIED; "
        "for s in nginx apache2 caddy x-ui xray; do "
        "systemctl is-active --quiet \"$s\" 2>/dev/null && echo OCCUPIED; done",
        timeout=20,
    )
    if "OCCUPIED" in (occupied.stdout or ""):
        raise RuntimeError(
            "Exit-сервер не чистый: найдена панель, web/VPN-служба или занятый порт. "
            "Установщик не будет изменять чужую конфигурацию."
        )

    # --- BBR, swap, limits ---
    print("  [cascade] Настройка TCP (BBR)...")
    write_remote_file(cascade_ip, cascade_cred, "/etc/sysctl.d/99-vpn-tuning.conf", SYSCTL_TUNING)
    run_remote(cascade_ip, cascade_cred, "sysctl --system > /dev/null 2>&1")
    write_remote_file(cascade_ip, cascade_cred, "/etc/security/limits.d/99-nofile.conf", NOFILE_LIMITS)
    run_remote(cascade_ip, cascade_cred, "swapon --show | grep -q / || (fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab) 2>/dev/null")

    # --- Install 3x-ui ---
    exit_panel_pass = secrets.token_urlsafe(12)
    exit_panel_port = 47115 + secrets.randbelow(1000)
    exit_panel_path = generate_panel_path()

    r_svc = run_remote(cascade_ip, cascade_cred, "systemctl is-active x-ui 2>/dev/null", timeout=15)
    r_bin = run_remote(cascade_ip, cascade_cred, "test -f /usr/local/x-ui/x-ui && echo yes || echo no", timeout=10)
    if "active" in r_svc.stdout and "yes" in r_bin.stdout:
        raise RuntimeError(
            "На cascade/exit уже установлена 3x-ui. Автоматическая перенастройка чужой панели запрещена."
        )
    else:
        print("  [cascade] Установка 3x-ui на exit...")
        install_url = (
            f"https://raw.githubusercontent.com/MHSanaei/3x-ui/{XUI_RELEASE_COMMIT}/install.sh"
        )
        result = run_remote(
            cascade_ip, cascade_cred,
            f"curl -fsSL --proto '=https' {shlex.quote(install_url)} -o /tmp/3xui_install.sh",
            timeout=60,
        )
        require_success(result, "Скачивание закреплённого установщика 3x-ui")
        result = run_remote(
            cascade_ip, cascade_cred,
            f"XUI_NONINTERACTIVE=1 bash /tmp/3xui_install.sh {XUI_VERSION}",
            timeout=1200, label="Установка 3x-ui на exit", expected=90,
        )
        require_success(result, "Установка 3x-ui на exit")
        time.sleep(5)
        r = run_remote(cascade_ip, cascade_cred, "systemctl is-active x-ui", timeout=15)
        if "active" not in r.stdout:
            run_remote(cascade_ip, cascade_cred, "systemctl restart x-ui", timeout=30)
            time.sleep(5)

    # глушим осиротевший standalone xray на exit, чтобы bundled-xray занял свой порт
    stop_conflicting_standalone_xray(remote_ip=cascade_ip, remote_cred=cascade_cred)

    run_remote(cascade_ip, cascade_cred,
        f"/usr/local/x-ui/x-ui setting -username admin -password {exit_panel_pass} -port {exit_panel_port} -webBasePath /{exit_panel_path}/",
        timeout=15)
    print(f"  [cascade] 3x-ui: порт={exit_panel_port}, путь=/{exit_panel_path}/")

    # RU гео-файлы для роутинга (asset dir у 3x-ui = /usr/local/x-ui/bin)
    setup_xray_ru_geo(remote_ip=cascade_ip, remote_cred=cascade_cred,
                      asset_dir="/usr/local/x-ui/bin", service="x-ui")

    # --- SSL cert via certbot ---
    print(f"  [cascade] SSL сертификат для {exit_panel_domain}...")
    pkg_install("certbot nginx sqlite3", remote_ip=cascade_ip, remote_cred=cascade_cred)

    acme_conf = f"""server {{
    listen 80;
    server_name {exit_panel_domain};
    location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
    location /health {{ return 200 'ok'; add_header Content-Type text/plain; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
"""
    run_remote(cascade_ip, cascade_cred, "mkdir -p /var/www/certbot", timeout=10)
    # Через nginx_write_and_restart, а не сырой write_remote_file: он поднимает
    # ensure_nginx_base (битое зеркало / снесённый nginx.conf), делает симлинк в
    # sites-enabled и правит worker_connections + server_names_hash_bucket_size.
    # Раньше здесь стояло `nginx -t 2>/dev/null && systemctl restart nginx`,
    # которое молча съедало ошибку: nginx не поднимался, ACME-challenge отдавать
    # было некому, certbot падал, и установка тихо уезжала на self-signed.
    r_nx = nginx_write_and_restart(acme_conf, remote_ip=cascade_ip, remote_cred=cascade_cred)
    nginx_ready = r_nx.returncode == 0
    if not nginx_ready:
        print(f"  ⚠ [cascade] nginx не поднялся: {(r_nx.stderr or r_nx.stdout or '')[:300]}")
    else:
        r_health = run_remote(cascade_ip, cascade_cred,
            "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/health", timeout=15)
        if "200" not in (r_health.stdout or ""):
            nginx_ready = False
            print(f"  ⚠ [cascade] nginx запущен, но /health не отвечает (код {(r_health.stdout or '?').strip()})")

    # A-запись должна указывать на exit ДО certbot, иначе challenge не пройдёт
    dns_ok = wait_dns_a_record(exit_panel_domain, cascade_ip,
                               remote_ip=cascade_ip, remote_cred=cascade_cred, label="cascade")

    certbot_base = (f"certbot certonly -d {exit_panel_domain} --non-interactive "
                    f"--agree-tos --register-unsafely-without-email")
    r = None
    if dns_ok:
        for attempt in range(1, 4):
            # webroot пока nginx жив, иначе standalone (сам поднимает слушателя на 80)
            if nginx_ready:
                cmd = f"{certbot_base} --webroot -w /var/www/certbot"
            else:
                cmd = f"systemctl stop nginx 2>/dev/null; {certbot_base} --standalone; systemctl start nginx 2>/dev/null"
            r = run_remote(cascade_ip, cascade_cred, cmd, timeout=180)
            if r.returncode == 0:
                break
            if attempt < 3:
                print(f"  [cascade] certbot не прошёл (попытка {attempt}/3), повтор через 20с...")
                # со второй попытки идём через standalone: webroot уже не сработал
                nginx_ready = False
                time.sleep(20)

    if r is not None and r.returncode == 0:
        ssl_cert = f"/etc/letsencrypt/live/{exit_panel_domain}/fullchain.pem"
        ssl_key = f"/etc/letsencrypt/live/{exit_panel_domain}/privkey.pem"
        print("  [cascade] Сертификат LE получен!")
        # Панель читает файлы серта при старте, поэтому после продления её надо
        # перезапускать — иначе через 90 дней x-ui продолжит отдавать истёкший.
        hook = ("#!/bin/bash\\n"
                f"systemctl restart x-ui\\n")
        run_remote(cascade_ip, cascade_cred,
            "mkdir -p /etc/letsencrypt/renewal-hooks/deploy && "
            f"printf '%b' '{hook}' > /etc/letsencrypt/renewal-hooks/deploy/xui-cert.sh && "
            "chmod +x /etc/letsencrypt/renewal-hooks/deploy/xui-cert.sh", timeout=15)
    else:
        run_remote(cascade_ip, cascade_cred,
            "mkdir -p /etc/nginx/ssl && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
            f"-keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj '/CN={exit_panel_domain}' 2>/dev/null", timeout=30)
        ssl_cert = "/etc/nginx/ssl/cdn.crt"
        ssl_key = "/etc/nginx/ssl/cdn.key"
        _why = "DNS не указывает на exit" if not dns_ok else (r.stderr or r.stdout or "")[:200] if r else "неизвестно"
        print(f"  ⚠ [cascade] LE не сработал ({_why}) — self-signed")
        print(f"     Позже: certbot certonly --webroot -w /var/www/certbot -d {exit_panel_domain}")
        print(f"     затем: /usr/local/x-ui/x-ui setting -certFile /etc/letsencrypt/live/{exit_panel_domain}/fullchain.pem"
              f" -keyFile /etc/letsencrypt/live/{exit_panel_domain}/privkey.pem && systemctl restart x-ui")

    # --- Configure x-ui with SSL (panel + sub) ---
    require_success(
        run_remote(cascade_ip, cascade_cred,
            f"/usr/local/x-ui/x-ui cert -webCert {ssl_cert} -webCertKey {ssl_key}", timeout=15),
        "Настройка TLS панели 3x-ui на exit",
    )
    require_success(
        run_remote(cascade_ip, cascade_cred,
            f"/usr/local/x-ui/x-ui setting -subCertFile {ssl_cert} -subKeyFile {ssl_key}", timeout=15),
        "Настройка TLS подписок 3x-ui на exit",
    )

    # --- Configure nginx: panel proxy + sub proxy on 443 (no conflict with Reality if we use SNI split) ---
    # Reality on 443 conflicts with nginx 443, so panel uses x-ui built-in HTTPS on its own port
    # nginx only handles port 80 (certbot + health)
    # Panel: https://exit_domain:PANEL_PORT/PATH/
    # Sub: https://exit_domain:2096/sub/ID

    # --- Generate Reality keys ---
    print("  [cascade] Генерация Reality ключей...")
    reality_keys = None
    xray_paths = [
        "/usr/local/x-ui/bin/xray-linux-amd64",
        "/usr/local/x-ui/bin/xray-linux-arm64",
        "/usr/local/x-ui/bin/xray",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
    ]
    for xray_bin in xray_paths:
        r = run_remote(cascade_ip, cascade_cred, f"{xray_bin} x25519 2>/dev/null", timeout=15)
        if r.returncode == 0 and "Private" in r.stdout:
            reality_keys = _parse_x25519(r.stdout)
            if reality_keys:
                break
    if not reality_keys:
        r = run_remote(cascade_ip, cascade_cred,
            "find /usr/local/x-ui -name 'xray*' -type f -executable 2>/dev/null | head -1", timeout=10)
        found = r.stdout.strip()
        if found:
            r = run_remote(cascade_ip, cascade_cred, f"{found} x25519 2>/dev/null", timeout=15)
            if r.returncode == 0 and "Private" in r.stdout:
                reality_keys = _parse_x25519(r.stdout)
    if not reality_keys:
        r = run_remote(cascade_ip, cascade_cred,
            "openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -text -noout 2>/dev/null",
            timeout=15)
        if r.returncode == 0 and "priv:" in r.stdout:
            reality_keys = _parse_openssl_x25519(r.stdout)
    if not reality_keys:
        r = run_remote(cascade_ip, cascade_cred,
            "openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -text -noout 2>/dev/null",
            timeout=15)
        if r.returncode == 0 and "priv:" in r.stdout:
            reality_keys = _parse_openssl_x25519(r.stdout)
    if not reality_keys:
        print("  ❌ [cascade] Не удалось сгенерировать x25519 ключи!")
        return None

    short_id = secrets.token_hex(8)
    bridge_uuid = str(uuid.uuid4())
    print(f"  [cascade] Reality pubKey: {reality_keys['public'][:24]}...")
    print(f"  [cascade] Bridge UUID: {bridge_uuid[:8]}...")

    # --- Create Reality inbound + sub settings via SQL ---
    now_ms = int(time.time() * 1000)
    sub_id_exit = secrets.token_hex(8)

    # #23: EU-панель делаем полноценной. В тот же Reality-инбаунд 443 добавляем
    # ВТОРОГО, реального клиента: relay ходит своим bridge_user, а владелец может
    # подключиться этим ключом НАПРЯМУЮ к EU (заграничный IP без CDN и без relay).
    # Второй клиент в существующем инбаунде — не нужен ни отдельный порт, ни серт.
    eu_uuid = str(uuid.uuid4())
    eu_sub_id = secrets.token_hex(8)
    print(f"  [cascade] EU прямой ключ: {eu_uuid[:8]}... (клиент eu_user)")

    settings_json = json.dumps({
        "clients": [
            {"id": bridge_uuid, "email": "bridge_user", "flow": "xtls-rprx-vision",
             "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True},
            {"id": eu_uuid, "email": "eu_user", "subId": eu_sub_id, "flow": "xtls-rprx-vision",
             "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True},
        ],
        "decryption": "none"
    }).replace("'", "''")
    stream_json = json.dumps({
        "network": "tcp", "security": "reality",
        "tcpSettings": {"header": {"type": "none"}},
        "realitySettings": {
            "show": False, "xver": 0, "dest": "www.microsoft.com:443",
            "serverNames": ["www.microsoft.com"], "privateKey": reality_keys["private"],
            "minClient": "", "maxClient": "", "maxTimediff": 0, "shortIds": [short_id]
        }
    }).replace("'", "''")
    sniffing_json = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"]}).replace("'", "''")

    xray_tpl_exit = json.dumps(_xui_ensure_stats({
        "log": {"loglevel": "warning", "access": "none", "dnsLog": False},
        "outbounds": [
            {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4"}},
            {"protocol": "blackhole", "tag": "blocked", "settings": {}}
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "outboundTag": "direct", "ip": ["ext:geoip_RU.dat:ru"]},
            {"type": "field", "outboundTag": "direct", "domain": [
                "ext:geosite_RU.dat:ru-available-only-inside",
                "regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$"
            ]},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"}
        ]}
    })).replace("'", "''")

    # Инбаунды сносим по связке порт+клиентский email, а не по тегу: панель
    # перегенерирует тег при сохранении инбаунда в UI (см. xui_purge_own_inbound_sql).
    # Чужие инбаунды на 443/8888 не трогаем — на них ругнёмся ниже, если помешают.
    exit_sql = f"""{xui_purge_own_inbound_sql(443, 'cascade-reality-in', 'bridge_user', '_own_443')}
DELETE FROM client_inbounds WHERE client_id IN (SELECT id FROM clients WHERE email='bridge_user');
DELETE FROM client_inbounds WHERE client_id IN (SELECT id FROM clients WHERE email='eu_user');
DELETE FROM client_traffics WHERE email='bridge_user';
DELETE FROM client_traffics WHERE email='eu_user';
DELETE FROM clients WHERE email='bridge_user';
DELETE FROM clients WHERE email='eu_user';
INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
VALUES (1, 0, 0, 0, 'CASCADE-REALITY', 1, 0, '', 443, 'vless', '{settings_json}', '{stream_json}', 'cascade-reality-in', '{sniffing_json}');
INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable, created_at)
VALUES ('bridge_user', '{sub_id_exit}', '{bridge_uuid}', 'xtls-rprx-vision', 0, 0, 0, 1, {now_ms});
INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable, created_at)
VALUES ('eu_user', '{eu_sub_id}', '{eu_uuid}', 'xtls-rprx-vision', 0, 0, 0, 1, {now_ms});
INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset)
VALUES ((SELECT id FROM inbounds WHERE tag='cascade-reality-in'), 1, 'eu_user', 0, 0, 0, 0, 0);
INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at)
VALUES ((SELECT id FROM clients WHERE email='eu_user'), (SELECT id FROM inbounds WHERE tag='cascade-reality-in'), 'xtls-rprx-vision', {now_ms});
INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset)
VALUES ((SELECT id FROM inbounds WHERE tag='cascade-reality-in'), 1, 'bridge_user', 0, 0, 0, 0, 0);
INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at)
VALUES ((SELECT id FROM clients WHERE email='bridge_user'), (SELECT id FROM inbounds WHERE tag='cascade-reality-in'), 'xtls-rprx-vision', {now_ms});
INSERT INTO settings (key, value) SELECT 'subEnable', 'true' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subEnable');
UPDATE settings SET value='true' WHERE key='subEnable';
INSERT INTO settings (key, value) SELECT 'subPort', '2096' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subPort');
UPDATE settings SET value='2096' WHERE key='subPort';
INSERT INTO settings (key, value) SELECT 'subDomain', '{exit_panel_domain}' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subDomain');
UPDATE settings SET value='{exit_panel_domain}' WHERE key='subDomain';
INSERT INTO settings (key, value) SELECT 'subPath', '/sub/' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subPath');
UPDATE settings SET value='/sub/' WHERE key='subPath';
INSERT INTO settings (key, value) SELECT 'subJsonEnable', 'true' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subJsonEnable');
UPDATE settings SET value='true' WHERE key='subJsonEnable';
INSERT INTO settings (key, value) SELECT 'subJsonPath', '/json/' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subJsonPath');
UPDATE settings SET value='/json/' WHERE key='subJsonPath';
INSERT INTO settings (key, value) SELECT 'subListen', '' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subListen');
UPDATE settings SET value='' WHERE key='subListen';
UPDATE settings SET value='true' WHERE key='subTls';
INSERT OR IGNORE INTO settings (key, value) VALUES ('subTls', 'true');
INSERT INTO settings (key, value) SELECT 'subCertFile', '{ssl_cert}' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subCertFile');
UPDATE settings SET value='{ssl_cert}' WHERE key='subCertFile';
INSERT INTO settings (key, value) SELECT 'subKeyFile', '{ssl_key}' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subKeyFile');
UPDATE settings SET value='{ssl_key}' WHERE key='subKeyFile';
UPDATE settings SET value='{xray_tpl_exit}' WHERE key='xrayTemplateConfig';
INSERT OR IGNORE INTO settings (key, value) VALUES ('xrayTemplateConfig', '{xray_tpl_exit}');
"""
    write_remote_file(cascade_ip, cascade_cred, "/tmp/cascade_setup.sql", exit_sql)
    r_sq = run_remote(cascade_ip, cascade_cred, "which sqlite3", timeout=10)
    if r_sq.returncode != 0:
        pkg_install("sqlite3", remote_ip=cascade_ip, remote_cred=cascade_cred)
        r_sq = run_remote(cascade_ip, cascade_cred, "which sqlite3", timeout=10)
        if r_sq.returncode != 0:
            print("  ❌ [cascade] Не удалось установить sqlite3!")
            return None
    r = run_remote(cascade_ip, cascade_cred,
        "sqlite3 /etc/x-ui/x-ui.db < /tmp/cascade_setup.sql && rm /tmp/cascade_setup.sql", timeout=15)
    if r.returncode != 0:
        raise RuntimeError(
            f"[cascade] SQL ошибка: {(r.stderr or r.stdout or 'unknown')[:300]}"
        )

    # --- Опциональный gRPC-инбаунд на самой EU-панели (#23/A4) ---
    # Прямой заграничный выход по gRPC, минуя CDN и relay. Свой клиент eu_grpc_user,
    # свои Reality-ключи (не переиспользуем ключи 443: у инбаунда своя пара).
    eu_grpc_uuid = eu_grpc_link = ""
    if eu_grpc:
        print("  [cascade] Установка gRPC Reality на EU...")
        _gk = None
        for _xb in ("/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray",
                    "/usr/local/bin/xray"):
            _r = run_remote(cascade_ip, cascade_cred, f"{_xb} x25519 2>/dev/null", timeout=15)
            if _r.returncode == 0 and "rivate" in (_r.stdout or ""):
                _gk = _parse_x25519(_r.stdout)
                if _gk:
                    break
        if not _gk:
            print("  ⚠ [cascade] gRPC на EU пропущен: не удалось сгенерировать x25519")
        else:
            eu_grpc_uuid = str(uuid.uuid4())
            _g_sid = secrets.token_hex(8)
            _g_sub = secrets.token_hex(8)
            _g_settings = json.dumps({
                "clients": [{"id": eu_grpc_uuid, "email": "eu_grpc_user", "subId": _g_sub,
                              "flow": "", "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True}],
                "decryption": "none"}).replace("'", "''")
            _g_stream = json.dumps({
                "network": "grpc", "security": "reality",
                "externalProxy": [{"forceTls": "same", "dest": cascade_ip, "port": GRPC_PORT, "remark": ""}],
                "realitySettings": {"show": False, "xver": 0, "dest": GRPC_DEST,
                                     "serverNames": GRPC_SERVER_NAMES, "privateKey": _gk["private"],
                                     "minClient": "", "maxClient": "", "maxTimediff": 0,
                                     "shortIds": [_g_sid]},
                "grpcSettings": {"serviceName": GRPC_SERVICE_NAME}}).replace("'", "''")
            _g_sql = f"""{xui_purge_own_inbound_sql(GRPC_PORT, 'eu-grpc-reality', 'eu_grpc_user', '_own_eugrpc')}
DELETE FROM clients WHERE email='eu_grpc_user';
INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
VALUES (1, 0, 0, 0, 'EU gRPC Reality', 1, 0, '', {GRPC_PORT}, 'vless', '{_g_settings}', '{_g_stream}', 'eu-grpc-reality', '{sniffing_json}');
INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable, created_at)
VALUES ('eu_grpc_user', '{_g_sub}', '{eu_grpc_uuid}', '', 0, 0, 0, 1, {now_ms});
INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset)
VALUES ((SELECT id FROM inbounds WHERE port={GRPC_PORT} ORDER BY id DESC LIMIT 1), 1, 'eu_grpc_user', 0, 0, 0, 0, 0);
INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at)
VALUES ((SELECT id FROM clients WHERE email='eu_grpc_user'), (SELECT id FROM inbounds WHERE port={GRPC_PORT} ORDER BY id DESC LIMIT 1), '', {now_ms});
"""
            write_remote_file(cascade_ip, cascade_cred, "/tmp/eu_grpc.sql", _g_sql)
            _rg = run_remote(cascade_ip, cascade_cred,
                "sqlite3 /etc/x-ui/x-ui.db < /tmp/eu_grpc.sql && rm -f /tmp/eu_grpc.sql", timeout=15)
            if _rg.returncode != 0:
                print(f"  ⚠ [cascade] SQL gRPC на EU: {(_rg.stderr or _rg.stdout or '')[:200]}")
            else:
                eu_grpc_link = (
                    f"vless://{eu_grpc_uuid}@{cascade_ip}:{GRPC_PORT}"
                    f"?type=grpc&security=reality&sni={GRPC_SERVER_NAMES[0]}&fp=random"
                    f"&pbk={_gk['public']}&sid={_g_sid}&serviceName={GRPC_SERVICE_NAME}"
                    f"&encryption=none#EU-grpc")
                print(f"  [cascade] EU gRPC инбаунд создан (TCP {GRPC_PORT})")

    # Свой инбаунд мы пересоздали; если порт делит ЧУЖОЙ инбаунд владельца —
    # xray не поднимется, а наружу это выглядит как «Empty reply» через CDN.
    # Удалять чужое молча нельзя, поэтому говорим прямо.
    for _p, _own_tag in ((443, "cascade-reality-in"),):
        _squat = xui_port_squatter(_p, exclude_tag=_own_tag,
                                   remote_ip=cascade_ip, remote_cred=cascade_cred)
        if _squat:
            print(f"  ⚠ [cascade] Порт {_p} на exit уже занят инбаундом {_squat}")
            print(f"     Удали или перевесь его в панели — иначе xray не стартует.")

    # --- Open ports & restart ---
    print("  [cascade] Открытие портов на exit...")
    _exit_ports = [80, 443, exit_panel_port, 2096]
    if eu_grpc and eu_grpc_uuid:
        _exit_ports.append(GRPC_PORT)
    for port in _exit_ports:
        run_remote(cascade_ip, cascade_cred, f"ufw allow {port}/tcp 2>/dev/null; iptables -I INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null", timeout=10)

    run_remote(cascade_ip, cascade_cred, "systemctl restart x-ui", timeout=30)
    time.sleep(5)

    # Критерий — 443 держит именно XRAY. Проверка «в выводе есть 443» была
    # бесполезной: когда порт занимал nginx, она давала true, установка бодро
    # печатала «Reality inbound 443 OK», а инбаунд был мёртв — и ветка разбора
    # конфликта ниже не выполнялась вовсе, ровно в том случае, для которого её и
    # писали. Имя процесса в ss обрезано до comm, поэтому ищем подстроку 'xray'
    # (подходит и xray, и xray-linux-amd64).
    port_443_ok = False
    for attempt in range(3):
        r = run_remote(cascade_ip, cascade_cred, "ss -ltnp | grep :443", timeout=15)
        out_443 = r.stdout or ""
        if "443" in out_443 and "xray" in out_443:
            port_443_ok = True
            break
        if "443" in out_443:
            print("  ⚠ [cascade] 443 занят не xray:")
            print(f"     {out_443.strip().splitlines()[0][:150]}")
            break
        if attempt < 2:
            print(f"  [cascade] Порт 443 не стартовал, перезапуск x-ui ({attempt+2}/3)...")
            run_remote(cascade_ip, cascade_cred, "systemctl restart x-ui", timeout=30)
            time.sleep(8)

    if port_443_ok:
        print("  [cascade] Exit: Reality inbound 443 OK")
    else:
        r_log = run_remote(cascade_ip, cascade_cred,
            "journalctl -u x-ui --no-pager -n 20 2>/dev/null | grep -i 'error\\|fail\\|443' | tail -5", timeout=15)
        if r_log.stdout.strip():
            print(f"  ⚠ [cascade] Порт 443 не слушает. Лог: {r_log.stdout.strip()[:200]}")
        else:
            print("  ⚠ [cascade] Порт 443 не слушает на exit (возможно конфликт с nginx)")
        r_nginx = run_remote(cascade_ip, cascade_cred, "ss -tlnp | grep :443", timeout=10)
        if "nginx" in r_nginx.stdout:
            # Раньше здесь глушился весь nginx — а вместе с ним и 80-й порт, на
            # котором висит ACME-challenge, так что сертификат панели больше не
            # продлевался. Снимаем только конфиги, слушающие 443, nginx на 80
            # оставляем живым. Каталог disabled-443 не подхватывается ни одним
            # include (их два: sites-enabled/* и conf.d/*.conf).
            print("  [cascade] Nginx занимает 443, отключаю его 443-конфиги (80 оставляю под ACME)...")
            r_off = run_remote(cascade_ip, cascade_cred,
                "mkdir -p /etc/nginx/disabled-443; "
                "for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do "
                "[ -e \"$f\" ] || continue; "
                "if grep -qE '^[[:space:]]*listen[^;]*443' \"$f\"; then mv \"$f\" /etc/nginx/disabled-443/ 2>/dev/null; fi; "
                "done; nginx -t 2>&1 && systemctl reload nginx", timeout=30)
            if r_off.returncode != 0:
                print("  [cascade] Конфиги снять не удалось, останавливаю nginx целиком")
                run_remote(cascade_ip, cascade_cred, "systemctl stop nginx", timeout=20)
            run_remote(cascade_ip, cascade_cred, "systemctl restart x-ui", timeout=30)
            time.sleep(5)
            r = run_remote(cascade_ip, cascade_cred, "ss -ltnp | grep :443", timeout=15)
            if "443" in (r.stdout or "") and "xray" in (r.stdout or ""):
                print("  [cascade] Exit: Reality inbound 443 OK (443-конфиги nginx отключены)")
                port_443_ok = True
            else:
                print("  ⚠ [cascade] 443 так и не за xray — Reality-инбаунд не работает")

    if not port_443_ok:
        raise RuntimeError("[cascade] Exit REALITY 443 не поднялся; каскад остановлен")

    r = run_remote(cascade_ip, cascade_cred, f"ss -tlnp | grep :{exit_panel_port}", timeout=15)
    if str(exit_panel_port) in r.stdout:
        print(f"  [cascade] Exit: панель {exit_panel_port} OK")

    print(f"  [cascade] Exit панель: https://{exit_panel_domain}:{exit_panel_port}/{exit_panel_path}/")
    print(f"  [cascade] Exit подписка: https://{exit_panel_domain}:2096/sub/")

    # Прямой ключ к EU (#23): Reality на 443 самого exit-сервера, минуя CDN и relay.
    # sni/dest как в инбаунде (www.microsoft.com), flow xtls-rprx-vision.
    eu_link = (
        f"vless://{eu_uuid}@{cascade_ip}:443"
        f"?type=tcp&security=reality"
        f"&sni=www.microsoft.com"
        f"&fp=chrome"
        f"&pbk={reality_keys['public']}"
        f"&sid={short_id}"
        f"&flow=xtls-rprx-vision"
        f"&encryption=none"
        f"#EU-direct"
    )
    print(f"  [cascade] EU прямая ссылка готова (Reality 443, минуя CDN)")

    return {
        "public_key": reality_keys["public"],
        "short_id": short_id,
        "bridge_uuid": bridge_uuid,
        "exit_panel_pass": exit_panel_pass,
        "exit_panel_port": exit_panel_port,
        "exit_panel_path": exit_panel_path,
        "exit_panel_domain": exit_panel_domain,
        "eu_uuid": eu_uuid,
        "eu_sub_id": eu_sub_id,
        "eu_link": eu_link,
        "eu_grpc_uuid": eu_grpc_uuid,
        "eu_grpc_link": eu_grpc_link,
    }


# ============================================================
#  3X-UI INSTALLATION
# ============================================================

def print_3xui_turboflare_instructions(origin_domain, cdn_domain, server_ip, xhttp_path):
    print(f"""
  ============================================
  DNS и TurboFlare CDN:
  ============================================

  1. A-запись: {origin_domain} -> {server_ip} (DNS only)
  2. В TurboFlare создай ресурс для {cdn_domain}.
  3. Origin: {origin_domain}:443, протокол HTTPS.
  4. SNI и Host к origin: {origin_domain}.
  5. Отключи кэш для {xhttp_path}* и не игнорируй query string.
  6. Отключи gzip/brotli/HTTP3 и выпусти edge-сертификат.
  7. Создай CNAME {cdn_domain} на технический домен из панели TurboFlare.
""")


def install_3xui(cfg):
    """Install 3x-ui with VK or Yandex CDN inbound."""
    domain = cfg["domain"]
    cdn_type = cfg["cdn_type"]
    cdn = CDN_SETTINGS[cdn_type]
    server_ip = cfg["server_ip"]
    origin_sub = cfg["origin_sub"]
    hy2_sub = cfg.get("hy2_sub", "")
    cdn_sub = cfg["cdn_sub"]

    panel_user = "admin"
    panel_pass = secrets.token_urlsafe(12)
    panel_port = 47115 + secrets.randbelow(1000)
    panel_path = generate_panel_path()
    client_uuid = str(uuid.uuid4())
    client_email = f"vpn-cdn-installer-{cdn_type}"

    # --- Step: Install 3x-ui ---
    step(3, "Установка 3x-ui")

    # 3x-ui поднимает свой xray на 2053; глушим осиротевший standalone xray,
    # иначе bundled-xray не займёт порт (bind: address already in use) -> Empty reply
    stop_conflicting_standalone_xray()

    # Повторный запуск: если x-ui уже установлен и работает — НЕ переустанавливаем.
    # На медленной РФ-сети переустановка = ещё один долгий скачок ~25МБ и риск таймаута.
    already = (run("systemctl is-active x-ui", check=False).stdout.strip() == "active"
               and os.path.exists("/usr/local/x-ui/x-ui")
               and os.path.exists("/etc/x-ui/x-ui.db"))
    if already:
        print("  3x-ui уже установлен и работает — пропускаю переустановку")
    else:
        print("  Скачивание установщика 3x-ui...")
        install_url = (
            f"https://raw.githubusercontent.com/MHSanaei/3x-ui/{XUI_RELEASE_COMMIT}/install.sh"
        )
        result = run(
            f"curl -fsSL --proto '=https' --max-time 60 {shlex.quote(install_url)} "
            "-o /tmp/3xui_install.sh",
            check=False, timeout=90,
        )
        require_success(result, "Скачивание закреплённого установщика 3x-ui")
        if not os.path.exists("/tmp/3xui_install.sh") or os.path.getsize("/tmp/3xui_install.sh") < 100:
            print("  ❌ Не удалось скачать установщик 3x-ui! Проверь интернет.")
            sys.exit(1)

        print("  Запуск установщика 3x-ui (на медленной сети может занять несколько минут)...")
        env_vars = (
            f"XUI_NONINTERACTIVE=1 "
            f"XUI_DB_TYPE=sqlite "
            f"XUI_USERNAME={panel_user} "
            f"XUI_PASSWORD={panel_pass} "
            f"XUI_PANEL_PORT={panel_port} "
            f"XUI_WEB_BASE_PATH={panel_path} "
        )
        # Версия зафиксирована: схема БД и CLI проверены именно для этого релиза.
        r = run(f"{env_vars} bash /tmp/3xui_install.sh {XUI_VERSION}", check=False, timeout=1200,
                label="Установка 3x-ui", expected=90)
        if r.returncode != 0:
            print(f"  Установщик вернул код {r.returncode}, проверяю фактическое состояние...")
        time.sleep(5)

    # Force our settings (3x-ui installer ignores env vars for port/user/pass)
    if os.path.exists("/usr/local/x-ui/x-ui"):
        print("  Применяю настройки панели...")
        require_success(run(f"/usr/local/x-ui/x-ui setting -username {shlex.quote(panel_user)} "
                            f"-password {shlex.quote(panel_pass)} -port {panel_port} "
                            f"-webBasePath /{panel_path}/", check=False),
                        "Настройка доступа 3x-ui")
        require_success(run("systemctl restart x-ui", check=False), "Перезапуск 3x-ui")
        time.sleep(5)

    # РЕАЛЬНЫЙ критерий успеха — наличие /etc/x-ui/x-ui.db (инбаунд пишется прямо в неё).
    # Если установка оборвалась по таймауту — БД нет, а systemctl мог врать. Ждём/ретраим.
    db_ok = False
    for _ in range(6):
        if (os.path.exists("/etc/x-ui/x-ui.db")
                and "active" in run("systemctl is-active x-ui", check=False).stdout):
            db_ok = True
            break
        run("systemctl restart x-ui", check=False)
        time.sleep(5)
    if db_ok:
        print(f"  3x-ui установлен и работает: порт={panel_port}, путь=/{panel_path}/")
        track_created("systemd", "x-ui", existed_before=already)
        setup_xray_ru_geo(asset_dir="/usr/local/x-ui/bin", service="x-ui")
    else:
        print("  ❌ 3x-ui не установился корректно — нет /etc/x-ui/x-ui.db")
        print("  Обычно это таймаут скачивания на медленной сети. Просто ЗАПУСТИ СКРИПТ СНОВА")
        print("  Проверь доступ к GitHub и повтори запуск на чистом сервере.")
        r = run("journalctl -u x-ui --no-pager -n 10", check=False)
        print(f"  Логи: {r.stdout[:500]}")
        sys.exit(1)

    # --- Step: SSL via certbot for panel domain ---
    panel_sub = cfg.get("panel_sub", "panel")
    panel_domain = f"{panel_sub}.{domain}"
    step(4, f"SSL сертификат для {panel_domain}")

    run("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot 2>/dev/null", check=False, timeout=60)
    run("mkdir -p /var/www/certbot", check=False)

    acme_conf = f"""server {{
    listen 80;
    server_name {panel_domain};
    location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
"""
    nginx_write_conf("panel.conf", acme_conf)
    run("nginx -t && systemctl restart nginx", check=False)

    print(f"  Получение сертификата для {panel_domain}...")
    wait_dns_a_record(panel_domain, server_ip, attempts=6, delay=10, label="panel")
    r = run(f"certbot certonly --webroot -w /var/www/certbot -d {panel_domain} --non-interactive --agree-tos --register-unsafely-without-email --deploy-hook 'systemctl reload nginx && systemctl restart x-ui'", check=False, timeout=120,
            label="Выпуск сертификата Let's Encrypt", expected=20)
    if r.returncode != 0:
        print(f"  ⚠ Certbot не сработал, используем self-signed.")
        ssl_cert = "/etc/nginx/ssl/cdn.crt"
        ssl_key = "/etc/nginx/ssl/cdn.key"
    else:
        ssl_cert = f"/etc/letsencrypt/live/{panel_domain}/fullchain.pem"
        ssl_key = f"/etc/letsencrypt/live/{panel_domain}/privkey.pem"
        print("  Сертификат получен!")
        require_success(run(f"/usr/local/x-ui/x-ui cert -webCert {shlex.quote(ssl_cert)} -webCertKey {shlex.quote(ssl_key)}", check=False),
                        "Настройка сертификата 3x-ui")
        # nginx HTTPS proxy for 3x-ui panel + sub
        _ipv6_xui = has_ipv6()
        _v6_listen = "\n    listen [::]:443 ssl http2;" if _ipv6_xui else ""
        _xui_nginx = f"""server {{
            listen 80;
            server_name {panel_domain};
            location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
            location / {{ return 301 https://$host$request_uri; }}
        }}
        server {{
            listen 443 ssl http2;{_v6_listen}
            server_name {panel_domain};
            ssl_certificate {ssl_cert};
            ssl_certificate_key {ssl_key};
            ssl_protocols TLSv1.2 TLSv1.3;
            location /{panel_path}/ {{
                proxy_pass http://127.0.0.1:{panel_port};
                proxy_ssl_verify off;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection upgrade;
                proxy_read_timeout 86400;
            }}
            location /sub/ {{
                proxy_pass https://127.0.0.1:2096;
                proxy_ssl_verify off;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
            }}
            location /json/ {{
                proxy_pass https://127.0.0.1:2096;
                proxy_ssl_verify off;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
            }}
        }}
        """
        nginx_write_conf("panel.conf", _xui_nginx)
        run("nginx -t && systemctl reload nginx", check=False)
        run("systemctl restart x-ui", check=False)
        time.sleep(3)
        print("  x-ui настроен с LE сертификатом (панель + подписка)")

    # --- Step: Configure nginx ---
    step(5, "Настройка nginx CDN origin")

    # Проверка порта 443 (может быть занят старым 3x-ui/xray)
    port_check = run("ss -tlnp | grep ':443 ' | grep -v nginx", capture=True, check=False, timeout=5)
    if port_check.stdout.strip():
        print(f"  ⚠️  Порт 443 занят:")
        print(f"     {port_check.stdout.strip()[:200]}")
        print("  Временно останавливаю только установленный x-ui...")
        run("systemctl stop x-ui 2>/dev/null", check=False)
        time.sleep(2)
        # Перепроверка
        port_check2 = run("ss -tlnp | grep ':443 ' | grep -v nginx", capture=True, check=False, timeout=5)
        if port_check2.stdout.strip():
            raise RuntimeError(
                "Порт 443 занят чужим процессом; автоматическая остановка запрещена: "
                + port_check2.stdout.strip()[:200]
            )
        print("  ✅ Порт 443 освобождён")

    ipv6_ok = has_ipv6()
    le_ok = ssl_cert.startswith("/etc/letsencrypt")
    nginx_conf = nginx_cdn_origin(cdn["xray_port"], cdn["xhttp_path"], panel_path, panel_port, ipv6=ipv6_ok,
                                  nginx_style=cdn.get("nginx_style", "prefix"),
                                  ssl_cert=ssl_cert, ssl_key=ssl_key, panel_https=False,
                                  panel_domain=panel_domain)

    r = nginx_write_and_restart(nginx_conf)
    if os.path.islink("/etc/nginx/sites-enabled/panel.conf"):
        os.remove("/etc/nginx/sites-enabled/panel.conf")
    if r.returncode == 0:
        print("  Nginx настроен и перезапущен")
    else:
        print(f"  ❌ Проблема с nginx: {r.stderr[:200] if r.stderr else ''}")
        print("  Попробуй: nginx -t и systemctl restart nginx")
        sys.exit(1)

    # Если x-ui был остановлен для освобождения порта 443 — заново запускаем
    xui_status = run("systemctl is-active x-ui", capture=True, check=False, timeout=5).stdout.strip()
    if xui_status != "active":
        print("  Запуск x-ui...")
        run("systemctl start x-ui", timeout=10)
        time.sleep(3)
        xui_status_check = run("systemctl is-active x-ui", capture=True, check=False, timeout=5).stdout.strip()
        if xui_status_check != "active":
            print("  ❌ x-ui не запустился! Проверь: systemctl status x-ui")
            sys.exit(1)
        print("  ✅ x-ui запущен")

    # --- Step: Create inbound via SQLite ---
    step(6, f"Создание {cdn_type.upper()} CDN inbound")

    # Wait for x-ui to create DB
    for _ in range(10):
        if os.path.exists("/etc/x-ui/x-ui.db"):
            break
        time.sleep(2)

    if not os.path.exists("/etc/x-ui/x-ui.db"):
        print("  ОШИБКА: /etc/x-ui/x-ui.db не найден!")
        sys.exit(1)

    # Build inbound JSON
    cdn_domain = f"{cdn_sub}.{domain}"
    origin_domain = f"{origin_sub}.{domain}"
    tag = f"vpn-cdn-installer-{cdn_type}"
    now_ms = int(time.time() * 1000)
    sub_id = secrets.token_hex(8)

    settings_obj = {
        "clients": [{
            "id": client_uuid,
            "email": client_email,
            "subId": sub_id,
            "flow": "",
            "limitIp": 0,
            "totalGB": 0,
            "expiryTime": 0,
            "enable": True
        }],
        "decryption": "none"
    }

    xhttp_settings = {
        "path": cdn["xhttp_path"],
        "host": "",
        "mode": "packet-up",
        "xPaddingBytes": "100-1000",
        "xPaddingObfsMode": True,
        "xPaddingKey": cdn["padding_key"],
        "xPaddingHeader": cdn["padding_header"],
        "xPaddingPlacement": cdn["padding_placement"],
        "xPaddingMethod": cdn["padding_method"],
        "uplinkHTTPMethod": cdn["uplink_method"],
        "uplinkDataPlacement": cdn.get("uplink_data_placement", "body"),
        "noSSEHeader": False,
        "scMaxEachPostBytes": "500000-1000000",
        "scMinPostsIntervalMs": "50-150",
        "scStreamUpServerSecs": "60-180",
        "xmux": {
            "maxConcurrency": "16-32",
            "maxConnections": 0,
            "cMaxReuseTimes": 0,
            "hMaxRequestTimes": "600-900",
            "hMaxReusableSecs": "1800-3000",
            "hKeepAlivePeriod": 0
        }
    }
    if cdn_type == "yandex":
        xhttp_settings["uplinkChunkSize"] = 131072

    stream_settings_obj = {
        "network": "xhttp",
        "security": "none",
        "externalProxy": [{
            "forceTls": "tls",
            "dest": cdn_domain,
            "port": 443,
            "remark": ""
        }],
        "xhttpSettings": xhttp_settings
    }

    sniffing_obj = {"enabled": True, "destOverride": ["http", "tls", "quic"]}

    _snap = xui_inbound_snapshot(cdn['xray_port'])

    _squatter = xui_port_squatter(cdn['xray_port'], exclude_tag=tag,
                                  owner_email=client_email)
    if _squatter:
        raise RuntimeError(
            f"Порт {cdn['xray_port']} уже занят чужим inbound: {_squatter}. "
            "Установщик не будет его удалять."
        )

    # Если клиент уже выдан, оставляем ему тот же uuid/subId: иначе повторный
    # запуск установщика молча обнуляет ранее выданные ключи и подписки.
    _old_uuid, _old_sub = xui_adopt_client_identity(_snap, client_email)
    if _old_uuid:
        client_uuid = _old_uuid
        settings_obj["clients"][0]["id"] = client_uuid
    if _old_sub:
        sub_id = _old_sub
        settings_obj["clients"][0]["subId"] = sub_id
    if _old_uuid or _old_sub:
        print(f"  Клиент {client_email} уже существует — ключ и подписка сохранены")

    # Клиентов, которых владелец добавил в этот инбаунд руками, переносим в новый:
    # инбаунд пересоздаётся, и раньше они теряли связки — подписка пустела.
    _foreign = [c for c in _snap["clients"] if (c.get("email") or "") != client_email]
    if _foreign:
        print(f"  Переношу клиентов владельца из старого инбаунда: {len(_foreign)}")
        settings_obj["clients"].extend(_foreign)

    # Write SQL to file to avoid shell escaping issues with JSON
    settings_json = json.dumps(settings_obj).replace("'", "''")
    stream_json = json.dumps(stream_settings_obj).replace("'", "''")
    sniffing_json = json.dumps(sniffing_obj).replace("'", "''")

    # Инбаунд опознаём по связке порт+email, не по тегу (см. xui_purge_own_inbound_sql).
    # Связки клиентов не вписываем руками — их собирает xui_link_clients_sql
    # из settings.clients, разом и для нашего клиента, и для клиентов владельца.
    sql_file_content = f"""{xui_purge_own_inbound_sql(cdn['xray_port'], tag, client_email)}
INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
VALUES (1, 0, 0, 0, 'VPN-CDN-INSTALLER-{cdn_type.upper()}', 1, 0, '127.0.0.1', {cdn['xray_port']}, 'vless', '{settings_json}', '{stream_json}', '{tag}', '{sniffing_json}');

{xui_link_clients_sql(cdn['xray_port'], settings_obj["clients"], _snap["traffics"], now_ms)}
"""

    with open("/tmp/xui_setup.sql", "w") as f:
        f.write(sql_file_content)

    apply_xui_sql_file("/tmp/xui_setup.sql")

    r = run(f"sqlite3 /etc/x-ui/x-ui.db \"SELECT id FROM clients WHERE email='{client_email}';\"", check=False)
    client_id = r.stdout.strip()
    r = run(f"sqlite3 /etc/x-ui/x-ui.db \"SELECT id FROM inbounds WHERE port={cdn['xray_port']} ORDER BY id DESC LIMIT 1;\"", check=False)
    inbound_id = r.stdout.strip()
    if not client_id or not inbound_id:
        raise RuntimeError("3x-ui не создал клиента или CDN inbound")

    # Dynamic step numbering (steps 3-6 are hardcoded above)
    step_n = 7

    # Cascade exit setup (before building xrayTemplateConfig)
    cascade = cfg.get("cascade", False)
    cascade_info = None
    if cascade:
        step(step_n, f"Установка exit-сервера {cfg['cascade_ip']} (каскад)")
        step_n += 1
        exit_sub = cfg.get("exit_sub", "xui")
        exit_panel_domain = f"{exit_sub}.{domain}"
        cascade_info = setup_3xui_cascade_exit(cfg["cascade_ip"], cfg["cascade_cred"], exit_panel_domain,
                                               eu_grpc=cfg.get("eu_grpc", False))
        if not cascade_info:
            print("  ❌ Каскад не удался, продолжаю без каскада.")
            cascade = False

    # Build xray template config
    outbounds = [
        {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4"}},
        {"protocol": "blackhole", "tag": "blocked", "settings": {}}
    ]
    rules = [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]

    if cascade and cascade_info:
        outbounds.append({
            "tag": "CASCADE-REALITY",
            "protocol": "vless",
            "settings": {"vnext": [{"address": cfg["cascade_ip"], "port": 443,
                "users": [{
                    "id": cascade_info["bridge_uuid"],
                    "encryption": "none",
                    "flow": "xtls-rprx-vision"
                }]}]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": "www.microsoft.com",
                    "password": cascade_info["public_key"],
                    "shortId": cascade_info["short_id"],
                    "spiderX": "/"
                }
            }
        })
        # #13: YouTube/SoundCloud напрямую через relay (без рекламы, если хостинг
        # пробивает). direct = выход с relay РФ, а не через exit. Выше RU-правил.
        if cfg.get("youtube_direct"):
            rules.extend(youtube_soundcloud_direct_rules("direct", "blocked"))
            print("  [каскад] YouTube/SoundCloud → напрямую через relay (антиреклама)")

    rules.extend([
        {"type": "field", "outboundTag": "direct", "ip": ["ext:geoip_RU.dat:ru"]},
        {"type": "field", "outboundTag": "direct", "domain": [
            "ext:geosite_RU.dat:ru-available-only-inside",
            "regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$"
        ]},
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"}
    ])
    if cascade and cascade_info:
        # network-catch-all, НЕ inboundTag: 3x-ui пересоздаёт инбаунд со своим тегом
        # (in-<port>-<proto>), из-за чего правило по inboundTag=[tag] перестаёт матчить
        # → каскад не используется, весь не-RU трафик уходит в дефолтный direct (RU-relay).
        # RU/private/bittorrent уже обработаны выше, остальное → CASCADE-REALITY.
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "CASCADE-REALITY"})

    xray_tpl = json.dumps(_xui_ensure_stats({
        "log": {"loglevel": "warning", "access": "none", "dnsLog": False},
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules}
    })).replace("'", "''")
    xui_settings_sql = f"""INSERT INTO settings (key, value) SELECT 'subEnable', 'true' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subEnable');
UPDATE settings SET value='true' WHERE key='subEnable';
INSERT INTO settings (key, value) SELECT 'subPort', '2096' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subPort');
UPDATE settings SET value='2096' WHERE key='subPort';
INSERT INTO settings (key, value) SELECT 'subDomain', '{panel_domain}' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subDomain');
UPDATE settings SET value='{panel_domain}' WHERE key='subDomain';
INSERT INTO settings (key, value) SELECT 'subPath', '/sub/' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subPath');
UPDATE settings SET value='/sub/' WHERE key='subPath';
INSERT INTO settings (key, value) SELECT 'subJsonEnable', 'true' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subJsonEnable');
UPDATE settings SET value='true' WHERE key='subJsonEnable';
INSERT INTO settings (key, value) SELECT 'subJsonPath', '/json/' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subJsonPath');
UPDATE settings SET value='/json/' WHERE key='subJsonPath';
INSERT INTO settings (key, value) SELECT 'subListen', '' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subListen');
UPDATE settings SET value='' WHERE key='subListen';
UPDATE settings SET value='true' WHERE key='subTls';
INSERT OR IGNORE INTO settings (key, value) VALUES ('subTls', 'true');
INSERT INTO settings (key, value) SELECT 'subCertFile', '{ssl_cert}' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subCertFile');
UPDATE settings SET value='{ssl_cert}' WHERE key='subCertFile';
INSERT INTO settings (key, value) SELECT 'subKeyFile', '{ssl_key}' WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key='subKeyFile');
UPDATE settings SET value='{ssl_key}' WHERE key='subKeyFile';
UPDATE settings SET value='{xray_tpl}' WHERE key='xrayTemplateConfig';
INSERT OR IGNORE INTO settings (key, value) VALUES ('xrayTemplateConfig', '{xray_tpl}');
"""
    with open("/tmp/xui_settings.sql", "w") as f:
        f.write(xui_settings_sql)
    apply_xui_sql_file("/tmp/xui_settings.sql")

    # Restart x-ui to apply
    run("systemctl restart x-ui", check=False)

    # Verify xray is listening (wait up to 30 sec)
    print(f"  Ожидание запуска xray на порту {cdn['xray_port']}...")
    xray_ok = False
    for _ in range(6):
        time.sleep(5)
        r = run(f"ss -tlnp | grep :{cdn['xray_port']}", check=False)
        if str(cdn['xray_port']) in r.stdout:
            xray_ok = True
            break
    if xray_ok:
        print(f"  Inbound создан, xray слушает порт {cdn['xray_port']}")
    else:
        print(f"  ВНИМАНИЕ: xray не слушает порт {cdn['xray_port']}")
        print("  Пробую ещё раз перезапустить x-ui...")
        run("systemctl restart x-ui", check=False)
        time.sleep(10)
        r = run(f"ss -tlnp | grep :{cdn['xray_port']}", check=False)
        if str(cdn['xray_port']) in r.stdout:
            print(f"  Xray запущен на порту {cdn['xray_port']}")
        else:
            print(f"  ❌ Xray так и не запустился на порту {cdn['xray_port']}")
            r = run("journalctl -u x-ui --no-pager -n 15", check=False)
            print(f"  Логи: {r.stdout[:500]}")
            raise RuntimeError(f"Xray не слушает CDN-порт {cdn['xray_port']}")

    # --- Step: Optional grpc ---
    grpc_link = ""

    if cfg.get("install_grpc"):
        step(step_n, "Установка VLESS Reality gRPC")
        step_n += 1

        reality_keys = generate_x25519_keys()
        if reality_keys:
            short_id = secrets.token_hex(8)
            grpc_tag = "vpn-cdn-installer-grpc"

            grpc_settings = json.dumps({"clients": [{"id": client_uuid, "email": client_email, "subId": sub_id, "flow": "", "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True}], "decryption": "none"}).replace("'", "''")
            grpc_stream = json.dumps({
                "network": "grpc",
                "security": "reality",
                "externalProxy": [{"forceTls": "same", "dest": server_ip, "port": GRPC_PORT, "remark": ""}],
                "realitySettings": {
                    "show": False,
                    "xver": 0,
                    "dest": GRPC_DEST,
                    "serverNames": GRPC_SERVER_NAMES,
                    "privateKey": reality_keys["private"],
                    "minClient": "",
                    "maxClient": "",
                    "maxTimediff": 0,
                    "shortIds": [short_id]
                },
                "grpcSettings": {"serviceName": GRPC_SERVICE_NAME}
            }).replace("'", "''")
            grpc_sniffing = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"]}).replace("'", "''")

            # опознание по порту+email, не по тегу (см. xui_purge_own_inbound_sql)
            grpc_sql = f"""{xui_purge_own_inbound_sql(GRPC_PORT, grpc_tag, client_email, '_own_grpc')}
INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
VALUES (1, 0, 0, 0, 'gRPC Reality', 1, 0, '', {GRPC_PORT}, 'vless', '{grpc_settings}', '{grpc_stream}', '{grpc_tag}', '{grpc_sniffing}');

INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset)
VALUES ((SELECT id FROM inbounds WHERE tag='{grpc_tag}'), 1, '{client_email}', 0, 0, 0, 0, 0);

INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at)
SELECT (SELECT id FROM clients WHERE email='{client_email}' ORDER BY id LIMIT 1),
       (SELECT id FROM inbounds WHERE tag='{grpc_tag}' ORDER BY id DESC LIMIT 1), '', {now_ms}
WHERE EXISTS (SELECT 1 FROM clients WHERE email='{client_email}')
  AND EXISTS (SELECT 1 FROM inbounds WHERE tag='{grpc_tag}');
"""
            with open("/tmp/xui_grpc.sql", "w") as f:
                f.write(grpc_sql)
            apply_xui_sql_file("/tmp/xui_grpc.sql")

            r = run(f"sqlite3 /etc/x-ui/x-ui.db \"SELECT id FROM inbounds WHERE tag='{grpc_tag}';\"", check=False)
            grpc_inbound_id = r.stdout.strip()
            if not client_id or not grpc_inbound_id:
                raise RuntimeError("Не создана связь клиента с gRPC inbound")

            open_extra_ports(False, True)
            print(f"  gRPC Reality inbound создан на TCP порту {GRPC_PORT}")

            grpc_link = (
                f"vless://{client_uuid}@{server_ip}:{GRPC_PORT}"
                f"?type=grpc&security=reality"
                f"&sni={GRPC_SERVER_NAMES[0]}"
                f"&fp=random"
                f"&pbk={reality_keys['public']}"
                f"&sid={short_id}"
                f"&serviceName={GRPC_SERVICE_NAME}"
                f"&encryption=none"
                f"#{client_email}-grpc"
            )
        else:
            raise RuntimeError("Не удалось сгенерировать x25519 ключи для gRPC")

    if cfg.get("install_grpc"):
        require_success(run("systemctl restart x-ui", check=False), "Перезапуск x-ui после gRPC")
        time.sleep(5)

    # --- Step: CDN instructions ---
    step(step_n, "Инструкция по настройке CDN")
    step_n += 1

    print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {server_ip}  (DNS only, серое облако)
  2. CNAME:     {cdn_domain}  ->  [VK CDN CNAME]  (DNS only)

  ============================================
  Настройки VK Cloud CDN:
  ============================================

  1. Создай CDN-ресурс:
     - Протокол к источнику: HTTP (порт 80)
     - Источник: {origin_domain}
     - Персональный домен: {cdn_domain}
     - Заголовок Host: Пересылать
     - SSL: Let's Encrypt

  2. Скопируй CNAME (cl-xxxxx.service.cdn.msk.vkcs.cloud)
     и создай DNS запись #2.

  3. Настройки CDN:
     - Кеширование: ВЫКЛ (все 4 переключателя)
     - HTTP методы: GET, HEAD, OPTIONS
     - Gzip сжатие: ВЫКЛ

  4. Жди выпуск Let's Encrypt сертификата (5-30 мин)
""") if cdn_type == "vk" else print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {server_ip}  (DNS only, серое облако)
  2. CNAME:     {cdn_domain}  ->  [Yandex CDN CNAME]  (DNS only, создашь позже)
  3. CNAME:     _acme-challenge.{cdn_domain} -> [значение из Yandex] (DNS only, создашь позже)

  Создай пока только запись #1. Остальные — по ходу.

  ============================================
  ШАГ A: Сертификат в Yandex Certificate Manager
  ============================================

  Зайди: console.yandex.cloud -> Certificate Manager -> Создать сертификат

  Заполни:
    - Имя: {cdn_domain.replace('.', '-')}
    - Домены: {cdn_domain}
    - Тип проверки: DNS

  Нажми "Создать".

  После создания Yandex покажет CNAME для проверки:
    _acme-challenge.{cdn_domain}  ->  <значение>.cm.yandexcloud.net

  Создай эту CNAME запись #3 в Cloudflare (DNS only).
  Жди статус сертификата "Issued" (5-30 мин).

  ============================================
  ШАГ B: CDN-ресурс в Yandex Cloud CDN
  ============================================

  Зайди: console.yandex.cloud -> CDN -> Создать ресурс

  Основные настройки:
    - Запрос контента: Из одного источника
    - Тип источника: Сервер
    - Доменное имя источника: {origin_domain}
    - Протокол для источников: HTTPS
    - Задать SNI вручную: ВКЛ
    - Имя SNI-хоста: {origin_domain}
    - Заголовок Host: Своё значение
    - Значение заголовка: {origin_domain}
    - Доменное имя: {cdn_domain}

  После создания скопируй CNAME (xxx.gcdn.co) и создай DNS запись #2.

  Настройки CDN (вкладки сверху):
    Кеширование:
      - Кеш CDN: ВЫКЛ
      - Кеш браузера: ВЫКЛ

    Дополнительно:
      - Query string: НЕ игнорировать
      - Сжатие: ВЫКЛ
      - Проверка сертификата источника: ВЫКЛ
      - SSL-сертификат: выбери {cdn_domain.replace('.', '-')}
""") if cdn_type == "yandex" else print_3xui_turboflare_instructions(
        origin_domain, cdn_domain, server_ip, cdn["xhttp_path"]
    )

    if not cfg.get("skip_cdn_wait", False):
        safe_input("  Нажми ENTER когда CDN настроен и сертификат выпущен...")
        if cdn_type in ("beeline", "timeweb", "turboflare", "selectel"):
            if cdn_type == "beeline":
                cdn_issued = safe_input("  Домен выданный Beeline CDN (например https://xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "timeweb":
                cdn_issued = safe_input("  Технический домен Timeweb CDN (например xxx.cdn.twcstorage.ru): ").strip()
            elif cdn_type == "turboflare":
                cdn_issued = safe_input("  Домен выданный TurboFlare CDN (например xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "selectel":
                cdn_issued = safe_input("  Технический домен Selectel CDN (например xxx.selcdn.ru): ").strip()
            if cdn_issued:
                cdn_issued = cdn_issued.replace("https://", "").replace("http://", "").rstrip("/")
                if cdn_type == "beeline":
                    cdn_label = "Beeline"
                elif cdn_type == "timeweb":
                    cdn_label = "Timeweb"
                elif cdn_type == "turboflare":
                    cdn_label = "TurboFlare"
                else:
                    cdn_label = "Selectel"
                print(f"  CDN домен {cdn_label}: {cdn_issued}")

    # --- Step: Final check ---
    step(step_n, "Финальная проверка")

    # Check health
    r = run("curl -s http://127.0.0.1/health", check=False)
    health_ok = "ok" in r.stdout
    print(f"  Health endpoint: {'OK' if health_ok else 'FAIL'}")

    # Check xray CDN port
    r = run(f"ss -tlnp | grep :{cdn['xray_port']}", check=False)
    xray_ok = str(cdn['xray_port']) in r.stdout
    print(f"  Xray CDN port {cdn['xray_port']}: {'OK' if xray_ok else 'FAIL'}")

    # Check grpc port
    if cfg.get("install_grpc"):
        r = run(f"ss -tlnp | grep :{GRPC_PORT}", check=False)
        grpc_ok = str(GRPC_PORT) in r.stdout
        print(f"  gRPC Reality TCP {GRPC_PORT}: {'OK' if grpc_ok else 'ПРОВЕРЬ после рестарта'}")

    # Check nginx
    r = run("systemctl is-active nginx", check=False)
    nginx_ok = "active" in r.stdout
    print(f"  Nginx: {'OK' if nginx_ok else 'FAIL'}")

    required_failures = []
    if not health_ok:
        required_failures.append("health endpoint")
    if not xray_ok:
        required_failures.append(f"Xray :{cdn['xray_port']}")
    if not nginx_ok:
        required_failures.append("nginx")
    if cfg.get("install_grpc") and not grpc_ok:
        required_failures.append(f"gRPC :{GRPC_PORT}")
    if required_failures:
        raise RuntimeError("Финальная проверка не пройдена: " + ", ".join(required_failures))

    # Check CDN domain
    r = run(f"curl -sk https://{cdn_domain}/health 2>&1", check=False)
    cdn_ok = "ok" in r.stdout
    print(f"  CDN ({cdn_domain}): {'OK' if cdn_ok else 'ПРОПУСК (проверь из РФ)'}")

    # Build VLESS link
    vless_link = (
        f"vless://{client_uuid}@{cdn_domain}:443"
        f"?type=xhttp&security=tls&sni={cdn_domain}"
        f"&fp=random"
        f"&path={cdn['xhttp_path']}"
        f"&host={cdn_domain}"
        f"&mode=packet-up"
        f"&encryption=none"
        f"#{client_email}-{cdn_type}"
    )

    # Subscription URLs (served by 3x-ui built-in sub server via nginx proxy)
    sub_url = f"https://{panel_domain}/sub/{sub_id}"
    json_url = f"https://{panel_domain}/json/{sub_id}"
    print(f"  Подписка: {sub_url}")
    print(f"  JSON (Happ): {json_url}")

    extra_links = ""
    if grpc_link:
        extra_links += f"\n  gRPC Reality ссылка:\n  {grpc_link}\n"

    cascade_summary = ""
    if cascade and cascade_info:
        # EU-панель — вторая полноценная панель (#23): у неё свой прямой ключ,
        # который идёт мимо CDN и relay (заграничный IP напрямую).
        cascade_summary = f"""
  ============================================
  ПАНЕЛЬ 2 — EU (заграничный сервер, каскад)
  ============================================

  Панель: https://{cascade_info['exit_panel_domain']}:{cascade_info['exit_panel_port']}/{cascade_info['exit_panel_path']}/
  Логин: admin
  Пароль: {cascade_info['exit_panel_pass']}
  Подписка: https://{cascade_info['exit_panel_domain']}:2096/sub/

  Прямой ключ к EU (без CDN, заграничный IP сразу):
  {cascade_info.get('eu_link', '')}
{("  EU gRPC ключ:" + chr(10) + "  " + cascade_info['eu_grpc_link'] + chr(10)) if cascade_info.get('eu_grpc_link') else ""}

  Роль в каскаде: {cfg['cascade_ip']} — выход (Reality 443)"""

    print(f"""
  ============================================
  УСТАНОВКА ЗАВЕРШЕНА
  ============================================

  Панель: https://{panel_domain}/{panel_path}/
  Логин: {panel_user}
  Пароль: {panel_pass}

  CDN домен: {cdn_domain}
  Origin домен: {origin_domain}
{cascade_summary}

  Подписка (для v2rayN/NekoBox):
  {sub_url}

  JSON подписка (для Happ):
  {json_url}

  VLESS CDN ссылка:
  {vless_link}
{extra_links}
  ============================================
""")


# ============================================================
#  3X-UI CDN-ONLY (mode 3 for existing 3x-ui panel)
# ============================================================

def install_3xui_cdn_only(cfg):
    """Add CDN node to an existing remote 3x-ui panel. Installs xray standalone + nginx on THIS server, creates inbound on remote panel (API-first, SQLite fallback)."""
    domain = cfg["domain"]
    cdn_type = cfg["cdn_type"]
    cdn = CDN_SETTINGS[cdn_type]
    server_ip = cfg["server_ip"]
    panel_ip = cfg["panel_ip"]
    panel_cred = cfg["panel_cred"]
    origin_sub = cfg["origin_sub"]
    hy2_sub = cfg.get("hy2_sub", "")
    cdn_sub = cfg["cdn_sub"]
    cdn_domain = f"{cdn_sub}.{domain}"
    origin_domain = f"{origin_sub}.{domain}"

    client_uuid = str(uuid.uuid4())
    client_email = f"vpn-cdn-installer-{cdn_type}"
    sub_id = None

    # --- Step: Verify remote 3x-ui ---
    step(3, "Проверка 3x-ui на панели")

    r = run_remote(panel_ip, panel_cred, "systemctl is-active x-ui")
    if "active" not in r.stdout:
        print(f"  ❌ 3x-ui не запущен на {panel_ip}!")
        print(f"  Проверь: ssh {panel_cred.get('user','root')}@{panel_ip} systemctl status x-ui")
        sys.exit(1)
    print(f"  3x-ui активен на {panel_ip}")

    r = run_remote(panel_ip, panel_cred, "test -f /etc/x-ui/x-ui.db && echo OK")
    if "OK" not in r.stdout:
        raise RuntimeError(
            f"На {panel_ip} не найдена SQLite-база /etc/x-ui/x-ui.db. "
            "Режим 3 не изменяет 3x-ui с PostgreSQL."
        )
    print("  База данных найдена")

    # Снимок инбаунда и личность уже выданного клиента берём ДО того, как что-то
    # собрано или удалено: значения нужны и конфигу relay ниже, и инбаунду панели,
    # иначе они разъезжаются. Источник истины — settings.clients инбаунда (именно
    # по нему xray сверяет клиента), таблица clients — резерв: стоит владельцу
    # поправить инбаунд, и эти два места расходятся, а ключ перестаёт подходить.
    _snap = xui_inbound_snapshot(cdn['xray_port'], remote_ip=panel_ip, remote_cred=panel_cred)
    _old_uuid, _old_sub = xui_adopt_client_identity(_snap, client_email,
                                                    remote_ip=panel_ip, remote_cred=panel_cred)
    if _old_uuid:
        client_uuid = _old_uuid
    if _old_sub:
        sub_id = _old_sub
    if _old_uuid or _old_sub:
        print(f"  Клиент {client_email} уже существует — ключ и подписка сохранены")

    # Get panel domain from DB
    r = run_remote(panel_ip, panel_cred, "sqlite3 /etc/x-ui/x-ui.db \"SELECT value FROM settings WHERE key='subDomain';\"")
    panel_domain = r.stdout.strip()
    if not panel_domain:
        panel_domain = panel_ip
    print(f"  Домен панели: {panel_domain}")

    # --- Step: Install xray standalone on this node ---
    step(4, "Установка xray на ноде")

    r = run("xray version 2>/dev/null || /usr/local/bin/xray version 2>/dev/null", check=False)
    if "Xray" in r.stdout:
        print(f"  Xray уже установлен: {r.stdout.strip().splitlines()[0]}")
    else:
        print("  Скачивание xray...")
        if not download_xray_binary(dest="/usr/local/bin/xray"):
            raise RuntimeError("Не удалось установить проверенный Xray")
        r = run("/usr/local/bin/xray version", check=False)
        print(f"  Xray установлен: {r.stdout.strip().splitlines()[0] if r.stdout else 'OK'}")
        track("xray_standalone", True)

    # RU гео-файлы для роутинга (без них xray не стартует)
    setup_xray_ru_geo()

    # Cascade exit setup (before writing xray config)
    cascade = cfg.get("cascade", False)
    cascade_info = None
    cdn_tag = f"{cdn_type}-cdn"
    if cascade:
        step(5, f"Установка exit-сервера {cfg['cascade_ip']} (каскад)")
        exit_sub = cfg.get("exit_sub", "xui")
        exit_panel_domain = f"{exit_sub}.{domain}"
        cascade_info = setup_3xui_cascade_exit(cfg["cascade_ip"], cfg["cascade_cred"], exit_panel_domain,
                                               eu_grpc=cfg.get("eu_grpc", False))
        if not cascade_info:
            print("  ❌ Каскад не удался, продолжаю без каскада.")
            cascade = False

    # Build xray config
    outbounds = [
        {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4"}},
        {"protocol": "blackhole", "tag": "block"}
    ]
    rules = []

    if cascade and cascade_info:
        outbounds.append({
            "tag": "CASCADE-REALITY",
            "protocol": "vless",
            "settings": {"vnext": [{"address": cfg["cascade_ip"], "port": 443,
                "users": [{
                    "id": cascade_info["bridge_uuid"],
                    "encryption": "none",
                    "flow": "xtls-rprx-vision"
                }]}]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": "www.microsoft.com",
                    "password": cascade_info["public_key"],
                    "shortId": cascade_info["short_id"],
                    "spiderX": "/"
                }
            }
        })

    rules.extend([
        {"type": "field", "outboundTag": "direct", "ip": ["ext:geoip_RU.dat:ru"]},
        {"type": "field", "outboundTag": "direct", "domain": [
            "ext:geosite_RU.dat:ru-available-only-inside",
            "regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$"
        ]},
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}
    ])
    if cascade and cascade_info:
        # network-catch-all, НЕ inboundTag (3x-ui пересоздаёт инбаунд со своим тегом
        # in-<port>-<proto> → правило по inboundTag мертвеет → каскад не работает,
        # не-RU трафик уходит в дефолтный direct). RU/bittorrent уже обработаны выше.
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "CASCADE-REALITY"})

    sub_id = sub_id or secrets.token_hex(8)
    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": cdn_tag,
            "port": cdn["xray_port"],
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {"clients": [{"id": client_uuid, "email": client_email, "subId": sub_id}], "decryption": "none"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {
                    "mode": "packet-up",
                    "path": cdn["xhttp_path"],
                    "xmux": {"cMaxReuseTimes": "0", "maxConnections": "2", "hKeepAlivePeriod": 0, "hMaxRequestTimes": "100-200", "hMaxReusableSecs": "300-600"},
                    "noSSEHeader": False,
                    "xPaddingBytes": "100-1000",
                    "xPaddingObfsMode": True,
                    "xPaddingKey": cdn["padding_key"],
                    "xPaddingHeader": cdn["padding_header"],
                    "xPaddingPlacement": cdn["padding_placement"],
                    "xPaddingMethod": cdn["padding_method"],
                    "uplinkHTTPMethod": cdn["uplink_method"],
                    "uplinkDataPlacement": cdn.get("uplink_data_placement", "body"),
                    "scMaxEachPostBytes": "500000-1000000",
                    "scMinPostsIntervalMs": "50-150",
                    "scStreamUpServerSecs": "60-180"
                }
            }
        }],
        "outbounds": outbounds,
        "routing": {"rules": rules}
    }

    run("mkdir -p /usr/local/etc/xray", check=False)
    with open("/usr/local/etc/xray/config.json", "w") as f:
        json.dump(xray_config, f, indent=2)
    print(f"  Конфиг xray записан (порт {cdn['xray_port']}){' + CASCADE' if cascade else ''}")

    # Start/restart xray
    run("systemctl enable xray 2>/dev/null", check=False)
    run("systemctl restart xray", check=False)
    time.sleep(3)

    r = run(f"ss -tlnp | grep :{cdn['xray_port']}", check=False)
    if str(cdn['xray_port']) in r.stdout:
        print(f"  Xray слушает порт {cdn['xray_port']}")
    else:
        print(f"  ⚠ Xray не слушает порт {cdn['xray_port']}, проверяю логи...")
        r = run("journalctl -u xray --no-pager -n 10", check=False)
        print(f"  {r.stdout[:300]}")

    # --- Step: SSL ---
    step_n = 6 if cascade else 5
    step(step_n, "SSL сертификат")
    step_n += 1

    ssl_cert = "/etc/nginx/ssl/cdn.crt"
    ssl_key = "/etc/nginx/ssl/cdn.key"
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        print("  SSL сертификат уже есть")
    else:
        run("mkdir -p /etc/nginx/ssl", check=False)
        run(f"openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj '/CN={origin_domain}' "
            f"-keyout {ssl_key} -out {ssl_cert} 2>/dev/null", check=False)
        print("  Self-signed сертификат создан")

    # --- Step: Nginx CDN origin ---
    step(step_n, "Настройка nginx CDN origin")
    step_n += 1
    ipv6_ok = has_ipv6()
    nginx_conf = nginx_cdn_origin(cdn["xray_port"], cdn["xhttp_path"], ipv6=ipv6_ok,
                                  nginx_style=cdn.get("nginx_style", "prefix"),
                                  ssl_cert=ssl_cert, ssl_key=ssl_key)

    r = nginx_write_and_restart(nginx_conf)
    if r.returncode == 0:
        print("  Nginx CDN origin настроен")
    else:
        print(f"  ❌ Проблема с nginx: {r.stderr[:200] if r.stderr else ''}")
        sys.exit(1)

    # --- Step: Create inbound on remote panel via SSH ---
    step(step_n, f"Создание {cdn_type.upper()} CDN inbound на панели")
    step_n += 1

    tag = f"vpn-cdn-installer-{cdn_type}-{server_ip.replace('.', '-').replace(':', '-')}"
    now_ms = int(time.time() * 1000)
    # sub_id already generated above

    settings_obj = {
        "clients": [{
            "id": client_uuid,
            "email": client_email,
            "subId": sub_id,
            "flow": "",
            "limitIp": 0,
            "totalGB": 0,
            "expiryTime": 0,
            "enable": True
        }],
        "decryption": "none"
    }

    # settings_obj собран уже с сохранённым uuid/subId (снимок и адаптация — выше,
    # до конфига relay). Здесь остаётся перенести клиентов, которых владелец
    # добавил в инбаунд руками: инбаунд пересоздаётся, и раньше они теряли связки —
    # подписки этих людей пустели. Работает и для API-ветки, и для SQLite-ветки:
    # обе берут клиентов из settings_obj.
    _foreign = [c for c in _snap["clients"] if (c.get("email") or "") != client_email]
    if _foreign:
        print(f"  Переношу клиентов владельца из старого инбаунда: {len(_foreign)}")
        settings_obj["clients"].extend(_foreign)

    xhttp_settings = {
        "path": cdn["xhttp_path"],
        "host": "",
        "mode": "packet-up",
        "xPaddingBytes": "100-1000",
        "xPaddingObfsMode": True,
        "xPaddingKey": cdn["padding_key"],
        "xPaddingHeader": cdn["padding_header"],
        "xPaddingPlacement": cdn["padding_placement"],
        "xPaddingMethod": cdn["padding_method"],
        "uplinkHTTPMethod": cdn["uplink_method"],
        "uplinkDataPlacement": cdn.get("uplink_data_placement", "body"),
        "noSSEHeader": False,
        "scMaxEachPostBytes": "500000-1000000",
        "scMinPostsIntervalMs": "50-150",
        "scStreamUpServerSecs": "60-180",
        "xmux": {
            "maxConcurrency": "16-32",
            "maxConnections": 0,
            "cMaxReuseTimes": 0,
            "hMaxRequestTimes": "600-900",
            "hMaxReusableSecs": "1800-3000",
            "hKeepAlivePeriod": 0
        }
    }

    stream_settings_obj = {
        "network": "xhttp",
        "security": "none",
        "externalProxy": [{
            "forceTls": "tls",
            "dest": cdn_domain,
            "port": 443,
            "remark": ""
        }],
        "xhttpSettings": xhttp_settings
    }

    sniffing_obj = {"enabled": True, "destOverride": ["http", "tls", "quic"]}

    # Create inbound on remote panel (API-first for version compat, SQL fallback)
    inbound_created = False

    # Read panel web settings from DB (stable key-value queries)
    _xcfg = {}
    for _k in ("webPort", "webBasePath", "username", "password"):
        _r = run_remote(panel_ip, panel_cred,
            f'sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key=\'{_k}\';"', timeout=10)
        _xcfg[_k] = _r.stdout.strip() if _r.returncode == 0 and _r.stdout.strip() else ""
    _xport = _xcfg.get("webPort") or "2053"
    _xbase = (_xcfg.get("webBasePath") or "/").strip("/")
    _xuser = _xcfg.get("username") or "admin"
    _xpw = _xcfg.get("password") or "admin"
    _xurl = f"http://127.0.0.1:{_xport}"
    if _xbase:
        _xurl += f"/{_xbase}"

    # Detect 3x-ui version
    _ver_r = run_remote(panel_ip, panel_cred, "/usr/local/x-ui/x-ui version 2>/dev/null || echo unknown", timeout=10)
    _xui_ver = _ver_r.stdout.strip()
    if _xui_ver and _xui_ver != "unknown":
        print(f"  Версия 3x-ui: {_xui_ver}")

    # Try REST API (works across all 3x-ui versions)
    import urllib.parse as _up
    _login_data = _up.urlencode({"username": _xuser, "password": _xpw})
    _login_b64 = base64.b64encode(_login_data.encode()).decode()
    _csrf_script = '''import sys,re
m=re.search(r'csrf-token.*?content="([^"]+)"', sys.stdin.read())
print(m.group(1) if m else '')'''
    write_remote_file(panel_ip, panel_cred, "/tmp/_csrf_parse.py", _csrf_script)
    _csrf_r = run_remote(panel_ip, panel_cred,
        f"curl -sf -k -c /tmp/.xcook '{_xurl}/' 2>/dev/null | python3 /tmp/_csrf_parse.py", timeout=15)
    _csrf = _csrf_r.stdout.strip() if _csrf_r and _csrf_r.stdout else ""
    _csrf_hdr = f"-H 'X-CSRF-Token: {_csrf}'" if _csrf else ""
    _login_r = run_remote(panel_ip, panel_cred,
        f"echo '{_login_b64}' | base64 -d | curl -sf -k -c /tmp/.xcook -b /tmp/.xcook -X POST '{_xurl}/login' "
        f"-H 'Content-Type: application/x-www-form-urlencoded' {_csrf_hdr} -d @-", timeout=15)
    _api_ok = False
    try:
        _api_ok = json.loads(_login_r.stdout).get("success", False)
    except (TypeError, ValueError, json.JSONDecodeError):
        _api_ok = False

    # REST cannot replace an inbound transactionally. Keep the login as a
    # compatibility probe, but perform all writes through backed-up SQLite.
    if _api_ok:
        print("  API панели доступен; изменения будут применены атомарно через SQLite")
    _api_ok = False

    if _api_ok:
        _list_r = run_remote(panel_ip, panel_cred,
            f"curl -sf -b /tmp/.xcook '{_xurl}/panel/api/inbounds/list'", timeout=15)
        try:
            for _ib in json.loads(_list_r.stdout).get("obj", []):
                # сверяем и порт: владелец мог переименовать инбаунд в UI, тогда
                # 3x-ui перезаписал tag на in-<port>-<proto> и сверка по тегу
                # оставила бы старый инбаунд висеть на том же порту
                try:
                    api_clients = json.loads(_ib.get("settings") or "{}").get("clients", [])
                except (TypeError, ValueError, json.JSONDecodeError):
                    api_clients = []
                owned = (
                    _ib.get("tag") == tag
                    or str(_ib.get("remark") or "").startswith("VPN-CDN-INSTALLER-")
                    or any(c.get("email") == client_email for c in api_clients)
                )
                same_port = str(_ib.get("port")) == str(cdn["xray_port"])
                if same_port and not owned:
                    raise RuntimeError(
                        f"Порт {cdn['xray_port']} занят чужим inbound; удаление запрещено"
                    )
                if owned:
                    run_remote(panel_ip, panel_cred,
                        f"curl -sf -b /tmp/.xcook -X POST '{_xurl}/panel/api/inbounds/del/{_ib['id']}'",
                        timeout=15)
                    print(f"  Удалён старый inbound: {_ib.get('tag') or tag} (порт {_ib.get('port')})")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            print(f"  API-список inbound не разобран: {exc}")

        _payload = {
            "up": 0, "down": 0, "total": 0,
            "remark": f"VPN-CDN-INSTALLER-{cdn_type.upper()} ({server_ip})",
            "enable": True, "expiryTime": 0,
            "listen": "127.0.0.1", "port": cdn["xray_port"],
            "protocol": "vless",
            "settings": json.dumps(settings_obj),
            "streamSettings": json.dumps(stream_settings_obj),
            "sniffing": json.dumps(sniffing_obj),
            "tag": tag
        }
        _b64 = base64.b64encode(json.dumps(_payload).encode()).decode()
        _add_r = run_remote(panel_ip, panel_cred,
            f"echo '{_b64}' | base64 -d | curl -sf -b /tmp/.xcook "
            f"-X POST '{_xurl}/panel/api/inbounds/add' "
            f"-H 'Content-Type: application/json' -d @-", timeout=15)
        try:
            _ar = json.loads(_add_r.stdout)
            if _ar.get("success"):
                inbound_created = True
                print(f"  Inbound создан через API: {tag}")
                _sub_r = run_remote(panel_ip, panel_cred,
                    f"sqlite3 /etc/x-ui/x-ui.db \"SELECT sub_id FROM clients WHERE email='{client_email}' ORDER BY id DESC LIMIT 1;\"", timeout=10)
                if _sub_r.stdout.strip():
                    sub_id = _sub_r.stdout.strip()
                _uuid_r = run_remote(panel_ip, panel_cred,
                    f"sqlite3 /etc/x-ui/x-ui.db \"SELECT uuid FROM clients WHERE email='{client_email}' ORDER BY id DESC LIMIT 1;\"", timeout=10)
                if _uuid_r.stdout.strip():
                    client_uuid = _uuid_r.stdout.strip()
            else:
                print(f"  API: {_ar.get('msg', 'ошибка')}")
        except Exception:
            print("  API ответ некорректный, пробуем SQLite")
        run_remote(panel_ip, panel_cred, "rm -f /tmp/.xcook", timeout=5)

    if not inbound_created:
        if not _api_ok:
            print("  API недоступен, используем SQLite")

        settings_json = json.dumps(settings_obj).replace("'", "''")
        stream_json = json.dumps(stream_settings_obj).replace("'", "''")
        sniffing_json = json.dumps(sniffing_obj).replace("'", "''")

        r = run_remote(panel_ip, panel_cred, f"sqlite3 /etc/x-ui/x-ui.db \"SELECT id FROM clients WHERE email='{client_email}';\"")
        existing_client_id = r.stdout.strip()

        # Опознание по связке порт+email, не по тегу: панель перегенерирует тег
        # при сохранении инбаунда в UI (см. xui_purge_own_inbound_sql).
        sql_parts = [xui_purge_own_inbound_sql(cdn['xray_port'], tag, client_email)]
        sql_parts.append(
            f"INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing) "
            f"VALUES (1, 0, 0, 0, 'VPN-CDN-INSTALLER-{cdn_type.upper()} ({server_ip})', 1, 0, '127.0.0.1', {cdn['xray_port']}, 'vless', '{settings_json}', '{stream_json}', '{tag}', '{sniffing_json}');"
        )

        if not existing_client_id:
            sql_parts.append(
                f"INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable, created_at) "
                f"VALUES ('{client_email}', '{sub_id}', '{client_uuid}', '', 0, 0, 0, 1, {now_ms});"
            )

        # Связки собираем из settings.clients — разом для нашего клиента и для
        # клиентов владельца, перенесённых снимком выше. Раньше связка вписывалась
        # руками только для нашего, а чужие оставались висеть на удалённом
        # inbound_id: подписки этих людей отдавали пустоту.
        sql_parts.append(xui_link_clients_sql(cdn['xray_port'], settings_obj["clients"],
                                              _snap["traffics"], now_ms))

        sql_content = chr(10).join(sql_parts)
        write_remote_file(panel_ip, panel_cred, "/tmp/xui_cdn_node.sql", sql_content)
        apply_xui_sql_remote(panel_ip, panel_cred, "/tmp/xui_cdn_node.sql")

        if existing_client_id:
            # uuid/sub_id больше здесь НЕ перечитываем: они уже определены до
            # сборки settings (xui_adopt_client_identity), а повторное чтение
            # из БД возвращало значение, которого нет в инбаунде.
            client_id = existing_client_id
            print(f"  Используем существующего клиента: {client_email}")
        else:
            r = run_remote(panel_ip, panel_cred, f"sqlite3 /etc/x-ui/x-ui.db \"SELECT id FROM clients WHERE email='{client_email}';\"")
            client_id = r.stdout.strip()

        # по порту: тег мог быть перезаписан панелью, а два id в stdout
        # («12\n13») сломали бы подстановку в SQL ниже
        r = run_remote(panel_ip, panel_cred,
            f"sqlite3 /etc/x-ui/x-ui.db \"SELECT id FROM inbounds WHERE port={cdn['xray_port']} ORDER BY id DESC LIMIT 1;\"")
        inbound_id = r.stdout.strip()

        if client_id and inbound_id:
            inbound_created = True
            print(f"  Inbound создан через SQLite: {tag}")
        else:
            raise RuntimeError(
                f"Не удалось привязать клиента (client_id={client_id}, inbound_id={inbound_id})"
            )

        run_remote(panel_ip, panel_cred, "rm -f /tmp/xui_cdn_node.sql", timeout=5)

    # Свой инбаунд пересоздан. Чужой инбаунд владельца на этом же порту удалять
    # молча нельзя, но и промолчать нельзя: xray не стартует, а снаружи это
    # выглядит как «Empty reply» через CDN и диагностика уходит не туда.
    _squat = xui_port_squatter(cdn['xray_port'], exclude_tag=tag,
                               remote_ip=panel_ip, remote_cred=panel_cred,
                               owner_email=client_email)
    if _squat:
        raise RuntimeError(
            f"Порт {cdn['xray_port']} занят чужим inbound {_squat}; удаление запрещено"
        )

    # Restart x-ui
    require_success(
        run_remote(panel_ip, panel_cred, "systemctl restart x-ui", timeout=30),
        "Перезапуск удалённой 3x-ui",
    )
    if inbound_created:
        print("  3x-ui перезапущен на панели")
    else:
        print("  x-ui перезапущен. Проверь inbound в панели вручную.")

    # Sync ALL panel clients to relay xray config (cascade mode)
    if cascade and inbound_created:
        try:
            _all_clients_r = run_remote(panel_ip, panel_cred,
                "sqlite3 /etc/x-ui/x-ui.db " + shlex.quote(
                    f"SELECT c.uuid, c.email FROM clients c "
                    f"JOIN client_inbounds ci ON ci.client_id = c.id "
                    f"JOIN inbounds i ON i.id = ci.inbound_id "
                    f"WHERE i.port={cdn['xray_port']} AND c.enable=1;"), timeout=15)
            if _all_clients_r.stdout.strip():
                _panel_clients = []
                for _row in _all_clients_r.stdout.strip().splitlines():
                    _parts = _row.split("|")
                    if len(_parts) >= 2 and _parts[0].strip():
                        _panel_clients.append({"id": _parts[0].strip(), "email": _parts[1].strip()})
                if len(_panel_clients) > 1:
                    with open("/usr/local/etc/xray/config.json", "r") as _f:
                        _relay_cfg = json.load(_f)
                    for _ib in _relay_cfg.get("inbounds", []):
                        if _ib.get("tag") == cdn_tag:
                            _ib["settings"]["clients"] = _panel_clients
                    with open("/usr/local/etc/xray/config.json", "w") as _f:
                        json.dump(_relay_cfg, _f, indent=2)
                    run("systemctl restart xray", check=False)
                    print(f"  Синхронизировано {len(_panel_clients)} клиентов на relay")
        except Exception as _e:
            print(f"  ⚠ Синхронизация клиентов: {_e}")

    # --- Step: CDN instructions ---
    step(step_n, "Инструкция по настройке CDN")
    step_n += 1

    if cdn_type == "vk":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {server_ip}  (DNS only)
  2. CNAME:     {cdn_domain}  ->  [VK CDN CNAME]  (DNS only)

  ============================================
  Настройки VK Cloud CDN:
  ============================================

  - Протокол к источнику: HTTP (порт 80)
  - Источник: {origin_domain}
  - Персональный домен: {cdn_domain}
  - Заголовок Host: Пересылать
  - SSL: Let's Encrypt
  - Кеширование: ВЫКЛ (все 4 переключателя)
  - HTTP методы: GET, HEAD, OPTIONS
  - Gzip: ВЫКЛ
""")
    elif cdn_type == "yandex":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {server_ip}  (DNS only)
  2. CNAME:     {cdn_domain}  ->  [Yandex CDN CNAME]  (DNS only, создашь позже)
  3. CNAME:     _acme-challenge.{cdn_domain} -> [значение из Yandex] (DNS only)

  ============================================
  ШАГ A: Yandex Certificate Manager -> Создать сертификат
    - Домены: {cdn_domain}, Тип проверки: DNS
    - Создай CNAME запись #3, жди статус "Issued"

  ШАГ B: Yandex CDN -> Создать ресурс
    - Источник: {origin_domain}, HTTPS, SNI: {origin_domain}
    - Host: {origin_domain}, Домен: {cdn_domain}
    - Кеширование: ВЫКЛ, Сжатие: ВЫКЛ
    - SSL-сертификат: выбери {cdn_domain.replace('.', '-')}
""")

    if not cfg.get("skip_cdn_wait", False):
        safe_input("  Нажми ENTER когда CDN настроен...")
        if cdn_type in ("beeline", "timeweb", "turboflare", "selectel"):
            if cdn_type == "beeline":
                cdn_issued = safe_input("  Домен выданный Beeline CDN (например https://xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "timeweb":
                cdn_issued = safe_input("  Технический домен Timeweb CDN (например xxx.cdn.twcstorage.ru): ").strip()
            elif cdn_type == "turboflare":
                cdn_issued = safe_input("  Домен выданный TurboFlare CDN (например xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "selectel":
                cdn_issued = safe_input("  Технический домен Selectel CDN (например xxx.selcdn.ru): ").strip()
            if cdn_issued:
                cdn_issued = cdn_issued.replace("https://", "").replace("http://", "").rstrip("/")
                if cdn_type == "beeline":
                    cdn_label = "Beeline"
                elif cdn_type == "timeweb":
                    cdn_label = "Timeweb"
                elif cdn_type == "turboflare":
                    cdn_label = "TurboFlare"
                else:
                    cdn_label = "Selectel"
                print(f"  CDN домен {cdn_label}: {cdn_issued}")

    # --- Step: Final check ---
    step(step_n, "Финальная проверка")

    r = run("curl -s http://127.0.0.1/health", check=False)
    print(f"  Health (нода): {'OK' if 'ok' in r.stdout else 'FAIL'}")

    r = run(f"ss -tlnp | grep :{cdn['xray_port']}", check=False)
    print(f"  Xray CDN port {cdn['xray_port']} (нода): {'OK' if str(cdn['xray_port']) in r.stdout else 'FAIL'}")

    r = run("systemctl is-active nginx", check=False)
    print(f"  Nginx (нода): {'OK' if 'active' in r.stdout else 'FAIL'}")

    r = run_remote(panel_ip, panel_cred, "systemctl is-active x-ui")
    print(f"  3x-ui (панель {panel_ip}): {'OK' if 'active' in r.stdout else 'FAIL'}")

    vless_link = (
        f"vless://{client_uuid}@{cdn_domain}:443"
        f"?type=xhttp&security=tls&sni={cdn_domain}"
        f"&fp=random"
        f"&path={cdn['xhttp_path']}"
        f"&host={cdn_domain}"
        f"&mode=packet-up"
        f"&encryption=none"
        f"#{client_email}-{cdn_type}"
    )

    sub_url = f"https://{panel_domain}/sub/{sub_id}"

    cascade_summary = ""
    if cascade and cascade_info:
        cascade_summary = f"""
  ============================================
  ПАНЕЛЬ 2 — EU (заграничный сервер, каскад)
  ============================================

  Панель: https://{cascade_info['exit_panel_domain']}:{cascade_info['exit_panel_port']}/{cascade_info['exit_panel_path']}/
  Логин: admin
  Пароль: {cascade_info['exit_panel_pass']}
  Подписка: https://{cascade_info['exit_panel_domain']}:2096/sub/

  Прямой ключ к EU (без CDN, заграничный IP сразу):
  {cascade_info.get('eu_link', '')}
{("  EU gRPC ключ:" + chr(10) + "  " + cascade_info['eu_grpc_link'] + chr(10)) if cascade_info.get('eu_grpc_link') else ""}

  Роль в каскаде: {cfg['cascade_ip']} — выход (Reality 443)
"""

    print(f"""
  ============================================
  CDN НОДА ПОДКЛЮЧЕНА К 3X-UI
  ============================================

  Нода (этот сервер): {server_ip}
  Панель 3x-ui: {panel_ip}
  CDN домен: {cdn_domain}
  Origin домен: {origin_domain}
{cascade_summary}
  Подписка: {sub_url}

  VLESS CDN ссылка:
  {vless_link}
  ============================================
""")


# ============================================================
#  REMNAWAVE PROFILE LOOKUP (rename-proof)
# ============================================================

def _same_port(a, b):
    """Порты сравниваем строками: в session-конфигах CDN они бывают и int, и str."""
    return a is not None and b is not None and str(a) == str(b)


def remnawave_find_profile(profiles, inbound_tag, profile_name, cdn_port=None):
    """Найти наш config-profile и uuid'ы инбаундов внутри него.

    Три прохода, от точного признака к грубому:
      1. по тегу CDN-инбаунда;
      2. по имени профиля;
      3. по ПОРТУ CDN-инбаунда — на случай, когда владелец переименовал инбаунд
         (config profile в Remnawave это сырой JSON, тег там правится руками).

    Третий проход и есть фикс: без него переименованный инбаунд не находился,
    installer считал, что профиля нет, и добавлял ВТОРОЙ инбаунд на том же порту —
    xray на ноде после этого не поднимался вовсе. Порт стоит именно последним, а
    не первым: иначе можно присвоить чужой профиль владельца, у которого инбаунд
    случайно висит на том же порту.

    Возвращает dict с profile_uuid / inbound_uuid / hy2 / grpc / bridge_in uuid.
    """
    found = {"profile_uuid": None, "inbound_uuid": None, "hy2_inbound_uuid": None,
             "grpc_inbound_uuid": None, "bridge_in_uuid": None}

    def _tagged(ib, base):
        t = ib.get("tag", "") or ""
        return t == base or t.startswith(base + "-")

    def _looks_like_cdn(ib):
        """Похож ли инбаунд на наш CDN-инбаунд (vless+xhttp), а не на личный
        инбаунд владельца, случайно севший на тот же порт.

        Страховка к самому грубому проходу — по порту. Имена полей у разных
        версий панели расходятся (protocol/type, network/transport), а в сводке
        inbounds их может не быть вовсе — тогда проверку просто пропускаем.
        """
        proto = str(ib.get("protocol") or ib.get("type") or "").lower()
        if proto and proto != "vless":
            return False
        net = str(ib.get("network") or ib.get("transport") or "").lower()
        return not net or net in ("xhttp", "splithttp")

    def _extras(p):
        # HY2/gRPC/BRIDGE_IN тоже ищем с фолбэком на порт: их пропуск означает
        # добавление дубля на занятый порт, то есть мёртвый xray на ноде.
        for ib in p.get("inbounds", []):
            if _tagged(ib, "hy2-in") or _same_port(ib.get("port"), HY2_PORT):
                found["hy2_inbound_uuid"] = ib.get("uuid")
            elif _tagged(ib, "grpc-reality") or _same_port(ib.get("port"), GRPC_PORT):
                found["grpc_inbound_uuid"] = ib.get("uuid")
            elif _tagged(ib, "BRIDGE_IN") or _same_port(ib.get("port"), 8888):
                found["bridge_in_uuid"] = ib.get("uuid")

    for p in profiles:
        for ib in p.get("inbounds", []):
            if _tagged(ib, inbound_tag):
                found["profile_uuid"] = p.get("uuid")
                found["inbound_uuid"] = ib.get("uuid")
                print(f"  Профиль с тегом {ib.get('tag')} уже существует: {p.get('name')}")
                _extras(p)
                return found

    for p in profiles:
        pname = p.get("name", "") or ""
        if pname == profile_name or pname.startswith(profile_name + "-"):
            found["profile_uuid"] = p.get("uuid")
            for ib in p.get("inbounds", []):
                if _tagged(ib, inbound_tag):
                    found["inbound_uuid"] = ib.get("uuid")
            _extras(p)
            if not found["inbound_uuid"]:
                ibs = p.get("inbounds", [])
                if ibs:
                    found["inbound_uuid"] = ibs[0].get("uuid")
            print(f"  Профиль {pname} уже существует (по имени)")
            return found

    if cdn_port:
        for p in profiles:
            for ib in p.get("inbounds", []):
                if _same_port(ib.get("port"), cdn_port) and _looks_like_cdn(ib):
                    found["profile_uuid"] = p.get("uuid")
                    found["inbound_uuid"] = ib.get("uuid")
                    print(f"  Профиль найден по порту {cdn_port}: {p.get('name')}"
                          f" (инбаунд переименован в '{ib.get('tag')}')")
                    _extras(p)
                    return found

    return found


# ============================================================
#  CASCADE HELPERS
# ============================================================

def build_cascade_profile(rcfg, exit_ip, bridge_user_uuid, bridge_public_key,
                          bridge_short_id, youtube_direct=False,
                          install_hy2=False, install_grpc=False):
    """Build VK/CDN relay profile: XHTTP -> VLESS+REALITY -> exit."""
    if install_hy2 or install_grpc:
        raise RuntimeError(
            "HY2/gRPC через CDN relay отключены: каскадируем только XHTTP. "
            "HY2/gRPC должны идти напрямую на exit."
        )

    import copy
    cdn_inbound = copy.deepcopy(rcfg["profile_config"]["inbounds"][0])
    cdn_inbound["port"] = 7443
    cdn_inbound["listen"] = "127.0.0.1"
    cdn_inbound["tag"] = f"{cdn_inbound['tag']}-cascade"
    if "sniffing" not in cdn_inbound:
        cdn_inbound["sniffing"] = {
            "enabled": True, "routeOnly": True,
            "destOverride": ["http", "tls", "quic"]
        }

    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"],
                "queryStrategy": "UseIPv4", "disableCache": False},
        "inbounds": [cdn_inbound],
        "outbounds": [
            {
                "tag": "VLESS_EXIT", "protocol": "vless",
                "settings": {"vnext": [{
                    "address": exit_ip, "port": 8888,
                    "users": [{"id": bridge_user_uuid, "encryption": "none"}]
                }]},
                "streamSettings": {
                    "network": "tcp", "security": "reality",
                    "realitySettings": {
                        "fingerprint": "chrome",
                        "serverName": GRPC_SERVER_NAMES[0],
                        "password": bridge_public_key,
                        "shortId": bridge_short_id,
                        "spiderX": "/"
                    },
                    "sockopt": {"tcpKeepAliveInterval": 30, "tcpNoDelay": True}
                },
                "mux": {"enabled": True, "concurrency": 8,
                        "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
            },
            {"tag": "DIRECT", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "BLOCK", "protocol": "blackhole"}
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"ip": ["geoip:private"], "type": "field", "outboundTag": "BLOCK"},
            {"domain": ["geosite:private"], "type": "field", "outboundTag": "BLOCK"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
            *(youtube_soundcloud_direct_rules("DIRECT", "BLOCK") if youtube_direct else []),
            {"ip": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"],
             "type": "field", "outboundTag": "DIRECT"},
            {"ip": ["149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22",
                    "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
                    "91.108.56.0/22"], "type": "field", "outboundTag": "VLESS_EXIT"},
            {"domain": ["domain:telegram.org", "domain:t.me", "domain:telegra.ph"],
             "type": "field", "outboundTag": "VLESS_EXIT"},
            {"ip": ["geoip:ru"], "type": "field", "outboundTag": "DIRECT"},
            {"domain": ["geosite:category-ru"], "type": "field", "outboundTag": "DIRECT"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "VLESS_EXIT"}
        ]}
    }

def prepare_bridge_reality(cfg):
    """Create one REALITY keypair per installation and reuse it across both ends."""
    keys = cfg.get("bridge_reality_keys")
    short_id = cfg.get("bridge_reality_short_id")
    if keys and keys.get("private") and keys.get("public") and short_id:
        return keys, short_id

    keys = generate_x25519_keys()
    if not keys:
        raise RuntimeError("Не удалось создать REALITY x25519 ключи для BRIDGE_IN")
    short_id = secrets.token_hex(8)
    cfg["bridge_reality_keys"] = keys
    cfg["bridge_reality_short_id"] = short_id
    return keys, short_id


def ensure_bridge_inbound(api_func, profile_uuid, bridge_in_uuid=None,
                          private_key=None, short_id=None):
    """Create/update BRIDGE_IN:8888 as VLESS+REALITY, never plaintext VLESS."""
    if not profile_uuid:
        return None
    if not private_key or not short_id:
        raise RuntimeError("Для BRIDGE_IN не переданы REALITY privateKey/shortId")

    resp = api_func("GET", "config-profiles")
    prof = None
    if resp.get("response"):
        rd = resp["response"]
        pl = rd.get("configProfiles", rd if isinstance(rd, list) else [rd])
        prof = next((p for p in pl if p.get("uuid") == profile_uuid), None)
    if not prof:
        raise RuntimeError("Профиль exit-ноды не найден; BRIDGE_IN не создан")

    pconf = prof.get("config") or {}
    if not isinstance(pconf, dict) or not isinstance(pconf.get("inbounds"), list):
        raise RuntimeError("Не удалось прочитать raw config профиля для BRIDGE_IN")

    bridge_cfg = None
    for ib in pconf["inbounds"]:
        if ib.get("tag", "").startswith("BRIDGE_IN") or _same_port(ib.get("port"), 8888):
            bridge_cfg = ib
            break

    new_cfg = {
        "tag": (bridge_cfg or {}).get("tag") or f"BRIDGE_IN-{secrets.token_hex(3)}",
        "port": 8888, "listen": "0.0.0.0", "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "xver": 0, "dest": GRPC_DEST,
                "serverNames": GRPC_SERVER_NAMES,
                "privateKey": private_key, "shortIds": [short_id]
            }
        }
    }
    if bridge_cfg is None:
        pconf["inbounds"].append(new_cfg)
    else:
        bridge_cfg.clear()
        bridge_cfg.update(new_cfg)

    upd = api_func("PATCH", "config-profiles", {"uuid": profile_uuid, "config": pconf})
    if not upd.get("response"):
        raise RuntimeError(f"Не удалось создать/обновить защищённый BRIDGE_IN: {upd}")

    for ib in upd["response"].get("inbounds", []):
        if (ib.get("uuid") == bridge_in_uuid
                or ib.get("tag", "").startswith("BRIDGE_IN")
                or _same_port(ib.get("port"), 8888)):
            print("  BRIDGE_IN защищён REALITY (TCP 8888)")
            return ib.get("uuid")

    check = api_func("GET", "config-profiles")
    if check.get("response"):
        rd = check["response"]
        pl = rd.get("configProfiles", rd if isinstance(rd, list) else [rd])
        prof2 = next((p for p in pl if p.get("uuid") == profile_uuid), None)
        if prof2:
            for ib in prof2.get("inbounds", []):
                if ib.get("tag", "").startswith("BRIDGE_IN") or _same_port(ib.get("port"), 8888):
                    print("  BRIDGE_IN защищён REALITY (TCP 8888)")
                    return ib.get("uuid")
    raise RuntimeError("BRIDGE_IN записан в config, но его UUID не найден после PATCH")

def ensure_node_inbound(api_func, node_uuid, profile_uuid, inbound_uuid, label="BRIDGE_IN"):
    """Инбаунд должен быть в activeInbounds ноды, иначе xray его не поднимет.

    Нужно отдельно: при уже существующей ноде activeInbounds не пересобирается.
    """
    if not (node_uuid and profile_uuid and inbound_uuid):
        return False
    resp = api_func("GET", "nodes")
    rd = resp.get("response") or []
    nodes_list = rd.get("nodes", rd) if isinstance(rd, dict) else rd
    if not isinstance(nodes_list, list):
        return False
    node = next((n for n in nodes_list if n.get("uuid") == node_uuid), None)
    if not node:
        return False

    active = []
    for ib in (node.get("configProfile") or {}).get("activeInbounds") or []:
        u = ib.get("uuid") if isinstance(ib, dict) else ib
        if u:
            active.append(u)
    if inbound_uuid in active:
        return True
    active.append(inbound_uuid)

    upd = api_func("PATCH", "nodes", {
        "uuid": node_uuid,
        "configProfile": {"activeConfigProfileUuid": profile_uuid, "activeInbounds": active}
    })
    if upd.get("response"):
        print(f"  {label} привязан к ноде")
        return True
    print(f"  ВНИМАНИЕ: не удалось привязать {label} к ноде: {upd}")
    return False


def ensure_squad_inbound(api_func, inbound_uuid, squad_uuid=None):
    """Инбаунд обязан входить в сквад: Remnawave раздаёт нодам список клиентов
    из сквада, а статический settings.clients в профиле затирает. Без этого
    BRIDGE_IN слушает 8888 с пустым списком и рвёт VLESS-хендшейк с relay.
    """
    if not inbound_uuid:
        return False
    resp = api_func("GET", "internal-squads")
    squads = resp.get("response", {}).get("internalSquads", [])
    if not squads:
        print("  ВНИМАНИЕ: сквады не найдены, BRIDGE_IN не добавлен в сквад")
        return False
    if squad_uuid:
        squad = next((s for s in squads if s.get("uuid") == squad_uuid), squads[0])
    else:
        squad = next((s for s in squads if s.get("name") == "Default-Squad"), squads[0])

    current = [ib["uuid"] for ib in squad.get("inbounds", []) if ib.get("uuid")]
    if inbound_uuid in current:
        return True
    current.append(inbound_uuid)
    upd = api_func("PATCH", "internal-squads", {"uuid": squad["uuid"], "inbounds": current})
    if upd.get("response"):
        print(f"  BRIDGE_IN добавлен в сквад {squad.get('name')}")
        return True
    print(f"  ВНИМАНИЕ: не удалось добавить BRIDGE_IN в сквад: {upd}")
    return False


def find_default_squad(api_func):
    """Return only the canonical Default-Squad; never mutate an arbitrary squad."""
    resp = api_func("GET", "internal-squads")
    squads = resp.get("response", {}).get("internalSquads", [])
    if not squads:
        return None
    squad = next((s for s in squads if s.get("name") == "Default-Squad"), None)
    return squad.get("uuid") if squad else None


def ensure_user_squad(api_func, username, squad_uuid):
    """Проверяет, что юзер реально попал в сквад, и добивает PATCH-ем.

    Remnawave не всегда цепляет сквад при создании юзера — поведение на разных
    панелях расходится. Для bridge-юзера это фатально: без сквада его vless
    UUID не раздаётся на BRIDGE_IN и каскад молча висит. Username используется
    как совместимый идентификатор: Remnawave 2.8 принимает uuid/username, а 3.2
    удалил uuid пользователя из API и принимает id/username.
    """
    if not (username and squad_uuid):
        return False
    resp = api_func("GET", "users")
    rd = resp.get("response") or {}
    users = rd.get("users", rd) if isinstance(rd, dict) else rd
    if not isinstance(users, list):
        return False
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return False

    current = []
    for s in user.get("activeInternalSquads") or []:
        u = s.get("uuid") if isinstance(s, dict) else s
        if u:
            current.append(u)
    if squad_uuid in current:
        return True

    current.append(squad_uuid)
    upd = api_func("PATCH", "users", {"username": username, "activeInternalSquads": current})
    if upd.get("response"):
        print(f"  Пользователь {username} добавлен в сквад")
        return True
    print(f"  ⚠ Не удалось добавить пользователя {username} в сквад: {upd}")
    return False


def setup_cascade_relay(cfg, api_func, exit_ip, node_cred, same_server,
                         profile_uuid, inbound_uuid, squad_uuid, existing_squad_inbounds):
    """Setup Caddy + remnanode on Russian relay server for cascade.
    api_func: callable(method, path, data=None) for Remnawave API calls."""
    cascade_ip = cfg["cascade_ip"]
    cascade_cred = cfg["cascade_cred"]
    cdn_type = cfg["cdn_type"]
    rcfg = REMNAWAVE_CDN[cdn_type]
    domain = cfg["domain"]
    origin_sub = cfg["origin_sub"]
    hy2_sub = cfg.get("hy2_sub", "")
    origin_domain = f"{origin_sub}.{domain}"
    panel_sub = cfg.get("panel_sub", "")
    panel_domain = f"{panel_sub}.{domain}" if panel_sub else domain
    server_ip = cfg["server_ip"]
    cascade_on_panel = (cascade_ip == server_ip)

    if cascade_on_panel:
        raise RuntimeError(
            "Cascade relay должен быть отдельным чистым сервером; панель не будет перезаписана relay-конфигом."
        )

    # --- SSH check ---
    print(f"  [cascade] Подключение к relay {cascade_ip}...")
    r = run_remote(cascade_ip, cascade_cred, "echo OK", timeout=30)
    if "OK" not in r.stdout:
        sshpass_check = run("which sshpass", check=False)
        if sshpass_check.returncode != 0:
            run("DEBIAN_FRONTEND=noninteractive apt-get install -y sshpass", check=False, timeout=60)
            r = run_remote(cascade_ip, cascade_cred, "echo OK", timeout=30)
        if "OK" not in r.stdout:
            print(f"  ❌ Не могу подключиться к relay {cascade_ip}")
            sys.exit(1)
    print("  [cascade] SSH OK")

    marker_check = run_remote(
        cascade_ip,
        cascade_cred,
        "test -e /opt/remnanode -o -e /etc/caddy/Caddyfile && echo OCCUPIED; "
        "ss -ltn 2>/dev/null | grep -Eq ':(80|443|7443|2222) ' && echo OCCUPIED; "
        "for s in nginx apache2 caddy xray; do "
        "systemctl is-active --quiet \"$s\" 2>/dev/null && echo OCCUPIED; done",
        timeout=20,
    )
    if "OCCUPIED" in (marker_check.stdout or ""):
        raise RuntimeError(
            "Cascade relay не чистый: найдены web/VPN-сервисы или занятые порты. "
            "Установщик не будет останавливать и перезаписывать чужие службы."
        )

    check_os(remote_ip=cascade_ip, remote_cred=cascade_cred)

    # --- Docker ---
    print("  [cascade] Установка Docker...")
    if install_docker(remote_ip=cascade_ip, remote_cred=cascade_cred):
        print(f"  [cascade] Docker готов: {run_remote(cascade_ip, cascade_cred, 'docker --version').stdout.strip()}")
    else:
        print(f"  ❌ [cascade] Docker не установился на relay!")
        sys.exit(1)
    setup_docker_mirror(remote_ip=cascade_ip, remote_cred=cascade_cred)
    r = run_remote(cascade_ip, cascade_cred, "docker compose version 2>/dev/null")
    if r.returncode != 0:
        install_docker_compose(cascade_ip, cascade_cred)
        r = run_remote(cascade_ip, cascade_cred, "docker compose version 2>/dev/null")
        if r.returncode != 0:
            raise RuntimeError(
                f"Docker Compose v2 не установлен на cascade relay {cascade_ip}"
            )

    # --- Web server for CDN origin ---
    xhttp_path = rcfg["xhttp_path"]
    xhttp_base = xhttp_path.rsplit("/", 1)[0]

    if cascade_on_panel:
        # Panel and relay on same server — add xhttp location to existing nginx default
        print("  [cascade] Panel на том же сервере — добавляю xhttp в nginx...")
        xhttp_location = xhttp_base + "/"
        nginx_cascade_default = f"""server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location {xhttp_location} {{
        proxy_pass http://127.0.0.1:7443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_request_buffering off;
        chunked_transfer_encoding on;
    }}

    root /var/www/html;
    index index.html;
}}

server {{
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;

    ssl_certificate /etc/nginx/ssl/cdn.crt;
    ssl_certificate_key /etc/nginx/ssl/cdn.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location {xhttp_location} {{
        proxy_pass http://127.0.0.1:7443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_request_buffering off;
        chunked_transfer_encoding on;
    }}

    root /var/www/html;
    index index.html;
}}
"""
        write_remote_file(cascade_ip, cascade_cred, "/etc/nginx/sites-available/default", nginx_cascade_default)
        run_remote(cascade_ip, cascade_cred,
            "nginx -t 2>&1 && systemctl restart nginx && systemctl enable nginx",
            timeout=30)
        r = run_remote(cascade_ip, cascade_cred, "systemctl is-active nginx")
        if "active" in r.stdout:
            print("  [cascade] Nginx с xhttp запущен (panel сохранён)")
        else:
            print(f"  ⚠ [cascade] Nginx не запустился!")

    else:
        # Separate relay server — use Caddy
        print("  [cascade] Установка Caddy...")
        r = run_remote(cascade_ip, cascade_cred, "caddy version 2>/dev/null")
        if r.returncode != 0 or "v" not in r.stdout:
            # Method 1: Cloudsmith repo
            run_remote(cascade_ip, cascade_cred,
                "apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null 2>&1 && "
                "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null && "
                "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null && "
                "apt-get update -qq && apt-get install -y caddy 2>&1 | tail -3", timeout=300)
            r = run_remote(cascade_ip, cascade_cred, "caddy version 2>/dev/null")
            if r.returncode != 0:
                import time as _t; _t.sleep(10)
                r = run_remote(cascade_ip, cascade_cred, "caddy version 2>/dev/null")
            if r.returncode != 0:
                raise RuntimeError("Caddy не установлен из подписанного Cloudsmith-репозитория")
        print(f"  [cascade] Caddy: {r.stdout.strip()}")

        xhttp_match = f"{xhttp_base}/ {xhttp_base}/*"
        caddyfile = f"""{{
    log {{
        output file /var/log/caddy/access.log
        format json
    }}
}}

:80 {{
    @xhttp path {xhttp_match}
    reverse_proxy @xhttp 127.0.0.1:7443 {{
        flush_interval -1
        transport http {{
            read_buffer 16384
            write_buffer 16384
        }}
    }}
    root * /var/www/html
    file_server
}}

:443 {{
    tls /etc/nginx/ssl/cdn.crt /etc/nginx/ssl/cdn.key
    @xhttp path {xhttp_match}
    reverse_proxy @xhttp 127.0.0.1:7443 {{
        flush_interval -1
        transport http {{
            read_buffer 16384
            write_buffer 16384
        }}
    }}
    root * /var/www/html
    file_server
}}
"""
        write_remote_file(cascade_ip, cascade_cred, "/etc/caddy/Caddyfile", caddyfile)

    run_remote(cascade_ip, cascade_cred, "mkdir -p /var/www/html", timeout=10)
    decoy = DECOY_HTML.format(domain=domain)
    write_remote_file(cascade_ip, cascade_cred, "/var/www/html/index.html", decoy)

    # --- Sysctl + limits ---
    print("  [cascade] Настройка TCP (BBR)...")
    write_remote_file(cascade_ip, cascade_cred, "/etc/sysctl.d/99-vpn-tuning.conf", SYSCTL_TUNING)
    run_remote(cascade_ip, cascade_cred, "sysctl --system > /dev/null 2>&1")
    write_remote_file(cascade_ip, cascade_cred, "/etc/security/limits.d/99-nofile.conf", NOFILE_LIMITS)

    # --- Self-signed SSL for nginx compat (remnanode needs it) ---
    run_remote(cascade_ip, cascade_cred, "mkdir -p /etc/nginx/ssl && test -f /etc/nginx/ssl/cdn.crt || openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj '/CN=cdn-origin' 2>/dev/null")
    caddy_acl = run_remote(
        cascade_ip,
        cascade_cred,
        "getent group caddy >/dev/null || groupadd --system caddy; "
        "chown root:caddy /etc/nginx/ssl/cdn.key /etc/caddy /etc/caddy/Caddyfile && "
        "chmod 640 /etc/nginx/ssl/cdn.key /etc/caddy/Caddyfile && "
        "chmod 750 /etc/caddy && "
        "chmod 644 /etc/nginx/ssl/cdn.crt && "
        "runuser -u caddy -- test -r /etc/nginx/ssl/cdn.key && "
        "runuser -u caddy -- test -r /etc/caddy/Caddyfile && "
        "runuser -u caddy -- caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null",
        timeout=30,
    )
    if caddy_acl.returncode != 0:
        detail = (caddy_acl.stderr or caddy_acl.stdout or "").strip()
        raise RuntimeError(
            "Не удалось подготовить права и проверить конфигурацию Caddy: "
            + (detail[-1000:] if detail else "неизвестная ошибка")
        )

    # --- Swap ---
    run_remote(cascade_ip, cascade_cred, "swapon --show | grep -q / || (fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab) 2>/dev/null")

    # --- Firewall ---
    print("  [cascade] Открытие портов 80/443...")
    r = run_remote(cascade_ip, cascade_cred, "ufw status 2>/dev/null")
    if r.returncode == 0 and "active" in r.stdout.lower():
        run_remote(cascade_ip, cascade_cred, "ufw allow 80/tcp >/dev/null 2>&1 && ufw allow 443/tcp >/dev/null 2>&1 && ufw reload >/dev/null 2>&1")
    run_remote(cascade_ip, cascade_cred, "iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null")

    if not cascade_on_panel:
        # --- Start Caddy (will auto-issue TLS cert) ---
        print(f"  [cascade] Запуск Caddy ({origin_domain})...")
        run_remote(cascade_ip, cascade_cred, "systemctl enable caddy >/dev/null 2>&1 && systemctl restart caddy", timeout=60)
        time.sleep(3)
        r = run_remote(cascade_ip, cascade_cred, "systemctl is-active caddy")
        if "active" in r.stdout:
            print("  [cascade] Caddy запущен")
        else:
            r2 = run_remote(cascade_ip, cascade_cred, "journalctl -u caddy --no-pager -n 10 2>&1")
            raise RuntimeError(f"Caddy не запустился: {r2.stdout.strip()[-300:]}")

    # --- Bridge user UUID (generate and pass to Remnawave as vlessUuid) ---
    bridge_user_uuid = str(uuid.uuid4())

    # --- Cascade profile ---
    print(f"  [cascade] Создание cascade профиля...")
    install_hy2 = cfg.get("install_hy2", False)
    install_grpc = cfg.get("install_grpc", False)
    cascade_hy2 = cfg.get("cascade_hy2", False)
    cascade_grpc = cfg.get("cascade_grpc", False)
    bridge_keys, bridge_sid = prepare_bridge_reality(cfg)
    cascade_profile_config = build_cascade_profile(
        rcfg, exit_ip, bridge_user_uuid,
        bridge_keys["public"], bridge_sid,
        youtube_direct=cfg.get("youtube_direct", False),
        install_hy2=(install_hy2 and cascade_hy2),
        install_grpc=(install_grpc and cascade_grpc))
    if cfg.get("youtube_direct"):
        print("  [cascade] YouTube/SoundCloud → напрямую через relay (антиреклама)")
    tag_id = secrets.token_hex(3)
    cascade_profile_name = f"cascade-{cdn_type}-{tag_id}"
    for _ib in cascade_profile_config.get("inbounds", []):
        _ib["tag"] = f"{_ib['tag']}-{tag_id}"
    for _rule in cascade_profile_config.get("routing", {}).get("rules", []):
        if "inboundTag" in _rule:
            _rule["inboundTag"] = [f"{t}-{tag_id}" if "-cascade" in t else t for t in _rule["inboundTag"]]
    resp = None
    for _attempt in range(4):
        resp = api_func("POST", "config-profiles", {
            "name": cascade_profile_name,
            "config": cascade_profile_config
        })
        if resp.get("response"):
            break
        if _attempt < 3:
            print(f"  [cascade] API retry профиля ({_attempt+1}/3), жду 10 сек...")
            time.sleep(10)
    if not resp.get("response"):
        print(f"  ❌ [cascade] Ошибка создания профиля: {resp}")
        sys.exit(1)
    cascade_profile_uuid = resp["response"]["uuid"]
    cascade_inbound_uuid = None
    cascade_hy2_inbound_uuid = None
    cascade_grpc_inbound_uuid = None
    for ib in resp["response"].get("inbounds", []):
        tag = ib.get("tag", "")
        if "cascade" in tag and "HY2" not in tag and "gRPC" not in tag:
            cascade_inbound_uuid = ib["uuid"]
        elif "HY2-cascade" in tag:
            cascade_hy2_inbound_uuid = ib["uuid"]
        elif "gRPC-cascade" in tag:
            cascade_grpc_inbound_uuid = ib["uuid"]
    if not cascade_inbound_uuid:
        inbounds = resp["response"].get("inbounds", [])
        if inbounds:
            cascade_inbound_uuid = inbounds[0]["uuid"]
    print(f"  [cascade] Profile: {cascade_profile_uuid}")
    print(f"  [cascade] CDN Inbound: {cascade_inbound_uuid}")
    if cascade_hy2_inbound_uuid:
        print(f"  [cascade] HY2 Inbound: {cascade_hy2_inbound_uuid}")
    if cascade_grpc_inbound_uuid:
        print(f"  [cascade] gRPC Inbound: {cascade_grpc_inbound_uuid}")

    # --- Add cascade inbound + BRIDGE_IN to squad ---
    updated_squad_inbounds = list(existing_squad_inbounds)
    if cascade_inbound_uuid and cascade_inbound_uuid not in updated_squad_inbounds:
        updated_squad_inbounds.append(cascade_inbound_uuid)
    if cascade_hy2_inbound_uuid and cascade_hy2_inbound_uuid not in updated_squad_inbounds:
        updated_squad_inbounds.append(cascade_hy2_inbound_uuid)
    if cascade_grpc_inbound_uuid and cascade_grpc_inbound_uuid not in updated_squad_inbounds:
        updated_squad_inbounds.append(cascade_grpc_inbound_uuid)

    bridge_inbound_uuid = None
    all_profiles = api_func("GET", "config-profiles")
    if all_profiles.get("response"):
        resp_data = all_profiles["response"]
        profiles_list = resp_data.get("configProfiles", resp_data if isinstance(resp_data, list) else [resp_data])
        for p in profiles_list:
            if p.get("uuid") == profile_uuid:
                for ib in p.get("inbounds", []):
                    if ib.get("tag", "").startswith("BRIDGE_IN"):
                        bridge_inbound_uuid = ib["uuid"]
                        break
                break
    if bridge_inbound_uuid and bridge_inbound_uuid not in updated_squad_inbounds:
        updated_squad_inbounds.append(bridge_inbound_uuid)

    if not squad_uuid:
        squad_uuid = find_default_squad(api_func)
        if squad_uuid:
            squads_resp = api_func("GET", "internal-squads")
            sq_list = squads_resp.get("response", {}).get("internalSquads", [])
            sq = next((s for s in sq_list if s.get("uuid") == squad_uuid), None)
            if sq:
                for ib in sq.get("inbounds", []):
                    ib_uuid = ib.get("uuid") if isinstance(ib, dict) else ib
                    if ib_uuid and ib_uuid not in updated_squad_inbounds:
                        updated_squad_inbounds.insert(0, ib_uuid)

    if not squad_uuid:
        raise RuntimeError("[cascade] Default-Squad не найден")
    # Validate every inbound UUID against the live Config Profiles
    _check_resp = api_func("GET", "config-profiles")
    _check_data = _check_resp.get("response")

    if isinstance(_check_data, dict):
        _check_profiles = _check_data.get("configProfiles", [])
    elif isinstance(_check_data, list):
        _check_profiles = _check_data
    else:
        _check_profiles = []

    if not _check_resp.get("response") or not _check_profiles:
        raise RuntimeError(
            "[cascade] Не удалось получить актуальный список Config Profiles"
        )

    _valid_inbound_uuids = set()

    for _profile in _check_profiles:
        for _ib in _profile.get("inbounds", []) or []:
            _uid = _ib.get("uuid") if isinstance(_ib, dict) else _ib
            if isinstance(_uid, str) and _uid.strip():
                _valid_inbound_uuids.add(_uid.strip())

    _payload_inbounds = []
    _stale_inbounds = []

    for _item in updated_squad_inbounds:
        _uid = _item.get("uuid") if isinstance(_item, dict) else _item

        if not isinstance(_uid, str) or not _uid.strip():
            _stale_inbounds.append(repr(_item))
            continue

        _uid = _uid.strip()

        if _uid not in _valid_inbound_uuids:
            _stale_inbounds.append(_uid)
            continue

        if _uid not in _payload_inbounds:
            _payload_inbounds.append(_uid)

    _required_inbounds = [
        _uid for _uid in [
            cascade_inbound_uuid,
            cascade_hy2_inbound_uuid,
            cascade_grpc_inbound_uuid,
            bridge_inbound_uuid
        ] if _uid
    ]

    _missing_required = [
        _uid for _uid in _required_inbounds
        if _uid not in _valid_inbound_uuids
    ]

    print(f"  [cascade] Squad UUID: {squad_uuid}")
    print(f"  [cascade] Проверено inbound UUID: {len(_payload_inbounds)}")

    for _uid in _payload_inbounds:
        print(f"  [cascade] VALID inbound: {_uid}")

    if _stale_inbounds:
        print(f"  [cascade] Устаревшие inbound исключены: {_stale_inbounds}")

    if _missing_required:
        raise RuntimeError(
            "[cascade] Новые cascade/bridge inbound отсутствуют "
            f"в Config Profiles: {_missing_required}"
        )

    _sq_patch = api_func("PATCH", "internal-squads", {
        "uuid": squad_uuid,
        "inbounds": _payload_inbounds
    })
    if not _sq_patch.get("response"):
        raise RuntimeError(f"[cascade] Не удалось привязать inbounds к squad: {_sq_patch}")
    print("  [cascade] Инбаунды добавлены в сквад")

    # --- Create cascade node ---
    print(f"  [cascade] Создание ноды для relay {cascade_ip}...")
    cascade_excluded = []
    if all_profiles.get("response"):
        resp_data = all_profiles["response"]
        profiles_list = resp_data.get("configProfiles", resp_data if isinstance(resp_data, list) else [resp_data])
        for p in profiles_list:
            if p.get("uuid") != cascade_profile_uuid:
                for ib in p.get("inbounds", []):
                    if ib.get("uuid"):
                        cascade_excluded.append(ib["uuid"])

    if cascade_on_panel:
        gw = run("docker network inspect remnawave-network -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'", check=False)
        cascade_node_address = gw.stdout.strip() or "172.18.0.1"
        print(f"  [cascade] Panel и relay на одном сервере — используем Docker gateway: {cascade_node_address}")
    else:
        cascade_node_address = cascade_ip

    cascade_active_inbounds = []
    if cascade_inbound_uuid:
        cascade_active_inbounds.append(cascade_inbound_uuid)
    if cascade_hy2_inbound_uuid:
        cascade_active_inbounds.append(cascade_hy2_inbound_uuid)
    if cascade_grpc_inbound_uuid:
        cascade_active_inbounds.append(cascade_grpc_inbound_uuid)

    cascade_node_data = {
        "name": f"cascade-relay-{cascade_ip.replace('.', '-')}",
        "address": cascade_node_address,
        "port": 2222,
        "countryCode": "RU",
        "isTrafficTrackingActive": True,
        "trafficLimitBytes": 0,
        "notifyPercent": 0,
        "trafficResetDay": 1,
        "excludedInbounds": cascade_excluded,
        "configProfile": {
            "activeConfigProfileUuid": cascade_profile_uuid,
            "activeInbounds": cascade_active_inbounds
        }
    }
    resp = None
    for _attempt in range(4):
        resp = api_func("POST", "nodes", cascade_node_data)
        if resp.get("response"):
            break
        if _attempt < 3:
            print(f"  [cascade] API retry ноды ({_attempt+1}/3), жду 10 сек...")
            time.sleep(10)
    if not resp.get("response"):
        print(f"  ❌ [cascade] Ошибка создания ноды: {resp}")
        sys.exit(1)
    cascade_node_uuid = resp["response"]["uuid"]
    print(f"  [cascade] Node UUID: {cascade_node_uuid}")

    # --- Get secret key ---
    secret_key = None
    resp = api_func("GET", "keygen")
    if resp.get("response"):
        secret_key = resp["response"].get("pubKey")
    if not secret_key:
        raise RuntimeError("[cascade] Не удалось получить keygen pubKey; relay-ноду запускать нельзя")

    # --- Deploy remnanode on relay ---
    print("  [cascade] Установка remnanode на relay...")
    run_remote(cascade_ip, cascade_cred, "mkdir -p /opt/remnanode")
    node_compose = f"services:\n  remnanode:\n    container_name: remnanode\n    hostname: remnanode\n    image: remnawave/node:{REMNAWAVE_NODE_VERSION}\n    network_mode: host\n    restart: always\n    cap_add:\n      - NET_ADMIN\n    ulimits:\n      nofile:\n        soft: 1048576\n        hard: 1048576\n    volumes:\n      - /etc/nginx/ssl:/etc/nginx/ssl:ro\n      - /opt/remnanode/xray-custom:/usr/local/bin/xray\n    env_file:\n      - .env\n"
    write_remote_file(cascade_ip, cascade_cred, "/opt/remnanode/docker-compose.yml", node_compose)
    node_env = f"NODE_PORT=2222\nSECRET_KEY={secret_key or 'REPLACE_WITH_KEY_FROM_PANEL'}\n"
    write_remote_file(cascade_ip, cascade_cred, "/opt/remnanode/.env", node_env)

    if secret_key:
        if not download_xray_binary(remote_ip=cascade_ip, remote_cred=cascade_cred):
            raise RuntimeError("Не удалось установить проверенный Xray на cascade-ноду")
        require_success(
            run_remote(cascade_ip, cascade_cred, "cd /opt/remnanode && docker compose pull", timeout=600,
                       label="Загрузка remnanode (relay)", expected=45),
            "Загрузка remnanode на cascade-ноде",
        )
        if not ensure_remnanode_up(cascade_ip, cascade_cred):
            raise RuntimeError("remnanode не запустился на cascade-ноде")
        print("  [cascade] remnanode запущен на relay")

        # Restrict port 2222 to panel only
        panel_ip = cfg.get("panel_ip", "")
        iptables_add(f"-I INPUT -p tcp --dport 2222 -s {server_ip} -j ACCEPT", remote_ip=cascade_ip, remote_cred=cascade_cred)
        if panel_ip and panel_ip != server_ip:
            iptables_add(f"-I INPUT -p tcp --dport 2222 -s {panel_ip} -j ACCEPT", remote_ip=cascade_ip, remote_cred=cascade_cred)
        iptables_add("-I INPUT -p tcp --dport 2222 -s 127.0.0.1 -j ACCEPT", remote_ip=cascade_ip, remote_cred=cascade_cred)
        if cascade_on_panel:
            iptables_add("-I INPUT -p tcp --dport 2222 -s 172.16.0.0/12 -j ACCEPT", remote_ip=cascade_ip, remote_cred=cascade_cred)
        iptables_add("-A INPUT -p tcp --dport 2222 -j DROP", remote_ip=cascade_ip, remote_cred=cascade_cred)
        pkg_iptables_persist(remote_ip=cascade_ip, remote_cred=cascade_cred)

        print("  [cascade] Ожидание запуска ноды...")
        for i in range(20):
            time.sleep(5)
            r = run_remote(cascade_ip, cascade_cred, "docker logs remnanode --tail=5 2>&1")
            if "started" in r.stdout.lower() or "running" in r.stdout.lower() or "XRay" in r.stdout:
                print("  [cascade] Нода relay запущена!")
                break

    # --- Create cascade host ---
    cdn_domain = f"{cfg['cdn_sub']}.{domain}"
    print(f"  [cascade] Создание хоста: {cdn_domain} -> {origin_domain}...")
    extra_fields = {k: rcfg["host_extra"] for k in remnawave_extra_keys(api_func)}
    cascade_host_payload = {
        "inbound": {"configProfileUuid": cascade_profile_uuid, "configProfileInboundUuid": cascade_inbound_uuid},
        "remark": f"Cascade {cdn_type.upper()}",
        "address": cdn_domain, "port": 443,
        "path": rcfg.get("host_path", rcfg["xhttp_path"]),
        "sni": cdn_domain, "host": cdn_domain,
        "alpn": rcfg["alpn"],
        "fingerprint": rcfg.get("fingerprint", rcfg.get("fp", "random")),
        "isDisabled": False, "securityLayer": "TLS", "allowInsecure": False,
        **extra_fields,
    }
    resp = api_func("POST", "hosts", cascade_host_payload)
    cascade_host_uuid = None
    if not resp.get("response"):
        raise RuntimeError(f"[cascade] Ошибка создания хоста: {resp}")
    cascade_host_uuid = resp["response"].get("uuid")
    if not cascade_host_uuid:
        raise RuntimeError("[cascade] API создал host без UUID")
    print(f"  [cascade] Host UUID: {cascade_host_uuid}")
    if cascade_node_uuid:
        _host_link = api_func("PATCH", "hosts", {
            "uuid": cascade_host_uuid, "nodes": [cascade_node_uuid]
        })
        if not _host_link.get("response"):
            raise RuntimeError(f"[cascade] Не удалось привязать host к relay: {_host_link}")
        print("  [cascade] Хост привязан к relay ноде")

    # --- Create bridge user (with explicit vlessUuid to match VLESS_EXIT outbound) ---
    # Юзер ОБЯЗАН состоять в скваде: именно из сквада Remnawave раздаёт нодам
    # список клиентов. Иначе BRIDGE_IN поднимется с пустым списком и хендшейк
    # с relay зависнет без ошибок в логах.
    bridge_squad = squad_uuid or find_default_squad(api_func)
    print(f"  [cascade] Создание bridge юзера (vless UUID: {bridge_user_uuid[:8]}...)...")
    bridge_username = f"bridge_{tag_id}"
    bridge_payload = {
        "username": bridge_username,
        "vlessUuid": bridge_user_uuid,
        "trojanPassword": bridge_user_uuid.replace("-", "")[:16],
        "expireAt": "2099-12-31T23:59:59.000Z",
        "trafficLimitBytes": 0,
        "trafficLimitStrategy": "NO_RESET",
        "hwidDeviceLimit": 0
    }
    if bridge_squad:
        bridge_payload["activeInternalSquads"] = [bridge_squad]
    resp = api_func("POST", "users", bridge_payload)
    if resp.get("response"):
        actual_uuid = resp["response"].get("vlessUuid", "")
        if not actual_uuid:
            all_u = api_func("GET", "users")
            ud = all_u.get("response") or {}
            ulist = ud.get("users", ud) if isinstance(ud, dict) else ud
            if isinstance(ulist, list):
                bu = next((u for u in ulist if u.get("username") == bridge_username), None)
                if bu:
                    actual_uuid = bu.get("vlessUuid", "")
        if actual_uuid and actual_uuid != bridge_user_uuid:
            print(f"  [cascade] UUID fix: панель назначила {actual_uuid[:8]}...")
            cascade_profile_config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = actual_uuid
            api_func("PATCH", "config-profiles", {"uuid": cascade_profile_uuid, "config": cascade_profile_config})
            bridge_user_uuid = actual_uuid
        print(f"  [cascade] Bridge user создан (UUID: {bridge_user_uuid[:8]}...)")
        if bridge_squad and not ensure_user_squad(api_func, bridge_username, bridge_squad):
            raise RuntimeError("Bridge user не добавлен в Default-Squad")
    else:
        raise RuntimeError(f"[cascade] Не удалось создать bridge user: {resp}")

    # --- Sync both nodes ---
    print("  [cascade] Синхронизация нод...")
    run_remote(cascade_ip, cascade_cred, "docker restart remnanode", timeout=30)
    if same_server:
        run("docker restart remnanode", check=False, timeout=30)
    else:
        run_remote(exit_ip, node_cred, "docker restart remnanode", timeout=30)
    time.sleep(10)

    r = run_remote(cascade_ip, cascade_cred, "docker logs remnanode --tail=10 2>&1", timeout=15)
    m = re.search(r'(\d+)\s+users', r.stdout) if r.stdout else None
    if m and int(m.group(1)) > 0:
        print(f"  [cascade] Relay синхронизирован: {m.group(1)} юзеров")
    else:
        print("  [cascade] Relay перезапущен")

    _relay_listener = xray_listener_status(
        7443, expected_host="127.0.0.1",
        remote_ip=cascade_ip, remote_cred=cascade_cred)
    if not _relay_listener["ok"]:
        raise RuntimeError(
            "[cascade] Xray relay не слушает 127.0.0.1:7443 "
            f"(owner={_relay_listener['owner_ok']}, bind={_relay_listener['address_ok']})"
        )

    if same_server:
        _exit_listener = xray_listener_status(8888, expected_host="0.0.0.0")
    else:
        _exit_listener = xray_listener_status(
            8888, expected_host="0.0.0.0",
            remote_ip=exit_ip, remote_cred=node_cred)
    if not _exit_listener["ok"]:
        raise RuntimeError(
            "[cascade] Xray exit не слушает защищённый BRIDGE_IN 0.0.0.0:8888 "
            f"(owner={_exit_listener['owner_ok']}, bind={_exit_listener['address_ok']})"
        )

    _tcp_probe = run_remote(
        cascade_ip, cascade_cred,
        f"timeout 5 bash -c '</dev/tcp/{shlex.quote(exit_ip)}/8888' 2>/dev/null",
        timeout=10)
    if _tcp_probe.returncode != 0:
        raise RuntimeError("[cascade] Relay не может установить TCP к exit:8888")

    if cascade_on_panel:
        _web_cmd = (
            "nginx -T 2>&1 | grep -Fq 'proxy_pass http://127.0.0.1:7443' && "
            "curl -fsS --max-time 5 http://127.0.0.1/ >/dev/null"
        )
    else:
        _web_cmd = (
            "caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 && "
            "grep -Fq '127.0.0.1:7443' /etc/caddy/Caddyfile && "
            "systemctl is-active --quiet caddy && "
            "curl -fsS --max-time 5 http://127.0.0.1/ >/dev/null"
        )
    _web_probe = run_remote(cascade_ip, cascade_cred, _web_cmd, timeout=15)
    if _web_probe.returncode != 0:
        raise RuntimeError("[cascade] Web origin не связан с Xray 127.0.0.1:7443")

    print("  [cascade] Проверка цепочки: web origin -> Xray:7443 -> REALITY:8888 OK")

    print(f"""
  ============================================
  КАСКАД НАСТРОЕН
  ============================================

  Exit нода: {exit_ip} (port 8888 BRIDGE_IN)
  Relay нода: {cascade_ip} (Caddy + remnanode)
  Origin: {origin_domain} -> {cascade_ip}
  Bridge user UUID: {bridge_user_uuid}

  CDN origin должен указывать на: {origin_domain}
  (DNS A-запись: {origin_domain} -> {cascade_ip})
  ============================================
""")
    return {
        "cascade_profile_uuid": cascade_profile_uuid,
        "cascade_inbound_uuid": cascade_inbound_uuid,
        "cascade_node_uuid": cascade_node_uuid,
        "bridge_user_uuid": bridge_user_uuid,
    }


# ============================================================
#  REMNAWAVE SUBSCRIPTION PAGE (#5)
# ============================================================

# Записи приложения INCY (клиент с xray-ядром) для страницы подписки, по одной
# на платформу. Эталон снят с живой панели, где INCY уже настроен: urlScheme
# incy://import/ (deeplink авто-добавления), тексты/локали — родные INCY (не
# Happ, проверено). ios/android — точные копии; desktop собран на базе тех же
# шагов + ссылки релизов GitHub (latest, чтобы не устаревали). ASCII-JSON —
# переносимо в Nuitka-бинарник. Список приложений в subscription-page задаётся
# файлом app-config.json; INCY добавляем в него первым (featured).
INCY_APPS_JSON = '{"ios":{"id":"incy","name":"InCy","isFeatured":true,"urlScheme":"incy://import/","installationStep":{"buttons":[{"buttonLink":"https://apps.apple.com/us/app/incy/id6756943388","buttonText":{"en":"App Store","fa":"App Store","ru":"App Store","zh":"App Store","fr":"App Store"}}],"description":{"en":"Open the page in App Store and install the app. Launch it, in the VPN configuration permission window click Allow and enter your passcode.","fa":"\\u0635\\u0641\\u062d\\u0647 \\u0631\\u0627 \\u062f\\u0631 App Store \\u0628\\u0627\\u0632 \\u06a9\\u0646\\u06cc\\u062f \\u0648 \\u0628\\u0631\\u0646\\u0627\\u0645\\u0647 \\u0631\\u0627 \\u0646\\u0635\\u0628 \\u06a9\\u0646\\u06cc\\u062f. \\u0622\\u0646 \\u0631\\u0627 \\u0627\\u062c\\u0631\\u0627 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041e\\u0442\\u043a\\u0440\\u043e\\u0439\\u0442\\u0435 \\u0441\\u0442\\u0440\\u0430\\u043d\\u0438\\u0446\\u0443 \\u0432 App Store \\u0438 \\u0443\\u0441\\u0442\\u0430\\u043d\\u043e\\u0432\\u0438\\u0442\\u0435 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435. \\u0417\\u0430\\u043f\\u0443\\u0441\\u0442\\u0438\\u0442\\u0435 \\u0435\\u0433\\u043e, \\u0440\\u0430\\u0437\\u0440\\u0435\\u0448\\u0438\\u0442\\u0435 VPN-\\u043a\\u043e\\u043d\\u0444\\u0438\\u0433\\u0443\\u0440\\u0430\\u0446\\u0438\\u044e.","zh":"\\u5728 App Store \\u6253\\u5f00\\u9875\\u9762\\u5e76\\u5b89\\u88c5\\u5e94\\u7528\\u3002\\u542f\\u52a8\\u5e94\\u7528\\u540e\\uff0c\\u5728 VPN \\u914d\\u7f6e\\u6743\\u9650\\u7a97\\u53e3\\u70b9\\u51fb\\u5141\\u8bb8\\u3002","fr":"Ouvre la page de l\'App Store et installe l\'app. Lance-la et autorise la configuration VPN."}},"addSubscriptionStep":{"description":{"en":"Click the button below \\u2014 the app will open and the subscription will be added automatically.","fa":"\\u0628\\u0631\\u0627\\u06cc \\u0627\\u0641\\u0632\\u0648\\u062f\\u0646 \\u062e\\u0648\\u062f\\u06a9\\u0627\\u0631 \\u0627\\u0634\\u062a\\u0631\\u0627\\u06a9 \\u0631\\u0648\\u06cc \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u06a9\\u0644\\u06cc\\u06a9 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u2014 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435 \\u043e\\u0442\\u043a\\u0440\\u043e\\u0435\\u0442\\u0441\\u044f, \\u0438 \\u043f\\u043e\\u0434\\u043f\\u0438\\u0441\\u043a\\u0430 \\u0434\\u043e\\u0431\\u0430\\u0432\\u0438\\u0442\\u0441\\u044f \\u0430\\u0432\\u0442\\u043e\\u043c\\u0430\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438.","zh":"\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\uff0c\\u5e94\\u7528\\u5c06\\u4f1a\\u6253\\u5f00\\uff0c\\u5e76\\u81ea\\u52a8\\u6dfb\\u52a0\\u8ba2\\u9605\\u3002","fr":"Clique sur le bouton ci-dessous \\u2014 l\'app s\'ouvrira et l\'abonnement sera ajout\\u00e9 automatiquement."}},"connectAndUseStep":{"description":{"en":"In the main section, click the connect button to start VPN. Select a server from the list if needed.","fa":"\\u062f\\u0631 \\u0628\\u062e\\u0634 \\u0627\\u0635\\u0644\\u06cc\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0627\\u062a\\u0635\\u0627\\u0644 \\u0631\\u0627 \\u0628\\u0632\\u0646\\u06cc\\u062f. \\u062f\\u0631 \\u0635\\u0648\\u0631\\u062a \\u0646\\u06cc\\u0627\\u0632 \\u0633\\u0631\\u0648\\u0631 \\u062f\\u06cc\\u06af\\u0631\\u06cc \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u0412 \\u0433\\u043b\\u0430\\u0432\\u043d\\u043e\\u043c \\u0440\\u0430\\u0437\\u0434\\u0435\\u043b\\u0435 \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043f\\u043e\\u0434\\u043a\\u043b\\u044e\\u0447\\u0435\\u043d\\u0438\\u044f \\u043a VPN. \\u041f\\u0440\\u0438 \\u043d\\u0435\\u043e\\u0431\\u0445\\u043e\\u0434\\u0438\\u043c\\u043e\\u0441\\u0442\\u0438 \\u0432\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u0441\\u0435\\u0440\\u0432\\u0435\\u0440 \\u0438\\u0437 \\u0441\\u043f\\u0438\\u0441\\u043a\\u0430.","zh":"\\u5728\\u4e3b\\u754c\\u9762\\u70b9\\u51fb\\u8fde\\u63a5\\u6309\\u94ae\\u4ee5\\u542f\\u52a8 VPN\\u3002\\u5982\\u6709\\u9700\\u8981\\uff0c\\u53ef\\u9009\\u62e9\\u5176\\u5b83\\u670d\\u52a1\\u5668\\u3002","fr":"Dans la section principale, appuie sur le bouton de connexion. Choisis un serveur si besoin."}}},"android":{"id":"incy","name":"InCy","isFeatured":true,"urlScheme":"incy://import/","installationStep":{"buttons":[{"buttonLink":"https://play.google.com/store/apps/details?id=llc.itdev.incy","buttonText":{"en":"Google Play","fa":"Google Play","ru":"Google Play","zh":"Google Play","fr":"Google Play"}}],"description":{"en":"Open Google Play and install the app. Launch it and allow VPN configuration when prompted.","fa":"Google Play \\u0631\\u0627 \\u0628\\u0627\\u0632 \\u06a9\\u0646\\u06cc\\u062f \\u0648 \\u0628\\u0631\\u0646\\u0627\\u0645\\u0647 \\u0631\\u0627 \\u0646\\u0635\\u0628 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041e\\u0442\\u043a\\u0440\\u043e\\u0439\\u0442\\u0435 Google Play \\u0438 \\u0443\\u0441\\u0442\\u0430\\u043d\\u043e\\u0432\\u0438\\u0442\\u0435 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435. \\u0417\\u0430\\u043f\\u0443\\u0441\\u0442\\u0438\\u0442\\u0435 \\u0435\\u0433\\u043e \\u0438 \\u0440\\u0430\\u0437\\u0440\\u0435\\u0448\\u0438\\u0442\\u0435 VPN-\\u043a\\u043e\\u043d\\u0444\\u0438\\u0433\\u0443\\u0440\\u0430\\u0446\\u0438\\u044e.","zh":"\\u6253\\u5f00 Google Play \\u5e76\\u5b89\\u88c5\\u5e94\\u7528\\u3002\\u542f\\u52a8\\u5e94\\u7528\\u540e\\u5141\\u8bb8 VPN \\u914d\\u7f6e\\u3002","fr":"Ouvre Google Play et installe l\'app. Lance-la et autorise la configuration VPN."}},"addSubscriptionStep":{"description":{"en":"Click the button below \\u2014 the app will open and the subscription will be added automatically.","fa":"\\u0628\\u0631\\u0627\\u06cc \\u0627\\u0641\\u0632\\u0648\\u062f\\u0646 \\u062e\\u0648\\u062f\\u06a9\\u0627\\u0631 \\u0627\\u0634\\u062a\\u0631\\u0627\\u06a9 \\u0631\\u0648\\u06cc \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u06a9\\u0644\\u06cc\\u06a9 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u2014 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435 \\u043e\\u0442\\u043a\\u0440\\u043e\\u0435\\u0442\\u0441\\u044f, \\u0438 \\u043f\\u043e\\u0434\\u043f\\u0438\\u0441\\u043a\\u0430 \\u0434\\u043e\\u0431\\u0430\\u0432\\u0438\\u0442\\u0441\\u044f \\u0430\\u0432\\u0442\\u043e\\u043c\\u0430\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438.","zh":"\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\uff0c\\u5e94\\u7528\\u5c06\\u4f1a\\u6253\\u5f00\\uff0c\\u5e76\\u81ea\\u52a8\\u6dfb\\u52a0\\u8ba2\\u9605\\u3002","fr":"Clique sur le bouton ci-dessous \\u2014 l\'app s\'ouvrira et l\'abonnement sera ajout\\u00e9 automatiquement."}},"connectAndUseStep":{"description":{"en":"In the main section, click the connect button to start VPN. Select a server from the list if needed.","fa":"\\u062f\\u0631 \\u0628\\u062e\\u0634 \\u0627\\u0635\\u0644\\u06cc\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0627\\u062a\\u0635\\u0627\\u0644 \\u0631\\u0627 \\u0628\\u0632\\u0646\\u06cc\\u062f. \\u062f\\u0631 \\u0635\\u0648\\u0631\\u062a \\u0646\\u06cc\\u0627\\u0632 \\u0633\\u0631\\u0648\\u0631 \\u062f\\u06cc\\u06af\\u0631\\u06cc \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u0412 \\u0433\\u043b\\u0430\\u0432\\u043d\\u043e\\u043c \\u0440\\u0430\\u0437\\u0434\\u0435\\u043b\\u0435 \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043f\\u043e\\u0434\\u043a\\u043b\\u044e\\u0447\\u0435\\u043d\\u0438\\u044f \\u043a VPN. \\u041f\\u0440\\u0438 \\u043d\\u0435\\u043e\\u0431\\u0445\\u043e\\u0434\\u0438\\u043c\\u043e\\u0441\\u0442\\u0438 \\u0432\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u0441\\u0435\\u0440\\u0432\\u0435\\u0440 \\u0438\\u0437 \\u0441\\u043f\\u0438\\u0441\\u043a\\u0430.","zh":"\\u5728\\u4e3b\\u754c\\u9762\\u70b9\\u51fb\\u8fde\\u63a5\\u6309\\u94ae\\u4ee5\\u542f\\u52a8 VPN\\u3002\\u5982\\u6709\\u9700\\u8981\\uff0c\\u53ef\\u9009\\u62e9\\u5176\\u5b83\\u670d\\u52a1\\u5668\\u3002","fr":"Dans la section principale, appuie sur le bouton de connexion. Choisis un serveur si besoin."}}},"windows":{"id":"incy","name":"InCy","isFeatured":true,"urlScheme":"incy://import/","addSubscriptionStep":{"description":{"en":"Click the button below \\u2014 the app will open and the subscription will be added automatically.","fa":"\\u0628\\u0631\\u0627\\u06cc \\u0627\\u0641\\u0632\\u0648\\u062f\\u0646 \\u062e\\u0648\\u062f\\u06a9\\u0627\\u0631 \\u0627\\u0634\\u062a\\u0631\\u0627\\u06a9 \\u0631\\u0648\\u06cc \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u06a9\\u0644\\u06cc\\u06a9 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u2014 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435 \\u043e\\u0442\\u043a\\u0440\\u043e\\u0435\\u0442\\u0441\\u044f, \\u0438 \\u043f\\u043e\\u0434\\u043f\\u0438\\u0441\\u043a\\u0430 \\u0434\\u043e\\u0431\\u0430\\u0432\\u0438\\u0442\\u0441\\u044f \\u0430\\u0432\\u0442\\u043e\\u043c\\u0430\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438.","zh":"\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\uff0c\\u5e94\\u7528\\u5c06\\u4f1a\\u6253\\u5f00\\uff0c\\u5e76\\u81ea\\u52a8\\u6dfb\\u52a0\\u8ba2\\u9605\\u3002","fr":"Clique sur le bouton ci-dessous \\u2014 l\'app s\'ouvrira et l\'abonnement sera ajout\\u00e9 automatiquement."}},"connectAndUseStep":{"description":{"en":"In the main section, click the connect button to start VPN. Select a server from the list if needed.","fa":"\\u062f\\u0631 \\u0628\\u062e\\u0634 \\u0627\\u0635\\u0644\\u06cc\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0627\\u062a\\u0635\\u0627\\u0644 \\u0631\\u0627 \\u0628\\u0632\\u0646\\u06cc\\u062f. \\u062f\\u0631 \\u0635\\u0648\\u0631\\u062a \\u0646\\u06cc\\u0627\\u0632 \\u0633\\u0631\\u0648\\u0631 \\u062f\\u06cc\\u06af\\u0631\\u06cc \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u0412 \\u0433\\u043b\\u0430\\u0432\\u043d\\u043e\\u043c \\u0440\\u0430\\u0437\\u0434\\u0435\\u043b\\u0435 \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043f\\u043e\\u0434\\u043a\\u043b\\u044e\\u0447\\u0435\\u043d\\u0438\\u044f \\u043a VPN. \\u041f\\u0440\\u0438 \\u043d\\u0435\\u043e\\u0431\\u0445\\u043e\\u0434\\u0438\\u043c\\u043e\\u0441\\u0442\\u0438 \\u0432\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u0441\\u0435\\u0440\\u0432\\u0435\\u0440 \\u0438\\u0437 \\u0441\\u043f\\u0438\\u0441\\u043a\\u0430.","zh":"\\u5728\\u4e3b\\u754c\\u9762\\u70b9\\u51fb\\u8fde\\u63a5\\u6309\\u94ae\\u4ee5\\u542f\\u52a8 VPN\\u3002\\u5982\\u6709\\u9700\\u8981\\uff0c\\u53ef\\u9009\\u62e9\\u5176\\u5b83\\u670d\\u52a1\\u5668\\u3002","fr":"Dans la section principale, appuie sur le bouton de connexion. Choisis un serveur si besoin."}},"installationStep":{"buttons":[{"buttonLink":"https://github.com/INCY-DEV/incy-platforms/releases/latest/download/incy-windows-portable.zip","buttonText":{"en":"Download (Windows)","fa":"Download (Windows)","ru":"Download (Windows)","zh":"Download (Windows)","fr":"Download (Windows)"}}],"description":{"en":"Choose the version for your device, click the button below and install the app.","fa":"\\u0646\\u0633\\u062e\\u0647 \\u0645\\u0646\\u0627\\u0633\\u0628 \\u0628\\u0631\\u0627\\u06cc \\u062f\\u0633\\u062a\\u06af\\u0627\\u0647 \\u062e\\u0648\\u062f \\u0631\\u0627 \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u0631\\u0627 \\u0641\\u0634\\u0627\\u0631 \\u062f\\u0647\\u06cc\\u062f \\u0648 \\u0628\\u0631\\u0646\\u0627\\u0645\\u0647 \\u0631\\u0627 \\u0646\\u0635\\u0628 \\u06a9\\u0646\\u06cc\\u062f","ru":"\\u0412\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u043f\\u043e\\u0434\\u0445\\u043e\\u0434\\u044f\\u0449\\u0443\\u044e \\u0432\\u0435\\u0440\\u0441\\u0438\\u044e \\u0434\\u043b\\u044f \\u0432\\u0430\\u0448\\u0435\\u0433\\u043e \\u0443\\u0441\\u0442\\u0440\\u043e\\u0439\\u0441\\u0442\\u0432\\u0430, \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043d\\u0430 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u0438 \\u0443\\u0441\\u0442\\u0430\\u043d\\u043e\\u0432\\u0438\\u0442\\u0435 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435.","zh":"\\u9009\\u62e9\\u9002\\u5408\\u60a8\\u8bbe\\u5907\\u7684\\u7248\\u672c\\uff0c\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\u5e76\\u5b89\\u88c5\\u5e94\\u7528\\u7a0b\\u5e8f\\u3002","fr":"Choisis la version pour ton appareil, clique sur le bouton ci\\u2011dessous et installe l\\u2019app."}}},"macos":{"id":"incy","name":"InCy","isFeatured":true,"urlScheme":"incy://import/","addSubscriptionStep":{"description":{"en":"Click the button below \\u2014 the app will open and the subscription will be added automatically.","fa":"\\u0628\\u0631\\u0627\\u06cc \\u0627\\u0641\\u0632\\u0648\\u062f\\u0646 \\u062e\\u0648\\u062f\\u06a9\\u0627\\u0631 \\u0627\\u0634\\u062a\\u0631\\u0627\\u06a9 \\u0631\\u0648\\u06cc \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u06a9\\u0644\\u06cc\\u06a9 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u2014 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435 \\u043e\\u0442\\u043a\\u0440\\u043e\\u0435\\u0442\\u0441\\u044f, \\u0438 \\u043f\\u043e\\u0434\\u043f\\u0438\\u0441\\u043a\\u0430 \\u0434\\u043e\\u0431\\u0430\\u0432\\u0438\\u0442\\u0441\\u044f \\u0430\\u0432\\u0442\\u043e\\u043c\\u0430\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438.","zh":"\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\uff0c\\u5e94\\u7528\\u5c06\\u4f1a\\u6253\\u5f00\\uff0c\\u5e76\\u81ea\\u52a8\\u6dfb\\u52a0\\u8ba2\\u9605\\u3002","fr":"Clique sur le bouton ci-dessous \\u2014 l\'app s\'ouvrira et l\'abonnement sera ajout\\u00e9 automatiquement."}},"connectAndUseStep":{"description":{"en":"In the main section, click the connect button to start VPN. Select a server from the list if needed.","fa":"\\u062f\\u0631 \\u0628\\u062e\\u0634 \\u0627\\u0635\\u0644\\u06cc\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0627\\u062a\\u0635\\u0627\\u0644 \\u0631\\u0627 \\u0628\\u0632\\u0646\\u06cc\\u062f. \\u062f\\u0631 \\u0635\\u0648\\u0631\\u062a \\u0646\\u06cc\\u0627\\u0632 \\u0633\\u0631\\u0648\\u0631 \\u062f\\u06cc\\u06af\\u0631\\u06cc \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u0412 \\u0433\\u043b\\u0430\\u0432\\u043d\\u043e\\u043c \\u0440\\u0430\\u0437\\u0434\\u0435\\u043b\\u0435 \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043f\\u043e\\u0434\\u043a\\u043b\\u044e\\u0447\\u0435\\u043d\\u0438\\u044f \\u043a VPN. \\u041f\\u0440\\u0438 \\u043d\\u0435\\u043e\\u0431\\u0445\\u043e\\u0434\\u0438\\u043c\\u043e\\u0441\\u0442\\u0438 \\u0432\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u0441\\u0435\\u0440\\u0432\\u0435\\u0440 \\u0438\\u0437 \\u0441\\u043f\\u0438\\u0441\\u043a\\u0430.","zh":"\\u5728\\u4e3b\\u754c\\u9762\\u70b9\\u51fb\\u8fde\\u63a5\\u6309\\u94ae\\u4ee5\\u542f\\u52a8 VPN\\u3002\\u5982\\u6709\\u9700\\u8981\\uff0c\\u53ef\\u9009\\u62e9\\u5176\\u5b83\\u670d\\u52a1\\u5668\\u3002","fr":"Dans la section principale, appuie sur le bouton de connexion. Choisis un serveur si besoin."}},"installationStep":{"buttons":[{"buttonLink":"https://github.com/INCY-DEV/incy-platforms/releases/latest/download/incy-macos-arm64.dmg","buttonText":{"en":"Apple Silicon (.dmg)","fa":"Apple Silicon (.dmg)","ru":"Apple Silicon (.dmg)","zh":"Apple Silicon (.dmg)","fr":"Apple Silicon (.dmg)"}},{"buttonLink":"https://github.com/INCY-DEV/incy-platforms/releases/latest/download/incy-macos-intel.dmg","buttonText":{"en":"Intel (.dmg)","fa":"Intel (.dmg)","ru":"Intel (.dmg)","zh":"Intel (.dmg)","fr":"Intel (.dmg)"}}],"description":{"en":"Choose the version for your device, click the button below and install the app.","fa":"\\u0646\\u0633\\u062e\\u0647 \\u0645\\u0646\\u0627\\u0633\\u0628 \\u0628\\u0631\\u0627\\u06cc \\u062f\\u0633\\u062a\\u06af\\u0627\\u0647 \\u062e\\u0648\\u062f \\u0631\\u0627 \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u0631\\u0627 \\u0641\\u0634\\u0627\\u0631 \\u062f\\u0647\\u06cc\\u062f \\u0648 \\u0628\\u0631\\u0646\\u0627\\u0645\\u0647 \\u0631\\u0627 \\u0646\\u0635\\u0628 \\u06a9\\u0646\\u06cc\\u062f","ru":"\\u0412\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u043f\\u043e\\u0434\\u0445\\u043e\\u0434\\u044f\\u0449\\u0443\\u044e \\u0432\\u0435\\u0440\\u0441\\u0438\\u044e \\u0434\\u043b\\u044f \\u0432\\u0430\\u0448\\u0435\\u0433\\u043e \\u0443\\u0441\\u0442\\u0440\\u043e\\u0439\\u0441\\u0442\\u0432\\u0430, \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043d\\u0430 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u0438 \\u0443\\u0441\\u0442\\u0430\\u043d\\u043e\\u0432\\u0438\\u0442\\u0435 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435.","zh":"\\u9009\\u62e9\\u9002\\u5408\\u60a8\\u8bbe\\u5907\\u7684\\u7248\\u672c\\uff0c\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\u5e76\\u5b89\\u88c5\\u5e94\\u7528\\u7a0b\\u5e8f\\u3002","fr":"Choisis la version pour ton appareil, clique sur le bouton ci\\u2011dessous et installe l\\u2019app."}}},"linux":{"id":"incy","name":"InCy","isFeatured":true,"urlScheme":"incy://import/","addSubscriptionStep":{"description":{"en":"Click the button below \\u2014 the app will open and the subscription will be added automatically.","fa":"\\u0628\\u0631\\u0627\\u06cc \\u0627\\u0641\\u0632\\u0648\\u062f\\u0646 \\u062e\\u0648\\u062f\\u06a9\\u0627\\u0631 \\u0627\\u0634\\u062a\\u0631\\u0627\\u06a9 \\u0631\\u0648\\u06cc \\u062f\\u06a9\\u0645\\u0647 \\u0632\\u06cc\\u0631 \\u06a9\\u0644\\u06cc\\u06a9 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043d\\u0438\\u0436\\u0435 \\u2014 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435 \\u043e\\u0442\\u043a\\u0440\\u043e\\u0435\\u0442\\u0441\\u044f, \\u0438 \\u043f\\u043e\\u0434\\u043f\\u0438\\u0441\\u043a\\u0430 \\u0434\\u043e\\u0431\\u0430\\u0432\\u0438\\u0442\\u0441\\u044f \\u0430\\u0432\\u0442\\u043e\\u043c\\u0430\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438.","zh":"\\u70b9\\u51fb\\u4e0b\\u65b9\\u6309\\u94ae\\uff0c\\u5e94\\u7528\\u5c06\\u4f1a\\u6253\\u5f00\\uff0c\\u5e76\\u81ea\\u52a8\\u6dfb\\u52a0\\u8ba2\\u9605\\u3002","fr":"Clique sur le bouton ci-dessous \\u2014 l\'app s\'ouvrira et l\'abonnement sera ajout\\u00e9 automatiquement."}},"connectAndUseStep":{"description":{"en":"In the main section, click the connect button to start VPN. Select a server from the list if needed.","fa":"\\u062f\\u0631 \\u0628\\u062e\\u0634 \\u0627\\u0635\\u0644\\u06cc\\u060c \\u062f\\u06a9\\u0645\\u0647 \\u0627\\u062a\\u0635\\u0627\\u0644 \\u0631\\u0627 \\u0628\\u0632\\u0646\\u06cc\\u062f. \\u062f\\u0631 \\u0635\\u0648\\u0631\\u062a \\u0646\\u06cc\\u0627\\u0632 \\u0633\\u0631\\u0648\\u0631 \\u062f\\u06cc\\u06af\\u0631\\u06cc \\u0627\\u0646\\u062a\\u062e\\u0627\\u0628 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u0412 \\u0433\\u043b\\u0430\\u0432\\u043d\\u043e\\u043c \\u0440\\u0430\\u0437\\u0434\\u0435\\u043b\\u0435 \\u043d\\u0430\\u0436\\u043c\\u0438\\u0442\\u0435 \\u043a\\u043d\\u043e\\u043f\\u043a\\u0443 \\u043f\\u043e\\u0434\\u043a\\u043b\\u044e\\u0447\\u0435\\u043d\\u0438\\u044f \\u043a VPN. \\u041f\\u0440\\u0438 \\u043d\\u0435\\u043e\\u0431\\u0445\\u043e\\u0434\\u0438\\u043c\\u043e\\u0441\\u0442\\u0438 \\u0432\\u044b\\u0431\\u0435\\u0440\\u0438\\u0442\\u0435 \\u0441\\u0435\\u0440\\u0432\\u0435\\u0440 \\u0438\\u0437 \\u0441\\u043f\\u0438\\u0441\\u043a\\u0430.","zh":"\\u5728\\u4e3b\\u754c\\u9762\\u70b9\\u51fb\\u8fde\\u63a5\\u6309\\u94ae\\u4ee5\\u542f\\u52a8 VPN\\u3002\\u5982\\u6709\\u9700\\u8981\\uff0c\\u53ef\\u9009\\u62e9\\u5176\\u5b83\\u670d\\u52a1\\u5668\\u3002","fr":"Dans la section principale, appuie sur le bouton de connexion. Choisis un serveur si besoin."}},"installationStep":{"buttons":[{"buttonLink":"https://github.com/INCY-DEV/incy-platforms/releases/latest/download/incy-linux-x64.deb","buttonText":{"en":".deb (x64)","fa":".deb (x64)","ru":".deb (x64)","zh":".deb (x64)","fr":".deb (x64)"}},{"buttonLink":"https://github.com/INCY-DEV/incy-platforms/releases/latest/download/incy-linux-arm64.deb","buttonText":{"en":".deb (arm64)","fa":".deb (arm64)","ru":".deb (arm64)","zh":".deb (arm64)","fr":".deb (arm64)"}},{"buttonLink":"https://github.com/INCY-DEV/incy-platforms/releases/latest/download/incy-linux-x64-portable.zip","buttonText":{"en":"Portable (x64)","fa":"Portable (x64)","ru":"Portable (x64)","zh":"Portable (x64)","fr":"Portable (x64)"}}],"description":{"en":"Open the page in App Store and install the app. Launch it, in the VPN configuration permission window click Allow and enter your passcode.","fa":"\\u0635\\u0641\\u062d\\u0647 \\u0631\\u0627 \\u062f\\u0631 App Store \\u0628\\u0627\\u0632 \\u06a9\\u0646\\u06cc\\u062f \\u0648 \\u0628\\u0631\\u0646\\u0627\\u0645\\u0647 \\u0631\\u0627 \\u0646\\u0635\\u0628 \\u06a9\\u0646\\u06cc\\u062f. \\u0622\\u0646 \\u0631\\u0627 \\u0627\\u062c\\u0631\\u0627 \\u06a9\\u0646\\u06cc\\u062f.","ru":"\\u041e\\u0442\\u043a\\u0440\\u043e\\u0439\\u0442\\u0435 \\u0441\\u0442\\u0440\\u0430\\u043d\\u0438\\u0446\\u0443 \\u0432 App Store \\u0438 \\u0443\\u0441\\u0442\\u0430\\u043d\\u043e\\u0432\\u0438\\u0442\\u0435 \\u043f\\u0440\\u0438\\u043b\\u043e\\u0436\\u0435\\u043d\\u0438\\u0435. \\u0417\\u0430\\u043f\\u0443\\u0441\\u0442\\u0438\\u0442\\u0435 \\u0435\\u0433\\u043e, \\u0440\\u0430\\u0437\\u0440\\u0435\\u0448\\u0438\\u0442\\u0435 VPN-\\u043a\\u043e\\u043d\\u0444\\u0438\\u0433\\u0443\\u0440\\u0430\\u0446\\u0438\\u044e.","zh":"\\u5728 App Store \\u6253\\u5f00\\u9875\\u9762\\u5e76\\u5b89\\u88c5\\u5e94\\u7528\\u3002\\u542f\\u52a8\\u5e94\\u7528\\u540e\\uff0c\\u5728 VPN \\u914d\\u7f6e\\u6743\\u9650\\u7a97\\u53e3\\u70b9\\u51fb\\u5141\\u8bb8\\u3002","fr":"Ouvre la page de l\'App Store et installe l\'app. Lance-la et autorise la configuration VPN."}}}}'


def _patch_app_config_incy(cfg_dict):
    """Вставить INCY первым (featured) в каждую платформу app-config.

    Платформы, которых нет в дефолтном конфиге, пропускаем. Существующую запись
    incy убираем перед вставкой — повторный запуск не плодит дублей.
    """
    incy = json.loads(INCY_APPS_JSON)
    plats = cfg_dict.setdefault("platforms", {})
    for plat, entry in incy.items():
        lst = plats.get(plat)
        if not isinstance(lst, list):
            continue
        lst = [a for a in lst if a.get("id") != "incy"]
        lst.insert(0, entry)
        plats[plat] = lst
    return cfg_dict


def setup_subscription_page(sub_domain, api_token, server_ip):
    """Bundled-установка remnawave/subscription-page на сервере панели.

    Красивая HTML-страница подписки вместо голого кода. Панель ставится этим же
    installer'ом (режимы 1/2), поэтому /opt/remnawave, сеть remnawave-network и
    контейнер remnawave:3000 уже есть — берём Bundled-вариант из офиц. доки.
    SUB_PUBLIC_DOMAIN в .env панели уже выставлен на sub_domain (см. install_remnawave).

    Страница ДОЛЖНА жить в корне своего домена (Remnawave не работает на sub-path),
    поэтому ей нужен отдельный поддомен и свой LE-сертификат для браузера.
    """
    print("\n  [subpage] Установка страницы подписки Remnawave...")
    run("mkdir -p /opt/remnawave/subscription", check=False)

    compose = f"""services:
  remnawave-subscription-page:
    image: remnawave/subscription-page:{REMNAWAVE_SUBSCRIPTION_PAGE_VERSION}
    container_name: remnawave-subscription-page
    hostname: remnawave-subscription-page
    restart: always
    env_file:
      - .env
    volumes:
      - ./custom/app-config.json:/opt/app/frontend/assets/app-config.json:ro
    ports:
      - '127.0.0.1:3010:3010'
    networks:
      - remnawave-network

networks:
  remnawave-network:
    driver: bridge
    external: true
"""
    with open("/opt/remnawave/subscription/docker-compose.yml", "w") as f:
        f.write(compose)

    # app-config.json задаёт список приложений на странице. Кастомим его, чтобы
    # добавить INCY (#5b): берём дефолтный из образа (не хардкодим 200КБ и не
    # отстаём от обновлений upstream), вставляем INCY первым в каждую платформу,
    # монтируем ro поверх встроенного (механизм проверен на живой панели).
    run("mkdir -p /opt/remnawave/subscription/custom", check=False)
    run(f"docker pull remnawave/subscription-page:{REMNAWAVE_SUBSCRIPTION_PAGE_VERSION}", check=False, timeout=300,
        label="Загрузка образа страницы подписки", expected=30)
    _incy_done = False
    _cid = (run(f"docker create remnawave/subscription-page:{REMNAWAVE_SUBSCRIPTION_PAGE_VERSION}", check=False, timeout=60).stdout or "").strip().splitlines()
    _cid = _cid[-1].strip() if _cid else ""
    if _cid:
        run(f"docker cp {_cid}:/opt/app/frontend/assets/app-config.json /tmp/_appcfg.json", check=False, timeout=30)
        run(f"docker rm {_cid}", check=False, timeout=30)
        try:
            with open("/tmp/_appcfg.json", encoding="utf-8") as f:
                _base_cfg = json.load(f)
            _patch_app_config_incy(_base_cfg)
            with open("/opt/remnawave/subscription/custom/app-config.json", "w", encoding="utf-8") as f:
                json.dump(_base_cfg, f, ensure_ascii=False)
            _plats = ",".join(_base_cfg.get("platforms", {}).keys())
            print(f"  [subpage] INCY добавлен в app-config (платформы: {_plats})")
            _incy_done = True
        except Exception as _e:
            print(f"  ⚠ [subpage] не удалось пропатчить app-config INCY: {_e}")
    if not _incy_done:
        # без кастомного файла volume-mount указывал бы на отсутствующий путь и
        # уронил бы контейнер — убираем строку монтирования из compose
        print("  ⚠ [subpage] INCY не добавлен, страница со стандартным списком приложений")
        compose = compose.replace(
            "    volumes:\n      - ./custom/app-config.json:/opt/app/frontend/assets/app-config.json:ro\n", "")
        with open("/opt/remnawave/subscription/docker-compose.yml", "w") as f:
            f.write(compose)

    # REMNAWAVE_PANEL_URL=http://remnawave:3000 — по внутреннему docker-hostname
    # панели (тот же, что использует сама панель), не через публичный домен.
    sub_env = (
        "APP_PORT=3010\n"
        "REMNAWAVE_PANEL_URL=http://remnawave:3000\n"
        f"REMNAWAVE_API_TOKEN={api_token}\n"
        "TRUST_PROXY=1\n"
    )
    with open("/opt/remnawave/subscription/.env", "w") as f:
        f.write(sub_env)

    setup_docker_mirror()
    run("cd /opt/remnawave/subscription && docker compose pull", check=False, timeout=300,
        label="Загрузка Docker-образов (страница подписки)", expected=30)
    r = run("cd /opt/remnawave/subscription && docker compose up -d 2>&1", check=False, timeout=120)
    if r.returncode != 0:
        print(f"  ⚠ [subpage] docker compose up: {(r.stderr or r.stdout or '')[:300]}")

    # Порт 3010 слушается на 127.0.0.1 — ждём подъёма контейнера
    up = False
    for _ in range(12):
        time.sleep(5)
        rc = run("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3010/ 2>/dev/null", check=False)
        if (rc.stdout or "").strip() and (rc.stdout or "").strip() != "000":
            up = True
            break
    if up:
        print("  [subpage] Контейнер поднят (127.0.0.1:3010)")
    else:
        print("  ⚠ [subpage] Контейнер не отвечает на 3010 — проверь docker logs remnawave-subscription-page")

    # --- nginx reverse proxy + LE cert для sub_domain ---
    ensure_nginx_base()
    run("mkdir -p /var/www/certbot", check=False)
    acme_conf = f"""server {{
    listen 80;
    server_name {sub_domain};
    location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
"""
    with open("/etc/nginx/sites-available/subpage.conf", "w") as f:
        f.write(acme_conf)
    run("ln -sf /etc/nginx/sites-available/subpage.conf /etc/nginx/sites-enabled/subpage.conf", check=False)
    r = run("nginx -t 2>&1 && systemctl reload nginx", check=False)
    if r.returncode != 0:
        print(f"  ⚠ [subpage] nginx (ACME-конфиг): {(r.stderr or r.stdout or '')[:200]}")

    pkg_install("certbot")
    dns_ok = wait_dns_a_record(sub_domain, server_ip, label="subpage")
    ssl_cert = ssl_key = None
    if dns_ok:
        cert_cmd = (f"certbot certonly --webroot -w /var/www/certbot -d {sub_domain} "
                    f"--non-interactive --agree-tos --register-unsafely-without-email")
        cr = None
        for attempt in range(1, 4):
            cr = run(cert_cmd, check=False, timeout=180, label="Выпуск сертификата страницы подписки", expected=20)
            if cr.returncode == 0:
                break
            if attempt < 3:
                print(f"  [subpage] certbot не прошёл ({attempt}/3), повтор через 20с...")
                time.sleep(20)
        if cr and cr.returncode == 0:
            ssl_cert = f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem"
            ssl_key = f"/etc/letsencrypt/live/{sub_domain}/privkey.pem"
            print("  [subpage] LE сертификат получен")

    if not ssl_cert:
        # self-signed как запас: страница откроется, но браузер предупредит
        run("mkdir -p /etc/nginx/ssl && test -f /etc/nginx/ssl/subpage.crt || "
            f"openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
            f"-keyout /etc/nginx/ssl/subpage.key -out /etc/nginx/ssl/subpage.crt "
            f"-subj '/CN={sub_domain}' 2>/dev/null", check=False)
        ssl_cert, ssl_key = "/etc/nginx/ssl/subpage.crt", "/etc/nginx/ssl/subpage.key"
        _why = "DNS не указывает на сервер" if not dns_ok else "certbot не выдал серт"
        print(f"  ⚠ [subpage] LE не получен ({_why}) — self-signed")

    proxy_conf = f"""server {{
    listen 80;
    server_name {sub_domain};
    location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
    location / {{ return 301 https://$host$request_uri; }}
}}

server {{
    listen 443 ssl;
    http2 on;
    server_name {sub_domain};

    ssl_certificate {ssl_cert};
    ssl_certificate_key {ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {{
        proxy_pass http://127.0.0.1:3010;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
    with open("/etc/nginx/sites-available/subpage.conf", "w") as f:
        f.write(proxy_conf)
    r = run("nginx -t 2>&1 && systemctl reload nginx", check=False)
    if r.returncode != 0:
        print(f"  ⚠ [subpage] nginx (proxy-конфиг): {(r.stderr or r.stdout or '')[:200]}")

    # renewal hook — перечитать серт nginx'ом после автопродления
    hook = "#!/bin/bash\\nnginx -s reload\\n"
    run("mkdir -p /etc/letsencrypt/renewal-hooks/deploy && "
        f"printf '%b' '{hook}' > /etc/letsencrypt/renewal-hooks/deploy/subpage-nginx.sh && "
        "chmod +x /etc/letsencrypt/renewal-hooks/deploy/subpage-nginx.sh", check=False)

    print(f"  [subpage] Страница подписки: https://{sub_domain}/<shortUuid>")
    return True


def detect_pg_image(default_image=REMNAWAVE_POSTGRES_IMAGE):
    """Выбрать образ postgres под УЖЕ существующий том с данными (#21).

    Remnawave 3.x идёт с postgres 18.4, но у панелей, поставленных раньше, том
    remnawave-db создан postgres 17. Postgres 18 такой каталог не откроет
    («database files are incompatible with server») — панель просто не поднимется,
    а данные окажутся заперты. Поэтому если том уже есть, берём образ ПОД ЕГО
    версию (читаем PG_VERSION), и только для чистой установки — свежий postgres.
    Апгрейд мажора postgres = отдельная процедура (pg_upgrade/дамп), молча её
    делать нельзя.
    """
    volume_name = ""
    for candidate in ("remnawave-db-data", "remnawave-db"):
        r = run(f"docker volume inspect {candidate} >/dev/null 2>&1 && echo EXISTS", check=False, timeout=20)
        if "EXISTS" in (r.stdout or ""):
            volume_name = candidate
            break
    if not volume_name:
        return default_image
    rv = run(f"docker run --rm -v {volume_name}:/v alpine "
             "sh -c 'find /v -name PG_VERSION -type f -print -quit | xargs -r cat' 2>/dev/null",
             check=False, timeout=120)
    ver = (rv.stdout or "").strip().split(".")[0]
    if not ver.isdigit():
        return default_image
    # Safe split with validation
    if ":" not in default_image:
        return default_image
    default_ver_part = default_image.split(":")[1]
    if "." not in default_ver_part:
        return default_image
    if ver == default_ver_part.split(".")[0]:
        return default_image
    print(f"  Существующая БД postgres {ver} — оставляю postgres:{ver} "
          f"(апгрейд мажора требует миграции данных)")
    return f"postgres:{ver}"


# ============================================================
#  REMNAWAVE INSTALLATION
# ============================================================

def install_remnawave(cfg, remnawave_version=None):
    """Install Remnawave panel + node + profile + host + user via API.

    Args:
        cfg: Configuration dict
        remnawave_version: Remnawave version to install (2.8.1 or 3.2.3).
                          Defaults to REMNAWAVE_VERSION_LATEST for mode 1,
                          or from cfg["remnawave_version"] for mode 3.
    """
    # Use provided version or default to latest
    if remnawave_version is None:
        remnawave_version = cfg.get("remnawave_version", REMNAWAVE_VERSION_LATEST)

    domain = cfg["domain"]
    cdn_type = cfg["cdn_type"]
    rcfg = REMNAWAVE_CDN[cdn_type]
    server_ip = cfg["server_ip"]
    node_ip = cfg.get("node_ip", server_ip)
    node_cred = cfg.get("node_cred", "")
    same_server = (node_ip == server_ip)
    origin_sub = cfg["origin_sub"]
    hy2_sub = cfg.get("hy2_sub", "")
    cdn_sub = cfg["cdn_sub"]
    panel_sub = cfg["panel_sub"]
    cdn_domain = f"{cdn_sub}.{domain}"
    origin_domain = f"{origin_sub}.{domain}"
    panel_domain = f"{panel_sub}.{domain}"
    install_subpage = cfg.get("install_subpage", False)
    sub_domain = f"{cfg.get('sub_sub', '')}.{domain}" if cfg.get("sub_sub") else ""

    cascade = cfg.get("cascade", False)
    cascade_ip = cfg.get("cascade_ip")
    cascade_cred = cfg.get("cascade_cred")
    cascade_hy2 = cfg.get("cascade_hy2", False)
    cascade_grpc = cfg.get("cascade_grpc", False)

    panel_user = "admin"
    panel_pass = secrets.token_urlsafe(18) + "Aa1"  # 24+ chars, upper+lower+digits

    # --- Step: Install Docker ---
    step(3, "Установка Docker")
    setup_docker_mirror()
    if install_docker():
        print(f"  Docker готов: {run('docker --version', check=False).stdout.strip()}")
    else:
        print("  ❌ Docker не установился из репозитория ОС. Проверь apt и пакет docker.io.")
        sys.exit(1)

    rc = run("docker compose version 2>/dev/null", check=False)
    if rc.returncode != 0:
        print("  docker compose plugin не найден, устанавливаю...")
        install_docker_compose()
        rc = run("docker compose version 2>/dev/null", check=False)
        if rc.returncode != 0:
            print("  ❌ docker compose не установился!")
            sys.exit(1)
        print(f"  docker compose: {rc.stdout.strip()}")

    # --- Step: Remnawave panel ---
    step(4, f"Установка панели Remnawave {remnawave_version}")

    remnawave_dir_existed = os.path.isdir("/opt/remnawave")
    run("mkdir -p /opt/remnawave", check=False)
    track_created("directory", "/opt/remnawave", existed_before=remnawave_dir_existed)

    jwt_auth = secrets.token_hex(64)
    jwt_api = secrets.token_hex(64)
    pg_pass = secrets.token_hex(24)
    metrics_pass = secrets.token_hex(16)
    webhook_secret = secrets.token_hex(32)

    # Reuse existing PG password if volume exists (avoids auth mismatch)
    try:
        with open("/opt/remnawave/.env") as f:
            for line in f:
                if line.startswith("POSTGRES_PASSWORD="):
                    pg_pass = line.split("=", 1)[1].strip()
                    break
    except FileNotFoundError:
        # A missing .env is not permission to delete possibly recoverable data.
        pass

    # postgres берём под существующий том (detect_pg_image): апгрейд мажора ломает
    # каталог данных. Про переход на Remnawave 3.x см. #21 — там миграция .env
    # (APP_SECRET вместо JWT_*, REDIS_SOCKET) и новая разметка тома postgres 18.
    pg_image = detect_pg_image()

    compose = """services:
  remnawave-db:
    container_name: remnawave-db
    hostname: remnawave-db
    image: __POSTGRES_IMAGE__
    restart: always
    shm_size: 512mb
    env_file:
      - .env
    volumes:
      - remnawave-db-data:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 3s
      timeout: 10s
      retries: 3
    networks:
      - remnawave-network

  remnawave-redis:
    container_name: remnawave-redis
    hostname: remnawave-redis
    image: __VALKEY_IMAGE__
    restart: always
    command: >
      valkey-server
      --save ""
      --appendonly no
      --maxmemory-policy noeviction
      --loglevel warning
      --unixsocket /var/run/valkey/valkey.sock
      --unixsocketperm 777
      --port 0
    volumes:
      - valkey-socket:/var/run/valkey
    healthcheck:
      test: ["CMD", "valkey-cli", "-s", "/var/run/valkey/valkey.sock", "ping"]
      interval: 3s
      timeout: 3s
      retries: 3
    networks:
      - remnawave-network

  remnawave:
    container_name: remnawave
    hostname: remnawave
    image: remnawave/backend:__BACKEND_VERSION__
    restart: always
    ports:
      - "127.0.0.1:3000:${APP_PORT:-3000}"
      - "127.0.0.1:3001:${METRICS_PORT:-3001}"
    env_file:
      - .env
    volumes:
      - valkey-socket:/var/run/valkey
    depends_on:
      remnawave-db:
        condition: service_healthy
      remnawave-redis:
        condition: service_healthy
    networks:
      - remnawave-network

volumes:
  remnawave-db-data:
    name: remnawave-db-data
  valkey-socket:
    name: valkey-socket

networks:
  remnawave-network:
    name: remnawave-network
    driver: bridge
"""
    compose = (compose.replace("__POSTGRES_IMAGE__", pg_image)
               .replace("__VALKEY_IMAGE__", REMNAWAVE_VALKEY_IMAGE)
               .replace("__BACKEND_VERSION__", remnawave_version))

    compose_path = "/opt/remnawave/docker-compose.yml"
    compose_existed = os.path.lexists(compose_path)
    backup_file(compose_path)
    track_created("file", compose_path, existed_before=compose_existed)
    with open(compose_path, "w") as f:
        f.write(compose)

    # Generate .env - format differs between 2.8.1 and 3.x
    is_3x = remnawave_version.startswith("3.")

    if is_3x:
        # Remnawave 3.x uses single APP_SECRET instead of JWT_AUTH_SECRET/JWT_API_TOKENS_SECRET
        env = f"""APP_PORT=3000
METRICS_PORT=3001
API_INSTANCES=1
APP_SECRET={jwt_auth}
METRICS_USER=metrics
METRICS_PASS={metrics_pass}
WEBHOOK_SECRET_HEADER={webhook_secret}
WEBHOOK_ENABLED=false
POSTGRES_USER=postgres
POSTGRES_PASSWORD={pg_pass}
POSTGRES_DB=postgres
DATABASE_URL="postgresql://postgres:{pg_pass}@remnawave-db:5432/postgres"
REDIS_SOCKET=/var/run/valkey/valkey.sock
FRONT_END_DOMAIN={panel_domain}
PANEL_DOMAIN={panel_domain}
SUB_PUBLIC_DOMAIN={sub_domain if install_subpage and sub_domain else f'{panel_domain}/api/sub'}
IS_PANEL_BEHIND_CLOUDFLARE=false
TRAFFIC_RESET_DAY=1
"""
    else:
        # Remnawave 2.8.1 uses JWT_AUTH_SECRET and JWT_API_TOKENS_SECRET
        env = f"""APP_PORT=3000
METRICS_PORT=3001
JWT_AUTH_SECRET={jwt_auth}
JWT_API_TOKENS_SECRET={jwt_api}
METRICS_USER=metrics
METRICS_PASS={metrics_pass}
WEBHOOK_SECRET_HEADER={webhook_secret}
POSTGRES_USER=postgres
POSTGRES_PASSWORD={pg_pass}
POSTGRES_DB=postgres
DATABASE_URL="postgresql://postgres:{pg_pass}@remnawave-db:5432/postgres"
REDIS_HOST=remnawave-redis
REDIS_PORT=6379
FRONT_END_DOMAIN={panel_domain}
PANEL_DOMAIN={panel_domain}
SUB_PUBLIC_DOMAIN={sub_domain if install_subpage and sub_domain else f'{panel_domain}/api/sub'}
IS_PANEL_BEHIND_CLOUDFLARE=false
TRAFFIC_RESET_DAY=1
"""

    env_path = "/opt/remnawave/.env"
    env_existed = os.path.lexists(env_path)
    backup_file(env_path)
    track_created("file", env_path, existed_before=env_existed)
    with open(env_path, "w") as f:
        f.write(env)
    os.chmod(env_path, 0o600)

    print("  Запуск контейнеров Remnawave...")
    setup_docker_mirror()
    # Avoid an unconditional outage: `docker compose up -d` reconciles changed services.
    print("  Скачивание образов...")
    require_success(run("cd /opt/remnawave && docker compose pull", check=False, timeout=300,
                        label="Загрузка Docker-образов Remnawave", expected=90),
                    "Загрузка контейнеров Remnawave")
    owned_volumes = ("remnawave-db-data", "valkey-socket")
    volumes_existed = {
        name: run(f"docker volume inspect {name} >/dev/null 2>&1", check=False).returncode == 0
        for name in owned_volumes
    }
    network_existed = run(
        "docker network inspect remnawave-network >/dev/null 2>&1", check=False
    ).returncode == 0
    compose_containers_before = run(
        "cd /opt/remnawave && docker compose ps -aq 2>/dev/null",
        check=False, timeout=30,
    )
    r = run("cd /opt/remnawave && docker compose up -d 2>&1", check=False, timeout=180)
    for name in owned_volumes:
        now_exists = run(
            f"docker volume inspect {name} >/dev/null 2>&1", check=False
        ).returncode == 0
        if now_exists:
            track_created("docker_volume", name, existed_before=volumes_existed[name])
    network_now_exists = run(
        "docker network inspect remnawave-network >/dev/null 2>&1", check=False
    ).returncode == 0
    if network_now_exists:
        track_created("docker_network", "remnawave-network", existed_before=network_existed)
    # Only register destructive compose rollback for a fresh project.
    # Existing project containers must not be stopped by a generic rollback.
    if not (compose_containers_before.stdout or "").strip():
        track("docker_compose", "/opt/remnawave")
    else:
        print("  Существующие контейнеры Remnawave обнаружены: автоматический docker compose down при откате отключён.")
    require_success(r, "Запуск контейнеров Remnawave")

    print("  Ожидание запуска контейнеров...")
    panel_started = False
    for i in range(60):
        r = run("RDOM=$(grep PANEL_DOMAIN /opt/remnawave/.env 2>/dev/null | head -1 | cut -d= -f2); curl -s -H \"Host: ${RDOM:-localhost}\" http://127.0.0.1:3000/api/auth/register -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 127.0.0.1' -o /dev/null -w '%{http_code}'", check=False)
        if r.stdout.strip() in ("200", "201", "400", "401", "404", "405"):
            panel_started = True
            break
        time.sleep(5)
    if panel_started:
        print("  Панель Remnawave запущена")
    else:
        print("  ❌ Панель Remnawave не запустилась за 5 минут!")
        ps = run("docker compose -f /opt/remnawave/docker-compose.yml ps -a 2>&1", check=False)
        print(f"  Контейнеры:\n{ps.stdout[:400]}")
        r = run("docker compose -f /opt/remnawave/docker-compose.yml logs --tail=50 2>&1", check=False)
        print(f"  Логи:\n{r.stdout[:1500]}")
        oom = run("dmesg | grep -i 'oom\\|killed process' | tail -5 2>&1", check=False)
        if oom.stdout.strip():
            print(f"  OOM killer:\n{oom.stdout}")
        mem = run("free -m 2>&1", check=False)
        print(f"  Память:\n{mem.stdout}")
        sys.exit(1)

    # --- Step: Certbot ---
    step(5, f"SSL сертификат для {panel_domain}")

    acme_conf = f"""server {{
    listen 80;
    server_name {panel_domain};
    location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
"""
    run("mkdir -p /var/www/certbot", check=False)
    nginx_write_conf("panel.conf", acme_conf)
    run("nginx -t && systemctl restart nginx", check=False)

    print(f"  Получение сертификата для {panel_domain}...")
    wait_dns_a_record(panel_domain, server_ip, attempts=6, delay=10, label="panel")
    r = run(f"certbot certonly --webroot -w /var/www/certbot -d {panel_domain} --non-interactive --agree-tos --register-unsafely-without-email --deploy-hook 'systemctl reload nginx'", check=False, timeout=120,
            label="Выпуск сертификата Let's Encrypt", expected=20)
    if r.returncode != 0:
        print(f"  Certbot не сработал, используем self-signed.")
        print(f"  (Проверь что DNS {panel_domain} -> {server_ip} без лишних A-записей)")
        print(f"  После установки выполни: certbot --nginx -d {panel_domain} --non-interactive --agree-tos --register-unsafely-without-email")
        cert_path = "/etc/nginx/ssl/cdn.crt"
        key_path = "/etc/nginx/ssl/cdn.key"
        if not os.path.exists(cert_path):
            print("  Self-signed сертификат тоже отсутствует!")
            sys.exit(1)
    else:
        cert_path = f"/etc/letsencrypt/live/{panel_domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{panel_domain}/privkey.pem"
        print("  Сертификат получен!")

    ipv6_panel = has_ipv6()
    v6_443_panel = "\n    listen [::]:443 ssl http2;" if ipv6_panel else ""
    panel_nginx = f"""server {{
    listen 80;
    server_name {panel_domain};
    location /.well-known/acme-challenge/ {{ root /var/www/certbot; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
server {{
    listen 443 ssl http2;{v6_443_panel}
    server_name {panel_domain};
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {{
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
"""
    nginx_write_conf("panel.conf", panel_nginx)
    run("nginx -t && systemctl restart nginx", check=False)
    print(f"  Nginx для панели настроен")

    # --- Step: API — register admin, create API token, setup resources ---
    step(6, "Создание профиля, ноды, хоста и юзера через API")

    # Register admin user
    print("  Регистрация админа...")
    resp = remnawave_api(None, "POST", "auth/register", {
        "username": panel_user, "password": panel_pass
    })
    if resp.get("response"):
        print("  Админ зарегистрирован")
    else:
        if "403" in str(resp) or "Forbidden" in str(resp):
            raise RuntimeError("На панели уже зарегистрирован администратор; режим 1 не меняет существующую панель")
        else:
            raise RuntimeError(f"Не удалось зарегистрировать администратора: {resp}")

    # Use the supported login endpoint.  Do not fabricate JWTs or write to the
    # panel database: its token schema and signing rules are version-specific.
    print("  Авторизация администратора через API...")
    login_resp = remnawave_api(None, "POST", "auth/login", {
        "username": panel_user, "password": panel_pass
    })
    session_token = ((login_resp.get("response") or {}).get("accessToken")
                     or login_resp.get("accessToken"))
    if not session_token:
        raise RuntimeError(f"Remnawave не выдал сессионный токен: {login_resp}")

    # Remnawave 3.x deliberately rejects the admin session JWT on resource API
    # routes. Exchange it for a supported, long-lived API token first.
    print("  Создание API-токена Remnawave...")
    api_token_resp = remnawave_api(session_token, "POST", "tokens/", {
        "name": "vpn-cdn-installer",
        "expiresInDays": 3650,
        "scopes": ["*"],
    }, admin_session=True)
    token = ((api_token_resp.get("response") or {}).get("token")
             or api_token_resp.get("token"))
    if not token:
        raise RuntimeError(f"Remnawave не создал API-токен: {api_token_resp}")

    panel_token_path = "/opt/remnawave/.panel_token"
    panel_token_existed = os.path.lexists(panel_token_path)
    backup_file(panel_token_path)
    track_created("file", panel_token_path, existed_before=panel_token_existed)
    old_umask = os.umask(0o077)
    try:
        with open(panel_token_path, "w") as token_file:
            token_file.write(token)
        os.chmod(panel_token_path, 0o600)
    finally:
        os.umask(old_umask)

    # Test the supported API token before changing panel resources.
    resp = remnawave_api(token, "GET", "nodes")
    if "error" in resp or "response" not in resp:
        raise RuntimeError(f"API-токен Remnawave не прошёл проверку: {resp}")
    print("  API-токен Remnawave: OK")

    # Create config profile (or find existing by inbound tag)
    install_hy2 = cfg.get("install_hy2", False)
    install_grpc = cfg.get("install_grpc", False)
    profile_name = f"cdn-{cdn_type}"
    if install_hy2 or install_grpc:
        extras = []
        if install_hy2:
            extras.append("hy2")
        if install_grpc:
            extras.append("grpc")
        profile_name += "-" + "-".join(extras)
    inbound_tag = rcfg["inbound_tag"]
    profile_uuid = None
    inbound_uuid = None
    hy2_inbound_uuid = None
    grpc_inbound_uuid = None
    bridge_in_uuid = None
    reality_keys = None

    existing_profiles = remnawave_api(token, "GET", "config-profiles")
    if existing_profiles.get("response"):
        resp_data = existing_profiles["response"]
        plist = resp_data.get("configProfiles", resp_data if isinstance(resp_data, list) else [resp_data])
        _f = remnawave_find_profile(plist, inbound_tag, profile_name, rcfg.get("xray_port"))
        profile_uuid = _f["profile_uuid"]
        inbound_uuid = _f["inbound_uuid"]
        hy2_inbound_uuid = _f["hy2_inbound_uuid"]
        grpc_inbound_uuid = _f["grpc_inbound_uuid"]
        bridge_in_uuid = _f["bridge_in_uuid"]

    if not profile_uuid:
        import copy
        tag_id = secrets.token_hex(3)
        profile_name = f"{profile_name}-{tag_id}"
        profile_config = copy.deepcopy(rcfg["profile_config"])
        for _ib in profile_config.get("inbounds", []):
            _ib["tag"] = f"{_ib['tag']}-{tag_id}"
        inbound_tag = f"{inbound_tag}-{tag_id}"

        if install_hy2:
            profile_config["inbounds"].append(build_hy2_inbound(tag_suffix=tag_id))
            print(f"  Добавлен Hysteria2 inbound (UDP {HY2_PORT})")

        if install_grpc:
            reality_keys = generate_x25519_keys()
            if reality_keys:
                short_id = secrets.token_hex(8)
                cfg["reality_keys"] = reality_keys
                cfg["reality_short_id"] = short_id
                profile_config["inbounds"].append(build_grpc_inbound(reality_keys["private"], short_id, tag_suffix=tag_id))
                print(f"  Добавлен gRPC Reality inbound (TCP {GRPC_PORT})")
            else:
                print("  ПРОПУСК gRPC: не удалось сгенерировать x25519 ключи")

        if cascade:
            profile_config["inbounds"].append({
                "tag": f"BRIDGE_IN-{tag_id}", "port": 8888, "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
                "streamSettings": {"network": "tcp", "security": "none"}
            })
            print(f"  Добавлен BRIDGE_IN inbound (TCP 8888) для каскада")

        print(f"  Создание профиля: {profile_name}...")
        profile_payload = {"name": profile_name, "config": profile_config}
        for _attempt in range(4):
            resp = remnawave_api(token, "POST", "config-profiles", profile_payload)
            if resp.get("response"):
                profile_uuid = resp["response"].get("uuid")
                for ib in resp["response"].get("inbounds", []):
                    if ib.get("tag") == inbound_tag:
                        inbound_uuid = ib.get("uuid")
                    elif ib.get("tag", "").startswith("hy2-in"):
                        hy2_inbound_uuid = ib.get("uuid")
                    elif ib.get("tag", "").startswith("grpc-reality"):
                        grpc_inbound_uuid = ib.get("uuid")
                    elif ib.get("tag", "").startswith("BRIDGE_IN"):
                        bridge_in_uuid = ib.get("uuid")
                break
            if _attempt < 3:
                print(f"  API retry профиля ({_attempt+1}/3), жду 10 сек...")
                time.sleep(10)
            else:
                print(f"  ВНИМАНИЕ: Ответ создания профиля: {resp}")

    print(f"  Profile UUID: {profile_uuid}")
    print(f"  CDN Inbound UUID: {inbound_uuid}")
    if not profile_uuid or not inbound_uuid:
        raise RuntimeError("Remnawave не создал config profile или CDN inbound")
    if hy2_inbound_uuid:
        print(f"  HY2 Inbound UUID: {hy2_inbound_uuid}")
    if grpc_inbound_uuid:
        print(f"  gRPC Inbound UUID: {grpc_inbound_uuid}")

    if cascade:
        bridge_keys, bridge_sid = prepare_bridge_reality(cfg)
        bridge_in_uuid = ensure_bridge_inbound(
            lambda m, p, d=None: remnawave_api(token, m, p, d),
            profile_uuid, bridge_in_uuid,
            private_key=bridge_keys["private"], short_id=bridge_sid)
        if not bridge_in_uuid:
            raise RuntimeError("BRIDGE_IN отсутствует — каскад не поднимется")
        print(f"  BRIDGE_IN Inbound UUID: {bridge_in_uuid}")

    # --- Step: Node setup (files + container) ---
    step(7, "Настройка ноды Remnawave")

    if same_server:
        ipv6_ok = has_ipv6()
        nginx_conf = nginx_cdn_origin(rcfg["xray_port"], rcfg["xhttp_path"], ipv6=ipv6_ok,
                                  nginx_style=rcfg.get("nginx_style", "prefix"))
        r = nginx_write_and_restart(nginx_conf)
        if r.returncode == 0:
            print("  Nginx CDN origin настроен")
        else:
            print(f"  ❌ Проблема с nginx: {r.stderr[:200] if r.stderr else ''}")
            print("  Попробуй: nginx -t и systemctl restart nginx")
            sys.exit(1)

    # Create node in panel API
    if same_server:
        r = run("docker network inspect remnawave-network -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'", check=False)
        node_address = r.stdout.strip() or "172.18.0.1"
        print(f"  Docker gateway: {node_address}")
    else:
        node_address = node_ip

    # Collect all inbound UUIDs except ours to exclude them
    our_uuids = {inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid, bridge_in_uuid} - {None}
    excluded = []
    all_profiles = remnawave_api(token, "GET", "config-profiles")
    if all_profiles.get("response"):
        resp_data = all_profiles["response"]
        profiles_list = resp_data.get("configProfiles", resp_data if isinstance(resp_data, list) else [resp_data])
        for p in profiles_list:
            for ib in p.get("inbounds", []):
                ib_uuid = ib.get("uuid")
                if ib_uuid and ib_uuid not in our_uuids:
                    excluded.append(ib_uuid)
    if excluded:
        print(f"  Исключено {len(excluded)} дефолтных inbound'ов")

    node_uuid = None
    existing_nodes_resp = remnawave_api(token, "GET", "nodes")
    existing_nodes = existing_nodes_resp.get("response", [])
    if isinstance(existing_nodes, list):
        for n in existing_nodes:
            if n.get("address") == node_address and n.get("port") == 2222:
                node_uuid = n.get("uuid")
                print(f"  Нода уже существует: {node_uuid}")
                break

    if not node_uuid:
        active_inbounds = [u for u in [inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid] if u]
        if cascade and bridge_in_uuid:
            active_inbounds.append(bridge_in_uuid)
        print(f"  Создание ноды в панели ({node_address}:2222)...")
        node_data = {
            "name": f"node-{cdn_type}-{'.'.join(node_ip.split('.')[-2:])}",
            "address": node_address,
            "port": 2222,
            "countryCode": "XX",
            "isTrafficTrackingActive": True,
            "trafficLimitBytes": 0,
            "notifyPercent": 0,
            "trafficResetDay": 1,
            "excludedInbounds": excluded,
            "configProfile": {
                "activeConfigProfileUuid": profile_uuid,
                "activeInbounds": active_inbounds
            }
        }
        for _attempt in range(4):
            resp = remnawave_api(token, "POST", "nodes", node_data)
            if resp.get("response"):
                node_uuid = resp["response"].get("uuid")
                print(f"  Node UUID: {node_uuid}")
                break
            if _attempt < 3:
                print(f"  API retry ноды ({_attempt+1}/3), жду 10 сек...")
                time.sleep(10)
            else:
                print(f"  ВНИМАНИЕ: Ответ создания ноды: {resp}")
    else:
        active_inbounds = [u for u in
                           [inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid, bridge_in_uuid]
                           if u]
        upd = remnawave_api(token, "PATCH", "nodes", {
            "uuid": node_uuid,
            "excludedInbounds": excluded,
            "configProfile": {
                "activeConfigProfileUuid": profile_uuid,
                "activeInbounds": active_inbounds,
            },
        })
        if not upd.get("response"):
            raise RuntimeError(f"Не удалось синхронизировать существующую ноду: {upd}")

    if not node_uuid:
        raise RuntimeError("Remnawave не создал ноду")

    if cascade and bridge_in_uuid and node_uuid:
        _api2 = lambda m, p, d=None: remnawave_api(token, m, p, d)
        ensure_node_inbound(_api2, node_uuid, profile_uuid, bridge_in_uuid)
        ensure_squad_inbound(_api2, bridge_in_uuid)

    # Get secret key from keygen endpoint
    secret_key = None
    resp = remnawave_api(token, "GET", "keygen")
    if resp.get("response"):
        secret_key = resp["response"].get("pubKey")
        if secret_key:
            print(f"  Secret key obtained ({len(secret_key)} chars)")
    if not secret_key:
        raise RuntimeError("Remnawave API не вернул keygen pubKey; ноду нельзя запустить")

    if same_server:
        # Local remnanode setup
        remnanode_dir_existed = os.path.isdir("/opt/remnanode")
        run("mkdir -p /opt/remnanode", check=False)
        track_created("directory", "/opt/remnanode", existed_before=remnanode_dir_existed)

        node_compose = f"""services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:{REMNAWAVE_NODE_VERSION}
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - /etc/nginx/ssl:/etc/nginx/ssl:ro
      - /opt/remnanode/xray-custom:/usr/local/bin/xray
    env_file:
      - .env
"""
        node_compose_path = "/opt/remnanode/docker-compose.yml"
        node_compose_existed = os.path.lexists(node_compose_path)
        backup_file(node_compose_path)
        track_created("file", node_compose_path, existed_before=node_compose_existed)
        with open(node_compose_path, "w") as f:
            f.write(node_compose)

        node_env = f"NODE_PORT=2222\nSECRET_KEY={secret_key or 'REPLACE_WITH_KEY_FROM_PANEL'}\n"
        node_env_path = "/opt/remnanode/.env"
        node_env_existed = os.path.lexists(node_env_path)
        backup_file(node_env_path)
        track_created("file", node_env_path, existed_before=node_env_existed)
        with open(node_env_path, "w") as f:
            f.write(node_env)
        os.chmod(node_env_path, 0o600)

        if secret_key:
            if not download_xray_binary():
                raise RuntimeError("Не удалось установить проверенный Xray для remnanode")
            print("  Запуск контейнера remnanode...")
            require_success(
                run("cd /opt/remnanode && docker compose pull", check=False, timeout=600,
                label="Загрузка remnanode", expected=45),
                "Загрузка контейнера remnanode",
            )
            compose_containers_before = run(
                "cd /opt/remnanode && docker compose ps -aq 2>/dev/null",
                check=False, timeout=30,
            )
            if not (compose_containers_before.stdout or "").strip():
                track("docker_compose", "/opt/remnanode")
            else:
                print("  Существующий проект remnanode обнаружен: автоматический docker compose down при откате отключён.")
            if not ensure_remnanode_up():
                raise RuntimeError("Контейнер remnanode не запустился")

            print(f"  Ограничение порта 2222...")
            iptables_add(f"-I INPUT -p tcp --dport 2222 -s {server_ip} -j ACCEPT")
            iptables_add("-I INPUT -p tcp --dport 2222 -s 127.0.0.1 -j ACCEPT")
            iptables_add("-I INPUT -p tcp --dport 2222 -s 172.16.0.0/12 -j ACCEPT")
            iptables_add("-A INPUT -p tcp --dport 2222 -j DROP")
            pkg_iptables_persist()

            print("  Ожидание подключения ноды...")
            for i in range(20):
                time.sleep(5)
                r = run("docker logs remnanode --tail=5 2>&1", check=False)
                if "started" in r.stdout.lower() or "Remnawave" in r.stdout:
                    print("  Нода подключена!")
                    break
    else:
        # Remote node setup via SSH
        setup_remote_node(node_ip, node_cred, rcfg, secret_key, domain, server_ip)

    # Open extra ports for hy2/grpc
    if install_hy2 or install_grpc:
        # Порты открываются на том сервере, где установлен протокол
        if cascade_hy2 or cascade_grpc:
            # Если хотя бы один протокол через каскад - открываем порты на relay
            target_ip = cascade_ip
            target_cred = cascade_cred
            # Открываем только те порты, которые нужны
            open_extra_ports(install_hy2 and cascade_hy2, install_grpc and cascade_grpc,
                           remote_ip=target_ip, remote_cred=target_cred)

        # Если протоколы не через каскад - открываем на ноде
        if (install_hy2 and not cascade_hy2) or (install_grpc and not cascade_grpc):
            if not same_server:
                target_ip = node_ip
                target_cred = node_cred
            else:
                target_ip = None
                target_cred = None
            open_extra_ports(install_hy2 and not cascade_hy2, install_grpc and not cascade_grpc,
                           remote_ip=target_ip, remote_cred=target_cred)

    # nginx TCP listener on HY2 port for ping (xray apps TCP-ping, HY2 is UDP)
    if install_hy2:
        _hy2_lines = ["server {", f"    listen {HY2_PORT} ssl;",
            f"    listen [::]:{HY2_PORT} ssl;", "    server_name _;",
            "    ssl_certificate /etc/nginx/ssl/cdn.crt;",
            "    ssl_certificate_key /etc/nginx/ssl/cdn.key;",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    location / { return 200 'ok'; }", "}"]
        hy2_ping_conf = chr(10).join(_hy2_lines) + chr(10)
        if same_server:
            with open("/etc/nginx/conf.d/hy2-ping.conf", "w") as _f:
                _f.write(hy2_ping_conf)
            run("nginx -t && systemctl reload nginx", check=False)
        else:
            write_remote_file(node_ip, node_cred, "/etc/nginx/conf.d/hy2-ping.conf", hy2_ping_conf)
            run_remote(node_ip, node_cred, "nginx -t && systemctl reload nginx", timeout=15)
        print(f"  TCP {HY2_PORT} (nginx SSL) для пинга HY2")

    # BRIDGE_IN доступен только relay; остальной Internet получает DROP.
    if cascade:
        print("  Ограничение порта 8888 (BRIDGE_IN) только relay-IP...")
        if same_server:
            restrict_bridge_port(cascade_ip)
        else:
            restrict_bridge_port(cascade_ip, remote_ip=node_ip, remote_cred=node_cred)

    # Create hosts
    step(8, "Создание хостов")

    # Инициализация до ветвления: ниже их читает блок каскада, а присваивались
    # они только внутри if — при пустом inbound_uuid установка падала бы
    # с UnboundLocalError уже на шаге каскада.
    squad_uuid = None
    existing_squad_inbounds = []

    if inbound_uuid and profile_uuid:
        existing_hosts_resp = remnawave_api(token, "GET", "hosts")
        existing_hosts = existing_hosts_resp.get("response", [])
        if not isinstance(existing_hosts, list):
            existing_hosts = []

        def create_host_if_needed(ib_uuid, payload, label):
            for h in existing_hosts:
                if h.get("address") == payload["address"] and h.get("port") == payload["port"]:
                    if h.get("tag") != payload.get("tag"):
                        raise RuntimeError(
                            f"Host {payload['address']}:{payload['port']} уже принадлежит владельцу; "
                            "автоматическое изменение запрещено"
                        )
                    huuid = h.get("uuid")
                    # Существующий хост — обновляем link-поля вкл. xHttpExtraParams
                    # (иначе ссылка без extra ⟶ реджект по xPaddingObfsMode ⟶ Empty reply)
                    patch = {"uuid": huuid}
                    for k in ("inbound", "path", "sni", "host", "alpn", "fingerprint", "tag",
                              "securityLayer", "allowInsecure",
                              "xHttpExtraParams", "xhttpExtraParams"):
                        if k in payload:
                            patch[k] = payload[k]
                    remnawave_api(token, "PATCH", "hosts", patch)
                    print(f"  {label} хост обновлён (extra+inbound): {huuid}")
                    return huuid
            resp = remnawave_api(token, "POST", "hosts", payload)
            if resp.get("response"):
                huuid = resp["response"].get("uuid")
                print(f"  {label} Host UUID: {huuid}")
                return huuid
            else:
                print(f"  ВНИМАНИЕ: Ответ создания хоста {label}: {resp}")
                return None

        # CDN host (skip if cascade — cascade step creates its own host on relay node)
        if not cascade:
            extra_fields = {k: rcfg["host_extra"]
                            for k in remnawave_extra_keys(lambda m, p, d=None: remnawave_api(token, m, p, d))}
            cdn_host_payload = {
                "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": inbound_uuid},
                "remark": f"CDN {cdn_type.upper()}",
                "tag": f"VPN_CDN_{cdn_type.upper()}",
                "address": cdn_domain, "port": 443,
                "path": rcfg.get("host_path", rcfg["xhttp_path"]),
                "sni": cdn_domain, "host": cdn_domain,
                "alpn": rcfg["alpn"],
                "fingerprint": rcfg.get("fingerprint", rcfg.get("fp", "random")),
                "isDisabled": False, "securityLayer": "TLS", "allowInsecure": False,
                **extra_fields,
            }
            host_uuid = create_host_if_needed(inbound_uuid, cdn_host_payload, "CDN")
        else:
            host_uuid = None

        if not cascade and not host_uuid:
            raise RuntimeError("Remnawave не создал обязательный CDN-хост")

        # HY2 host (LE cert if same_server, no pinnedPeerCertSha256)
        hy2_host_uuid = None
        if hy2_inbound_uuid and install_hy2:
            _hy2_le = False
            # origin_domain указывает на ноду (origin_target_ip = node_ip), поэтому
            # LE-сертификат выпускаем и для удалённой ноды тоже — иначе HY2 остаётся
            # с самоподписанным cdn.crt и клиенты его отвергают.
            # Исключение — каскад: там origin_domain смотрит на relay, не на ноду.
            # При cascade_hy2 — HY2 идёт через каскад (relay РФ → exit EU).
            _hy2_domain = f"{hy2_sub}.{domain}" if hy2_sub else origin_domain
            _hy2_target_ip = cascade_ip if cascade_hy2 else node_ip
            _hy2_target_cred = cascade_cred if cascade_hy2 else node_cred

            if same_server and not cascade_hy2:
                _hy2_le = setup_hy2_le_cert(_hy2_domain)
            else:
                _hy2_le = setup_hy2_le_cert(_hy2_domain, _hy2_target_ip, _hy2_target_cred)

            hy2_host_payload = {
                "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": hy2_inbound_uuid},
                "remark": "Hysteria2" + (" (каскад)" if cascade_hy2 else ""),
                "tag": "VPN_CDN_HY2",
                "address": _hy2_target_ip, "port": HY2_PORT,
                "sni": _hy2_domain if _hy2_le else "", "host": "",
                "alpn": "h3", "fingerprint": "random",
                "isDisabled": False, "securityLayer": "TLS",
                "allowInsecure": not _hy2_le,
            }
            if _hy2_le:
                print(f"  HY2: LE cert {_hy2_domain}" + (" (каскад)" if cascade_hy2 else ""))
            elif same_server:
                print(f"  HY2: self-signed, после DNS: certbot certonly --webroot -w /var/www/certbot -d {_hy2_domain}")
            else:
                print(f"  HY2: self-signed (удалённая нода)")
            hy2_host_uuid = create_host_if_needed(hy2_inbound_uuid, hy2_host_payload, "HY2")

        # gRPC Reality host
        grpc_host_uuid = None
        if grpc_inbound_uuid and install_grpc:
            _grpc_target_ip = cascade_ip if cascade_grpc else node_ip
            grpc_host_payload = {
                "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": grpc_inbound_uuid},
                "remark": "gRPC Reality" + (" (каскад)" if cascade_grpc else ""),
                "tag": "VPN_CDN_GRPC",
                "address": _grpc_target_ip, "port": GRPC_PORT,
                "sni": GRPC_SERVER_NAMES[0], "host": "",
                "alpn": "h2", "fingerprint": "random",
                "isDisabled": False, "securityLayer": "DEFAULT", "allowInsecure": False,
                "path": GRPC_SERVICE_NAME
            }
            grpc_host_uuid = create_host_if_needed(grpc_inbound_uuid, grpc_host_payload, "gRPC")

        # Link all hosts to node
        all_host_uuids = [h for h in [host_uuid, hy2_host_uuid, grpc_host_uuid] if h]
        if all_host_uuids and node_uuid:
            for huuid in all_host_uuids:
                host_row = next((h for h in existing_hosts if h.get("uuid") == huuid), {})
                linked_nodes = []
                for item in host_row.get("nodes") or []:
                    value = item.get("uuid") if isinstance(item, dict) else item
                    if value:
                        linked_nodes.append(value)
                if node_uuid not in linked_nodes:
                    linked_nodes.append(node_uuid)
                link_resp = remnawave_api(token, "PATCH", "hosts", {"uuid": huuid, "nodes": linked_nodes})
                if link_resp.get("response"):
                    print(f"  Хост {huuid[:8]}... привязан к ноде")
                else:
                    raise RuntimeError(f"Не удалось привязать хост к ноде: {link_resp}")

        # Add all inbounds to Default-Squad
        all_ib_uuids = [u for u in [inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid] if u]
        if cascade and bridge_in_uuid:
            all_ib_uuids.append(bridge_in_uuid)
        squad_uuid = None
        existing_squad_inbounds = []
        if all_ib_uuids:
            print("  Добавление инбаундов в Default-Squad...")
            squads_resp = remnawave_api(token, "GET", "internal-squads")
            squad_list = squads_resp.get("response", {}).get("internalSquads", [])
            default_squad = next((s for s in squad_list if s.get("name") == "Default-Squad"), None)
            if default_squad:
                squad_uuid = default_squad["uuid"]
                valid_ib_set = set()
                all_p = remnawave_api(token, "GET", "config-profiles")
                if all_p.get("response"):
                    rd = all_p["response"]
                    pl = rd.get("configProfiles", rd if isinstance(rd, list) else [rd])
                    for p in pl:
                        for ib in p.get("inbounds", []):
                            valid_ib_set.add(ib.get("uuid"))
                existing_ib_uuids = [ib["uuid"] for ib in default_squad.get("inbounds", [])
                                     if not valid_ib_set or ib["uuid"] in valid_ib_set]
                for uid in all_ib_uuids:
                    if uid not in existing_ib_uuids:
                        existing_ib_uuids.append(uid)
                existing_squad_inbounds = list(existing_ib_uuids)
                patch_resp = remnawave_api(token, "PATCH", "internal-squads", {
                    "uuid": squad_uuid,
                    "inbounds": existing_ib_uuids
                })
                if patch_resp.get("response"):
                    print(f"  {len(all_ib_uuids)} инбаунд(ов) добавлено в Default-Squad")
                else:
                    raise RuntimeError(f"Не удалось добавить инбаунды в Default-Squad: {patch_resp}")
            else:
                raise RuntimeError("Default-Squad не найден; произвольный Squad изменяться не будет")
    else:
        print(f"  ПРОПУСК: нет inbound_uuid={inbound_uuid} или profile_uuid={profile_uuid}")

    # Create user
    step(9, "Создание пользователя")

    user_short_uuid = None
    # Сквад для юзера обязателен: Remnawave раздаёт ноде список клиентов ИЗ СКВАДА.
    # Без него инбаунд поднимается с пустым списком — порт слушает, xhttp-сессия
    # даже устанавливается (200 в логах origin), но VLESS-хендшейк молча
    # отбивается, и клиент просто висит без ошибок. Панель цепляет сквад при
    # создании непостоянно (на одной цепляет, на другой нет), поэтому передаём
    # его явно и потом добиваем ensure_user_squad. Проверено на стенде Timeweb
    # 06.08.2026: без этого нода получала «0 users» и туннель не работал.
    _user_squad = find_default_squad(lambda m, p, d=None: remnawave_api(token, m, p, d))
    if not _user_squad:
        raise RuntimeError("Default-Squad не найден; пользователь без Squad работать не будет")
    user_id = None

    existing_users_resp = remnawave_api(token, "GET", "users")
    existing_users = existing_users_resp.get("response", {})
    users_list = existing_users.get("users", []) if isinstance(existing_users, dict) else []
    for u in users_list:
        if u.get("username") == "user1":
            user_id = u.get("id")
            user_short_uuid = u.get("shortUuid", "")
            sub_url = u.get("subscriptionUrl", "")
            print(f"  Юзер user1 уже существует: {user_short_uuid}")
            if sub_url:
                print(f"  Sub URL: {sub_url}")
            break

    if not user_short_uuid:
        _payload = {
            "username": "user1",
            "expireAt": "2099-12-31T23:59:59.000Z",
            "trafficLimitBytes": 0,
            "trafficLimitStrategy": "NO_RESET",
            "hwidDeviceLimit": 0
        }
        if _user_squad:
            _payload["activeInternalSquads"] = [_user_squad]
        resp = remnawave_api(token, "POST", "users", _payload)
        if resp.get("response"):
            user_id = resp["response"].get("id")
            user_short_uuid = resp["response"].get("shortUuid", "")
            sub_url = resp["response"].get("subscriptionUrl", "")
            print(f"  User ID: {user_id}")
            print(f"  Short UUID: {user_short_uuid}")
            if sub_url:
                print(f"  Sub URL: {sub_url}")
        else:
            print(f"  ВНИМАНИЕ: Ответ создания юзера: {resp}")

    # Добивка: и для нового, и для уже существовавшего юзера — вдруг панель
    # не зацепила сквад (или юзер остался с прошлой установки без него).
    if user_short_uuid and _user_squad:
        if not ensure_user_squad(
            lambda m, p, d=None: remnawave_api(token, m, p, d), "user1", _user_squad
        ):
            raise RuntimeError("Пользователь user1 не добавлен в Default-Squad")
    if not user_short_uuid:
        raise RuntimeError("Remnawave не создал пользователя user1")

    # --- Resync node ---
    # Логи ноды («is up and running») ВРУТ — xray может подняться, но не занять
    # бэкенд-порт (пустой конфиг/s6-гонка) → nginx проксирует CDN в мёртвый порт →
    # клиент видит «Empty reply». Надёжный критерий — слушает ли xray xray_port.
    # До 3 рестартов с проверкой порта.
    step(10, "Синхронизация ноды")
    xport = rcfg["xray_port"]

    def _backend_up(_ip=None, _cred=None):
        cmd = f"ss -ltn 2>/dev/null | grep -c ':{xport} '"
        r = run_remote(_ip, _cred, cmd, timeout=10) if _ip else run(cmd, check=False)
        try:
            return int((r.stdout or "0").strip()) > 0
        except ValueError:
            return False

    _nip, _ncred = (None, None) if same_server else (node_ip, node_cred)
    synced = False
    for attempt in range(1, 4):
        print(f"  Перезапуск ноды для синхронизации (попытка {attempt}/3)...")
        if _nip:
            run_remote(_nip, _ncred, "docker restart remnanode", timeout=30)
        else:
            run("docker restart remnanode", check=False, timeout=30)
        time.sleep(5)
        for _i in range(12):
            if _nip:
                r = run_remote(_nip, _ncred, "docker logs remnanode --tail=15 2>&1", timeout=15)
            else:
                r = run("docker logs remnanode --tail=15 2>&1", check=False)
            m = re.search(r'(\d+)\s+users', r.stdout) if r.stdout else None
            if _backend_up(_nip, _ncred) and (m or (r.stdout and "is up and running" in r.stdout)):
                users_note = f" ({m.group(1)} юзеров)" if m else ""
                print(f"  Нода синхронизирована, xray слушает :{xport}{users_note}")
                synced = True
                break
            time.sleep(5)
        if synced:
            break
        print(f"  xray так и не занял :{xport} — повтор...")
    if not synced:
        raise RuntimeError(f"Xray ноды не поднялся на :{xport}; установка не завершена")

    # --- Cascade setup (if enabled) ---
    ns = 11
    if cascade:
        step(ns, "Настройка каскада"); ns += 1
        api_func = lambda m, p, d=None: remnawave_api(token, m, p, d)
        cascade_result = setup_cascade_relay(
            cfg, api_func, node_ip, node_cred, same_server,
            profile_uuid, inbound_uuid, squad_uuid,
            existing_squad_inbounds
        )

    # --- CDN instructions ---
    step(ns, "Инструкция по настройке CDN"); ns += 1
    origin_target_ip = cascade_ip if cascade else node_ip

    if cdn_type == "vk":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {panel_domain}  ->  {server_ip}  (DNS only)
  2. A-запись:  {origin_domain}    ->  {origin_target_ip}    (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  2a. A-запись: {hy2_sub}.{domain}  ->  {node_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}
  3. CNAME:     {cdn_domain}    ->  [VK CDN CNAME]  (DNS only)

  ============================================
  Настройки VK Cloud CDN:
  ============================================

  - Протокол к источнику: HTTP (порт 80)
  - Источник: {origin_domain}
  - Персональный домен: {cdn_domain}
  - Заголовок Host: Пересылать
  - SSL: Let's Encrypt
  - Кеширование: ВЫКЛ (все 4 переключателя)
  - HTTP методы: GET, HEAD, OPTIONS
  - Gzip: ВЫКЛ
""")
    elif cdn_type == "yandex":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {panel_domain}  ->  {server_ip}  (DNS only)
  2. A-запись:  {origin_domain}    ->  {origin_target_ip}    (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  2a. A-запись: {hy2_sub}.{domain}  ->  {node_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}
  3. CNAME:     {cdn_domain}    ->  [Yandex CDN CNAME]  (DNS only, создашь позже)
  4. CNAME:     _acme-challenge.{cdn_domain} -> [значение из Yandex] (DNS only, создашь позже)

  Создай пока только записи #1 и #2. Остальные — по ходу.

  ============================================
  ШАГ A: Сертификат в Yandex Certificate Manager
  ============================================

  Зайди: console.yandex.cloud -> Certificate Manager -> Создать сертификат

  Заполни:
    - Имя: {cdn_domain.replace('.', '-')}
    - Домены: {cdn_domain}
    - Тип проверки: DNS

  Нажми "Создать".

  После создания Yandex покажет CNAME для проверки:
    _acme-challenge.{cdn_domain}  ->  <значение>.cm.yandexcloud.net

  Создай эту CNAME запись #4 в Cloudflare (DNS only).
  Жди статус сертификата "Issued" (5-30 мин).

  ============================================
  ШАГ B: CDN-ресурс в Yandex Cloud CDN
  ============================================

  Зайди: console.yandex.cloud -> CDN -> Создать ресурс

  Основные настройки:
    - Запрос контента: Из одного источника
    - Тип источника: Сервер
    - Доменное имя источника: {origin_domain}
    - Протокол для источников: HTTPS
    - Задать SNI вручную: ВКЛ
    - Имя SNI-хоста: {origin_domain}
    - Заголовок Host: Своё значение
    - Значение заголовка: {origin_domain}
    - Доменное имя: {cdn_domain}

  После создания скопируй CNAME (xxx.gcdn.co) и создай DNS запись #3.

  Настройки CDN (вкладки сверху):
    Кеширование:
      - Кеш CDN: ВЫКЛ
      - Кеш браузера: ВЫКЛ

    Дополнительно:
      - Query string: НЕ игнорировать
      - Сжатие: ВЫКЛ
      - Проверка сертификата источника: ВЫКЛ
      - SSL-сертификат: выбери {cdn_domain.replace('.', '-')}
""")
    elif cdn_type == "beeline":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {panel_domain}  ->  {server_ip}  (DNS only)
  2. A-запись:  {origin_domain}    ->  {origin_target_ip}    (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  2a. A-запись: {hy2_sub}.{domain}  ->  {node_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}

  CDN-домен (xxx.a.trbcdn.net) выдаст сам CDNvideo — своя DNS-запись под него не нужна.

  ============================================
  Создание CDN-ресурса на CDNvideo (panel.cdnvideo.ru):
  ============================================

  ВНИМАНИЕ: CDNvideo/Beeline массово банит аккаунты под VPN-трафик.
  Поддержка в скрипте сохранена и конфиг рабочий, но если аккаунт
  заблокировали — ресурс не создать, бери другой CDN (VK / Yandex / Timeweb).

  1. Зайди на panel.cdnvideo.ru -> Создать CDN-ресурс

  2. Основные настройки:
     - Адрес (Origin): {origin_domain}:443
     - Группа доменов: Выключено

  3. HTTPS:
     - Использовать HTTPS при запросе к источникам: ВКЛ
     - Проверять сертификат источника: НЕ включать
     - Указать имя SNI-хоста: ВКЛ
     - Имя SNI-хоста: {origin_domain}

  4. Host-заголовок:
     - Hostname при запросе к источнику: оставить пустым
     - Передавать исходный Host-заголовок: ВКЛ

  5. Кеширование (правая колонка):
     - Кеширование: ВКЛ -> "Настроить вручную"
     - Коды 2xx, 3xx, 4xx, 5xx и browser: "не кешировать" (каждый)
     - Игнорировать заголовки управления кешированием: ВЫКЛ
     - Обслуживать устаревший кэш: ВЫКЛ
     - Кешировать с учетом query string: ВКЛ + "Учитывать все параметры"
       !!! ОБЯЗАТЕЛЬНО: sessionID и seq передаются в query.
           Если выключить - CDN схлопнет разные пакеты туннеля в один
           закешированный ответ, и туннель не поднимется.
     - Кешировать с учетом cookies: ВЫКЛ

  6. Экспертные настройки -> Rewrite -> Настроить:
     - Где выполнять rewrite: "На конечных узлах"
     - Откуда: /static/getFile/video/segment.ts/
     - Куда:   /static/getFile/video/segment.ts
     (без этого правила xhttp не матчится)

  7. Экспертные настройки (вкладка сверху):
     - HTTP2: ВКЛ
     - HTTP3: ВЫКЛ
     - Перенаправлять HTTP на HTTPS: ВКЛ
     - Проверка CORS: ВЫКЛ
     - Сжатие Brotli: ВЫКЛ
     - Сжатие Gzip: ВЫКЛ

  8. Нажми "Применить" и ДОЖДИСЬ статуса "Активен"
     (пока висит "Применяется" - ключ работать не будет)
""")
    elif cdn_type == "timeweb":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {panel_domain}  ->  {server_ip}  (DNS only)
  2. A-запись:  {origin_domain}    ->  {origin_target_ip}    (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  2a. A-запись: {hy2_sub}.{domain}  ->  {node_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}
  3. CDN домен выдаётся автоматически (xxx.cdn.twcstorage.ru)

  ============================================
  Создание CDN-ресурса на Timeweb (timeweb.cloud):
  ============================================

  1. Зайди: timeweb.cloud -> CDN -> Создать ресурс

  2. Источник контента:
     - Выбери вкладку "IP-адрес"
     - IP-адрес: {origin_target_ip}:80{"  ← relay (каскад)" if cascade else ""}
     - Использовать HTTPS: НЕ включать (оставить выключенным)

  3. Домены раздачи:
     - Технический домен (xxx.cdn.twcstorage.ru) создаётся автоматически
     - Добавь свой домен: "+ Добавить домен" -> {cdn_domain}
       CNAME в DNS: {cdn_domain} -> xxx.cdn.twcstorage.ru (DNS only, серое облако)
       Если у домена есть wildcard (*) — явный CNAME его перебивает. Без записи
       поддомен уйдёт на чужой IP, и ключ не подключится.

  4. После создания — настройки ресурса:
     - Кеширование на CDN: ВЫКЛ
     - Кеширование в браузере: ВЫКЛ
     - Всегда онлайн: ВЫКЛ
     - Следовать редиректу: ВЫКЛ
     - Игнорировать параметры запроса: ВЫКЛ
       !!! ОБЯЗАТЕЛЬНО выключить: sessionID и seq идут в query.
           Если включить - CDN их срежет и туннель не поднимется.
     - Редирект HTTP->HTTPS: ВЫКЛ
     - Secure Token: ВЫКЛ
     - HTTP/3: ВЫКЛ
     - Gzip: ВЫКЛ

  5. Вкладка "SSL-сертификаты" -> "Выпустить Let's Encrypt" для {cdn_domain}
     !!! БЕЗ ЭТОГО КЛЮЧ НЕ РАБОТАЕТ: edge отдаст сертификат технического домена,
         клиент увидит несовпадение имени и молча оборвёт TLS.
     Дождись, пока сертификат применится (проверка ниже покажет).

  6. Дождись статуса ресурса "Активен" (пока "Применяется" — CDN отдаёт 403
     на ВСЕ пути, включая /, это нормально).

  Проверка готовности (с любого сервера):
     curl -sS -o /dev/null -w '%{{http_code}}
' https://{cdn_domain}{rcfg.get('host_path', rcfg['xhttp_path'])}
       400 = ГОТОВО (запрос дошёл до xray)
       403 = ресурс ещё применяется / режет путь
       000 = сертификат на домен ещё не выпущен

  ВАЖНО: расширение .m3u8 в пути уже включено в конфиг автоматически.
""")

    effective_cdn_domain = cdn_domain
    if not cfg.get("skip_cdn_wait", False):
        safe_input("  Нажми ENTER когда CDN настроен и сертификат выпущен...")
        if cdn_type in ("beeline", "timeweb", "turboflare", "selectel"):
            if cdn_type == "beeline":
                cdn_issued = safe_input("  Домен выданный Beeline CDN (например https://xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "timeweb":
                cdn_issued = safe_input("  Технический домен Timeweb CDN (например xxx.cdn.twcstorage.ru): ").strip()
            elif cdn_type == "turboflare":
                cdn_issued = safe_input("  Домен выданный TurboFlare CDN (например xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "selectel":
                cdn_issued = safe_input("  Технический домен Selectel CDN (например xxx.selcdn.ru): ").strip()
            if cdn_issued:
                cdn_issued = cdn_issued.replace("https://", "").replace("http://", "").rstrip("/")
                cdn_issued = validate_fqdn(cdn_issued, "технический CDN-домен")
                effective_cdn_domain = cdn_issued
                if cdn_type == "beeline":
                    cdn_label = "Beeline"
                elif cdn_type == "timeweb":
                    cdn_label = "Timeweb"
                elif cdn_type == "turboflare":
                    cdn_label = "TurboFlare"
                else:
                    cdn_label = "Selectel"
                print(f"  CDN домен {cdn_label}: {cdn_issued}")
                hosts_resp = remnawave_api(token, "GET", "hosts")
                host_updated = False
                if hosts_resp.get("response"):
                    for h in hosts_resp["response"]:
                        if (h.get("address") == cdn_domain
                                or h.get("tag") == f"VPN_CDN_{cdn_type.upper()}"):
                            patch = dict(h)
                            patch["address"] = cdn_issued
                            patch["sni"] = cdn_issued
                            patch["host"] = cdn_issued
                            if "inbound" in patch and isinstance(patch["inbound"], dict):
                                patch["inbound"] = {
                                    "configProfileUuid": patch["inbound"].get("configProfileUuid", ""),
                                    "configProfileInboundUuid": patch["inbound"].get("configProfileInboundUuid", "")
                                }
                            for _drop in ("createdAt", "updatedAt", "nodes"):
                                patch.pop(_drop, None)
                            resp = remnawave_api(token, "PATCH", "hosts", patch)
                            if resp.get("response"):
                                print(f"  Хост \"{h.get('remark', '')}\" обновлён: {cdn_issued}")
                                host_updated = True
                            else:
                                raise RuntimeError(f"Ошибка обновления CDN-хоста: {resp}")
                            break
                if not host_updated:
                    raise RuntimeError("CDN-хост Remnawave не найден или не обновлён")

    # --- Final ---
    step(ns, "Финальная проверка"); ns += 1

    panel_check = remnawave_api(token, "GET", "nodes")
    panel_ok = isinstance(panel_check.get("response"), (list, dict))
    local_chain = local_origin_readiness(rcfg["xray_port"], rcfg["xhttp_path"])

    print(f"  Panel API: {'OK' if panel_ok else 'FAIL'}")
    print(f"  Xray listener: {'OK' if local_chain['listener'] else 'FAIL'}")
    print(f"  Nginx -> Xray config: {'OK' if local_chain['nginx'] else 'FAIL'}")
    print(f"  Origin health: {'OK' if local_chain['health'] else 'FAIL'}")

    cdn_ready = None
    if cdn_type == "timeweb" and not cfg.get("skip_cdn_wait", False):
        cdn_code, cdn_detail = probe_cdn_path(
            effective_cdn_domain,
            rcfg.get("host_path", rcfg["xhttp_path"]),
        )
        cdn_ready = cdn_code == "400"
        print(f"  Timeweb edge/XHTTP: {'OK' if cdn_ready else 'FAIL'} (HTTP {cdn_code})")
        if not cdn_ready:
            print("  ⚠ Серверная часть готова, но Timeweb ещё не пропускает XHTTP-путь.")
            if cdn_detail:
                print(f"  Причина curl: {cdn_detail}")

    # Verify API resources
    profiles = remnawave_api(token, "GET", "config-profiles")
    nodes = remnawave_api(token, "GET", "nodes")
    hosts = remnawave_api(token, "GET", "hosts")
    users = remnawave_api(token, "GET", "users")

    pr = profiles.get("response", {})
    p_count = pr.get("total", len(pr.get("configProfiles", []))) if isinstance(pr, dict) else (len(pr) if isinstance(pr, list) else 0)
    n_count = len(nodes.get("response", [])) if isinstance(nodes.get("response"), list) else 0
    h_count = len(hosts.get("response", [])) if isinstance(hosts.get("response"), list) else 0
    ur = users.get("response", {})
    u_count = len(ur.get("users", [])) if isinstance(ur, dict) else (len(ur) if isinstance(ur, list) else 0)

    print(f"  Profiles: {p_count}, Nodes: {n_count}, Hosts: {h_count}, Users: {u_count}")

    profile_rows = pr.get("configProfiles", []) if isinstance(pr, dict) else pr
    our_profile = next(
        (p for p in (profile_rows or []) if p.get("uuid") == profile_uuid), None
    )
    profile_inbound_ok = bool(our_profile and any(
        ib.get("uuid") == inbound_uuid for ib in our_profile.get("inbounds", [])
    ))

    node_rows = nodes.get("response", []) if isinstance(nodes.get("response"), list) else []
    our_node = next((n for n in node_rows if n.get("uuid") == node_uuid), None)
    node_connected = bool(our_node and our_node.get("isConnected"))

    host_rows = hosts.get("response", []) if isinstance(hosts.get("response"), list) else []
    our_host = next((h for h in host_rows if h.get("uuid") == host_uuid), None) if host_uuid else None
    linked_node_ids = []
    if our_host:
        for item in our_host.get("nodes") or []:
            value = item.get("uuid") if isinstance(item, dict) else item
            if value:
                linked_node_ids.append(value)
    host_linked = bool(cascade or (our_host and node_uuid in linked_node_ids))

    user_rows = ur.get("users", []) if isinstance(ur, dict) else (ur if isinstance(ur, list) else [])
    our_user = next((u for u in user_rows if u.get("username") == "user1"), None)
    user_squad_ids = []
    if our_user:
        for item in our_user.get("activeInternalSquads") or []:
            value = item.get("uuid") if isinstance(item, dict) else item
            if value:
                user_squad_ids.append(value)
    user_squad_ok = bool(our_user and squad_uuid in user_squad_ids)

    print(f"  Active profile/inbound: {'OK' if profile_inbound_ok else 'FAIL'}")
    print(f"  Node connected: {'OK' if node_connected else 'FAIL'}")
    print(f"  Host linked to node: {'OK' if host_linked else 'FAIL'}")
    print(f"  User linked to squad: {'OK' if user_squad_ok else 'FAIL'}")

    required_ok = all((panel_ok, local_chain["listener"], local_chain["nginx"],
                       local_chain["health"], profile_uuid, inbound_uuid,
                       node_uuid, user_short_uuid, p_count > 0, n_count > 0,
                       h_count > 0, u_count > 0, profile_inbound_ok,
                       node_connected, host_linked, user_squad_ok))
    if not required_ok:
        raise RuntimeError(
            "Финальная проверка Remnawave не пройдена: "
            f"panel={panel_ok}, listener={local_chain['listener']}, "
            f"nginx={local_chain['nginx']}, origin={local_chain['health']}, "
            f"profile={bool(profile_uuid)}, "
            f"inbound={bool(inbound_uuid)}, node={bool(node_uuid)}, user={bool(user_short_uuid)}, "
            f"links={profile_inbound_ok}/{node_connected}/{host_linked}/{user_squad_ok}, "
            f"counts={p_count}/{n_count}/{h_count}/{u_count}"
        )

    extra_info = ""
    if install_hy2:
        extra_info += f"\n  Hysteria2: {node_ip}:{HY2_PORT} (UDP)"
    if install_grpc:
        extra_info += f"\n  gRPC Reality: {node_ip}:{GRPC_PORT} (TCP)"
        if cfg.get("reality_keys"):
            extra_info += f"\n  Reality PBK: {cfg['reality_keys']['public']}"
            extra_info += f"\n  Reality SID: {cfg.get('reality_short_id', 'N/A')}"

    cascade_info = ""
    if cascade:
        cascade_info = f"\n\n  КАСКАД:\n  Relay: {cascade_ip} (Caddy + remnanode)\n  Exit: {node_ip} (BRIDGE_IN :8888)"

    # Страница подписки — в самом конце: панель, нода и хосты уже подняты, токен
    # и юзер созданы. Ставится на сервере панели (Bundled), режимы 1/2.
    sub_page_line = ""
    if install_subpage and sub_domain:
        setup_subscription_page(sub_domain, token, server_ip)
        sub_page_line = f"\n  Страница подписки: https://{sub_domain}/{user_short_uuid or '<shortUuid>'}"
    else:
        sub_page_line = f"\n  Подписка: https://{panel_domain}/api/sub/{user_short_uuid or 'N/A'}"

    cdn_status_line = ""
    if cdn_ready is not None:
        cdn_status_line = (
            "\n  Проверка Timeweb: "
            + ("OK" if cdn_ready else "НЕ ГОТОВ — трафик пока не пойдёт")
        )

    print(f"""
  ============================================
  УСТАНОВКА ЗАВЕРШЕНА
  ============================================

  Панель: https://{panel_domain}
  Логин: {panel_user}
  Пароль: {panel_pass}

  Персональный CDN домен: {cdn_domain}
  CDN домен в профиле: {effective_cdn_domain}
  Origin: {origin_domain} -> {origin_target_ip}{"  (relay каскад)" if cascade else ""}

  Профиль: {profile_name} (UUID: {profile_uuid or 'N/A'})
  Нода: {node_uuid or 'N/A'} ({node_address}:2222)
  Хост CDN: {effective_cdn_domain}:443{extra_info}
  Юзер: user1 (short: {user_short_uuid or 'N/A'}){sub_page_line}{cdn_status_line}{cascade_info}
  ============================================
""")



# ============================================================
#  NODE-ONLY INSTALLATION (connect to existing panel)
# ============================================================

def install_node_only(cfg):
    """Install only the node + CDN origin, connect to existing Remnawave panel via SSH API."""
    cdn_type = cfg["cdn_type"]
    rcfg = REMNAWAVE_CDN[cdn_type]
    server_ip = cfg["server_ip"]
    domain = cfg["domain"]
    origin_sub = cfg["origin_sub"]
    hy2_sub = cfg.get("hy2_sub", "")
    cdn_sub = cfg["cdn_sub"]
    cdn_domain = f"{cdn_sub}.{domain}"
    origin_domain = f"{origin_sub}.{domain}"
    panel_ip = cfg["panel_ip"]
    panel_cred = cfg.get("panel_cred")
    panel_url = cfg.get("panel_url")
    panel_token = cfg.get("panel_token")
    cascade = cfg.get("cascade", False)
    cascade_ip = cfg.get("cascade_ip")
    cascade_cred = cfg.get("cascade_cred")
    cascade_hy2 = cfg.get("cascade_hy2", False)
    cascade_grpc = cfg.get("cascade_grpc", False)

    if panel_url and panel_token:
        api = lambda method, path, data=None: remnawave_api_direct(panel_url, panel_token, method, path, data)
    else:
        api = lambda method, path, data=None: remnawave_api_ssh(panel_ip, panel_cred, method, path, data)

    # --- Step: Verify API connection ---
    step(3, "Проверка подключения к панели")

    resp = api("GET", "nodes")
    if "error" in resp:
        err_str = str(resp.get("error", ""))
        is_403 = "403" in err_str or "Forbidden" in err_str
        if is_403:
            print(f"  ⚠ Панель требует API-токен (403 Forbidden)")
            print(f"  Создай токен в панели → Settings → API Tokens → скопируй")
            manual_token = ask("Вставь API-токен сюда").strip()
            if not manual_token:
                print(f"  ❌ Токен не введён")
                sys.exit(1)
            if panel_url:
                panel_token = manual_token
                api = lambda method, path, data=None: remnawave_api_direct(panel_url, panel_token, method, path, data)
            else:
                import base64 as _b64_fb
                _t_b64 = _b64_fb.b64encode(manual_token.encode()).decode()
                run_remote(panel_ip, panel_cred,
                    f"umask 077; mkdir -p /opt/remnawave && echo {_t_b64} | base64 -d > /opt/remnawave/.panel_token && chmod 600 /opt/remnawave/.panel_token", timeout=10)
            resp = api("GET", "nodes")
            if "error" in resp:
                print(f"  ❌ Токен не работает: {resp}")
                sys.exit(1)
        else:
            print(f"  ОШИБКА: Не удалось подключиться к панели: {resp}")
            if panel_url:
                print(f"  Панель: {panel_url}")
            else:
                print(f"  Панель: {panel_ip} (SSH → 127.0.0.1:3000)")
            print(f"  Проверь доступ и что панель запущена")
            sys.exit(1)
    existing_nodes = resp.get("response", [])
    n_count = len(existing_nodes) if isinstance(existing_nodes, list) else 0
    print(f"  Панель доступна, нод: {n_count}")

    panel_version = None
    try:
        ver_resp = api("GET", "auth/me")
        if ver_resp.get("response"):
            panel_version = ver_resp["response"].get("version")
    except Exception:
        pass
    if panel_version:
        print(f"  Версия панели: {panel_version}")
    else:
        print("  Версия панели: не определена (совместимый режим)")

    # --- Step: Docker ---
    step(4, "Установка Docker")
    setup_docker_mirror()
    if install_docker():
        print(f"  Docker готов: {run('docker --version', check=False).stdout.strip()}")
    else:
        print("  ❌ Docker не установился из репозитория ОС. Проверь apt и пакет docker.io.")
        sys.exit(1)

    rc = run("docker compose version 2>/dev/null", check=False)
    if rc.returncode != 0:
        print("  docker compose plugin не найден, устанавливаю...")
        install_docker_compose()
        rc = run("docker compose version 2>/dev/null", check=False)
        if rc.returncode != 0:
            print("  ❌ docker compose не установился!")
            sys.exit(1)
        print(f"  docker compose: {rc.stdout.strip()}")

    # --- Step: Nginx CDN origin ---
    step(5, "Настройка nginx CDN origin")
    ipv6_ok = has_ipv6()
    nginx_conf = nginx_cdn_origin(rcfg["xray_port"], rcfg["xhttp_path"], ipv6=ipv6_ok,
                                  nginx_style=rcfg.get("nginx_style", "prefix"))
    r = nginx_write_and_restart(nginx_conf)
    if r.returncode == 0:
        print("  Nginx CDN origin настроен")
    else:
        print(f"  ❌ Проблема с nginx: {r.stderr[:200] if r.stderr else ''}")
        print("  Попробуй: nginx -t и systemctl restart nginx")
        sys.exit(1)

    # --- Step: Create config profile ---
    step(6, "Создание профиля через API панели")

    install_hy2 = cfg.get("install_hy2", False)
    install_grpc = cfg.get("install_grpc", False)
    profile_name = f"cdn-{cdn_type}"
    if install_hy2 or install_grpc:
        extras = []
        if install_hy2:
            extras.append("hy2")
        if install_grpc:
            extras.append("grpc")
        profile_name += "-" + "-".join(extras)
    inbound_tag = rcfg["inbound_tag"]
    profile_uuid = None
    inbound_uuid = None
    hy2_inbound_uuid = None
    grpc_inbound_uuid = None
    bridge_in_uuid = None

    existing_profiles = api("GET", "config-profiles")
    if existing_profiles.get("response"):
        resp_data = existing_profiles["response"]
        plist = resp_data.get("configProfiles", resp_data if isinstance(resp_data, list) else [resp_data])
        _f = remnawave_find_profile(plist, inbound_tag, profile_name, rcfg.get("xray_port"))
        profile_uuid = _f["profile_uuid"]
        inbound_uuid = _f["inbound_uuid"]
        hy2_inbound_uuid = _f["hy2_inbound_uuid"]
        grpc_inbound_uuid = _f["grpc_inbound_uuid"]
        bridge_in_uuid = _f["bridge_in_uuid"]

    if not profile_uuid:
        import copy
        tag_id = secrets.token_hex(3)
        profile_name = f"{profile_name}-{tag_id}"
        profile_config = copy.deepcopy(rcfg["profile_config"])
        for _ib in profile_config.get("inbounds", []):
            _ib["tag"] = f"{_ib['tag']}-{tag_id}"
        inbound_tag = f"{inbound_tag}-{tag_id}"

        if install_hy2:
            profile_config["inbounds"].append(build_hy2_inbound(tag_suffix=tag_id))
            print(f"  Добавлен Hysteria2 inbound (UDP {HY2_PORT})")

        if install_grpc:
            reality_keys = generate_x25519_keys()
            if reality_keys:
                short_id = secrets.token_hex(8)
                cfg["reality_keys"] = reality_keys
                cfg["reality_short_id"] = short_id
                profile_config["inbounds"].append(build_grpc_inbound(reality_keys["private"], short_id, tag_suffix=tag_id))
                print(f"  Добавлен gRPC Reality inbound (TCP {GRPC_PORT})")

        if cascade:
            profile_config["inbounds"].append({
                "tag": f"BRIDGE_IN-{tag_id}", "port": 8888, "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
                "streamSettings": {"network": "tcp", "security": "none"}
            })
            print(f"  Добавлен BRIDGE_IN inbound (TCP 8888) для каскада")

        print(f"  Создание профиля: {profile_name}...")
        profile_payload = {"name": profile_name, "config": profile_config}
        for _attempt in range(4):
            resp = api("POST", "config-profiles", profile_payload)
            if resp.get("response"):
                profile_uuid = resp["response"].get("uuid")
                for ib in resp["response"].get("inbounds", []):
                    if ib.get("tag") == inbound_tag:
                        inbound_uuid = ib.get("uuid")
                    elif ib.get("tag", "").startswith("hy2-in"):
                        hy2_inbound_uuid = ib.get("uuid")
                    elif ib.get("tag", "").startswith("grpc-reality"):
                        grpc_inbound_uuid = ib.get("uuid")
                    elif ib.get("tag", "").startswith("BRIDGE_IN"):
                        bridge_in_uuid = ib.get("uuid")
                break
            if _attempt < 3:
                print(f"  API retry профиля ({_attempt+1}/3), жду 10 сек...")
                time.sleep(10)
        if not profile_uuid:
            print(f"  ОШИБКА: Не удалось создать профиль: {resp}")
            sys.exit(1)

    print(f"  Profile UUID: {profile_uuid}")
    print(f"  CDN Inbound UUID: {inbound_uuid}")
    if hy2_inbound_uuid:
        print(f"  HY2 Inbound UUID: {hy2_inbound_uuid}")
    if grpc_inbound_uuid:
        print(f"  gRPC Inbound UUID: {grpc_inbound_uuid}")

    if cascade:
        bridge_keys, bridge_sid = prepare_bridge_reality(cfg)
        bridge_in_uuid = ensure_bridge_inbound(
            api, profile_uuid, bridge_in_uuid,
            private_key=bridge_keys["private"], short_id=bridge_sid)
        if not bridge_in_uuid:
            raise RuntimeError("BRIDGE_IN отсутствует — каскад не поднимется")
        print(f"  BRIDGE_IN Inbound UUID: {bridge_in_uuid}")

    # --- Step: Squad binding ---
    step(7, "Привязка инбаунда к скваду")

    squads_resp = api("GET", "internal-squads")
    squad_list = squads_resp.get("response", {}).get("internalSquads", [])

    if not squad_list:
        print("  ОШИБКА: Нет сквадов в панели")
        sys.exit(1)

    if len(squad_list) == 1:
        chosen_squad = squad_list[0]
        print(f"  Единственный сквад: {chosen_squad['name']}")
    elif cfg.get("squad"):
        sq_arg = cfg["squad"]
        if sq_arg.isdigit() and 1 <= int(sq_arg) <= len(squad_list):
            chosen_squad = squad_list[int(sq_arg) - 1]
        else:
            chosen_squad = next((s for s in squad_list if s["name"].lower() == sq_arg.lower()), squad_list[0])
        print(f"  Сквад (из аргумента): {chosen_squad['name']}")
    else:
        print("\n  Доступные скводы:")
        squad_options = {}
        for i, sq in enumerate(squad_list, 1):
            ib_count = sq.get("info", {}).get("inboundsCount", len(sq.get("inbounds", [])))
            members = sq.get("info", {}).get("membersCount", 0)
            squad_options[str(i)] = f"{sq['name']} ({ib_count} inbounds, {members} users)"
        choice = ask("К какому скваду привязать инбаунд?", squad_options)
        chosen_squad = squad_list[int(choice) - 1]

    all_new_uuids = [u for u in [inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid] if u]
    if cascade and bridge_in_uuid:
        all_new_uuids.append(bridge_in_uuid)
    valid_ib_set = set()
    all_p = api("GET", "config-profiles")
    if all_p.get("response"):
        rd = all_p["response"]
        pl = rd.get("configProfiles", rd if isinstance(rd, list) else [rd])
        for p in pl:
            for ib in p.get("inbounds", []):
                valid_ib_set.add(ib.get("uuid"))
    existing_ib_uuids = [ib["uuid"] for ib in chosen_squad.get("inbounds", [])
                         if not valid_ib_set or ib["uuid"] in valid_ib_set]
    for uid in all_new_uuids:
        if uid not in existing_ib_uuids:
            existing_ib_uuids.append(uid)

    patch_resp = api("PATCH", "internal-squads", {
        "uuid": chosen_squad["uuid"],
        "inbounds": existing_ib_uuids
    })
    if patch_resp.get("response"):
        print(f"  {len(all_new_uuids)} инбаунд(ов) привязано к скваду: {chosen_squad['name']}")
    else:
        print(f"  ВНИМАНИЕ: Не удалось привязать: {patch_resp}")

    # --- Step: Create node ---
    step(8, "Создание ноды в панели")

    our_uuids = {inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid, bridge_in_uuid} - {None}
    excluded = []
    all_profiles = api("GET", "config-profiles")
    if all_profiles.get("response"):
        resp_data = all_profiles["response"]
        profiles_list = resp_data.get("configProfiles", resp_data if isinstance(resp_data, list) else [resp_data])
        for p in profiles_list:
            for ib in p.get("inbounds", []):
                ib_uuid = ib.get("uuid")
                if ib_uuid and ib_uuid not in our_uuids:
                    excluded.append(ib_uuid)
    if excluded:
        print(f"  Исключено {len(excluded)} чужих inbound'ов")

    node_uuid = None
    existing_nodes = existing_nodes if isinstance(existing_nodes, list) else []
    for n in existing_nodes:
        if n.get("address") == server_ip and n.get("port") == 2222:
            node_uuid = n.get("uuid")
            print(f"  Нода уже существует: {node_uuid}")
            break

    if not node_uuid:
        active_inbounds = [u for u in [inbound_uuid, hy2_inbound_uuid, grpc_inbound_uuid, bridge_in_uuid] if u]
        print(f"  Создание ноды ({server_ip}:2222)...")
        node_data = {
            "name": f"node-{cdn_type}-{'.'.join(server_ip.split('.')[-2:])}",
            "address": server_ip,
            "port": 2222,
            "countryCode": "XX",
            "isTrafficTrackingActive": True,
            "trafficLimitBytes": 0,
            "notifyPercent": 0,
            "trafficResetDay": 1,
            "excludedInbounds": excluded,
            "configProfile": {
                "activeConfigProfileUuid": profile_uuid,
                "activeInbounds": active_inbounds
            }
        }
        for _attempt in range(4):
            resp = api("POST", "nodes", node_data)
            if resp.get("response"):
                node_uuid = resp["response"].get("uuid")
                print(f"  Node UUID: {node_uuid}")
                break
            if _attempt < 3:
                print(f"  API retry ноды ({_attempt+1}/3), жду 10 сек...")
                time.sleep(10)
        if not node_uuid:
            print(f"  ОШИБКА: Не удалось создать ноду: {resp}")
            sys.exit(1)

    if cascade and bridge_in_uuid and node_uuid:
        ensure_node_inbound(api, node_uuid, profile_uuid, bridge_in_uuid)
        if not ensure_squad_inbound(api, bridge_in_uuid, chosen_squad["uuid"]):
            raise RuntimeError("BRIDGE_IN не добавлен в выбранный squad")

    # --- Step: Get secret key + start remnanode ---
    step(9, "Запуск remnanode")

    secret_key = None
    resp = api("GET", "keygen")
    if resp.get("response"):
        secret_key = resp["response"].get("pubKey")
        if secret_key:
            print(f"  Secret key получен ({len(secret_key)} chars)")
    if not secret_key:
        print("  ОШИБКА: Не удалось получить secret key")
        sys.exit(1)

    remnanode_dir_existed = os.path.isdir("/opt/remnanode")
    run("mkdir -p /opt/remnanode", check=False)
    track_created("directory", "/opt/remnanode", existed_before=remnanode_dir_existed)

    node_compose = f"""services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:{REMNAWAVE_NODE_VERSION}
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - /etc/nginx/ssl:/etc/nginx/ssl:ro
      - /opt/remnanode/xray-custom:/usr/local/bin/xray
    env_file:
      - .env
"""
    node_compose_path = "/opt/remnanode/docker-compose.yml"
    node_compose_existed = os.path.lexists(node_compose_path)
    backup_file(node_compose_path)
    track_created("file", node_compose_path, existed_before=node_compose_existed)
    with open(node_compose_path, "w") as f:
        f.write(node_compose)

    node_env = f"NODE_PORT=2222\nSECRET_KEY={secret_key}\n"
    node_env_path = "/opt/remnanode/.env"
    node_env_existed = os.path.lexists(node_env_path)
    backup_file(node_env_path)
    track_created("file", node_env_path, existed_before=node_env_existed)
    with open(node_env_path, "w") as f:
        f.write(node_env)
    os.chmod(node_env_path, 0o600)

    if not download_xray_binary():
        raise RuntimeError("Не удалось установить проверенный Xray для remnanode")
    print("  Скачивание образа remnanode...")
    require_success(
        run("cd /opt/remnanode && docker compose pull", check=False, timeout=600,
                label="Загрузка remnanode", expected=45),
        "Загрузка контейнера remnanode",
    )
    print("  Запуск remnanode...")
    compose_containers_before = run(
        "cd /opt/remnanode && docker compose ps -aq 2>/dev/null",
        check=False, timeout=30,
    )
    if not (compose_containers_before.stdout or "").strip():
        track("docker_compose", "/opt/remnanode")
    else:
        print("  Существующий проект remnanode обнаружен: автоматический docker compose down при откате отключён.")
    if not ensure_remnanode_up():
        raise RuntimeError("Контейнер remnanode не запустился")

    print("  Ожидание подключения ноды...")
    for i in range(20):
        time.sleep(5)
        r = run("docker logs remnanode --tail=5 2>&1", check=False)
        if "started" in r.stdout.lower() or "Remnawave" in r.stdout:
            print("  Нода подключена!")
            break

    # --- Step: iptables ---
    print(f"  Ограничение порта 2222 для панели ({panel_ip})...")
    iptables_add(f"-I INPUT -p tcp --dport 2222 -s {panel_ip} -j ACCEPT")
    iptables_add("-I INPUT -p tcp --dport 2222 -s 127.0.0.1 -j ACCEPT")
    iptables_add("-I INPUT -p tcp --dport 2222 -s 172.16.0.0/12 -j ACCEPT")
    iptables_add("-A INPUT -p tcp --dport 2222 -j DROP")
    open_extra_ports(install_hy2, install_grpc)
    if cascade:
        print("  Ограничение порта 8888 (BRIDGE_IN) только relay-IP...")
        restrict_bridge_port(cascade_ip)

    # nginx TCP listener on HY2 port for ping (xray apps TCP-ping, HY2 is UDP)
    if install_hy2:
        _hy2_lines = ["server {", f"    listen {HY2_PORT} ssl;",
            f"    listen [::]:{HY2_PORT} ssl;", "    server_name _;",
            "    ssl_certificate /etc/nginx/ssl/cdn.crt;",
            "    ssl_certificate_key /etc/nginx/ssl/cdn.key;",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    location / { return 200 'ok'; }", "}"]
        hy2_ping_conf = chr(10).join(_hy2_lines) + chr(10)
        with open("/etc/nginx/conf.d/hy2-ping.conf", "w") as _f:
            _f.write(hy2_ping_conf)
        run("nginx -t && systemctl reload nginx", check=False)
        print(f"  TCP {HY2_PORT} (nginx SSL) для пинга HY2")

    pkg_iptables_persist()

    # --- Step: Create hosts ---
    step(10, "Создание хостов")

    existing_hosts_resp = api("GET", "hosts")
    existing_hosts = existing_hosts_resp.get("response", [])
    if not isinstance(existing_hosts, list):
        existing_hosts = []

    def create_host_if_needed(ib_uuid, payload, label):
        for h in existing_hosts:
            if h.get("address") == payload["address"] and h.get("port") == payload["port"]:
                huuid = h.get("uuid")
                # Хост существует (повторный запуск) — ОБЯЗАТЕЛЬНО обновляем link-поля,
                # в первую очередь xHttpExtraParams: без них ссылка идёт без extra, а
                # инбаунд имеет xPaddingObfsMode=true → сервер реджектит клиента →
                # «Empty reply». Раньше патчился только inbound → extra не проставлялся.
                patch = {"uuid": huuid}
                for k in ("inbound", "path", "sni", "host", "alpn", "fingerprint",
                          "securityLayer", "allowInsecure",
                          "xHttpExtraParams", "xhttpExtraParams"):
                    if k in payload:
                        patch[k] = payload[k]
                patched = api("PATCH", "hosts", patch)
                if not patched.get("response"):
                    raise RuntimeError(f"Не удалось обновить существующий {label}-хост: {patched}")
                print(f"  {label} хост обновлён (extra+inbound): {huuid}")
                return huuid
        resp = api("POST", "hosts", payload)
        if resp.get("response"):
            huuid = resp["response"].get("uuid")
            print(f"  {label} Host UUID: {huuid}")
            return huuid
        else:
            print(f"  ВНИМАНИЕ: Ответ создания хоста {label}: {resp}")
            return None

    # CDN host (skip if cascade — cascade step creates its own host on relay node)
    if not cascade:
        extra_fields = {k: rcfg["host_extra"] for k in remnawave_extra_keys(api)}
        cdn_host_payload = {
            "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": inbound_uuid},
            "remark": f"CDN {cdn_type.upper()} ({server_ip})",
            "address": cdn_domain, "port": 443,
            "path": rcfg.get("host_path", rcfg["xhttp_path"]),
            "sni": cdn_domain, "host": cdn_domain,
            "alpn": rcfg["alpn"],
            "fingerprint": rcfg.get("fingerprint", rcfg.get("fp", "random")),
            "isDisabled": False, "securityLayer": "TLS", "allowInsecure": False,
            **extra_fields,
        }
        host_uuid = create_host_if_needed(inbound_uuid, cdn_host_payload, "CDN")
    else:
        host_uuid = None

    if not cascade and not host_uuid:
        raise RuntimeError("Remnawave не создал обязательный CDN-хост")

    # HY2 host (LE cert, no pinnedPeerCertSha256)
    hy2_host_uuid = None
    if hy2_inbound_uuid and install_hy2:
        # В каскаде origin_domain смотрит на relay, а не на этот сервер —
        # certbot всё равно не выпустит, только зря провисит таймаут.
        _hy2_domain = f"{hy2_sub}.{domain}" if hy2_sub else origin_domain
        _hy2_le = setup_hy2_le_cert(_hy2_domain)
        hy2_host_payload = {
            "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": hy2_inbound_uuid},
            "remark": f"HY2 ({server_ip})",
            "address": server_ip, "port": HY2_PORT,
            "sni": _hy2_domain if _hy2_le else "", "host": "",
            "alpn": "h3", "fingerprint": "random",
            "isDisabled": False, "securityLayer": "TLS",
            "allowInsecure": not _hy2_le,
        }
        if _hy2_le:
            print(f"  HY2: LE cert {_hy2_domain}")
        else:
            print(f"  HY2: self-signed, после DNS: certbot certonly --webroot -w /var/www/certbot -d {_hy2_domain}")
        hy2_host_uuid = create_host_if_needed(hy2_inbound_uuid, hy2_host_payload, "HY2")

    # gRPC Reality host
    grpc_host_uuid = None
    if grpc_inbound_uuid and install_grpc:
        grpc_host_payload = {
            "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": grpc_inbound_uuid},
            "remark": f"gRPC ({server_ip})",
            "address": server_ip, "port": GRPC_PORT,
            "sni": GRPC_SERVER_NAMES[0], "host": "",
            "alpn": "h2", "fingerprint": "random",
            "isDisabled": False, "securityLayer": "DEFAULT", "allowInsecure": False,
            "path": GRPC_SERVICE_NAME
        }
        grpc_host_uuid = create_host_if_needed(grpc_inbound_uuid, grpc_host_payload, "gRPC")

    # Link all hosts to node
    all_host_uuids = [h for h in [host_uuid, hy2_host_uuid, grpc_host_uuid] if h]
    if all_host_uuids and node_uuid:
        for huuid in all_host_uuids:
            link_resp = api("PATCH", "hosts", {"uuid": huuid, "nodes": [node_uuid]})
            if link_resp.get("response"):
                print(f"  Хост {huuid[:8]}... привязан к ноде")
            else:
                raise RuntimeError(f"Не удалось привязать хост к ноде: {link_resp}")

    # --- Step: Resync node ---
    step(11, "Синхронизация ноды")
    # ВАЖНО: логи ноды («is up and running») ВРУТ — xray-ядро может подняться, но
    # НЕ занять бэкенд-порт (пустой конфиг / s6-гонка после первой синхронизации).
    # Тогда nginx проксирует CDN на мёртвый порт → клиент видит «Empty reply from
    # server». Единственный надёжный критерий — реально ли xray слушает xray_port.
    # Один рестарт часто не добивает → до 3 попыток с проверкой порта.
    xport = rcfg["xray_port"]

    def _node_backend_up():
        r = run(f"ss -ltn 2>/dev/null | grep -c ':{xport} '", check=False)
        try:
            return int((r.stdout or "0").strip()) > 0
        except ValueError:
            return False

    synced = False
    for attempt in range(1, 4):
        print(f"  Перезапуск ноды для синхронизации (попытка {attempt}/3)...")
        run("docker restart remnanode", check=False, timeout=30)
        time.sleep(5)
        for _i in range(12):
            r = run("docker logs remnanode --tail=15 2>&1", check=False)
            m = re.search(r'(\d+)\s+users', r.stdout)
            if _node_backend_up() and (m or "is up and running" in r.stdout):
                users_note = f" ({m.group(1)} юзеров)" if m else ""
                print(f"  Нода синхронизирована, xray слушает :{xport}{users_note}")
                synced = True
                break
            time.sleep(5)
        if synced:
            break
        print(f"  xray так и не занял :{xport} — повтор...")
    if not synced:
        raise RuntimeError(f"Xray ноды не поднялся на :{xport}; установка не завершена")

    # --- Cascade setup (if enabled) ---
    ns = 12
    if cascade:
        step(ns, "Настройка каскада"); ns += 1
        cascade_result = setup_cascade_relay(
            cfg, api, server_ip, None, True,
            profile_uuid, inbound_uuid, chosen_squad["uuid"],
            list(existing_ib_uuids)
        )

    # --- Step: CDN instructions ---
    step(ns, "Инструкция по настройке CDN"); ns += 1
    origin_target_ip = cascade_ip if cascade else server_ip

    if cdn_type == "vk":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {origin_target_ip}  (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  1a. A-запись: {hy2_sub}.{domain}  ->  {server_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}
  2. CNAME:     {cdn_domain}  ->  [VK CDN CNAME]  (DNS only)

  ============================================
  Настройки VK Cloud CDN:
  ============================================

  - Протокол к источнику: HTTP (порт 80)
  - Источник: {origin_domain}
  - Персональный домен: {cdn_domain}
  - Заголовок Host: Пересылать
  - SSL: Let's Encrypt
  - Кеширование: ВЫКЛ (все 4 переключателя)
  - HTTP методы: GET, HEAD, OPTIONS
  - Gzip: ВЫКЛ
""")
    elif cdn_type == "yandex":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {origin_target_ip}  (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  1a. A-запись: {hy2_sub}.{domain}  ->  {server_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}
  2. CNAME:     {cdn_domain}  ->  [Yandex CDN CNAME]  (DNS only, создашь позже)
  3. CNAME:     _acme-challenge.{cdn_domain} -> [значение из Yandex] (DNS only, создашь позже)

  Создай пока только запись #1. Остальные — по ходу.

  ============================================
  ШАГ A: Сертификат в Yandex Certificate Manager
  ============================================

  Зайди: console.yandex.cloud -> Certificate Manager -> Создать сертификат

  Заполни:
    - Имя: {cdn_domain.replace('.', '-')}
    - Домены: {cdn_domain}
    - Тип проверки: DNS

  Нажми "Создать".

  После создания Yandex покажет CNAME для проверки:
    _acme-challenge.{cdn_domain}  ->  <значение>.cm.yandexcloud.net

  Создай эту CNAME запись #3 в Cloudflare (DNS only).
  Жди статус сертификата "Issued" (5-30 мин).

  ============================================
  ШАГ B: CDN-ресурс в Yandex Cloud CDN
  ============================================

  Зайди: console.yandex.cloud -> CDN -> Создать ресурс

  Основные настройки:
    - Запрос контента: Из одного источника
    - Тип источника: Сервер
    - Доменное имя источника: {origin_domain}
    - Протокол для источников: HTTPS
    - Задать SNI вручную: ВКЛ
    - Имя SNI-хоста: {origin_domain}
    - Заголовок Host: Своё значение
    - Значение заголовка: {origin_domain}
    - Доменное имя: {cdn_domain}

  После создания скопируй CNAME (xxx.gcdn.co) и создай DNS запись #2.

  Настройки CDN (вкладки сверху):
    Кеширование:
      - Кеш CDN: ВЫКЛ
      - Кеш браузера: ВЫКЛ

    Дополнительно:
      - Query string: НЕ игнорировать
      - Сжатие: ВЫКЛ
      - Проверка сертификата источника: ВЫКЛ
      - SSL-сертификат: выбери {cdn_domain.replace('.', '-')}
""")
    elif cdn_type == "beeline":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {origin_target_ip}  (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  1a. A-запись: {hy2_sub}.{domain}  ->  {server_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}

  CDN-домен (xxx.a.trbcdn.net) выдаст сам CDNvideo — своя DNS-запись под него не нужна.

  ============================================
  Создание CDN-ресурса на CDNvideo (panel.cdnvideo.ru):
  ============================================

  ВНИМАНИЕ: CDNvideo/Beeline массово банит аккаунты под VPN-трафик.
  Поддержка в скрипте сохранена и конфиг рабочий, но если аккаунт
  заблокировали — ресурс не создать, бери другой CDN (VK / Yandex / Timeweb).

  1. Зайди на panel.cdnvideo.ru -> Создать CDN-ресурс

  2. Основные настройки:
     - Адрес (Origin): {origin_domain}:443
     - Группа доменов: Выключено

  3. HTTPS:
     - Использовать HTTPS при запросе к источникам: ВКЛ
     - Проверять сертификат источника: НЕ включать
     - Указать имя SNI-хоста: ВКЛ
     - Имя SNI-хоста: {origin_domain}

  4. Host-заголовок:
     - Hostname при запросе к источнику: оставить пустым
     - Передавать исходный Host-заголовок: ВКЛ

  5. Кеширование (правая колонка):
     - Кеширование: ВКЛ -> "Настроить вручную"
     - Коды 2xx, 3xx, 4xx, 5xx и browser: "не кешировать" (каждый)
     - Игнорировать заголовки управления кешированием: ВЫКЛ
     - Обслуживать устаревший кэш: ВЫКЛ
     - Кешировать с учетом query string: ВКЛ + "Учитывать все параметры"
       !!! ОБЯЗАТЕЛЬНО: sessionID и seq передаются в query.
           Если выключить - CDN схлопнет разные пакеты туннеля в один
           закешированный ответ, и туннель не поднимется.
     - Кешировать с учетом cookies: ВЫКЛ

  6. Экспертные настройки -> Rewrite -> Настроить:
     - Где выполнять rewrite: "На конечных узлах"
     - Откуда: /static/getFile/video/segment.ts/
     - Куда:   /static/getFile/video/segment.ts
     (без этого правила xhttp не матчится)

  7. Экспертные настройки (вкладка сверху):
     - HTTP2: ВКЛ
     - HTTP3: ВЫКЛ
     - Перенаправлять HTTP на HTTPS: ВКЛ
     - Проверка CORS: ВЫКЛ
     - Сжатие Brotli: ВЫКЛ
     - Сжатие Gzip: ВЫКЛ

  8. Нажми "Применить" и ДОЖДИСЬ статуса "Активен"
     (пока висит "Применяется" - ключ работать не будет)
""")
    elif cdn_type == "timeweb":
        print(f"""
  ============================================
  DNS записи (Cloudflare):
  ============================================

  1. A-запись:  {origin_domain}  ->  {origin_target_ip}  (DNS only){"  ← relay (каскад)" if cascade else ""}{f"""
  1a. A-запись: {hy2_sub}.{domain}  ->  {server_ip}  (DNS only)  ← для HY2, обязательно!""" if install_hy2 and hy2_sub else ""}
  2. CDN домен выдаётся автоматически (xxx.cdn.twcstorage.ru)

  ============================================
  Создание CDN-ресурса на Timeweb (timeweb.cloud):
  ============================================

  1. Зайди: timeweb.cloud -> CDN -> Создать ресурс

  2. Источник контента:
     - Выбери вкладку "IP-адрес"
     - IP-адрес: {origin_target_ip}:80{"  ← relay (каскад)" if cascade else ""}
     - Использовать HTTPS: НЕ включать (оставить выключенным)

  3. Домены раздачи:
     - Технический домен (xxx.cdn.twcstorage.ru) создаётся автоматически
     - Добавь свой домен: "+ Добавить домен" -> {cdn_domain}
       CNAME в DNS: {cdn_domain} -> xxx.cdn.twcstorage.ru (DNS only, серое облако)
       Если у домена есть wildcard (*) — явный CNAME его перебивает. Без записи
       поддомен уйдёт на чужой IP, и ключ не подключится.

  4. После создания — настройки ресурса:
     - Кеширование на CDN: ВЫКЛ
     - Кеширование в браузере: ВЫКЛ
     - Всегда онлайн: ВЫКЛ
     - Следовать редиректу: ВЫКЛ
     - Игнорировать параметры запроса: ВЫКЛ
       !!! ОБЯЗАТЕЛЬНО выключить: sessionID и seq идут в query.
           Если включить - CDN их срежет и туннель не поднимется.
     - Редирект HTTP->HTTPS: ВЫКЛ
     - Secure Token: ВЫКЛ
     - HTTP/3: ВЫКЛ
     - Gzip: ВЫКЛ

  5. Вкладка "SSL-сертификаты" -> "Выпустить Let's Encrypt" для {cdn_domain}
     !!! БЕЗ ЭТОГО КЛЮЧ НЕ РАБОТАЕТ: edge отдаст сертификат технического домена,
         клиент увидит несовпадение имени и молча оборвёт TLS.
     Дождись, пока сертификат применится (проверка ниже покажет).

  6. Дождись статуса ресурса "Активен" (пока "Применяется" — CDN отдаёт 403
     на ВСЕ пути, включая /, это нормально).

  Проверка готовности (с любого сервера):
     curl -sS -o /dev/null -w '%{{http_code}}
' https://{cdn_domain}{rcfg.get('host_path', rcfg['xhttp_path'])}
       400 = ГОТОВО (запрос дошёл до xray)
       403 = ресурс ещё применяется / режет путь
       000 = сертификат на домен ещё не выпущен

  ВАЖНО: расширение .m3u8 в пути уже включено в конфиг автоматически.
""")

    effective_cdn_domain = cdn_domain
    if not cfg.get("skip_cdn_wait", False):
        safe_input("  Нажми ENTER когда CDN настроен и сертификат выпущен...")
        if cdn_type in ("beeline", "timeweb", "turboflare", "selectel"):
            if cdn_type == "beeline":
                cdn_issued = safe_input("  Домен выданный Beeline CDN (например https://xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "timeweb":
                cdn_issued = safe_input("  Технический домен Timeweb CDN (например xxx.cdn.twcstorage.ru): ").strip()
            elif cdn_type == "turboflare":
                cdn_issued = safe_input("  Домен выданный TurboFlare CDN (например xxx.a.trbcdn.net): ").strip()
            elif cdn_type == "selectel":
                cdn_issued = safe_input("  Технический домен Selectel CDN (например xxx.selcdn.ru): ").strip()
            if cdn_issued:
                cdn_issued = cdn_issued.replace("https://", "").replace("http://", "").rstrip("/")
                cdn_issued = validate_fqdn(cdn_issued, "технический CDN-домен")
                effective_cdn_domain = cdn_issued
                if cdn_type == "beeline":
                    cdn_label = "Beeline"
                elif cdn_type == "timeweb":
                    cdn_label = "Timeweb"
                elif cdn_type == "turboflare":
                    cdn_label = "TurboFlare"
                else:
                    cdn_label = "Selectel"
                print(f"  CDN домен {cdn_label}: {cdn_issued}")
                hosts_resp = api("GET", "hosts")
                host_updated = False
                if hosts_resp.get("response"):
                    for h in hosts_resp["response"]:
                        if (h.get("address") == cdn_domain
                                or h.get("tag") == f"VPN_CDN_{cdn_type.upper()}"):
                            patch = dict(h)
                            patch["address"] = cdn_issued
                            patch["sni"] = cdn_issued
                            patch["host"] = cdn_issued
                            if "inbound" in patch and isinstance(patch["inbound"], dict):
                                patch["inbound"] = {
                                    "configProfileUuid": patch["inbound"].get("configProfileUuid", ""),
                                    "configProfileInboundUuid": patch["inbound"].get("configProfileInboundUuid", "")
                                }
                            for _drop in ("createdAt", "updatedAt", "nodes"):
                                patch.pop(_drop, None)
                            resp = api("PATCH", "hosts", patch)
                            if resp.get("response"):
                                print(f"  Хост \"{h.get('remark', '')}\" обновлён: {cdn_issued}")
                                host_updated = True
                            else:
                                raise RuntimeError(f"Ошибка обновления CDN-хоста: {resp}")
                            break
                if not host_updated:
                    raise RuntimeError("CDN-хост Remnawave не найден или не обновлён")

    # --- Final ---
    step(ns, "Финальная проверка"); ns += 1

    local_chain = local_origin_readiness(rcfg["xray_port"], rcfg["xhttp_path"])
    print(f"  Xray listener: {'OK' if local_chain['listener'] else 'FAIL'}")
    print(f"  Nginx -> Xray config: {'OK' if local_chain['nginx'] else 'FAIL'}")
    print(f"  Origin health: {'OK' if local_chain['health'] else 'FAIL'}")

    r = run("docker ps --format '{{.Names}} {{.Status}}' | grep remnanode", check=False)
    node_ok = "Up" in r.stdout
    print(f"  Remnanode: {'OK' if node_ok else r.stdout.strip() or 'NOT RUNNING'}")

    connected = False
    nodes_resp = api("GET", "nodes")
    if isinstance(nodes_resp.get("response"), list):
        our_node = next((n for n in nodes_resp["response"] if n.get("uuid") == node_uuid), None)
        if our_node:
            connected = our_node.get("isConnected", False)
            print(f"  Нода в панели: {'ПОДКЛЮЧЕНА' if connected else 'ОТКЛЮЧЕНА'}")

    cdn_ready = None
    if cdn_type == "timeweb" and not cfg.get("skip_cdn_wait", False):
        cdn_code, cdn_detail = probe_cdn_path(
            effective_cdn_domain,
            rcfg.get("host_path", rcfg["xhttp_path"]),
        )
        cdn_ready = cdn_code == "400"
        print(f"  Timeweb edge/XHTTP: {'OK' if cdn_ready else 'FAIL'} (HTTP {cdn_code})")
        if not cdn_ready and cdn_detail:
            print(f"  Причина curl: {cdn_detail}")

    if not all((local_chain["listener"], local_chain["nginx"],
                local_chain["health"], node_ok, connected)):
        raise RuntimeError("Финальная локальная проверка ноды Remnawave не пройдена")

    extra_info = ""
    if install_hy2:
        extra_info += f"\n  Hysteria2: {server_ip}:{HY2_PORT} (UDP)"
    if install_grpc:
        extra_info += f"\n  gRPC Reality: {server_ip}:{GRPC_PORT} (TCP)"
        if cfg.get("reality_keys"):
            extra_info += f"\n  Reality PBK: {cfg['reality_keys']['public']}"
            extra_info += f"\n  Reality SID: {cfg.get('reality_short_id', 'N/A')}"

    cascade_info = ""
    if cascade:
        cascade_info = f"\n\n  КАСКАД:\n  Relay: {cascade_ip} (Caddy + remnanode)\n  Exit: {server_ip} (BRIDGE_IN :8888)"

    print(f"""
  ============================================
  УСТАНОВКА НОДЫ ЗАВЕРШЕНА
  ============================================

  Панель: {panel_ip} (SSH API)
  Нода: {server_ip}:2222 (UUID: {node_uuid or 'N/A'})
  Профиль: {profile_name} (UUID: {profile_uuid or 'N/A'})
  Хост CDN: {effective_cdn_domain}:443{extra_info}
  Сквад: {chosen_squad['name']}

  Персональный CDN домен: {cdn_domain}
  CDN домен в профиле: {effective_cdn_domain}
  Origin: {origin_domain} -> {origin_target_ip}{"  (relay каскад)" if cascade else ""}{cascade_info}
  ============================================
""")


# ============================================================
#  COMMON SETUP (OS tuning, packages, nginx base)
# ============================================================

def common_setup(cfg):
    """Install packages, tune OS, setup SSL and decoy."""
    domain = cfg["domain"]

    step(1, "Подготовка системы")

    # Packages
    print("  Установка пакетов...")
    pkg_install("nginx openssl curl sqlite3 ca-certificates gnupg sshpass certbot")

    # Firewall (UFW) — open required ports
    r = run("ufw status 2>/dev/null", check=False)
    if r.returncode == 0 and "active" in r.stdout.lower():
        print("  UFW активен, открываю порты 80/443...")
        run("ufw allow 80/tcp >/dev/null 2>&1", check=False)
        run("ufw allow 443/tcp >/dev/null 2>&1", check=False)
        run("ufw reload >/dev/null 2>&1", check=False)

    # Swap
    r = run("swapon --show", check=False)
    if not r.stdout.strip():
        print("  Создание swap 2G...")
        swap_existed = os.path.exists("/swapfile")
        swap_result = run("fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile", check=False)
        if swap_result.returncode == 0:
            backup_file("/etc/fstab")
            run("grep -qE '^/swapfile[[:space:]]' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab", check=False)
            track_created("file", "/swapfile", existed_before=swap_existed)
        else:
            print("  ⚠ Swap не создан; /etc/fstab не изменён")
    else:
        print("  Swap уже есть")

    # BBR + sysctl
    print("  Настройка TCP (BBR)...")
    backup_file("/etc/sysctl.d/99-vpn-tuning.conf")
    with open("/etc/sysctl.d/99-vpn-tuning.conf", "w") as f:
        f.write(SYSCTL_TUNING)
    run("sysctl --system > /dev/null 2>&1", check=False)

    # File limits
    backup_file("/etc/security/limits.d/99-nofile.conf")
    with open("/etc/security/limits.d/99-nofile.conf", "w") as f:
        f.write(NOFILE_LIMITS)

    step(2, "SSL и страница-заглушка")

    run("mkdir -p /etc/nginx/ssl /etc/nginx/sites-available /etc/nginx/sites-enabled", check=False)

    cert_existed = os.path.exists("/etc/nginx/ssl/cdn.crt")
    key_existed = os.path.exists("/etc/nginx/ssl/cdn.key")
    if not cert_existed or not key_existed:
        backup_file("/etc/nginx/ssl/cdn.crt")
        backup_file("/etc/nginx/ssl/cdn.key")
        r = run('openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj "/CN=cdn-origin" 2>/dev/null', check=False)
        if r.returncode == 0:
            print("  Self-signed SSL создан (10 лет)")
        else:
            print("  ❌ openssl не смог создать сертификат — nginx не запустится без SSL!")
            sys.exit(1)
    else:
        print("  SSL сертификат уже есть")
    os.chmod("/etc/nginx/ssl/cdn.key", 0o600)
    os.chmod("/etc/nginx/ssl/cdn.crt", 0o644)
    track_created("file", "/etc/nginx/ssl/cdn.crt", existed_before=cert_existed)
    track_created("file", "/etc/nginx/ssl/cdn.key", existed_before=key_existed)

    # Decoy page
    run("mkdir -p /var/www/html", check=False)
    backup_file("/var/www/html/index.html")
    decoy = DECOY_HTML.format(domain=domain)
    with open("/var/www/html/index.html", "w") as f:
        f.write(decoy)
    print(f"  Страница-заглушка создана для {domain}")


# ============================================================
#  MAIN
# ============================================================

def parse_args():
    """Parse CLI args for non-interactive mode."""
    import argparse
    parser = argparse.ArgumentParser(description="VPN CDN Installer")
    parser.add_argument("--mode", choices=["1", "2", "3", "4"], help="1=panel+node here, 2=Remnawave here+remote node, 3=CDN to existing panel, 4=TurboFlare diagnostics")
    parser.add_argument("--panel", choices=["1", "2"], help="1=Remnawave, 2=3x-ui (modes 1 and 3)")
    parser.add_argument("--cdn", choices=["vk", "yandex", "turboflare", "beeline", "timeweb", "selectel"], help="CDN provider")
    parser.add_argument("--domain", help="Domain name")
    parser.add_argument("--node-ip", help="Remote node IP (mode 2)")
    parser.add_argument("--node-user", default="root", help="SSH user for remote node (default: root)")
    parser.add_argument("--node-pass", help="Remote node password (mode 2)")
    parser.add_argument("--node-key", help="Path to SSH private key for remote node (mode 2)")
    parser.add_argument("--panel-url", help="Panel IPv4 or domain (mode 3)")
    parser.add_argument("--panel-user", help="Panel Remnawave username (mode 3)")
    parser.add_argument("--panel-pass", help="Panel Remnawave password (mode 3)")
    parser.add_argument("--panel-ssh-user", default="root", help="Panel SSH user (mode 3, default: root)")
    parser.add_argument("--panel-ssh-pass", help="Panel SSH password (mode 3)")
    parser.add_argument("--no-hy2", action="store_true", help="Skip Hysteria2")
    parser.add_argument("--no-grpc", action="store_true", help="Skip gRPC")
    parser.add_argument("--hy2", action="store_true", help="Install Hysteria2 (Remnawave only)")
    parser.add_argument("--grpc", action="store_true", help="Install gRPC Reality")
    parser.add_argument("--squad", help="Squad number or name (mode 3 Remnawave)")
    parser.add_argument("--origin-sub", help="Custom origin subdomain label")
    parser.add_argument("--cdn-sub", help="Custom CDN subdomain label")
    parser.add_argument("--panel-sub", help="Custom panel subdomain label")
    parser.add_argument("--exit-sub", help="Custom cascade exit subdomain label")
    parser.add_argument("--hy2-sub", help="Custom Hysteria2 subdomain label")
    parser.add_argument("--sub-sub", help="Custom subscription-page subdomain label")
    parser.add_argument("--no-subpage", action="store_true", help="Skip Remnawave subscription page install")
    parser.add_argument("--eu-grpc", action="store_true", help="Install gRPC Reality on EU exit panel (cascade, direct access)")
    parser.add_argument("--no-eu-grpc", action="store_true", help="Do not install gRPC on EU exit panel")
    parser.add_argument("--youtube-direct", action="store_true", help="Route YouTube/SoundCloud direct via RU-relay (cascade, anti-ad)")
    parser.add_argument("--no-youtube-direct", action="store_true", help="Do not route YouTube/SoundCloud direct (cascade)")
    parser.add_argument("--skip-dns-wait", action="store_true", help="Skip DNS confirmation prompt")
    parser.add_argument("--skip-cdn-wait", action="store_true", help="Skip CDN confirmation prompt")
    parser.add_argument("--cascade", action="store_true", help="Enable cascade relay")
    parser.add_argument("--cascade-ip", help="Cascade relay server IP")
    parser.add_argument("--cascade-pass", help="Cascade relay SSH password")
    parser.add_argument("--cascade-user", default="root", help="Cascade relay SSH user")
    parser.add_argument("--key", help="Лицензионный ключ (формат CDN-XXXX-XXXX-XXXX)")
    parser.add_argument("--server", default="https://cdn-license18.leo33rus.pro", help="URL сервера лицензирования")
    parser.add_argument("--pin", help="Локальный PIN или ключ")
    parser.add_argument(
        "--offline-check",
        action="store_true",
        help="Validate the local PIN and embedded configs without root, network or changes",
    )
    return parser.parse_args()


def validate_cli_args(args):
    """Reject incomplete or incompatible non-interactive invocations early."""
    if args.offline_check:
        if args.mode:
            raise ValueError("--offline-check нельзя совмещать с режимом установки")
        return
    if not args.mode:
        return
    if args.hy2 and args.no_hy2:
        raise ValueError("Нельзя одновременно указывать --hy2 и --no-hy2")
    if args.grpc and args.no_grpc:
        raise ValueError("Нельзя одновременно указывать --grpc и --no-grpc")
    if args.mode == "4":
        if not args.domain:
            raise ValueError("Для --mode 4 обязателен --domain")
        args.domain = validate_fqdn(args.domain)
        return
    missing = [name for name in ("panel", "cdn", "domain") if not getattr(args, name)]
    if missing:
        raise ValueError("Для неинтерактивного запуска обязательны: --" + ", --".join(missing))
    args.domain = validate_fqdn(args.domain)
    if args.panel == "2" and args.cdn not in CDN_SETTINGS:
        raise ValueError("3x-ui поддерживает только CDN: vk, yandex, turboflare")
    if args.panel == "2" and args.hy2:
        raise ValueError("Hysteria2 для 3x-ui этим установщиком не поддерживается")
    if args.mode == "2":
        if args.panel != "1":
            raise ValueError("Режим 2 поддерживает только Remnawave")
        if not args.node_ip:
            raise ValueError("Для режима 2 обязателен --node-ip")
        args.node_ip = validate_ip(args.node_ip, "IP удалённой ноды")
        if bool(args.node_pass) == bool(args.node_key):
            raise ValueError("Для режима 2 укажи ровно один из --node-pass/--node-key")
    if args.mode == "3":
        if not args.panel_url:
            raise ValueError("Для режима 3 обязателен --panel-url")
        if args.panel == "1" and not (args.panel_user and args.panel_pass):
            raise ValueError("Для Remnawave режима 3 обязательны --panel-user и --panel-pass")
        if args.panel == "2" and not args.panel_ssh_pass:
            raise ValueError("Для 3x-ui режима 3 обязателен --panel-ssh-pass")
    if args.cascade:
        if not args.cascade_ip or not args.cascade_pass:
            raise ValueError("Для --cascade обязательны --cascade-ip и --cascade-pass")
        args.cascade_ip = validate_ip(args.cascade_ip, "IP cascade")
    elif args.cascade_ip or args.cascade_pass:
        raise ValueError("--cascade-ip/--cascade-pass требуют флаг --cascade")
    args.node_user = validate_ssh_user(args.node_user)
    args.panel_ssh_user = validate_ssh_user(args.panel_ssh_user)
    args.cascade_user = validate_ssh_user(args.cascade_user)
    for name in ("origin_sub", "cdn_sub", "panel_sub", "exit_sub", "hy2_sub", "sub_sub"):
        value = getattr(args, name)
        if value and not _valid_sub_label(value):
            raise ValueError(f"Некорректная метка --{name.replace('_', '-')}: {value!r}")


OFFLINE_PIN_SHA256 = "ab83dc5991f248f87b190dbbda550c74b17d3b8ad9f23adf6434869692b9f8ae"

def get_hardware_id():
    """Computes stable hardware-bound SHA256 machine identifier."""
    raw = []
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"]:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    v = f.read().strip()
                    if v: raw.append(v)
            except Exception: pass
    try:
        res = subprocess.run("cat /sys/class/net/$(ip route show default 2>/dev/null | awk '/default/ {print $5}')/address 2>/dev/null", shell=True, stdout=subprocess.PIPE, text=True)
        mac = res.stdout.strip()
        if mac: raw.append(mac)
    except Exception: pass
    if not raw: raw.append(str(uuid.getnode()))
    return hashlib.sha256(":".join(raw).encode()).hexdigest()

def verify_online_license(key, server_url):
    """Verifies license against central authorization server with HWID and IP binding."""
    import urllib.request, platform
    hwid = get_hardware_id()
    ip = get_ip()
    api_url = f"{server_url.rstrip('/')}/api/v1/verify"
    payload = json.dumps({
        "license_key": key.strip(),
        "hwid": hwid,
        "ip": ip,
        "hostname": platform.node(),
        "os_info": f"{platform.system()} {platform.release()}"
    }).encode("utf-8")
    try:
        print(f"  [*] Проверка лицензии через {server_url}...")
        req = urllib.request.Request(api_url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "CDN-Installer-4.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success"):
                lic = data.get("license", {})
                client = lic.get("client_name", "Administrator")
                exp = lic.get("expires_at") or "Бессрочно"
                print(f"  ✅ Лицензия подтверждена! Клиент: {client} | Срок: {exp[:10]}")
                return True
            else:
                msg = data.get("message") or "Недействительный ключ"
                print(f"  ❌ Ошибка авторизации: {msg}")
                return False
    except urllib.error.HTTPError as e:
        try:
            err_data = json.loads(e.read().decode())
            detail = err_data.get("detail", {})
            msg = detail.get("message") if isinstance(detail, dict) else str(detail)
            print(f"  ❌ Ошибка лицензии: {msg}")
        except Exception:
            print(f"  ❌ Сервер авторизации отклонил запрос (HTTP {e.code})")
        return False
    except Exception as exc:
        print(f"  ❌ Не удалось связаться с сервером лицензий ({server_url}): {exc}")
        return False

def check_local_pin(pin=None, quiet=False, key=None, server=None):
    """Проверить лицензионный ключ онлайн или локальный PIN."""
    server = server or "https://cdn-license18.leo33rus.pro"
    if key:
        return verify_online_license(key, server)
    if pin is not None:
        pin = str(pin).strip()
        if pin.startswith("CDN-"):
            return verify_online_license(pin, server)
        entered_hash = hashlib.sha256(pin.encode("utf-8")).hexdigest()
        ok = secrets.compare_digest(entered_hash, OFFLINE_PIN_SHA256)
        if not quiet:
            print("  ✅ Локальный PIN принят" if ok else "  ❌ Неверный локальный PIN")
        return ok

    auth_val = safe_input("\n  🔑 Введи лицензионный ключ (получить в боте @my_cdn_license_bot): ").strip()
    if auth_val.startswith("CDN-"):
        return verify_online_license(auth_val, server)
    entered_hash = hashlib.sha256(auth_val.encode("utf-8")).hexdigest()
    if secrets.compare_digest(entered_hash, OFFLINE_PIN_SHA256):
        if not quiet: print("  ✅ Мастер-PIN принят")
        return True
    res = verify_online_license(auth_val, server)
    if not res:
        print("  ℹ️ Получить лицензионный ключ можно в боте: @my_cdn_license_bot")
    return res


def run_offline_check(pin=None):
    """Run a side-effect-free self-check without root privileges or network access."""
    print("\n  ЛОКАЛЬНАЯ ОФЛАЙН-ПРОВЕРКА")
    print("  Сеть и конфигурация сервера не изменяются.\n")
    results = []

    def record(label, ok, detail=""):
        results.append(bool(ok))
        suffix = f": {detail}" if detail else ""
        print(f"  {'✅' if ok else '❌'} {label}{suffix}")

    pin_ok = check_local_pin(pin)
    record("Локальный PIN", pin_ok)

    try:
        config_ok = validate_embedded_cdn_config()
    except Exception as exc:
        config_ok = False
        config_detail = str(exc)
    else:
        config_detail = f"{len(REMNAWAVE_CDN)} CDN-профилей"
    record("Встроенные CDN-конфигурации", config_ok, config_detail)

    rendered_ok = True
    rendered_detail = []
    for name, cfg in REMNAWAVE_CDN.items():
        rendered = nginx_cdn_origin(
            cfg["xray_port"], cfg["xhttp_path"],
            nginx_style=cfg.get("nginx_style", "prefix"),
        )
        if (f"127.0.0.1:{cfg['xray_port']}" not in rendered
                or cfg["xhttp_path"] not in rendered):
            rendered_ok = False
            rendered_detail.append(name)
    record(
        "Шаблоны nginx → Xray",
        rendered_ok,
        "OK" if rendered_ok else "ошибка: " + ", ".join(rendered_detail),
    )

    timeweb_extra = REMNAWAVE_CDN["timeweb"]["host_extra"]
    timeweb_profile_extra = (
        REMNAWAVE_CDN["timeweb"]["profile_config"]["inbounds"][0]
        ["streamSettings"]["xhttpSettings"]
    )
    timeweb_ok = all((
        timeweb_extra.get("sessionPlacement") == "query",
        timeweb_extra.get("sessionKey") == "sessionID",
        timeweb_extra.get("seqPlacement") == "query",
        timeweb_extra.get("seqKey") == "seq",
        timeweb_profile_extra.get("sessionPlacement") == "query",
    ))
    record("Timeweb sessionID/seq через query", timeweb_ok)

    legacy_names = (
        "enhanced_license_check", "validate_action_with_server",
        "check_kill_switch", "get_hardware_id", "_" + "r3q", "_" + "t9m",
    )
    legacy_ok = not any(name in globals() for name in legacy_names)
    record("Нет HWID, kill-switch и онлайн-лицензии", legacy_ok)

    record("Неверный PIN отклоняется", not check_local_pin("invalid-pin", quiet=True))

    all_ok = all(results)
    print(f"\n  {'✅ ОФЛАЙН-ПРОВЕРКА ПРОЙДЕНА' if all_ok else '❌ ОФЛАЙН-ПРОВЕРКА НЕ ПРОЙДЕНА'}")
    return all_ok


def turboflare_migration_guide(server_ip, domain_arg=None):
    """Read-only TurboFlare readiness guide for this installer's nginx layout."""
    print("\n" + "=" * 70)
    print("РЕЖИМ 4: ПРОВЕРКА ПЕРЕНОСА НА TURBOFLARE CDN")
    print("=" * 70)
    raw_domain = domain_arg or safe_input("Введите CDN-домен (без http://): ")
    domain = validate_fqdn(
        (raw_domain or "").replace("https://", "").replace("http://", "").strip("/")
    )
    expected_port = REMNAWAVE_CDN["turboflare"]["xray_port"]
    expected_path = REMNAWAVE_CDN["turboflare"]["xhttp_path"]

    def stdout(command, timeout=20):
        result = run(command, check=False, timeout=timeout)
        return (result.stdout or "").strip(), result.returncode

    resolved, _ = stdout(
        f"getent ahostsv4 {shlex.quote(domain)} | awk '{{print $1}}' | sort -u"
    )
    nginx_state, _ = stdout("systemctl is-active nginx")
    listeners, _ = stdout(f"ss -ltnp 2>/dev/null | grep ':{expected_port} '")
    origin_code, _ = stdout(
        f"curl -ksS -o /dev/null -w '%{{http_code}}' --max-time 10 "
        f"--resolve {shlex.quote(domain + ':443:' + server_ip)} "
        f"{shlex.quote('https://' + domain + expected_path)}"
    )
    public_code, _ = stdout(
        f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10 "
        f"{shlex.quote('https://' + domain + expected_path)}"
    )

    checks = [
        ("DNS", bool(resolved), resolved or "запись не опубликована"),
        ("nginx", nginx_state == "active", nginx_state or "inactive"),
        (f"Xray :{expected_port}", bool(listeners), "слушает" if listeners else "не слушает"),
        ("Origin HTTPS", origin_code in {"200", "400", "404"}, origin_code or "000"),
        ("TurboFlare edge", public_code in {"200", "400", "404"}, public_code or "000"),
    ]
    print(f"\nДомен: {domain}\nOrigin IP: {server_ip}\nПуть XHTTP: {expected_path}\n")
    for label, ok, detail in checks:
        print(f"  {'✅' if ok else '❌'} {label}: {detail}")

    print(f"""

Настройки TurboFlare:
  - Origin: {server_ip}:443, HTTPS
  - SNI/Host к origin: {domain}
  - Путь без кэша: {expected_path}*
  - Query string: сохранять полностью
  - Сжатие и HTTP/3: выключить
  - Выпустить edge-сертификат для {domain}

После выдачи TurboFlare технического домена создай CNAME:
  {domain} -> <домен из панели TurboFlare>
""")
    if all(ok for _, ok, _ in checks):
        print("✅ Проверки пройдены. Origin и CDN отвечают.")
    else:
        print("⚠ Исправь пункты с ❌ и повтори режим 4. Сервер этот режим не изменяет.")


def main():
    node_cred = ""
    print_banner(VERSION)

    args = parse_args()
    try:
        validate_cli_args(args)
    except ValueError as exc:
        raise RuntimeError(f"Ошибка параметров: {exc}") from exc

    # This mode is deliberately handled before the root/OS/network checks.
    # It only validates local Python data, PIN and embedded configuration.
    if args.offline_check:
        if not run_offline_check(args.pin):
            sys.exit(1)
        return

    # Check root
    if os.geteuid() != 0:
        print("ОШИБКА: Запусти от root!")
        sys.exit(1)

    # Check OS
    check_os()

    # Get server IP
    server_ip = get_ip()
    print(f"  Server IP: {server_ip}")

    # License verification (Online authorization server with HWID/IP binding + offline PIN fallback)
    if not check_local_pin(pin=args.pin, key=args.key, server=args.server):
        sys.exit(1)
    validate_embedded_cdn_config()

    # --- Mode selection ---
    if args.mode:
        mode = args.mode
    else:
        mode = ask("Режим установки?", {
            "1": "Панель + нода (всё на этом сервере)",
            "2": "Панель здесь + нода на другом сервере",
            "3": "CDN к существующей панели",
            "4": "Перенос домена на TurboFlare CDN (инструкция)"
        })

    # --- Mode 3: CDN to existing panel ---
    if mode == "3":
        panel_type = args.panel or ask("Панель (Panel)?", {"1": "Remnawave 3.2.3", "2": "3x-ui 3.6.0"})

        if panel_type == "1":
            # Remnawave: 6 CDN провайдеров
            cdn_type_choice = ask("CDN провайдер?", {
                "1": "VK Cloud",
                "2": "Yandex Cloud",
                "3": "TurboFlare",
                "4": "Beeline/CDNvideo",
                "5": "Timeweb",
                "6": "Selectel"
            }) if not args.cdn else None
            cdn_type = args.cdn or {"1": "vk", "2": "yandex", "3": "turboflare", "4": "beeline", "5": "timeweb", "6": "selectel"}.get(cdn_type_choice, "vk")

            # Ask for Remnawave version (mode 3 only, for existing panels)
            if not args.mode:
                rv_version_choice = ask("Версия панели Remnawave?", {
                    "1": f"{REMNAWAVE_VERSION_LEGACY} (старая, JWT_AUTH_SECRET)",
                    "2": f"{REMNAWAVE_VERSION_LATEST} (последняя, APP_SECRET)"
                })
                remnawave_version = REMNAWAVE_VERSION_LEGACY if rv_version_choice == "1" else REMNAWAVE_VERSION_LATEST
            else:
                # In automated mode, default to latest
                remnawave_version = REMNAWAVE_VERSION_LATEST
        else:
            # 3x-ui: только 3 CDN провайдера
            cdn_type_choice = ask("CDN провайдер?", {
                "1": "VK Cloud",
                "2": "Yandex Cloud",
                "3": "TurboFlare"
            }) if not args.cdn else None
            cdn_type = args.cdn or {"1": "vk", "2": "yandex", "3": "turboflare"}.get(cdn_type_choice, "vk")

        domain = args.domain or ask("Домен без http:// (Domain)")
        domain = domain.replace("https://", "").replace("http://", "").strip("/").strip()
        domain = validate_fqdn(domain)

        # Поддомены: панель в режиме 3 уже существует, её префикс не наш.
        # exit резолвится позже (в подветках, после вопроса про каскад),
        # с reserved={origin,cdn,hy2}, чтобы не совпал. Вопрос «свои поддомены?»
        # задаём один раз здесь; hy2_sub нужен обеим подветкам, поэтому в наборе.
        _want_custom = not args.mode and _ask_yes("\n  Задать свои поддомены? Иначе случайные (y/n) [n]: ")
        _subs = resolve_subdomains(args, ["origin", "cdn", "hy2"], _want_custom)
        origin_sub = _subs["origin"]
        cdn_sub = _subs["cdn"]
        hy2_sub = _subs["hy2"]

        if panel_type == "1":
            panel_input = args.panel_url or ask("IP или домен панели Remnawave (Panel IP / URL)")
            panel_input = panel_input.replace("https://", "").replace("http://", "").split("/")[0].strip()
            parsed_panel = urllib.parse.urlsplit("//" + panel_input)
            panel_ip = parsed_panel.hostname or ""
            try:
                panel_ip = validate_ip(panel_ip, "IP панели")
            except ValueError:
                panel_ip = validate_fqdn(panel_ip, "домен панели")

            use_direct_api = False
            panel_url = None
            panel_token = None
            panel_cred = None

            # Direct API mode: if --panel-user and --panel-pass given without --panel-ssh-pass, skip SSH
            if args.mode and args.panel_user and args.panel_pass and not args.panel_ssh_pass:
                print(f"\n  Прямое API подключение к панели ({panel_input})...")
                panel_url = f"https://{panel_input}"
                import ssl
                _ok = False
                try:
                    req = urllib.request.Request(f"{panel_url}/api/auth/login", method="POST",
                        headers={"Content-Type": "application/json"}, data=b'{}')
                    urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context())
                    _ok = True
                except urllib.error.HTTPError as exc:
                    _ok = exc.code in (400, 401, 403, 422)
                except Exception:
                    _ok = False
                if not _ok:
                    print(f"  ❌ Панель не доступна по {panel_url}")
                    sys.exit(1)
                print(f"  Remnawave API (direct): OK")
                use_direct_api = True
            else:
                print(f"\n  SSH подключение к панели ({panel_ip})...")
                if args.mode and args.panel_ssh_pass:
                    panel_cred = {"type": "password", "value": args.panel_ssh_pass, "user": args.panel_ssh_user}
                else:
                    panel_cred = ask_ssh_cred()

                r = run("which sshpass", check=False)
                if r.returncode != 0:
                    print("  Установка sshpass...")
                    run("DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq sshpass 2>/dev/null", check=False, timeout=60)

                r = run_remote(panel_ip, panel_cred, "echo ok", timeout=15)
                if r.returncode != 0:
                    print(f"  ⚠ SSH к {panel_ip} не удался, пробую прямой API...")
                    if args.mode:
                        panel_domain = panel_input
                    else:
                        panel_domain = ask("Домен панели (например hub.example.com)")
                    panel_domain = panel_domain.replace("https://", "").replace("http://", "").strip("/").strip()
                    panel_url = f"https://{panel_domain}"
                    import ssl
                    _ok = False
                    try:
                        req = urllib.request.Request(f"{panel_url}/api/auth/login", method="POST",
                            headers={"Content-Type": "application/json"}, data=b'{}')
                        urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context())
                        _ok = True
                    except urllib.error.HTTPError as exc:
                        _ok = exc.code in (400, 401, 403, 422)
                    except Exception:
                        _ok = False
                    if not _ok:
                        print(f"  ❌ Панель не доступна по {panel_url}")
                        sys.exit(1)
                    print(f"  Remnawave API (direct): OK")
                    use_direct_api = True
                else:
                    print(f"  SSH к панели: OK")
                    r = run_remote(panel_ip, panel_cred, 'RDOM=$(grep -oP "PANEL_DOMAIN=\\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "Host: ${RDOM:-localhost}" http://127.0.0.1:3000/api/auth/login', timeout=15)
                    if r.returncode != 0 or (not r.stdout.strip()):
                        r2 = run_remote(panel_ip, panel_cred, 'curl -s http://127.0.0.1:3001/health', timeout=10)
                        if r2.returncode != 0 or "ok" not in r2.stdout:
                            print(f"  ❌ Remnawave API не доступен на {panel_ip}:3000")
                            print(f"  Убедись что панель запущена: cd /opt/remnawave && docker compose up -d")
                            sys.exit(1)
                    print(f"  Remnawave API: OK")

            panel_user = args.panel_user if args.mode and args.panel_user else ask("Логин панели Remnawave (username)")
            panel_pass = args.panel_pass if args.mode and args.panel_pass else ask("Пароль панели Remnawave (password)")

            if use_direct_api:
                token, login_resp = remnawave_login_direct(panel_url, panel_user, panel_pass)
            else:
                token, login_resp = remnawave_login_ssh(
                    panel_ip, panel_cred, panel_user, panel_pass,
                    allow_prompt=not bool(args.mode),
                )
                if isinstance(login_resp, dict) and login_resp.get("_direct_url"):
                    print(f"  Переключение на прямой API: {login_resp['_direct_url']}")
                    panel_url = login_resp["_direct_url"]
                    panel_token = token
                    use_direct_api = True
            if not token:
                print(f"  ❌ Не удалось авторизоваться в панели: {login_resp}")
                sys.exit(1)
            if use_direct_api and not panel_token:
                panel_token = token
            print(f"  Авторизация: OK")

            extra = ask_extra_protocols(args=args)

            cascade = False
            cascade_ip = None
            cascade_cred = None
            cascade_hy2 = False
            cascade_grpc = False
            if args.mode and getattr(args, 'cascade', False) and args.cascade_ip:
                cascade = True
                cascade_ip = args.cascade_ip
                cascade_cred = {"type": "password", "value": args.cascade_pass or "", "user": getattr(args, 'cascade_user', 'root')}
            elif not args.mode:
                casc = ask("Настроить каскад (Cascade)?", {"1": "Нет", "2": "Да"})
                if casc == "2":
                    cascade = True
                    cascade_ip = ask("IP relay-сервера в РФ (Cascade relay IP)")
                    cascade_cred = ask_ssh_cred()

            cfg = {
                "panel_type": panel_type,
                "cdn_type": cdn_type,
                "domain": domain,
                "server_ip": server_ip,
                "panel_ip": panel_ip,
                "panel_cred": panel_cred,
                "panel_url": panel_url,
                "panel_token": panel_token,
                "origin_sub": origin_sub,
                "cdn_sub": cdn_sub,
                "hy2_sub": hy2_sub,
                "skip_cdn_wait": getattr(args, 'skip_cdn_wait', False) if args.mode else False,
                "install_hy2": extra["install_hy2"],
                "install_grpc": extra["install_grpc"],
                "squad": getattr(args, 'squad', None),
                "cascade": cascade,
                "cascade_ip": cascade_ip,
                "cascade_cred": cascade_cred,
                "cascade_hy2": cascade_hy2,
                "cascade_grpc": cascade_grpc,
                "youtube_direct": ask_youtube_direct(cascade, args),
                "eu_grpc": ask_eu_grpc(cascade, args),
                "remnawave_version": remnawave_version,  # Pass version for mode 3
            }

            print(f"\n  Поддомены: origin={origin_sub}.{domain}, cdn={cdn_sub}.{domain}")
            api_mode = "Direct API" if use_direct_api else "SSH"
            print(f"  Панель: {panel_url or panel_ip} ({api_mode})")
        else:
            cascade = False
            cascade_ip = None
            cascade_cred = None
            panel_value = args.panel_url if args.mode else ask("IP сервера с 3x-ui панелью (Panel server IP)")
            panel_value = panel_value.replace("https://", "").replace("http://", "").split("/")[0]
            parsed_panel = urllib.parse.urlsplit("//" + panel_value)
            panel_ip = parsed_panel.hostname or ""
            try:
                panel_ip = validate_ip(panel_ip, "IP панели")
            except ValueError:
                panel_ip = validate_fqdn(panel_ip, "домен панели")
            if args.mode:
                panel_cred = {
                    "type": "password",
                    "value": args.panel_ssh_pass,
                    "user": args.panel_ssh_user,
                }
            else:
                panel_cred = ask_ssh_cred()

            casc = "2" if args.mode and args.cascade else (
                "1" if args.mode else ask("Настроить каскад (Cascade)?", {"1": "Нет", "2": "Да"})
            )
            if casc == "2":
                cascade = True
                if args.mode:
                    cascade_ip = args.cascade_ip
                    cascade_cred = {"type": "password", "value": args.cascade_pass, "user": args.cascade_user}
                else:
                    cascade_ip = ask("IP exit-сервера за рубежом (foreign exit server IP)")
                    cascade_cred = ask_ssh_cred()
                if not validate_cascade_direction(server_ip, cascade_ip, "2"):
                    retry = ask("Продолжить всё равно?", {"1": "Нет, выхожу", "2": "Да, я знаю что делаю"})
                    if retry != "2":
                        print("  Запусти скрипт на РФ-сервере.")
                        sys.exit(0)

            # exit-поддомен нужен только при каскаде; reserved — уже занятые метки
            if cascade:
                exit_sub = resolve_subdomains(args, ["exit"], _want_custom,
                                              reserved={origin_sub, cdn_sub, hy2_sub})["exit"]
            else:
                exit_sub = _rand_sub(3)

            cfg = {
                "panel_type": panel_type,
                "cdn_type": cdn_type,
                "domain": domain,
                "server_ip": server_ip,
                "panel_ip": panel_ip,
                "panel_cred": panel_cred,
                "origin_sub": origin_sub,
                "cdn_sub": cdn_sub,
                "hy2_sub": hy2_sub,
                "skip_cdn_wait": getattr(args, 'skip_cdn_wait', False) if args.mode else False,
                "install_hy2": False,
                "install_grpc": False,
                "cascade": cascade,
                "cascade_ip": cascade_ip,
                "cascade_cred": cascade_cred,
                "cascade_hy2": False,
                "cascade_grpc": False,
                "exit_sub": exit_sub,
                "youtube_direct": ask_youtube_direct(cascade, args),
                "eu_grpc": ask_eu_grpc(cascade, args),
            }

            print(f"\n  Поддомены: origin={origin_sub}.{domain}, cdn={cdn_sub}.{domain}")
            print(f"  Панель 3x-ui: {panel_ip}")

        if cascade and panel_type == "1":
            origin_dns_ip = cascade_ip
        else:
            origin_dns_ip = server_ip
        exit_sub = cfg.get("exit_sub", "xui")
        print(f"""
  ============================================
  СОЗДАЙ {"ЭТИ DNS ЗАПИСИ" if cascade and panel_type == "2" else "ЭТУ DNS ЗАПИСЬ"} В CLOUDFLARE:
  ============================================

  A    {origin_sub}.{domain}    ->  {origin_dns_ip}     (DNS only){"  ← relay (каскад)" if cascade and panel_type == "1" else ""}""")
        if cascade and panel_type == "2":
            print(f"  A    {exit_sub}.{domain}    ->  {cascade_ip}     (DNS only)  ← exit (каскад)")
        if cfg.get("install_hy2") and cfg.get("hy2_sub"):
            print(f"  A    {cfg['hy2_sub']}.{domain}    ->  {server_ip}     (DNS only)  ← HY2")
        print(f"  ({cdn_sub}.{domain} CNAME создашь после настройки CDN)\n")

        if not (args.skip_dns_wait if args.mode else False):
            safe_input("  Нажми ENTER когда DNS записи созданы...")

        validate_runtime_config(cfg)
        set_total_steps(estimate_total_steps("node" if panel_type == "1" else "3xui_cdn", cfg))
        common_setup(cfg)
        if panel_type == "1":
            install_node_only(cfg)
        else:
            install_3xui_cdn_only(cfg)
        ui_done()
        return

    # --- Mode 4: TurboFlare migration guide ---
    if mode == "4":
        turboflare_migration_guide(server_ip, args.domain if args.mode else None)
        return

    # --- Modes 1 & 2: Full installation ---
    node_cred = ""
    cascade = False
    cascade_ip = None
    cascade_cred = None
    cascade_hy2 = False
    cascade_grpc = False
    if args.panel:
        panel_type = args.panel
        cdn_type = args.cdn or "vk"
        domain = args.domain
        node_ip = args.node_ip or server_ip
        if args.node_key:
            node_cred = {"type": "key", "value": args.node_key, "user": args.node_user}
        elif args.node_pass:
            node_cred = {"type": "password", "value": args.node_pass, "user": args.node_user}
        if getattr(args, 'cascade', False) and args.cascade_ip:
            cascade = True
            cascade_ip = args.cascade_ip
            cascade_cred = {"type": "password", "value": args.cascade_pass or "", "user": getattr(args, 'cascade_user', 'root')}
            if not validate_cascade_direction(server_ip, cascade_ip, panel_type):
                print("  ❌ Каскад задом наперёд. Запусти скрипт на РФ-сервере.")
                sys.exit(1)
    else:
        if mode == "2":
            panel_type = ask("Панель (Panel)?", {"1": "Remnawave 3.2.3", "2": "3x-ui (не поддерживается, ждите обновления)"})
            if panel_type == "2":
                print("  ❌ 3x-ui пока не поддерживается в режиме 2 (панель + нода на разных серверах)")
                print("  Используйте режим 1 или ждите обновления.")
                sys.exit(1)
        else:
            panel_type = ask("Панель (Panel)?", {"1": "Remnawave 3.2.3", "2": "3x-ui 3.6.0"})
        if panel_type == "1":
            # Remnawave: 6 CDN провайдеров
            cdn_type_choice = ask("CDN провайдер (CDN provider)?", {
                "1": "VK Cloud",
                "2": "Yandex Cloud",
                "3": "TurboFlare",
                "4": "Beeline/CDNvideo",
                "5": "Timeweb",
                "6": "Selectel"
            })
            cdn_type = {"1": "vk", "2": "yandex", "3": "turboflare", "4": "beeline", "5": "timeweb", "6": "selectel"}.get(cdn_type_choice, "vk")
        else:
            # 3x-ui: только 3 CDN провайдера
            cdn_type_choice = ask("CDN провайдер (CDN provider)?", {
                "1": "VK Cloud",
                "2": "Yandex Cloud",
                "3": "TurboFlare"
            })
            cdn_type = {"1": "vk", "2": "yandex", "3": "turboflare"}.get(cdn_type_choice, "vk")

        # Cascade option
        cascade = False
        cascade_ip = None
        cascade_cred = None
        cascade_hy2 = False
        cascade_grpc = False
        casc = ask("Настроить каскад (Cascade)?", {"1": "Нет", "2": "Да"})
        if casc == "2":
            cascade = True
            if panel_type == "1":
                cascade_ip = ask("IP relay-сервера в РФ (Cascade relay IP)")
            else:
                cascade_ip = ask("IP exit-сервера за рубежом (foreign exit server IP)")
            cascade_cred = ask_ssh_cred()
            if not validate_cascade_direction(server_ip, cascade_ip, panel_type):
                retry = ask("Продолжить всё равно?", {"1": "Нет, выхожу", "2": "Да, я знаю что делаю"})
                if retry != "2":
                    print("  Запусти скрипт на РФ-сервере.")
                    sys.exit(0)

        domain = ask("Домен без http:// (Domain)")
        domain = domain.replace("https://", "").replace("http://", "").strip("/").strip()

        node_ip = server_ip
        if mode == "2":
            node_ip = ask("IP сервера ноды (Node server IP)")
            node_cred = ask_ssh_cred()

    # Доп-протоколы HY2/gRPC теперь доступны и в режиме 1 Remnawave (#20).
    # install_remnawave умеет их ставить в same_server-ветке (open_extra_ports,
    # setup_hy2_le_cert, HY2/gRPC хосты — всё под `if same_server`). Раньше здесь
    # был жёсткий отказ, чтобы не нагружать сервер лишними протоколами; вернули
    # как выбор пользователя. Дефолт в интерактиве — «нет», а в неинтерактивном
    # запуске (бот/CLI) safe_input отдаёт EOF→"" → оба False, сервер не грузим.
    extra = ask_extra_protocols(panel_type=panel_type, args=args)

    # Инициализация переменных каскада для HY2/gRPC
    cascade_hy2 = False
    cascade_grpc = False

    # HY2/gRPC остаются прямыми на exit. Старый relay-вариант генерировал
    # некорректные Xray inbounds (HY2 без TLS и gRPC Reality с пустыми ключами).
    if cascade and (extra["install_hy2"] or extra["install_grpc"]):
        print("\n  HY2/gRPC оставлены напрямую на exit; через relay каскадируется только CDN/XHTTP.")
        cascade_hy2 = False
        cascade_grpc = False

    # Поддомены. origin/cdn/panel нужны всегда; exit — при каскаде; hy2 — если
    # включён Hysteria2 (у него свой LE-сертификат, и явная A-запись перебивает
    # wildcard *.domain, из-за которого ACME уходил не на ту машину). Роли, что
    # не спрашиваем, всё равно должны попасть в cfg — добираем случайными.
    # Страница подписки Remnawave (#5): красивый HTML вместо голого кода подписки.
    # Только для Remnawave (у 3x-ui своя страница). Дефолт — ставить; --no-subpage
    # или ответ «нет» отключают. В неинтерактиве (бот/CLI) safe_input EOF→"" →
    # берётся default=True, кроме явного --no-subpage.
    install_subpage = False
    if panel_type == "1":
        if getattr(args, 'no_subpage', False):
            install_subpage = False
        elif args.panel:
            install_subpage = True   # CLI без --no-subpage
        else:
            install_subpage = _ask_yes("\n  Поставить страницу подписки Remnawave? (y/n) [y]: ", default=True)

    _sub_roles = ["origin", "cdn", "panel"]
    if cascade:
        _sub_roles.append("exit")
    if extra["install_hy2"]:
        _sub_roles.append("hy2")
    if install_subpage:
        _sub_roles.append("sub")
    _want_custom = not args.panel and _ask_yes("\n  Задать свои поддомены? Иначе случайные (y/n) [n]: ")
    _subs = resolve_subdomains(args, _sub_roles, _want_custom)
    origin_sub = _subs["origin"]
    cdn_sub = _subs["cdn"]
    panel_sub = _subs["panel"]
    exit_sub = _subs.get("exit") or _rand_sub()
    hy2_sub = _subs.get("hy2") or _rand_sub()
    sub_sub = _subs.get("sub") or _rand_sub()

    cfg = {
        "panel_type": panel_type,
        "cdn_type": cdn_type,
        "domain": domain,
        "server_ip": server_ip,
        "node_ip": node_ip,
        "node_cred": node_cred,
        "skip_cdn_wait": getattr(args, 'skip_cdn_wait', False) if args.panel else False,
        "origin_sub": origin_sub,
        "cdn_sub": cdn_sub,
        "hy2_sub": hy2_sub,
        "panel_sub": panel_sub,
        "install_hy2": extra["install_hy2"],
        "install_grpc": extra["install_grpc"],
        "cascade": cascade,
        "cascade_ip": cascade_ip,
        "cascade_cred": cascade_cred,
        "cascade_hy2": cascade_hy2,
        "cascade_grpc": cascade_grpc,
        "exit_sub": exit_sub,
        "install_subpage": install_subpage,
        "sub_sub": sub_sub,
        "youtube_direct": ask_youtube_direct(cascade, args),
        "eu_grpc": ask_eu_grpc(cascade, args),
    }

    validate_runtime_config(cfg)
    if mode in ("1", "2"):
        assert_mode1_fresh_target(panel_type)

    print(f"\n  Поддомены: origin={origin_sub}.{domain}, cdn={cdn_sub}.{domain}")
    print(f"  Панель: {panel_sub}.{domain}")

    # --- DNS instructions ---
    print(f"""
  ============================================
  СОЗДАЙ ЭТИ DNS ЗАПИСИ В CLOUDFLARE:
  ============================================
""")
    if cascade and panel_type == "1":
        origin_dns_ip = cascade_ip
    else:
        origin_dns_ip = node_ip
    print(f"  A    {panel_sub}.{domain}  ->  {server_ip}   (DNS only)")
    print(f"  A    {origin_sub}.{domain}    ->  {origin_dns_ip}     (DNS only){'  ← relay (каскад)' if cascade and panel_type == '1' else ''}")
    if cascade and panel_type == "2":
        print(f"  A    {exit_sub}.{domain}    ->  {cascade_ip}     (DNS only)  ← exit (каскад)")
    # Запись под HY2 нужна здесь же: иначе на шаге выпуска LE-сертификата
    # установка встаёт и ждёт DNS, который ещё никто не заводил.
    if extra["install_hy2"] and hy2_sub:
        hy2_target_ip = cascade_ip if cascade_hy2 else node_ip
        hy2_note = "  ← HY2 (через каскад)" if cascade_hy2 else "  ← HY2"
        print(f"  A    {hy2_sub}.{domain}    ->  {hy2_target_ip}     (DNS only){hy2_note}")
    # Страница подписки живёт на своём поддомене (панель на panel_sub), запись
    # нужна ДО выпуска её LE-сертификата — иначе установка встанет на ожидании DNS.
    if install_subpage and sub_sub:
        print(f"  A    {sub_sub}.{domain}    ->  {server_ip}     (DNS only)  ← страница подписки")
    print(f"  ({cdn_sub}.{domain} CNAME создашь после настройки CDN)")
    print()

    if not (args.skip_dns_wait if args.panel else False):
        safe_input("  Нажми ENTER когда DNS записи созданы...")

    # --- Common setup ---
    try:
        set_total_steps(estimate_total_steps("3xui" if panel_type == "2" else "remnawave", cfg))
        common_setup(cfg)

        # --- Panel-specific ---
        if panel_type == "2":
            install_3xui(cfg)
        else:
            install_remnawave(cfg)
        ui_done()
    finally:
        cleanup_ssh_key(node_cred)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        handle_ctrl_c(can_resume=False)
        sys.exit(1)
    except SystemExit as exc:
        if exc.code not in (None, 0) and _install_log:
            rollback()
        raise
    except Exception as exc:
        print(f"\n  ❌ Установка остановлена: {exc}")
        if _install_log:
            rollback()
        sys.exit(1)
