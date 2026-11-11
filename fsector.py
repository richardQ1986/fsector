#!/usr/bin/env python3
"""
Fsector - Pentest tools over Tor
A blue-team friendly wrapper around nmap, nikto, and whatweb via Tor.
Version 1.6.2 - Bugfix release: NEWNYM ACK, web tool DNS, preflight, tor proc conflict.
"""

import os
import sys
import time
import json
import shutil
import socket
import subprocess
import tempfile
import re
import atexit
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
    )
    from rich.text import Text
    from rich.live import Live
    from rich import box
except ImportError:
    print("[!] Missing dependency: rich\n    pip install rich", file=sys.stderr)
    sys.exit(1)


APP_NAME = "Fsector"
VERSION = "1.6.2"

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_COOKIE_PATH = "/var/run/tor/control.authcookie"
TOR_STARTUP_TIMEOUT = 30
ROTATION_WAIT = 15
ROTATION_MAX_WAIT = 45          # FIX #10: پویا تا این حد صبر می‌کنیم
SENSITIVE_PORTS = {"22", "23", "445", "3389", "3306", "5432", "6379", "9200", "27017"}

console = Console()

_temp_files = []

def _cleanup_temp():
    for p in _temp_files:
        try:
            os.unlink(p)
        except OSError:
            pass

atexit.register(_cleanup_temp)

BANNER = r"""
███████╗███████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
█████╗  ███████╗███████╗██║        ██║   ██║   ██║██████╔╝
██╔══╝  ╚════██║╚════██║██║        ██║   ██║   ██║██╔══██╗
██║     ███████║███████║╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝     ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""

TOOLS = {
    "1": {"name": "nmap",    "desc": "Port & service scanner (via Tor)",
          "binaries": ["nmap"]},
    "2": {"name": "nikto",   "desc": "Web server vulnerability scanner (via Tor)",
          "binaries": ["nikto"]},
    "3": {"name": "whatweb", "desc": "Web technology fingerprinting (via Tor)",
          "binaries": ["whatweb"]},
}

SCAN_PLANS = {
    "1": {
        "name": "Paranoid (T0) - Maximum stealth",
        "flags": ["-T0", "--max-parallelism", "1", "-p", "22,80,443,3389"],
        "desc": "Slowest, minimal noise. May take hours. Best for strict IDS.",
        "warning": "This scan can take HOURS. Only use on small port sets.",
    },
    "2": {
        "name": "Sneaky (T1) - Very stealthy",
        "flags": ["-T1", "--max-parallelism", "1", "--top-ports", "100"],
        "desc": "15s delay per probe. Good balance of stealth and time.",
        "warning": None,
    },
    "3": {
        "name": "Polite (T2) - Balanced",
        "flags": ["-T2", "--top-ports", "100"],
        "desc": "Low bandwidth, less aggressive. Reasonable for Tor.",
        "warning": None,
    },
    "4": {
        "name": "Aggressive (T4) - Fast",
        "flags": ["-T4", "--top-ports", "1000"],
        "desc": "Faster, more noise. Simulates an impatient attacker.",
        "warning": "This generates more traffic and may trigger IDS alerts.",
    },
}


@dataclass
class PortResult:
    port: str
    protocol: str
    state: str
    service: str = "-"
    version: str = "-"


@dataclass
class ScanSummary:
    target: str
    exit_ip: str = "unknown"
    elapsed: float = 0.0
    ports: list = field(default_factory=list)


def show_banner_animated() -> None:
    lines = BANNER.strip("\n").split("\n")
    with Live(console=console, refresh_per_second=30, transient=False) as live:
        for i, line in enumerate(lines):
            for j in range(0, len(line) + 1, 8):
                partial = "\n".join(lines[:i] + [line[:j]])
                live.update(Text(partial, style="bold cyan"))
                time.sleep(0.012)
        live.update(Text("\n".join(lines), style="bold cyan"))
    console.print(Text.assemble(
        ("  🧅 ", "bold"),
        (APP_NAME, "bold cyan"),
        (f" v{VERSION}", "dim"),
        ("  ·  ", "dim"),
        ("Pentest tools over Tor", "italic dim"),
    ))
    console.print()


def check_binary(name: str) -> bool:
    return shutil.which(name) is not None


# FIX #4: preflight پویا — فقط ابزارهای موردنیاز همان اسکن
def preflight(required: Optional[list] = None) -> bool:
    """
    اگر required داده شود، فقط همان باینری‌ها چک می‌شوند.
    در غیر این صورت، پیش‌نیازهای پایه بررسی می‌شوند.
    """
    base = ["tor", "proxychains4", "curl", "tor-resolve"]
    needed = list(base)
    if required:
        for b in required:
            if b not in needed:
                needed.append(b)

    ok = True
    for binary in needed:
        if check_binary(binary):
            console.print(f"  [green]✓[/] {binary}")
        else:
            console.print(f"  [red]✗[/] {binary} [yellow](not found)[/]")
            ok = False
    return ok


def port_is_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(host: str, port: int, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_is_open(host, port):
            return True
        time.sleep(0.5)
    return False


# FIX #9: start_tor دیگر پروسهٔ دستی نمی‌سازد اگر سرویس systemd فعال است
def _tor_service_active() -> bool:
    try:
        r = subprocess.run(["systemctl", "is-active", "--quiet", "tor"],
                           capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def start_tor() -> Optional[subprocess.Popen]:
    if port_is_open(TOR_SOCKS_HOST, TOR_SOCKS_PORT):
        console.print("  [dim]Tor already listening on :9050[/]")
        return None

    # FIX #9: اگر سرویس tor موجود است، از systemctl استفاده کن، نه پروسهٔ دستی
    if _tor_service_active():
        console.print("  [dim]Starting tor service via systemctl...[/]")
        try:
            subprocess.run(["systemctl", "start", "tor"], check=True,
                           capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            console.print(f"  [red]✗[/] systemctl start tor failed: {e.stderr.strip()[:200]}")
            return None
        if wait_for_port(TOR_SOCKS_HOST, TOR_SOCKS_PORT, TOR_STARTUP_TIMEOUT):
            console.print("  [green]✓[/] Tor service ready on :9050")
            return None  # مالک پروسه نیستیم؛ در finally هم terminate نمی‌کنیم
        console.print("  [red]✗[/] Tor service failed to open SOCKS port")
        return None

    console.print("  [dim]Launching tor...[/]")
    try:
        proc = subprocess.Popen(
            ["tor",
             "--SocksPort", str(TOR_SOCKS_PORT),
             "--ControlPort", str(TOR_CONTROL_PORT)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        console.print("  [red]✗[/] tor binary not found")
        return None

    if not wait_for_port(TOR_SOCKS_HOST, TOR_SOCKS_PORT, TOR_STARTUP_TIMEOUT):
        console.print("  [red]✗[/] Tor failed to open SOCKS port in time")
        proc.terminate()
        return None

    console.print("  [green]✓[/] Tor SOCKS5 ready on :9050")
    return proc


def ensure_control_port() -> bool:
    if port_is_open(TOR_SOCKS_HOST, TOR_CONTROL_PORT, timeout=1.0):
        return True

    console.print("  [yellow]![/] ControlPort :9051 not open")
    console.print("  [dim]IP rotation and exit IP display need this.[/]")

    if os.geteuid() != 0:
        console.print("  [dim]Tip: run with sudo to enable it automatically.[/]")
        return False

    if not Confirm.ask("  Auto-enable ControlPort in /etc/tor/torrc?", default=True):
        return False

    torrc = "/etc/tor/torrc"
    try:
        with open(torrc, "r") as f:
            content = f.read()
    except FileNotFoundError:
        console.print(f"  [red]✗[/] {torrc} not found")
        return False

    has_control = any(
        line.strip().startswith("ControlPort") and not line.strip().startswith("#")
        for line in content.splitlines()
    )
    has_cookie = any(
        line.strip().startswith("CookieAuthentication") and not line.strip().startswith("#")
        for line in content.splitlines()
    )

    changed = False
    if not has_control:
        content += "\nControlPort 9051\n"
        changed = True
    if not has_cookie:
        content += "CookieAuthentication 1\n"
        changed = True

    if not changed:
        console.print("  [yellow]![/] Lines seem present but port still closed.")
        console.print("  [dim]Check /etc/tor/torrc manually and restart tor.[/]")
        return False

    try:
        shutil.copy(torrc, torrc + ".fsector.bak")
        with open(torrc, "w") as f:
            f.write(content)
        console.print("  [green]✓[/] /etc/tor/torrc updated (backup: .fsector.bak)")
        console.print("  [dim]Restarting tor...[/]")
        result = subprocess.run(
            ["systemctl", "restart", "tor"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            console.print(f"  [red]✗[/] systemctl failed: {result.stderr.strip()[:200]}")
            return False
        time.sleep(3)

        if port_is_open(TOR_SOCKS_HOST, TOR_CONTROL_PORT, timeout=2.0):
            console.print("  [green]✓[/] ControlPort now open")
            return True
        console.print("  [red]✗[/] Port still closed after restart")
        return False
    except Exception as e:
        console.print(f"  [red]✗[/] Failed: {e}")
        return False


# FIX #3: پاسخ NEWNYM را می‌خوانیم و تأیید می‌کنیم
def _control_read(sock: socket.socket, size: int = 4096) -> bytes:
    sock.settimeout(5)
    try:
        return sock.recv(size)
    except socket.timeout:
        return b""


def send_newnym() -> bool:
    cookie_hex = ""
    try:
        with open(TOR_COOKIE_PATH, "rb") as f:
            cookie_bytes = f.read()

        if len(cookie_bytes) != 32:
            console.print(f"  [red]✗[/] Cookie size is {len(cookie_bytes)}, expected 32")
            return False

        cookie_hex = cookie_bytes.hex()
    except PermissionError:
        console.print("  [red]✗[/] Permission denied reading cookie. Run with sudo.")
        return False
    except FileNotFoundError:
        console.print("  [dim]No cookie file, trying passwordless auth...[/]")

    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_CONTROL_PORT), timeout=3) as s:
            # مرحله ۱: احراز هویت
            if cookie_hex:
                s.sendall(f"AUTHENTICATE {cookie_hex}\r\n".encode())
            else:
                s.sendall(b"AUTHENTICATE\r\n")
            auth_resp = _control_read(s)
            if not auth_resp.startswith(b"250"):
                console.print(f"  [red]✗[/] AUTHENTICATE failed: {auth_resp[:120]!r}")
                return False

            # مرحله ۲: SIGNAL NEWNYM
            s.sendall(b"SIGNAL NEWNYM\r\n")
            newnym_resp = _control_read(s)
            if not newnym_resp.startswith(b"250"):
                console.print(f"  [red]✗[/] NEWNYM failed: {newnym_resp[:120]!r}")
                return False

            s.sendall(b"QUIT\r\n")
            return True
    except OSError as e:
        console.print(f"  [red]✗[/] Socket error: {e}")
        return False


# FIX #10: صبر پویا تا تغییر IP (با timeout سخت)
def rotate_and_wait(min_seconds: int = ROTATION_WAIT,
                    max_seconds: int = ROTATION_MAX_WAIT) -> tuple:
    old_ip = get_exit_ip()

    if not send_newnym():
        return False, old_ip, old_ip

    console.print(f"  [dim]Waiting for new circuit (min {min_seconds}s, max {max_seconds}s)...[/]")

    new_ip = old_ip
    start = time.time()
    with Progress(
        SpinnerColumn("growVertical", style="bold cyan", speed=1.0),
        TextColumn("[bold cyan]Building new Tor circuits"),
        TextColumn("[dim]·[/]"),
        TextColumn("[green]{task.fields[elapsed]}s[/]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("rotate", total=None, elapsed=0)
        while True:
            elapsed = int(time.time() - start)
            progress.update(task, elapsed=elapsed)
            time.sleep(1)
            elapsed = int(time.time() - start)

            # حداقل زمان را صبر می‌کنیم، بعد IP را چک می‌کنیم
            if elapsed < min_seconds:
                continue

            new_ip = get_exit_ip()
            if new_ip != "unknown" and new_ip != old_ip:
                break
            if elapsed >= max_seconds:
                break

    return True, old_ip, new_ip


def get_exit_ip() -> str:
    endpoints = [
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "https://check.torproject.org/api/ip",
    ]
    for url in endpoints:
        try:
            out = subprocess.check_output(
                ["curl", "-s", "--max-time", "30",
                 "--socks5-hostname", f"{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
                 url],
                stderr=subprocess.DEVNULL,
            ).decode().strip()

            if out.startswith("{"):
                try:
                    data = json.loads(out)
                    ip = data.get("IP") or data.get("ip")
                    if ip and ip != "unknown":
                        return ip
                except json.JSONDecodeError:
                    pass
            elif out and len(out) < 64 and "." in out:
                return out
        except Exception:
            continue
    return "unknown"


# FIX #1: tor-resolve فقط برای اعتبارسنجی؛ نام دامنه برای ابزارهای وب حفظ می‌شود
def resolve_target_via_tor(target: str) -> Optional[str]:
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target):
        return target

    console.print(f"  [dim]Validating DNS for {target} via Tor...[/]")
    try:
        result = subprocess.check_output(
            ["tor-resolve", target],
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).decode().strip()

        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", result):
            console.print(f"  [green]✓[/] DNS OK (resolved via Tor: [cyan]{result}[/])")
            return result
        else:
            console.print(f"  [yellow]![/] tor-resolve returned unexpected: {result}")
            return None
    except subprocess.TimeoutExpired:
        console.print("  [red]✗[/] tor-resolve timed out")
        return None
    except FileNotFoundError:
        console.print("  [red]✗[/] tor-resolve not found.")
        return None
    except subprocess.CalledProcessError as e:
        console.print(f"  [red]✗[/] tor-resolve failed: {e}")
        return None


# FIX #5: دامنه‌های تک‌برچسبی و localhost پذیرفته می‌شوند
def validate_target(target: str) -> Optional[str]:
    ipv4_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ipv4_re.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return None
        return "Invalid IPv4 address (octet > 255)"

    # برچسب‌های تک (localhost, intranet) + دامنه‌های چندبرچسبی + کاراکترهای مجاز
    domain_re = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
    if domain_re.match(target):
        return None

    return "Invalid target (not a valid IP or domain)"


def write_proxychains_conf() -> str:
    fd, path = tempfile.mkstemp(prefix="fsector_", suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write(
            "strict_chain\n"
            "proxy_dns\n"
            "remote_dns_subnet 224\n"
            "tcp_read_time_out 15000\n"
            "tcp_connect_time_out 8000\n"
            "[ProxyList]\n"
            f"socks5 {TOR_SOCKS_HOST} {TOR_SOCKS_PORT}\n"
        )
    _temp_files.append(path)
    return path


# --- nmap ---
# FIX #8: فقط پورت‌های باز/فیلترشده برگردانده می‌شوند (closed حذف)
def parse_nmap_xml(xml_str: str) -> list:
    root = ET.fromstring(xml_str)
    results = []
    for port in root.findall(".//port"):
        state_el = port.find("state")
        service_el = port.find("service")
        state = state_el.get("state") if state_el is not None else "unknown"

        # closed را نگه نمی‌داریم تا JSON سبک بماند
        if state == "closed":
            continue

        service = "-"
        version = "-"
        if service_el is not None:
            service = service_el.get("name", "-")
            product = service_el.get("product", "")
            ver = service_el.get("version", "")
            version = f"{product} {ver}".strip() or "-"

        results.append(PortResult(
            port=port.get("portid", "?"),
            protocol=port.get("protocol", "tcp"),
            state=state,
            service=service,
            version=version,
        ))
    return results


def run_nmap_via_tor(target: str, conf_path: str, plan: dict) -> tuple:
    cmd = [
        "proxychains4", "-f", conf_path, "-q",
        "nmap", "-sT", "-Pn", "-n", "-oX", "-",
        *plan["flags"],
        target,
    ]
    console.print(f"[dim]$ {' '.join(cmd)}[/]")

    start = time.time()
    try:
        with Progress(
            SpinnerColumn("growVertical", style="bold cyan", speed=1.2),
            TextColumn("[bold cyan]Scanning via Tor..."),
            BarColumn(bar_width=None, style="cyan", complete_style="green"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("scan", total=None)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    except subprocess.TimeoutExpired:
        console.print("[red]✗ Scan timed out[/]")
        return [], time.time() - start
    except KeyboardInterrupt:
        console.print("\n[yellow]![/] Scan interrupted by user")
        return [], time.time() - start

    elapsed = time.time() - start

    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        if "proxychains" in err.lower():
            console.print(f"[red]✗ proxychains error:[/] {err[:300]}")
            console.print("[dim]Hint: is Tor running on :9050?[/]")
        elif "nmap" in err.lower():
            console.print(f"[red]✗ nmap error:[/] {err[:300]}")
        else:
            console.print(f"[red]✗ Scan failed:[/] {err[:300]}")
        return [], elapsed

    xml_out = proc.stdout
    idx = xml_out.find("<?xml")
    if idx >= 0:
        xml_out = xml_out[idx:]

    try:
        results = parse_nmap_xml(xml_out)
    except ET.ParseError as e:
        console.print(f"[red]✗ Failed to parse nmap XML:[/] {e}")
        return [], elapsed

    return results, elapsed


# --- nikto ---
# FIX #1: نام دامنه ارسال می‌شود (نه IP)؛ FIX #6: پارس بهتر
def run_nikto_via_tor(target: str, conf_path: str) -> tuple:
    cmd = [
        "proxychains4", "-f", conf_path, "-q",
        "nikto", "-h", target, "-nointeractive", "-Format", "txt",
    ]
    console.print(f"[dim]$ {' '.join(cmd)}[/]")

    start = time.time()
    try:
        with Progress(
            SpinnerColumn("growVertical", style="bold cyan", speed=1.2),
            TextColumn("[bold cyan]Running Nikto via Tor..."),
            BarColumn(bar_width=None, style="cyan", complete_style="green"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("scan", total=None)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        console.print("[red]✗ Nikto timed out[/]")
        return [], time.time() - start
    except KeyboardInterrupt:
        console.print("\n[yellow]![/] Nikto interrupted by user")
        return [], time.time() - start

    elapsed = time.time() - start

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip()[:500] or "unknown error"
        console.print(f"[red]✗ nikto error:[/] {err}")
        return [], elapsed

    output = proc.stdout.strip()
    findings = []
    for line in output.splitlines():
        s = line.strip()
        # FIX #6: خطوط + و - و هشدارها را بگیر (نه فقط + با :)
        if s.startswith("+ ") or s.startswith("- "):
            text = s[2:].strip()
            if text and not text.lower().startswith(("target ip", "target hostname",
                                                     "target port", "start time",
                                                     "end time", "server:", "no cgi")):
                findings.append(text)

    # FIX #6: version به‌جای ۲۰۰ کاراکتر خام، خلاصهٔ معنادار
    details = f"{len(findings)} findings"
    if findings:
        preview = " | ".join(findings[:3])
        if len(findings) > 3:
            preview += f" (+{len(findings) - 3} more)"
        details = preview[:300]

    results = [PortResult(
        port="nikto",
        protocol="-",
        state="findings" if findings else "info",
        service=f"{len(findings)} findings" if findings else "no findings",
        version=details,
    )] if output else []

    return results, elapsed


# --- whatweb ---
# FIX #1: نام دامنه؛ FIX #7: از فایل موقت برای JSON استفاده می‌کنیم تا آلودگی proxychains مشکل نسازد
def run_whatweb_via_tor(target: str, conf_path: str) -> tuple:
    fd, json_path = tempfile.mkstemp(prefix="fsector_whatweb_", suffix=".json")
    os.close(fd)
    _temp_files.append(json_path)

    cmd = [
        "proxychains4", "-f", conf_path, "-q",
        "whatweb", "-a", "1", "--no-errors",
        "--log-json", json_path, target,
    ]
    console.print(f"[dim]$ {' '.join(cmd)}[/]")

    start = time.time()
    try:
        with Progress(
            SpinnerColumn("growVertical", style="bold cyan", speed=1.2),
            TextColumn("[bold cyan]Running WhatWeb via Tor..."),
            BarColumn(bar_width=None, style="cyan", complete_style="green"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("scan", total=None)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        console.print("[red]✗ WhatWeb timed out[/]")
        return [], time.time() - start
    except KeyboardInterrupt:
        console.print("\n[yellow]![/] WhatWeb interrupted by user")
        return [], time.time() - start

    elapsed = time.time() - start

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip()[:500] or "unknown error"
        console.print(f"[red]✗ whatweb error:[/] {err}")
        return [], elapsed

    # FIX #7: خواندن از فایل، نه stdout (که ممکن است با پیام proxychains آلوده شود)
    raw = ""
    try:
        with open(json_path, "r") as f:
            raw = f.read().strip()
    except OSError:
        pass

    if not raw:
        console.print("  [yellow]![/] whatweb produced no JSON output")
        return [], elapsed

    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            plugins = data.get("plugins", {})
            techs = ", ".join(plugins.keys())[:100]
            results.append(PortResult(
                port="whatweb",
                protocol="-",
                state="detected",
                service=techs or "none",
                version=f"{len(plugins)} plugins",
            ))
        except json.JSONDecodeError:
            # FIX #7: هشدار می‌دهیم تا کاربر بداند چیزی از دست رفته
            console.print(f"  [dim]skip non-JSON line: {line[:80]}[/]")
            continue

    return results, elapsed


# --- جدول و منو ---
def style_state(state: str) -> str:
    return {
        "open":          "[bold green]🟢 open[/]",
        "closed":        "[bold red]🔴 closed[/]",
        "filtered":      "[bold yellow]🟡 filtered[/]",
        "open|filtered": "[bold yellow]🟡 open|filtered[/]",
        "findings":      "[bold yellow]📋 findings[/]",
        "detected":      "[bold cyan]🔎 detected[/]",
        "critical":      "[bold red]🚨 critical[/]",
        "high":          "[bold red]🔴 high[/]",
        "medium":        "[bold yellow]🟡 medium[/]",
        "low":           "[bold blue]🔵 low[/]",
        "info":          "[dim]ℹ info[/]",
    }.get(state, state)


# FIX #14: فقط برای پورت‌های عددی nmap؛ برای nikto/whatweb اعمال نمی‌شود
def style_port(port: str) -> str:
    if port.isdigit() and port in SENSITIVE_PORTS:
        return f"[bold red]{port}[/]"
    return f"[green]{port}[/]"


def render_table(summary: ScanSummary, tool_name: str) -> None:
    open_count = sum(1 for p in summary.ports if p.state == "open")
    closed_count = sum(1 for p in summary.ports if p.state == "closed")
    filtered_count = sum(1 for p in summary.ports if "filtered" in p.state)
    findings_count = sum(1 for p in summary.ports if p.state in ("findings", "detected", "critical", "high", "medium", "low", "info"))

    caption = (
        f"Target: [bold]{summary.target}[/]  ·  "
        f"Exit IP: [magenta]{summary.exit_ip}[/]  ·  "
        f"[green]{open_count} open[/] / "
        f"[red]{closed_count} closed[/] / "
        f"[yellow]{filtered_count} filtered[/] / "
        f"[cyan]{findings_count} findings[/]  ·  "
        f"[dim]{summary.elapsed:.1f}s[/]"
    )

    table = Table(
        title=f"🔍 {tool_name.upper()} Results via Tor",
        title_style="bold cyan",
        caption=caption,
        caption_style="dim",
        header_style="bold magenta",
        border_style="bright_blue",
        box=box.ROUNDED,
    )
    table.add_column("Port/Item", justify="center", no_wrap=True)
    table.add_column("State", justify="center", no_wrap=True)
    table.add_column("Service", style="cyan")
    table.add_column("Details", style="white", overflow="fold")

    shown = [p for p in summary.ports if p.state != "closed"]
    if not shown:
        table.add_row("-", "[dim]no results[/]", "-", "-")
    else:
        for p in shown:
            table.add_row(
                style_port(p.port),
                style_state(p.state),
                p.service,
                p.version,
            )

    console.print()
    console.print(table)


def choose_tool() -> str:
    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        box=box.SIMPLE,
    )
    table.add_column("#", justify="center", style="cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Description", style="dim")
    for key, info in TOOLS.items():
        table.add_row(key, info["name"], info["desc"])

    console.print(table)
    choice = Prompt.ask("Select tool [cyan]number[/]", choices=list(TOOLS.keys()))
    return TOOLS[choice]["name"]


def choose_plan() -> dict:
    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        box=box.SIMPLE,
    )
    table.add_column("#", justify="center", style="cyan")
    table.add_column("Plan", style="bold")
    table.add_column("Description", style="dim")
    for key, plan in SCAN_PLANS.items():
        table.add_row(key, plan["name"], plan["desc"])

    console.print(table)
    choice = Prompt.ask("Select plan [cyan]number[/]", choices=list(SCAN_PLANS.keys()))
    plan = SCAN_PLANS[choice]

    if plan["warning"]:
        console.print(f"  [yellow]⚠ {plan['warning']}[/]")
        if not Confirm.ask("  Continue?", default=False):
            return choose_plan()

    return plan


def main() -> int:
    show_banner_animated()

    console.rule("[bold cyan]1/6 · Preflight")
    # FIX #4: ابتدا فقط پیش‌نیازهای پایه، بعد از انتخاب ابزار، باینری اختصاصی چک می‌شود
    if not preflight():
        console.print("\n[red]Missing base dependencies. Run:[/]")
        console.print("  [yellow]sudo bash install.sh[/]")
        return 1

    console.rule("[bold cyan]2/6 · Starting Tor")
    tor_proc = start_tor()
    if tor_proc is None and not port_is_open(TOR_SOCKS_HOST, TOR_SOCKS_PORT):
        console.print("[red]✗ Tor not available. Aborting.[/]")
        return 1

    try:
        console.rule("[bold cyan]3/6 · ControlPort & identity")
        control_ok = ensure_control_port()

        if control_ok and send_newnym():
            console.print("  [green]✓[/] NEWNYM acknowledged by Tor")
        else:
            console.print("  [yellow]![/] IP rotation disabled (ControlPort unavailable)")

        current_ip = get_exit_ip()
        if current_ip != "unknown":
            console.print(f"  [green]✓[/] Current exit IP: [magenta]{current_ip}[/]")
        else:
            console.print("  [yellow]![/] Could not determine exit IP")

        console.rule("[bold cyan]4/6 · Configure scan")
        tool = choose_tool()

        # FIX #4: چک باینری اختصاصی همان ابزار
        if not preflight(TOOLS[[k for k, v in TOOLS.items() if v["name"] == tool][0]]["binaries"]):
            console.print(f"[red]✗ Missing binary for {tool}. Aborting.[/]")
            return 1

        plan = None
        if tool == "nmap":
            console.print("\n  [bold]Select scan plan:[/]")
            plan = choose_plan()
            console.print(f"  [green]✓[/] Plan: [cyan]{plan['name']}[/]")

        target = Prompt.ask("  Target [cyan](IP or domain, no https://)[/]").strip()
        if not target:
            console.print("[red]✗ Empty target[/]")
            return 1

        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):].rstrip("/")
                console.print(f"  [dim]→ using {target}[/]")

        err = validate_target(target)
        if err:
            console.print(f"[red]✗ {err}[/]")
            return 1

        # FIX #1: DNS را با Tor اعتبارسنجی می‌کنیم، اما برای ابزارهای وب نام دامنه را نگه می‌داریم
        resolved_ip = resolve_target_via_tor(target)
        if not resolved_ip:
            console.print("[red]✗ Could not resolve target via Tor. Aborting to prevent DNS leak.[/]")
            return 1

        # انتخاب هدفی که به ابزار داده می‌شود
        scan_target = resolved_ip if tool == "nmap" else target
        if tool != "nmap":
            console.print(f"  [dim]Passing hostname to {tool} (DNS tunneled via proxychains)[/]")

        console.rule("[bold cyan]5/6 · Rotate identity before scan?")
        if control_ok:
            console.print(
                f"  [dim]A fresh Tor circuit gives a new exit IP, "
                f"but it takes ~{ROTATION_WAIT}s to build.[/]"
            )
            do_rotate = Confirm.ask(
                f"  Rotate IP now and wait up to {ROTATION_MAX_WAIT}s before scanning?",
                default=True,
            )

            if do_rotate:
                console.print("  [dim]Requesting new identity from Tor...[/]")
                success, old_ip, new_ip = rotate_and_wait(ROTATION_WAIT, ROTATION_MAX_WAIT)

                if not success:
                    console.print("  [red]✗[/] Rotation failed")
                    if not Confirm.ask("  Continue with current IP?", default=True):
                        return 1
                elif old_ip == new_ip and new_ip != "unknown":
                    # FIX #2: پیام دقیق‌تر — ممکن است Tor مدار جدید ساخته باشد ولی IP یکی باشد
                    console.print(f"  [yellow]![/] Exit IP unchanged: {new_ip} (new circuit may share exit)")
                elif old_ip == new_ip == "unknown":
                    console.print("  [yellow]![/] Could not verify IP before/after rotation")
                else:
                    console.print(
                        f"  [green]✓[/] Exit IP changed: "
                        f"[dim]{old_ip}[/] → [magenta]{new_ip}[/]"
                    )
                    current_ip = new_ip
            else:
                console.print(f"  [dim]Using current IP {current_ip}[/]")
        else:
            console.print("  [dim]Skipping rotation (ControlPort unavailable)[/]")

        if not Confirm.ask(
            f"\n  Run [bold]{tool}[/] against [bold]{target}[/] via Tor?",
            default=True,
        ):
            console.print("[yellow]Aborted by user.[/]")
            return 0

        console.rule("[bold cyan]6/6 · Executing")
        conf = write_proxychains_conf()
        # FIX #11: try/finally بی‌معنی حذف شد؛ atexit مسئول پاک‌سازی است
        if tool == "nmap":
            ports, elapsed = run_nmap_via_tor(scan_target, conf, plan)
        elif tool == "nikto":
            ports, elapsed = run_nikto_via_tor(scan_target, conf)
        elif tool == "whatweb":
            ports, elapsed = run_whatweb_via_tor(scan_target, conf)
        else:
            console.print(f"[red]✗ Unknown tool: {tool}[/]")
            return 1

        summary = ScanSummary(
            target=f"{target} ({resolved_ip})" if resolved_ip != target else target,
            exit_ip=current_ip,
            elapsed=elapsed,
            ports=ports,
        )
        render_table(summary, tool)

        safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
        default_path = f"fsector_{tool}_{safe}_{int(time.time())}.json"
        with open(default_path, "w") as f:
            json.dump({
                "tool": tool,
                "plan": plan["name"] if plan else None,
                "target": summary.target,
                "exit_ip": summary.exit_ip,
                "elapsed": round(summary.elapsed, 2),
                "results": [p.__dict__ for p in summary.ports],
            }, f, indent=2)
        console.print(f"[green]✓[/] Results saved to [cyan]{default_path}[/]")

        if Confirm.ask("\n[dim]Save a copy elsewhere?[/]", default=False):
            custom_path = Prompt.ask("  Path")
            try:
                shutil.copy(default_path, custom_path)
                console.print(f"[green]✓[/] Copied to [cyan]{custom_path}[/]")
            except Exception as e:
                console.print(f"[red]✗ Copy failed: {e}[/]")

    finally:
        if tor_proc is not None:
            console.print("\n[dim]Stopping Tor...[/]")
            tor_proc.terminate()
            try:
                tor_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tor_proc.kill()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")
        sys.exit(130)