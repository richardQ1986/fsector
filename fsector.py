
#!/usr/bin/env python3
"""
Fsector - Pentest tools over Tor
A blue-team friendly wrapper around nmap via Tor SOCKS5.
"""

import os
import sys
import time
import json
import shutil
import socket
import subprocess
import tempfile
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
VERSION = "1.4"

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_COOKIE_PATH = "/var/run/tor/control.authcookie"
TOR_STARTUP_TIMEOUT = 30
ROTATION_WAIT = 15
SENSITIVE_PORTS = {"22", "23", "445", "3389", "3306", "5432", "6379", "9200", "27017"}

console = Console()

BANNER = r"""
███████╗███████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
█████╗  ███████╗███████╗██║        ██║   ██║   ██║██████╔╝
██╔══╝  ╚════██║╚════██║██║        ██║   ██║   ██║██╔══██╗
██║     ███████║███████║╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝     ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""

TOOLS = {
    "1": {"name": "nmap", "desc": "Port & service scanner (via Tor)"},
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


def preflight() -> bool:
    ok = True
    for binary in ("tor", "proxychains4", "nmap", "curl"):
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


def start_tor() -> Optional[subprocess.Popen]:
    if port_is_open(TOR_SOCKS_HOST, TOR_SOCKS_PORT):
        console.print("  [dim]Tor already listening on :9050[/]")
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


def send_newnym() -> bool:
    """Authenticate with Tor using cookie file, then send NEWNYM."""
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
        # No cookie — try passwordless AUTHENTICATE (works if auth is disabled)
        console.print("  [dim]No cookie file, trying passwordless auth...[/]")
        cookie_hex = ""

    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_CONTROL_PORT), timeout=3) as s:
            if cookie_hex:
                cmd = f"AUTHENTICATE {cookie_hex}\r\nSIGNAL NEWNYM\r\nQUIT\r\n"
            else:
                cmd = "AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT\r\n"
            s.sendall(cmd.encode())
            time.sleep(2)
        return True
    except OSError as e:
        console.print(f"  [red]✗[/] Socket error: {e}")
        return False


def rotate_and_wait(wait_seconds: int = ROTATION_WAIT) -> tuple:
    old_ip = get_exit_ip()

    if not send_newnym():
        return False, old_ip, old_ip

    with Progress(
        SpinnerColumn("growVertical", style="bold cyan", speed=1.0),
        TextColumn("[bold cyan]Building new Tor circuits"),
        TextColumn("[dim]·[/]"),
        TextColumn("[green]{task.fields[remaining]}s remaining[/]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "rotate",
            total=wait_seconds,
            remaining=wait_seconds,
        )
        for i in range(wait_seconds):
            time.sleep(1)
            progress.update(task, remaining=wait_seconds - (i + 1))
            progress.advance(task)

    new_ip = get_exit_ip()
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
    return path


def parse_nmap_xml(xml_str: str) -> list:
    root = ET.fromstring(xml_str)
    results = []
    for port in root.findall(".//port"):
        state_el = port.find("state")
        service_el = port.find("service")
        state = state_el.get("state") if state_el is not None else "unknown"

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
        "nmap", "-sT", "-Pn", "-oX", "-",
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

    elapsed = time.time() - start

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip()[:500] or "unknown error"
        console.print(f"[red]✗ nmap error:[/] {err}")
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


def style_state(state: str) -> str:
    return {
        "open":          "[bold green]🟢 open[/]",
        "closed":        "[bold red]🔴 closed[/]",
        "filtered":      "[bold yellow]🟡 filtered[/]",
        "open|filtered": "[bold yellow]🟡 open|filtered[/]",
    }.get(state, state)


def style_port(port: str) -> str:
    if port in SENSITIVE_PORTS:
        return f"[bold red]{port}[/]"
    return f"[green]{port}[/]"


def render_table(summary: ScanSummary) -> None:
    open_count = sum(1 for p in summary.ports if p.state == "open")
    closed_count = sum(1 for p in summary.ports if p.state == "closed")
    filtered_count = sum(1 for p in summary.ports if "filtered" in p.state)

    caption = (
        f"Target: [bold]{summary.target}[/]  ·  "
        f"Exit IP: [magenta]{summary.exit_ip}[/]  ·  "
        f"[green]{open_count} open[/] / "
        f"[red]{closed_count} closed[/] / "
        f"[yellow]{filtered_count} filtered[/]  ·  "
        f"[dim]{summary.elapsed:.1f}s[/]"
    )

    table = Table(
        title="🔍 Scan Results via Tor",
        title_style="bold cyan",
        caption=caption,
        caption_style="dim",
        header_style="bold magenta",
        border_style="bright_blue",
        box=box.ROUNDED,
    )
    table.add_column("Port", justify="center", no_wrap=True)
    table.add_column("State", justify="center", no_wrap=True)
    table.add_column("Service", style="cyan")
    table.add_column("Version", style="white", overflow="fold")

    shown = [p for p in summary.ports if p.state != "closed"]
    if not shown:
        table.add_row("-", "[dim]no open ports[/]", "-", "-")
    else:
        for p in sorted(shown, key=lambda x: int(x.port) if x.port.isdigit() else 0):
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
    if not preflight():
        console.print("\n[red]Missing dependencies. Run:[/]")
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
            console.print("  [green]✓[/] NEWNYM signal sent")
        else:
            console.print("  [yellow]![/] IP rotation disabled (ControlPort unavailable)")

        current_ip = get_exit_ip()
        if current_ip != "unknown":
            console.print(f"  [green]✓[/] Current exit IP: [magenta]{current_ip}[/]")
        else:
            console.print("  [yellow]![/] Could not determine exit IP")

        console.rule("[bold cyan]4/6 · Configure scan")
        tool = choose_tool()

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

        console.rule("[bold cyan]5/6 · Rotate identity before scan?")
        if control_ok:
            console.print(
                f"  [dim]A fresh Tor circuit gives a new exit IP, "
                f"but it takes ~{ROTATION_WAIT}s to build.[/]"
            )
            do_rotate = Confirm.ask(
                f"  Rotate IP now and wait {ROTATION_WAIT}s before scanning?",
                default=True,
            )

            if do_rotate:
                console.print("  [dim]Requesting new identity from Tor...[/]")
                success, old_ip, new_ip = rotate_and_wait(ROTATION_WAIT)

                if not success:
                    console.print("  [red]✗[/] Rotation failed")
                    if not Confirm.ask("  Continue with current IP?", default=True):
                        return 1
                elif old_ip == new_ip and new_ip != "unknown":
                    console.print(f"  [yellow]![/] Tor reused IP: {new_ip}")
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
        try:
            ports, elapsed = run_nmap_via_tor(target, conf, plan)
        finally:
            try:
                os.unlink(conf)
            except OSError:
                pass

        summary = ScanSummary(
            target=target,
            exit_ip=current_ip,
            elapsed=elapsed,
            ports=ports,
        )
        render_table(summary)

        if Confirm.ask("\n[dim]Export results as JSON?[/]", default=False):
            safe = target.replace(".", "_").replace("/", "_")
            out_path = f"fsector_{safe}_{int(time.time())}.json"
            with open(out_path, "w") as f:
                json.dump({
                    "tool": "nmap",
                    "plan": plan["name"] if plan else None,
                    "target": summary.target,
                    "exit_ip": summary.exit_ip,
                    "elapsed": round(summary.elapsed, 2),
                    "ports": [p.__dict__ for p in summary.ports],
                }, f, indent=2)
            console.print(f"[green]✓[/] Saved to [cyan]{out_path}[/]")

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