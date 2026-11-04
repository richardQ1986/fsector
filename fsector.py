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
    from rich import box
except ImportError:
    print("[!] Missing dependency: rich\n    pip install rich", file=sys.stderr)
    sys.exit(1)


APP_NAME = "Fsector"
VERSION = "1.2"

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
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
    "1": {"name": "nmap", "desc": "TCP connect port & service scanner (via Tor)"},
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


def show_banner() -> None:
    console.print(Text(BANNER.strip("\n"), style="bold cyan"), justify="left")
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


def send_newnym() -> bool:
    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_CONTROL_PORT), timeout=2) as s:
            s.sendall(b"AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT\r\n")
            time.sleep(0.5)
        return True
    except OSError:
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
    try:
        out = subprocess.check_output(
            ["curl", "-s", "--max-time", "10",
             "--socks5-hostname", f"{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
             "https://check.torproject.org/api/ip"],
            stderr=subprocess.DEVNULL,
        )
        return json.loads(out).get("IP", "unknown")
    except Exception:
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


def run_nmap_via_tor(target: str, conf_path: str) -> tuple:
    cmd = [
        "proxychains4", "-f", conf_path, "-q",
        "nmap", "-sT", "-Pn", "-T4",
        "--top-ports", "100",
        "-oX", "-", target,
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
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
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


def main() -> int:
    show_banner()

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
        console.rule("[bold cyan]3/6 · Initial identity")
        if send_newnym():
            console.print("  [green]✓[/] NEWNYM signal sent")
        else:
            console.print("  [yellow]![/] ControlPort unavailable (skipping)")

        current_ip = get_exit_ip()
        console.print(f"  [green]✓[/] Current exit IP: [magenta]{current_ip}[/]")

        console.rule("[bold cyan]4/6 · Configure scan")
        tool = choose_tool()
        target = Prompt.ask("  Target [cyan](IP or domain)[/]").strip()
        if not target:
            console.print("[red]✗ Empty target[/]")
            return 1

        console.rule("[bold cyan]5/6 · Rotate identity before scan?")
        console.print(
            f"  [dim]A fresh Tor circuit gives a new exit IP, but it takes "
            f"~{ROTATION_WAIT}s to build.[/]"
        )
        do_rotate = Confirm.ask(
            f"  Rotate IP now and wait {ROTATION_WAIT}s before scanning?",
            default=True,
        )

        if do_rotate:
            console.print("  [dim]Requesting new identity from Tor...[/]")
            success, old_ip, new_ip = rotate_and_wait(ROTATION_WAIT)

            if not success:
                console.print("  [red]✗[/] Rotation failed (ControlPort unreachable)")
                if not Confirm.ask("  Continue scan with current IP anyway?", default=False):
                    return 1
            elif old_ip == new_ip and new_ip != "unknown":
                console.print(
                    f"  [yellow]![/] Tor reused the same exit IP: [magenta]{new_ip}[/]"
                )
                console.print("  [dim](Tor may be under rate-limit; continuing anyway)[/]")
            else:
                console.print(
                    f"  [green]✓[/] Exit IP changed: "
                    f"[dim]{old_ip}[/] → [magenta]{new_ip}[/]"
                )
                current_ip = new_ip
        else:
            console.print(f"  [dim]Skipping rotation, using current IP {current_ip}[/]")

        if not Confirm.ask(
            f"\n  Run [bold]{tool}[/] against [bold]{target}[/] via Tor?",
            default=True,
        ):
            console.print("[yellow]Aborted by user.[/]")
            return 0

        console.rule("[bold cyan]6/6 · Executing")
        conf = write_proxychains_conf()
        try:
            ports, elapsed = run_nmap_via_tor(target, conf)
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