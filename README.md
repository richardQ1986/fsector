<div align="center">

# 🧅 Fsector

**Pentest tools over Tor — with stealth scan plans and a beautiful terminal UI.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux&logoColor=white)]()
[![Tor](https://img.shields.io/badge/Powered%20by-Tor-7D4698?style=for-the-badge&logo=tor-project&logoColor=white)](https://www.torproject.org/)

*Scan quietly. Rotate identity. Stay invisible.*

</div>

---

## 📖 What is Fsector?

**Fsector** is a command-line wrapper that routes **nmap** through the **Tor** anonymity network via `proxychains`, giving blue teams and authorized penetration testers a clean, interactive way to perform stealthy reconnaissance without leaking their real IP.

It is **not** a magic invisibility cloak — it is a carefully engineered tool that:

- forces all scan traffic through Tor's SOCKS5 proxy,
- rotates the Tor exit node before every scan (`NEWNYM`),
- lets you choose a **stealth profile** (from paranoid `-T0` to aggressive `-T4`),
- and renders the results in a beautiful, color-coded terminal table.

---

## ✨ Features

| | Feature |
|---|---|
| 🧅 | **Tor-first** — every probe goes through `127.0.0.1:9050` |
| 🔄 | **Identity rotation** — new circuit + new exit IP before each scan |
| 🛡️ | **4 stealth plans** — Paranoid (T0), Sneaky (T1), Polite (T2), Aggressive (T4) |
| 🎬 | **Animated banner** — reveal effect on startup |
| 📊 | **Rich terminal table** — sensitive ports highlighted in red |
| 🔐 | **Auto ControlPort setup** — detects and configures `/etc/tor/torrc` for you |
| 🌐 | **Multi-endpoint IP check** — `icanhazip`, `ifconfig.me`, `ipify`, `check.torproject.org` |
| 💾 | **JSON export** — save scan results for reporting |
| 🐧 | **Auto-installer** — detects your distro (Debian, Fedora, Arch) and installs prerequisites |

---

## 🖼️ Screenshot

<img width="1280" height="771" alt="fsector terminal" src="https://github.com/user-attachments/assets/d737a772-b04a-473a-9485-2c76c5619dea" />

