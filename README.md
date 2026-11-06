<div align="center">



<img width="1280" height="480" alt="msg69078375-16411" src="https://github.com/user-attachments/assets/24dbb361-354d-4267-98fa-68d4ebd240d5" />


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

## ⚠️ Legal Disclaimer & Terms of Use

**Fsector is provided for educational, authorized penetration testing, and defensive security purposes only.**

By downloading, installing, or using this software, you explicitly agree to the following terms:

1.  **No Warranty (AS IS):** This software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement [citation:1][citation:2]. The author(s) make no guarantees regarding the accuracy, reliability, or safety of this tool.
2.  **User Responsibility:** You, the end-user, are solely responsible for your actions and any consequences that arise from the use of this software. You must ensure that you have explicit, written permission to scan or test any network, system, or application. Unauthorized scanning is illegal in most jurisdictions and may violate local and international laws.
3.  **Limitation of Liability:** In no event shall the author(s) or copyright holder(s) be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software [citation:1][citation:6]. This includes, but is not limited to, legal fees, criminal charges, or any damage caused to target systems.
4.  **Indemnification:** You agree to indemnify, defend, and hold harmless the author(s) from and against any and all claims, liabilities, damages, losses, or expenses (including reasonable attorneys' fees) arising out of or in any way connected with your access to or use of this software.

**The author(s) do not condone, encourage, or support any illegal activity. This tool is a technical instrument, and like any instrument, its ethical and legal use depends entirely on the user.**

**If you are unsure about the legality of your actions, do not use this tool.**

---

## 📬 Contact & Support

If you have any questions, suggestions, or have discovered a security vulnerability in this tool, please feel free to reach out:

- **GitHub Issues:** [Open an issue](https://github.com/richardQ1986/fsector/issues)
- **Developer:** [richardQ1986](https://github.com/richardQ1986)

---

## 🏁 Final Note

**Fsector** was built with the belief that security tools should be both powerful and elegant. Whether you are a blue teamer mapping your own infrastructure, a pentester conducting an authorized engagement, or a researcher studying anonymity networks, this tool is designed to give you precision without the noise.

> *"The quieter you become, the more you are able to hear."* — Ram Dass

**Use it wisely, use it legally, and stay invisible.**

---

<div align="center">

**© 2026 richardQ1986 — Released under the MIT License.**

[![Back to Top](https://img.shields.io/badge/%E2%AC%86%20Back%20to%20Top-000000?style=for-the-badge)](#-fsector)

</div>
