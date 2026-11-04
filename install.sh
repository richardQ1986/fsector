#!/usr/bin/env bash
# Fsector installer - auto-detect distro, install prerequisites
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

banner() {
cat <<'EOF'
███████╗███████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
█████╗  ███████╗███████╗██║        ██║   ██║   ██║██████╔╝
██╔══╝  ╚════██║╚════██║██║        ██║   ██║   ██║██╔══██╗
██║     ███████║███████║╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝     ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
EOF
echo -e "${BOLD}            Fsector Installer  ·  v1.2${RESET}"
echo
}

banner

if [[ $EUID -ne 0 ]]; then
  fail "Please run as root:  sudo bash install.sh"
fi

if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DISTRO="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
else
  fail "Cannot detect distribution (/etc/os-release missing)"
fi

info "Detected distro: ${BOLD}${PRETTY_NAME:-$DISTRO}${RESET}"

install_pkgs() {
  local pkgs_debian=("tor" "proxychains4" "nmap" "curl" "python3" "python3-pip")
  local pkgs_fedora=("tor" "proxychains-ng" "nmap" "curl" "python3" "python3-pip")
  local pkgs_arch=("tor" "proxychains-ng" "nmap" "curl" "python" "python-pip")

  case "$DISTRO" in
    ubuntu|debian|kali|parrot|linuxmint|pop)
      info "Installing system packages via apt..."
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs_debian[@]}" \
        || fail "apt install failed"
      ;;
    fedora|rhel|centos|rocky|almalinux)
      info "Installing system packages via dnf..."
      dnf install -y epel-release || true
      dnf install -y "${pkgs_fedora[@]}" || fail "dnf install failed"
      ;;
    arch|manjaro|endeavouros)
      info "Installing system packages via pacman..."
      pacman -Sy --noconfirm "${pkgs_arch[@]}" || fail "pacman install failed"
      ;;
    *)
      if [[ "$DISTRO_LIKE" == *"debian"* || "$DISTRO_LIKE" == *"ubuntu"* ]]; then
        info "Falling back to apt..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs_debian[@]}" \
          || fail "apt install failed"
      else
        fail "Unsupported distro: $DISTRO. Install manually: tor, proxychains, nmap, python3, curl"
      fi
      ;;
  esac
  ok "System packages installed"
}

install_pkgs

for bin in tor proxychains4 nmap curl python3; do
  if command -v "$bin" &>/dev/null; then
    ok "$bin found"
  else
    if [[ "$bin" == "proxychains4" ]] && command -v proxychains &>/dev/null; then
      warn "proxychains4 not found, but 'proxychains' exists — creating symlink"
      ln -sf "$(command -v proxychains)" /usr/local/bin/proxychains4
      ok "proxychains4 -> proxychains symlink created"
    else
      fail "$bin not found after installation"
    fi
  fi
done

info "Installing Python dependency (rich)..."
if pip3 install --quiet --break-system-packages 'rich>=13.7.0' 2>/dev/null; then
  ok "rich installed (system pip)"
elif pip3 install --quiet 'rich>=13.7.0' 2>/dev/null; then
  ok "rich installed"
else
  warn "System pip failed, creating isolated venv..."
  python3 -m venv /opt/fsector-venv
  /opt/fsector-venv/bin/pip install --quiet 'rich>=13.7.0' \
    || fail "Failed to install rich even in venv"
  ok "rich installed in /opt/fsector-venv"
fi

info "Checking Tor service..."
if systemctl list-unit-files 2>/dev/null | grep -q '^tor.service'; then
  systemctl enable --now tor 2>/dev/null && ok "tor.service enabled & started" \
    || warn "Could not start tor.service (fsector will launch its own tor)"
else
  warn "tor.service not found — fsector will launch tor on demand"
fi

if [[ -f "./fsector.py" ]]; then
  chmod +x ./fsector.py
  ok "fsector.py made executable"
fi

echo
ok "Installation complete! Run with:"
echo -e "    ${BOLD}sudo python3 fsector.py${RESET}"
echo