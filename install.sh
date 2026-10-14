#!/usr/bin/env bash
# ==============================================================================
#   FlashTunnel - One-Command Installer
#   Repository: https://github.com/Lagtor-code/flashtunnel
# ==============================================================================

set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "=================================================================="
echo "                   FlashTunnel - Installer                        "
echo "        High-Performance TCP Stealth Tunnel for Linux             "
echo "=================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root (sudo bash $0).${NC}"
    exit 1
fi

ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo -e "${RED}[!] Only x86_64 architecture is supported. Detected: ${ARCH}${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Checking prerequisites...${NC}"
MISSING_PKGS=""
for pkg in curl git iptables; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo -e "${YELLOW}[*] Installing required packages:${MISSING_PKGS} ...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends $MISSING_PKGS >/dev/null 2>&1 || true
fi

REPO_URL="https://github.com/Lagtor-code/flashtunnel.git"
INSTALL_DIR="/opt/flashtunnel"
BIN_DEST="/usr/local/bin/flashtunnel-bin"
MENU_DEST="/usr/local/bin/flashtunnel-menu"
WRAPPER="/usr/local/bin/flashtunnel"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"

echo -e "${YELLOW}[*] Fetching latest FlashTunnel release...${NC}"

if [ -f "${SCRIPT_DIR}/bin/flashtunnel" ] && [ -f "${SCRIPT_DIR}/flashtunnel.sh" ]; then
    mkdir -p "$INSTALL_DIR"
    cp -r "${SCRIPT_DIR}"/* "$INSTALL_DIR/" 2>/dev/null || true
else
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR" && git pull --quiet || true
    else
        rm -rf "$INSTALL_DIR"
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi
fi

# Install Binary
if [ -f "${INSTALL_DIR}/bin/flashtunnel" ]; then
    cp "${INSTALL_DIR}/bin/flashtunnel" "$BIN_DEST"
elif [ -f "${INSTALL_DIR}/flashtunnel" ]; then
    cp "${INSTALL_DIR}/flashtunnel" "$BIN_DEST"
else
    echo -e "${RED}[!] Binary not found in repository.${NC}"
    exit 1
fi
chmod +x "$BIN_DEST"

# Install Menu Script
if [ -f "${INSTALL_DIR}/flashtunnel.sh" ]; then
    cp "${INSTALL_DIR}/flashtunnel.sh" "$MENU_DEST"
else
    echo -e "${RED}[!] flashtunnel.sh not found in repository.${NC}"
    exit 1
fi
chmod +x "$MENU_DEST"

# Create Smart Global Wrapper
cat > "$WRAPPER" << 'EOF'
#!/usr/bin/env bash
if [ $# -eq 0 ]; then
    if [ -t 0 ]; then
        exec /usr/local/bin/flashtunnel-menu
    elif [ -c /dev/tty ] && (true < /dev/tty) 2>/dev/null; then
        exec /usr/local/bin/flashtunnel-menu </dev/tty
    else
        exec /usr/local/bin/flashtunnel-menu
    fi
else
    exec /usr/local/bin/flashtunnel-bin "$@"
fi
EOF
chmod +x "$WRAPPER"

echo -e "\n${GREEN}${BOLD}[+] FlashTunnel installed successfully!${NC}"
echo -e "${CYAN}Run '${BOLD}flashtunnel${NC}${CYAN}' anytime to access the management menu.${NC}\n"

# Launch Menu if interactive
if [ -t 0 ]; then
    exec /usr/local/bin/flashtunnel-menu
elif [ -c /dev/tty ] && (true < /dev/tty) 2>/dev/null; then
    exec /usr/local/bin/flashtunnel-menu </dev/tty
fi
