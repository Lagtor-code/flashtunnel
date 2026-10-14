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
for pkg in curl iptables; do
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

RAW_BASE="https://raw.githubusercontent.com/Lagtor-code/flashtunnel/main"
INSTALL_DIR="/opt/flashtunnel"
BIN_DEST="/usr/local/bin/flashtunnel-bin"
MENU_DEST="/usr/local/bin/flashtunnel-menu"
WRAPPER="/usr/local/bin/flashtunnel"

mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"

echo -e "${YELLOW}[*] Fetching latest FlashTunnel release...${NC}"

# 1. Try local files first
if [ -f "${SCRIPT_DIR}/bin/flashtunnel" ] && [ -f "${SCRIPT_DIR}/flashtunnel.sh" ]; then
    echo -e "${GREEN}[*] Installing from local files...${NC}"
    cp --remove-destination "${SCRIPT_DIR}/bin/flashtunnel" "$BIN_DEST" 2>/dev/null || cp "${SCRIPT_DIR}/bin/flashtunnel" "$BIN_DEST"
    cp --remove-destination "${SCRIPT_DIR}/flashtunnel.sh" "$MENU_DEST" 2>/dev/null || cp "${SCRIPT_DIR}/flashtunnel.sh" "$MENU_DEST"
    cp -r "${SCRIPT_DIR}"/* "$INSTALL_DIR/" 2>/dev/null || true
else
    # 2. Direct fast curl download to temp files (avoids ETXTBSY if binary is running)
    TMP_BIN=$(mktemp /tmp/flashtunnel_bin.XXXXXX)
    TMP_MENU=$(mktemp /tmp/flashtunnel_menu.XXXXXX)
    trap 'rm -f "$TMP_BIN" "$TMP_MENU"' EXIT

    echo -e "${CYAN}[*] Downloading FlashTunnel binary...${NC}"
    curl -sSL --retry 3 --retry-delay 1 -o "$TMP_BIN" "${RAW_BASE}/bin/flashtunnel"
    
    echo -e "${CYAN}[*] Downloading FlashTunnel manager...${NC}"
    curl -sSL --retry 3 --retry-delay 1 -o "$TMP_MENU" "${RAW_BASE}/flashtunnel.sh"
    
    # Safe replacement avoiding ETXTBSY (Text file busy) error
    cp --remove-destination "$TMP_BIN" "$BIN_DEST" 2>/dev/null || (rm -f "$BIN_DEST" && cp "$TMP_BIN" "$BIN_DEST")
    cp --remove-destination "$TMP_MENU" "$MENU_DEST" 2>/dev/null || (rm -f "$MENU_DEST" && cp "$TMP_MENU" "$MENU_DEST")
    cp --remove-destination "$TMP_BIN" "${INSTALL_DIR}/flashtunnel" 2>/dev/null || true
    cp --remove-destination "$TMP_MENU" "${INSTALL_DIR}/flashtunnel.sh" 2>/dev/null || true
fi

chmod +x "$BIN_DEST"
chmod +x "$MENU_DEST"

# Verify binary
if [ ! -s "$BIN_DEST" ]; then
    echo -e "${RED}[!] Failed to download binary. Please check internet connection.${NC}"
    exit 1
fi

# Reload and restart active FlashTunnel services if upgrading
for svc in /etc/systemd/system/flashtunnel*.service; do
    if [ -f "$svc" ]; then
        sname=$(basename "$svc")
        if systemctl is-active --quiet "$sname" 2>/dev/null; then
            echo -e "${YELLOW}[*] Restarting running service ${sname} to apply update...${NC}"
            systemctl restart "$sname" 2>/dev/null || true
        fi
    fi
done

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
