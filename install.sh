#!/usr/bin/env bash
# ==============================================================================
#   ⚡ FLASHTUNNEL - ONE-COMMAND INSTALLER ⚡
#   Fast, Automated Deployment for Iran & Kharej Servers
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
echo "          ⚡ FLASHTUNNEL - ONE COMMAND INSTALLER ⚡              "
echo "  High-Performance Zig TCP Stealth Tunnel | Zapret Anti-DPI       "
echo "=================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] لطفا با دسترسی root اجرا کنید (sudo bash $0).${NC}"
    exit 1
fi

ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo -e "${RED}[!] در حال حاضر معماری x86_64 پشتیبانی می‌شود. معماری سیستم شما: ${ARCH}${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] در حال بررسی و نصب پیش‌نیازها...${NC}"
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y git curl iptables systemd procps ca-certificates >/dev/null 2>&1 || true

REPO_URL="https://github.com/Lagtor-code/flashtunnel.git"
INSTALL_DIR="/opt/flashtunnel"
BIN_DEST="/usr/local/bin/flashtunnel-bin"
MENU_DEST="/usr/local/bin/flashtunnel-menu"
WRAPPER="/usr/local/bin/flashtunnel"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"

echo -e "${YELLOW}[*] در حال دریافت آخرین نسخه FlashTunnel از گیت‌هاب...${NC}"

if [ -f "${SCRIPT_DIR}/bin/flashtunnel" ] && [ -f "${SCRIPT_DIR}/flashtunnel.sh" ]; then
    echo -e "${GREEN}[*] فایل‌های پروژه در مسیر محلی یافت شدند: ${SCRIPT_DIR}${NC}"
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
    echo -e "${RED}[!] فایل باینری flashtunnel در مخزن یافت نشد.${NC}"
    exit 1
fi
chmod +x "$BIN_DEST"

# Install Menu Script
if [ -f "${INSTALL_DIR}/flashtunnel.sh" ]; then
    cp "${INSTALL_DIR}/flashtunnel.sh" "$MENU_DEST"
else
    echo -e "${RED}[!] فایل flashtunnel.sh در مخزن یافت نشد.${NC}"
    exit 1
fi
chmod +x "$MENU_DEST"

# Create Smart Global Wrapper
cat > "$WRAPPER" << 'EOF'
#!/usr/bin/env bash
if [ $# -eq 0 ]; then
    if [ -t 0 ]; then
        exec /usr/local/bin/flashtunnel-menu
    else
        exec /usr/local/bin/flashtunnel-menu </dev/tty
    fi
else
    exec /usr/local/bin/flashtunnel-bin "$@"
fi
EOF
chmod +x "$WRAPPER"

echo -e "\n${GREEN}${BOLD}[✓] نصب و راه‌اندازی با موفقیت انجام شد!${NC}"
echo -e "${CYAN}از این پس با تایپ دستور ${BOLD}flashtunnel${NC}${CYAN} در ترمینال، منوی مدیریت تانل باز خواهد شد.${NC}\n"
sleep 1

# Launch Menu immediately (connect to tty if piped from curl)
if [ -t 0 ]; then
    exec /usr/local/bin/flashtunnel-menu
elif [ -c /dev/tty ]; then
    exec /usr/local/bin/flashtunnel-menu </dev/tty
fi
