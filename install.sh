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
    echo -e "${RED}[!] در حال حاضر فقط معماری x86_64 پشتیبانی می‌شود. معماری شما: ${ARCH}${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] در حال بررسی پیش‌نیازها...${NC}"
MISSING_PKGS=""
for pkg in curl git iptables; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo -e "${YELLOW}[*] در حال نصب بسته‌های مورد نیاز:$MISSING_PKGS ...${NC}"
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

echo -e "${YELLOW}[*] در حال دریافت آخرین نسخه FlashTunnel...${NC}"

if [ -f "${SCRIPT_DIR}/bin/flashtunnel" ] && [ -f "${SCRIPT_DIR}/flashtunnel.sh" ]; then
    echo -e "${GREEN}[*] استفاده از فایل‌های محلی مخزن...${NC}"
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
    echo -e "${RED}[!] باینری flashtunnel در مخزن یافت نشد.${NC}"
    exit 1
fi
chmod +x "$BIN_DEST"

# Install Menu Script
if [ -f "${INSTALL_DIR}/flashtunnel.sh" ]; then
    cp "${INSTALL_DIR}/flashtunnel.sh" "$MENU_DEST"
else
    echo -e "${RED}[!] اسکریپت flashtunnel.sh در مخزن یافت نشد.${NC}"
    exit 1
fi
chmod +x "$MENU_DEST"

# Create Smart Global Wrapper
cat > "$WRAPPER" << 'EOF'
#!/usr/bin/env bash
if [ $# -eq 0 ]; then
    if [ -t 0 ]; then
        exec /usr/local/bin/flashtunnel-menu
    elif [ -c /dev/tty ]; then
        exec /usr/local/bin/flashtunnel-menu </dev/tty
    else
        exec /usr/local/bin/flashtunnel-menu
    fi
else
    exec /usr/local/bin/flashtunnel-bin "$@"
fi
EOF
chmod +x "$WRAPPER"

echo -e "\n${GREEN}${BOLD}[✓] FlashTunnel با موفقیت نصب شد!${NC}"
echo -e "${CYAN}از این پس با تایپ دستور ${BOLD}flashtunnel${NC}${CYAN} در هر زمان، منوی مدیریت تانل باز خواهد شد.${NC}\n"

# Launch Menu if interactive
if [ -t 0 ]; then
    exec /usr/local/bin/flashtunnel-menu
elif [ -c /dev/tty ]; then
    exec /usr/local/bin/flashtunnel-menu </dev/tty
fi
