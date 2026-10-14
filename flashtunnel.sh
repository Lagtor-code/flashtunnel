#!/usr/bin/env bash
# ==============================================================================
#   ⚡ FLASHTUNNEL - HIGH-PERFORMANCE ZIG TCP STEALTH TUNNEL ⚡
#   Core: Native Zig Engine | RAM: <0.5MB | Transport: Pure TCP + TLS 1.3
#   Anti-DPI: multidisorder:pos=2:seqovl=1:urg=true | Crypto: ChaCha20-Poly1305
# ==============================================================================

set -e

CONFIG_DIR="/etc/flashtunnel"
CONFIG_FILE="${CONFIG_DIR}/config.env"
BINARY_PATH="/usr/local/bin/flashtunnel-bin"
SERVICE_FILE="/etc/systemd/system/flashtunnel.service"

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check root privilege
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] لطفا این اسکریپت را با دسترسی root اجرا کنید.${NC}"
        exit 1
    fi
}

# Ensure binary is in place
check_binary() {
    if [ ! -f "$BINARY_PATH" ]; then
        if [ -f "/usr/local/bin/mytunnel" ]; then
            cp /usr/local/bin/mytunnel "$BINARY_PATH"
        elif [ -f "./bin/flashtunnel" ]; then
            cp ./bin/flashtunnel "$BINARY_PATH"
        elif [ -f "./flashtunnel" ]; then
            cp ./flashtunnel "$BINARY_PATH"
        elif [ -f "./mytunnel_linux" ]; then
            cp ./mytunnel_linux "$BINARY_PATH"
        elif [ -f "/usr/local/bin/flashtunnel" ] && file /usr/local/bin/flashtunnel | grep -q "ELF"; then
            cp /usr/local/bin/flashtunnel "$BINARY_PATH"
        else
            echo -e "${RED}[!] باینری flashtunnel یافت نشد.${NC}"
            exit 1
        fi
    fi
    chmod +x "$BINARY_PATH" 2>/dev/null || true

    # Install menu symlink
    if [ -f "$0" ] && [ ! -f "/usr/local/bin/flashtunnel-menu" ]; then
        cp "$0" /usr/local/bin/flashtunnel-menu 2>/dev/null || true
        chmod +x /usr/local/bin/flashtunnel-menu 2>/dev/null || true
    fi
}

# Header Banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════╗"
    echo "  ║         ⚡ FLASHTUNNEL - ZIG TCP STEALTH TUNNEL ⚡             ║"
    echo "  ║       Engine: Native Zig | Memory: <0.5MB | 0-Copy I/O         ║"
    echo "  ║       Anti-DPI: multidisorder:pos=2:seqovl=1:urg               ║"
    echo "  ║       Crypto: ChaCha20-Poly1305 + TLS 1.3 Record Masking       ║"
    echo "  ╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show Dashboard Status
show_status() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        local status_text
        if systemctl is-active --quiet flashtunnel; then
            status_text="${GREEN}● فعال و در حال اجرا (Active)${NC}"
        else
            status_text="${RED}○ متوقف شده (Inactive)${NC}"
        fi

        echo -e "${BOLD}┌── [ وضعیت تانل ]${NC}"
        echo -e "│  وضعیت سرویس   : ${status_text}"
        echo -e "│  نقش سرور     : ${YELLOW}${ROLE^^}${NC}"
        if [ "$ROLE" == "server" ]; then
            echo -e "│  پورت تانل     : ${CYAN}${TUNNEL_PORT}${NC}"
            echo -e "│  پورت مقصد Xray: ${GREEN}${XRAY_PORT}${NC}"
        else
            echo -e "│  سرور خارج    : ${CYAN}${SERVER_IP}:${TUNNEL_PORT}${NC}"
            echo -e "│  پورت لیسن ورودی: ${GREEN}${XRAY_PORT}${NC}"
            if [ -n "$EXTRA_PORTS" ]; then
                echo -e "│  پورت‌های اضافه : ${YELLOW}${EXTRA_PORTS}${NC}"
            fi
        fi
        echo -e "│  کلید امنیتی   : ${PURPLE}${KEY}${NC}"
        echo -e "│  تکنیک ضد فیلتر: ${BOLD}multidisorder:pos=2:seqovl=1:urg${NC}"
        echo -e "${BOLD}└───────────────────────────────────────────────────────────────${NC}"
    else
        echo -e "${YELLOW}[!] هنوز هیچ تانلی روی این سرور پیکربندی نشده است.${NC}"
    fi
    echo ""
}

# Install / Setup Server (Kharej)
setup_server() {
    show_banner
    echo -e "${GREEN}${BOLD}=== راه‌اندازی سرور خارج (Server - Kharej) ===${NC}\n"

    read -p "پورت تانل برای دریافت ارتباط از ایران [پیش‌فرض 4433]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-4433}

    read -p "پورت مقصد محلی Xray روی سرور خارج [پیش‌فرض 443]: " XRAY_PORT
    XRAY_PORT=${XRAY_PORT:-443}

    DEFAULT_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16 ; echo '')
    read -p "رمز عبور تانل [پیش‌فرض $DEFAULT_KEY]: " KEY
    KEY=${KEY:-$DEFAULT_KEY}

    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF
ROLE=server
TUNNEL_PORT=$TUNNEL_PORT
XRAY_PORT=$XRAY_PORT
KEY=$KEY
EOF

    # Create Systemd Service
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=FlashTunnel Server (Xray Reality)
After=network.target

[Service]
Type=simple
User=root
ExecStart=${BINARY_PATH} server --listen 0.0.0.0:${TUNNEL_PORT} --target 127.0.0.1:${XRAY_PORT} --tcp --key ${KEY}
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now flashtunnel

    echo -e "\n${GREEN}[✓] سرور خارج با موفقیت راه‌اندازی شد!${NC}"
    local EXT_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
    echo -e "${CYAN}مشخصات جهت اتصال از سرور ایران:${NC}"
    echo -e "  آی‌پی سرور خارج: ${BOLD}${EXT_IP}${NC}"
    echo -e "  پورت تانل     : ${BOLD}${TUNNEL_PORT}${NC}"
    echo -e "  کلید امنیتی   : ${BOLD}${KEY}${NC}"
    echo ""
    read -p "جهت بازگشت اینتر را بزنید..." dummy
}

# Install / Setup Client (Iran Relay)
setup_client() {
    show_banner
    echo -e "${GREEN}${BOLD}=== راه‌اندازی سرور ایران (Client / Relay - Iran) ===${NC}\n"

    read -p "آدرس IP سرور خارج: " SERVER_IP
    while [ -z "$SERVER_IP" ]; do
        read -p "آی‌پی سرور خارج الزامی است: " SERVER_IP
    done

    read -p "پورت تانل سرور خارج [پیش‌فرض 4433]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-4433}

    read -p "پورت اصلی ورودی برای کاربران [پیش‌فرض 443]: " XRAY_PORT
    XRAY_PORT=${XRAY_PORT:-443}

    read -p "پورت‌های اضافه فوروارد به پورت اصلی (مثال: 8443,2087,8080) [پیش‌فرض 8443,2087,8080]: " EXTRA_PORTS
    EXTRA_PORTS=${EXTRA_PORTS:-"8443,2087,8080"}

    read -p "رمز عبور تانل (دقیقاً برابر با کلید سرور خارج): " KEY
    while [ -z "$KEY" ]; do
        read -p "رمز عبور الزامی است: " KEY
    done

    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF
ROLE=client
SERVER_IP=$SERVER_IP
TUNNEL_PORT=$TUNNEL_PORT
XRAY_PORT=$XRAY_PORT
EXTRA_PORTS=$EXTRA_PORTS
KEY=$KEY
EOF

    # Configure Multi-port redirection via iptables
    local PRE_EXEC=""
    if [ -n "$EXTRA_PORTS" ]; then
        iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$EXTRA_PORTS" -j REDIRECT --to-ports "$XRAY_PORT" 2>/dev/null || true
        iptables -t nat -A PREROUTING -p tcp -m multiport --dports "$EXTRA_PORTS" -j REDIRECT --to-ports "$XRAY_PORT"
        PRE_EXEC="ExecStartPre=/sbin/iptables -t nat -A PREROUTING -p tcp -m multiport --dports ${EXTRA_PORTS} -j REDIRECT --to-ports ${XRAY_PORT}"
    fi

    # Create Systemd Service
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=FlashTunnel Client (Xray Reality Relay)
After=network.target

[Service]
Type=simple
User=root
${PRE_EXEC}
ExecStart=${BINARY_PATH} client --server ${SERVER_IP}:${TUNNEL_PORT} --listen 0.0.0.0:${XRAY_PORT} --tcp --key ${KEY}
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now flashtunnel

    echo -e "\n${GREEN}[✓] رله سرور ایران با موفقیت راه‌اندازی شد!${NC}"
    local EXT_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
    echo -e "${CYAN}مشخصات برای تنظیم در کلاینت (v2rayNG / Nekoray):${NC}"
    echo -e "  آدرس (Address): ${BOLD}${EXT_IP}${NC}"
    echo -e "  پورت اصلی    : ${BOLD}${XRAY_PORT}${NC}"
    if [ -n "$EXTRA_PORTS" ]; then
        echo -e "  پورت‌های جایگزین: ${BOLD}${EXTRA_PORTS}${NC}"
    fi
    echo ""
    read -p "جهت بازگشت اینتر را بزنید..." dummy
}

# View Live Logs
view_logs() {
    echo -e "${CYAN}در حال نمایش لاگ‌های زنده تانل (برای خروج Ctrl+C بزنید)...${NC}\n"
    journalctl -u flashtunnel -f --no-pager
}

# Restart Service
restart_tunnel() {
    echo -e "${YELLOW}[*] در حال ریستارت سرویس...${NC}"
    systemctl restart flashtunnel
    echo -e "${GREEN}[✓] سرویس با موفقیت ریستارت شد.${NC}"
    sleep 1
}

# Stop Service
stop_tunnel() {
    echo -e "${YELLOW}[*] در حال متوقف کردن سرویس...${NC}"
    systemctl stop flashtunnel
    echo -e "${GREEN}[✓] سرویس متوقف شد.${NC}"
    sleep 1
}

# Uninstall
uninstall_tunnel() {
    read -p "آیا از حذف کامل FlashTunnel اطمینان دارید؟ (y/n): " confirm
    if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
        systemctl stop flashtunnel 2>/dev/null || true
        systemctl disable flashtunnel 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        rm -rf "$CONFIG_DIR"
        rm -f "$BINARY_PATH"
        rm -f /usr/local/bin/flashtunnel-menu
        rm -f /usr/local/bin/flashtunnel
        echo -e "${GREEN}[✓] FlashTunnel و تمام فایل‌های وابسته با موفقیت حذف شدند.${NC}"
    else
        echo -e "${YELLOW}[*] عملیات لغو شد.${NC}"
    fi
    sleep 1
}

# Main Loop
main_menu() {
    check_root
    check_binary

    while true; do
        show_banner
        show_status

        echo -e "${BOLD}انتخاب عملیات:${NC}"
        echo -e "  ${GREEN}1)${NC} 🚀 راه‌اندازی سرور خارج (Server - Kharej)"
        echo -e "  ${GREEN}2)${NC} 🇮🇷 راه‌اندازی سرور ایران (Client / Relay - Iran)"
        echo -e "  ${CYAN}3)${NC} 📊 مشاهده لاگ زنده ترافیک (Live Logs)"
        echo -e "  ${YELLOW}4)${NC} 🔄 ریستارت تانل (Restart)"
        echo -e "  ${YELLOW}5)${NC} 🛑 توقف تانل (Stop)"
        echo -e "  ${RED}6)${NC} 🗑️  حذف کامل و پاک‌سازی (Uninstall)"
        echo -e "  ${BOLD}0)${NC} ❌ خروج"
        echo ""
        read -p "شماره مورد نظر را وارد کنید: " choice

        case "$choice" in
            1) setup_server ;;
            2) setup_client ;;
            3) view_logs ;;
            4) restart_tunnel ;;
            5) stop_tunnel ;;
            6) uninstall_tunnel ;;
            0) exit 0 ;;
            *) echo -e "${RED}[!] گزینه نامعتبر است.${NC}"; sleep 1 ;;
        esac
    done
}

main_menu
