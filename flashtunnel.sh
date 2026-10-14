#!/usr/bin/env bash
# ==============================================================================
#   FlashTunnel - High-Performance TCP Stealth Tunnel
#   Core: Native Zig Engine | Architecture: Pure TCP + TLS 1.3
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
NC='\033[0m'

# Check root privilege
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Please run this script with root privileges.${NC}"
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
            echo -e "${RED}[!] FlashTunnel binary not found.${NC}"
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
    echo "  +------------------------------------------------------------+"
    echo "  |                FlashTunnel Manager                         |"
    echo "  |        High-Performance TCP Stealth Tunnel for Linux       |"
    echo "  +------------------------------------------------------------+"
    echo -e "${NC}"
}

# Show Dashboard Status
show_status() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        local status_text
        if systemctl is-active --quiet flashtunnel 2>/dev/null || systemctl is-active --quiet mytunnel 2>/dev/null; then
            status_text="${GREEN}Active (Running)${NC}"
        else
            status_text="${RED}Inactive (Stopped)${NC}"
        fi

        echo -e "${BOLD}[ Tunnel Status ]${NC}"
        echo -e "  Service Status : ${status_text}"
        echo -e "  Node Role      : ${YELLOW}${ROLE^^}${NC}"
        if [ "$ROLE" == "server" ]; then
            echo -e "  Tunnel Port    : ${CYAN}${TUNNEL_PORT}${NC}"
            echo -e "  Target Port    : ${GREEN}${XRAY_PORT}${NC}"
        else
            echo -e "  Remote Server  : ${CYAN}${SERVER_IP}:${TUNNEL_PORT}${NC}"
            echo -e "  Listen Port    : ${GREEN}${XRAY_PORT}${NC}"
            if [ -n "$EXTRA_PORTS" ]; then
                echo -e "  Redirect Ports : ${YELLOW}${EXTRA_PORTS}${NC}"
            fi
        fi
        echo -e "  Security Key   : ${PURPLE}${KEY}${NC}"
        echo -e "  Desync Mode    : ${BOLD}multidisorder (Active)${NC}"
        echo -e "----------------------------------------------------------------"
    else
        echo -e "${YELLOW}[!] FlashTunnel is not configured on this server yet.${NC}"
    fi
    echo ""
}

# Install / Setup Server (Kharej)
setup_server() {
    show_banner
    echo -e "${GREEN}${BOLD}=== Configure Server (Foreign / Upstream) ===${NC}\n"

    read -p "Tunnel listen port for incoming relay connections [default: 4433]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-4433}

    read -p "Target service port on localhost [default: 443]: " XRAY_PORT
    XRAY_PORT=${XRAY_PORT:-443}

    DEFAULT_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16 ; echo '')
    read -p "Tunnel security key [default: $DEFAULT_KEY]: " KEY
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
Description=FlashTunnel Server
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

    echo -e "\n${GREEN}[+] Server configured and started successfully!${NC}"
    local EXT_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
    echo -e "${CYAN}Connection parameters for Relay / Client:${NC}"
    echo -e "  Server IP    : ${BOLD}${EXT_IP}${NC}"
    echo -e "  Tunnel Port  : ${BOLD}${TUNNEL_PORT}${NC}"
    echo -e "  Security Key : ${BOLD}${KEY}${NC}"
    echo ""
    read -p "Press Enter to return to menu..." dummy
}

# Install / Setup Client (Iran Relay)
setup_client() {
    show_banner
    echo -e "${GREEN}${BOLD}=== Configure Client (Relay / Local) ===${NC}\n"

    read -p "Remote Server IP address: " SERVER_IP
    while [ -z "$SERVER_IP" ]; do
        read -p "Remote Server IP is required: " SERVER_IP
    done

    read -p "Tunnel port on remote server [default: 4433]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-4433}

    read -p "Local incoming listen port [default: 443]: " XRAY_PORT
    XRAY_PORT=${XRAY_PORT:-443}

    read -p "Additional redirected ports (comma-separated) [default: 8443,2087,8080]: " EXTRA_PORTS
    EXTRA_PORTS=${EXTRA_PORTS:-"8443,2087,8080"}

    read -p "Tunnel security key (must match server): " KEY
    while [ -z "$KEY" ]; do
        read -p "Security key is required: " KEY
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
Description=FlashTunnel Client
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

    echo -e "\n${GREEN}[+] Client relay configured and started successfully!${NC}"
    local EXT_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
    echo -e "${CYAN}Client connection details:${NC}"
    echo -e "  Relay Address  : ${BOLD}${EXT_IP}${NC}"
    echo -e "  Main Port      : ${BOLD}${XRAY_PORT}${NC}"
    if [ -n "$EXTRA_PORTS" ]; then
        echo -e "  Fallback Ports : ${BOLD}${EXTRA_PORTS}${NC}"
    fi
    echo ""
    read -p "Press Enter to return to menu..." dummy
}

# View Live Logs
view_logs() {
    echo -e "${CYAN}Streaming live logs (Press Ctrl+C to exit)...${NC}\n"
    journalctl -u flashtunnel -u mytunnel -f --no-pager
}

# Restart Service
restart_tunnel() {
    echo -e "${YELLOW}[*] Restarting service...${NC}"
    systemctl restart flashtunnel 2>/dev/null || systemctl restart mytunnel 2>/dev/null || true
    echo -e "${GREEN}[+] Service restarted successfully.${NC}"
    sleep 1
}

# Stop Service
stop_tunnel() {
    echo -e "${YELLOW}[*] Stopping service...${NC}"
    systemctl stop flashtunnel 2>/dev/null || systemctl stop mytunnel 2>/dev/null || true
    echo -e "${GREEN}[+] Service stopped.${NC}"
    sleep 1
}

# Uninstall
uninstall_tunnel() {
    read -p "Are you sure you want to completely remove FlashTunnel? (y/n): " confirm
    if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
        systemctl stop flashtunnel 2>/dev/null || true
        systemctl disable flashtunnel 2>/dev/null || true
        systemctl stop mytunnel 2>/dev/null || true
        systemctl disable mytunnel 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        rm -rf "$CONFIG_DIR"
        rm -f "$BINARY_PATH"
        rm -f /usr/local/bin/flashtunnel-menu
        rm -f /usr/local/bin/flashtunnel
        echo -e "${GREEN}[+] FlashTunnel has been completely removed.${NC}"
    else
        echo -e "${YELLOW}[*] Action cancelled.${NC}"
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

        echo -e "${BOLD}Select an option:${NC}"
        echo -e "  ${GREEN}1)${NC} Configure Server (Foreign / Upstream)"
        echo -e "  ${GREEN}2)${NC} Configure Client (Relay / Local)"
        echo -e "  ${CYAN}3)${NC} View Live Logs"
        echo -e "  ${YELLOW}4)${NC} Restart Service"
        echo -e "  ${YELLOW}5)${NC} Stop Service"
        echo -e "  ${RED}6)${NC} Uninstall"
        echo -e "  ${BOLD}0)${NC} Exit"
        echo ""
        read -p "Enter selection [0-6]: " choice

        case "$choice" in
            1) setup_server ;;
            2) setup_client ;;
            3) view_logs ;;
            4) restart_tunnel ;;
            5) stop_tunnel ;;
            6) uninstall_tunnel ;;
            0) exit 0 ;;
            *) echo -e "${RED}[!] Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

main_menu
