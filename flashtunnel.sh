#!/usr/bin/env bash
# ==============================================================================
#   FlashTunnel - High-Performance TCP Stealth Tunnel Manager
#   Features: Multi-Tunnel Support | Status & Ping Checker | Pure TCP
# ==============================================================================

CONFIG_DIR="/etc/flashtunnel"
TUNNELS_DIR="${CONFIG_DIR}/tunnels"
BINARY_PATH="/usr/local/bin/flashtunnel-bin"
MENU_PATH="/usr/local/bin/flashtunnel-menu"
WRAPPER_PATH="/usr/local/bin/flashtunnel"

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

# Ensure directories and binary
init_environment() {
    mkdir -p "$CONFIG_DIR" "$TUNNELS_DIR"

    if [ ! -f "$BINARY_PATH" ]; then
        if [ -f "/usr/local/bin/mytunnel" ]; then
            cp /usr/local/bin/mytunnel "$BINARY_PATH"
        elif [ -f "./bin/flashtunnel" ]; then
            cp ./bin/flashtunnel "$BINARY_PATH"
        elif [ -f "./flashtunnel" ]; then
            cp ./flashtunnel "$BINARY_PATH"
        elif [ -f "./mytunnel_linux" ]; then
            cp ./mytunnel_linux "$BINARY_PATH"
        elif [ -f "/usr/local/bin/flashtunnel" ] && file /usr/local/bin/flashtunnel 2>/dev/null | grep -q "ELF"; then
            cp /usr/local/bin/flashtunnel "$BINARY_PATH"
        else
            echo -e "${RED}[!] FlashTunnel binary not found.${NC}"
            exit 1
        fi
    fi
    chmod +x "$BINARY_PATH" 2>/dev/null || true

    # Install menu symlink
    if [ -f "$0" ] && [ ! -f "$MENU_PATH" ]; then
        cp "$0" "$MENU_PATH" 2>/dev/null || true
        chmod +x "$MENU_PATH" 2>/dev/null || true
    fi

    # Migrate legacy single config if present
    if [ -f "${CONFIG_DIR}/config.env" ] && [ ! -f "${TUNNELS_DIR}/default.conf" ]; then
        cp "${CONFIG_DIR}/config.env" "${TUNNELS_DIR}/default.conf"
    fi
}

# Safe config parser (never crashes on bad quotes, syntax errors, or special characters)
load_conf() {
    local conf_file="$1"
    NAME=""
    ROLE=""
    TUNNEL_PORT=""
    XRAY_PORT=""
    SERVER_IP=""
    EXTRA_PORTS=""
    KEY=""
    CREATED_AT=""

    [ ! -f "$conf_file" ] && return 1

    while IFS='=' read -r raw_key raw_val || [ -n "$raw_key" ]; do
        local key=$(echo "$raw_key" | tr -d '[:space:]')
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        
        # Clean value: strip carriage returns, surrounding quotes, and dangling escape backslashes
        local val=$(echo "$raw_val" | tr -d '\r' | sed -e 's/^[[:space:]]*["'\'']//' -e 's/["'\''][[:space:]]*$//' -e 's/\\$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        case "$key" in
            NAME)        NAME="$val" ;;
            ROLE)        ROLE="$val" ;;
            TUNNEL_PORT) TUNNEL_PORT="$val" ;;
            XRAY_PORT)   XRAY_PORT="$val" ;;
            SERVER_IP)   SERVER_IP="$val" ;;
            EXTRA_PORTS) EXTRA_PORTS="$val" ;;
            KEY)         KEY="$val" ;;
            CREATED_AT)  CREATED_AT="$val" ;;
        esac
    done < "$conf_file"

    [ -z "$NAME" ] && NAME=$(basename "$conf_file" .conf)
    return 0
}

# Robust Public IP Detection
get_public_ip() {
    local ip=""
    for service in "https://api.ipify.org" "https://icanhazip.com" "https://ifconfig.io/ip" "https://ipinfo.io/ip"; do
        ip=$(curl -s4 -m 2 "$service" 2>/dev/null | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$ip"
            return
        fi
    done
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' | tr -d '[:space:]')
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip"
    else
        echo "127.0.0.1"
    fi
}

# Check TCP Latency in ms using python3 or /dev/tcp
measure_latency() {
    local host="$1"
    local port="$2"
    if [ -z "$host" ] || [ -z "$port" ]; then
        echo "N/A"
        return
    fi

    python3 -c "
import socket, time, sys
t0 = time.perf_counter()
try:
    s = socket.create_connection(('$host', int('$port')), timeout=2.0)
    lat = (time.perf_counter() - t0) * 1000.0
    s.close()
    print(f'{lat:.1f}ms')
except Exception:
    print('TIMEOUT')
" 2>/dev/null || echo "TIMEOUT"
}

# Header Banner
show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}"
    echo "  +------------------------------------------------------------+"
    echo "  |                    FlashTunnel Manager                     |"
    echo "  |        High-Performance TCP Stealth Tunnel for Linux       |"
    echo "  +------------------------------------------------------------+"
    echo -e "${NC}"
}

# List All Configured Tunnels
get_tunnel_list() {
    find "$TUNNELS_DIR" -maxdepth 1 -name "*.conf" -type f 2>/dev/null | sort
}

# Show Dashboard Status
show_status() {
    local configs=($(get_tunnel_list))
    echo -e "${BOLD}[ Configured Tunnels ]${NC}"

    if [ ${#configs[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}No tunnels configured yet. Use option 1 or 2 to add one.${NC}"
        echo -e "----------------------------------------------------------------"
        echo ""
        return
    fi

    printf "  %-12s %-8s %-10s %-14s %-24s\n" "NAME" "ROLE" "STATUS" "LISTEN PORT" "REMOTE/TARGET"
    echo -e "  ----------------------------------------------------------------------"

    for conf in "${configs[@]}"; do
        load_conf "$conf"
        local t_name=$(basename "$conf" .conf)
        local svc_name="flashtunnel-${t_name}"
        # support legacy service name for default
        if [ "$t_name" == "default" ] && systemctl is-active --quiet flashtunnel 2>/dev/null; then
            svc_name="flashtunnel"
        fi

        local status_str="${RED}STOPPED${NC}"
        if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
            status_str="${GREEN}RUNNING${NC}"
        fi

        local remote_info=""
        local listen_info=""
        if [ "$ROLE" == "server" ]; then
            listen_info="${TUNNEL_PORT}"
            remote_info="127.0.0.1:${XRAY_PORT}"
        else
            listen_info="${XRAY_PORT}"
            [ -n "$EXTRA_PORTS" ] && listen_info="${XRAY_PORT} (+${EXTRA_PORTS})"
            remote_info="${SERVER_IP}:${TUNNEL_PORT}"
        fi

        printf "  %-12s %-8s %-19b %-14s %-24s\n" "$t_name" "${ROLE^^}" "$status_str" "$listen_info" "$remote_info"
    done
    echo -e "----------------------------------------------------------------"
    echo ""
}

# Add New Server Tunnel
add_server_tunnel() {
    show_banner
    echo -e "${GREEN}${BOLD}=== Add New Server Tunnel (Foreign / Upstream) ===${NC}\n"

    echo -e "${CYAN}Port Configuration Guide:${NC}"
    echo -e "  - ${BOLD}Tunnel Listen Port${NC}    : The external port FlashTunnel listens on to receive encrypted"
    echo -e "                            traffic from your Iran relay (e.g. 4433, 8443)."
    echo -e "  - ${BOLD}Local Target Service Port${NC}: The internal port of your VPN/proxy core (e.g. Xray/V2Ray in 3X-UI)."
    echo -e "                            FlashTunnel forwards decrypted traffic to 127.0.0.1:<target_port>."
    
    local active_ports=$(ss -tlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -nu | tr '\n' ' ')
    if [ -n "$active_ports" ]; then
        echo -e "  - ${YELLOW}Detected Active Ports${NC}  : ${active_ports}"
    fi
    echo -e "----------------------------------------------------------------\n"

    read -p "Tunnel identifier name [default: server1]: " T_NAME
    T_NAME=${T_NAME:-server1}
    T_NAME=$(echo "$T_NAME" | tr -dc 'a-zA-Z0-9_-')

    if [ -f "${TUNNELS_DIR}/${T_NAME}.conf" ]; then
        echo -e "${RED}[!] A tunnel with name '${T_NAME}' already exists.${NC}"
        read -p "Press Enter to return..." dummy
        return
    fi

    read -p "Tunnel listen port for incoming relay [default: 4433]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-4433}

    read -p "Local target service port (e.g. Xray inbound port) [default: 443]: " XRAY_PORT
    XRAY_PORT=${XRAY_PORT:-443}

    if ! ss -tlnp 2>/dev/null | grep -qE "(:|\])${XRAY_PORT} "; then
        echo -e "\n${YELLOW}[!] Warning: No service is currently listening on port ${XRAY_PORT}.${NC}"
        echo -e "    Ensure your VPN inbound (e.g. in 3X-UI) is configured and running on port ${XRAY_PORT}.\n"
    fi

    local default_key="FlashKey2026"
    read -p "Tunnel security key [default: ${default_key}]: " INPUT_KEY
    KEY=${INPUT_KEY:-$default_key}

    # Save Config
    local now_str=$(date '+%Y-%m-%d_%H:%M:%S' 2>/dev/null || echo "2026-10-14")
    cat > "${TUNNELS_DIR}/${T_NAME}.conf" <<EOF
NAME=$T_NAME
ROLE=server
TUNNEL_PORT=$TUNNEL_PORT
XRAY_PORT=$XRAY_PORT
KEY=$KEY
CREATED_AT=$now_str
EOF

    # Create Systemd Unit
    local svc_file="/etc/systemd/system/flashtunnel-${T_NAME}.service"
    cat > "$svc_file" <<EOF
[Unit]
Description=FlashTunnel Server Instance (${T_NAME})
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
    systemctl enable --now "flashtunnel-${T_NAME}"

    echo -e "\n${GREEN}[+] Server tunnel '${T_NAME}' created and started successfully!${NC}"
    local EXT_IP=$(get_public_ip)
    echo -e "${CYAN}Connection parameters for Client / Relay:${NC}"
    echo -e "  Server Address : ${BOLD}${EXT_IP}${NC}"
    echo -e "  Tunnel Port    : ${BOLD}${TUNNEL_PORT}${NC}"
    echo -e "  Security Key   : ${BOLD}${KEY}${NC}"
    echo ""
    read -p "Press Enter to return to menu..." dummy
}

# Add New Client Tunnel (Relay)
add_client_tunnel() {
    show_banner
    echo -e "${GREEN}${BOLD}=== Add New Client Tunnel (Relay / Local) ===${NC}\n"

    echo -e "${CYAN}Port Configuration Guide:${NC}"
    echo -e "  - ${BOLD}Remote Server IP & Port${NC}: The IP and Tunnel Port of your foreign server configured in Step 1."
    echo -e "  - ${BOLD}Local Incoming Port${NC}    : The port on THIS Iran server that VPN clients connect to (e.g. 443)."
    echo -e "  - ${BOLD}Additional Ports${NC}       : Extra fallback ports redirected to main port (e.g. 8443, 2087, 8080)."
    echo -e "----------------------------------------------------------------\n"

    read -p "Tunnel identifier name [default: relay1]: " T_NAME
    T_NAME=${T_NAME:-relay1}
    T_NAME=$(echo "$T_NAME" | tr -dc 'a-zA-Z0-9_-')

    if [ -f "${TUNNELS_DIR}/${T_NAME}.conf" ]; then
        echo -e "${RED}[!] A tunnel with name '${T_NAME}' already exists.${NC}"
        read -p "Press Enter to return..." dummy
        return
    fi

    read -p "Remote Server IP address: " SERVER_IP
    while [ -z "$SERVER_IP" ]; do
        read -p "Remote Server IP is required: " SERVER_IP
    done

    read -p "Tunnel port on remote server [default: 4433]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-4433}

    read -p "Local incoming listen port for clients [default: 443]: " XRAY_PORT
    XRAY_PORT=${XRAY_PORT:-443}

    read -p "Additional redirected ports (comma-separated) [default: 8443,2087,8080]: " EXTRA_PORTS
    EXTRA_PORTS=${EXTRA_PORTS:-"8443,2087,8080"}

    local default_key="FlashKey2026"
    read -p "Tunnel security key (must match server) [default: ${default_key}]: " INPUT_KEY
    KEY=${INPUT_KEY:-$default_key}

    # Save Config
    local now_str=$(date '+%Y-%m-%d_%H:%M:%S' 2>/dev/null || echo "2026-10-14")
    cat > "${TUNNELS_DIR}/${T_NAME}.conf" <<EOF
NAME=$T_NAME
ROLE=client
SERVER_IP=$SERVER_IP
TUNNEL_PORT=$TUNNEL_PORT
XRAY_PORT=$XRAY_PORT
EXTRA_PORTS=$EXTRA_PORTS
KEY=$KEY
CREATED_AT=$now_str
EOF

    # Configure Multi-port redirection via iptables
    local PRE_EXEC=""
    if [ -n "$EXTRA_PORTS" ]; then
        iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$EXTRA_PORTS" -j REDIRECT --to-ports "$XRAY_PORT" 2>/dev/null || true
        iptables -t nat -A PREROUTING -p tcp -m multiport --dports "$EXTRA_PORTS" -j REDIRECT --to-ports "$XRAY_PORT"
        PRE_EXEC="ExecStartPre=/sbin/iptables -t nat -A PREROUTING -p tcp -m multiport --dports ${EXTRA_PORTS} -j REDIRECT --to-ports ${XRAY_PORT}"
    fi

    # Create Systemd Unit
    local svc_file="/etc/systemd/system/flashtunnel-${T_NAME}.service"
    cat > "$svc_file" <<EOF
[Unit]
Description=FlashTunnel Client Instance (${T_NAME})
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
    systemctl enable --now "flashtunnel-${T_NAME}"

    echo -e "\n${GREEN}[+] Client relay tunnel '${T_NAME}' created and started successfully!${NC}"
    local EXT_IP=$(get_public_ip)
    echo -e "${CYAN}Client connection details:${NC}"
    echo -e "  Relay Address  : ${BOLD}${EXT_IP}${NC}"
    echo -e "  Main Port      : ${BOLD}${XRAY_PORT}${NC}"
    if [ -n "$EXTRA_PORTS" ]; then
        echo -e "  Fallback Ports : ${BOLD}${EXTRA_PORTS}${NC}"
    fi
    echo ""
    read -p "Press Enter to return to menu..." dummy
}

# Manage Individual Tunnel
manage_single_tunnel() {
    local conf_file="$1"
    local t_name=$(basename "$conf_file" .conf)
    local svc_name="flashtunnel-${t_name}"
    [ "$t_name" == "default" ] && systemctl is-active --quiet flashtunnel 2>/dev/null && svc_name="flashtunnel"

    while true; do
        load_conf "$conf_file"
        show_banner
        echo -e "${BOLD}Managing Tunnel: ${CYAN}${t_name}${NC} (${YELLOW}${ROLE^^}${NC})"
        echo -e "----------------------------------------------------------------"
        if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
            echo -e "  Status: ${GREEN}Active (Running)${NC}"
        else
            echo -e "  Status: ${RED}Inactive (Stopped)${NC}"
        fi

        if [ "$ROLE" == "server" ]; then
            echo -e "  Listen Port : ${TUNNEL_PORT} -> Local Target: ${XRAY_PORT}"
        else
            echo -e "  Listen Port : ${XRAY_PORT} -> Remote Server: ${SERVER_IP}:${TUNNEL_PORT}"
        fi
        echo -e "  Security Key: ${KEY}"
        echo -e "----------------------------------------------------------------"
        echo -e "  ${GREEN}1)${NC} Start Tunnel"
        echo -e "  ${YELLOW}2)${NC} Stop Tunnel"
        echo -e "  ${CYAN}3)${NC} Restart Tunnel"
        echo -e "  ${BLUE}4)${NC} View Live Logs"
        echo -e "  ${RED}5)${NC} Delete Tunnel"
        echo -e "  ${BOLD}0)${NC} Back to Tunnel List"
        echo ""
        if ! read -p "Select an option [0-5]: " act; then
            return
        fi

        case "$act" in
            1)
                systemctl start "$svc_name"
                echo -e "${GREEN}[+] Tunnel started.${NC}"
                sleep 1
                ;;
            2)
                systemctl stop "$svc_name"
                echo -e "${YELLOW}[+] Tunnel stopped.${NC}"
                sleep 1
                ;;
            3)
                systemctl restart "$svc_name"
                echo -e "${GREEN}[+] Tunnel restarted.${NC}"
                sleep 1
                ;;
            4)
                echo -e "${CYAN}Streaming live logs for ${svc_name} (Press Ctrl+C to exit)...${NC}\n"
                journalctl -u "$svc_name" -f --no-pager
                ;;
            5)
                read -p "Are you sure you want to delete tunnel '${t_name}'? (y/n): " confirm
                if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
                    systemctl stop "$svc_name" 2>/dev/null || true
                    systemctl disable "$svc_name" 2>/dev/null || true
                    rm -f "/etc/systemd/system/${svc_name}.service"
                    rm -f "$conf_file"
                    systemctl daemon-reload
                    echo -e "${GREEN}[+] Tunnel '${t_name}' deleted successfully.${NC}"
                    sleep 1
                    return
                fi
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}[!] Invalid choice.${NC}"; sleep 1
                ;;
        esac
    done
}

# Manage Tunnels Submenu
manage_tunnels_menu() {
    while true; do
        show_banner
        local configs=($(get_tunnel_list))
        echo -e "${BOLD}=== Manage Existing Tunnels ===${NC}\n"

        if [ ${#configs[@]} -eq 0 ]; then
            echo -e "${YELLOW}No tunnels configured yet.${NC}"
            read -p "Press Enter to return..." dummy
            return
        fi

        local idx=1
        for conf in "${configs[@]}"; do
            load_conf "$conf"
            local t_name=$(basename "$conf" .conf)
            local svc_name="flashtunnel-${t_name}"
            [ "$t_name" == "default" ] && systemctl is-active --quiet flashtunnel 2>/dev/null && svc_name="flashtunnel"

            local st="${RED}STOPPED${NC}"
            systemctl is-active --quiet "$svc_name" 2>/dev/null && st="${GREEN}RUNNING${NC}"
            echo -e "  ${BOLD}${idx})${NC} ${CYAN}${t_name}${NC} [${YELLOW}${ROLE^^}${NC}] - ${st}"
            idx=$((idx + 1))
        done

        echo -e "\n  ${BOLD}0)${NC} Back to Main Menu"
        echo ""
        if ! read -p "Select tunnel number to manage [0-$((idx-1))]: " sel; then
            return
        fi

        if [ "$sel" == "0" ] || [ -z "$sel" ]; then
            return
        elif [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -lt "$idx" ]; then
            local target_conf="${configs[$((sel-1))]}"
            manage_single_tunnel "$target_conf"
        else
            echo -e "${RED}[!] Invalid selection.${NC}"; sleep 1
        fi
    done
}

# Check Tunnel Status & Ping / Latency
check_status_and_ping() {
    show_banner
    echo -e "${BOLD}=== Tunnel Connectivity & Latency Check ===${NC}\n"

    local configs=($(get_tunnel_list))
    if [ ${#configs[@]} -eq 0 ]; then
        echo -e "${YELLOW}No tunnels configured to check.${NC}"
        read -p "Press Enter to return..." dummy
        return
    fi

    for conf in "${configs[@]}"; do
        load_conf "$conf"
        local t_name=$(basename "$conf" .conf)
        local svc_name="flashtunnel-${t_name}"
        [ "$t_name" == "default" ] && systemctl is-active --quiet flashtunnel 2>/dev/null && svc_name="flashtunnel"

        echo -e "${BOLD}Tunnel: ${CYAN}${t_name}${NC} (${ROLE^^})"

        # 1. Service Status
        if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
            echo -e "  [+] Service State : ${GREEN}ACTIVE (Running)${NC}"
        else
            echo -e "  [-] Service State : ${RED}INACTIVE (Stopped)${NC}"
        fi

        # 2. Port listening check
        local l_port="$XRAY_PORT"
        [ "$ROLE" == "server" ] && l_port="$TUNNEL_PORT"
        if ss -tlnp 2>/dev/null | grep -q ":${l_port} "; then
            echo -e "  [+] Listen Port   : ${GREEN}Port ${l_port} is OPEN and listening${NC}"
        else
            echo -e "  [-] Listen Port   : ${YELLOW}Port ${l_port} is NOT actively listening${NC}"
        fi

        # 3. Latency & Ping
        if [ "$ROLE" == "client" ]; then
            echo -n "  [*] Checking latency to remote server (${SERVER_IP}:${TUNNEL_PORT})... "
            local lat=$(measure_latency "$SERVER_IP" "$TUNNEL_PORT")
            if [ "$lat" != "TIMEOUT" ]; then
                echo -e "${GREEN}CONNECTED (${lat})${NC}"
            else
                echo -e "${RED}TIMEOUT / UNREACHABLE${NC}"
            fi
        else
            echo -n "  [*] Checking latency to local target (127.0.0.1:${XRAY_PORT})... "
            local lat=$(measure_latency "127.0.0.1" "$XRAY_PORT")
            if [ "$lat" != "TIMEOUT" ]; then
                echo -e "${GREEN}REACHABLE (${lat})${NC}"
            else
                echo -e "${YELLOW}LOCAL PORT NOT RESPONDING${NC}"
                echo -e "      ${RED}[!] Notice: No VPN service (e.g. Xray) is answering on port ${XRAY_PORT}.${NC}"
                echo -e "      ${YELLOW}Ensure your inbound in 3X-UI / Xray is active and configured on port ${XRAY_PORT}.${NC}"
            fi
        fi
        echo -e "----------------------------------------------------------------"
    done

    echo ""
    read -p "Press Enter to return to menu..." dummy
}

# View Live Logs for All
view_all_logs() {
    echo -e "${CYAN}Streaming live logs for all FlashTunnel services (Press Ctrl+C to exit)...${NC}\n"
    journalctl -u "flashtunnel*" -f --no-pager
}

# Uninstall Everything
uninstall_all() {
    read -p "Are you sure you want to remove FlashTunnel and ALL tunnels? (y/n): " confirm
    if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
        for svc in /etc/systemd/system/flashtunnel*.service; do
            if [ -f "$svc" ]; then
                local b_svc=$(basename "$svc")
                systemctl stop "$b_svc" 2>/dev/null || true
                systemctl disable "$b_svc" 2>/dev/null || true
                rm -f "$svc"
            fi
        done
        systemctl daemon-reload
        rm -rf "$CONFIG_DIR"
        rm -f "$BINARY_PATH"
        rm -f "$MENU_PATH"
        rm -f "$WRAPPER_PATH"
        echo -e "${GREEN}[+] FlashTunnel and all tunnels completely removed.${NC}"
    else
        echo -e "${YELLOW}[*] Cancelled.${NC}"
    fi
    sleep 1
}

# Main Interactive Loop
main_menu() {
    check_root
    init_environment

    while true; do
        show_banner
        show_status

        echo -e "${BOLD}Select an option:${NC}"
        echo -e "  ${GREEN}1)${NC} Add New Server Tunnel (Foreign / Upstream)"
        echo -e "  ${GREEN}2)${NC} Add New Client Tunnel (Relay / Local)"
        echo -e "  ${CYAN}3)${NC} Manage Tunnels (Start / Stop / Restart / Delete)"
        echo -e "  ${BLUE}4)${NC} Check Status & Ping / Latency"
        echo -e "  ${YELLOW}5)${NC} View Live Logs"
        echo -e "  ${RED}6)${NC} Uninstall FlashTunnel"
        echo -e "  ${BOLD}0)${NC} Exit"
        echo ""
        if ! read -p "Enter selection [0-6]: " choice; then
            echo ""
            exit 0
        fi

        case "$choice" in
            1) add_server_tunnel ;;
            2) add_client_tunnel ;;
            3) manage_tunnels_menu ;;
            4) check_status_and_ping ;;
            5) view_all_logs ;;
            6) uninstall_all ;;
            0) exit 0 ;;
            *) echo -e "${RED}[!] Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

main_menu
