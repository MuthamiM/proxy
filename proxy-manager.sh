#!/bin/bash
# ============================================
# Proxy User Manager
# Add, remove, and list proxy users
# ============================================

PASSWD_FILE="/etc/squid/proxy_users"
SCRIPT_NAME=$(basename "$0")

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

usage() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}   USA Proxy - User Manager${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "Usage: sudo ./$SCRIPT_NAME ${YELLOW}<command>${NC} [options]"
    echo ""
    echo -e "Commands:"
    echo -e "  ${GREEN}add${NC}      <username> <password>   Add a new user"
    echo -e "  ${GREEN}remove${NC}   <username>              Remove a user"
    echo -e "  ${GREEN}list${NC}                             List all users"
    echo -e "  ${GREEN}status${NC}                           Show proxy status"
    echo -e "  ${GREEN}restart${NC}                          Restart proxy"
    echo -e "  ${GREEN}logs${NC}                             Show recent access logs"
    echo ""
    echo -e "Examples:"
    echo -e "  sudo ./$SCRIPT_NAME add john mypassword123"
    echo -e "  sudo ./$SCRIPT_NAME remove john"
    echo -e "  sudo ./$SCRIPT_NAME list"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: Please run as root (sudo)${NC}"
        exit 1
    fi
}

add_user() {
    local username="$1"
    local password="$2"

    if [ -z "$username" ] || [ -z "$password" ]; then
        echo -e "${RED}Error: Username and password required${NC}"
        echo -e "Usage: sudo ./$SCRIPT_NAME add <username> <password>"
        exit 1
    fi

    # Check if user already exists
    if grep -q "^${username}:" "$PASSWD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}User '${username}' already exists. Updating password...${NC}"
        htpasswd -b "$PASSWD_FILE" "$username" "$password"
    else
        htpasswd -b "$PASSWD_FILE" "$username" "$password"
    fi

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[OK] User '${username}' added/updated successfully.${NC}"
        echo -e "${CYAN}Proxy connection info:${NC}"
        local host_ip=$(tailscale ip -4 2>/dev/null || curl -s ifconfig.me 2>/dev/null || echo '127.0.0.1')
        echo -e "  Host:     ${host_ip} (Tailscale / Network IP)"
        echo -e "  Port:     3128"
        echo -e "  Username: ${username}"
        echo -e "  Password: ${password}"
        echo -e "  Egress:   WireGuard US (Secaucus, NJ / 155.117.189.107)"
    else
        echo -e "${RED}[ERROR] Failed to add user${NC}"
        exit 1
    fi
}

remove_user() {
    local username="$1"

    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username required${NC}"
        echo -e "Usage: sudo ./$SCRIPT_NAME remove <username>"
        exit 1
    fi

    if grep -q "^${username}:" "$PASSWD_FILE" 2>/dev/null; then
        htpasswd -D "$PASSWD_FILE" "$username"
        echo -e "${GREEN}[OK] User '${username}' removed successfully.${NC}"
    else
        echo -e "${RED}User '${username}' not found${NC}"
        exit 1
    fi
}

list_users() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}   SPY - Registered Proxy Users${NC}"
    echo -e "${CYAN}========================================${NC}"

    if [ ! -f "$PASSWD_FILE" ] || [ ! -s "$PASSWD_FILE" ]; then
        echo -e "${YELLOW}No users registered yet.${NC}"
        echo -e "Add one with: sudo ./$SCRIPT_NAME add <username> <password>"
        return
    fi

    echo ""
    local count=0
    while IFS=: read -r username _; do
        count=$((count + 1))
        echo -e "  ${GREEN}${count}.${NC} ${username}"
    done < "$PASSWD_FILE"
    echo ""
    echo -e "${CYAN}Total: ${count} user(s)${NC}"
}

show_status() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}   SPY Proxy Status${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    # Service status
    if systemctl is-active --quiet squid; then
        echo -e "  Service:  ${GREEN}[RUNNING]${NC}"
    else
        echo -e "  Service:  ${RED}[STOPPED]${NC}"
    fi

    # Enabled on boot
    if systemctl is-enabled --quiet squid; then
        echo -e "  Boot:     ${GREEN}[ENABLED]${NC}"
    else
        echo -e "  Boot:     ${RED}[DISABLED]${NC}"
    fi

    # Connection info
    local egress_ip=$(curl -s --interface 10.2.0.2 ifconfig.me 2>/dev/null || echo "155.117.189.107")
    local host_ip=$(tailscale ip -4 2>/dev/null || echo "100.87.92.72")
    echo -e "  Host IP:    ${YELLOW}${host_ip}${NC} (Tailscale Proxy Host)"
    echo -e "  Egress IP:  ${YELLOW}${egress_ip}${NC} (WireGuard Outbound)"
    echo -e "  Port:       ${YELLOW}3128${NC}"
    echo -e "  Location:   ${YELLOW}Secaucus, NJ, USA${NC}"

    # User count
    local users=0
    if [ -f "$PASSWD_FILE" ]; then
        users=$(wc -l < "$PASSWD_FILE")
    fi
    echo -e "  Users:    ${YELLOW}${users}${NC}"
    echo ""
}

show_logs() {
    echo -e "${CYAN}Last 20 access log entries:${NC}"
    echo ""
    tail -20 /var/log/squid/access.log 2>/dev/null || echo -e "${YELLOW}No logs yet.${NC}"
}

restart_proxy() {
    echo -e "${YELLOW}Restarting Squid proxy...${NC}"
    systemctl restart squid
    if systemctl is-active --quiet squid; then
        echo -e "${GREEN}[OK] Proxy restarted successfully.${NC}"
    else
        echo -e "${RED}[ERROR] Failed to restart. Check: journalctl -u squid${NC}"
        exit 1
    fi
}

# --- Main ---
case "${1}" in
    add)
        check_root
        add_user "$2" "$3"
        ;;
    remove|rm|delete)
        check_root
        remove_user "$2"
        ;;
    list|ls)
        check_root
        list_users
        ;;
    status)
        check_root
        show_status
        ;;
    restart)
        check_root
        restart_proxy
        ;;
    logs|log)
        check_root
        show_logs
        ;;
    *)
        usage
        ;;
esac
