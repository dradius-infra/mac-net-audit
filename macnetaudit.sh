#!/usr/bin/env bash
# ==============================================================================
# MacNetAudit by dradius
# Deterministic, Zero-Assumption L2-L7 Network Triage & Posture Assessment
# Target OS: macOS (Darwin) | Dependencies: nmap, arp-scan (Optional fallback)
# ==============================================================================

# 1. Enforce Root Privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf "\033[0;31m[ERROR] Root privileges required for raw sockets, pfctl, arp-scan & nmap.\033[0m\n" >&2
    printf "Execute with: sudo %s\n" "$0" >&2
    exit 1
fi

# Ensure standard system path and clean locale parsing
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export LC_ALL=C

# Formatting Palette
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

printf "${BOLD}${CYAN}====================================================${NC}\n"
printf "${BOLD}${CYAN}     MACNETAUDIT: STRICT DETERMINISTIC AUDIT        ${NC}\n"
printf "${BOLD}${CYAN}====================================================${NC}\n\n"

# ----------------------------------------------------
# 1. Interface, Strict CIDR & Routing
# ----------------------------------------------------
PRIMARY_IFACE=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
if [ -z "$PRIMARY_IFACE" ]; then
    printf "${RED}[CRITICAL] No active default routing interface detected. Offline.${NC}\n" >&2
    exit 1
fi

SERVICE_NAME=$(networksetup -listnetworkserviceorder 2>/dev/null | grep -B 1 "$PRIMARY_IFACE" | head -n 1 | cut -d ' ' -f 2-)
LOCAL_IP4=$(ipconfig getifaddr "$PRIMARY_IFACE" 2>/dev/null || true)
LOCAL_IP6=$(ifconfig "$PRIMARY_IFACE" inet6 2>/dev/null | awk '/inet6/ && !/fe80/ {print $2; exit}' || true)
SUBNET_MASK=$(ipconfig getoption "$PRIMARY_IFACE" subnet_mask 2>/dev/null || true)
GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}' || true)

# Bitwise Mask-to-CIDR (Deterministic)
mask2cidr() {
    [ -z "$1" ] && printf "Unassigned" && return
    local x=0
    local IFS='.'
    for octet in $1; do
        case $octet in
            255) ((x+=8)) ;;
            254) ((x+=7)) ;;
            252) ((x+=6)) ;;
            248) ((x+=5)) ;;
            240) ((x+=4)) ;;
            224) ((x+=3)) ;;
            192) ((x+=2)) ;;
            128) ((x+=1)) ;;
            0)   ((x+=0)) ;;
            *)   printf "Invalid" && return ;;
        esac
    done
    printf "%s" "$x"
}

CIDR_PREFIX=$(mask2cidr "$SUBNET_MASK")

printf "${BOLD}${YELLOW}[1] Interface, Addressing & Routing:${NC}\n"
printf "  Active Route  : ${GREEN}%s${NC} (%s)\n" "$PRIMARY_IFACE" "${SERVICE_NAME:-Unknown Link}"
printf "  IPv4 Subnet   : ${GREEN}%s/%s${NC} (Mask: %s)\n" "${LOCAL_IP4:-Unassigned}" "$CIDR_PREFIX" "${SUBNET_MASK:-Unassigned}"
printf "  Global IPv6   : ${GREEN}%s${NC}\n" "${LOCAL_IP6:-None}"
printf "  Default GW    : ${GREEN}%s${NC}\n" "${GATEWAY:-None}"

# ----------------------------------------------------
# 2. Wi-Fi Layer-2 Security & Rogue AP Verification
# ----------------------------------------------------
printf "\n${BOLD}${YELLOW}[2] Wi-Fi Layer-2 Security & Rogue AP Audit:${NC}\n"
WIFI_INFO=$(system_profiler SPAirPortDataType 2>/dev/null || true)
CURRENT_SSID=$(printf "%s\n" "$WIFI_INFO" | awk -F': ' '/Current Network Information:/{getline; sub(/:$/, ""); sub(/^[ \t]+/, ""); print; exit}')

if [ -n "$CURRENT_SSID" ]; then
    AUTH_TYPE=$(printf "%s\n" "$WIFI_INFO" | awk -F': ' '/Security:/{print $2; exit}' | sed 's/^[ \t]*//')
    CONNECTED_BSSID=$(printf "%s\n" "$WIFI_INFO" | awk -F': ' '/BSSID:/{print $2; exit}' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
    PHY_MODE=$(printf "%s\n" "$WIFI_INFO" | awk -F': ' '/PHY Mode:/{print $2; exit}' | sed 's/^[ \t]*//')
    RSSI_NOISE=$(printf "%s\n" "$WIFI_INFO" | awk -F': ' '/Signal \/ Noise:/{print $2; exit}' | sed 's/^[ \t]*//')

    printf "  SSID / BSSID  : ${GREEN}%s${NC} (%s)\n" "$CURRENT_SSID" "${CONNECTED_BSSID:-Hidden}"
    printf "  PHY / Link    : ${GREEN}%s${NC} | Signal: ${GREEN}%s${NC}\n" "${PHY_MODE:-N/A}" "${RSSI_NOISE:-N/A}"

    if [[ "$AUTH_TYPE" =~ "None" || -z "$AUTH_TYPE" ]]; then
        printf "  Encryption    : ${RED}[CRITICAL] Open Wi-Fi (No Encryption / MITM Risk)${NC}\n"
    elif [[ "$AUTH_TYPE" =~ "WPA3" ]]; then
        printf "  Encryption    : ${GREEN}[SECURE] %s${NC}\n" "$AUTH_TYPE"
    else
        printf "  Encryption    : ${YELLOW}[ACCEPTABLE] %s${NC}\n" "$AUTH_TYPE"
    fi

    # Evil Twin / Rogue AP Detection
    if [ -n "$CONNECTED_BSSID" ]; then
        DUPLICATE_BEACONS=$(printf "%s\n" "$WIFI_INFO" | grep -B 1 -A 4 "SSID: ${CURRENT_SSID}" | awk '/BSSID:/ {print tolower($2)}' | tr -d ' ' | sort -u | grep -v -F "$CONNECTED_BSSID" || true)
        if [ -n "$DUPLICATE_BEACONS" ]; then
            printf "  Evil Twin RF  : ${YELLOW}[NOTICE] Multiple APs broadcasting same SSID with distinct BSSID(s):${NC}\n"
            while IFS= read -r bssid; do
                [ -n "$bssid" ] && printf "    -> Alternate BSSID: %s\n" "$bssid"
            done <<< "$DUPLICATE_BEACONS"
        else
            printf "  Evil Twin RF  : ${GREEN}[CLEAN] Only connected BSSID observed.${NC}\n"
        fi
    fi
else
    printf "  Interface Type: ${GREEN}Ethernet / Thunderbolt Wired Link (No RF Exposure)${NC}\n"
fi

# ----------------------------------------------------
# 3. macOS Kernel PF & System Trust Store
# ----------------------------------------------------
printf "\n${BOLD}${YELLOW}[3] Endpoint Security, Kernel PF & Trust Store:${NC}\n"

PF_INFO=$(pfctl -s info 2>/dev/null || true)
if printf "%s\n" "$PF_INFO" | grep -q "Status: Enabled"; then
    PF_RULES=$(pfctl -s rules 2>/dev/null | wc -l | tr -d ' ')
    PF_STATES=$(pfctl -s states 2>/dev/null | wc -l | tr -d ' ')
    printf "  Kernel PF     : ${GREEN}[ENABLED]${NC} States: %s | Rules: %s\n" "$PF_STATES" "$PF_RULES"
    NAT_RULES=$(pfctl -s nat 2>/dev/null | grep "rdr" || true)
    if [ -n "$NAT_RULES" ]; then
        printf "  PF Redirects  : ${RED}[ALERT] Active Port Interception/Redirections in Kernel!${NC}\n"
    else
        printf "  PF Redirects  : ${GREEN}[CLEAN] No NAT/Port Redirections configured.${NC}\n"
    fi
else
    printf "  Kernel PF     : ${YELLOW}[DISABLED] PF not enforcing packet filters${NC}\n"
fi

ADMIN_CERTS=$(security dump-trust-settings -d 2>/dev/null | grep -c "Certificate" || true)
SYSTEM_CERTS=$(security dump-trust-settings -s 2>/dev/null | grep -c "Certificate" || true)
if [ "${ADMIN_CERTS:-0}" -gt 0 ] || [ "${SYSTEM_CERTS:-0}" -gt 0 ]; then
    printf "  Trust Store   : ${RED}[ALERT] Custom Root CAs Detected (Admin: %s, System: %s)${NC}\n" "${ADMIN_CERTS:-0}" "${SYSTEM_CERTS:-0}"
else
    printf "  Trust Store   : ${GREEN}[CLEAN] Standard Apple Root CAs Only (No TLS Interception)${NC}\n"
fi

# ----------------------------------------------------
# 4. Perimeter Policy & DNS Integrity
# ----------------------------------------------------
printf "\n${BOLD}${YELLOW}[4] Perimeter Policy & DNS Integrity:${NC}\n"

CAPTIVE=$(curl -s -m 2 http://captive.apple.com/hotspot-detect.html 2>/dev/null || true)
if [[ "$CAPTIVE" =~ "Success" ]]; then
    printf "  Captive Portal: ${GREEN}[CLEAR] Direct WAN Access${NC}\n"
else
    printf "  Captive Portal: ${RED}[RESTRICTED] Captive Gateway Redirection Active${NC}\n"
fi

LOCAL_DNS=$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/ {print $3; exit}')
SEARCH_DOMAINS=$(scutil --dns 2>/dev/null | awk '/search domain\[0\]/ {print $3; exit}')
printf "  Primary DNS   : ${GREEN}%s${NC}\n" "${LOCAL_DNS:-None Assigned}"
if [ -n "$SEARCH_DOMAINS" ]; then
    printf "  Search Domain : ${YELLOW}[INJECTED] '%s'${NC}\n" "$SEARCH_DOMAINS"
fi

# ----------------------------------------------------
# 5. Full L2 Subnet Discovery & Inventory
# ----------------------------------------------------
printf "\n${BOLD}${YELLOW}[5] Full L2 Subnet Discovery (Active LAN Nodes):${NC}\n"

ACTIVE_HOSTS_LIST=()

if command -v arp-scan &>/dev/null; then
    printf "  ${CYAN}Scanning via raw ARP frames (arp-scan)...${NC}\n"
    # POSIX-compliant line parsing: splits accurately on variable spaces without field destruction
    while read -r dev_ip dev_mac dev_vendor; do
        [ -z "$dev_ip" ] && continue
        ACTIVE_HOSTS_LIST+=("$dev_ip")

        if [ "$dev_ip" = "$GATEWAY" ]; then
            printf "    - ${GREEN}%s${NC} (%s) [Default Gateway] - ${YELLOW}%s${NC}\n" "$dev_ip" "$dev_mac" "${dev_vendor:-Generic Node}"
        elif [ "$dev_ip" = "$LOCAL_IP4" ]; then
            printf "    - ${GREEN}%s${NC} (%s) [This Mac] - %s\n" "$dev_ip" "$dev_mac" "${dev_vendor:-Apple}"
        else
            printf "    - %s (%s) - %s\n" "$dev_ip" "$dev_mac" "${dev_vendor:-Generic Node}"
        fi
    done < <(arp-scan --interface="$PRIMARY_IFACE" --localnet --quiet 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {ip=$1; mac=$2; $1=""; $2=""; sub(/^[ \t]+/, ""); print ip, mac, $0}')
else
    printf "  ${YELLOW}[arp-scan not installed - Falling back to ARP cache]${NC}\n"
    ping -c 2 -q "$GATEWAY" &>/dev/null || true
    ping -c 2 -t 1 224.0.0.1 &>/dev/null || true
    while read -r entry; do
        DEV_IP=$(printf "%s\n" "$entry" | awk '{print $2}' | tr -d '()')
        DEV_MAC=$(printf "%s\n" "$entry" | awk '{print $4}')
        [ -z "$DEV_IP" ] && continue
        ACTIVE_HOSTS_LIST+=("$DEV_IP")
        printf "    - %s (%s)\n" "$DEV_IP" "$DEV_MAC"
    done < <(arp -an -i "$PRIMARY_IFACE" 2>/dev/null | grep -v "incomplete" || true)
fi

printf "  ${CYAN}IPv6 NDP Neighbors:${NC}\n"
ndp -an 2>/dev/null | grep "$PRIMARY_IFACE" | grep -v "incomplete" | awk '{print "    - " $1 " (" $2 ")"}' | head -n 6 || true

# ----------------------------------------------------
# 6. Deep Gateway & Subnet-Wide Service Sweep (Nmap Engine)
# ----------------------------------------------------
printf "\n${BOLD}${YELLOW}[6] Multi-Host Port Exposure & Gateway Profiling (Nmap):${NC}\n"

if command -v nmap &>/dev/null; then
    # 6A. Gateway Sweep
    if [ -n "$GATEWAY" ] && [ "$GATEWAY" != "None" ]; then
        printf "  ${CYAN}[Target 1/2] Profiling Gateway (%s) OS & Versions...${NC}\n" "$GATEWAY"
        GW_NMAP=$(nmap -sS -sV -O --top-ports 20 -T4 --open "$GATEWAY" 2>/dev/null || true)
        GW_OS=$(printf "%s\n" "$GW_NMAP" | awk -F': ' '/OS details/ {print $2}' | head -n1)
        [ -z "$GW_OS" ] && GW_OS=$(printf "%s\n" "$GW_NMAP" | awk -F': ' '/Running/ {print $2}' | head -n1)

        printf "  Gateway OS    : ${GREEN}%s${NC}\n" "${GW_OS:-Embedded Linux / Hardened Gateway}"
        printf "%s\n" "$GW_NMAP" | grep -E '^[0-9]+/(tcp|udp)' | while IFS= read -r port_line; do
            printf "    -> ${GREEN}%s${NC}\n" "$port_line"
        done
    fi

    # 6B. Subnet Neighbors Sweep
    TARGET_PEERS=()
    for ip in "${ACTIVE_HOSTS_LIST[@]}"; do
        if [ "$ip" != "$GATEWAY" ] && [ "$ip" != "$LOCAL_IP4" ]; then
            TARGET_PEERS+=("$ip")
        fi
    done

    if [ ${#TARGET_PEERS[@]} -gt 0 ]; then
        printf "\n  ${CYAN}[Target 2/2] Scanning %s active neighbor(s) for exposed ports...${NC}\n" "${#TARGET_PEERS[@]}"
        PEER_SCAN=$(nmap -sS -p 22,23,80,443,445,3389,8080 -T4 --open "${TARGET_PEERS[@]}" 2>/dev/null || true)

        CURRENT_HOST=""
        while IFS= read -r scan_line; do
            if printf "%s\n" "$scan_line" | grep -q "Nmap scan report for"; then
                CURRENT_HOST=$(printf "%s\n" "$scan_line" | awk '{print $NF}' | tr -d '()')
            elif printf "%s\n" "$scan_line" | grep -qE '^[0-9]+/tcp.*open'; then
                PORT_INFO=$(printf "%s\n" "$scan_line" | awk '{print $1 " " $3}')
                printf "    -> Host ${GREEN}%s${NC} has open: ${YELLOW}%s${NC}\n" "$CURRENT_HOST" "$PORT_INFO"
            fi
        done <<< "$PEER_SCAN"
    else
        printf "  ${GREEN}No other peers present on subnet to audit.${NC}\n"
    fi
else
    printf "  ${YELLOW}[Nmap not installed - Skipping active service detection]${NC}\n"
fi

# ----------------------------------------------------
# 7. Local Host Sockets Exposure
# ----------------------------------------------------
printf "\n${BOLD}${YELLOW}[7] Local Host Inbound Exposure (This Mac):${NC}\n"
LISTENING=$(lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1 {printf "    %-14s %-8s %s\n", $1, $9, $3}' | sort -u || true)
if [ -n "$LISTENING" ]; then
    printf "%s\n" "$LISTENING" | head -n 6
else
    printf "    ${GREEN}[SECURE] No listening ports exposed.${NC}\n"
fi

