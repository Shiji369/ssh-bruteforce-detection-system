#!/bin/bash

# ==================================================
# SSH BRUTE-FORCE DETECTION SYSTEM
# ==================================================

THRESHOLD=5
BLOCK_THRESHOLD=10
WINDOW_MIN=10

LOGFILE=""
LOG_TYPE=""
OUTFILE="./flagged_ips.txt"
AUTO_BLOCK=true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ==================================================
# FUNCTIONS
# ==================================================

block_ip() {

    local ip="$1"

    # Never block localhost
    if [ "$ip" = "127.0.0.1" ] || [ "$ip" = "::1" ]; then
        echo -e "${YELLOW}[WARNING] Localhost will not be blocked: $ip${NC}"
        return
    fi

    # IPv4
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then

        if sudo iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            echo "[INFO] IPv4 already blocked: $ip"
        else
            sudo iptables -I INPUT -s "$ip" -j DROP

            if [ $? -eq 0 ]; then
                echo -e "${RED}[BLOCKED] IPv4: $ip${NC}"
            else
                echo "[ERROR] Failed to block IPv4: $ip"
            fi
        fi

    # IPv6
    elif [[ "$ip" == *:* ]]; then

        if sudo ip6tables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            echo "[INFO] IPv6 already blocked: $ip"
        else
            sudo ip6tables -I INPUT -s "$ip" -j DROP

            if [ $? -eq 0 ]; then
                echo -e "${RED}[BLOCKED] IPv6: $ip${NC}"
            else
                echo "[ERROR] Failed to block IPv6: $ip"
            fi
        fi

    else
        echo "[ERROR] Invalid IP address: $ip"
    fi
}

unblock_ip() {

    local ip="$1"

    # IPv6
    if [[ "$ip" == *:* ]]; then

        if sudo ip6tables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            sudo ip6tables -D INPUT -s "$ip" -j DROP
            echo -e "${GREEN}[UNBLOCKED] IPv6: $ip${NC}"
        else
            echo "[INFO] IPv6 is not blocked: $ip"
        fi

    # IPv4
    else

        if sudo iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            sudo iptables -D INPUT -s "$ip" -j DROP
            echo -e "${GREEN}[UNBLOCKED] IPv4: $ip${NC}"
        else
            echo "[INFO] IPv4 is not blocked: $ip"
        fi

    fi
}

# ==================================================
# COMMAND LINE OPTIONS
# ==================================================

while getopts "t:w:l:o:u:h" opt; do

    case "$opt" in

        t)
            THRESHOLD="$OPTARG"
            ;;

        w)
            WINDOW_MIN="$OPTARG"
            ;;

        l)
            LOGFILE="$OPTARG"
            LOG_TYPE="file"
            ;;

        o)
            OUTFILE="$OPTARG"
            ;;

        u)
            unblock_ip "$OPTARG"
            exit 0
            ;;

        h)
            echo
            echo "Usage:"
            echo "  sudo $0"
            echo "  sudo $0 -t 3 -w 5"
            echo "  sudo $0 -u IP_ADDRESS"
            echo
            echo "Options:"
            echo "  -t    Alert threshold"
            echo "  -w    Time window in minutes"
            echo "  -l    Custom log file"
            echo "  -o    Output file"
            echo "  -u    Unblock an IP"
            echo "  -h    Help"
            echo
            exit 0
            ;;

        *)
            echo "Invalid option. Use -h for help."
            exit 1
            ;;

    esac

done

# ==================================================
# VALIDATION
# ==================================================

if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]] || [ "$THRESHOLD" -lt 1 ]; then
    echo "[ERROR] Invalid threshold."
    exit 1
fi

if ! [[ "$WINDOW_MIN" =~ ^[0-9]+$ ]] || [ "$WINDOW_MIN" -lt 1 ]; then
    echo "[ERROR] Invalid time window."
    exit 1
fi

WINDOW_SEC=$((WINDOW_MIN * 60))

# ==================================================
# AUTOMATIC LOG SOURCE DETECTION
# ==================================================

if [ -z "$LOG_TYPE" ]; then

    if [ -f "/var/log/auth.log" ]; then

        LOGFILE="/var/log/auth.log"
        LOG_TYPE="file"

    elif [ -f "/var/log/secure" ]; then

        LOGFILE="/var/log/secure"
        LOG_TYPE="file"

    elif command -v journalctl >/dev/null 2>&1; then

        LOG_TYPE="journal"

    else

        echo "[ERROR] No supported SSH log source found."
        exit 1

    fi

fi

# ==================================================
# VALIDATE LOG FILE
# ==================================================

if [ "$LOG_TYPE" = "file" ] && [ ! -f "$LOGFILE" ]; then

    echo "[ERROR] Log file not found: $LOGFILE"
    exit 1

fi

# ==================================================
# DISPLAY CONFIGURATION
# ==================================================

echo "=================================================="
echo "       SSH Brute-Force Detection System"
echo "=================================================="

if [ "$LOG_TYPE" = "file" ]; then
    echo "Log source      : $LOGFILE"
else
    echo "Log source      : systemd journal"
fi

echo "Alert threshold : $THRESHOLD attempts"
echo "Block threshold : $BLOCK_THRESHOLD attempts"
echo "Window          : $WINDOW_MIN minute(s)"
echo "Output          : $OUTFILE"

if [ "$AUTO_BLOCK" = true ]; then
    echo -e "Auto-block      : ${RED}ENABLED${NC}"
else
    echo -e "Auto-block      : ${GREEN}DISABLED${NC}"
fi

echo "Press Ctrl+C to stop."
echo "=================================================="

# ==================================================
# IN-MEMORY DATA
# ==================================================

declare -A IP_TIMESTAMPS
declare -A ALERTED
declare -A BLOCKED

# ==================================================
# LIVE LOG MONITORING
# ==================================================

if [ "$LOG_TYPE" = "file" ]; then

    tail -n 0 -F "$LOGFILE"

elif [ "$LOG_TYPE" = "journal" ]; then

    journalctl -u ssh -f -o cat

fi |
grep --line-buffered "Failed password" |
while IFS= read -r line
do

    # ==================================================
    # EXTRACT IPv4 / IPv6
    # ==================================================

    ip=$(echo "$line" | sed -nE 's/.*from ([0-9a-fA-F:.]+) port.*/\1/p')

    [ -z "$ip" ] && continue

    # ==================================================
    # CURRENT TIME
    # ==================================================

    now=$(date +%s)

    # ==================================================
    # ADD TIMESTAMP
    # ==================================================

    IP_TIMESTAMPS[$ip]="${IP_TIMESTAMPS[$ip]} $now"

    # ==================================================
    # REMOVE OLD ATTEMPTS
    # ==================================================

    recent=""
    count=0

    for t in ${IP_TIMESTAMPS[$ip]}
    do

        if [ $((now - t)) -le "$WINDOW_SEC" ]; then

            recent="$recent $t"
            count=$((count + 1))

        fi

    done

    IP_TIMESTAMPS[$ip]="$recent"

    # ==================================================
    # DISPLAY EVENT
    # ==================================================

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Failed SSH login from $ip | Attempts: $count"

    # ==================================================
    # ALERT AT 5 ATTEMPTS
    # ==================================================

    if [ "$count" -ge "$THRESHOLD" ]; then

        if [ "${ALERTED[$ip]}" != "1" ]; then

            echo -e "${RED}----------------------------------------------------${NC}"
            echo -e "${RED}[ALERT] Possible SSH brute-force attack!${NC}"
            echo -e "${RED}Source IP : $ip${NC}"
            echo -e "${RED}Attempts  : $count${NC}"
            echo -e "${RED}Window    : $WINDOW_MIN minute(s)${NC}"
            echo -e "${RED}----------------------------------------------------${NC}"

            echo "$(date '+%Y-%m-%d %H:%M:%S') | IP: $ip | Attempts: $count | Possible SSH Brute-Force" >> "$OUTFILE"

            ALERTED[$ip]=1

        fi

    fi

    # ==================================================
    # BLOCK AT 10 ATTEMPTS
    # ==================================================

    if [ "$count" -ge "$BLOCK_THRESHOLD" ]; then

        if [ "${BLOCKED[$ip]}" != "1" ]; then

            echo -e "${RED}====================================================${NC}"
            echo -e "${RED}[BLOCK] $ip reached $count failed attempts!${NC}"
            echo -e "${RED}Action: Automatically blocking IP${NC}"
            echo -e "${RED}====================================================${NC}"

            if [ "$AUTO_BLOCK" = true ]; then
                block_ip "$ip"
            fi

            BLOCKED[$ip]=1

        fi

    fi

done
