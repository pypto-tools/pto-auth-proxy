#!/usr/bin/env bash
set -Eeuo pipefail

CHAIN=PTO_AUTH_PROXY_GUARD
PROXY_USER=${2:-pypto}
PORTS=${3:-${PTO_AUTH_PROXY_GUARD_PORTS:-${PTO_AUTH_PROXY_UPSTREAM_PORT:-4780},4781}}

IFS=, read -r -a port_values <<<"$PORTS"
((${#port_values[@]} > 0)) || {
    echo "egress guard ports must not be empty" >&2
    exit 2
}
for port in "${port_values[@]}"; do
    [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) || {
        echo "invalid egress guard port: $port" >&2
        exit 2
    }
done

usage() {
    echo "Usage: $0 {start|reload|stop|check|watch} [PROXY_USER] [PORTS]" >&2
    exit 2
}

((EUID == 0)) || {
    echo "egress guard must run as root" >&2
    exit 1
}

PROXY_UID=$(id -u "$PROXY_USER") || {
    echo "proxy user does not exist: $PROXY_USER" >&2
    exit 1
}

pick_tool() {
    local family=$1 candidate
    for candidate in "${family}tables-legacy" "${family}tables"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            command -v "$candidate"
            return
        fi
    done
    echo "missing ${family}tables command" >&2
    return 1
}

IPTABLES=$(pick_tool ip)
IP6TABLES=$(pick_tool ip6)

remove_jump() {
    local tool=$1
    while "$tool" -w 10 -t filter -C OUTPUT -j "$CHAIN" 2>/dev/null; do
        "$tool" -w 10 -t filter -D OUTPUT -j "$CHAIN"
    done
}

stop_family() {
    local tool=$1
    remove_jump "$tool"
    if "$tool" -w 10 -t filter -nL "$CHAIN" >/dev/null 2>&1; then
        "$tool" -w 10 -t filter -F "$CHAIN"
        "$tool" -w 10 -t filter -X "$CHAIN"
    fi
}

start_family() {
    local tool=$1 destination=$2

    "$tool" -w 10 -t filter -N "$CHAIN" 2>/dev/null || true
    "$tool" -w 10 -t filter -F "$CHAIN"
    "$tool" -w 10 -t filter -A "$CHAIN" \
        -d "$destination" -p tcp -m multiport --dports "$PORTS" \
        -m owner --uid-owner "$PROXY_UID" -j RETURN
    "$tool" -w 10 -t filter -A "$CHAIN" \
        -d "$destination" -p tcp -m multiport --dports "$PORTS" \
        -j REJECT --reject-with tcp-reset

    remove_jump "$tool"
    "$tool" -w 10 -t filter -I OUTPUT 1 -j "$CHAIN"
}

check_family() {
    local tool=$1 destination=$2
    "$tool" -w 10 -t filter -C OUTPUT -j "$CHAIN"
    "$tool" -w 10 -t filter -C "$CHAIN" \
        -d "$destination" -p tcp -m multiport --dports "$PORTS" \
        -m owner --uid-owner "$PROXY_UID" -j RETURN
    "$tool" -w 10 -t filter -C "$CHAIN" \
        -d "$destination" -p tcp -m multiport --dports "$PORTS" \
        -j REJECT --reject-with tcp-reset
}

check_all() {
    check_family "$IPTABLES" 127.0.0.0/8 &&
        check_family "$IP6TABLES" ::1/128
}

start_all() {
    start_family "$IPTABLES" 127.0.0.0/8
    start_family "$IP6TABLES" ::1/128
}

case "${1:-}" in
    start|reload)
        start_all
        ;;
    stop)
        stop_family "$IPTABLES"
        stop_family "$IP6TABLES"
        ;;
    check)
        check_all
        ;;
    watch)
        WATCH_INTERVAL=${PTO_AUTH_PROXY_GUARD_INTERVAL:-30}
        [[ "$WATCH_INTERVAL" =~ ^[0-9]+$ ]] && ((WATCH_INTERVAL >= 5)) || {
            echo "PTO_AUTH_PROXY_GUARD_INTERVAL must be an integer >= 5" >&2
            exit 2
        }
        trap 'exit 0' TERM INT
        check_all >/dev/null 2>&1 || start_all
        while true; do
            sleep "$WATCH_INTERVAL" &
            wait $! || exit 0
            if ! check_all >/dev/null 2>&1; then
                echo "egress guard rule drift detected; restoring rules" >&2
                start_all
            fi
        done
        ;;
    *) usage ;;
esac
