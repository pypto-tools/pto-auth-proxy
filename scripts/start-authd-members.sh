#!/usr/bin/env bash
# Start one system-managed authd instance for every authorized proxy user.
# This is run once at boot so users never need to re-run join after a reboot.
set -Eeuo pipefail

LIST_ONLY=0
if [[ ${1:-} == --list ]]; then
    LIST_ONLY=1
    shift
fi
PROXY_GROUP=${1:-proxyusers}
PROXY_OWNER=${2:-pypto}

((LIST_ONLY || EUID == 0)) || {
    echo "authd member startup must run as root" >&2
    exit 1
}

group_entry=$(getent group "$PROXY_GROUP") || {
    echo "proxy group does not exist: $PROXY_GROUP" >&2
    exit 1
}
group_gid=$(cut -d: -f3 <<<"$group_entry")
supplementary_members=$(cut -d: -f4 <<<"$group_entry")

declare -A members=()
IFS=',' read -r -a listed_members <<<"$supplementary_members"
for user in "${listed_members[@]}"; do
    [[ -n "$user" && "$user" != "$PROXY_OWNER" ]] && members["$user"]=1
done
while IFS=: read -r user _ _ primary_gid _; do
    if [[ "$primary_gid" == "$group_gid" && "$user" != "$PROXY_OWNER" ]]; then
        members["$user"]=1
    fi
done < <(getent passwd)

if ((${#members[@]} == 0)); then
    echo "No users in $PROXY_GROUP; no authd instances to start"
    exit 0
fi

if ((LIST_ONLY)); then
    printf '%s\n' "${!members[@]}" | sort
    exit 0
fi

failures=0
install -d -m 0755 -o root -g root /run/pto-auth-proxy
while IFS= read -r user; do
    if ! id "$user" >/dev/null 2>&1; then
        echo "Skipping unknown user listed in $PROXY_GROUP: $user" >&2
        failures=1
        continue
    fi
    user_uid=$(id -u "$user")
    # Each user owns only their own directory. proxyusers can traverse it to
    # reach the socket but cannot pre-create or replace another user's path.
    install -d -m 0750 -o "$user" -g "$PROXY_GROUP" \
        "/run/pto-auth-proxy/$user_uid"
    unit=$(systemd-escape --template=pto-auth-proxy-authd@.service "$user")
    if systemctl start "$unit"; then
        echo "Started $unit"
    else
        echo "Failed to start $unit" >&2
        failures=1
    fi
done < <(printf '%s\n' "${!members[@]}" | sort)

exit "$failures"
