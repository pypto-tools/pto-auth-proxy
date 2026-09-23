#!/usr/bin/env bash
# leave-proxy.sh — revoke the current user's proxy access and undo join.

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ME=$(id -un)
UID_NUM=$(id -u)
AUTHD_CONFIG_HOME=$HOME/.config/pto-auth-proxy
SHELL_CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy
DISABLED_FILE=$AUTHD_CONFIG_HOME/access.disabled
BEGIN_MARKER='# >>> pto-auth-proxy managed environment >>>'
END_MARKER='# <<< pto-auth-proxy managed environment <<<'
LEGACY_BEGIN_MARKER='# ---- 686 authenticated proxy ----'
LEGACY_END_MARKER='# ---------------------------------'
FAILED=0
TEMP_FILES=()

pass() { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }

cleanup() {
    ((${#TEMP_FILES[@]} == 0)) || rm -f -- "${TEMP_FILES[@]}"
}
trap cleanup EXIT

disable_access() {
    local temporary
    install -d -m 0700 "$AUTHD_CONFIG_HOME"
    temporary=$(mktemp "$AUTHD_CONFIG_HOME/.access-disabled.XXXXXX")
    TEMP_FILES+=("$temporary")
    chmod 0600 "$temporary"
    printf '%s\n' 'disabled by pto-auth-proxy leave' >"$temporary"
    mv -f -- "$temporary" "$DISABLED_FILE"

    rm -f -- "$AUTHD_CONFIG_HOME/token.sha256"
    rm -f -- "$AUTHD_CONFIG_HOME/secret-uri" "$AUTHD_CONFIG_HOME/env.sh"
    if [[ "$SHELL_CONFIG_HOME" != "$AUTHD_CONFIG_HOME" ]]; then
        rm -f -- "$SHELL_CONFIG_HOME/secret-uri" "$SHELL_CONFIG_HOME/env.sh"
    fi
    pass "proxy token revoked and future authentication disabled"
}

remove_shell_block() {
    local display_path=$1 shell_rc=$1 temporary
    local begin_count end_count legacy_begin_count legacy_end_count

    [[ -e "$shell_rc" || -L "$shell_rc" ]] || return 0
    if [[ -L "$shell_rc" ]]; then
        shell_rc=$(readlink -f -- "$shell_rc") || {
            warn "cannot edit dangling shell startup symlink: $display_path"
            return 1
        }
    fi
    [[ -f "$shell_rc" && -w "$shell_rc" ]] || {
        warn "shell startup file is not writable: $display_path"
        return 1
    }

    begin_count=$(grep -Fxc "$BEGIN_MARKER" "$shell_rc" || true)
    end_count=$(grep -Fxc "$END_MARKER" "$shell_rc" || true)
    legacy_begin_count=$(grep -Fxc "$LEGACY_BEGIN_MARKER" "$shell_rc" || true)
    legacy_end_count=$(grep -Fxc "$LEGACY_END_MARKER" "$shell_rc" || true)
    if ((begin_count != end_count || begin_count > 1 ||
         legacy_begin_count != legacy_end_count || legacy_begin_count > 1)); then
        warn "refusing to edit malformed proxy block in $display_path"
        return 1
    fi
    if ((begin_count == 0 && legacy_begin_count == 0)); then
        return 0
    fi

    temporary=$(mktemp "${shell_rc}.pto-auth-proxy-leave.XXXXXX")
    TEMP_FILES+=("$temporary")
    awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" \
        -v legacy_begin="$LEGACY_BEGIN_MARKER" \
        -v legacy_end="$LEGACY_END_MARKER" '
        $0 == begin || $0 == legacy_begin { skipping = 1; next }
        ($0 == end || $0 == legacy_end) && skipping { skipping = 0; next }
        !skipping { print }
    ' "$shell_rc" >"$temporary"
    chmod --reference="$shell_rc" "$temporary"
    mv -f -- "$temporary" "$shell_rc"
    pass "removed managed proxy environment from $display_path"
}

stop_compatibility_authd() {
    if [[ ${PTO_AUTH_PROXY_LEAVE_SKIP_PROCESS_STOP:-0} == 1 ]]; then
        return 0
    fi
    pkill -u "$ME" -f authproxy-watchdog.sh 2>/dev/null || true
    pkill -u "$ME" -f authproxy-authd.py 2>/dev/null || true
}

revoke_running_authd() {
    local system_socket="/run/pto-auth-proxy/${UID_NUM}/authd.sock"
    local legacy_socket="/tmp/authproxy-${ME}.sock"

    if [[ ${PTO_AUTH_PROXY_LEAVE_SKIP_PROCESS_STOP:-0} == 1 ]]; then
        return 0
    fi
    if SOCKET_LIST="$system_socket:$legacy_socket" USER_NAME="$ME" \
        python3 - <<'PY'
import json
import os
import socket

for path in os.environ["SOCKET_LIST"].split(":"):
    if not path:
        continue
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3)
            client.connect(path)
            request = {"op": "revoke-token", "user": os.environ["USER_NAME"]}
            client.sendall((json.dumps(request) + "\n").encode())
            reply = json.loads(client.recv(4096).decode())
        if reply.get("ok"):
            raise SystemExit(0)
    except (OSError, ValueError, json.JSONDecodeError):
        continue
raise SystemExit(1)
PY
    then
        pass "running authd acknowledged logout"
        return 0
    fi

    # An authd started before this feature was deployed does not understand
    # revoke-token. Terminating only this user's daemon makes systemd reload
    # the installed code; a non-systemd daemon remains stopped. If no matching
    # process can be signalled, unlink its sockets so it cannot accept a new
    # authentication request before the next restart.
    if pkill -u "$ME" -f "$SCRIPT_DIR/authd.py" 2>/dev/null; then
        pass "reloaded the current user's authd to enforce logout"
    else
        rm -f -- "$system_socket" "$legacy_socket" 2>/dev/null || {
            warn "could not detach an older authd socket"
            return 1
        }
    fi
}

disable_access
revoke_running_authd || FAILED=1
stop_compatibility_authd

if [[ -n ${PTO_AUTH_PROXY_SHELL_RC:-} ]]; then
    remove_shell_block "$PTO_AUTH_PROXY_SHELL_RC" || FAILED=1
else
    remove_shell_block "$HOME/.bashrc" || FAILED=1
    remove_shell_block "$HOME/.zshrc" || FAILED=1
fi

echo
echo "Proxy access for $ME is disabled."
echo "  - new proxy authentication attempts are rejected"
echo "  - open a new terminal to drop inherited proxy environment variables"
echo "  - run 'pto-auth-proxy join' to enable access again"
echo "  - administrators may also remove unused accounts from proxyusers"
if ((FAILED)); then
    warn "access is disabled, but one or more shell startup files need manual cleanup"
    exit 1
fi
