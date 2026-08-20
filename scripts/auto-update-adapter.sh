#!/usr/bin/env bash
# pto-auth-proxy adapter for the generic repo_auto_update module.
# The generic module runs this as pypto for verify and as root for apply.
set -Eeuo pipefail

CHECKOUT=${1:?missing checkout}
TARGET=${2:?missing target}
SCRATCH_DIR=${3:?missing scratch directory}
MODE=${REPO_AUTO_UPDATE_ADAPTER_MODE:-}

case "$MODE" in
    verify)
        cd -- "$CHECKOUT"
        exec bash tests/run.sh
        ;;
    apply)
        ((EUID == 0)) || {
            echo "pto-auth-proxy update application must run as root" >&2
            exit 1
        }
        SCRIPT_PATH=$(readlink -f -- "${BASH_SOURCE[0]}")
        PREFIX=$(cd -- "$(dirname -- "$SCRIPT_PATH")/.." && pwd)
        TOOL_DIR=$(cd -- "$PREFIX/.." && pwd)
        AUTH_CONFIG=$TOOL_DIR/config/auth-proxy.env
        [[ -f "$AUTH_CONFIG" && ! -L "$AUTH_CONFIG" &&
           $(stat -c %u "$AUTH_CONFIG") == 0 &&
           $((8#$(stat -c %a "$AUTH_CONFIG") & 8#022)) == 0 ]] || {
            echo "unsafe auth-proxy configuration" >&2
            exit 1
        }
        set -a
        # shellcheck source=/dev/null
        source "$AUTH_CONFIG"
        set +a
        PROXY_OWNER=${PTO_AUTH_PROXY_OWNER:-pypto}
        PROXY_GROUP=${PTO_AUTH_PROXY_GROUP:-proxyusers}

        backup=$SCRATCH_DIR/application-backup
        failed_application=$SCRATCH_DIR/failed-application
        unit_backup=$SCRATCH_DIR/unit-backup
        units=(
            pto-auth-proxy.service
            pto-auth-proxy-authd@.service
            pto-auth-proxy-authd-members.service
            pto-auth-proxy-egress-guard.service
            pto-auth-proxy-auto-update.service
            pto-auth-proxy-auto-update.timer
        )
        cp -a -- "$PREFIX" "$backup"
        install -d -m 0700 "$unit_backup"
        for unit in "${units[@]}"; do
            unit_path=/etc/systemd/system/$unit
            if [[ -e "$unit_path" || -L "$unit_path" ]]; then
                cp -a -- "$unit_path" "$unit_backup/$unit"
            else
                : >"$unit_backup/$unit.absent"
            fi
        done

        restore_pending=1
        restore_previous() {
            local unit unit_path restore_failed=0
            mv -- "$PREFIX" "$failed_application" || return 1
            if ! mv -- "$backup" "$PREFIX"; then
                mv -- "$failed_application" "$PREFIX" || true
                return 1
            fi
            for unit in "${units[@]}"; do
                unit_path=/etc/systemd/system/$unit
                if [[ -e "$unit_backup/$unit" || -L "$unit_backup/$unit" ]]; then
                    cp -a -- "$unit_backup/$unit" "$unit_path" || restore_failed=1
                else
                    rm -f -- "$unit_path" || restore_failed=1
                fi
            done
            systemctl daemon-reload || restore_failed=1
            return "$restore_failed"
        }
        finish_apply() {
            local rc=$?
            trap - EXIT
            if ((restore_pending)); then
                echo "candidate install failed; restoring previous application and units" >&2
                restore_previous || rc=1
            fi
            exit "$rc"
        }
        trap finish_apply EXIT

        if bash "$CHECKOUT/scripts/install.sh" \
                --tools-root "$(dirname -- "$TOOL_DIR")" \
                --proxy-user "$PROXY_OWNER" \
                --proxy-group "$PROXY_GROUP" \
                --install-service \
                --install-updater; then
            restore_pending=0
            printf 'pto-auth-proxy update adapter applied %s\n' "${TARGET:0:12}"
            exit 0
        fi
        exit 1
        ;;
    *)
        echo "REPO_AUTO_UPDATE_ADAPTER_MODE must be verify or apply" >&2
        exit 2
        ;;
esac
