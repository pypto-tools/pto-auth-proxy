#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TOOLS_ROOT=/home/pypto-tools
TOOL_NAME=pto-auth-proxy
TOOL_DIR=$TOOLS_ROOT/$TOOL_NAME
PREFIX=$TOOL_DIR/app
CONFIG_DIR=$TOOL_DIR/config
STATE_DIR=$TOOL_DIR/state
LOG_DIR=$TOOL_DIR/logs
TMP_DIR=$TOOL_DIR/tmp
BIN_LINK=/usr/local/bin/pto-auth-proxy
INIT_CONFIG=0
INSTALL_SERVICE=0
ENABLE_SERVICE=0
INSTALL_UPDATER=0
ENABLE_UPDATER=0
PROXY_USER=pypto
PROXY_GROUP=proxyusers
INSTALL_TEMP_FILES=()

cleanup() {
    ((${#INSTALL_TEMP_FILES[@]} == 0)) || rm -f -- "${INSTALL_TEMP_FILES[@]}"
}
trap cleanup EXIT

while (($#)); do
    case "$1" in
        --tools-root)
            TOOLS_ROOT=$2
            TOOL_DIR=$TOOLS_ROOT/$TOOL_NAME
            PREFIX=$TOOL_DIR/app
            CONFIG_DIR=$TOOL_DIR/config
            STATE_DIR=$TOOL_DIR/state
            LOG_DIR=$TOOL_DIR/logs
            TMP_DIR=$TOOL_DIR/tmp
            shift 2
            ;;
        --prefix) PREFIX=$2; shift 2 ;;
        --init-config) INIT_CONFIG=1; shift ;;
        --install-service) INSTALL_SERVICE=1; shift ;;
        --enable-service)
            INSTALL_SERVICE=1
            ENABLE_SERVICE=1
            shift
            ;;
        --install-updater) INSTALL_UPDATER=1; shift ;;
        --enable-updater)
            INSTALL_UPDATER=1
            ENABLE_UPDATER=1
            shift
            ;;
        --proxy-user) PROXY_USER=$2; shift 2 ;;
        --proxy-group) PROXY_GROUP=$2; shift 2 ;;
        -h|--help)
            cat <<'EOF'
用法: scripts/install.sh [OPTIONS]

只安装程序；默认不创建配置、不安装 service、不启用或启动服务。

  --init-config          首次创建配置和白名单（已有文件不覆盖）
  --install-service      安装主代理、守卫及 authd unit，但不 enable/start/restart
  --enable-service       安装并启用全部开机服务，但不立即启动任何服务
  --install-updater      安装独立更新服务和 timer，但不启用
  --enable-updater       安装并启用更新轮询 timer（不会重启代理）
  --proxy-user USER      服务用户，默认 pypto
  --proxy-group GROUP    服务用户组，默认 proxyusers
  --tools-root DIR       默认 /home/pypto-tools
  --prefix DIR           覆盖 app 安装目录
EOF
            exit 0
            ;;
        *) echo "未知参数: $1" >&2; exit 2 ;;
    esac
done

((EUID == 0)) || {
    echo "安装到正式目录需要 root" >&2
    exit 1
}
id "$PROXY_USER" >/dev/null 2>&1 || {
    echo "服务用户不存在: $PROXY_USER" >&2
    exit 1
}
getent group "$PROXY_GROUP" >/dev/null 2>&1 || {
    echo "服务用户组不存在: $PROXY_GROUP" >&2
    exit 1
}

install_atomic() {
    local source=$1 destination=$2 mode=$3 temporary
    temporary=$(mktemp "${destination%/*}/.pto-auth-proxy-install.XXXXXX")
    INSTALL_TEMP_FILES+=("$temporary")
    install -m "$mode" "$source" "$temporary"
    chown root:root "$temporary"
    mv -Tf -- "$temporary" "$destination"
}

install -d -m 0755 "$PREFIX/bin" "$PREFIX/auth-proxy" \
    "$PREFIX/lib/repo-auto-update" \
    "$CONFIG_DIR" "$TMP_DIR"
install -d -m 0750 -o "$PROXY_USER" -g "$PROXY_GROUP" \
    "$STATE_DIR" "$STATE_DIR/reports" "$LOG_DIR"

install_atomic "$PROJECT_DIR/bin/pto-auth-proxy" \
    "$PREFIX/bin/pto-auth-proxy" 0755
install_atomic "$PROJECT_DIR/auth_proxy.py" \
    "$PREFIX/auth-proxy/auth_proxy.py" 0755
install_atomic "$PROJECT_DIR/authd.py" \
    "$PREFIX/auth-proxy/authd.py" 0755
install_atomic "$PROJECT_DIR/join-proxy.sh" \
    "$PREFIX/auth-proxy/join-proxy.sh" 0755
install_atomic "$PROJECT_DIR/configure-shell.sh" \
    "$PREFIX/auth-proxy/configure-shell.sh" 0755
install_atomic "$PROJECT_DIR/status_proxy.py" \
    "$PREFIX/auth-proxy/status_proxy.py" 0755
install_atomic "$PROJECT_DIR/test_proxy.sh" \
    "$PREFIX/auth-proxy/test_proxy.sh" 0755
install_atomic "$PROJECT_DIR/scripts/egress-guard.sh" \
    "$PREFIX/bin/pto-auth-proxy-egress-guard" 0755
install_atomic "$PROJECT_DIR/scripts/start-authd-members.sh" \
    "$PREFIX/bin/pto-auth-proxy-start-authd-members" 0755
install_atomic "$PROJECT_DIR/modules/repo_auto_update/updater.sh" \
    "$PREFIX/lib/repo-auto-update/updater.sh" 0755
install_atomic "$PROJECT_DIR/modules/repo_auto_update/manifest.py" \
    "$PREFIX/lib/repo-auto-update/manifest.py" 0755
install_atomic "$PROJECT_DIR/scripts/auto-update-adapter.sh" \
    "$PREFIX/bin/pto-auth-proxy-update-verify" 0755
install_atomic "$PROJECT_DIR/scripts/auto-update-adapter.sh" \
    "$PREFIX/bin/pto-auth-proxy-update-apply" 0755
expected_bin_link=$PREFIX/bin/pto-auth-proxy
if [[ ! -L "$BIN_LINK" || $(readlink -- "$BIN_LINK") != "$expected_bin_link" ]]; then
    ln -sfn "$expected_bin_link" "$BIN_LINK"
fi

if ((INIT_CONFIG)); then
    [[ -e "$CONFIG_DIR/auth-proxy.env" ]] ||
        install -m 0644 "$PROJECT_DIR/config/auth-proxy.env.example" \
            "$CONFIG_DIR/auth-proxy.env"
    [[ -e "$CONFIG_DIR/whitelist.txt" ]] ||
        install -m 0644 "$PROJECT_DIR/config/whitelist.txt" \
            "$CONFIG_DIR/whitelist.txt"
fi

if ((INSTALL_SERVICE)); then
    service_tmp=$(mktemp /tmp/pto-auth-proxy.service.XXXXXX)
    authd_service_tmp=$(mktemp /tmp/pto-auth-proxy-authd.service.XXXXXX)
    members_service_tmp=$(mktemp /tmp/pto-auth-proxy-authd-members.service.XXXXXX)
    guard_service_tmp=$(mktemp /tmp/pto-auth-proxy-egress-guard.service.XXXXXX)
    INSTALL_TEMP_FILES+=("$service_tmp" "$authd_service_tmp" \
        "$members_service_tmp" "$guard_service_tmp")
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@TOOL_DIR@|$TOOL_DIR|g" \
        -e "s|@PROXY_USER@|$PROXY_USER|g" \
        -e "s|@PROXY_GROUP@|$PROXY_GROUP|g" \
        "$PROJECT_DIR/systemd/pto-auth-proxy.service.in" >"$service_tmp"
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@TOOL_DIR@|$TOOL_DIR|g" \
        "$PROJECT_DIR/systemd/pto-auth-proxy-authd@.service.in" \
        >"$authd_service_tmp"
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@PROXY_USER@|$PROXY_USER|g" \
        -e "s|@PROXY_GROUP@|$PROXY_GROUP|g" \
        "$PROJECT_DIR/systemd/pto-auth-proxy-authd-members.service.in" \
        >"$members_service_tmp"
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@TOOL_DIR@|$TOOL_DIR|g" \
        -e "s|@PROXY_USER@|$PROXY_USER|g" \
        "$PROJECT_DIR/systemd/pto-auth-proxy-egress-guard.service.in" \
        >"$guard_service_tmp"
    install -m 0644 "$service_tmp" /etc/systemd/system/pto-auth-proxy.service
    install -m 0644 "$authd_service_tmp" \
        /etc/systemd/system/pto-auth-proxy-authd@.service
    install -m 0644 "$members_service_tmp" \
        /etc/systemd/system/pto-auth-proxy-authd-members.service
    install -m 0644 "$guard_service_tmp" \
        /etc/systemd/system/pto-auth-proxy-egress-guard.service
    systemctl daemon-reload
    if ((ENABLE_SERVICE)); then
        systemctl enable pto-auth-proxy-authd-members.service \
            pto-auth-proxy-egress-guard.service pto-auth-proxy.service
        echo "已安装全部 unit 并启用成员 authd、出口守卫和主代理；当前均未启动"
    else
        echo "已安装主代理、守卫、成员启动器及 authd 模板；未启用、未启动"
    fi
fi

if ((INSTALL_UPDATER)); then
    updater_service_tmp=$(mktemp /tmp/pto-auth-proxy-auto-update.service.XXXXXX)
    updater_timer_tmp=$(mktemp /tmp/pto-auth-proxy-auto-update.timer.XXXXXX)
    updater_config_tmp=$(mktemp /tmp/pto-auth-proxy-auto-update.env.XXXXXX)
    INSTALL_TEMP_FILES+=("$updater_service_tmp" "$updater_timer_tmp" \
        "$updater_config_tmp")
    sed -e "s|@NAME@|pto-auth-proxy|g" \
        -e "s|@UPDATER@|$PREFIX/lib/repo-auto-update/updater.sh|g" \
        -e "s|@CONFIG@|$CONFIG_DIR/auto-update.env|g" \
        -e "s|@READ_WRITE_PATHS@|$TOOL_DIR /etc/systemd/system /run/lock|g" \
        "$PROJECT_DIR/modules/repo_auto_update/repo-auto-update.service.in" \
        >"$updater_service_tmp"
    sed -e "s|@NAME@|pto-auth-proxy|g" \
        -e "s|@SERVICE_NAME@|pto-auth-proxy-auto-update.service|g" \
        "$PROJECT_DIR/modules/repo_auto_update/repo-auto-update.timer.in" \
        >"$updater_timer_tmp"
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@TOOL_DIR@|$TOOL_DIR|g" \
        -e "s|@PROXY_USER@|$PROXY_USER|g" \
        "$PROJECT_DIR/config/auto-update.env.in" >"$updater_config_tmp"
    [[ -e "$CONFIG_DIR/auto-update.env" ]] || \
        install -m 0644 "$updater_config_tmp" "$CONFIG_DIR/auto-update.env"
    install -m 0644 "$updater_service_tmp" \
        /etc/systemd/system/pto-auth-proxy-auto-update.service
    install -m 0644 "$updater_timer_tmp" \
        /etc/systemd/system/pto-auth-proxy-auto-update.timer
    systemctl daemon-reload
    if ((ENABLE_UPDATER)); then
        systemctl enable --now pto-auth-proxy-auto-update.timer
        echo "更新轮询 timer 已启用；是否部署及目标 commit 由主仓 rollout 控制，不会重启代理"
    else
        echo "已安装自动更新 unit；timer 未启用"
    fi
fi

echo "程序: $PREFIX"
echo "配置: $CONFIG_DIR"
echo "状态: $STATE_DIR"
echo "日志: $LOG_DIR"
echo "命令: $BIN_LINK"
