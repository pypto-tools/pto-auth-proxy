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
PROXY_USER=pypto
PROXY_GROUP=proxyusers

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
        --proxy-user) PROXY_USER=$2; shift 2 ;;
        --proxy-group) PROXY_GROUP=$2; shift 2 ;;
        -h|--help)
            cat <<'EOF'
用法: scripts/install.sh [OPTIONS]

只安装程序；默认不创建配置、不安装 service、不启动服务。

  --init-config          首次创建配置和白名单（已有文件不覆盖）
  --install-service      安装 systemd unit，但不 enable/start/restart
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

install -d -m 0755 "$PREFIX/bin" "$PREFIX/auth-proxy" \
    "$CONFIG_DIR" "$TMP_DIR"
install -d -m 0750 -o "$PROXY_USER" -g "$PROXY_GROUP" \
    "$STATE_DIR" "$STATE_DIR/reports" "$LOG_DIR"

install -m 0755 "$PROJECT_DIR/bin/pto-auth-proxy" \
    "$PREFIX/bin/pto-auth-proxy"
install -m 0755 "$PROJECT_DIR/auth_proxy.py" \
    "$PREFIX/auth-proxy/auth_proxy.py"
install -m 0755 "$PROJECT_DIR/authd.py" \
    "$PREFIX/auth-proxy/authd.py"
install -m 0755 "$PROJECT_DIR/join-proxy.sh" \
    "$PREFIX/auth-proxy/join-proxy.sh"
install -m 0755 "$PROJECT_DIR/test_proxy.sh" \
    "$PREFIX/auth-proxy/test_proxy.sh"
ln -sfn "$PREFIX/bin/pto-auth-proxy" "$BIN_LINK"

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
    trap 'rm -f "$service_tmp"' EXIT
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@TOOL_DIR@|$TOOL_DIR|g" \
        -e "s|@PROXY_USER@|$PROXY_USER|g" \
        -e "s|@PROXY_GROUP@|$PROXY_GROUP|g" \
        "$PROJECT_DIR/systemd/pto-auth-proxy.service.in" >"$service_tmp"
    install -m 0644 "$service_tmp" /etc/systemd/system/pto-auth-proxy.service
    systemctl daemon-reload
    echo "已安装 pto-auth-proxy.service；未启用、未启动"
fi

echo "程序: $PREFIX"
echo "配置: $CONFIG_DIR"
echo "状态: $STATE_DIR"
echo "日志: $LOG_DIR"
echo "命令: $BIN_LINK"
