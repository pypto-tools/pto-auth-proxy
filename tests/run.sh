#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

for file in \
    "$PROJECT_DIR/bin/pto-auth-proxy" \
    "$PROJECT_DIR/configure-shell.sh" \
    "$PROJECT_DIR/join-proxy.sh" \
    "$PROJECT_DIR/test_proxy.sh" \
    "$PROJECT_DIR/scripts/egress-guard.sh" \
    "$PROJECT_DIR/scripts/auto-update-adapter.sh" \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh" \
    "$PROJECT_DIR/scripts/start-authd-members.sh" \
    "$PROJECT_DIR/scripts/install.sh"; do
    bash -n "$file"
done

PYTHONDONTWRITEBYTECODE=1 python3 - "$PROJECT_DIR/auth_proxy.py" \
    "$PROJECT_DIR/authd.py" "$PROJECT_DIR/status_proxy.py" \
    "$PROJECT_DIR/modules/repo_auto_update/manifest.py" <<'PY'
from pathlib import Path
import sys

for name in sys.argv[1:]:
    path = Path(name)
    compile(path.read_text(), str(path), "exec")
PY

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PROJECT_DIR" \
    python3 -m unittest discover -s "$PROJECT_DIR/tests" -p 'test_*.py' -v

# Validation checks both configuration and the runtime account. Exercise it
# through a symlink as installed in /usr/local/bin, so path resolution cannot
# regress to /usr/local/config.
TEST_TMP=$(mktemp -d)
trap 'rm -rf -- "$TEST_TMP"' EXIT
CURRENT_USER=$(id -un)
sed "s/^PTO_AUTH_PROXY_OWNER=.*/PTO_AUTH_PROXY_OWNER=$CURRENT_USER/" \
    "$PROJECT_DIR/config/auth-proxy.env.example" >"$TEST_TMP/auth-proxy.env"
ln -s "$PROJECT_DIR/bin/pto-auth-proxy" "$TEST_TMP/pto-auth-proxy"
"$TEST_TMP/pto-auth-proxy" --config "$TEST_TMP/auth-proxy.env" validate

if [[ "$CURRENT_USER" != pypto ]]; then
    if "$PROJECT_DIR/bin/pto-auth-proxy" validate \
        >"$TEST_TMP/wrong-user.out" 2>&1; then
        echo "validate 应拒绝非 pypto 用户" >&2
        exit 1
    fi
    grep -Fq "必须以用户 pypto 运行" "$TEST_TMP/wrong-user.out"
fi

# Packaging and service safety invariants.
grep -Fq 'TOOLS_ROOT=/home/pypto-tools' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'BIN_LINK=/usr/local/bin/pto-auth-proxy' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'User=@PROXY_USER@' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
grep -Fq 'Group=@PROXY_GROUP@' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
AUTHD_UNIT="$PROJECT_DIR/systemd/pto-auth-proxy-authd@.service.in"
grep -Fq 'User=%I' "$AUTHD_UNIT"
grep -Fq 'ExecStart=/usr/bin/python3 @PREFIX@/auth-proxy/authd.py' "$AUTHD_UNIT"
grep -Fq 'EnvironmentFile=-@TOOL_DIR@/config/auth-proxy.env' "$AUTHD_UNIT"
grep -Fq 'ExecStartPre=-/usr/bin/pkill -u %I -f authproxy-watchdog.sh' \
    "$AUTHD_UNIT"
grep -Fq 'ExecStartPre=-/usr/bin/pkill -u %I -f authproxy-authd.py' \
    "$AUTHD_UNIT"
grep -Fq 'Restart=always' "$AUTHD_UNIT"
grep -Fq 'PrivateTmp=false' "$AUTHD_UNIT"
grep -Fq 'WantedBy=multi-user.target' "$AUTHD_UNIT"
if grep -Eq '^(Group|SupplementaryGroups)=' "$AUTHD_UNIT"; then
    echo "authd 模板不得向非成员授予 proxyusers 身份" >&2
    exit 1
fi
if grep -Fq 'User=root' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"; then
    echo "代理服务不应以 root 运行" >&2
    exit 1
fi
if grep -Eq 'systemctl +(start|restart)' \
    "$PROJECT_DIR/scripts/install.sh"; then
    echo "安装脚本不应自动启动或重启服务" >&2
    exit 1
fi
if grep -F 'systemctl enable --now' "$PROJECT_DIR/scripts/install.sh" |
   grep -Fv 'pto-auth-proxy-auto-update.timer' >/dev/null; then
    echo "只有显式 --enable-updater 可以 enable --now timer" >&2
    exit 1
fi
grep -Fq -- '--enable-service' "$PROJECT_DIR/scripts/install.sh"
grep -Fq -- '--install-updater' "$PROJECT_DIR/scripts/install.sh"
grep -Fq -- '--enable-updater' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'systemctl enable --now pto-auth-proxy-auto-update.timer' \
    "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'repo-auto-update.service.in' \
    "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'repo-auto-update.timer.in' \
    "$PROJECT_DIR/scripts/install.sh"
UPDATE_TIMER="$PROJECT_DIR/modules/repo_auto_update/repo-auto-update.timer.in"
grep -Fq 'OnCalendar=*-*-* 03:37:00 Asia/Shanghai' "$UPDATE_TIMER"
grep -Fq 'RandomizedDelaySec=20min' "$UPDATE_TIMER"
grep -Fq 'Persistent=false' "$UPDATE_TIMER"
if grep -Eq 'OnBootSec|OnUnitActiveSec' "$UPDATE_TIMER"; then
    echo "自动更新 timer 应每天定时检查，而不是按分钟轮询" >&2
    exit 1
fi
grep -Fq 'activation != "next-restart"' \
    "$PROJECT_DIR/modules/repo_auto_update/manifest.py"
grep -Fq 'sequence < installed_sequence' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'explicit rollback is required' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'installed revision is absent from fetched history' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'running services were not restarted' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'REPO_AUTO_UPDATE_ADAPTER_MODE=verify' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'REPO_AUTO_UPDATE_ADAPTER_MODE=apply' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'REPO_AUTO_UPDATE_REPOSITORY=' \
    "$PROJECT_DIR/modules/repo_auto_update/example.env"
grep -Fq 'REPO_AUTO_UPDATE_FETCH_USER=@PROXY_USER@' \
    "$PROJECT_DIR/config/auto-update.env.in"
grep -Fq 'REPO_AUTO_UPDATE_FETCH_ALL_PROXY=socks5h://127.0.0.1:4780' \
    "$PROJECT_DIR/config/auto-update.env.in"
grep -Fq 'runuser -u "$REPO_AUTO_UPDATE_FETCH_USER"' \
    "$PROJECT_DIR/modules/repo_auto_update/updater.sh"
grep -Fq 'This directory is self-contained' \
    "$PROJECT_DIR/modules/repo_auto_update/README.md"
grep -Fq 'if ((ENABLE_SERVICE)); then' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'systemctl enable pto-auth-proxy-authd-members.service' \
    "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'pto-auth-proxy-egress-guard.service pto-auth-proxy.service' \
    "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'Wants=network-online.target pto-auth-proxy-egress-guard.service' \
    "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
grep -Fq 'EnvironmentFile=-@TOOL_DIR@/config/auth-proxy.env' \
    "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
grep -Fq 'PTO_AUTH_PROXY_GUARD_PORTS' \
    "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
grep -Fq 'ExecStartPre=+@PREFIX@/bin/pto-auth-proxy-egress-guard check' \
    "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
GUARD_UNIT="$PROJECT_DIR/systemd/pto-auth-proxy-egress-guard.service.in"
grep -Fq 'EnvironmentFile=-@TOOL_DIR@/config/auth-proxy.env' "$GUARD_UNIT"
grep -Fq 'ExecStartPre=@PREFIX@/bin/pto-auth-proxy-egress-guard start' \
    "$GUARD_UNIT"
grep -Fq 'pto-auth-proxy-egress-guard watch' "$GUARD_UNIT"
grep -Fq 'Restart=always' "$GUARD_UNIT"
grep -Fq 'install -d -m 0750 -o "$user" -g "$PROXY_GROUP"' \
    "$PROJECT_DIR/scripts/start-authd-members.sh"
grep -Fq '/run/pto-auth-proxy/$user_uid' \
    "$PROJECT_DIR/scripts/start-authd-members.sh"
grep -Fq 'PTO_AUTH_PROXY_UPSTREAM_CONNECT_TIMEOUT' \
    "$PROJECT_DIR/config/auth-proxy.env.example"
grep -Fq 'PTO_AUTH_PROXY_RELAY_HALF_CLOSE_TIMEOUT' \
    "$PROJECT_DIR/config/auth-proxy.env.example"
grep -Fq -- '--install-service' \
    "$PROJECT_DIR/scripts/auto-update-adapter.sh"
grep -Fq 'restoring previous application and units' \
    "$PROJECT_DIR/scripts/auto-update-adapter.sh"
grep -Fq 'pto-auth-proxy-authd@.service.in' "$PROJECT_DIR/scripts/install.sh"
grep -Fq '/etc/systemd/system/pto-auth-proxy-authd@.service' \
    "$PROJECT_DIR/scripts/install.sh"
MEMBERS_UNIT="$PROJECT_DIR/systemd/pto-auth-proxy-authd-members.service.in"
grep -Fq 'Before=pto-auth-proxy.service' "$MEMBERS_UNIT"
grep -Fq 'ExecStart=@PREFIX@/bin/pto-auth-proxy-start-authd-members' \
    "$MEMBERS_UNIT"
grep -Fq 'WantedBy=multi-user.target' "$MEMBERS_UNIT"
if [[ "$CURRENT_USER" != pypto ]]; then
    "$PROJECT_DIR/scripts/start-authd-members.sh" --list proxyusers pypto |
        grep -Fqx "$CURRENT_USER"
fi
if "$PROJECT_DIR/scripts/start-authd-members.sh" --list proxyusers pypto |
    grep -Fqx pypto; then
    echo "proxy owner should not need a PAM verifier instance" >&2
    exit 1
fi
grep -Fq 'pto-auth-proxy join' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'pto-auth-proxy test' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'systemctl is-active --quiet "$SYSTEMD_UNIT"' \
    "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'systemctl is-enabled "$SYSTEMD_UNIT"' \
    "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'SYSTEMD_BOOT_ENABLED=1' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'authproxy-watchdog.sh' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'authproxy-authd.py' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'configure-shell.sh' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'issue-token' "$PROJECT_DIR/join-proxy.sh"
grep -Fq 'status_proxy.py' "$PROJECT_DIR/bin/pto-auth-proxy"
grep -Fq 'pto-auth-proxy test' "$PROJECT_DIR/test_proxy.sh"
grep -Fq -- '--enable-service' "$PROJECT_DIR/skills/pto-auth-proxy/SKILL.md"
grep -Fq 'pto-auth-proxy status' "$PROJECT_DIR/skills/pto-auth-proxy/SKILL.md"
grep -Fq 'pto-auth-proxy-authd-members.service' \
    "$PROJECT_DIR/skills/pto-auth-proxy/SKILL.md"
grep -Fq '4780/4781' "$PROJECT_DIR/skills/pto-auth-proxy/SKILL.md"
grep -Fq 'ten-minute rotation grace' \
    "$PROJECT_DIR/skills/pto-auth-proxy/SKILL.md"
if grep -Fq 'PrivateTmp=true' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"; then
    echo "PrivateTmp 会隔离用户 authd socket" >&2
    exit 1
fi

# The interactive E2E test must retrieve real GitHub content, not only a code.
grep -Fq 'https://github.com/openai/codex' "$PROJECT_DIR/test_proxy.sh"
grep -Fq 'https://api.github.com/repos/openai/codex' "$PROJECT_DIR/test_proxy.sh"
grep -Fq 'https://raw.githubusercontent.com/openai/codex/main/README.md' \
    "$PROJECT_DIR/test_proxy.sh"

# Shell onboarding is isolated under a temporary HOME. It must be idempotent,
# keep credentials out of the rc file, and configure all HTTP proxy spellings.
SHELL_HOME=$TEST_TMP/shell-home
mkdir -p "$SHELL_HOME"
{
    printf '%s\n' '# existing user content'
    printf '%s\n' '# ---- 686 authenticated proxy ----'
    printf '%s\n' 'export HTTPS_PROXY=http://legacy@127.0.0.1:4780'
    printf '%s\n' '# ---------------------------------'
} >"$SHELL_HOME/.bashrc"
printf '%s' 'test?password' | \
    HOME="$SHELL_HOME" SHELL=/bin/bash \
    PTO_AUTH_PROXY_SHELL_RC="$SHELL_HOME/.bashrc" \
    "$PROJECT_DIR/configure-shell.sh" testuser >/dev/null
grep -Fqx '# existing user content' "$SHELL_HOME/.bashrc"
if grep -Fq '4780' "$SHELL_HOME/.bashrc"; then
    echo "legacy proxy block was not removed" >&2
    exit 1
fi
[[ $(grep -Fxc '# >>> pto-auth-proxy managed environment >>>' \
    "$SHELL_HOME/.bashrc") == 1 ]]
[[ $(stat -c '%a' "$SHELL_HOME/.config/pto-auth-proxy/secret-uri") == 600 ]]
grep -Fqx 'test%3Fpassword' \
    "$SHELL_HOME/.config/pto-auth-proxy/secret-uri"
if grep -Fq 'test%3Fpassword' "$SHELL_HOME/.bashrc"; then
    echo "shell rc must not contain proxy credentials" >&2
    exit 1
fi
first_hash=$(sha256sum "$SHELL_HOME/.bashrc" | cut -d' ' -f1)
printf '%s' 'test?password' | \
    HOME="$SHELL_HOME" SHELL=/bin/bash \
    PTO_AUTH_PROXY_SHELL_RC="$SHELL_HOME/.bashrc" \
    "$PROJECT_DIR/configure-shell.sh" testuser >/dev/null
second_hash=$(sha256sum "$SHELL_HOME/.bashrc" | cut -d' ' -f1)
[[ "$first_hash" == "$second_hash" ]]
HOME="$SHELL_HOME" bash --noprofile --norc -c '
    export NO_PROXY=custom.example
    source "$HOME/.bashrc"
    [[ "$HTTP_PROXY" == http://testuser:*@127.0.0.1:20809 ]]
    [[ "$HTTPS_PROXY" == "$HTTP_PROXY" ]]
    [[ "$http_proxy" == "$HTTP_PROXY" ]]
    [[ "$https_proxy" == "$HTTP_PROXY" ]]
    [[ "$ALL_PROXY" == socks5h://testuser:*@127.0.0.1:20808 ]]
    [[ "$all_proxy" == "$ALL_PROXY" ]]
    [[ ",$NO_PROXY," == *,custom.example,* ]]
    [[ ",$NO_PROXY," == *,localhost,* ]]
    [[ ",$NO_PROXY," == *,127.0.0.0/8,* ]]
'

# Dotfile-manager symlinks must survive onboarding.
SYMLINK_HOME=$TEST_TMP/symlink-home
DOTFILES=$TEST_TMP/dotfiles
mkdir -p "$SYMLINK_HOME" "$DOTFILES"
printf '%s\n' '# linked user content' >"$DOTFILES/bashrc"
ln -s "$DOTFILES/bashrc" "$SYMLINK_HOME/.bashrc"
printf '%s' 'symlink-password' | \
    HOME="$SYMLINK_HOME" SHELL=/bin/bash \
    PTO_AUTH_PROXY_SHELL_RC="$SYMLINK_HOME/.bashrc" \
    "$PROJECT_DIR/configure-shell.sh" testuser >/dev/null
[[ -L "$SYMLINK_HOME/.bashrc" ]]
grep -Fq '# >>> pto-auth-proxy managed environment >>>' "$DOTFILES/bashrc"

# A malformed existing block must fail before any credential is written.
BAD_HOME=$TEST_TMP/bad-home
mkdir -p "$BAD_HOME"
printf '%s\n' '# >>> pto-auth-proxy managed environment >>>' >"$BAD_HOME/.bashrc"
if printf '%s' 'must-not-persist' | \
    HOME="$BAD_HOME" SHELL=/bin/bash \
    PTO_AUTH_PROXY_SHELL_RC="$BAD_HOME/.bashrc" \
    "$PROJECT_DIR/configure-shell.sh" testuser >/dev/null 2>&1; then
    echo "malformed managed block should be rejected" >&2
    exit 1
fi
[[ ! -e "$BAD_HOME/.config/pto-auth-proxy/secret-uri" ]]

echo "All tests passed"
