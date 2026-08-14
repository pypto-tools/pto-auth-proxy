#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

for file in \
    "$PROJECT_DIR/bin/pto-auth-proxy" \
    "$PROJECT_DIR/join-proxy.sh" \
    "$PROJECT_DIR/test_proxy.sh" \
    "$PROJECT_DIR/scripts/install.sh"; do
    bash -n "$file"
done

PYTHONDONTWRITEBYTECODE=1 python3 - "$PROJECT_DIR/auth_proxy.py" \
    "$PROJECT_DIR/authd.py" <<'PY'
from pathlib import Path
import sys

for name in sys.argv[1:]:
    path = Path(name)
    compile(path.read_text(), str(path), "exec")
PY

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PROJECT_DIR" \
    python3 -m unittest discover -s "$PROJECT_DIR/tests" -p 'test_*.py' -v

"$PROJECT_DIR/bin/pto-auth-proxy" validate

# Packaging and service safety invariants.
grep -Fq 'TOOLS_ROOT=/home/pypto-tools' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'BIN_LINK=/usr/local/bin/pto-auth-proxy' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'BIN_ALIAS=/usr/local/bin/pto-authproxy' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'ln -sfn "$PREFIX/bin/pto-auth-proxy" "$BIN_ALIAS"' \
    "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'User=@PROXY_USER@' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"
if grep -Fq 'User=root' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"; then
    echo "代理服务不应以 root 运行" >&2
    exit 1
fi
if grep -Eq 'systemctl +(start|restart)|enable --now' \
    "$PROJECT_DIR/scripts/install.sh"; then
    echo "安装脚本不应自动启动或重启服务" >&2
    exit 1
fi
grep -Fq -- '--enable-service' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'if ((ENABLE_SERVICE)); then' "$PROJECT_DIR/scripts/install.sh"
grep -Fq 'systemctl enable pto-auth-proxy.service' \
    "$PROJECT_DIR/scripts/install.sh"
if grep -Fq 'PrivateTmp=true' "$PROJECT_DIR/systemd/pto-auth-proxy.service.in"; then
    echo "PrivateTmp 会隔离用户 authd socket" >&2
    exit 1
fi

# The interactive E2E test must retrieve real GitHub content, not only a code.
grep -Fq 'https://github.com/openai/codex' "$PROJECT_DIR/test_proxy.sh"
grep -Fq 'https://api.github.com/repos/openai/codex' "$PROJECT_DIR/test_proxy.sh"
grep -Fq 'https://raw.githubusercontent.com/openai/codex/main/README.md' \
    "$PROJECT_DIR/test_proxy.sh"

echo "All tests passed"
