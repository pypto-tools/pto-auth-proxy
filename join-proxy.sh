#!/usr/bin/env bash
# join-proxy.sh — one-command onboarding for a new proxyusers member.
#
# Every user in `proxyusers` runs this once. It:
#   1. Installs authd.py into ~/.local/bin/authproxy-authd.py
#   2. Starts authd as a detached background process (setsid + nohup)
#   3. Optionally writes a wrapper into ~/bin so the user can restart it
#   4. Verifies authd works by asking for the user's password
#
# The daemon writes its socket to /run/user/<uid>/authproxy-authd.sock if that
# exists (systemd-user runtime dir), else /tmp/authproxy-<user>.sock. The auth
# proxy checks both locations.
#
# Prereqs (admin needs to do these once):
#   - `proxyusers` group exists and this user is a member
#   - python3-pam is installed system-wide OR in this user's site-packages
#
# Usage:  bash /data/pypto/auth-proxy/join-proxy.sh

set -u
ME=$(id -un)
UID_NUM=$(id -u)

pass()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail()   { printf '\033[31m✗\033[0m %s\n' "$*"; }
info()   { printf '\033[36m•\033[0m %s\n' "$*"; }
header() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

SRC_DIR=/data/pypto/auth-proxy
BIN_DIR=$HOME/.local/bin
LOG_FILE=$HOME/.local/authproxy-authd.log

# The daemon writes its socket to /tmp/authproxy-<user>.sock. We deliberately
# do NOT use XDG_RUNTIME_DIR (/run/user/<uid>/) because that dir is 0700 so
# the auth_proxy (running as pypto) can't stat/connect through it. The
# /tmp socket is chgrp'd to proxyusers with mode 0660, and authd verifies
# SO_PEERCRED to make sure only the proxy owner can actually use it.
SOCK="/tmp/authproxy-${ME}.sock"

header "Step 1: group membership"
if id -nG "$ME" | tr ' ' '\n' | grep -qx proxyusers; then
  pass "$ME is in proxyusers"
else
  fail "$ME is NOT in proxyusers. Ask admin: sudo usermod -aG proxyusers $ME  (then log out and back in)"
  exit 1
fi

header "Step 2: python-pam available"
if python3 -c 'import pam' 2>/dev/null; then
  pass "python3 can import pam"
else
  fail "python3 lacks the python-pam module."
  info ""
  info "  Install it by running ONE of the following:"
  info ""
  info "    sudo dnf install -y python3-pam       # (recommended, system-wide)"
  info "    pip3 install --user python-pam        # (fallback, user only)"
  info ""
  info "  Then re-run this script:"
  info "    bash $0"
  info ""
  exit 1
fi

header "Step 3: install authd into your home"
mkdir -p "$BIN_DIR"
cp "$SRC_DIR/authd.py" "$BIN_DIR/authproxy-authd.py"
chmod 700 "$BIN_DIR/authproxy-authd.py"

# A tiny watchdog wrapper: keeps authd alive with 3s backoff if it crashes.
cat > "$BIN_DIR/authproxy-watchdog.sh" << 'WD'
#!/usr/bin/env bash
# authproxy-watchdog.sh -- keep authd alive
LOG="${HOME}/.local/authproxy-authd.log"
BIN="${HOME}/.local/bin/authproxy-authd.py"
echo "$(date '+%F %T') watchdog started (pid=$$)" >> "$LOG"
while true; do
  python3 "$BIN" >> "$LOG" 2>&1
  rc=$?
  echo "$(date '+%F %T') authd exited rc=$rc, restarting in 3s" >> "$LOG"
  sleep 3
done
WD
chmod 700 "$BIN_DIR/authproxy-watchdog.sh"
pass "$BIN_DIR/authproxy-authd.py + watchdog installed"

header "Step 4: (re)start authd via watchdog"
# Kill both the previous watchdog and its child authd
pkill -u "$ME" -f authproxy-watchdog.sh 2>/dev/null || true
pkill -u "$ME" -f authproxy-authd.py    2>/dev/null || true
sleep 0.5
rm -f "$SOCK" 2>/dev/null || true

setsid nohup bash "$BIN_DIR/authproxy-watchdog.sh" </dev/null \
    >>"$LOG_FILE" 2>&1 &
disown $! 2>/dev/null || true
sleep 1

if pgrep -u "$ME" -f authproxy-watchdog.sh >/dev/null \
   && pgrep -u "$ME" -f authproxy-authd.py >/dev/null; then
  pass "watchdog pid: $(pgrep -u "$ME" -f authproxy-watchdog.sh) / authd pid: $(pgrep -u "$ME" -f authproxy-authd.py)"
else
  fail "authd or watchdog failed to start"
  tail -30 "$LOG_FILE"
  exit 1
fi

if [ -S "$SOCK" ]; then
  pass "socket ready at $SOCK"
  ls -l "$SOCK"
else
  fail "socket $SOCK not present"
  tail -20 "$LOG_FILE"
  exit 1
fi

header "Step 5: verify authd (needs your password)"
info "Testing authd on the local unix socket only. Nothing hits the network."
read -r -p "Test now? [Y/n] " ans
if [ "${ans:-Y}" = "Y" ] || [ "${ans:-y}" = "y" ] || [ -z "${ans:-}" ]; then
  read -r -s -p "Your Linux password: " PW
  echo
  # Pass SOCK and username via env vars (visible in `env`, but only to root/self,
  # and no secret data). The password is fed to python via stdin so it never
  # appears in argv or environment.
  RESP=$(SOCK="$SOCK" USER_NAME="$ME" python3 -c '
import socket, sys, os, json
pw = sys.stdin.read().rstrip("\n")
req = json.dumps({"user": os.environ["USER_NAME"], "pass": pw}) + "\n"
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ["SOCK"])
s.sendall(req.encode())
print(s.recv(4096).decode().strip())
' <<< "$PW" 2>&1)
  unset PW
  if printf '%s' "$RESP" | grep -q '"ok": *true'; then
    pass "authd verified your password: $RESP"
  else
    fail "authd rejected: $RESP"
    info "  If reason mentions faillock, wait 60s and retry."
    info "  If reason mentions cross-user, this authd is running as the wrong user (should not happen)."
    exit 1
  fi
fi

echo
echo "All set."
echo "  - authd is running as $ME, listening on $SOCK"
echo "  - log: $LOG_FILE"
echo "  - if you log out and back in, re-run this script to restart authd"
echo "    (or ask admin to enable lingering via: sudo loginctl enable-linger $ME)"
echo
echo "== Configure your shell to use the proxy =="
echo
echo "  Claude Code / Codex / any Node.js tool only speaks HTTP proxy, so"
echo "  point HTTPS_PROXY/HTTP_PROXY at the HTTP CONNECT port :20809. That"
echo "  port tunnels arbitrary TLS traffic, so almost every modern CLI"
echo "  (curl, wget, npm, pip, git, node, ...) works with just these two."
echo
echo "  1. Store your password (chmod 600):"
echo "       umask 077 && echo 'YOUR_LINUX_PASSWORD' > ~/.proxy-secret"
echo
echo "  2. Append to ~/.bashrc:"
echo
cat <<BASHRC
       # ---- 686 authenticated proxy ----
       export HTTPS_PROXY="http://${ME}:\$(cat ~/.proxy-secret)@127.0.0.1:20809"
       export HTTP_PROXY="\$HTTPS_PROXY"
       export NO_PROXY='localhost,127.0.0.0/8,::1,169.254.169.254,192.168.0.0/16,10.0.0.0/8'
       # ---------------------------------
BASHRC
echo
echo "  3. Reload and restart any tool that reads env at start:"
echo "       source ~/.bashrc"
echo "       pkill -u $ME claude 2>/dev/null; claude   # example for Claude Code"
echo
echo "  4. (Optional) Verify end-to-end:"
echo "       bash $SRC_DIR/test_proxy.sh"
echo
echo "  Advanced: for tools that only speak SOCKS5 (rare), you can also set"
echo "       export ALL_PROXY=\"socks5h://${ME}:\\\$(cat ~/.proxy-secret)@127.0.0.1:20808\""
echo "  but this is optional and usually not needed."
echo
