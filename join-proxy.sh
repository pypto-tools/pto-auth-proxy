#!/usr/bin/env bash
# join-proxy.sh — one-command onboarding for a new proxyusers member.
#
# Every user in `proxyusers` can run this safely. If the administrator enabled
# pto-auth-proxy-authd@<user>.service, join reuses that boot-persistent daemon
# and removes only the legacy per-home watchdog. Otherwise it installs and
# starts the legacy detached watchdog as a compatibility fallback.
#
# System-managed daemons use a protected /run socket; the compatibility daemon
# uses /tmp. The password is read once for PAM verification, then URL-encoded
# into a mode-0600 credential file. It never appears in argv or the environment.
#
# Prereqs (admin needs to do these once):
#   - `proxyusers` group exists and this user is a member
#   - python3-pam is installed system-wide OR in this user's site-packages
#
# Usage:  pto-auth-proxy join

set -u
ME=$(id -un)
UID_NUM=$(id -u)

pass()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail()   { printf '\033[31m✗\033[0m %s\n' "$*"; }
info()   { printf '\033[36m•\033[0m %s\n' "$*"; }
header() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR=${PTO_AUTH_PROXY_SOURCE_DIR:-$SCRIPT_DIR}
BIN_DIR=$HOME/.local/bin
LOG_FILE=$HOME/.local/authproxy-authd.log
PROXY_OWNER=${PTO_AUTH_PROXY_OWNER:-pypto}
PROXY_GROUP=${PTO_AUTH_PROXY_GROUP:-proxyusers}
PAM_SERVICE=${PTO_AUTH_PROXY_PAM_SERVICE:-sshd}
SYSTEMD_UNIT="pto-auth-proxy-authd@${ME}.service"
if command -v systemd-escape >/dev/null 2>&1; then
  ESCAPED_SYSTEMD_UNIT=$(systemd-escape \
    --template=pto-auth-proxy-authd@.service "$ME" 2>/dev/null || true)
  [ -z "$ESCAPED_SYSTEMD_UNIT" ] || SYSTEMD_UNIT=$ESCAPED_SYSTEMD_UNIT
fi
SYSTEMD_MANAGED=0
SYSTEMD_BOOT_ENABLED=0

# Treat an enabled or already-active system instance as authoritative. Merely
# installing the template is not enough: an unenabled instance would not
# return after reboot, so join keeps the compatibility watchdog in that case.
if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_UNIT_STATE=$(systemctl is-enabled "$SYSTEMD_UNIT" 2>/dev/null || true)
  if [ "$SYSTEMD_UNIT_STATE" = enabled ]; then
    SYSTEMD_BOOT_ENABLED=1
  fi
  if systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null \
     || [ "$SYSTEMD_UNIT_STATE" = enabled ] \
     || [ "$SYSTEMD_UNIT_STATE" = enabled-runtime ]; then
    SYSTEMD_MANAGED=1
  fi
fi

# The boot member starter creates this per-user directory as user:proxyusers
# mode 0750. Legacy joins retain /tmp for compatibility.
SYSTEM_SOCK="/run/pto-auth-proxy/${UID_NUM}/authd.sock"
if [ -d "${SYSTEM_SOCK%/*}" ]; then
  SOCK=$SYSTEM_SOCK
else
  SOCK="/tmp/authproxy-${ME}.sock"
fi

header "Step 1: group membership"
if id -nG "$ME" | tr ' ' '\n' | grep -qx "$PROXY_GROUP"; then
  pass "$ME is in $PROXY_GROUP"
else
  fail "$ME is NOT in $PROXY_GROUP. Ask admin: sudo usermod -aG $PROXY_GROUP $ME  (then log out and back in)"
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
  info "  Then re-run onboarding:"
  info "    pto-auth-proxy join"
  info ""
  exit 1
fi

if [ "$SYSTEMD_MANAGED" -eq 1 ]; then
  header "Step 3: systemd-managed authd"
  pass "$SYSTEMD_UNIT is enabled or active"
  info "Using the shared deployed authd; no per-home copy is needed."
else
  header "Step 3: install compatibility authd into your home"
  mkdir -p "$BIN_DIR"
  cp "$SRC_DIR/authd.py" "$BIN_DIR/authproxy-authd.py"
  chmod 700 "$BIN_DIR/authproxy-authd.py"

  # A tiny watchdog keeps authd alive with 3s backoff if it crashes. Persist
  # only non-sensitive daemon configuration; passwords never enter it.
  {
  printf '#!/usr/bin/env bash\n'
  printf 'export PTO_AUTH_PROXY_OWNER=%q\n' "$PROXY_OWNER"
  printf 'export PTO_AUTH_PROXY_GROUP=%q\n' "$PROXY_GROUP"
  printf 'export PTO_AUTH_PROXY_PAM_SERVICE=%q\n' "$PAM_SERVICE"
  cat << 'WD'
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
  } > "$BIN_DIR/authproxy-watchdog.sh"
  chmod 700 "$BIN_DIR/authproxy-watchdog.sh"
  pass "$BIN_DIR/authproxy-authd.py + watchdog installed"
fi

if [ "$SYSTEMD_MANAGED" -eq 1 ]; then
  header "Step 4: use boot-persistent systemd authd"

  if ! systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null; then
    # This may succeed under a local policy rule. Never prompt for privilege;
    # if it is not allowed, tell the user exactly what the administrator needs.
    systemctl --no-ask-password start "$SYSTEMD_UNIT" 2>/dev/null || true
  fi

  # Type=simple becomes active just before Python binds its socket. Give the
  # new process time to replace a possible legacy socket before checking it.
  sleep 0.5
  for _ in 1 2 3 4 5; do
    systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null \
      && [ -S "$SOCK" ] && break
    sleep 0.2
  done

  if ! systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null \
     || [ ! -S "$SOCK" ]; then
    fail "$SYSTEMD_UNIT is enabled but not ready"
    info "  Ask the administrator to run:"
    info "    sudo systemctl restart $SYSTEMD_UNIT"
    info "    sudo systemctl status $SYSTEMD_UNIT"
    exit 1
  fi

  # The system unit runs the shared authd.py path, so these patterns select
  # only the old per-home fallback and cannot kill the systemd MainPID. Do
  # this only after systemd is healthy, preserving the fallback on failures.
  pkill -u "$ME" -f authproxy-watchdog.sh 2>/dev/null || true
  pkill -u "$ME" -f authproxy-authd.py 2>/dev/null || true
  if [ "$SYSTEMD_BOOT_ENABLED" -eq 1 ]; then
    pass "$SYSTEMD_UNIT is active and enabled for server reboot"
  else
    pass "$SYSTEMD_UNIT is active; join did not start a duplicate daemon"
    info "  For boot persistence, ask the administrator to run:"
    info "    sudo systemctl enable $SYSTEMD_UNIT"
  fi
else
  header "Step 4: (re)start compatibility authd via watchdog"
  pkill -u "$ME" -f authproxy-watchdog.sh 2>/dev/null || true
  pkill -u "$ME" -f authproxy-authd.py 2>/dev/null || true
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
fi

if [ ! -S "$SOCK" ]; then
  fail "socket $SOCK not present"
  [ "$SYSTEMD_MANAGED" -eq 1 ] || tail -20 "$LOG_FILE"
  exit 1
fi
pass "socket ready at $SOCK"
ls -l "$SOCK"

header "Step 5: verify authd and configure future shells"
info "Your Linux password is checked once over the local unix socket."
info "New authd versions exchange it for a revocable random proxy token."
read -r -s -p "Your Linux password: " PW
echo
# Pass only the socket and username via env. The password is fed over stdin so
# neither the Linux password nor issued token appears in argv or environment.
AUTH_RESULT=$(SOCK="$SOCK" USER_NAME="$ME" python3 -c '
import socket, sys, os, json
pw = sys.stdin.read().rstrip("\n")

def request(payload):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(12)
    try:
        s.connect(os.environ["SOCK"])
        s.sendall((json.dumps(payload) + "\n").encode())
        data = b""
        while b"\n" not in data and len(data) < 16384:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return json.loads(data.decode())
    finally:
        s.close()

user = os.environ["USER_NAME"]
capabilities = request({"op": "capabilities"})
if capabilities.get("ok") and "token-v1" in capabilities.get("capabilities", []):
    response = request({"op": "issue-token", "user": user, "pass": pw})
    if not response.get("ok") or not response.get("token"):
        print("authentication failed: " + str(response.get("reason", "unknown")),
              file=sys.stderr)
        raise SystemExit(1)
    print("token")
    print(response["token"], end="")
else:
    response = request({"user": user, "pass": pw})
    if not response.get("ok"):
        print("authentication failed: " + str(response.get("reason", "unknown")),
              file=sys.stderr)
        raise SystemExit(1)
    print("password")
    print(pw, end="")
' <<< "$PW" 2>&1)
AUTH_RC=$?
unset PW
if ((AUTH_RC != 0)); then
  fail "authd rejected authentication: $AUTH_RESULT"
  info "  If reason mentions faillock, wait 60s and retry."
  exit 1
fi

AUTH_MODE=${AUTH_RESULT%%$'\n'*}
PROXY_CREDENTIAL=${AUTH_RESULT#*$'\n'}
if [[ "$AUTH_RESULT" == "$PROXY_CREDENTIAL" || -z "$PROXY_CREDENTIAL" ]]; then
  unset AUTH_RESULT PROXY_CREDENTIAL
  fail "authd returned an invalid credential response"
  exit 1
fi
unset AUTH_RESULT
if [[ "$AUTH_MODE" == token ]]; then
  pass "Linux password verified; an independent proxy token was issued"
else
  pass "Linux password verified; legacy authd requires password compatibility mode"
fi

if ! printf '%s' "$PROXY_CREDENTIAL" | bash "$SRC_DIR/configure-shell.sh" "$ME"; then
  unset PROXY_CREDENTIAL
  fail "authd is healthy, but automatic shell configuration failed"
  info "  No running process was changed. Fix the reported shell file issue and re-run join."
  exit 1
fi
unset PROXY_CREDENTIAL

if [[ "$AUTH_MODE" == token ]]; then
  pass "future shells use the proxy token; Linux password is not stored"
else
  info "Current authd will gain token support after its next system-managed start."
fi
unset AUTH_MODE

pass "future shells are configured for authenticated proxy port ${PTO_AUTH_PROXY_HTTP_PORT:-20809}"

echo
echo "All set."
echo "  - authd is running as $ME, listening on $SOCK"
if [ "$SYSTEMD_MANAGED" -eq 1 ]; then
  echo "  - managed by systemd: $SYSTEMD_UNIT"
  if [ "$SYSTEMD_BOOT_ENABLED" -eq 1 ]; then
    echo "  - it starts automatically after a server reboot; join remains safe to re-run"
  else
    echo "  - join remains safe to re-run, but boot start requires administrator enablement"
  fi
else
  echo "  - compatibility log: $LOG_FILE"
  echo "  - this fallback is not boot-persistent; ask the administrator to enable:"
  echo "      sudo systemctl enable --now $SYSTEMD_UNIT"
fi
echo "  - proxy environment: ${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/env.sh"
echo "  - open a new terminal to inherit it"
echo "  - VS Code / Codex already running must use Reload Window when convenient"
echo "  - no running process was restarted by join"
echo
echo "  Optional end-to-end verification:"
echo "       pto-auth-proxy test"
echo
