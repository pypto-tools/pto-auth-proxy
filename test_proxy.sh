#!/usr/bin/env bash
# test_proxy.sh — self-test for the authenticated SOCKS5 proxy on Ascend686.
#
# Run this on the Ascend686 host as your Linux user. It walks you through
# every check needed to confirm the new proxy works for you, without
# affecting anyone still using the old :4780 tunnel.
#
# Usage:
#   pto-authproxy test
set -u

PROXY_HOST=${PTO_AUTH_PROXY_LISTEN_HOST:-127.0.0.1}
PROXY_PORT=${PTO_AUTH_PROXY_SOCKS_PORT:-20808}
GROUP=${PTO_AUTH_PROXY_GROUP:-proxyusers}
USER_NAME=$(id -un)

pass()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail()   { printf '\033[31m✗\033[0m %s\n' "$*"; }
info()   { printf '\033[36m•\033[0m %s\n' "$*"; }
header() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# ---- 1. Group membership -------------------------------------------------
header "Step 1: group membership"
if id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx "$GROUP"; then
  pass "$USER_NAME is in group '$GROUP'"
else
  fail "$USER_NAME is NOT in group '$GROUP'"
  info "  Ask the admin to run:  sudo usermod -aG $GROUP $USER_NAME"
  info "  Then log OUT of ssh and log back IN (group changes require a new session)."
  exit 1
fi

# ---- 2. Port reachable ---------------------------------------------------
header "Step 2: proxy port reachable"
if command -v nc >/dev/null 2>&1; then
  if nc -z -w 3 "$PROXY_HOST" "$PROXY_PORT" 2>/dev/null; then
    pass "TCP $PROXY_HOST:$PROXY_PORT is open"
  else
    fail "cannot connect to $PROXY_HOST:$PROXY_PORT — proxy is not running"
    info "  Ask the admin to start auth_proxy.py"
    exit 1
  fi
else
  # nc absent → fall back to bash /dev/tcp
  if (exec 3<>"/dev/tcp/$PROXY_HOST/$PROXY_PORT") 2>/dev/null; then
    pass "TCP $PROXY_HOST:$PROXY_PORT is open (via bash /dev/tcp)"
    exec 3>&- 3<&-
  else
    fail "cannot connect to $PROXY_HOST:$PROXY_PORT — proxy is not running"
    exit 1
  fi
fi

# ---- 3. Prompt for the Linux password (never echoed, never stored) -------
header "Step 3: authenticate"
info "Enter YOUR Linux password for user '$USER_NAME' (same as ssh)."
info "It is not echoed and not saved anywhere by this script."
read -r -s -p "Password: " USER_PASS
echo
if [ -z "$USER_PASS" ]; then
  fail "empty password"
  exit 1
fi

# Helper: run curl through proxy, echo BOTH the HTTP code and stderr on one line
_probe() {
    # $1=user  $2=pass  $3=url  $4=maxtime
    local out
    out=$(curl --max-time "${4:-8}" -sS \
        --socks5-hostname "${PROXY_HOST}:${PROXY_PORT}" \
        --proxy-user "${1}:${2}" \
        "$3" -o /dev/null \
        -w 'HTTP=%{http_code}' 2>&1 || true)
    printf '%s' "$out"
}

# 3b. Correct password → must succeed (test this FIRST so we don't trip faillock)
info "Testing YOUR password against a whitelisted domain (github.com)…"
RESULT_OK=$(_probe "$USER_NAME" "$USER_PASS" "https://github.com/" 10)
CODE_OK=$(printf '%s' "$RESULT_OK" | grep -oE 'HTTP=[0-9]+' | tail -1 | cut -d= -f2)
if [ -n "$CODE_OK" ] && [ "$CODE_OK" -gt 0 ] 2>/dev/null && [ "$CODE_OK" != "000" ]; then
  pass "authenticated request went through (HTTP $CODE_OK)"
else
  fail "auth with your real password did NOT work: $RESULT_OK"
  info "  Possible causes:"
  info "  - wrong password"
  info "  - faillock lockout (from earlier failed attempts) — wait 60s and retry"
  info "  - authd not running (run join-proxy.sh again)"
  exit 1
fi

info "Skipping the wrong-password check because it consumes faillock counters"
info "(deny=3 unlock_time=60). If you want to verify auth actually rejects,"
info "wait until AFTER Steps 4/5 and run:  bash $0 --check-reject"

# ---- 4. Whitelist checks -------------------------------------------------
header "Step 4: service whitelist positive tests"
SERVICE_OK=1
for dest in "api.github.com" "api.anthropic.com" "api.openai.com"; do
  CODE=$(curl --max-time 10 -sS \
      --socks5-hostname "${PROXY_HOST}:${PROXY_PORT}" \
      --proxy-user "${USER_NAME}:${USER_PASS}" \
      "https://${dest}/" -o /dev/null \
      -w '%{http_code}' 2>&1 || true)
  if [ "$CODE" -gt 0 ] 2>/dev/null && [ "$CODE" -ne 407 ]; then
    pass "$dest reachable (HTTP $CODE)"
  else
    fail "$dest FAILED (result: $CODE)"
    SERVICE_OK=0
  fi
done
if [ "$SERVICE_OK" -ne 1 ]; then
  exit 1
fi

header "Step 5: GitHub content retrieval"
_github_content() {
  local label=$1 url=$2 pattern=$3 body
  body=$(curl --max-time 20 -fsSL \
      --socks5-hostname "${PROXY_HOST}:${PROXY_PORT}" \
      --proxy-user "${USER_NAME}:${USER_PASS}" \
      "$url" 2>&1) || {
    fail "$label FAILED: $body"
    return 1
  }
  if printf '%s' "$body" | grep -Fq "$pattern"; then
    pass "$label returned expected content"
  else
    fail "$label returned data but expected marker was missing"
    return 1
  fi
}

GITHUB_CONTENT_OK=1
_github_content "GitHub repository page" \
  "https://github.com/openai/codex" "openai/codex" || GITHUB_CONTENT_OK=0
_github_content "GitHub repository API" \
  "https://api.github.com/repos/openai/codex" '"full_name": "openai/codex"' || GITHUB_CONTENT_OK=0
_github_content "GitHub raw file" \
  "https://raw.githubusercontent.com/openai/codex/main/README.md" "Codex CLI" || GITHUB_CONTENT_OK=0
if [ "$GITHUB_CONTENT_OK" -ne 1 ]; then
  fail "one or more GitHub content checks failed"
  exit 1
fi

# ---- 6. Whitelist negative test -----------------------------------------
header "Step 6: non-whitelisted domain must be blocked"
OUT=$(curl --max-time 5 -sS \
    --socks5-hostname "${PROXY_HOST}:${PROXY_PORT}" \
    --proxy-user "${USER_NAME}:${USER_PASS}" \
    https://www.baidu.com/ -o /dev/null \
    -w '%{http_code}' 2>&1 || true)
if printf '%s' "$OUT" | grep -qiE 'SOCKS5|not allowed|000'; then
  pass "www.baidu.com correctly denied (expected — not on whitelist)"
else
  fail "www.baidu.com was NOT denied — whitelist not enforced: $OUT"
  exit 1
fi

# ---- 7. Completion -------------------------------------------------------
header "Step 7: complete"
pass "all proxy and GitHub content checks passed"
info "Shell configuration is managed separately by 'pto-auth-proxy join'."
info "Do not print expanded proxy environment variables; they contain credentials."
