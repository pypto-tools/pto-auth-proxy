---
name: setup-auth-proxy
description: Configures the current Linux user (running on the Ascend686 shared server) to use the authenticated HTTPS proxy on 127.0.0.1:20809. Use this when a new user needs internet access to Claude / OpenAI / GitHub / Google APIs and has been added to the proxyusers group by an administrator. The skill checks prerequisites, installs the user's authd daemon, updates ~/.bashrc with the correct proxy environment variables, and points at a test script that verifies the end-to-end path. Do NOT invoke this if the user is not on the Ascend686 host or if network egress is already working without a proxy.
---

# setup-auth-proxy

Goal: bring a new proxyusers member online so their shell + tools reach the
authenticated proxy at `127.0.0.1:20809` (HTTP) and are counted / audited per
user.

## Preconditions to verify BEFORE running any command

Ask the user to run each check and paste the output back. Do not proceed
past a failed check without fixing it.

1. Confirm the current host is Ascend686 by running `hostname`. Abort the
   skill if the hostname does not look like `liteserver-hps-*` (or whichever
   value the admin declared) -- this skill only makes sense on that box.

2. Confirm the current user is in the `proxyusers` group:

   ```
   id | tr ' ,()' '\n' | grep -x proxyusers
   ```

   If nothing prints, the user has not been added to the group (or was
   added but hasn't re-logged-in yet). STOP and instruct the user:

   > An admin needs to run: `sudo usermod -aG proxyusers <you>` and you
   > must log out and log back in for the group to take effect.

3. Confirm `python3` can `import pam`:

   ```
   python3 -c 'import pam' && echo OK || echo MISSING
   ```

   If `MISSING`, install python-pam **before** proceeding. Prefer the
   system-wide install (works for every user):

   ```
   sudo dnf install -y python3-pam
   ```

   If sudo is unavailable, fall back to user-space:

   ```
   pip3 install --user python-pam
   ```

   Re-run the `python3 -c 'import pam'` check after installing. If it
   still fails, stop and surface the pip/dnf error to the user.

## Run the deployment script

Run `join-proxy.sh` with **NO** password test at the end. The password
prompt inside the script is optional and only useful when the user wants
to catch typos immediately -- from Claude Code's point of view we don't
know their password and we don't want to consume a faillock counter.

```
bash /data/pypto/auth-proxy/join-proxy.sh
```

When the script prints `Test now? [Y/n]` press `N` (or type `n` + Enter).
The script will finish, install `~/.local/bin/authproxy-authd.py` + a
watchdog wrapper, and start the authd daemon in the background.

Verify success:

```
ls -l /tmp/authproxy-$(id -un).sock
pgrep -u $USER -af authproxy-authd.py
```

You should see a socket file owned by the user with group `proxyusers`
mode `0660`, and one running python process. If either is missing, look
at `~/.local/authproxy-authd.log` for the reason and surface it.

## Store the password privately

Ask the user for their Linux login password. NEVER print or log the
value. Write it to `~/.proxy-secret` with 0600 permissions:

```
umask 077
read -rs -p 'Your Linux password (will not echo): ' PW; echo
printf '%s' "$PW" > ~/.proxy-secret
unset PW
chmod 600 ~/.proxy-secret
```

If the user cannot recall their password, direct them to reset it with
their team's usual process before continuing -- do not try to guess.

## Update ~/.bashrc

Append the proxy exports to `~/.bashrc`. Use idempotent logic: check for
an existing block first so re-running this skill doesn't create
duplicates.

```
if ! grep -q '# ---- 686 authenticated proxy ----' ~/.bashrc; then
  cat >> ~/.bashrc <<'PROXYENV'

# ---- 686 authenticated proxy ----
export HTTPS_PROXY="http://$(id -un):$(cat ~/.proxy-secret)@127.0.0.1:20809"
export HTTP_PROXY="$HTTPS_PROXY"
export NO_PROXY='localhost,127.0.0.0/8,::1,169.254.169.254,192.168.0.0/16,10.0.0.0/8'
# ---------------------------------
PROXYENV
fi
```

Reload the current shell:

```
source ~/.bashrc
```

Confirm the variables are set (values are safe to print -- the password
is expanded from `~/.proxy-secret` at command time, not stored plainly in
the env once `bash -c` finishes):

```
env | grep -E '^(HTTPS_PROXY|HTTP_PROXY|NO_PROXY)='
```

## MANDATORY: run the end-to-end self-test

This is the acceptance test. Do not consider the setup complete until it
passes. The script performs a real handshake against Google, GitHub and
OpenAI through the proxy, plus a negative check that a non-whitelisted
domain gets denied:

```
bash /data/pypto/auth-proxy/test_proxy.sh
```

Expect every step to print a green `✓`. The full output should contain,
in order:

- `✓ <user> is in group 'proxyusers'`
- `✓ TCP 127.0.0.1:20808 is open`
- `✓ authenticated request went through (HTTP <code>)`
- `✓ api.github.com reachable`
- `✓ www.google.com reachable`
- `✓ api.openai.com reachable`
- `✓ www.baidu.com correctly denied`

If any step fails, report the exact failing line back to the user and
consult `/data/pypto/auth-proxy/auth_proxy.log` (readable to
proxyusers members) for the reason. Common failures:

- `authd rejected: code 6 Permission denied` -- password wrong OR
  faillock has locked the user after 3+ failed attempts. Wait 60
  seconds with no further attempts, then retry.
- `curl: (97) User was rejected by the SOCKS5 server` -- authd isn't
  running (see `pgrep -u $USER -af authproxy-authd.py`); re-run
  `bash /data/pypto/auth-proxy/join-proxy.sh` to relaunch it.
- `TCP 127.0.0.1:20808 is open` fails -- the shared proxy daemon is
  down on the host; escalate to pypto.

## Restart running tools

Any process started before `source ~/.bashrc` still has the old
(possibly empty) proxy env. Kill and restart the tools the user cares
about, for example:

```
pkill -u $USER claude 2>/dev/null; claude   # Claude Code
pkill -u $USER codex  2>/dev/null; codex    # Codex CLI
```

## Things NOT to do

- Do not commit `~/.proxy-secret` to git or share its contents.
- Do not add `ALL_PROXY=socks5h://...` by default. HTTP 20809 handles
  every mainstream CLI and Node.js tool; SOCKS 20808 is only needed for
  the rare tool that speaks raw SOCKS5 and does not honour
  `HTTPS_PROXY`.
- Do not retry a failing password more than twice. `faillock` will
  lock the account after 3 attempts and every extra try just resets
  the 60-second unlock timer.
- Do not attempt to run `join-proxy.sh` as root or via sudo. The
  authd daemon must run under the user's own uid so PAM can verify
  the user's password without cross-user restrictions.
