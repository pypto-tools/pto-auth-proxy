#!/usr/bin/env python3
"""Per-user PAM authentication daemon.

Runs as an unprivileged Linux user (say `david`). Listens on a Unix socket
whose path is either $XDG_RUNTIME_DIR/authproxy-authd.sock or, when systemd
has not created a runtime dir, /tmp/authproxy-<username>.sock.

The socket is group-owned by `proxyusers` and mode 0660 so the auth_proxy
process (running as pypto, who is also a member of proxyusers) can connect,
but random unrelated users on the host cannot. Because a proxyusers group
member could still connect and impersonate the proxy, on every incoming
connection we additionally check SO_PEERCRED and require the caller's UID to
be either `pypto` (the proxy owner) or ourselves (for self-tests).

On each connection reads one JSON line `{"user": "<username>", "pass":
"<password>"}` and replies `{"ok": true|false, "code": N, "reason": "..."}`.
authd only ever verifies its own owner, so a stolen socket cannot be used to
probe arbitrary users' passwords.
"""
from __future__ import annotations
import asyncio
import concurrent.futures
import grp
import hashlib
import hmac
import json
import os
import pwd
import signal
import socket
import struct
import sys
import time

import pam as _pam_mod

PAM_SERVICE = "sshd"

# --- performance knobs ----------------------------------------------------
# Serial PAM was the bottleneck: pam_unix forks unix_chkpwd (~100ms each),
# so 20 concurrent Claude Code requests would queue to ~2 seconds. Run
# several in parallel and cache successful auths briefly so that a burst
# of requests from the same user only hits PAM once.
PAM_WORKERS       = 8              # parallel PAM calls
CACHE_TTL         = 60             # seconds; matches faillock's unlock_time
CACHE_MAX_ENTRIES = 128
PAM_TIMEOUT       = 8              # seconds; refuse if PAM hangs
# --------------------------------------------------------------------------

# Who is allowed to CONNECT to this authd (by UID). We accept:
#   - the proxy owner (pypto) -- production path
#   - ourselves               -- for self-tests via join-proxy.sh
_PROXY_OWNER = "pypto"
try:
    _ALLOWED_UIDS = {pwd.getpwnam(_PROXY_OWNER).pw_uid}
except KeyError:
    _ALLOWED_UIDS = set()

# Group that owns the socket file. Only members can even open() it.
_SOCK_GROUP = "proxyusers"
# NOTE: no module-level pam instance -- see comment in handle() for why.

_UID = os.getuid()
_MY_NAME = pwd.getpwuid(_UID).pw_name

# Always use /tmp/authproxy-<user>.sock. We used to prefer XDG_RUNTIME_DIR
# (/run/user/<uid>/), but that directory is 0700 owned by the user, so the
# auth_proxy process (running as pypto) cannot stat/connect there. /tmp is
# world-readable so pypto can find and open the socket, and we lock it down
# via chgrp proxyusers + chmod 0660 + SO_PEERCRED checks in handle().
_SOCK = f"/tmp/authproxy-{_MY_NAME}.sock"


def log(msg: str) -> None:
    print(f"authd[{_MY_NAME}]: {msg}", flush=True)


# --------------------------------------------------------------------------
# Success cache: maps (user, HMAC(password)) -> expiry timestamp.
# Only successful auths are cached (so wrong passwords still cost a PAM call
# every time, and faillock keeps working). The password HMAC uses a random
# per-process key so cached tokens can't be replayed if the file is dumped.
# --------------------------------------------------------------------------
_CACHE_KEY = os.urandom(32)
_cache: dict[tuple[str, bytes], float] = {}
# NB: dict get/set/del are atomic on CPython, so no lock is needed as long
# as all mutations happen on the event-loop thread.


def _pw_fingerprint(pw: str) -> bytes:
    return hmac.new(_CACHE_KEY, pw.encode("utf-8"), hashlib.sha256).digest()


def _cache_get(user: str, pw: str) -> bool:
    key = (user, _pw_fingerprint(pw))
    exp = _cache.get(key)
    if exp is None:
        return False
    if exp < time.monotonic():
        _cache.pop(key, None)
        return False
    return True


def _cache_put(user: str, pw: str) -> None:
    if len(_cache) >= CACHE_MAX_ENTRIES:
        # Drop expired entries first; if still full, drop soonest-to-expire.
        now = time.monotonic()
        for k, e in list(_cache.items()):
            if e < now:
                _cache.pop(k, None)
        while len(_cache) >= CACHE_MAX_ENTRIES:
            oldest = min(_cache.items(), key=lambda kv: kv[1])[0]
            _cache.pop(oldest, None)
    _cache[(user, _pw_fingerprint(pw))] = time.monotonic() + CACHE_TTL


# Dedicated pool -- default asyncio executor is single-threaded and would
# serialize all PAM calls.
_pam_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=PAM_WORKERS,
    thread_name_prefix="pam",
)


def _pam_call(user: str, password: str):
    """Runs in the PAM thread pool. Returns (ok, code, reason)."""
    p = _pam_mod.pam()
    try:
        ok = p.authenticate(user, password, service=PAM_SERVICE)
    except Exception as inner:
        return (False, -1, f"pam exception: {inner!r}")
    return (bool(ok),
            getattr(p, "code", None),
            getattr(p, "reason", None))


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # Verify who is calling us (SO_PEERCRED).
    peer_uid = -1
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None and sock.family == socket.AF_UNIX:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("iII"))
            _pid, peer_uid, _gid = struct.unpack("iII", creds)
    except Exception:
        pass

    allowed = _ALLOWED_UIDS | {_UID}
    if peer_uid not in allowed:
        log(f"reject connection from uid={peer_uid} "
            f"(only {sorted(allowed)} allowed)")
        try:
            writer.write((json.dumps(
                {"ok": False, "code": -3,
                 "reason": f"caller uid={peer_uid} not permitted"}) + "\n").encode())
            await writer.drain()
        except Exception:
            pass
        writer.close()
        return

    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5)
        req = json.loads(line.decode("utf-8"))
        user = str(req.get("user", ""))
        password = str(req.get("pass", ""))

        if user != _MY_NAME:
            reply = {"ok": False, "code": -1,
                     "reason": f"authd for {_MY_NAME!r} refuses to verify {user!r}"}
        elif _cache_get(user, password):
            # Cache hit: same (user, password) succeeded in the last CACHE_TTL
            # seconds. Skip PAM entirely -- this is what makes bursty
            # workloads (Claude Code, npm install, etc.) fast.
            reply = {"ok": True, "code": 0, "reason": "cache"}
        else:
            # Fresh PAM call in the dedicated pool (parallelism=PAM_WORKERS)
            # with a hard timeout so a hung unix_chkpwd cannot stall the
            # event loop.
            try:
                ok, code, reason = await asyncio.wait_for(
                    asyncio.get_running_loop().run_in_executor(
                        _pam_pool, _pam_call, user, password),
                    timeout=PAM_TIMEOUT,
                )
            except asyncio.TimeoutError:
                ok, code, reason = False, -4, f"pam timeout >{PAM_TIMEOUT}s"
            reply = {"ok": ok, "code": code, "reason": reason}
            if ok:
                _cache_put(user, password)

        writer.write((json.dumps(reply) + "\n").encode("utf-8"))
        await writer.drain()
        via = "cache" if reply.get("reason") == "cache" else "pam"
        log(f"peer_uid={peer_uid} user={user!r} -> ok={reply['ok']} code={reply.get('code')} via={via}")
    except Exception as e:
        try:
            writer.write((json.dumps({"ok": False, "code": -2,
                                      "reason": f"exception: {e!r}"}) + "\n").encode())
            await writer.drain()
        except Exception:
            pass
        log(f"exception: {e!r}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    # Ensure parent dir exists (only relevant for the /tmp fallback).
    parent = os.path.dirname(_SOCK)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    try:
        os.unlink(_SOCK)
    except FileNotFoundError:
        pass

    server = await asyncio.start_unix_server(handle, path=_SOCK)

    # Make socket group-readable by proxyusers so the proxy (running as
    # pypto) can connect. We still verify SO_PEERCRED in handle() to ensure
    # the caller is actually the proxy owner and not some other proxyusers
    # member trying to abuse this authd.
    try:
        gid = grp.getgrnam(_SOCK_GROUP).gr_gid
        os.chown(_SOCK, -1, gid)
        os.chmod(_SOCK, 0o660)
        log(f"socket {_SOCK} owner-only-mode=0660 group={_SOCK_GROUP}")
    except KeyError:
        log(f"WARNING: group {_SOCK_GROUP!r} not found; using 0600 socket "
            "(the proxy owner will NOT be able to connect)")
        os.chmod(_SOCK, 0o600)
    except PermissionError as e:
        log(f"WARNING: chown to group {_SOCK_GROUP!r} failed: {e}; using 0600")
        os.chmod(_SOCK, 0o600)

    log(f"listening on {_SOCK} (uid={_UID}, service={PAM_SERVICE!r}, "
        f"allowed peer uids={sorted(_ALLOWED_UIDS | {_UID})})")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    loop.add_signal_handler(signal.SIGINT,  stop.set)
    async with server:
        try:
            await stop.wait()
        finally:
            log("stopping")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
