#!/usr/bin/env python3
"""Per-user PAM authentication daemon.

Runs as an unprivileged Linux user (say `david`). System-managed instances
listen below /run/pto-auth-proxy/<uid>/; legacy per-home instances retain the
/tmp/authproxy-<username>.sock compatibility path.

The socket is group-owned by `proxyusers` and mode 0660 so the auth_proxy
process (running as pypto, who is also a member of proxyusers) can connect,
but random unrelated users on the host cannot. Because a proxyusers group
member could still connect and impersonate the proxy, on every incoming
connection we additionally check SO_PEERCRED and require the caller's UID to
be either `pypto` (the proxy owner) or ourselves (for self-tests).

Normal authentication remains compatible with `{"user": "<username>",
"pass": "<credential>"}`. A self-call may also use `issue-token` after PAM
verification; the returned random proxy token is stored only by the user and
can be revoked without changing the Linux password.
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
import secrets
import signal
import socket
import struct
import sys
import tempfile
import time

import pam as _pam_mod

PAM_SERVICE = os.environ.get("PTO_AUTH_PROXY_PAM_SERVICE", "sshd")

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
_PROXY_OWNER = os.environ.get("PTO_AUTH_PROXY_OWNER", "pypto")
try:
    _ALLOWED_UIDS = {pwd.getpwnam(_PROXY_OWNER).pw_uid}
except KeyError:
    _ALLOWED_UIDS = set()

# Group that owns the socket file. Only members can even open() it.
_SOCK_GROUP = os.environ.get("PTO_AUTH_PROXY_GROUP", "proxyusers")
# NOTE: no module-level pam instance -- see comment in handle() for why.

_UID = os.getuid()
_MY_NAME = pwd.getpwuid(_UID).pw_name
_MY_HOME = pwd.getpwuid(_UID).pw_dir
_TOKEN_PREFIX = "pto_"
_TOKEN_BYTES = 32
_TOKEN_BODY_LENGTH = (_TOKEN_BYTES * 8 + 5) // 6
_TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_TOKEN_DIR = os.path.join(_MY_HOME, ".config", "pto-auth-proxy")
_TOKEN_HASH_FILE = os.path.join(_TOKEN_DIR, "token.sha256")
_TOKEN_ROTATION_GRACE = 600

_SYSTEM_RUNTIME_DIR = f"/run/pto-auth-proxy/{_UID}"
_SYSTEM_SOCK = os.path.join(_SYSTEM_RUNTIME_DIR, "authd.sock")
_LEGACY_SOCK = f"/tmp/authproxy-{_MY_NAME}.sock"


def _choose_socket_path() -> str:
    """Prefer an administrator-created, non-group-writable runtime directory."""
    try:
        runtime = os.stat(_SYSTEM_RUNTIME_DIR)
    except OSError:
        return _LEGACY_SOCK
    if runtime.st_uid == _UID and runtime.st_mode & 0o022 == 0:
        return _SYSTEM_SOCK
    print(f"authd[{_MY_NAME}]: WARNING: refusing unsafe runtime directory "
          f"{_SYSTEM_RUNTIME_DIR}; using legacy socket", flush=True)
    return _LEGACY_SOCK


_SOCK = _choose_socket_path()


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


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _looks_like_proxy_token(credential: str) -> bool:
    body = credential.removeprefix(_TOKEN_PREFIX)
    return credential.startswith(_TOKEN_PREFIX) \
        and len(body) == _TOKEN_BODY_LENGTH \
        and all(char in _TOKEN_ALPHABET for char in body)


def _token_matches(token: str) -> bool:
    if not token.startswith(_TOKEN_PREFIX):
        return False
    try:
        with open(_TOKEN_HASH_FILE, "r", encoding="ascii") as token_file:
            stored = token_file.read().strip()
    except (FileNotFoundError, OSError):
        return False
    digest = _token_digest(token)
    try:
        record = json.loads(stored)
        if hmac.compare_digest(str(record.get("current", "")), digest):
            return True
        previous = str(record.get("previous", ""))
        previous_until = float(record.get("previous_until", 0))
        return previous_until >= time.time() and hmac.compare_digest(previous, digest)
    except (TypeError, ValueError, json.JSONDecodeError):
        # Compatibility with the initial single-digest token file format.
        return hmac.compare_digest(stored, digest)


def _issue_proxy_token() -> str:
    """Create a random token and atomically persist only its SHA-256 digest."""
    os.makedirs(_TOKEN_DIR, mode=0o700, exist_ok=True)
    os.chmod(_TOKEN_DIR, 0o700)
    token = _TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)
    previous = ""
    try:
        with open(_TOKEN_HASH_FILE, "r", encoding="ascii") as token_file:
            stored = token_file.read().strip()
        try:
            previous = str(json.loads(stored).get("current", ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            previous = stored
    except OSError:
        pass
    record = {
        "version": 1,
        "current": _token_digest(token),
        "previous": previous,
        "previous_until": time.time() + _TOKEN_ROTATION_GRACE if previous else 0,
    }
    fd, temp_path = tempfile.mkstemp(prefix=".token-sha256.", dir=_TOKEN_DIR,
                                     text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as token_file:
            json.dump(record, token_file, separators=(",", ":"))
            token_file.write("\n")
        os.replace(temp_path, _TOKEN_HASH_FILE)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise
    return token


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


async def _pam_call_async(user: str, password: str):
    try:
        return await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(
                _pam_pool, _pam_call, user, password),
            timeout=PAM_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return False, -4, f"pam timeout >{PAM_TIMEOUT}s"


async def _authenticate(user: str, credential: str):
    """Authenticate a token when it matches, otherwise preserve PAM fallback."""
    if _looks_like_proxy_token(credential):
        ok = _token_matches(credential)
        return {
            "ok": ok,
            "code": 0 if ok else -6,
            "reason": "token" if ok else "invalid proxy token",
        }, "token"
    if _cache_get(user, credential):
        return {"ok": True, "code": 0, "reason": "cache"}, "cache"

    # The short prefix is not reserved: an existing Linux password may start
    # with ``pto_``. Only the full generated token shape bypasses PAM. This
    # preserves such passwords without sending stale, token-shaped secrets to
    # PAM repeatedly and risking an account lockout.
    ok, code, reason = await _pam_call_async(user, credential)
    if ok:
        _cache_put(user, credential)
    return {"ok": ok, "code": code, "reason": reason}, "pam"


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
        op = str(req.get("op", "authenticate"))
        user = str(req.get("user", ""))
        credential = str(req.get("pass", ""))
        via = "protocol"

        if op == "capabilities":
            reply = {"ok": True, "code": 0,
                     "capabilities": ["token-v1"]}
        elif user != _MY_NAME:
            reply = {"ok": False, "code": -1,
                     "reason": f"authd for {_MY_NAME!r} refuses to verify {user!r}"}
        elif op == "issue-token":
            if peer_uid != _UID:
                reply = {"ok": False, "code": -5,
                         "reason": "only the user may issue their proxy token"}
            else:
                ok, code, reason = await _pam_call_async(user, credential)
                via = "pam"
                reply = {"ok": ok, "code": code, "reason": reason}
                if ok:
                    _cache_put(user, credential)
                    reply["token"] = _issue_proxy_token()
        elif op != "authenticate":
            reply = {"ok": False, "code": -7,
                     "reason": f"unsupported operation: {op}"}
        else:
            reply, via = await _authenticate(user, credential)

        writer.write((json.dumps(reply) + "\n").encode("utf-8"))
        await writer.drain()
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
    # The secure /run directory is created by the root member starter. The
    # fallback's parent is /tmp and already exists on a normal system.
    parent = os.path.dirname(_SOCK)
    if parent and not os.path.isdir(parent):
        raise RuntimeError(f"authd socket directory is missing: {parent}")
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
