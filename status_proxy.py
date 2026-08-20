#!/usr/bin/env python3
"""One-line readiness check for an auth-proxy user."""
from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import socket
import subprocess
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


TIMEOUT = 5


def group_member(user: str, group_name: str) -> bool:
    try:
        account = pwd.getpwnam(user)
        group = grp.getgrnam(group_name)
    except KeyError:
        return False
    return account.pw_gid == group.gr_gid or user in group.gr_mem


def authd_capability(user: str) -> tuple[bool, str]:
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return False, "down"
    candidates = (
        f"/run/pto-auth-proxy/{uid}/authd.sock",
        f"/tmp/authproxy-{user}.sock",
    )
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(TIMEOUT)
                client.connect(path)
                request = json.dumps({"op": "capabilities"}) + "\n"
                client.sendall(request.encode())
                response = json.loads(client.recv(4096).decode())
            capabilities = response.get("capabilities", [])
            return True, "token" if "token-v1" in capabilities else "legacy"
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return False, "down"


def proxy_url(user: str, host: str, port: int) -> tuple[str | None, str]:
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        value = os.environ.get(name, "")
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme == "http" \
                and parsed.hostname in {host, "localhost"} and parsed.port == port \
                and parsed.username and parsed.password:
            return value, "env"

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "")
    config_home = Path(xdg_config_home) if xdg_config_home \
        else Path.home() / ".config"
    candidates = [
        config_home / "pto-auth-proxy" / "secret-uri",
        Path.home() / ".proxy-secret-uri",
    ]
    url_host = f"[{host}]" if ":" in host else host
    for secret_file in candidates:
        try:
            secret_uri = secret_file.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if secret_uri:
            return (f"http://{quote(user, safe='')}:{secret_uri}@"
                    f"{url_host}:{port}"), "file"
    return None, "missing"


def authenticated_connect(url: str, target: str = "api.github.com:443") -> str:
    parsed = urlsplit(url)
    if not parsed.hostname or not parsed.port or parsed.username is None \
            or parsed.password is None:
        return "bad-url"
    credentials = f"{unquote(parsed.username)}:{unquote(parsed.password)}"
    authorization = base64.b64encode(credentials.encode()).decode("ascii")
    request = (
        f"CONNECT {target} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Proxy-Authorization: Basic {authorization}\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((parsed.hostname, parsed.port), TIMEOUT) as client:
            client.settimeout(TIMEOUT)
            client.sendall(request.encode("ascii"))
            response = b""
            while b"\r\n" not in response and len(response) < 4096:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response += chunk
    except OSError:
        return "down"
    try:
        return response.split(b"\r\n", 1)[0].split()[1].decode("ascii")
    except (IndexError, UnicodeDecodeError):
        return "bad-response"


def direct_access_is_correct(user: str, owner: str, host: str,
                             ports: tuple[int, ...]) -> bool:
    expected_open = user == owner
    for port in ports:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            is_open = client.connect_ex((host, port)) == 0
        if is_open != expected_open:
            return False
    return True


def guard_service_active() -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet",
             "pto-auth-proxy-egress-guard.service"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def guard_ports(upstream_port: int) -> tuple[int, ...]:
    raw = os.environ.get(
        "PTO_AUTH_PROXY_GUARD_PORTS", f"{upstream_port},4781")
    try:
        ports = tuple(int(value) for value in raw.split(","))
    except ValueError:
        return ()
    if not ports or any(port < 1 or port > 65535 for port in ports):
        return ()
    return ports


def main() -> int:
    user = pwd.getpwuid(os.getuid()).pw_name
    group_name = os.environ.get("PTO_AUTH_PROXY_GROUP", "proxyusers")
    owner = os.environ.get("PTO_AUTH_PROXY_OWNER", "pypto")
    host = os.environ.get("PTO_AUTH_PROXY_LISTEN_HOST", "127.0.0.1")
    port = int(os.environ.get("PTO_AUTH_PROXY_HTTP_PORT", "20809"))
    upstream_host = os.environ.get("PTO_AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1")
    upstream_port = int(os.environ.get("PTO_AUTH_PROXY_UPSTREAM_PORT", "4780"))
    protected_ports = guard_ports(upstream_port)

    member_ok = group_member(user, group_name)
    authd_ok, authd_mode = authd_capability(user)
    url, config_source = proxy_url(user, host, port)
    connect_status = authenticated_connect(url) if url else "no-credential"
    guard_service_ok = guard_service_active()
    direct_ok = bool(protected_ports) and direct_access_is_correct(
        user, owner, upstream_host, protected_ports)
    guard_ok = guard_service_ok and direct_ok

    ready = member_ok and authd_ok and connect_status == "200" and guard_ok
    state = "READY" if ready else "NOT_READY"
    if not guard_service_ok:
        guard_state = "service-down"
    elif not direct_ok:
        guard_state = "rule-wrong"
    else:
        guard_state = "owner-allowed" if user == owner else "blocked"
    print(
        f"{state}: group={'ok' if member_ok else 'missing'} "
        f"authd={authd_mode} credential={config_source} "
        f"proxy={connect_status} guard={guard_state}"
    )
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
