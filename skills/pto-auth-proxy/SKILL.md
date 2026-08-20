---
name: pto-auth-proxy
description: Inspect, validate, configure, test, and operate the pto-auth-proxy authenticated whitelist proxy on shared Linux servers.
---

# pto-auth-proxy

Use the public `pto-auth-proxy` command. Keep read-only diagnosis, configuration
changes, user onboarding, and production service operations clearly separated.

## Safety boundaries

- Never ask a user to paste or reveal a Linux password, proxy password, token,
  private key, `.proxy-secret*`, or expanded proxy URL.
- Never print `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, process environments, or
  shell configuration without redacting credentials.
- Never write credentials into this repository, `auth-proxy.env`, service units,
  logs, reports, command arguments, or chat.
- `validate`, `traffic`, `status`, log inspection, socket inspection, and
  configuration review are read-only. `status` opens only short diagnostic
  connections and never prints credentials.
- `join` reuses an enabled system authd instance, or installs and restarts the
  current user's compatibility watchdog when no instance is enabled. Run it
  only when the user explicitly requests onboarding, verification, or repair.
- Editing the whitelist, signaling the proxy, installing a unit, and starting,
  stopping, restarting, enabling, or disabling a service are state-changing
  administrator operations. Require explicit user intent for the exact action.
- The repository updater is separate from the proxy service.
  `--install-updater` leaves its timer disabled for image preparation;
  `--enable-updater` enables persistent repository-state polling. Polling alone
  does not select or deploy a commit, and neither option authorizes restarting
  the proxy.
- Do not deploy directly from a dirty worktree. Do not overwrite config, state,
  logs, reports, or an existing production deployment during an upgrade.
- Never direct a normal user or tool to `4780/4781`. Those loopback upstream
  ports are guarded for the proxy owner only; users must use authenticated
  `20808/20809`.

## Read-only checks

```bash
pto-auth-proxy validate
pto-auth-proxy traffic 30
pto-auth-proxy status
ss -lnt | grep -E ':(20808|20809|4780|4781)\b'
```

Inspect only credential-free fields when diagnosing configuration. Proxy URLs
must always be redacted before display.

## User commands

Use the public command instead of asking users to locate or execute repository
scripts directly:

```bash
pto-auth-proxy join
pto-auth-proxy status
pto-auth-proxy test
```

`join` is needed once for onboarding or later for explicit credential repair.
It privately prompts once for the Linux password. A token-capable authd verifies
PAM, issues a random proxy token, persists only its digest, creates a mode-0600
credential/environment file, and idempotently connects it to `.bashrc` or
`.zshrc`. The previous token has a ten-minute rotation grace. Older authd
versions remain compatible with password credentials during rolling upgrades.
HTTP/HTTPS variables use authenticated port `20809`; `ALL_PROXY/all_proxy` use
authenticated SOCKS5 port `20808`. Never configure either family to use the
direct upstream ports.

`join` prefers an active system instance `pto-auth-proxy-authd@<user>.service`;
otherwise it installs the compatibility per-home watchdog for the current boot.
`pto-auth-proxy-authd-members.service` enumerates `proxyusers` and starts all
per-user system instances at every server boot, so an onboarded user must not be
asked to re-run `join` after reboot. Re-running `join` must not create a second
daemon beside a healthy system instance. System instances use protected
per-user sockets below `/run/pto-auth-proxy/<uid>/`; `/tmp` is only a legacy
compatibility fallback.

After onboarding, ask the user to open a new terminal. A running VS Code/Codex
process needs a user-initiated Reload Window because an existing process cannot
inherit new environment variables. Do not kill or restart user tools from
`join`. Use `pto-auth-proxy status` for normal diagnosis; `READY` accepts both
`authd=token` and the rolling-upgrade `authd=legacy` state.

`test` is an interactive end-to-end check and may require the user to enter a
credential locally. Never enter, capture, or relay that credential for them.

## GitHub acceptance boundary

Core GitHub access includes:

- repository HTML at `github.com`;
- repository metadata from `api.github.com`;
- raw files from `raw.githubusercontent.com`;
- HTTPS Git smart protocol and codeload/assets hosts.

The repository's automated tests verify host policy. The interactive
`pto-auth-proxy test` command performs real GitHub content retrieval using a
password entered privately by the user in their own terminal. Never enter or
capture that password on the user's behalf.

Do not broaden the whitelist to GHCR, GitHub Pages, GitHub Codespaces, or other
products unless the user explicitly requests that scope and an administrator
accepts the additional egress.

## Configuration changes

Before proposing a change:

1. Read the current installed config and whitelist with secrets redacted.
2. Confirm whether the requested domain is already covered by an existing glob.
3. Prefer the narrowest domain pattern that supports the required workflow.
4. Run repository tests and `pto-auth-proxy validate` against the candidate
   configuration.
5. Report the exact diff. Do not signal or restart the running service unless
   separately requested.

## Deployment

The repository installer copies code into the standard `pypto-tools` layout.
By default it does not install, enable, start, stop, or restart services.
`--install-service` installs the shared proxy, per-user authd template, boot
member starter, and egress guard without enabling or starting them.
`--enable-service` explicitly enables these boot services, but still does not
start or restart them immediately. Individual authd instances do not need to be
enabled: `pto-auth-proxy-authd-members.service` discovers the authorized group
on every boot.

Keep the server timer enabled for persistent repository-state checks. Interpret
the main repository's `update/rollout.json` as follows:

- `enabled=false`: deployment is paused; polling may continue.
- `enabled=true` with an empty `target`: deployment is armed but idle. Treat
  this as healthy; do not test or install a candidate.
- `enabled=true` with a full commit ID: verify and stage that exact commit. Do
  not substitute the current branch HEAD.

For a targeted rollout, require the target to be an ancestor of the configured
main branch and increase `sequence`. Require `allow_rollback=true` for a
downgrade. Always merge code and tests before publishing the separate manifest
control commit. Never point `target` at the control commit itself unless that is
the version intentionally being deployed.

The updater fetches as the unprivileged proxy owner through the owner-only local
SOCKS upstream when root has no direct egress. It preserves local
configuration/state/logs and stages the candidate without restarting proxy or
authd services. The auth-proxy adapter stages matching service units and runs
daemon-reload, but does not enable, start, or restart them; an apply failure
restores both application files and units. Only `activation=next-restart` is accepted. Never change this
to remote forced restart behavior: uninterrupted authenticated proxy access
takes priority.

Keep updater installations compatible with `ProtectSystem=strict`. If the
global command symlink already points to the deployed application, the
installer must skip rewriting it instead of granting the updater broad write
access to `/usr/local/bin`.

The polling engine is the reusable `modules/repo_auto_update/` module. It must
remain tool-neutral. Auth-proxy-specific verification, backup, and installation
belong in `scripts/auto-update-adapter.sh`. Another tool should copy the module,
create its own root-owned config from `example.env`, and provide its own verify
and apply adapters; do not add other tools' behavior to the generic engine.

The egress guard uses IPv4/IPv6 owner rules so only the configured proxy owner
can connect directly to loopback `4780/4781`. The authenticated service remains
non-root and reaches the upstream as that owner. The guard continuously checks
and repairs rule drift, and the shared proxy verifies the rules before each
start. Verify the service and access matrix with `pto-auth-proxy status` after
deployment.

Client handshake, upstream connect/handshake, half-close relay, and writer-close timeouts are
local containment controls. They do not repair an unavailable remote tunnel;
they make it fail promptly and prevent abandoned relay tasks from accumulating.

Production cutover requires a shadow-port test and an explicit rollback plan;
follow the repository README and preserve the previous deployment until
acceptance passes. Treat the later `systemctl start` or `restart` as a separate
state-changing operation requiring explicit user intent.
