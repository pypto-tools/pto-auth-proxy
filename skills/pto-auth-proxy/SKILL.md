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
- `validate`, `traffic`, log inspection, socket inspection, and configuration
  review are read-only.
- `join` installs and restarts the current user's authd. Run it only when the
  user explicitly requests onboarding or repair.
- Editing the whitelist, signaling the proxy, installing a unit, and starting,
  stopping, restarting, enabling, or disabling a service are state-changing
  administrator operations. Require explicit user intent for the exact action.
- Do not deploy directly from a dirty worktree. Do not overwrite config, state,
  logs, reports, or an existing production deployment during an upgrade.

## Read-only checks

```bash
pto-auth-proxy validate
pto-auth-proxy traffic 30
ss -lnt | grep -E ':(20808|20809|4780)\b'
```

Inspect only credential-free fields when diagnosing configuration. Proxy URLs
must always be redacted before display.

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
It intentionally does not enable, start, stop, or restart the proxy. Production
cutover requires a shadow-port test and an explicit rollback plan; follow the
repository README and preserve the previous deployment until acceptance passes.
