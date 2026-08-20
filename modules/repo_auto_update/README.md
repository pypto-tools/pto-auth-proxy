# Repository Auto Update Module

This directory is self-contained and may be copied into another tool. It
provides repository polling, a strict rollout manifest, commit de-duplication,
branch ancestry checks, locking, unprivileged verification, and staged-version
markers. It deliberately contains no tool-specific installation logic.

The adopting tool supplies:

1. A root-owned configuration based on `example.env`.
   Repository fetches run as root by default. Hosts whose root service has no
   direct egress may set `REPO_AUTO_UPDATE_FETCH_USER` and
   `REPO_AUTO_UPDATE_FETCH_ALL_PROXY`; the proxy URL should not contain a
   credential because the configuration is intentionally non-secret.
2. An executable adapter. The module calls it as an unprivileged user for
   verification, then as root for application:

   ```text
   adapter CHECKOUT TARGET SCRATCH_DIR
   ```

   Use separate paths for `REPO_AUTO_UPDATE_VERIFY` and
   `REPO_AUTO_UPDATE_APPLY` when the two operations need different programs.
3. A repository manifest with schema:

   ```json
   {"schema":1,"enabled":false,"target":"","activation":"next-restart",
    "sequence":0,"allow_rollback":false}
   ```

Copy `updater.sh`, `manifest.py`, and the two systemd templates together. Keep
the timer disabled while building an image, then explicitly enable it on a
managed server so repository-state checks continue independently of deployment
state. The generic module never restarts a tool; the adapter must preserve that
invariant if uninterrupted service is required.

An enabled manifest may leave `target` empty with `sequence:0`. This is the
armed-but-idle state: polling remains healthy and deployment is permitted, but
no repository revision is tested or applied until a target is selected.

| `enabled` | `target` | Result |
| --- | --- | --- |
| `false` | any | Report paused and exit successfully |
| `true` | empty | Report armed-but-idle and exit successfully |
| `true` | full commit ID | Verify and apply that exact commit |

For a targeted rollout, increase `sequence`; reusing or decreasing an installed
sequence is rejected. A target older than the installed commit additionally
requires `allow_rollback:true`, making rollback an explicit repository
decision. The target must already be an ancestor of the configured branch; the
module never treats the current branch HEAD as an implicit deployment target.

The adopting adapter and installer must be safe inside the service's
`ProtectSystem=strict` sandbox. List every mutable production path in
`ReadWritePaths`, but do not grant broad access merely to refresh an unchanged
global entrypoint. Prefer an idempotent installer that skips an existing correct
symlink such as `/usr/local/bin/tool -> /opt/tool/app/bin/tool`.

Successful application writes `installed-revision`, `installed-sequence`, and
`pending-activation` below the configured state directory. Application means
files have been staged in the production application path; service activation
remains a separate administrator-controlled restart or boot.

If the installed revision is no longer present in fetched history, the updater
fails closed unless the manifest explicitly sets `allow_rollback:true`. This
prevents a rewritten branch from silently bypassing rollback protection.
