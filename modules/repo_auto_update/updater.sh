#!/usr/bin/env bash
# Generic repository-controlled staged updater.
# Usage: repo-auto-update CONFIG_FILE
set -Eeuo pipefail

MODULE_DIR=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)
MANIFEST_PARSER=$MODULE_DIR/manifest.py
CONFIG_FILE=${1:-}

log() { printf '%s: %s\n' "${REPO_AUTO_UPDATE_NAME:-repo-auto-update}" "$*"; }
fail() { log "ERROR: $*" >&2; exit 1; }

((EUID == 0)) || fail "must run as root"
[[ $# == 1 && -n "$CONFIG_FILE" ]] || fail "usage: $0 CONFIG_FILE"

safe_root_path() {
    local path=$1 expected=$2 mode
    [[ ! -L "$path" ]] || return 1
    case "$expected" in
        directory) [[ -d "$path" ]] || return 1 ;;
        file) [[ -f "$path" && $(stat -c %h "$path" 2>/dev/null) == 1 ]] || return 1 ;;
        *) return 1 ;;
    esac
    [[ $(stat -c %u "$path" 2>/dev/null) == 0 ]] || return 1
    mode=$(stat -c %a "$path" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

safe_root_path "${CONFIG_FILE%/*}" directory || fail "unsafe config directory"
safe_root_path "$CONFIG_FILE" file || fail "unsafe updater config: $CONFIG_FILE"
safe_root_path "$MODULE_DIR" directory || fail "unsafe module directory"
safe_root_path "$MANIFEST_PARSER" file || fail "unsafe manifest parser"

set -a
# shellcheck source=/dev/null
source "$CONFIG_FILE"
set +a

: "${REPO_AUTO_UPDATE_NAME:?missing REPO_AUTO_UPDATE_NAME}"
: "${REPO_AUTO_UPDATE_REPOSITORY:?missing REPO_AUTO_UPDATE_REPOSITORY}"
: "${REPO_AUTO_UPDATE_BRANCH:?missing REPO_AUTO_UPDATE_BRANCH}"
: "${REPO_AUTO_UPDATE_MANIFEST:?missing REPO_AUTO_UPDATE_MANIFEST}"
: "${REPO_AUTO_UPDATE_STATE_DIR:?missing REPO_AUTO_UPDATE_STATE_DIR}"
: "${REPO_AUTO_UPDATE_TMP_DIR:?missing REPO_AUTO_UPDATE_TMP_DIR}"
: "${REPO_AUTO_UPDATE_TEST_USER:?missing REPO_AUTO_UPDATE_TEST_USER}"
: "${REPO_AUTO_UPDATE_VERIFY:?missing REPO_AUTO_UPDATE_VERIFY}"
: "${REPO_AUTO_UPDATE_APPLY:?missing REPO_AUTO_UPDATE_APPLY}"
: "${REPO_AUTO_UPDATE_LOCK_FILE:=/run/lock/${REPO_AUTO_UPDATE_NAME}.lock}"
: "${REPO_AUTO_UPDATE_FETCH_USER:=root}"
: "${REPO_AUTO_UPDATE_FETCH_ALL_PROXY:=}"

[[ "$REPO_AUTO_UPDATE_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || fail "invalid update name"
[[ "$REPO_AUTO_UPDATE_REPOSITORY" == https://* ||
   "$REPO_AUTO_UPDATE_REPOSITORY" == ssh://* ||
   "$REPO_AUTO_UPDATE_REPOSITORY" == git@*:* ]] || fail "unsupported repository URL"
[[ "$REPO_AUTO_UPDATE_BRANCH" =~ ^[A-Za-z0-9._/-]+$ &&
   "$REPO_AUTO_UPDATE_BRANCH" != -* &&
   "$REPO_AUTO_UPDATE_BRANCH" != *..* ]] || fail "invalid update branch"
[[ "$REPO_AUTO_UPDATE_MANIFEST" != /* &&
   "$REPO_AUTO_UPDATE_MANIFEST" != ../* &&
   "$REPO_AUTO_UPDATE_MANIFEST" != */../* ]] || fail "invalid manifest path"
id "$REPO_AUTO_UPDATE_TEST_USER" >/dev/null 2>&1 || fail "test user does not exist"
id "$REPO_AUTO_UPDATE_FETCH_USER" >/dev/null 2>&1 || fail "fetch user does not exist"
if [[ -n "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY" ]]; then
    [[ "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY" == socks5://* ||
       "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY" == socks5h://* ||
       "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY" == http://* ||
       "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY" == https://* ]] || \
        fail "unsupported fetch proxy URL"
fi
safe_root_path "$REPO_AUTO_UPDATE_TMP_DIR" directory || fail "unsafe temporary directory"
safe_root_path "${REPO_AUTO_UPDATE_STATE_DIR%/*}" directory || fail "unsafe state parent"
safe_root_path "$REPO_AUTO_UPDATE_VERIFY" file || fail "unsafe verify adapter"
safe_root_path "$REPO_AUTO_UPDATE_APPLY" file || fail "unsafe apply adapter"
[[ -x "$REPO_AUTO_UPDATE_VERIFY" && -x "$REPO_AUTO_UPDATE_APPLY" ]] || \
    fail "update adapters must be executable"

install -d -m 0755 -o root -g root "$REPO_AUTO_UPDATE_STATE_DIR"
safe_root_path "$REPO_AUTO_UPDATE_STATE_DIR" directory || fail "unsafe state directory"
RELEASE_FILE=$REPO_AUTO_UPDATE_STATE_DIR/installed-revision
SEQUENCE_FILE=$REPO_AUTO_UPDATE_STATE_DIR/installed-sequence
PENDING_FILE=$REPO_AUTO_UPDATE_STATE_DIR/pending-activation
for control in "$RELEASE_FILE" "$SEQUENCE_FILE" "$PENDING_FILE"; do
    if [[ -e "$control" || -L "$control" ]]; then
        safe_root_path "$control" file || fail "unsafe control file: $control"
    fi
done

atomic_write() {
    local destination=$1 value=$2 temporary
    temporary=$(mktemp "$REPO_AUTO_UPDATE_STATE_DIR/.write.XXXXXX")
    chmod 0600 "$temporary"
    printf '%s\n' "$value" >"$temporary"
    mv -Tf -- "$temporary" "$destination"
}

lock_parent=${REPO_AUTO_UPDATE_LOCK_FILE%/*}
safe_root_path "$lock_parent" directory || fail "unsafe lock directory"
if [[ -e "$REPO_AUTO_UPDATE_LOCK_FILE" || -L "$REPO_AUTO_UPDATE_LOCK_FILE" ]]; then
    safe_root_path "$REPO_AUTO_UPDATE_LOCK_FILE" file || fail "unsafe lock file"
else
    install -m 0600 -o root -g root /dev/null "$REPO_AUTO_UPDATE_LOCK_FILE"
fi
exec 9>>"$REPO_AUTO_UPDATE_LOCK_FILE"
flock -n 9 || { log "another update check is running"; exit 0; }

checkout_root=$(mktemp -d "$REPO_AUTO_UPDATE_TMP_DIR/repo-auto-update.XXXXXX")
cleanup() { rm -rf -- "$checkout_root"; }
trap cleanup EXIT
chmod 0755 "$checkout_root"
checkout=$checkout_root/repository

clone_args=(git clone --no-checkout --single-branch --branch
    "$REPO_AUTO_UPDATE_BRANCH" "$REPO_AUTO_UPDATE_REPOSITORY" "$checkout")
if [[ "$REPO_AUTO_UPDATE_FETCH_USER" == root ]]; then
    "${clone_args[@]}" >/dev/null 2>&1 || fail "cannot fetch update repository"
else
    fetch_home=$(getent passwd "$REPO_AUTO_UPDATE_FETCH_USER" | cut -d: -f6)
    fetch_group=$(id -gn "$REPO_AUTO_UPDATE_FETCH_USER")
    [[ -n "$fetch_home" && -d "$fetch_home" ]] || fail "invalid fetch-user home"
    install -d -m 0700 -o "$REPO_AUTO_UPDATE_FETCH_USER" -g "$fetch_group" \
        "$checkout"
    fetch_env=(env HOME="$fetch_home")
    if [[ -n "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY" ]]; then
        fetch_env=(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
            -u all_proxy HOME="$fetch_home" \
            ALL_PROXY="$REPO_AUTO_UPDATE_FETCH_ALL_PROXY")
    fi
    if ! runuser -u "$REPO_AUTO_UPDATE_FETCH_USER" -- \
            "${fetch_env[@]}" "${clone_args[@]}" >/dev/null 2>&1; then
        fail "cannot fetch update repository"
    fi
    chown -R root:root "$checkout"
fi

manifest=$checkout_root/rollout.json
if ! git -C "$checkout" show \
        "origin/$REPO_AUTO_UPDATE_BRANCH:$REPO_AUTO_UPDATE_MANIFEST" \
        >"$manifest" 2>/dev/null; then
    fail "repository has no $REPO_AUTO_UPDATE_MANIFEST"
fi
rollout_output=$checkout_root/rollout.output
python3 "$MANIFEST_PARSER" "$manifest" >"$rollout_output" || \
    fail "invalid rollout manifest"
mapfile -t rollout <"$rollout_output"
((${#rollout[@]} == 5)) || fail "invalid rollout manifest response"

if [[ ${rollout[0]} != true ]]; then
    log "remote rollout is paused"
    exit 0
fi
target=${rollout[1]}
sequence=${rollout[3]}
allow_rollback=${rollout[4]}
if [[ -z "$target" ]]; then
    log "deployment is enabled; no target is selected"
    exit 0
fi
installed=
[[ ! -f "$RELEASE_FILE" ]] || installed=$(<"$RELEASE_FILE")
installed_sequence=0
[[ ! -f "$SEQUENCE_FILE" ]] || installed_sequence=$(<"$SEQUENCE_FILE")
[[ "$installed_sequence" =~ ^[0-9]+$ ]] || fail "invalid installed sequence"
if [[ "$installed" == "$target" ]]; then
    if ((sequence > installed_sequence)); then
        atomic_write "$SEQUENCE_FILE" "$sequence"
    fi
    log "target ${target:0:12} is already staged"
    exit 0
fi
if ((sequence < installed_sequence)); then
    fail "rollout sequence $sequence is older than installed sequence $installed_sequence"
fi
if ((sequence == installed_sequence && installed_sequence != 0)); then
    fail "rollout sequence $sequence was reused for a different target"
fi

git -C "$checkout" cat-file -e "$target^{commit}" 2>/dev/null || \
    fail "rollout target is not present on fetched branch"
git -C "$checkout" merge-base --is-ancestor \
    "$target" "origin/$REPO_AUTO_UPDATE_BRANCH" || \
    fail "rollout target is not an ancestor of the configured branch"
git -C "$checkout" checkout --detach "$target" >/dev/null 2>&1 || \
    fail "cannot check out rollout target"
if [[ -n "$installed" ]]; then
    if ! git -C "$checkout" cat-file -e "$installed^{commit}" 2>/dev/null; then
        [[ "$allow_rollback" == true ]] || \
            fail "installed revision is absent from fetched history; explicit rollback is required"
    elif git -C "$checkout" merge-base --is-ancestor \
            "$target" "$installed" && [[ "$allow_rollback" != true ]]; then
        fail "target is older than the installed revision; explicit rollback is required"
    fi
fi

chmod -R a+rX "$checkout"
test_home=$(getent passwd "$REPO_AUTO_UPDATE_TEST_USER" | cut -d: -f6)
[[ -n "$test_home" && -d "$test_home" ]] || fail "invalid test-user home"
if ! runuser -u "$REPO_AUTO_UPDATE_TEST_USER" -- env HOME="$test_home" \
        PYTHONDONTWRITEBYTECODE=1 \
        REPO_AUTO_UPDATE_ADAPTER_MODE=verify \
        "$REPO_AUTO_UPDATE_VERIFY" "$checkout" "$target" "$checkout_root"; then
    fail "candidate ${target:0:12} failed verification"
fi

if ! REPO_AUTO_UPDATE_ADAPTER_MODE=apply \
        "$REPO_AUTO_UPDATE_APPLY" "$checkout" "$target" "$checkout_root"; then
    fail "candidate ${target:0:12} failed application"
fi

atomic_write "$RELEASE_FILE" "$target"
atomic_write "$SEQUENCE_FILE" "$sequence"
atomic_write "$PENDING_FILE" "$target"
log "staged ${target:0:12}; running services were not restarted"
log "activation is deferred to the next administrator-controlled restart or boot"
