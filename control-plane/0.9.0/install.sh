#!/usr/bin/env bash
# remyral-ctl — install, upgrade and operate a self-hosted Remyral control plane on one Linux host.
# p16-selfhost-onboarding: docs/design/p16-selfhost-onboarding.md, ADR-0063, docs/ops/selfhost-install.md
# (Turkish: docs/guide/tr/kurulum.md). Published as both `install.sh` and `remyral-ctl` (the same bytes).
#
#   sudo bash install.sh --domain console.example.com --tls letsencrypt --email ops@example.com
#   remyral-ctl install   [--domain D] [--tls letsencrypt|cloudflare|proxy] [--email E] [--data-dir DIR]
#                        [--version V] [--channel stable] [--release-url URL | --bundle DIR] [--registry PREFIX]
#                        [--tls-cert F --tls-key F] [--http-port N] [--https-port N] [--bind ADDR]
#                        [--trusted-proxy CIDR]... [--backup-recipient AGE_PUBKEY] [--no-update-check]
#                        [--new-setup-token] [--skip-checks] [--yes] [--dry-run]
#   remyral-ctl upgrade   [--to V] [--check] [--skip-backup] [--yes] [--dry-run] [--bundle DIR]
#   remyral-ctl rollback  [--to V] [--restore-backup ID] [--yes] [--dry-run]
#   remyral-ctl status | version | backup [--reason R] | drill [--backup ID] | doctor | setup-token | help
#   remyral-ctl restore --backup ID [--yes]   (replace the database with a backup of this host; the old one is kept)
#   remyral-ctl apply-pending   (root systemd units run it: requests the console signed — domain, update, rollback, backups)
#   remyral-ctl backup-change show | cancel | confirm   (a recipient / off-site change the console asked for waits 72 h)
#   remyral-ctl uninstall [--purge-data] [--yes] [--dry-run]
#
# Trust: every release manifest is Ed25519-signed by the vendor's offline release key (domain
# `remyral-control-plane-release/v1`); the trusted public keys are compiled into this file by the release tool and,
# after the first install, kept in <data>/trust/keys. Images are pulled by digest only (the signed manifest names
# them), so the registry cannot substitute content. A failed verification stops before anything is pulled or changed.
#
# Requirements: Linux (x86_64 / aarch64), root, Docker Engine >= 24 with the compose plugin >= 2.24, OpenSSL >= 3,
# curl. Windows and macOS are not supported for the control plane (they are supported as worker machines).
#
# Test hooks (scripts/test/selfhost-ctl.test.mjs; never needed in production): REMYRAL_CTL_ALLOW_NONROOT=1,
# REMYRAL_CTL_OS, REMYRAL_CTL_ARCH, REMYRAL_CTL_MEMINFO, REMYRAL_CTL_TRUST (space-separated keys), REMYRAL_CTL_BIN_DIR,
# REMYRAL_CTL_SYSTEMD_DIR, REMYRAL_CTL_GATE_TRIES, REMYRAL_CTL_SLEEP, REMYRAL_CTL_DOMAIN_GATE_TRIES,
# REMYRAL_CTL_ALIAS_GRACE (seconds), REMYRAL_CTL_ADDRESSES (space-separated), REMYRAL_CTL_FREE_KB (free disk, KiB).
#
# Domain changes from the console (p17-domain-wizard, ADR-0063 amendment 2026-10-24): the master writes a request into
# <data>/host/requests, signed with its lease-signing key (domain `remyral-host-domain-change/v1`). `apply-pending`
# (root; a systemd path unit on the request file and a one-minute timer that also writes the heartbeat) verifies the
# signature against the public half of <data>/secrets/lease-signing.pem, re-validates every field with the rules of
# `install --domain/--tls/--email`, refuses expired or replayed requests, then changes ONLY the domain / TLS mode /
# ACME e-mail: stack.env, the Traefik configuration, `compose up` of master + web (+ proxy). The previous name keeps
# answering until the new one is healthy (and an hour after); a new name that does not become healthy is rolled back.
# The request carries data, never commands.
set -euo pipefail
umask 077

# >>> written by scripts/release/control-plane.mjs (empty in the source tree) >>>
REMYRAL_TRUSTED_KEYS='WdOSMgYAE6UjtBX32o62ho-mW-tVZ-SkuNHK7Dl4W6w'
REMYRAL_DEFAULT_RELEASE_URL='https://releases.remyral.com/control-plane'
REMYRAL_CTL_BUNDLE_VERSION='0.9.0'
# <<< written by scripts/release/control-plane.mjs <<<

readonly RELEASE_CONTEXT='remyral-control-plane-release/v1'
readonly FEED_CONTEXT='remyral-control-plane-feed/v1'
readonly PROJECT='remyral-prod'
readonly PROXY_NETWORK_NAME='remyral-proxy'
readonly KEEP_RELEASES=3
readonly MIN_DOCKER='24.0.0'
readonly MIN_COMPOSE='2.24.0'
readonly MIN_MEM_MIB=3500
readonly WARN_MEM_MIB=7500
readonly MIN_DISK_GIB=10
readonly WARN_DISK_GIB=20
readonly B64U_KEY_RE='^[A-Za-z0-9_-]{43}$'
readonly VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
readonly IMAGE_RE='^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$'
readonly DIGEST_RE='^sha256:[0-9a-f]{64}$'
readonly DOMAIN_RE='^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
readonly EMAIL_RE='^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$'
readonly UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
readonly ISO_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
readonly DOMAIN_CHANGE_CONTEXT='remyral-host-domain-change/v1'
# p17-host-actions (ADR-0063 amendment 2026-10-26): the other request kinds the console may sign — a closed list; each
# kind has its own signature domain `remyral-host-<kind>/v1`, its own closed set of fields and its own handler.
readonly HOST_REQUEST_KINDS='upgrade rollback backup-run backup-drill backup-restore backup-config backup-offsite backup-change-cancel'
# p17-panel-settings Part 0 (ADR-0063 amendment 2026-10-26, "host time lock"): a request that ADDS an encryption
# recipient or CHANGES the off-site target waits this long on the host — counted from the time THIS host first saw it
# (never the master-signed createdAt) — before it takes effect; `backup-change-cancel` (or `remyral-ctl backup-change
# cancel`) withdraws it meanwhile. Not configurable: a shorter wait would be the whole attack.
readonly BACKUP_CHANGE_WAIT_S=259200
readonly HOST_RESULT_KIND='remyral-host-result/v1'
readonly BACKUP_ID_RE='^remana-[a-z]+-[0-9]{8}T[0-9]{6}Z$'
readonly AGE_RECIPIENT_RE='^age1[02-9ac-hj-np-z]{58}$'
readonly HHMM_RE='^([01][0-9]|2[0-3]):[0-5][0-9]$'

# ---------------------------------------------------------------- output

STEP_NO=0
out() { printf '%s\n' "$*"; }
note() { printf '       %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() {
  printf 'remyral-ctl: %s\n' "$*" >&2
  exit 1
}
step() {
  STEP_NO=$((STEP_NO + 1))
  printf '[%2d] %s\n' "$STEP_NO" "$1"
}
show() { printf '       $ %s\n' "$*"; }
# Runs a command, or (dry run) only shows it.
run() {
  show "$*"
  if [ "$DRY" = 1 ]; then return 0; fi
  "$@"
}

# ---------------------------------------------------------------- options

CMD="${1:-}"
case "$CMD" in
  install | upgrade | rollback | status | version | backup | drill | restore | doctor | setup-token | apply-pending | backup-change | uninstall | help) shift ;;
  -h | --help) CMD=help ;;
  '' | -*) CMD=install ;;
  *) die "unknown command '$CMD' (install | upgrade | rollback | status | version | backup | drill | restore | doctor | setup-token | apply-pending | backup-change | uninstall | help)" ;;
esac

DRY=0
YES=0
DATA_DIR="${REMYRAL_DATA_DIR:-/var/lib/remyral}"
DOMAIN=''
TLS_MODE=''
ACME_EMAIL=''
WANT_VERSION=''
CHANNEL='stable'
RELEASE_URL=''
BUNDLE_DIR=''
REGISTRY=''
TLS_CERT=''
TLS_KEY=''
HTTP_PORT=''
HTTPS_PORT=''
BIND_ADDR=''
TRUSTED_PROXIES=''
BACKUP_RECIPIENT=''
UPDATE_CHECK=1
NEW_TOKEN=0
SKIP_CHECKS=0
CHECK_ONLY=0
SKIP_BACKUP=0
RESTORE_BACKUP=''
PURGE=0
BACKUP_REASON='manual'
BACKUP_ARG=''
CHANGE_ACTION=''

need_arg() { if [ "$#" -lt 2 ] || [ -z "$2" ]; then die "$1 needs a value"; fi; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --yes | -y) YES=1 ;;
    --data-dir) need_arg "$@"; DATA_DIR="$2"; shift ;;
    --domain) need_arg "$@"; DOMAIN="$2"; shift ;;
    --tls) need_arg "$@"; TLS_MODE="$2"; shift ;;
    --email) need_arg "$@"; ACME_EMAIL="$2"; shift ;;
    --version | --to) need_arg "$@"; WANT_VERSION="$2"; shift ;;
    --channel) need_arg "$@"; CHANNEL="$2"; shift ;;
    --release-url) need_arg "$@"; RELEASE_URL="$2"; shift ;;
    --bundle) need_arg "$@"; BUNDLE_DIR="$2"; shift ;;
    --registry) need_arg "$@"; REGISTRY="$2"; shift ;;
    --tls-cert) need_arg "$@"; TLS_CERT="$2"; shift ;;
    --tls-key) need_arg "$@"; TLS_KEY="$2"; shift ;;
    --http-port) need_arg "$@"; HTTP_PORT="$2"; shift ;;
    --https-port) need_arg "$@"; HTTPS_PORT="$2"; shift ;;
    --bind) need_arg "$@"; BIND_ADDR="$2"; shift ;;
    --trusted-proxy) need_arg "$@"; TRUSTED_PROXIES="${TRUSTED_PROXIES:+$TRUSTED_PROXIES }$2"; shift ;;
    --backup-recipient) need_arg "$@"; BACKUP_RECIPIENT="$2"; shift ;;
    --no-update-check) UPDATE_CHECK=0 ;;
    --new-setup-token) NEW_TOKEN=1 ;;
    --skip-checks) SKIP_CHECKS=1 ;;
    --check) CHECK_ONLY=1 ;;
    --skip-backup) SKIP_BACKUP=1 ;;
    --restore-backup) need_arg "$@"; RESTORE_BACKUP="$2"; shift ;;
    --purge-data) PURGE=1 ;;
    --reason) need_arg "$@"; BACKUP_REASON="$2"; shift ;;
    --backup) need_arg "$@"; BACKUP_ARG="$2"; shift ;;
    -h | --help) CMD=help ;;
    show | cancel | confirm)
      [ "$CMD" = backup-change ] || die "unknown option '$1' (remyral-ctl help)"
      CHANGE_ACTION="$1"
      ;;
    *) die "unknown option '$1' (remyral-ctl help)" ;;
  esac
  shift
done

case "$DATA_DIR" in
  /*) ;;
  *) die "--data-dir must be an absolute path" ;;
esac
DATA_DIR="${DATA_DIR%/}"
if [ -z "$DATA_DIR" ] || [ "$DATA_DIR" = / ]; then die "--data-dir must not be /"; fi

STACK_ENV="$DATA_DIR/stack.env"
RELEASE_ENV="$DATA_DIR/release.env"
STATE_DIR="$DATA_DIR/state"
RELEASES_DIR="$DATA_DIR/release"
TRUST_FILE="$DATA_DIR/trust/keys"
BIN_DIR="${REMYRAL_CTL_BIN_DIR:-/usr/local/bin}"
SYSTEMD_DIR="${REMYRAL_CTL_SYSTEMD_DIR:-/etc/systemd/system}"
GATE_TRIES="${REMYRAL_CTL_GATE_TRIES:-24}"
SLEEP_S="${REMYRAL_CTL_SLEEP:-5}"
HOST_DIR="$DATA_DIR/host"
# A new domain gets 5 minutes (60 × 5 s) to answer healthy with its certificate before the change is rolled back.
DOMAIN_GATE_TRIES="${REMYRAL_CTL_DOMAIN_GATE_TRIES:-60}"
ALIAS_GRACE_S="${REMYRAL_CTL_ALIAS_GRACE:-3600}"
WORK=''

cleanup() {
  # p17-host-actions: a restore that stopped half-way starts the stopped services again (the database is unchanged
  # unless the final rename ran).
  if [ -n "${RESTART_ON_EXIT:-}" ]; then
    dc "$RESTART_ON_EXIT" "$RELEASE_ENV" up -d master web backup >/dev/null 2>&1 || true
  fi
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then rm -rf "$WORK"; fi
  if [ "${LOCKED:-0}" = 1 ]; then rmdir "$DATA_DIR/.lock" 2>/dev/null || true; fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- small helpers

# `"key": "value"` of a JSON file written by the release tool (pretty-printed, one key per line). Only used on
# documents whose signature was verified first; every value is validated by the caller.
json_str() {
  sed -n "s/^ *\"$2\": \"\\([^\"]*\\)\",\\{0,1\\}\$/\\1/p" "$1" | head -n 1
}
# Same, inside the object `"$2": { … }`.
json_obj_str() {
  awk -v obj="\"$2\": {" -v key="\"$3\": \"" '
    index($0, obj) { inside = 1; next }
    inside && /^ *}/ { inside = 0 }
    inside && index($0, key) { s = substr($0, index($0, key) + length(key)); sub(/".*/, "", s); print s; exit }
  ' "$1"
}
# Keys of the object `"$2": { … }` (one per line).
json_obj_keys() {
  awk -v obj="\"$2\": {" '
    index($0, obj) { inside = 1; next }
    inside && /^ *}/ { inside = 0 }
    inside { s = $0; sub(/^ *"/, "", s); sub(/".*/, "", s); print s }
  ' "$1"
}
# String items of the array `"$2": [ … ]` (one per line; `[]` → nothing).
json_array() {
  awk -v arr="\"$2\": [" '
    index($0, arr) { if ($0 ~ /\]/) exit; inside = 1; next }
    inside && /^ *\]/ { exit }
    inside { s = $0; sub(/^ *"/, "", s); sub(/",? *$/, "", s); gsub(/\\"/, "\"", s); print s }
  ' "$1"
}
sha256_of() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
b64u_to_file() {
  local s="$1" pad
  s="$(printf '%s' "$s" | tr '_-' '/+')"
  pad=$(((4 - ${#s} % 4) % 4))
  while [ "$pad" -gt 0 ]; do s="$s="; pad=$((pad - 1)); done
  printf '%s' "$s" | openssl base64 -d -A >"$2"
}
# PEM (SPKI) of a raw base64url Ed25519 public key: DER prefix 302a300506032b6570032100 ‖ 32 bytes.
key_pem() {
  local raw="$WORK/key.raw"
  b64u_to_file "$1" "$raw"
  [ "$(wc -c <"$raw" | tr -d ' ')" = 32 ] || return 1
  printf -- '-----BEGIN PUBLIC KEY-----\n'
  { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; cat "$raw"; } | openssl base64 -A
  printf '\n-----END PUBLIC KEY-----\n'
}
# 0 if version $1 > $2 (numeric x.y.z; a pre-release sorts before its release).
ver_gt() {
  local a="$1" b="$2" a1 a2 a3 b1 b2 b3 ap bp
  ap="${a#*-}"; [ "$ap" = "$a" ] && ap=''
  bp="${b#*-}"; [ "$bp" = "$b" ] && bp=''
  a="${a%%-*}"; b="${b%%-*}"
  IFS=. read -r a1 a2 a3 <<EOF
$a
EOF
  IFS=. read -r b1 b2 b3 <<EOF
$b
EOF
  a3="${a3:-0}"; b3="${b3:-0}"
  if [ "$a1" -ne "$b1" ]; then [ "$a1" -gt "$b1" ]; return; fi
  if [ "$a2" -ne "$b2" ]; then [ "$a2" -gt "$b2" ]; return; fi
  if [ "$a3" -ne "$b3" ]; then [ "$a3" -gt "$b3" ]; return; fi
  if [ -z "$ap" ] && [ -n "$bp" ]; then return 0; fi
  if [ -n "$ap" ] && [ -n "$bp" ] && [ "$ap" \> "$bp" ]; then return 0; fi
  return 1
}
ver_ge() { [ "$1" = "$2" ] || ver_gt "$1" "$2"; }
# A lower-case DNS name with at least one dot, at most 253 characters, not an IP address.
valid_domain() {
  [ "${#1}" -ge 4 ] && [ "${#1}" -le 253 ] || return 1
  printf '%s' "$1" | grep -Eq "$DOMAIN_RE" || return 1
  ! printf '%s' "${1##*.}" | grep -Eq '^[0-9]+$'
}
confirm() {
  if [ "$YES" = 1 ]; then return 0; fi
  if [ "$DRY" = 1 ]; then return 0; fi
  if [ ! -t 0 ]; then die "$1 — re-run with --yes to confirm non-interactively"; fi
  printf '%s [y/N] ' "$1"
  local a
  read -r a
  case "$a" in y | Y | yes | evet | e) return 0 ;; *) die "aborted" ;; esac
}
ask() { # ask VAR "question" — only on a terminal, never with --yes
  if [ "$YES" = 1 ] || [ ! -t 0 ]; then return 0; fi
  printf '%s: ' "$2"
  local a
  read -r a
  eval "$1=\$a"
}
lock() {
  [ "$DRY" = 1 ] && return 0
  # p17-host-actions: `apply-pending` runs `upgrade` / `rollback` / `restore` as a child under the lock it holds.
  if [ "${REMYRAL_CTL_LOCK_INHERITED:-0}" = 1 ] && [ -d "$DATA_DIR/.lock" ]; then return 0; fi
  mkdir -p "$DATA_DIR"
  mkdir "$DATA_DIR/.lock" 2>/dev/null || die "another remyral-ctl is running (remove $DATA_DIR/.lock if it is stale)"
  LOCKED=1
}
new_work() { WORK="$(mktemp -d "${TMPDIR:-/tmp}/remyral-ctl.XXXXXX")"; }
env_value() { # env_value FILE KEY → value of KEY=value (last one)
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1
}
set_env_value() { # set_env_value FILE KEY VALUE (replaces or appends; root-only file)
  [ "$DRY" = 1 ] && return 0
  awk -v k="$2" -v v="$3" 'BEGIN { done = 0 } index($0, k "=") == 1 { print k "=" v; done = 1; next } { print }
    END { if (!done) print k "=" v }' "$1" >"$1.tmp"
  chmod 0600 "$1.tmp"
  mv "$1.tmp" "$1"
}

# ---------------------------------------------------------------- trust and signatures

# The keys this run trusts: the installed list, else the test override, else the compiled-in list.
trusted_keys() {
  if [ -s "$TRUST_FILE" ]; then tr '\n' ' ' <"$TRUST_FILE"
  elif [ -n "${REMYRAL_CTL_TRUST:-}" ]; then printf '%s' "$REMYRAL_CTL_TRUST"
  else printf '%s' "$REMYRAL_TRUSTED_KEYS"
  fi
}
# verify_signed FILE SIGFILE CONTEXT — Ed25519 over "CONTEXT\n" ‖ FILE bytes with one of the trusted keys.
verify_signed() {
  local file="$1" sig="$2" ctx="$3" keys value k
  keys="$(trusted_keys)"
  [ -n "${keys// /}" ] || die "this remyral-ctl carries no release keys (a source copy, not a published release)"
  value="$(sed -n 's/.*"signature": *"\([A-Za-z0-9_-]*\)".*/\1/p' "$sig" | head -n 1)"
  [ -n "$value" ] || die "$(basename "$sig"): no signature"
  b64u_to_file "$value" "$WORK/sig.bin" || die "$(basename "$sig"): malformed signature"
  { printf '%s\n' "$ctx"; cat "$file"; } >"$WORK/signed.bin"
  for k in $keys; do
    printf '%s' "$k" | grep -Eq "$B64U_KEY_RE" || continue
    key_pem "$k" >"$WORK/key.pem" || continue
    if openssl pkeyutl -verify -pubin -inkey "$WORK/key.pem" -rawin -in "$WORK/signed.bin" \
      -sigfile "$WORK/sig.bin" >/dev/null 2>&1; then
      return 0
    fi
  done
  die "SIGNATURE CHECK FAILED for $(basename "$file"): not signed by a trusted Remyral release key — nothing was changed"
}

# ---------------------------------------------------------------- release source

release_base() {
  if [ -n "$RELEASE_URL" ]; then printf '%s' "${RELEASE_URL%/}"
  elif [ -n "$(env_value "$STACK_ENV" REMYRAL_RELEASE_URL)" ]; then env_value "$STACK_ENV" REMYRAL_RELEASE_URL
  else printf '%s' "${REMYRAL_DEFAULT_RELEASE_URL%/}"
  fi
}
fetch() { # fetch URL DEST
  case "$1" in
    https://*) ;;
    *) die "refusing to download over a non-https URL: $1" ;;
  esac
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$2" "$1" || die "download failed: $1"
}
# The signed feed into $WORK/feed.json (url mode). Prints nothing.
fetch_feed() {
  local base
  base="$(release_base)"
  [ -n "$base" ] || die "no release URL: pass --release-url https://… or --bundle <dir>"
  fetch "$base/feed.json" "$WORK/feed.json"
  fetch "$base/feed.sig.json" "$WORK/feed.sig.json"
  verify_signed "$WORK/feed.json" "$WORK/feed.sig.json" "$FEED_CONTEXT"
}
# Newest release of the feed (releases are listed newest first).
feed_latest() { json_str "$WORK/feed.json" version; }
feed_has() { grep -q "\"version\": \"$1\"" "$WORK/feed.json"; }

# Downloads (or copies from --bundle) release $1 into $2 and verifies it: signature, then every file's SHA-256.
fetch_release() {
  local v="$1" dest="$2" src='' f want got base
  mkdir -p "$dest"
  if [ -n "$BUNDLE_DIR" ]; then
    src="$BUNDLE_DIR"
    [ -f "$src/$v/manifest.json" ] && src="$src/$v"
    [ -f "$src/manifest.json" ] || die "$BUNDLE_DIR has no manifest.json"
    cp "$src/manifest.json" "$src/manifest.sig.json" "$dest/"
  else
    base="$(release_base)"
    fetch "$base/$v/manifest.json" "$dest/manifest.json"
    fetch "$base/$v/manifest.sig.json" "$dest/manifest.sig.json"
  fi
  verify_signed "$dest/manifest.json" "$dest/manifest.sig.json" "$RELEASE_CONTEXT"
  [ "$(json_str "$dest/manifest.json" name)" = remyral-control-plane ] || die "manifest is not a Remyral control-plane release"
  if [ -n "$v" ] && [ "$v" != "$(json_str "$dest/manifest.json" version)" ]; then
    die "manifest is for $(json_str "$dest/manifest.json" version), expected $v"
  fi
  for f in $(json_obj_keys "$dest/manifest.json" files); do
    case "$f" in */* | .* | '') die "manifest lists a bad file name: $f" ;; esac
    if [ -n "$src" ]; then cp "$src/$f" "$dest/$f" 2>/dev/null || die "bundle is missing $f"
    else fetch "$base/$v/$f" "$dest/$f"
    fi
    want="$(json_obj_str "$dest/manifest.json" files "$f")"
    got="$(sha256_of "$dest/$f")"
    [ "$want" = "$got" ] || die "INTEGRITY CHECK FAILED: $f does not match the signed manifest — nothing was changed"
  done
  for f in compose.yaml compose.selfhost.yaml remyral-ctl; do
    [ -f "$dest/$f" ] || die "release is missing $f"
  done
}
# Validated image reference of release dir $1 for component $2, with --registry applied (the digest is kept).
image_ref() {
  local ref
  ref="$(json_obj_str "$1/manifest.json" images "$2")"
  printf '%s' "$ref" | grep -Eq "$IMAGE_RE" || die "manifest: bad $2 image reference '$ref'"
  local registry="${REGISTRY:-$(env_value "$STACK_ENV" REMYRAL_REGISTRY)}"
  if [ -n "$registry" ]; then
    ref="${registry%/}/${ref##*/}"
  fi
  printf '%s' "$ref"
}
manifest_version() {
  local v
  v="$(json_str "$1/manifest.json" version)"
  printf '%s' "$v" | grep -Eq "$VERSION_RE" || die "manifest: bad version '$v'"
  printf '%s' "$v"
}
manifest_migrations() {
  local m
  m="$(json_str "$1/manifest.json" migrationsHead)"
  printf '%s' "$m" | grep -Eq '^[0-9]{4}$' || die "manifest: bad migrationsHead '$m'"
  printf '%s' "$m"
}
manifest_commit() {
  local c
  c="$(json_str "$1/manifest.json" commit)"
  printf '%s' "$c" | grep -Eq '^[0-9a-f]{40}$' || die "manifest: bad commit '$c'"
  printf '%s' "$c"
}
print_breaking() {
  local b
  b="$(json_array "$1/manifest.json" breaking)"
  if [ -n "$b" ]; then
    out "Breaking changes in $(manifest_version "$1"):"
    printf '%s\n' "$b" | sed 's/^/  - /'
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------- prerequisites

PROBLEMS=0
problem() {
  if [ "$SKIP_CHECKS" = 1 ]; then warn "$1 (ignored: --skip-checks)"
  else printf '       FAIL %s\n' "$1"; PROBLEMS=$((PROBLEMS + 1))
  fi
}
check_prereqs() { # check_prereqs install|upgrade
  local os arch mem_kb mem avail_kb avail dv cv ov probe
  step "check prerequisites"
  os="${REMYRAL_CTL_OS:-$(uname -s)}"
  arch="${REMYRAL_CTL_ARCH:-$(uname -m)}"
  case "$os" in
    Linux) note "ok   Linux ($arch)" ;;
    Darwin | MINGW* | MSYS* | CYGWIN* | Windows*)
      die "the control plane runs on Linux only — $os is not supported (Windows and macOS machines join as workers: Makineler → Makine ekle)" ;;
    *) die "unsupported operating system: $os" ;;
  esac
  case "$arch" in x86_64 | amd64 | aarch64 | arm64) ;; *) problem "CPU architecture $arch (x86_64 or aarch64 needed)" ;; esac
  if [ "$(id -u)" != 0 ] && [ "${REMYRAL_CTL_ALLOW_NONROOT:-0}" != 1 ]; then
    die "run as root (sudo): the installer writes $DATA_DIR, key files owned by the service users and the proxy ports"
  fi
  command -v docker >/dev/null 2>&1 || die "Docker is not installed (https://docs.docker.com/engine/install/)"
  dv="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
  if [ -z "$dv" ]; then problem "the Docker daemon is not reachable (is it running? are you root?)"
  elif ver_ge "${dv%%[+~]*}" "$MIN_DOCKER"; then note "ok   Docker $dv"
  else problem "Docker $dv is too old (>= $MIN_DOCKER needed)"
  fi
  cv="$(docker compose version --short 2>/dev/null || true)"
  cv="${cv#v}"
  if [ -z "$cv" ]; then problem "the Docker compose plugin is missing (apt install docker-compose-plugin)"
  elif ver_ge "${cv%%[+~]*}" "$MIN_COMPOSE"; then note "ok   Docker Compose $cv"
  else problem "Docker Compose $cv is too old (>= $MIN_COMPOSE needed)"
  fi
  ov="$(openssl version 2>/dev/null || true)"
  case "$ov" in
    'OpenSSL 3.'* | 'OpenSSL 4.'*) note "ok   ${ov%% (*}" ;;
    *) problem "OpenSSL 3 is needed to verify release signatures (found: ${ov:-none})" ;;
  esac
  if [ -z "$BUNDLE_DIR" ]; then
    if command -v curl >/dev/null 2>&1; then note "ok   curl"; else problem "curl is missing"; fi
  fi
  mem_kb="$(sed -n 's/^MemTotal: *\([0-9]*\) kB$/\1/p' "${REMYRAL_CTL_MEMINFO:-/proc/meminfo}" 2>/dev/null || true)"
  if [ -n "$mem_kb" ]; then
    mem=$((mem_kb / 1024))
    if [ "$mem" -lt "$MIN_MEM_MIB" ]; then problem "memory ${mem} MiB (at least 4 GiB needed)"
    elif [ "$mem" -lt "$WARN_MEM_MIB" ]; then note "ok   memory ${mem} MiB (8 GiB recommended)"
    else note "ok   memory ${mem} MiB"
    fi
  else problem "cannot read the memory size"
  fi
  probe="$DATA_DIR"
  while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
  avail_kb="${REMYRAL_CTL_FREE_KB:-$(df -Pk "$probe" | awk 'NR == 2 { print $4 }')}"
  avail=$((avail_kb / 1024 / 1024))
  if [ "$avail" -lt "$MIN_DISK_GIB" ]; then problem "free disk under $probe: ${avail} GiB (at least ${MIN_DISK_GIB} GiB needed)"
  elif [ "$avail" -lt "$WARN_DISK_GIB" ]; then note "ok   free disk ${avail} GiB (${WARN_DISK_GIB} GiB recommended)"
  else note "ok   free disk ${avail} GiB"
  fi
  if [ "$1" = install ] && [ -z "$(container_of proxy)" ]; then
    local p
    for p in "${HTTP_PORT:-80}" "${HTTPS_PORT:-443}"; do
      if command -v ss >/dev/null 2>&1; then
        if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then problem "port $p is already in use"
        else note "ok   port $p is free"
        fi
      else
        note "skip port $p check (ss not found)"
      fi
    done
  fi
  if [ "$PROBLEMS" -gt 0 ]; then die "$PROBLEMS prerequisite check(s) failed (see above; --skip-checks to override deliberately)"; fi
}

# ---------------------------------------------------------------- docker

# docker compose for release dir $1 with env file $2 (default: the active release.env).
dc() {
  local rel="$1" renv="${2:-$RELEASE_ENV}"
  shift 2
  docker compose -p "$PROJECT" --project-directory "$rel" --env-file "$STACK_ENV" --env-file "$renv" \
    -f "$rel/compose.yaml" -f "$rel/compose.selfhost.yaml" --profile backup "$@"
}
dc_show() { printf 'docker compose -p %s --project-directory %s --env-file %s --env-file %s -f %s -f %s --profile backup' \
  "$PROJECT" "$1" "$STACK_ENV" "${2:-$RELEASE_ENV}" "$1/compose.yaml" "$1/compose.selfhost.yaml"; }
container_of() {
  docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -n 1
}
psql_q() { # psql_q SQL → first line, or nothing
  local pg
  pg="$(container_of postgres)"
  [ -n "$pg" ] || return 0
  docker exec -u postgres "$pg" psql -U postgres -d remyral -X -tAc "$1" 2>/dev/null | head -n 1 | tr -d ' '
}
db_head() { psql_q "SELECT coalesce(max(version), '') FROM schema_migrations"; }
owners_count() { psql_q "SELECT count(*) FROM users"; }
pull_image() { # pull_image REF — by digest; the daemon checks the content against the digest
  local ref="$1" digest="${1##*@}" have
  printf '%s' "$digest" | grep -Eq "$DIGEST_RE" || die "not a digest reference: $ref"
  if docker image inspect "$ref" >/dev/null 2>&1; then note "present $ref"; return 0; fi
  show "docker pull --quiet $ref"
  [ "$DRY" = 1 ] && return 0
  docker pull --quiet "$ref" >/dev/null || die "pull failed: $ref"
  have="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null || true)"
  printf '%s\n' "$have" | grep -q "@$digest\$" || die "pulled image does not carry the signed digest $digest"
}
health_of() {
  local id
  id="$(container_of "$1")"
  [ -n "$id" ] || { printf 'missing'; return 0; }
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || printf 'missing'
}
running_image() {
  local id
  id="$(container_of "$1")"
  [ -n "$id" ] || return 0
  docker inspect --format '{{.Config.Image}}' "$id" 2>/dev/null || true
}
console_url() {
  local d="${1:-$DOMAIN}" p
  p="$(env_value "$STACK_ENV" REMYRAL_HTTPS_PORT)"
  if [ -n "$p" ] && [ "$p" != 443 ]; then printf 'https://%s:%s' "$d" "$p"; else printf 'https://%s' "$d"; fi
}
# Health gate: master/web healthy, running the signed images, the public probe and the console through the proxy.
GATE_FAILURES=''
health_gate() { # health_gate MASTER_REF WEB_REF
  local i port bind m w status root d
  d="$(env_value "$STACK_ENV" REMYRAL_DOMAIN)"
  port="$(env_value "$STACK_ENV" REMYRAL_HTTPS_PORT)"; port="${port:-443}"
  bind="$(env_value "$STACK_ENV" REMYRAL_BIND_ADDRESS)"
  case "$bind" in '' | 0.0.0.0 | '::') bind=127.0.0.1 ;; esac
  i=0
  while [ "$i" -lt "$GATE_TRIES" ]; do
    i=$((i + 1))
    GATE_FAILURES=''
    m="$(health_of master)"; w="$(health_of web)"
    [ "$m" = healthy ] || GATE_FAILURES="$GATE_FAILURES; master is $m"
    [ "$w" = healthy ] || GATE_FAILURES="$GATE_FAILURES; web is $w"
    [ "$(running_image master)" = "$1" ] || GATE_FAILURES="$GATE_FAILURES; master does not run the signed image"
    [ "$(running_image web)" = "$2" ] || GATE_FAILURES="$GATE_FAILURES; web does not run the signed image"
    status="$(curl -sk --max-time 10 --resolve "$d:$port:$bind" "https://$d:$port/api/status" 2>/dev/null || true)"
    printf '%s' "$status" | grep -q '"status": *"ok"' || GATE_FAILURES="$GATE_FAILURES; GET /api/status is not ok"
    root="$(curl -sk --max-time 10 --resolve "$d:$port:$bind" "https://$d:$port/" 2>/dev/null || true)"
    printf '%s' "$root" | grep -q 'id="root"' || GATE_FAILURES="$GATE_FAILURES; GET / does not serve the console"
    if [ -z "$GATE_FAILURES" ]; then return 0; fi
    [ "$i" -lt "$GATE_TRIES" ] && sleep "$SLEEP_S"
  done
  GATE_FAILURES="${GATE_FAILURES#; }"
  return 1
}

# ---------------------------------------------------------------- state

current_version() { if [ -f "$STATE_DIR/current" ]; then cat "$STATE_DIR/current" || true; fi; }
record() { # record VERSION STATUS MIGRATIONS BACKUP
  [ "$DRY" = 1 ] && return 0
  mkdir -p "$STATE_DIR"
  printf '%s %s %s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "${3:--}" "${4:--}" >>"$STATE_DIR/history"
  # `held`: a failed release that keeps running because the schema advanced (no automatic downgrade).
  if [ "$2" = active ] || [ "$2" = held ]; then printf '%s\n' "$1" >"$STATE_DIR/current.tmp" && mv "$STATE_DIR/current.tmp" "$STATE_DIR/current"; fi
}
# The newest healthy version other than $1 that is still on disk.
previous_version() {
  [ -f "$STATE_DIR/history" ] || return 0
  awk -v cur="$1" '$3 == "active" && $2 != cur { v = $2 } END { print v }' "$STATE_DIR/history" | while read -r v; do
    [ -n "$v" ] && [ -f "$RELEASES_DIR/$v/manifest.json" ] && printf '%s' "$v"
  done
}
release_env_text() { # release_env_text RELDIR
  local rel="$1" commit
  commit="$(manifest_commit "$rel")"
  printf '# Written by remyral-ctl: the running release, images pinned by digest.\n'
  printf 'REMYRAL_VERSION=%s\n' "$(manifest_version "$rel")"
  printf 'REMYRAL_RELEASE_TAG=%s\n' "${commit:0:12}"
  printf 'REMYRAL_MASTER_IMAGE=%s\n' "$(image_ref "$rel" master)"
  printf 'REMYRAL_WEB_IMAGE=%s\n' "$(image_ref "$rel" web)"
  printf 'REMYRAL_BACKUP_IMAGE=%s\n' "$(image_ref "$rel" backup)"
  printf 'REMYRAL_PULL_POLICY=never\n'
}
write_file() { # write_file PATH MODE < content (atomic)
  if [ "$DRY" = 1 ]; then cat >/dev/null; return 0; fi
  cat >"$1.tmp"
  chmod "$2" "$1.tmp"
  mv "$1.tmp" "$1"
}
prune_releases() {
  [ "$DRY" = 1 ] && return 0
  local keep cur v n=0
  cur="$(current_version)"
  keep=" $cur $(previous_version "$cur") "
  # Newest first by directory time (a glob cannot sort by time); one entry per line, never word-split.
  while IFS= read -r v; do
    case "$v" in *.partial) rm -rf "${RELEASES_DIR:?}/$v"; continue ;; esac
    n=$((n + 1))
    case "$keep" in *" $v "*) continue ;; esac
    if [ "$n" -gt "$KEEP_RELEASES" ]; then rm -rf "${RELEASES_DIR:?}/$v"; note "pruned release $v"; fi
  done < <(ls -1t "$RELEASES_DIR" 2>/dev/null)
}
# Installs the verified release dir $1 as $RELEASES_DIR/<version> and remyral-ctl into $BIN_DIR.
install_release_files() {
  local rel="$1" v
  v="$(manifest_version "$rel")"
  run mkdir -p "$RELEASES_DIR/$v"
  if [ "$DRY" = 0 ]; then
    cp "$rel"/* "$RELEASES_DIR/$v/"
    chmod 0644 "$RELEASES_DIR/$v"/*
    chmod 0755 "$RELEASES_DIR/$v/remyral-ctl" "$RELEASES_DIR/$v"
  fi
  show "install -m 0755 $RELEASES_DIR/$v/remyral-ctl $BIN_DIR/remyral-ctl"
  if [ "$DRY" = 0 ]; then
    mkdir -p "$BIN_DIR"
    cp "$RELEASES_DIR/$v/remyral-ctl" "$BIN_DIR/remyral-ctl.tmp" && chmod 0755 "$BIN_DIR/remyral-ctl.tmp" &&
      mv "$BIN_DIR/remyral-ctl.tmp" "$BIN_DIR/remyral-ctl"
  fi
}
# Key rotation: a manifest verified by a trusted key may name the keys to trust from now on (never empty).
update_trust() {
  local rel="$1" keys k ok=''
  keys="$(json_array "$rel/manifest.json" trustedKeys)"
  [ -n "$keys" ] || return 0
  for k in $keys; do printf '%s' "$k" | grep -Eq "$B64U_KEY_RE" && ok="$ok$k
"; done
  [ -n "$ok" ] || return 0
  [ "$DRY" = 1 ] && return 0
  mkdir -p "$(dirname "$TRUST_FILE")"
  if [ -s "$TRUST_FILE" ] && [ "$(cat "$TRUST_FILE")" != "$(printf '%s' "$ok" | sed '/^$/d')" ]; then
    note "release keys changed by the signed manifest of $(manifest_version "$rel")"
  fi
  printf '%s' "$ok" | sed '/^$/d' | write_file "$TRUST_FILE" 0644
}
trust_csv() { trusted_keys | tr -s ' ' ',' | sed 's/^,//; s/,$//'; }

# ---------------------------------------------------------------- install

gen_secret() { openssl rand -hex 32; }
# env_put FILE KEY VALUE — replaces the first KEY= line (dropping later duplicates) or appends one. Values go through the
# environment, never through awk's -v (which would interpret backslashes).
env_put() {
  K="$2" V="$3" awk 'BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
    index($0, k "=") == 1 { if (!done) print k "=" v; done = 1; next } { print }
    END { if (!done) print k "=" v }' "$1" >"$1.tmp" && mv "$1.tmp" "$1"
}
# env_default FILE KEY VALUE — only when KEY is not in the file yet (an operator's own value stays).
env_default() { grep -q "^$2=" "$1" || env_put "$1" "$2" "$3"; }
# stack.env: created on the first install; a re-run (p17-host-actions) keeps every line it does not manage — SMTP,
# VAPID, backup and other settings an operator added, comments, order — and every existing value of the settings it
# only defaults (paths, release URL, update feed). It changes only what the install flags set (domain, TLS mode, e-mail,
# ports, bind address, registry, trusted proxies, --release-url, --no-update-check) and the trusted release keys.
write_stack_env() {
  local f="$STACK_ENV" t="$WORK/stack.env" pg owner app backup redis base explicit_url=0
  [ -n "$RELEASE_URL" ] && explicit_url=1
  base="$(release_base)"
  if [ -f "$f" ]; then
    cp "$f" "$t"
  else
    {
      printf '# Remyral control plane — written by remyral-ctl install. Root only (0600): it holds the database and\n'
      printf '# Redis passwords. Back it up with the secrets directory (docs/ops/selfhost-install.md, "Backups").\n'
      printf '# Lines you add are kept when remyral-ctl install runs again.\n'
    } >"$t"
  fi
  env_default "$t" REMYRAL_ENV prod
  env_put "$t" REMYRAL_DOMAIN "$DOMAIN"
  env_put "$t" REMYRAL_TLS_MODE "$TLS_MODE"
  [ -z "$ACME_EMAIL" ] || env_put "$t" REMYRAL_ACME_EMAIL "$ACME_EMAIL"
  env_default "$t" REMYRAL_SECRETS_DIR "$DATA_DIR/secrets"
  env_default "$t" REMYRAL_BACKUP_DIR "$DATA_DIR/backups"
  env_default "$t" REMYRAL_BACKUP_CONFIG_DIR "$DATA_DIR/backup-config"
  env_default "$t" REMYRAL_STACK_ENV_FILE "$f"
  env_default "$t" REMYRAL_UPDATE_DIR "$DATA_DIR/update"
  env_default "$t" REMYRAL_PROXY_DIR "$DATA_DIR/proxy"
  env_default "$t" REMYRAL_ACME_DIR "$DATA_DIR/letsencrypt"
  env_default "$t" REMYRAL_HOST_DIR "$HOST_DIR"
  env_default "$t" PROXY_NETWORK "$PROXY_NETWORK_NAME"
  [ -z "$HTTP_PORT" ] || env_put "$t" REMYRAL_HTTP_PORT "$HTTP_PORT"
  [ -z "$HTTPS_PORT" ] || env_put "$t" REMYRAL_HTTPS_PORT "$HTTPS_PORT"
  [ -z "$BIND_ADDR" ] || env_put "$t" REMYRAL_BIND_ADDRESS "$BIND_ADDR"
  [ -z "$REGISTRY" ] || env_put "$t" REMYRAL_REGISTRY "$REGISTRY"
  if [ -n "$base" ]; then
    if [ "$explicit_url" = 1 ]; then env_put "$t" REMYRAL_RELEASE_URL "$base"
    else env_default "$t" REMYRAL_RELEASE_URL "$base"
    fi
  fi
  if [ -n "$TRUSTED_PROXIES" ]; then
    env_put "$t" REMYRAL_TRUSTED_PROXIES "$(printf '%s' "$TRUSTED_PROXIES" | tr ' ' ',')"
    env_default "$t" TRUST_PROXY_HOPS 2
  fi
  if [ "$UPDATE_CHECK" = 0 ]; then env_put "$t" REMYRAL_UPDATE_CHECK off
  elif [ -n "$base" ]; then
    if [ "$explicit_url" = 1 ]; then env_put "$t" UPDATE_FEED_URL "$base/feed.json"
    else env_default "$t" UPDATE_FEED_URL "$base/feed.json"
    fi
  fi
  env_put "$t" CONTROL_PLANE_RELEASE_KEYS "$(trust_csv)"
  # Secrets: generated once, never printed, never replaced.
  if ! grep -q '^POSTGRES_SUPERUSER_PASSWORD=' "$t"; then printf '# Secrets (generated once; never printed).\n' >>"$t"; fi
  pg="$(env_value "$t" POSTGRES_SUPERUSER_PASSWORD)"; [ -n "$pg" ] || env_put "$t" POSTGRES_SUPERUSER_PASSWORD "$(gen_secret)"
  owner="$(env_value "$t" REMYRAL_DB_OWNER_PASSWORD)"; [ -n "$owner" ] || env_put "$t" REMYRAL_DB_OWNER_PASSWORD "$(gen_secret)"
  app="$(env_value "$t" REMYRAL_DB_APP_PASSWORD)"; [ -n "$app" ] || env_put "$t" REMYRAL_DB_APP_PASSWORD "$(gen_secret)"
  backup="$(env_value "$t" REMYRAL_DB_BACKUP_PASSWORD)"; [ -n "$backup" ] || env_put "$t" REMYRAL_DB_BACKUP_PASSWORD "$(gen_secret)"
  redis="$(env_value "$t" REDIS_PASSWORD)"; [ -n "$redis" ] || env_put "$t" REDIS_PASSWORD "$(gen_secret)"
  write_file "$f" 0600 <"$t"
  rm -f "$t"
}
# Key files for the master (uid 10001, 0400); generated only when absent.
write_secret_files() {
  local d="$DATA_DIR/secrets"
  if [ ! -f "$d/totp.key" ]; then
    show "openssl rand -base64 32 > $d/totp.key"
    [ "$DRY" = 0 ] && openssl rand -base64 32 >"$d/totp.key"
  else note "kept $d/totp.key"
  fi
  if [ ! -f "$d/lease-signing.pem" ]; then
    show "openssl genpkey -algorithm ed25519 -out $d/lease-signing.pem"
    [ "$DRY" = 0 ] && openssl genpkey -algorithm ed25519 -out "$d/lease-signing.pem" 2>/dev/null
  else note "kept $d/lease-signing.pem"
  fi
  if [ "$DRY" = 0 ]; then
    chmod 0400 "$d/totp.key" "$d/lease-signing.pem"
    chmod 0700 "$d"
    if [ "$(id -u)" = 0 ]; then chown -R 10001:10001 "$d"; fi
  fi
}
write_proxy_config() {
  local f="$DATA_DIR/proxy/traefik.yml" cidr
  # shellcheck disable=SC2016 # the backticks are literal: Traefik rule syntax and a command in a YAML comment
  {
    printf '# Written by remyral-ctl (TLS mode: %s). Change it with `remyral-ctl install --tls …` (re-run).\n' "$TLS_MODE"
    printf 'entryPoints:\n  http:\n    address: ":80"\n  https:\n    address: ":443"\n'
    if [ -n "$TRUSTED_PROXIES" ]; then
      printf '    forwardedHeaders:\n      trustedIPs:\n'
      for cidr in $TRUSTED_PROXIES; do printf '        - "%s"\n' "$cidr"; done
    fi
    if [ "$TLS_MODE" = letsencrypt ]; then
      printf '    http:\n      tls:\n        certResolver: le\n'
    fi
    printf 'providers:\n  docker:\n    exposedByDefault: false\n    network: %s\n' "$PROXY_NETWORK_NAME"
    printf '    constraints: "Label(`com.docker.compose.project`,`%s`)"\n' "$PROJECT"
    printf '  file:\n    directory: /etc/traefik/dynamic\n    watch: true\n'
    if [ "$TLS_MODE" = letsencrypt ]; then
      printf 'certificatesResolvers:\n  le:\n    acme:\n      email: "%s"\n' "$ACME_EMAIL"
      printf '      storage: /letsencrypt/acme.json\n      httpChallenge:\n        entryPoint: http\n'
    fi
    printf 'log:\n  level: WARN\n'
  } | write_file "$f" 0644
  if [ -n "$TLS_CERT" ]; then
    run cp "$TLS_CERT" "$DATA_DIR/proxy/certs/server.crt"
    run cp "$TLS_KEY" "$DATA_DIR/proxy/certs/server.key"
    [ "$DRY" = 0 ] && chmod 0644 "$DATA_DIR/proxy/certs/server.crt" && chmod 0600 "$DATA_DIR/proxy/certs/server.key"
    printf 'tls:\n  stores:\n    default:\n      defaultCertificate:\n        certFile: /etc/traefik/certs/server.crt\n        keyFile: /etc/traefik/certs/server.key\n' |
      write_file "$DATA_DIR/proxy/dynamic/tls.yml" 0644
  fi
}
install_update_timer() {
  if [ "$UPDATE_CHECK" = 0 ]; then return 0; fi
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d "$SYSTEMD_DIR" ]; then
    note "skip the daily update check timer (no systemd); run 'remyral-ctl upgrade --check' from cron instead"
    return 0
  fi
  printf '[Unit]\nDescription=Remyral: check for a newer signed control-plane release\n\n[Service]\nType=oneshot\nExecStart=%s/remyral-ctl upgrade --check --data-dir %s\n' "$BIN_DIR" "$DATA_DIR" |
    write_file "$SYSTEMD_DIR/remyral-update-check.service" 0644
  printf '[Unit]\nDescription=Daily Remyral update check\n\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=1d\nRandomizedDelaySec=1h\n\n[Install]\nWantedBy=timers.target\n' |
    write_file "$SYSTEMD_DIR/remyral-update-check.timer" 0644
  run systemctl daemon-reload
  run systemctl enable --now remyral-update-check.timer
}
validate_install_flags() {
  # A re-run keeps what the first run chose unless a flag says otherwise.
  [ -n "$DOMAIN" ] || DOMAIN="$(env_value "$STACK_ENV" REMYRAL_DOMAIN)"
  [ -n "$ACME_EMAIL" ] || ACME_EMAIL="$(env_value "$STACK_ENV" REMYRAL_ACME_EMAIL)"
  [ -n "$HTTP_PORT" ] || HTTP_PORT="$(env_value "$STACK_ENV" REMYRAL_HTTP_PORT)"
  [ -n "$HTTPS_PORT" ] || HTTPS_PORT="$(env_value "$STACK_ENV" REMYRAL_HTTPS_PORT)"
  [ -n "$BIND_ADDR" ] || BIND_ADDR="$(env_value "$STACK_ENV" REMYRAL_BIND_ADDRESS)"
  [ -n "$REGISTRY" ] || REGISTRY="$(env_value "$STACK_ENV" REMYRAL_REGISTRY)"
  [ -n "$TRUSTED_PROXIES" ] || TRUSTED_PROXIES="$(env_value "$STACK_ENV" REMYRAL_TRUSTED_PROXIES | tr ',' ' ')"
  if [ "$(env_value "$STACK_ENV" REMYRAL_UPDATE_CHECK)" = off ]; then UPDATE_CHECK=0; fi
  [ -n "$DOMAIN" ] || ask DOMAIN "Domain of the console (e.g. remyral.example.com)"
  [ -n "$DOMAIN" ] || die "--domain is required (the console's public name, e.g. remyral.example.com)"
  valid_domain "$DOMAIN" || die "--domain '$DOMAIN' is not a lower-case DNS name"
  [ -n "$TLS_MODE" ] || TLS_MODE="$(env_value "$STACK_ENV" REMYRAL_TLS_MODE)"
  [ -n "$TLS_MODE" ] || ask TLS_MODE "TLS mode: letsencrypt | cloudflare | proxy"
  case "$TLS_MODE" in
    letsencrypt)
      [ -n "$ACME_EMAIL" ] || ask ACME_EMAIL "E-mail for Let's Encrypt (expiry notices)"
      printf '%s' "$ACME_EMAIL" | grep -Eq '^[^@ "]+@[^@ "]+\.[^@ "]+$' || die "--email is required for --tls letsencrypt" ;;
    cloudflare | proxy) ;;
    '') die "--tls is required: letsencrypt (this host answers on 80/443), cloudflare (proxied DNS) or proxy (your own reverse proxy terminates TLS)" ;;
    *) die "--tls must be letsencrypt, cloudflare or proxy" ;;
  esac
  if [ -n "$TLS_CERT$TLS_KEY" ]; then
    if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then die "--tls-cert and --tls-key must both name existing files"; fi
    [ "$TLS_MODE" != letsencrypt ] || die "--tls-cert is for the cloudflare / proxy modes (Let's Encrypt issues its own)"
  fi
  local p
  for p in "$HTTP_PORT" "$HTTPS_PORT"; do
    [ -z "$p" ] || printf '%s' "$p" | grep -Eq '^[1-9][0-9]{0,4}$' || die "bad port '$p'"
  done
  if [ "$TLS_MODE" = letsencrypt ] && [ -n "$HTTP_PORT$HTTPS_PORT" ]; then
    die "--tls letsencrypt needs the standard ports 80 and 443 (the HTTP-01 challenge)"
  fi
  local c
  for c in $TRUSTED_PROXIES; do
    printf '%s' "$c" | grep -Eq '^[0-9a-fA-F.:]+(/[0-9]{1,3})?$' || die "--trusted-proxy '$c' is not an IP or CIDR"
  done
  if [ -n "$BACKUP_RECIPIENT" ]; then
    printf '%s' "$BACKUP_RECIPIENT" | grep -Eq '^age1[0-9a-z]{58}$' || die "--backup-recipient must be an age public key (age1…)"
  fi
}
issue_setup_token() { # prints the one-time token box (never stored in clear anywhere)
  local rel="$1" token
  token="$(dc "$rel" "$RELEASE_ENV" exec -T master remyral-master setup:token 2>/dev/null || true)"
  token="$(printf '%s' "$token" | grep -E '^rst_[a-z2-7]{32}$' | head -n 1 || true)"
  if [ -z "$token" ]; then
    warn "could not issue a setup token; run 'remyral-ctl setup-token' once the console is up"
    return 0
  fi
  out ''
  out '  ------------------------------------------------------------------------'
  out '  One-time setup token (shown only now; valid 24 hours, single use):'
  out ''
  out "      $token"
  out ''
  out "  Open $(console_url)/setup and create the owner account with it."
  out '  ------------------------------------------------------------------------'
}

cmd_install() {
  validate_install_flags
  out "remyral-ctl install → $DOMAIN (TLS: $TLS_MODE, data: $DATA_DIR)$([ "$DRY" = 1 ] && printf ' — DRY RUN, nothing is changed')"
  check_prereqs install
  lock
  new_work
  local cur v rel
  cur="$(current_version)"
  step "resolve the release"
  if [ -n "$BUNDLE_DIR" ]; then
    v="$WANT_VERSION"
    note "offline bundle $BUNDLE_DIR"
  else
    fetch_feed
    v="${WANT_VERSION:-$(feed_latest)}"
    feed_has "$v" || die "release $v is not in the signed $CHANNEL feed"
  fi
  rel="$WORK/release"
  step "download and verify the signed release ${v:-from the bundle}"
  fetch_release "$v" "$rel"
  v="$(manifest_version "$rel")"
  note "ok: remyral-control-plane $v signed by a trusted key; every file matches the manifest"
  if [ -n "$cur" ] && [ "$cur" != "$v" ]; then
    die "release $cur is installed; use 'remyral-ctl upgrade --to $v' (install only re-applies the same release)"
  fi

  step "create $DATA_DIR (0700) and its sub-directories"
  local d
  for d in "" secrets backups backup-config update proxy proxy/dynamic proxy/certs letsencrypt release state trust; do
    run mkdir -p "$DATA_DIR/$d"
  done
  if [ "$DRY" = 0 ]; then
    chmod 0700 "$DATA_DIR" "$DATA_DIR/backups" "$DATA_DIR/backup-config" "$DATA_DIR/letsencrypt" "$DATA_DIR/state"
    chmod 0755 "$DATA_DIR/update" "$DATA_DIR/proxy" "$DATA_DIR/proxy/dynamic" "$DATA_DIR/proxy/certs" "$DATA_DIR/trust"
  fi

  ensure_host_dir

  step "trust: record the release keys in $TRUST_FILE"
  if [ ! -s "$TRUST_FILE" ]; then trusted_keys | tr ' ' '\n' | sed '/^$/d' | write_file "$TRUST_FILE" 0644; fi
  update_trust "$rel"

  step "secrets: stack.env (0600) and key files (0400), generated once, never printed"
  write_stack_env
  write_secret_files
  if [ -n "$BACKUP_RECIPIENT" ]; then
    printf '%s\n' "$BACKUP_RECIPIENT" | write_file "$DATA_DIR/backup-config/recipients.txt" 0644
  fi

  step "proxy: Traefik configuration for TLS mode $TLS_MODE"
  write_proxy_config

  step "install release $v into $RELEASES_DIR/$v and remyral-ctl into $BIN_DIR"
  install_release_files "$rel"
  rel="$RELEASES_DIR/$v"
  [ "$DRY" = 1 ] && rel="$WORK/release"

  step "proxy network $PROXY_NETWORK_NAME"
  if docker network inspect "$PROXY_NETWORK_NAME" >/dev/null 2>&1; then note "exists"
  else
    show "docker network create $PROXY_NETWORK_NAME"
    [ "$DRY" = 1 ] || docker network create "$PROXY_NETWORK_NAME" >/dev/null
  fi

  step "pull the signed images by digest"
  local master web backup
  master="$(image_ref "$rel" master)"; web="$(image_ref "$rel" web)"; backup="$(image_ref "$rel" backup)"
  pull_image "$master"; pull_image "$web"; pull_image "$backup"
  release_env_text "$rel" | write_file "$RELEASE_ENV" 0644
  show "$(dc_show "$rel") pull --quiet postgres redis proxy"
  [ "$DRY" = 0 ] && { dc "$rel" "$RELEASE_ENV" pull --quiet postgres redis proxy || die "pull of postgres / redis / traefik failed"; }

  step "start the database, migrate, start the stack"
  show "$(dc_show "$rel") up -d --wait --wait-timeout 180 postgres redis"
  show "$(dc_show "$rel") run --rm --no-TTY migrate"
  show "$(dc_show "$rel") up -d --wait --wait-timeout 300 master web proxy backup"
  if [ "$DRY" = 0 ]; then
    dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 180 postgres redis || die "postgres / redis did not become healthy"
    dc "$rel" "$RELEASE_ENV" run --rm --no-TTY migrate || die "migrations failed (the database is unchanged up to the failing one)"
    dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 master web proxy backup || true
  fi

  step "health gate: master/web healthy, signed images, /api/status and the console through the proxy"
  if [ "$DRY" = 0 ]; then
    health_gate "$master" "$web" || die "the stack is not healthy: $GATE_FAILURES (logs: docker compose -p $PROJECT logs master web proxy)"
    note "ok"
    record "$v" active "$(db_head)" -
  fi

  step "update check"
  install_update_timer

  step "domain applier (the console's domain changes without a terminal)"
  install_applier_units
  [ "$DRY" = 1 ] || write_heartbeat

  step "owner account"
  if [ "$DRY" = 1 ]; then
    show "$(dc_show "$rel") exec -T master remyral-master setup:token   # when no account exists yet; printed once"
  else
    local n
    n="$(owners_count)"
    if [ "${n:-0}" = 0 ]; then
      if [ -z "$cur" ] || [ "$NEW_TOKEN" = 1 ]; then issue_setup_token "$rel"
      else note "no owner yet: 'remyral-ctl setup-token' prints a new one-time setup token"
      fi
    else
      note "an account exists already — sign in"
    fi
  fi
  out ''
  out "OK: Remyral $v runs at $(console_url)$([ "$DRY" = 1 ] && printf ' (dry run)')"
  out "    Next: open $(console_url)/setup (first owner) — the setup wizard guides the rest."
  out "    Keep $STACK_ENV and $DATA_DIR/secrets backed up off this host."
}

# ---------------------------------------------------------------- upgrade / rollback

write_update_cache() { # copies the verified feed for the master's "update available" banner
  [ "$DRY" = 1 ] && return 0
  [ -d "$DATA_DIR/update" ] || return 0
  cp "$WORK/feed.json" "$DATA_DIR/update/feed.json.tmp" && chmod 0644 "$DATA_DIR/update/feed.json.tmp" &&
    mv "$DATA_DIR/update/feed.json.tmp" "$DATA_DIR/update/feed.json"
  cp "$WORK/feed.sig.json" "$DATA_DIR/update/feed.sig.json.tmp" && chmod 0644 "$DATA_DIR/update/feed.sig.json.tmp" &&
    mv "$DATA_DIR/update/feed.sig.json.tmp" "$DATA_DIR/update/feed.sig.json"
}
# p17-update-channel (ADR-0065): copies the worker release feed, the newest worker release bundle and the version catalog
# for the master (a master without outbound internet still gets them). Data only: the master verifies every signature
# with its own keys. Best effort — an older release location without these files changes nothing.
cache_copy() { # cache_copy URL DEST MAXBYTES
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 --max-filesize "$3" -o "$2.tmp" "$1" 2>/dev/null || { rm -f "$2.tmp"; return 1; }
  chmod 0644 "$2.tmp" && mv "$2.tmp" "$2"
}
write_channel_cache() {
  [ "$DRY" = 1 ] && return 0
  [ -d "$DATA_DIR/update" ] || return 0
  local base dir path keep d
  base="$(release_base)"
  [ -n "$base" ] || return 0
  dir="$DATA_DIR/update/workers"
  mkdir -p "$dir" "$DATA_DIR/update/catalog" && chmod 0755 "$dir" "$DATA_DIR/update/catalog"
  if cache_copy "$base/workers/feed.json" "$dir/feed.json" 1048576 &&
    cache_copy "$base/workers/feed.sig.json" "$dir/feed.sig.json" 4096; then
    # The newest release's upload document (listed first); only that one is kept.
    path="$(sed -n 's/^ *"path": "\([0-9][0-9A-Za-z.+-]*\/release\.json\)",\{0,1\}$/\1/p' "$dir/feed.json" | head -n 1)"
    if [ -n "$path" ]; then
      keep="${path%/release.json}"
      if [ ! -f "$dir/$path" ]; then
        mkdir -p "$dir/$keep" && chmod 0755 "$dir/$keep"
        cache_copy "$base/workers/$path" "$dir/$path" 50331648 || rm -rf "${dir:?}/$keep"
      fi
      for d in "$dir"/*/; do
        [ -d "$d" ] || continue
        [ "$(basename "$d")" = "$keep" ] || rm -rf "$d"
      done
    fi
  fi
  # Best effort: the signature is copied only next to a copied catalog.
  if cache_copy "$base/catalog/catalog.json" "$DATA_DIR/update/catalog/catalog.json" 393216; then
    cache_copy "$base/catalog/catalog.sig.json" "$DATA_DIR/update/catalog/catalog.sig.json" 4096 || true
  fi
}
pre_upgrade_backup() { # sets BACKUP_ID
  BACKUP_ID=''
  local b r
  b="$(container_of backup)"
  if [ -z "$b" ]; then
    if [ "$SKIP_BACKUP" = 1 ]; then warn "no backup service running; continuing without a backup (--skip-backup)"; return 0; fi
    if [ -n "${STOPPED_MASTER:-}" ] && [ "$DRY" = 0 ]; then docker start "$STOPPED_MASTER" >/dev/null || true; fi
    die "the backup service is not running, so there would be no way back — start it ('remyral-ctl status') or pass --skip-backup deliberately"
  fi
  if [ "$SKIP_BACKUP" = 1 ]; then warn "pre-upgrade backup skipped (--skip-backup)"; return 0; fi
  show "docker exec $b remyral-backup run --reason pre-upgrade"
  [ "$DRY" = 1 ] && { BACKUP_ID='<backup id>'; return 0; }
  if ! r="$(docker exec "$b" remyral-backup run --reason pre-upgrade)"; then
    if [ -n "${STOPPED_MASTER:-}" ]; then docker start "$STOPPED_MASTER" >/dev/null || true; fi
    rm -f "$DATA_DIR/release.env.next"
    die "the pre-upgrade backup failed; nothing was changed (the master is started again)"
  fi
  BACKUP_ID="$(printf '%s\n' "$r" | sed -n 's/^ *"runId": "\([^"]*\)".*/\1/p' | head -n 1)"
  printf '%s' "$BACKUP_ID" | grep -Eq '^remana-[a-z]+-[0-9]{8}T[0-9]{6}Z$' || BACKUP_ID=''
  note "backup ${BACKUP_ID:-taken (id not reported)}"
}
cmd_upgrade() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR (remyral-ctl install first)"
  local cur v rel nextrel nextenv before after master web prev
  cur="$(current_version)"
  [ -n "$cur" ] || die "no current release recorded in $STATE_DIR (re-run remyral-ctl install)"
  new_work
  if [ -n "$BUNDLE_DIR" ]; then
    v="$WANT_VERSION"
  else
    fetch_feed
    write_update_cache
    write_channel_cache
    v="${WANT_VERSION:-$(feed_latest)}"
    feed_has "$v" || die "release $v is not in the signed feed"
  fi
  if [ "$CHECK_ONLY" = 1 ]; then
    # p17-domain-wizard: an installation upgraded by an older remyral-ctl gets the domain applier from the daily check.
    # p17-host-actions: an applier whose path unit predates the newer request kinds is rewritten too.
    if [ "$DRY" = 0 ] && { [ ! -f "$SYSTEMD_DIR/remyral-apply-pending.timer" ] ||
      ! grep -q "requests/upgrade.json" "$SYSTEMD_DIR/remyral-apply-pending.path" 2>/dev/null; }; then
      ensure_host_dir >/dev/null
      install_applier_units >/dev/null
    fi
    if [ -n "$v" ] && ver_gt "$v" "$cur"; then out "update available: $cur → $v ($(console_url "$(env_value "$STACK_ENV" REMYRAL_DOMAIN)"))"
    else out "up to date: $cur"
    fi
    return 0
  fi
  out "remyral-ctl upgrade $cur → ${v:-<bundle>}$([ "$DRY" = 1 ] && printf ' — DRY RUN, nothing is changed')"
  check_prereqs upgrade
  lock
  rel="$WORK/release"
  step "download and verify the signed release"
  fetch_release "$v" "$rel"
  v="$(manifest_version "$rel")"
  note "ok: $v signed by a trusted key; every file matches the manifest"
  [ "$v" != "$cur" ] || { out "already on $v"; return 0; }
  ver_gt "$v" "$cur" || die "$v is older than the installed $cur — use 'remyral-ctl rollback --to $v'"
  local minfrom
  minfrom="$(json_str "$rel/manifest.json" minUpgradeFrom)"
  if [ -n "$minfrom" ] && ver_gt "$minfrom" "$cur"; then
    die "$v can only be installed over $minfrom or newer; upgrade to $minfrom first"
  fi
  if print_breaking "$rel"; then confirm "Upgrade to $v despite the breaking changes above?"; fi
  note "workers need remyral-worker >= $(json_str "$rel/manifest.json" minWorkerVersion) (they update themselves from Ayarlar → Sürümler)"

  step "install release files into $RELEASES_DIR/$v"
  install_release_files "$rel"
  update_trust "$rel"
  set_env_value "$STACK_ENV" CONTROL_PLANE_RELEASE_KEYS "$(trust_csv)"
  ensure_host_dir
  install_applier_units
  nextrel="$RELEASES_DIR/$v"
  [ "$DRY" = 1 ] && nextrel="$rel"
  prev="$RELEASES_DIR/$cur"
  [ -f "$prev/manifest.json" ] || die "the installed release $cur is missing from $RELEASES_DIR"

  step "pull the signed images by digest"
  master="$(image_ref "$nextrel" master)"; web="$(image_ref "$nextrel" web)"
  pull_image "$master"; pull_image "$web"; pull_image "$(image_ref "$nextrel" backup)"
  nextenv="$DATA_DIR/release.env.next"
  release_env_text "$nextrel" | write_file "$nextenv" 0644
  show "$(dc_show "$nextrel" "$nextenv") pull --quiet postgres redis proxy"
  [ "$DRY" = 0 ] && { dc "$nextrel" "$nextenv" pull --quiet postgres redis proxy || die "pull of postgres / redis / traefik failed"; }

  step "maintenance: stop the master (nothing writes during backup and migration)"
  STOPPED_MASTER="$(container_of master)"
  show "docker stop --time 20 ${STOPPED_MASTER:-<master>}"
  if [ "$DRY" = 0 ] && [ -n "$STOPPED_MASTER" ]; then docker stop --time 20 "$STOPPED_MASTER" >/dev/null; fi

  step "pre-upgrade backup (blocks; a failed backup stops the upgrade)"
  pre_upgrade_backup
  before="$(db_head)"

  step "migrate (forward-only) with $v"
  show "$(dc_show "$nextrel" "$nextenv") run --rm --no-TTY migrate"
  local migrated=1
  if [ "$DRY" = 0 ]; then dc "$nextrel" "$nextenv" run --rm --no-TTY migrate || migrated=0; fi
  after="$(db_head)"

  step "start $v"
  show "$(dc_show "$nextrel" "$nextenv") up -d --wait --wait-timeout 300 --remove-orphans master web proxy backup"
  if [ "$DRY" = 0 ] && [ "$migrated" = 1 ]; then
    dc "$nextrel" "$nextenv" up -d --wait --wait-timeout 300 --remove-orphans master web proxy backup || true
  fi

  step "health gate"
  if [ "$DRY" = 1 ]; then
    out ''
    out "OK: would run $v (dry run). On a failed gate: the images roll back to $cur when the schema did not advance;"
    out "    otherwise the upgrade holds and prints 'remyral-ctl rollback --restore-backup <id>' (docs/ops/selfhost-install.md)."
    return 0
  fi
  if [ "$migrated" = 1 ] && health_gate "$master" "$web"; then
    mv "$nextenv" "$RELEASE_ENV"
    record "$v" active "$after" "$BACKUP_ID"
    prune_releases
    out ''
    out "OK: Remyral $v runs at $(console_url "$(env_value "$STACK_ENV" REMYRAL_DOMAIN)") (pre-upgrade backup ${BACKUP_ID:-none})"
    return 0
  fi
  [ "$migrated" = 1 ] || GATE_FAILURES="migrations failed"
  out ''
  out "UPGRADE FAILED: $GATE_FAILURES"
  if [ "$before" = "$after" ]; then
    record "$v" failed "$after" "$BACKUP_ID"
    rm -f "$nextenv"
    step "automatic rollback to $cur (the schema did not change)"
    dc "$prev" "$RELEASE_ENV" up -d --wait --wait-timeout 300 --remove-orphans master web proxy backup || true
    if health_gate "$(image_ref "$prev" master)" "$(image_ref "$prev" web)"; then
      die "rolled back to $cur (healthy); $v is recorded as failed"
    fi
    die "rolled back to $cur but it is STILL UNHEALTHY: $GATE_FAILURES"
  fi
  # Hold: the new release stays (an older master refuses the newer schema); record that honestly.
  mv "$nextenv" "$RELEASE_ENV"
  record "$v" held "$after" "$BACKUP_ID"
  die "NOT rolled back: the schema advanced $before → $after and $cur refuses a newer schema. Fix forward, or restore the pre-upgrade backup and roll back: remyral-ctl rollback --to $cur --restore-backup ${BACKUP_ID:-<id from 'docker exec <backup> remyral-backup list'>}"
}

restore_backup() { # restore_backup ID — docs/ops/backup-restore.md §4 (keeps the replaced database)
  local id="$1" pg stamp dump
  printf '%s' "$id" | grep -Eq '^remana-[a-z]+-[0-9]{8}T[0-9]{6}Z$' || die "--restore-backup '$id' is not a backup id (remana-<env>-YYYYMMDDTHHMMSSZ: backup ids keep their stem)"
  dump="$DATA_DIR/backups/db/$id.dump"
  [ "$DRY" = 1 ] || [ -f "$dump" ] || die "$dump does not exist (docker exec <backup> remyral-backup list)"
  pg="$(container_of postgres)"
  [ "$DRY" = 1 ] || [ -n "$pg" ] || die "postgres is not running"
  stamp="$(date -u +%Y%m%d%H%M%S)"
  run docker cp "$dump" "$pg:/tmp/restore.dump"
  run docker exec -u postgres "$pg" psql -U postgres -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS remyral_restore'
  run docker exec -u postgres "$pg" psql -U postgres -v ON_ERROR_STOP=1 -c 'CREATE DATABASE remyral_restore OWNER remyral_owner'
  run docker exec -u postgres "$pg" pg_restore -U postgres -d remyral_restore --exit-on-error /tmp/restore.dump
  run docker exec -u postgres "$pg" psql -U postgres -v ON_ERROR_STOP=1 \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'remyral' AND pid <> pg_backend_pid()" \
    -c "ALTER DATABASE remyral RENAME TO remyral_replaced_$stamp" \
    -c 'ALTER DATABASE remyral_restore RENAME TO remyral' \
    -c 'REVOKE ALL ON DATABASE remyral FROM PUBLIC' \
    -c 'GRANT CONNECT ON DATABASE remyral TO remyral_app, remyral_backup'
  run docker exec "$pg" rm -f /tmp/restore.dump
  note "the replaced database is kept as remyral_replaced_$stamp (drop it once you are satisfied)"
}
cmd_rollback() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  local cur target rel head need
  cur="$(current_version)"
  target="${WANT_VERSION:-$(previous_version "$cur")}"
  [ -n "$target" ] || die "no previous healthy release on this host (remyral-ctl status)"
  [ "$target" != "$cur" ] || die "$target is already the current release"
  rel="$RELEASES_DIR/$target"
  [ -f "$rel/manifest.json" ] || die "release $target is not on this host"
  new_work
  out "remyral-ctl rollback $cur → $target$([ "$DRY" = 1 ] && printf ' — DRY RUN, nothing is changed')"
  step "verify the stored release $target"
  verify_signed "$rel/manifest.json" "$rel/manifest.sig.json" "$RELEASE_CONTEXT"
  lock
  need="$(manifest_migrations "$rel")"
  head="$(db_head)"
  if [ -n "$RESTORE_BACKUP" ]; then
    confirm "Replace the live database with backup $RESTORE_BACKUP (the current one is kept renamed)?"
    step "stop master and backup"
    run dc "$rel" "$RELEASE_ENV" stop master backup
    step "restore backup $RESTORE_BACKUP"
    restore_backup "$RESTORE_BACKUP"
    head="$(db_head)"
  fi
  if [ "$DRY" = 0 ] && [ -n "$head" ] && [ "$head" \> "$need" ]; then
    die "the database schema $head is newer than $target expects ($need); it would refuse to start. Restore the pre-upgrade backup: remyral-ctl rollback --to $target --restore-backup <id>"
  fi
  step "roll out $target"
  release_env_text "$rel" | write_file "$RELEASE_ENV" 0644
  show "$(dc_show "$rel") up -d --wait --wait-timeout 300 --remove-orphans master web proxy backup"
  if [ "$DRY" = 0 ]; then
    dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 --remove-orphans master web proxy backup || true
    step "health gate"
    health_gate "$(image_ref "$rel" master)" "$(image_ref "$rel" web)" || die "$target is unhealthy: $GATE_FAILURES"
    record "$cur" rolled_back - -
    record "$target" active "$(db_head)" "${RESTORE_BACKUP:--}"
  fi
  out "OK: Remyral $target runs$([ "$DRY" = 1 ] && printf ' (dry run)')"
}

# ---------------------------------------------------------------- domain changes from the console (apply-pending)

# <data>/host: requests/ (the master, uid 10001, writes signed requests), status/ (root; the master reads it).
ensure_host_dir() {
  if [ "$DRY" = 1 ]; then
    show "mkdir -p $HOST_DIR/requests $HOST_DIR/status"
    return 0
  fi
  mkdir -p "$HOST_DIR/requests" "$HOST_DIR/status"
  chmod 0755 "$HOST_DIR" "$HOST_DIR/status"
  chmod 0700 "$HOST_DIR/requests"
  if [ "$(id -u)" = 0 ]; then
    chown 0:0 "$HOST_DIR" "$HOST_DIR/status"
    chown 10001:10001 "$HOST_DIR/requests"
  fi
  if [ -f "$STACK_ENV" ] && [ "$(env_value "$STACK_ENV" REMYRAL_HOST_DIR)" != "$HOST_DIR" ]; then
    set_env_value "$STACK_ENV" REMYRAL_HOST_DIR "$HOST_DIR"
  fi
}
install_applier_units() {
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d "$SYSTEMD_DIR" ]; then
    note "skip the domain applier units (no systemd); run 'remyral-ctl apply-pending' every minute from root's crontab instead"
    return 0
  fi
  local k paths
  paths="PathChanged=$HOST_DIR/requests/domain-change.json"
  for k in $HOST_REQUEST_KINDS; do paths="$paths
PathChanged=$HOST_DIR/requests/$k.json"; done
  # An upgrade (pull, backup, migrate, health gate) can take a while: 90 minutes before systemd stops the applier.
  printf '[Unit]\nDescription=Remyral: apply a request the console made (signed by the master)\n\n[Service]\nType=oneshot\nTimeoutStartSec=90min\nExecStart=%s/remyral-ctl apply-pending --data-dir %s\n' "$BIN_DIR" "$DATA_DIR" |
    write_file "$SYSTEMD_DIR/remyral-apply-pending.service" 0644
  printf '[Unit]\nDescription=Remyral: a request from the console (domain, update, rollback, backups)\n\n[Path]\n%s\nUnit=remyral-apply-pending.service\n\n[Install]\nWantedBy=paths.target\n' "$paths" |
    write_file "$SYSTEMD_DIR/remyral-apply-pending.path" 0644
  printf '[Unit]\nDescription=Remyral: domain applier heartbeat and pending requests (every minute)\n\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=1min\nAccuracySec=10s\nUnit=remyral-apply-pending.service\n\n[Install]\nWantedBy=timers.target\n' |
    write_file "$SYSTEMD_DIR/remyral-apply-pending.timer" 0644
  run systemctl daemon-reload
  run systemctl enable --now remyral-apply-pending.path remyral-apply-pending.timer
}
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# One line of plain text for a JSON string value: no quotes, backslashes or control characters, at most 400 bytes.
# shellcheck disable=SC1003 # '\\' is tr's escaped backslash (a set member), not an attempt to escape a quote
json_text() { printf '%s' "$1" | LC_ALL=C tr -d '\000-\037"\\' | cut -c1-400; }
# The host's global addresses (the master compares a new name's DNS answers with them).
host_addresses() {
  local a list
  list="${REMYRAL_CTL_ADDRESSES:-$( (hostname -I 2>/dev/null || true) | tr -s ' ' ' ')} $(env_value "$STACK_ENV" REMYRAL_PUBLIC_ADDRESS)"
  for a in $list; do
    printf '%s' "$a" | grep -Eq '^[0-9a-fA-F.:]{2,45}$' || continue
    case "$a" in 127.* | ::1 | fe80:* | FE80:* | 169.254.*) continue ;; esac
    printf '%s\n' "$a"
  done | head -n 16
}
write_heartbeat() {
  [ "$DRY" = 1 ] && return 0
  [ -d "$HOST_DIR/status" ] || return 0
  local a first=1 cur
  {
    printf '{\n  "kind": "remyral-host-applier/v1",\n  "version": "%s",\n  "at": "%s",\n' \
      "$(json_text "${REMYRAL_CTL_BUNDLE_VERSION:-source}")" "$(now_iso)"
    printf '  "domain": "%s",\n  "tls": "%s",\n  "acmeEmail": "%s",\n  "httpsPort": "%s",\n' \
      "$(json_text "$(env_value "$STACK_ENV" REMYRAL_DOMAIN)")" "$(json_text "$(env_value "$STACK_ENV" REMYRAL_TLS_MODE)")" \
      "$(json_text "$(env_value "$STACK_ENV" REMYRAL_ACME_EMAIL)")" "$(json_text "$(env_value "$STACK_ENV" REMYRAL_HTTPS_PORT)")"
    printf '  "addresses": ['
    for a in $(host_addresses); do
      if [ "$first" = 1 ]; then printf '"%s"' "$a"; first=0; else printf ', "%s"' "$a"; fi
    done
    printf '],\n'
    # p17-host-actions: what this applier accepts and what the console may roll back to (releases still on disk).
    # shellcheck disable=SC2086 # HOST_REQUEST_KINDS is a constant space-separated list, split on purpose
    printf '  "kinds": [%s],\n' "$(json_list domain-change $HOST_REQUEST_KINDS)"
    cur="$(current_version)"
    printf '  "current": "%s",\n' "$(json_text "$cur")"
    printf '  "previous": "%s",\n' "$(json_text "$(previous_version "$cur")")"
    # shellcheck disable=SC2046 # one version per line, each matched against VERSION_RE: split on purpose
    printf '  "releases": [%s]' "$(json_list $(local_releases))"
    host_heartbeat_extra
    printf '\n}\n'
  } | write_file "$HOST_DIR/status/applier.json" 0644
}
# json_list A B … → "A", "B" (values already validated to plain characters).
json_list() {
  local first=1 v
  for v in "$@"; do
    if [ "$first" = 1 ]; then printf '"%s"' "$(json_text "$v")"; first=0; else printf ', "%s"' "$(json_text "$v")"; fi
  done
}
# Versions of the releases kept on this host (newest first by directory time), each with its verified manifest.
local_releases() {
  local v
  while IFS= read -r v; do
    printf '%s' "$v" | grep -Eq "$VERSION_RE" || continue
    [ -f "$RELEASES_DIR/$v/manifest.json" ] && printf '%s\n' "$v"
  done < <(ls -1t "$RELEASES_DIR" 2>/dev/null) | head -n 8
}
# The backup settings this host applies (Ayarlar → Yedekler shows and edits them): stack.env, the recipients and where
# the off-site copy goes — never the off-site keys.
host_heartbeat_extra() {
  local k v first=1 r o=''
  printf ',\n  "backup": {\n'
  for k in BACKUP_TIME BACKUP_INTERVAL_MINUTES BACKUP_KEEP_DAILY BACKUP_KEEP_WEEKLY BACKUP_KEEP_MONTHLY \
    BACKUP_KEEP_RECENT_HOURS BACKUP_DRILL_ENABLED BACKUP_DRILL_WEEKDAY BACKUP_DRILL_TIME PG_WAL_ARCHIVE; do
    v="$(env_value "$STACK_ENV" "$k")"
    printf '    "%s": "%s",\n' "$k" "$(json_text "$v")"
  done
  printf '    "recipients": ['
  if [ -f "$DATA_DIR/backup-config/recipients.txt" ]; then
    for r in $(grep -E "$AGE_RECIPIENT_RE" "$DATA_DIR/backup-config/recipients.txt" | head -n 10); do
      if [ "$first" = 1 ]; then printf '"%s"' "$r"; first=0; else printf ', "%s"' "$r"; fi
    done
  fi
  printf '],\n'
  if [ -f "$DATA_DIR/backup-config/offsite.env" ]; then o="$(offsite_describe "$DATA_DIR/backup-config/offsite.env")"; fi
  printf '    "offsite": "%s"' "$(json_text "$o")"
  pending_heartbeat
  printf '\n  }'
}
# Where the off-site copy goes, without credentials: s3://<bucket>/<prefix>/ @ <host>.
offsite_describe() {
  local f="$1" b p e r
  b="$(env_value "$f" BACKUP_S3_BUCKET)"; p="$(env_value "$f" BACKUP_S3_PREFIX)"
  e="$(env_value "$f" BACKUP_S3_ENDPOINT)"; r="$(env_value "$f" BACKUP_S3_REGION)"
  [ -n "$b" ] || return 0
  e="${e#https://}"
  printf 's3://%s/%s/ @ %s' "$b" "${p:-remana}" "${e:-s3.$r.amazonaws.com}"
}
# write_result ID STATE DOMAIN DETAIL — what the console shows ("Uygulanıyor… / Hazır / Hata: …").
write_result() {
  [ "$DRY" = 1 ] && return 0
  mkdir -p "$HOST_DIR/status" "$STATE_DIR"
  printf '{\n  "kind": "remyral-host-domain-result/v1",\n  "id": "%s",\n  "state": "%s",\n  "domain": "%s",\n  "detail": "%s",\n  "at": "%s"\n}\n' \
    "$(json_text "$1")" "$2" "$(json_text "$3")" "$(json_text "$4")" "$(now_iso)" |
    write_file "$HOST_DIR/status/domain-result.json" 0644
  printf '%s %s %s %s\n' "$(now_iso)" "$2" "${3:--}" "${1:--}" >>"$STATE_DIR/domain-history"
  case "$2" in
    applying) note "domain change ${3}: applying" ;;
    applied) note "domain change ${3}: applied — $4" ;;
    *) warn "domain change ${3:-?}: $2 — $4" ;;
  esac
}
# verify_master_signed FILE SIGFILE [CONTEXT] — Ed25519 over "CONTEXT\n" ‖ FILE by the master's lease-signing key (its public
# half, derived from <data>/secrets/lease-signing.pem — the only key a request may be signed with).
verify_master_signed() {
  local key="$DATA_DIR/secrets/lease-signing.pem" value
  [ -f "$key" ] || return 1
  openssl pkey -in "$key" -pubout -out "$WORK/master.pub.pem" 2>/dev/null || return 1
  value="$(sed -n 's/.*"signature": *"\([A-Za-z0-9_-]*\)".*/\1/p' "$2" | head -n 1)"
  [ -n "$value" ] || return 1
  b64u_to_file "$value" "$WORK/request.sig.bin" 2>/dev/null || return 1
  { printf '%s\n' "${3:-$DOMAIN_CHANGE_CONTEXT}"; cat "$1"; } >"$WORK/request.signed.bin"
  openssl pkeyutl -verify -pubin -inkey "$WORK/master.pub.pem" -rawin -in "$WORK/request.signed.bin" \
    -sigfile "$WORK/request.sig.bin" >/dev/null 2>&1
}
# The compose project name Traefik knows the services under (REMYRAL_PROJECT, else the default).
route_prefix() {
  local p
  p="$(env_value "$STACK_ENV" REMYRAL_PROJECT)"
  printf '%s' "${p:-$PROJECT}"
}
# The previous name keeps answering (Traefik file provider → the same services as the compose labels).
write_alias_routes() {
  local d="$1" p f="$DATA_DIR/proxy/dynamic/domain-previous.yml"
  p="$(route_prefix)"
  # shellcheck disable=SC2016 # the backticks are literal: Traefik rule syntax (Host(`…`)) and a command in a comment
  {
    printf '# Written by remyral-ctl apply-pending: the previous console name %s keeps answering after a domain change\n' "$d"
    printf '# (removed automatically; see `remyral-ctl status`). Same routes as the compose labels of master and web.\n'
    printf 'http:\n  routers:\n'
    printf '    remyral-previous-api:\n      rule: "Host(`%s`) && (Path(`/api`) || PathPrefix(`/api/`))"\n' "$d"
    printf '      entryPoints: [https]\n      tls: {}\n      priority: 100\n      middlewares: [%s-api-strip@docker]\n      service: %s-master@docker\n' "$p" "$p"
    printf '    remyral-previous-hooks:\n      rule: "Host(`%s`) && PathPrefix(`/v1/hooks/`)"\n' "$d"
    printf '      entryPoints: [https]\n      tls: {}\n      priority: 100\n      service: %s-master@docker\n' "$p"
    printf '    remyral-previous-worker:\n      rule: "Host(`%s`) && (Path(`/v1/worker`) || PathPrefix(`/v1/worker/releases/`) || PathPrefix(`/v1/worker/install/`) || Path(`/v1/worker/lease-keys`))"\n' "$d"
    printf '      entryPoints: [https]\n      tls: {}\n      priority: 100\n      service: %s-master@docker\n' "$p"
    printf '    remyral-previous-blocked:\n      rule: "Host(`%s`) && (Path(`/api/healthz`) || Path(`/api/readyz`) || Path(`/api/v1/worker`) || PathPrefix(`/api/v1/worker/`) || PathPrefix(`/api/forward-auth/`) || Path(`/api/coolify-sso/callback`) || PathPrefix(`/api/v1/hooks/`))"\n' "$d"
    printf '      entryPoints: [https]\n      tls: {}\n      priority: 200\n      service: %s-web@docker\n' "$p"
    printf '    remyral-previous-web:\n      rule: "Host(`%s`)"\n      entryPoints: [https]\n      tls: {}\n      priority: 1\n      service: %s-web@docker\n' "$d" "$p"
    printf '    remyral-previous-http:\n      rule: "Host(`%s`)"\n      entryPoints: [http]\n      middlewares: [%s-to-https@docker]\n      service: %s-web@docker\n' "$d" "$p" "$p"
  } | write_file "$f" 0644
}
remove_alias_routes() {
  rm -f "$DATA_DIR/proxy/dynamic/domain-previous.yml" "$STATE_DIR/domain-alias"
}
expire_domain_alias() {
  [ -f "$STATE_DIR/domain-alias" ] || return 0
  local d until
  read -r d until <"$STATE_DIR/domain-alias" || true
  printf '%s' "${until:-}" | grep -Eq '^[0-9]+$' || until=0
  if [ "$(date +%s)" -ge "$until" ]; then
    remove_alias_routes
    note "the previous console name ${d:-?} no longer answers"
  fi
}
# Health on the NEW name: master/web healthy, /api/status ok and the console through the proxy; with Let's Encrypt
# also a certificate the system trusts (curl without -k).
domain_gate() { # domain_gate DOMAIN TLS_MODE
  local d="$1" tls="$2" i port bind status root
  port="$(env_value "$STACK_ENV" REMYRAL_HTTPS_PORT)"; port="${port:-443}"
  bind="$(env_value "$STACK_ENV" REMYRAL_BIND_ADDRESS)"
  case "$bind" in '' | 0.0.0.0 | '::') bind=127.0.0.1 ;; esac
  i=0
  while [ "$i" -lt "$DOMAIN_GATE_TRIES" ]; do
    i=$((i + 1))
    GATE_FAILURES=''
    [ "$(health_of master)" = healthy ] || GATE_FAILURES="$GATE_FAILURES; master is $(health_of master)"
    [ "$(health_of web)" = healthy ] || GATE_FAILURES="$GATE_FAILURES; web is $(health_of web)"
    status="$(curl -sk --max-time 10 --resolve "$d:$port:$bind" "https://$d:$port/api/status" 2>/dev/null || true)"
    printf '%s' "$status" | grep -q '"status": *"ok"' || GATE_FAILURES="$GATE_FAILURES; https://$d/api/status is not ok"
    root="$(curl -sk --max-time 10 --resolve "$d:$port:$bind" "https://$d:$port/" 2>/dev/null || true)"
    printf '%s' "$root" | grep -q 'id="root"' || GATE_FAILURES="$GATE_FAILURES; https://$d/ does not serve the console"
    if [ "$tls" = letsencrypt ] &&
      ! curl -s -o /dev/null --max-time 10 --resolve "$d:$port:$bind" "https://$d:$port/api/status" >/dev/null 2>&1; then
      GATE_FAILURES="$GATE_FAILURES; no trusted certificate for $d yet (Let's Encrypt needs DNS pointing here and port 80 open)"
    fi
    if [ -z "$GATE_FAILURES" ]; then return 0; fi
    [ "$i" -lt "$DOMAIN_GATE_TRIES" ] && sleep "$SLEEP_S"
  done
  GATE_FAILURES="${GATE_FAILURES#; }"
  return 1
}
# Switches the console to DOMAIN (TLS mode, ACME e-mail) with the old name answering meanwhile; rolls back when the
# new name is not healthy in time.
apply_domain_change() { # apply_domain_change ID DOMAIN TLS EMAIL
  local id="$1" new="$2" tls="$3" email="$4" old old_tls old_email rel proxy_changed=0 failures
  old="$(env_value "$STACK_ENV" REMYRAL_DOMAIN)"
  old_tls="$(env_value "$STACK_ENV" REMYRAL_TLS_MODE)"
  old_email="$(env_value "$STACK_ENV" REMYRAL_ACME_EMAIL)"
  rel="$RELEASES_DIR/$(current_version)"
  if [ ! -f "$rel/compose.yaml" ]; then
    write_result "$id" failed "$new" "the installed release is missing from $RELEASES_DIR; nothing was changed"
    return 0
  fi
  write_result "$id" applying "$new" "switching from $old"
  mkdir -p "$STATE_DIR"
  cp -p "$STACK_ENV" "$STATE_DIR/stack.env.domain-prev"
  cp -p "$DATA_DIR/proxy/traefik.yml" "$STATE_DIR/traefik.yml.domain-prev"
  write_alias_routes "$old"
  set_env_value "$STACK_ENV" REMYRAL_DOMAIN "$new"
  set_env_value "$STACK_ENV" REMYRAL_TLS_MODE "$tls"
  [ -z "$email" ] || set_env_value "$STACK_ENV" REMYRAL_ACME_EMAIL "$email"
  if [ "$tls" != "$old_tls" ] || { [ -n "$email" ] && [ "$email" != "$old_email" ]; }; then
    TLS_MODE="$tls"
    ACME_EMAIL="${email:-$old_email}"
    TRUSTED_PROXIES="$(env_value "$STACK_ENV" REMYRAL_TRUSTED_PROXIES | tr ',' ' ')"
    TLS_CERT=''
    write_proxy_config
    proxy_changed=1
  fi
  dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 master web >/dev/null 2>&1 || true
  if [ "$proxy_changed" = 1 ]; then
    dc "$rel" "$RELEASE_ENV" up -d --force-recreate proxy >/dev/null 2>&1 || true
  fi
  if domain_gate "$new" "$tls"; then
    printf '%s %s\n' "$old" "$(($(date +%s) + ALIAS_GRACE_S))" >"$STATE_DIR/domain-alias"
    rm -f "$STATE_DIR/stack.env.domain-prev" "$STATE_DIR/traefik.yml.domain-prev"
    write_result "$id" applied "$new" "the console answers at $(console_url "$new"); $old keeps answering for $((ALIAS_GRACE_S / 60)) minutes"
    return 0
  fi
  failures="$GATE_FAILURES"
  # Roll back: the previous stack.env and proxy configuration, the old labels, no alias.
  cp -p "$STATE_DIR/stack.env.domain-prev" "$STACK_ENV"
  cp -p "$STATE_DIR/traefik.yml.domain-prev" "$DATA_DIR/proxy/traefik.yml"
  remove_alias_routes
  dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 master web >/dev/null 2>&1 || true
  if [ "$proxy_changed" = 1 ]; then
    dc "$rel" "$RELEASE_ENV" up -d --force-recreate proxy >/dev/null 2>&1 || true
  fi
  rm -f "$STATE_DIR/stack.env.domain-prev" "$STATE_DIR/traefik.yml.domain-prev"
  if domain_gate "$old" "$old_tls"; then
    write_result "$id" rolled_back "$new" "$new did not become healthy in time ($failures); the console is back on $old"
  else
    write_result "$id" failed "$new" "$new did not become healthy ($failures) and $old is not healthy after the rollback either ($GATE_FAILURES); see remyral-ctl status"
  fi
}
# Reads, verifies and consumes the request in <data>/host/requests, then applies it.
apply_request() {
  local req="$HOST_DIR/requests/domain-change.json" sig="$HOST_DIR/requests/domain-change.sig.json"
  local kind id nonce domain tls email prev created expires cur port
  if [ -L "$req" ] || [ ! -f "$req" ] || [ -L "$sig" ] || [ ! -f "$sig" ]; then
    rm -f "$req" "$sig"
    write_result '' refused '' 'the request or its signature is not a regular file'
    return 0
  fi
  head -c 8192 "$req" >"$WORK/request.json"
  head -c 4096 "$sig" >"$WORK/request.sig.json"
  rm -f "$req" "$sig"
  if ! verify_master_signed "$WORK/request.json" "$WORK/request.sig.json"; then
    write_result '' refused '' 'signature check failed: the request is not signed by the master of this installation'
    return 0
  fi
  kind="$(json_str "$WORK/request.json" kind)"
  id="$(json_str "$WORK/request.json" id)"
  printf '%s' "$id" | grep -Eq "$UUID_RE" || id=''
  if [ "$kind" != "$DOMAIN_CHANGE_CONTEXT" ] || [ -z "$id" ]; then
    write_result "$id" refused '' 'not a domain change request'
    return 0
  fi
  nonce="$(json_str "$WORK/request.json" nonce)"
  domain="$(json_str "$WORK/request.json" domain)"
  tls="$(json_str "$WORK/request.json" tls)"
  email="$(json_str "$WORK/request.json" email)"
  prev="$(json_str "$WORK/request.json" previousDomain)"
  created="$(json_str "$WORK/request.json" createdAt)"
  expires="$(json_str "$WORK/request.json" expiresAt)"
  printf '%s' "$nonce" | grep -Eq '^[0-9a-f]{32}$' || { write_result "$id" refused '' 'malformed nonce'; return 0; }
  valid_domain "$domain" || { write_result "$id" refused '' 'the domain is not a lower-case DNS name'; return 0; }
  case "$tls" in letsencrypt | cloudflare | proxy) ;; *) write_result "$id" refused "$domain" 'unknown TLS mode'; return 0 ;; esac
  [ -z "$email" ] || printf '%s' "$email" | grep -Eq "$EMAIL_RE" || { write_result "$id" refused "$domain" 'malformed e-mail'; return 0; }
  if ! { printf '%s' "$created" | grep -Eq "$ISO_RE" && printf '%s' "$expires" | grep -Eq "$ISO_RE"; }; then
    write_result "$id" refused "$domain" 'malformed time'
    return 0
  fi
  if [ ! "$(now_iso)" \< "$expires" ]; then
    write_result "$id" refused "$domain" "the request expired at $expires"
    return 0
  fi
  mkdir -p "$STATE_DIR"
  if [ -f "$STATE_DIR/domain-nonces" ] && grep -qx "$nonce" "$STATE_DIR/domain-nonces"; then
    write_result "$id" refused "$domain" 'this request was already used (replay)'
    return 0
  fi
  printf '%s\n' "$nonce" >>"$STATE_DIR/domain-nonces"
  tail -n 500 "$STATE_DIR/domain-nonces" >"$STATE_DIR/domain-nonces.tmp" && mv "$STATE_DIR/domain-nonces.tmp" "$STATE_DIR/domain-nonces"
  cur="$(env_value "$STACK_ENV" REMYRAL_DOMAIN)"
  if [ "$prev" != "$cur" ]; then
    write_result "$id" refused "$domain" "the request was made for $(json_text "$prev") but this host serves $cur"
    return 0
  fi
  if [ "$tls" = letsencrypt ]; then
    port="$(env_value "$STACK_ENV" REMYRAL_HTTP_PORT)$(env_value "$STACK_ENV" REMYRAL_HTTPS_PORT)"
    if [ -n "$port" ] && [ "$port" != 80443 ]; then
      write_result "$id" refused "$domain" "Let's Encrypt needs the standard ports 80 and 443"
      return 0
    fi
    if [ -z "$email" ] && [ -z "$(env_value "$STACK_ENV" REMYRAL_ACME_EMAIL)" ]; then
      write_result "$id" refused "$domain" "Let's Encrypt needs an e-mail address"
      return 0
    fi
  fi
  if [ "$domain" = "$cur" ] && [ "$tls" = "$(env_value "$STACK_ENV" REMYRAL_TLS_MODE)" ] &&
    { [ -z "$email" ] || [ "$email" = "$(env_value "$STACK_ENV" REMYRAL_ACME_EMAIL)" ]; }; then
    write_result "$id" applied "$domain" 'nothing to change'
    return 0
  fi
  apply_domain_change "$id" "$domain" "$tls" "$email"
}
cmd_apply_pending() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  [ "$DRY" = 0 ] || die "apply-pending has no dry run (it only acts on a signed request from the master)"
  [ -d "$HOST_DIR/status" ] || ensure_host_dir
  new_work
  write_heartbeat
  local req="$HOST_DIR/requests/domain-change.json" k
  if [ -e "$req" ] || [ -L "$req" ]; then
    if [ "${LOCKED:-0}" = 1 ] || mkdir "$DATA_DIR/.lock" 2>/dev/null; then
      LOCKED=1
      apply_request
    else
      note "another remyral-ctl is running; the domain change request waits for the next run"
    fi
  fi
  # p17-host-actions: the other kinds, one after the other (a fixed order; each is consumed before it runs).
  for k in $HOST_REQUEST_KINDS; do
    req="$HOST_DIR/requests/$k.json"
    if [ -e "$req" ] || [ -L "$req" ]; then
      if [ "${LOCKED:-0}" = 1 ] || mkdir "$DATA_DIR/.lock" 2>/dev/null; then
        LOCKED=1
        apply_host_request "$k"
        write_heartbeat
      else
        note "another remyral-ctl is running; the $k request waits for the next run"
      fi
    fi
  done
  # p17-panel-settings Part 0: a recipient / off-site change whose host time lock ran out takes effect now.
  if pending_due recipients || pending_due offsite; then
    if [ "${LOCKED:-0}" = 1 ] || mkdir "$DATA_DIR/.lock" 2>/dev/null; then
      LOCKED=1
      apply_due_backup_changes
    else
      note "another remyral-ctl is running; the due backup change waits for the next run"
    fi
  fi
  expire_domain_alias
  write_heartbeat
}

# ---------------------------------------------------------------- other console requests (p17-host-actions)
#
# The same machinery as the domain change, generalised (ADR-0063 amendment 2026-10-26): the master writes
# <data>/host/requests/<kind>.json + <kind>.sig.json, signed with its lease-signing key under `remyral-host-<kind>/v1`.
# The request is flat JSON of string values, one per line, with exactly the fields of its kind; the applier refuses
# anything else before reading a value, consumes the files, checks the time window and the nonce, re-validates every
# value with a fixed expression and then runs only its own code path for that kind (for upgrade / rollback: this very
# script as a child, under the lock this run holds). Results: <data>/host/status/<kind>-result.json (state, the current
# step, a short detail and the tail of the output without lines that name a secret).

host_context() { printf 'remyral-host-%s/v1' "$1"; }
# The fields of a kind besides the common ones (kind, id, nonce, createdAt, expiresAt).
host_fields() {
  case "$1" in
    upgrade) printf 'version fromVersion acceptBreaking' ;;
    rollback) printf 'version fromVersion backupId restoreDatabase' ;;
    backup-run) printf 'reason' ;;
    backup-drill) printf 'backupId' ;;
    backup-restore) printf 'backupId restoreDatabase' ;;
    backup-config)
      printf 'time intervalMinutes keepDaily keepWeekly keepMonthly keepRecentHours drillEnabled drillWeekday drillTime walArchive recipients'
      ;;
    backup-offsite) printf 'mode endpoint region bucket prefix pathStyle accessKeyId secretAccessKey' ;;
    backup-change-cancel) printf 'change' ;;
    *) return 1 ;;
  esac
}
# Seconds since the epoch of `YYYY-MM-DDTHH:MM:SSZ` (GNU date, else BSD date); empty when neither parses it.
iso_epoch() {
  date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null || true
}
# 0 when FILE is `{`, lines `  "key": "value",` with only the fields of KIND (each exactly once), `}`.
request_shape_ok() { # FILE KIND
  local f="$1" allowed line key seen=' ' fields
  fields="$(host_fields "$2")" || return 1
  allowed=" kind id nonce createdAt expiresAt $fields "
  [ "$(head -n 1 "$f")" = '{' ] && [ "$(tail -n 1 "$f")" = '}' ] || return 1
  while IFS= read -r line; do
    case "$line" in '{' | '}') continue ;; esac
    # (no `{0,1200}`: BSD grep caps repetition counts at 255; the length is checked on its own)
    [ "${#line}" -le 1300 ] || return 1
    printf '%s\n' "$line" | LC_ALL=C grep -Eq '^  "[A-Za-z]{1,32}": "[^"\\[:cntrl:]]*",?$' || return 1
    key="${line#  \"}"
    key="${key%%\"*}"
    case "$allowed" in *" $key "*) ;; *) return 1 ;; esac
    case "$seen" in *" $key "*) return 1 ;; esac
    seen="$seen$key "
  done <"$f"
  for key in $allowed; do
    case "$seen" in *" $key "*) ;; *) return 1 ;; esac
  done
}
# Output lines that may go into the status file: no line naming a password, secret, token or key value.
log_tail() { # LOGFILE
  [ -f "$1" ] || return 0
  LC_ALL=C grep -viE '(password|passwd|secret|token|access_key|accesskey|private|credential)[A-Za-z_]*[=:]' "$1" |
    tail -n 40 || true
}
# write_host_result KIND ID STATE STEP DETAIL [LOGFILE] — what the console shows while and after a request runs.
write_host_result() {
  [ "$DRY" = 1 ] && return 0
  local kind="$1" id="$2" state="$3" step="$4" detail="$5" log="${6:-}" first=1 l
  mkdir -p "$HOST_DIR/status" "$STATE_DIR"
  {
    printf '{\n  "kind": "%s",\n  "request": "%s",\n  "id": "%s",\n  "state": "%s",\n' \
      "$HOST_RESULT_KIND" "$kind" "$(json_text "$id")" "$state"
    printf '  "step": "%s",\n  "detail": "%s",\n  "at": "%s",\n  "log": [' \
      "$(json_text "$step")" "$(json_text "$detail")" "$(now_iso)"
    if [ -n "$log" ]; then
      while IFS= read -r l; do
        l="$(json_text "$(printf '%s' "$l" | LC_ALL=C sed 's/\x1b\[[0-9;]*[A-Za-z]//g')")"
        if [ "$first" = 1 ]; then printf '\n    "%s"' "$l"; first=0; else printf ',\n    "%s"' "$l"; fi
      done < <(log_tail "$log")
      [ "$first" = 1 ] || printf '\n  '
    fi
    printf ']\n}\n'
  } | write_file "$HOST_DIR/status/$kind-result.json" 0644
  case "$state" in
    applying) ;;
    *) printf '%s %s %s %s\n' "$(now_iso)" "$kind" "$state" "${id:--}" >>"$STATE_DIR/host-history" ;;
  esac
  case "$state" in
    applying | applied) note "$kind ${id:-?}: $state${step:+ — $step}" ;;
    *) warn "$kind ${id:-?}: $state — $detail" ;;
  esac
}
# Runs this script for a request (the existing code path of `upgrade` / `rollback` / `restore`) under the lock this run
# holds, streaming its output into LOGFILE and the step into the result file. Sets CHILD_RC and CHILD_STEP.
CHILD_RC=0
CHILD_STEP=''
run_host_child() { # KIND ID LOGFILE ARGS…
  local kind="$1" id="$2" log="$3" self line
  shift 3
  self="$BIN_DIR/remyral-ctl"
  [ -f "$self" ] || self="$0"
  : >"$log"
  chmod 0600 "$log"
  CHILD_RC=0
  CHILD_STEP='starting'
  while IFS= read -r line; do
    case "$line" in
      '__remyral_ctl_exit '*)
        CHILD_RC="${line#__remyral_ctl_exit }"
        continue
        ;;
    esac
    printf '%s\n' "$line" >>"$log"
    case "$line" in
      '['*']'*)
        CHILD_STEP="$(printf '%s' "$line" | sed 's/^\[ *[0-9]*\] //')"
        write_host_result "$kind" "$id" applying "$CHILD_STEP" '' "$log"
        write_heartbeat
        ;;
    esac
  done < <(
    rc=0
    REMYRAL_CTL_LOCK_INHERITED=1 bash "$self" "$@" --data-dir "$DATA_DIR" </dev/null 2>&1 || rc=$?
    printf '__remyral_ctl_exit %s\n' "$rc"
  )
}
# The last `remyral-ctl: …` line of a child's output (why it stopped).
child_reason() { sed -n 's/^remyral-ctl: //p' "$1" | tail -n 1; }

# Reads, verifies and consumes the request of KIND, then hands it to its handler.
apply_host_request() { # KIND
  local kind="$1" req="$HOST_DIR/requests/$1.json" sig="$HOST_DIR/requests/$1.sig.json" ctx id nonce created expires
  local c e n
  ctx="$(host_context "$kind")"
  if [ -L "$req" ] || [ ! -f "$req" ] || [ -L "$sig" ] || [ ! -f "$sig" ]; then
    rm -f "$req" "$sig"
    write_host_result "$kind" '' refused '' 'the request or its signature is not a regular file'
    return 0
  fi
  head -c 8192 "$req" >"$WORK/request.json"
  head -c 4096 "$sig" >"$WORK/request.sig.json"
  rm -f "$req" "$sig"
  if ! verify_master_signed "$WORK/request.json" "$WORK/request.sig.json" "$ctx"; then
    write_host_result "$kind" '' refused '' 'signature check failed: the request is not signed by the master of this installation'
    return 0
  fi
  id="$(json_str "$WORK/request.json" id)"
  printf '%s' "$id" | grep -Eq "$UUID_RE" || id=''
  if ! request_shape_ok "$WORK/request.json" "$kind" || [ "$(json_str "$WORK/request.json" kind)" != "$ctx" ] || [ -z "$id" ]; then
    write_host_result "$kind" "$id" refused '' "not a $kind request: only its own fields, as plain text values, are accepted"
    return 0
  fi
  nonce="$(json_str "$WORK/request.json" nonce)"
  created="$(json_str "$WORK/request.json" createdAt)"
  expires="$(json_str "$WORK/request.json" expiresAt)"
  printf '%s' "$nonce" | grep -Eq '^[0-9a-f]{32}$' || { write_host_result "$kind" "$id" refused '' 'malformed nonce'; return 0; }
  if ! { printf '%s' "$created" | grep -Eq "$ISO_RE" && printf '%s' "$expires" | grep -Eq "$ISO_RE"; }; then
    write_host_result "$kind" "$id" refused '' 'malformed time'
    return 0
  fi
  if [ ! "$(now_iso)" \< "$expires" ]; then
    write_host_result "$kind" "$id" refused '' "the request expired at $expires"
    return 0
  fi
  # A request is valid for at most an hour and cannot be dated ahead (5 minutes of clock skew).
  c="$(iso_epoch "$created")"; e="$(iso_epoch "$expires")"; n="$(date -u +%s)"
  if [ -z "$c" ] || [ -z "$e" ] || [ "$e" -le "$c" ] || [ $((e - c)) -gt 3600 ] || [ "$c" -gt $((n + 300)) ]; then
    write_host_result "$kind" "$id" refused '' 'the validity window of the request is outside the rules (at most one hour, not in the future)'
    return 0
  fi
  mkdir -p "$STATE_DIR"
  if [ -f "$STATE_DIR/host-nonces" ] && grep -qx "$nonce" "$STATE_DIR/host-nonces"; then
    write_host_result "$kind" "$id" refused '' 'this request was already used (replay)'
    return 0
  fi
  printf '%s\n' "$nonce" >>"$STATE_DIR/host-nonces"
  tail -n 5000 "$STATE_DIR/host-nonces" >"$STATE_DIR/host-nonces.tmp" && mv "$STATE_DIR/host-nonces.tmp" "$STATE_DIR/host-nonces"
  case "$kind" in
    upgrade) host_upgrade "$id" ;;
    rollback) host_rollback "$id" ;;
    backup-run) host_backup_run "$id" ;;
    backup-drill) host_backup_drill "$id" ;;
    backup-restore) host_backup_restore "$id" ;;
    backup-config) host_backup_config "$id" ;;
    backup-offsite) host_backup_offsite "$id" ;;
    backup-change-cancel) host_backup_change_cancel "$id" ;;
    *) write_host_result "$kind" "$id" refused '' "unknown request kind $kind" ;;
  esac
}

# upgrade: version (newer than the running one; the child verifies it against the signed feed and manifest),
# fromVersion (the release the console saw; a stale request is refused), acceptBreaking (yes: the owner confirmed the
# release's breaking changes in the console — without it the child stops before anything changes).
host_upgrade() { # ID
  local id="$1" f="$WORK/request.json" version from accept cur log reason state
  version="$(json_str "$f" version)"
  from="$(json_str "$f" fromVersion)"
  accept="$(json_str "$f" acceptBreaking)"
  printf '%s' "$version" | grep -Eq "$VERSION_RE" || { write_host_result upgrade "$id" refused '' 'malformed version'; return 0; }
  printf '%s' "$from" | grep -Eq "$VERSION_RE" || { write_host_result upgrade "$id" refused '' 'malformed fromVersion'; return 0; }
  case "$accept" in yes | no) ;; *) write_host_result upgrade "$id" refused '' 'acceptBreaking must be yes or no'; return 0 ;; esac
  cur="$(current_version)"
  if [ "$from" != "$cur" ]; then
    write_host_result upgrade "$id" refused '' "the request was made for $from but this host runs $cur"
    return 0
  fi
  if ! ver_gt "$version" "$cur"; then
    write_host_result upgrade "$id" refused '' "$version is not newer than the running $cur (a rollback goes back)"
    return 0
  fi
  log="$STATE_DIR/host-upgrade.log"
  write_host_result upgrade "$id" applying 'starting' "$cur → $version"
  if [ "$accept" = yes ]; then run_host_child upgrade "$id" "$log" upgrade --to "$version" --yes
  else run_host_child upgrade "$id" "$log" upgrade --to "$version"
  fi
  if [ "$CHILD_RC" = 0 ]; then
    write_host_result upgrade "$id" applied "$CHILD_STEP" "$(grep -E '^(OK: |already on )' "$log" | tail -n 1)" "$log"
    return 0
  fi
  reason="$(child_reason "$log")"
  case "$reason" in
    *'NOT rolled back'*) state=held ;;
    'rolled back to '*'(healthy)'*) state=rolled_back ;;
    *) state=failed ;;
  esac
  write_host_result upgrade "$id" "$state" "$CHILD_STEP" "${reason:-the upgrade stopped (exit $CHILD_RC)}" "$log"
}

# rollback: version (a release still on this host, not the running one), fromVersion (staleness), backupId + the
# separate flag restoreDatabase=yes (both or neither): restore that backup first — destructive, the console asks twice.
host_rollback() { # ID
  local id="$1" f="$WORK/request.json" version from backup restore cur log reason
  version="$(json_str "$f" version)"
  from="$(json_str "$f" fromVersion)"
  backup="$(json_str "$f" backupId)"
  restore="$(json_str "$f" restoreDatabase)"
  printf '%s' "$version" | grep -Eq "$VERSION_RE" || { write_host_result rollback "$id" refused '' 'malformed version'; return 0; }
  printf '%s' "$from" | grep -Eq "$VERSION_RE" || { write_host_result rollback "$id" refused '' 'malformed fromVersion'; return 0; }
  case "$restore" in yes | no) ;; *) write_host_result rollback "$id" refused '' 'restoreDatabase must be yes or no'; return 0 ;; esac
  if [ -n "$backup" ] && ! printf '%s' "$backup" | grep -Eq "$BACKUP_ID_RE"; then
    write_host_result rollback "$id" refused '' 'malformed backup id'
    return 0
  fi
  if { [ -n "$backup" ] && [ "$restore" != yes ]; } || { [ -z "$backup" ] && [ "$restore" = yes ]; }; then
    write_host_result rollback "$id" refused '' 'a database restore needs both the backup id and restoreDatabase=yes'
    return 0
  fi
  cur="$(current_version)"
  if [ "$from" != "$cur" ]; then
    write_host_result rollback "$id" refused '' "the request was made for $from but this host runs $cur"
    return 0
  fi
  if [ "$version" = "$cur" ] || [ ! -f "$RELEASES_DIR/$version/manifest.json" ]; then
    write_host_result rollback "$id" refused '' "release $version is not a previous release kept on this host"
    return 0
  fi
  if [ -n "$backup" ] && [ ! -f "$DATA_DIR/backups/db/$backup.dump" ]; then
    write_host_result rollback "$id" refused '' "backup $backup is not on this host"
    return 0
  fi
  log="$STATE_DIR/host-rollback.log"
  write_host_result rollback "$id" applying 'starting' "$cur → $version${backup:+ with backup $backup}"
  if [ -n "$backup" ]; then run_host_child rollback "$id" "$log" rollback --to "$version" --restore-backup "$backup" --yes
  else run_host_child rollback "$id" "$log" rollback --to "$version" --yes
  fi
  if [ "$CHILD_RC" = 0 ]; then
    write_host_result rollback "$id" applied "$CHILD_STEP" "$(grep -E '^OK: ' "$log" | tail -n 1)" "$log"
    return 0
  fi
  reason="$(child_reason "$log")"
  write_host_result rollback "$id" failed "$CHILD_STEP" "${reason:-the rollback stopped (exit $CHILD_RC)}" "$log"
}

# ---------------------------------------------------------------- backups from the console (p17-host-actions part 3)

# backup-run: reason (lower-case letters, digits, -; the console keeps the owner's own words in its audit trail).
host_backup_run() { # ID
  local id="$1" reason log run outcome
  reason="$(json_str "$WORK/request.json" reason)"
  printf '%s' "$reason" | grep -Eq '^[a-z0-9-]{1,40}$' ||
    { write_host_result backup-run "$id" refused '' 'the reason must be 1-40 lower-case letters, digits and -'; return 0; }
  log="$STATE_DIR/host-backup-run.log"
  write_host_result backup-run "$id" applying 'backup' "reason $reason"
  run_host_child backup-run "$id" "$log" backup --reason "$reason"
  run="$(sed -n 's/^ *"runId": "\([^"]*\)".*/\1/p' "$log" | head -n 1)"
  outcome="$(sed -n 's/^ *"outcome": "\([a-z]*\)".*/\1/p' "$log" | head -n 1)"
  if [ "$CHILD_RC" = 0 ]; then
    write_host_result backup-run "$id" applied 'backup' "backup ${run:-?}: ${outcome:-ok}" "$log"
  else
    write_host_result backup-run "$id" failed 'backup' "${run:+backup $run: }$(child_reason "$log" | head -c 300)${outcome:+ ($outcome)}" "$log"
  fi
}

# backup-drill: backupId ('' = the newest backup) — a restore drill into a throw-away database inside the backup
# service; the live database is not touched.
host_backup_drill() { # ID
  local id="$1" backup log outcome
  backup="$(json_str "$WORK/request.json" backupId)"
  if [ -n "$backup" ] && ! printf '%s' "$backup" | grep -Eq "$BACKUP_ID_RE"; then
    write_host_result backup-drill "$id" refused '' 'malformed backup id'
    return 0
  fi
  log="$STATE_DIR/host-backup-drill.log"
  write_host_result backup-drill "$id" applying 'restore drill' "${backup:-the newest backup}"
  if [ -n "$backup" ]; then run_host_child backup-drill "$id" "$log" drill --backup "$backup"
  else run_host_child backup-drill "$id" "$log" drill
  fi
  outcome="$(sed -n 's/^ *"outcome": "\([a-z]*\)".*/\1/p' "$log" | head -n 1)"
  if [ "$CHILD_RC" = 0 ]; then
    write_host_result backup-drill "$id" applied 'restore drill' "drill ${outcome:-passed}${backup:+ ($backup)}" "$log"
  else
    write_host_result backup-drill "$id" failed 'restore drill' "drill ${outcome:-failed}: $(child_reason "$log" | head -c 300)" "$log"
  fi
}

# backup-restore: backupId (a backup of this host) + restoreDatabase=yes (the separate flag; the console asks twice and
# has the owner type the id). Replaces the live database; the replaced one is kept renamed.
host_backup_restore() { # ID
  local id="$1" backup restore log
  backup="$(json_str "$WORK/request.json" backupId)"
  restore="$(json_str "$WORK/request.json" restoreDatabase)"
  printf '%s' "$backup" | grep -Eq "$BACKUP_ID_RE" || { write_host_result backup-restore "$id" refused '' 'malformed backup id'; return 0; }
  [ "$restore" = yes ] || { write_host_result backup-restore "$id" refused '' 'a database restore needs restoreDatabase=yes'; return 0; }
  if [ ! -f "$DATA_DIR/backups/db/$backup.dump" ]; then
    write_host_result backup-restore "$id" refused '' "backup $backup is not on this host"
    return 0
  fi
  log="$STATE_DIR/host-backup-restore.log"
  write_host_result backup-restore "$id" applying 'starting' "restore $backup"
  run_host_child backup-restore "$id" "$log" restore --backup "$backup" --yes
  if [ "$CHILD_RC" = 0 ]; then
    write_host_result backup-restore "$id" applied "$CHILD_STEP" "$(grep -E '^OK: ' "$log" | tail -n 1)" "$log"
  else
    write_host_result backup-restore "$id" failed "$CHILD_STEP" "$(child_reason "$log" | head -c 400)" "$log"
  fi
}

# One value of a backup-config request: '' (the default) or an integer within [min, max].
int_or_empty() { # VALUE MIN MAX
  [ -z "$1" ] && return 0
  printf '%s' "$1" | grep -Eq '^[0-9]{1,5}$' && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}
# backup-config: the schedule, retention, drill, WAL archiving and encryption recipients — applied into stack.env
# (BACKUP_* / PG_WAL_ARCHIVE) and backup-config/recipients.txt, then the backup service (and Postgres when WAL
# archiving changed) is recreated. A failure restores both files.
host_backup_config() { # ID
  local id="$1" f="$WORK/request.json" t iv kd kw km kh de dw dt wal rec r n=0 seen=' ' rel old_wal svc
  t="$(json_str "$f" time)"; iv="$(json_str "$f" intervalMinutes)"
  kd="$(json_str "$f" keepDaily)"; kw="$(json_str "$f" keepWeekly)"; km="$(json_str "$f" keepMonthly)"
  kh="$(json_str "$f" keepRecentHours)"; de="$(json_str "$f" drillEnabled)"; dw="$(json_str "$f" drillWeekday)"
  dt="$(json_str "$f" drillTime)"; wal="$(json_str "$f" walArchive)"; rec="$(json_str "$f" recipients)"
  local bad=''
  [ -z "$t" ] || printf '%s' "$t" | grep -Eq "$HHMM_RE" || bad='time must be HH:MM (UTC)'
  int_or_empty "$iv" 15 10080 || bad='intervalMinutes must be 15..10080 or empty'
  int_or_empty "$kd" 0 366 || bad='keepDaily must be 0..366'
  int_or_empty "$kw" 0 520 || bad='keepWeekly must be 0..520'
  int_or_empty "$km" 0 120 || bad='keepMonthly must be 0..120'
  int_or_empty "$kh" 0 744 || bad='keepRecentHours must be 0..744'
  if [ -n "$kd$kw$km" ] && [ "${kd:-7}" = 0 ] && [ "${kw:-4}" = 0 ] && [ "${km:-6}" = 0 ]; then bad='the retention keeps nothing'; fi
  case "$de" in true | false) ;; *) bad='drillEnabled must be true or false' ;; esac
  case "$dw" in sun | mon | tue | wed | thu | fri | sat) ;; *) bad='drillWeekday must be sun..sat' ;; esac
  [ -z "$dt" ] || printf '%s' "$dt" | grep -Eq "$HHMM_RE" || bad='drillTime must be HH:MM (UTC)'
  case "$wal" in on | off) ;; *) bad='walArchive must be on or off' ;; esac
  for r in $(printf '%s' "$rec" | tr ',' ' '); do
    printf '%s' "$r" | grep -Eq "$AGE_RECIPIENT_RE" || { bad='a recipient is not an age public key (age1…)'; break; }
    case "$seen" in *" $r "*) continue ;; esac
    seen="$seen$r "
    n=$((n + 1))
  done
  if [ -z "$bad" ] && { [ "$n" -lt 2 ] || [ "$n" -gt 10 ]; }; then bad='keep 2 to 10 different encryption recipients'; fi
  if [ -n "$bad" ]; then write_host_result backup-config "$id" refused '' "$bad"; return 0; fi
  rel="$RELEASES_DIR/$(current_version)"
  [ -f "$rel/compose.yaml" ] || { write_host_result backup-config "$id" failed '' "the installed release is missing from $RELEASES_DIR"; return 0; }
  # p17-panel-settings Part 0 — the host time lock: recipients this host does not use yet are NOT written now. The
  # schedule, retention, drill, WAL archiving and any removal apply at once (removals only while at least two current
  # recipients stay); the full requested set waits BACKUP_CHANGE_WAIT_S from the time this host first saw an addition.
  local cur added='' na=0 keep='' nk=0 immediate since old_set note=''
  cur="$(current_recipients)"
  for r in $seen; do
    if printf '%s\n' "$cur" | grep -qx "$r"; then keep="$keep$r "; nk=$((nk + 1))
    else added="$added$r "; na=$((na + 1))
    fi
  done
  if [ "$na" -gt 0 ]; then
    # shellcheck disable=SC2086 # cur holds one age public key per line (age1…, no glob characters): split on purpose
    if [ "$nk" -ge 2 ]; then immediate="$keep"; else immediate="$(printf '%s ' $cur)"; fi
    since="$(date -u +%s)"
    if [ -f "$(pending_dir)/recipients" ]; then
      old_set=" $(env_value "$(pending_dir)/recipients" set | tr ',' ' ') "
      local all_known=1
      for r in $added; do case "$old_set" in *" $r "*) ;; *) all_known=0 ;; esac; done
      # The same (or a smaller) addition keeps the time this host first saw it; anything new starts the wait again.
      if [ "$all_known" = 1 ]; then since="$(env_value "$(pending_dir)/recipients" since)"; fi
    fi
  else
    immediate="$seen"
  fi
  write_host_result backup-config "$id" applying 'write the settings' ''
  old_wal="$(env_value "$STACK_ENV" PG_WAL_ARCHIVE)"
  mkdir -p "$STATE_DIR" "$DATA_DIR/backup-config"
  cp -p "$STACK_ENV" "$STATE_DIR/stack.env.backup-prev"
  if [ -f "$DATA_DIR/backup-config/recipients.txt" ]; then cp -p "$DATA_DIR/backup-config/recipients.txt" "$STATE_DIR/recipients.backup-prev"
  else rm -f "$STATE_DIR/recipients.backup-prev"
  fi
  set_env_value "$STACK_ENV" BACKUP_TIME "$t"
  set_env_value "$STACK_ENV" BACKUP_INTERVAL_MINUTES "$iv"
  set_env_value "$STACK_ENV" BACKUP_KEEP_DAILY "$kd"
  set_env_value "$STACK_ENV" BACKUP_KEEP_WEEKLY "$kw"
  set_env_value "$STACK_ENV" BACKUP_KEEP_MONTHLY "$km"
  set_env_value "$STACK_ENV" BACKUP_KEEP_RECENT_HOURS "$kh"
  set_env_value "$STACK_ENV" BACKUP_DRILL_ENABLED "$de"
  set_env_value "$STACK_ENV" BACKUP_DRILL_WEEKDAY "$dw"
  set_env_value "$STACK_ENV" BACKUP_DRILL_TIME "$dt"
  set_env_value "$STACK_ENV" PG_WAL_ARCHIVE "$wal"
  # shellcheck disable=SC2086 # immediate is a space-separated list of validated age public keys: split on purpose
  if [ -n "$(printf '%s' "$immediate" | tr -d ' ')" ]; then write_recipients $immediate; fi
  svc='backup'
  [ "${old_wal:-off}" = "$wal" ] || svc='postgres backup'
  write_host_result backup-config "$id" applying "recreate: $svc" ''
  # shellcheck disable=SC2086
  if dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 $svc >"$STATE_DIR/host-backup-config.log" 2>&1; then
    rm -f "$STATE_DIR/stack.env.backup-prev" "$STATE_DIR/recipients.backup-prev"
    if [ "$na" -gt 0 ]; then
      pending_record recipients "$id" "$since" "set=$(printf '%s' "$seen" | sed 's/ $//' | tr ' ' ',')"
      write_host_result backup-config "$id" scheduled "recreate: $svc" \
        "applied (WAL archiving $wal); adding $na encryption recipient(s) waits until $(epoch_iso "$((since + BACKUP_CHANGE_WAIT_S))") (host time lock) — cancel in the console or: remyral-ctl backup-change cancel" \
        "$STATE_DIR/host-backup-config.log"
      return 0
    fi
    if [ -f "$(pending_dir)/recipients" ]; then pending_resolve recipients superseded; note=' (the waiting recipient change is withdrawn)'; fi
    write_host_result backup-config "$id" applied "recreate: $svc" "applied; $n recipients, WAL archiving $wal$note" "$STATE_DIR/host-backup-config.log"
    return 0
  fi
  cp -p "$STATE_DIR/stack.env.backup-prev" "$STACK_ENV"
  if [ -f "$STATE_DIR/recipients.backup-prev" ]; then cp -p "$STATE_DIR/recipients.backup-prev" "$DATA_DIR/backup-config/recipients.txt"; fi
  # shellcheck disable=SC2086
  dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 $svc >/dev/null 2>&1 || true
  rm -f "$STATE_DIR/stack.env.backup-prev" "$STATE_DIR/recipients.backup-prev"
  write_host_result backup-config "$id" failed "recreate: $svc" 'the services did not start with the new settings; the previous settings are back' "$STATE_DIR/host-backup-config.log"
}

# backup-offsite: mode set (endpoint, region, bucket, prefix, path style and the access keys — the only request that
# carries a credential: it is written into backup-config/offsite.env, root 0600, and never into a log or the status)
# or clear (the file is removed). The backup service reads the file on every run; nothing restarts.
host_backup_offsite() { # ID
  local id="$1" f="$WORK/request.json" mode endpoint region bucket prefix path key secret out
  mode="$(json_str "$f" mode)"
  out="$DATA_DIR/backup-config/offsite.env"
  case "$mode" in
    clear)
      rm -f "$out"
      pending_resolve offsite superseded
      write_host_result backup-offsite "$id" applied '' 'the off-site copy is off (backup-config/offsite.env removed; a waiting target change is withdrawn)'
      return 0
      ;;
    set) ;;
    *) write_host_result backup-offsite "$id" refused '' 'mode must be set or clear'; return 0 ;;
  esac
  endpoint="$(json_str "$f" endpoint)"; region="$(json_str "$f" region)"; bucket="$(json_str "$f" bucket)"
  prefix="$(json_str "$f" prefix)"; path="$(json_str "$f" pathStyle)"
  key="$(json_str "$f" accessKeyId)"; secret="$(json_str "$f" secretAccessKey)"
  local bad=''
  # https only — http just for this machine (a local MinIO), as the backup runner allows.
  [ -z "$endpoint" ] || printf '%s' "$endpoint" | grep -Eq '^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[1-9][0-9]{0,4})?$' ||
    printf '%s' "$endpoint" | grep -Eq '^http://(127\.0\.0\.1|localhost)(:[1-9][0-9]{0,4})?$' ||
    bad='the endpoint must be an https:// origin'
  printf '%s' "$region" | grep -Eq '^[a-z0-9-]{2,32}$' || bad='malformed region'
  printf '%s' "$bucket" | grep -Eq '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' || bad='malformed bucket name'
  if [ -n "$prefix" ]; then
    { printf '%s' "$prefix" | grep -Eq '^[A-Za-z0-9._/-]{1,200}$' && ! printf '%s' "$prefix" | grep -q '\.\.'; } ||
      bad='the prefix may contain A-Z a-z 0-9 . _ - and /'
  fi
  case "$path" in true | false | '') ;; *) bad='pathStyle must be true or false' ;; esac
  printf '%s' "$key" | grep -Eq '^[A-Za-z0-9._-]{3,128}$' || bad='malformed access key id'
  { [ "${#secret}" -ge 8 ] && [ "${#secret}" -le 256 ] && printf '%s' "$secret" | LC_ALL=C grep -Eq '^[!-~]+$'; } ||
    bad='malformed secret access key'
  if [ -n "$bad" ]; then write_host_result backup-offsite "$id" refused '' "$bad"; return 0; fi
  mkdir -p "$DATA_DIR/backup-config" "$(pending_dir)"
  chmod 0700 "$(pending_dir)"
  offsite_content "$bucket" "$region" "$endpoint" "$prefix" "$path" "$key" "$secret" | write_file "$WORK/offsite.env" 0600
  # p17-panel-settings Part 0 — the host time lock: another bucket, endpoint, region or access key (or a first target)
  # waits BACKUP_CHANGE_WAIT_S from the time this host first saw it; meanwhile the copies keep going where they went.
  if [ -f "$out" ] && same_offsite_target "$out" "$WORK/offsite.env"; then
    write_file "$out" 0600 <"$WORK/offsite.env"
    local note=''
    if [ -f "$(pending_dir)/offsite" ]; then pending_resolve offsite superseded; note=' (the waiting target change is withdrawn)'; fi
    write_host_result backup-offsite "$id" applied '' "the off-site copy goes to $(offsite_describe "$out")$note"
    return 0
  fi
  local since
  since="$(date -u +%s)"
  if [ -f "$(pending_dir)/offsite" ] && [ -f "$(pending_dir)/offsite.env" ] &&
    same_offsite_target "$(pending_dir)/offsite.env" "$WORK/offsite.env"; then
    since="$(env_value "$(pending_dir)/offsite" since)"
  fi
  write_file "$(pending_dir)/offsite.env" 0600 <"$WORK/offsite.env"
  pending_record offsite "$id" "$since" "target=$(offsite_describe "$WORK/offsite.env")"
  write_host_result backup-offsite "$id" scheduled '' \
    "the off-site target $(offsite_describe "$WORK/offsite.env") waits until $(epoch_iso "$((since + BACKUP_CHANGE_WAIT_S))") (host time lock); until then the copies go where they went — cancel in the console or: remyral-ctl backup-change cancel"
}

# offsite.env for the backup service (root 0600: it holds the access key).
offsite_content() { # BUCKET REGION ENDPOINT PREFIX PATHSTYLE KEY SECRET
  printf '# Written by remyral-ctl (Ayarlar → Yedekler → Off-site hedef). Root only: it holds the access key.\n'
  printf 'BACKUP_S3_BUCKET=%s\nBACKUP_S3_REGION=%s\n' "$1" "$2"
  [ -z "$3" ] || printf 'BACKUP_S3_ENDPOINT=%s\n' "$3"
  [ -z "$4" ] || printf 'BACKUP_S3_PREFIX=%s\n' "$4"
  [ -z "$5" ] || printf 'BACKUP_S3_FORCE_PATH_STYLE=%s\n' "$5"
  printf 'BACKUP_S3_ACCESS_KEY_ID=%s\nBACKUP_S3_SECRET_ACCESS_KEY=%s\n' "$6" "$7"
}
# 0 when two offsite.env files name the same target: bucket, endpoint, region and the same access key (prefix and
# path style may differ — they stay inside the owner's bucket).
same_offsite_target() { # FILE_A FILE_B
  local k
  for k in BACKUP_S3_BUCKET BACKUP_S3_ENDPOINT BACKUP_S3_REGION BACKUP_S3_ACCESS_KEY_ID BACKUP_S3_SECRET_ACCESS_KEY; do
    [ "$(env_value "$1" "$k")" = "$(env_value "$2" "$k")" ] || return 1
  done
}

# ---------------------------------------------------------------- the host time lock (p17-panel-settings Part 0)
#
# ADR-0063 amendment 2026-10-26 ("host time lock"): a compromised master could add its own age recipient and point the
# off-site copy at its own bucket, then receive the next secrets archive. Such a change waits on the host:
#   <data>/state/backup-pending/recipients   id=, since= (epoch, THIS host's clock when it first saw it), set=
#   <data>/state/backup-pending/offsite      id=, since=, target= (+ offsite.env next to it, 0600)
#   <data>/state/backup-pending/history      <iso> <change> applied|cancelled|superseded <id>
# The directory is root 0700; the master can neither read nor shorten it. `apply-pending` applies a change once
# `since + BACKUP_CHANGE_WAIT_S` passed; `backup-change-cancel` or `remyral-ctl backup-change cancel` withdraws it.

pending_dir() { printf '%s/backup-pending' "$STATE_DIR"; }
epoch_iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
# The recipients the backup service encrypts to now (one per line).
current_recipients() {
  [ -f "$DATA_DIR/backup-config/recipients.txt" ] || return 0
  grep -E "$AGE_RECIPIENT_RE" "$DATA_DIR/backup-config/recipients.txt" || true
}
write_recipients() { # R…
  {
    printf '# Written by remyral-ctl (Ayarlar → Yedekler): the owner'"'"'s age PUBLIC keys; the private keys stay offline.\n'
    printf '%s\n' "$@"
  } | write_file "$DATA_DIR/backup-config/recipients.txt" 0644
}
pending_record() { # CHANGE ID SINCE EXTRA_LINE
  [ "$DRY" = 1 ] && return 0
  mkdir -p "$(pending_dir)"
  chmod 0700 "$(pending_dir)"
  printf 'id=%s\nsince=%s\n%s\n' "$2" "$3" "$4" | write_file "$(pending_dir)/$1" 0600
}
pending_resolve() { # CHANGE STATE
  local f id
  f="$(pending_dir)/$1"
  [ -f "$f" ] || return 0
  id="$(env_value "$f" id)"
  rm -f "$f"
  [ "$1" != offsite ] || rm -f "$(pending_dir)/offsite.env"
  printf '%s %s %s %s\n' "$(now_iso)" "$1" "$2" "${id:--}" >>"$(pending_dir)/history"
  tail -n 50 "$(pending_dir)/history" >"$(pending_dir)/history.tmp" && mv "$(pending_dir)/history.tmp" "$(pending_dir)/history"
  note "backup change $1: $2"
}
# 0 when CHANGE is waiting and its time has come (SINCE is checked as a number; a broken file never applies).
pending_due() { # CHANGE
  local since
  [ -f "$(pending_dir)/$1" ] || return 1
  since="$(env_value "$(pending_dir)/$1" since)"
  printf '%s' "$since" | grep -Eq '^[0-9]{1,12}$' || return 1
  [ "$(date -u +%s)" -ge $((since + BACKUP_CHANGE_WAIT_S)) ]
}
# Applies one waiting change now (after the wait, or `backup-change confirm` by the operator), re-validating it.
pending_apply() { # CHANGE
  local f set r n=0 seen=' '
  f="$(pending_dir)/$1"
  [ -f "$f" ] || return 0
  case "$1" in
    recipients)
      set="$(env_value "$f" set)"
      for r in $(printf '%s' "$set" | tr ',' ' '); do
        printf '%s' "$r" | grep -Eq "$AGE_RECIPIENT_RE" || { warn "backup change recipients: not an age key; dropped"; pending_resolve recipients refused; return 0; }
        case "$seen" in *" $r "*) continue ;; esac
        seen="$seen$r "
        n=$((n + 1))
      done
      if [ "$n" -lt 2 ] || [ "$n" -gt 10 ]; then pending_resolve recipients refused; return 0; fi
      mkdir -p "$DATA_DIR/backup-config"
      # shellcheck disable=SC2086
      write_recipients $seen
      ;;
    offsite)
      [ -f "$(pending_dir)/offsite.env" ] || { pending_resolve offsite refused; return 0; }
      mkdir -p "$DATA_DIR/backup-config"
      write_file "$DATA_DIR/backup-config/offsite.env" 0600 <"$(pending_dir)/offsite.env"
      ;;
  esac
  pending_resolve "$1" applied
}
apply_due_backup_changes() {
  local c
  for c in recipients offsite; do
    if pending_due "$c"; then pending_apply "$c"; fi
  done
}
# The heartbeat's view of the waiting changes and the last outcomes (never a key).
pending_heartbeat() {
  local c f first=1 since added r rf cur
  printf ',\n    "pending": ['
  for c in recipients offsite; do
    f="$(pending_dir)/$c"
    [ -f "$f" ] || continue
    since="$(env_value "$f" since)"
    printf '%s' "$since" | grep -Eq '^[0-9]{1,12}$' || continue
    if [ "$first" = 1 ]; then first=0; else printf ','; fi
    printf '\n      {"change": "%s", "id": "%s", "since": "%s", "until": "%s", ' "$c" \
      "$(json_text "$(env_value "$f" id)")" "$(epoch_iso "$since")" "$(epoch_iso "$((since + BACKUP_CHANGE_WAIT_S))")"
    if [ "$c" = recipients ]; then
      cur="$(current_recipients)"
      added=''
      rf=1
      for r in $(env_value "$f" set | tr ',' ' '); do
        printf '%s' "$r" | grep -Eq "$AGE_RECIPIENT_RE" || continue
        printf '%s\n' "$cur" | grep -qx "$r" && continue
        if [ "$rf" = 1 ]; then added="\"$r\""; rf=0; else added="$added, \"$r\""; fi
      done
      printf '"added": [%s], "target": ""}' "$added"
    else
      printf '"added": [], "target": "%s"}' "$(json_text "$(env_value "$f" target)")"
    fi
  done
  [ "$first" = 1 ] || printf '\n    '
  printf '],\n    "changes": ['
  first=1
  if [ -f "$(pending_dir)/history" ]; then
    local at ch st id
    while read -r at ch st id; do
      if [ "$first" = 1 ]; then first=0; else printf ','; fi
      printf '\n      {"change": "%s", "state": "%s", "id": "%s", "at": "%s"}' "$(json_text "$ch")" "$(json_text "$st")" \
        "$(json_text "$id")" "$(json_text "$at")"
    done < <(tail -n 5 "$(pending_dir)/history")
  fi
  [ "$first" = 1 ] || printf '\n    '
  printf ']'
}

# backup-change-cancel: change = recipients | offsite | all — withdraws a waiting change (never shortens one).
host_backup_change_cancel() { # ID
  local id="$1" change c done=''
  change="$(json_str "$WORK/request.json" change)"
  case "$change" in recipients | offsite | all) ;; *) write_host_result backup-change-cancel "$id" refused '' 'change must be recipients, offsite or all'; return 0 ;; esac
  for c in recipients offsite; do
    [ "$change" = all ] || [ "$change" = "$c" ] || continue
    if [ -f "$(pending_dir)/$c" ]; then pending_resolve "$c" cancelled; done="$done $c"; fi
  done
  if [ -z "$done" ]; then write_host_result backup-change-cancel "$id" applied '' 'nothing was waiting'
  else write_host_result backup-change-cancel "$id" applied '' "cancelled:$done"
  fi
}

# `remyral-ctl backup-change show | cancel | confirm` — the operator on the host (root) sees, withdraws or confirms a
# waiting change at once. Confirming is the host's own decision; the console can never do it.
cmd_backup_change() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  local c f any=0
  case "${CHANGE_ACTION:-show}" in
    show)
      for c in recipients offsite; do
        f="$(pending_dir)/$c"
        [ -f "$f" ] || continue
        any=1
        out "  $c: waiting until $(epoch_iso "$(($(env_value "$f" since) + BACKUP_CHANGE_WAIT_S))") (request $(env_value "$f" id))"
        if [ "$c" = recipients ]; then note "new set: $(env_value "$f" set)"; else note "new target: $(env_value "$f" target)"; fi
      done
      [ "$any" = 1 ] || out "  no backup change is waiting"
      return 0
      ;;
  esac
  lock
  case "$CHANGE_ACTION" in
    cancel) for c in recipients offsite; do pending_resolve "$c" cancelled; done ;;
    confirm)
      [ "$YES" = 1 ] || [ ! -t 0 ] || confirm "Apply the waiting backup change(s) now, without the 72 h wait?"
      for c in recipients offsite; do pending_apply "$c"; done
      ;;
  esac
  new_work
  write_heartbeat
  out "OK"
}

# ---------------------------------------------------------------- status / version / backup / doctor / token

cmd_status() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  local cur s
  cur="$(current_version)"
  out "Remyral control plane at $(console_url "$(env_value "$STACK_ENV" REMYRAL_DOMAIN)")"
  out "  release   ${cur:-unknown} (TLS: $(env_value "$STACK_ENV" REMYRAL_TLS_MODE))"
  out "  schema    $(db_head)"
  for s in master web postgres redis proxy backup; do out "  $(printf '%-9s' "$s") $(health_of "$s")"; done
  if [ -f "$DATA_DIR/update/feed.json" ]; then
    local latest
    latest="$(json_str "$DATA_DIR/update/feed.json" version)"
    if [ -n "$latest" ] && [ -n "$cur" ] && ver_gt "$latest" "$cur"; then out "  update    $latest available — sudo remyral-ctl upgrade --to $latest"
    else out "  update    up to date (last check: $(json_str "$DATA_DIR/update/feed.json" generatedAt))"
    fi
  fi
  if [ -f "$HOST_DIR/status/domain-result.json" ]; then
    out "  domain    last change: $(json_str "$HOST_DIR/status/domain-result.json" state) $(json_str "$HOST_DIR/status/domain-result.json" domain) ($(json_str "$HOST_DIR/status/domain-result.json" at))"
  fi
  local k r
  for k in $HOST_REQUEST_KINDS; do
    r="$HOST_DIR/status/$k-result.json"
    [ -f "$r" ] && out "  $(printf '%-9s' "$k") last console request: $(json_str "$r" state) ($(json_str "$r" at)) $(json_str "$r" detail)"
  done
  local c f
  for c in recipients offsite; do
    f="$(pending_dir)/$c"
    [ -f "$f" ] || continue
    out "  WAITING   backup $c change from the console: takes effect $(epoch_iso "$(($(env_value "$f" since) + BACKUP_CHANGE_WAIT_S))")"
    if [ "$c" = recipients ]; then note "new recipient set: $(env_value "$f" set)"; else note "new off-site target: $(env_value "$f" target)"; fi
    note "not yours? sudo remyral-ctl backup-change cancel (and check who has owner access); yours: … confirm --yes"
  done
  if [ -f "$STATE_DIR/history" ]; then
    out "  history (newest last):"
    tail -n 5 "$STATE_DIR/history" | sed 's/^/    /'
  fi
}
cmd_version() {
  out "remyral-ctl ${REMYRAL_CTL_BUNDLE_VERSION:-source}"
  [ -f "$STATE_DIR/current" ] && out "installed $(current_version)"
  return 0
}
cmd_backup() {
  printf '%s' "$BACKUP_REASON" | grep -Eq '^[a-z0-9-]{1,40}$' || die "--reason must be lower-case letters, digits and -"
  local b
  b="$(container_of backup)"
  [ -n "$b" ] || die "the backup service is not running (remyral-ctl status)"
  run docker exec "$b" remyral-backup run --reason "$BACKUP_REASON"
}
# p17-host-actions: a restore drill now (into a throw-away database inside the backup service; the live one is untouched).
cmd_drill() {
  [ -z "$BACKUP_ARG" ] || printf '%s' "$BACKUP_ARG" | grep -Eq "$BACKUP_ID_RE" || die "--backup '$BACKUP_ARG' is not a backup id"
  local b
  b="$(container_of backup)"
  [ -n "$b" ] || die "the backup service is not running (remyral-ctl status)"
  if [ -n "$BACKUP_ARG" ]; then run docker exec "$b" remyral-backup drill --backup "$BACKUP_ARG"
  else run docker exec "$b" remyral-backup drill
  fi
}
# p17-host-actions: replace the live database with a backup of this host (docs/ops/backup-restore.md §4), with the
# running release: stop master + backup, restore (the replaced database is kept renamed), migrate forward, start,
# health gate. A stop half-way starts the services again (cleanup) — the database changes only at the final rename.
cmd_restore() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  [ -n "$BACKUP_ARG" ] || die "--backup ID is required (remana-<env>-YYYYMMDDTHHMMSSZ; docker exec <backup> remyral-backup list)"
  local cur rel head need
  cur="$(current_version)"
  rel="$RELEASES_DIR/$cur"
  [ -f "$rel/manifest.json" ] || die "the installed release $cur is missing from $RELEASES_DIR"
  new_work
  out "remyral-ctl restore $BACKUP_ARG on $cur$([ "$DRY" = 1 ] && printf ' — DRY RUN, nothing is changed')"
  step "verify the stored release $cur"
  verify_signed "$rel/manifest.json" "$rel/manifest.sig.json" "$RELEASE_CONTEXT"
  lock
  confirm "Replace the live database with backup $BACKUP_ARG (the current one is kept renamed)?"
  step "stop master and backup"
  [ "$DRY" = 1 ] || RESTART_ON_EXIT="$rel"
  run dc "$rel" "$RELEASE_ENV" stop master backup
  step "restore backup $BACKUP_ARG"
  restore_backup "$BACKUP_ARG"
  head="$(db_head)"
  need="$(manifest_migrations "$rel")"
  if [ "$DRY" = 0 ] && [ -n "$head" ] && [ "$head" \> "$need" ]; then
    die "the restored schema $head is newer than $cur expects ($need): upgrade to the release the backup was made with"
  fi
  step "migrate (forward-only) with $cur"
  show "$(dc_show "$rel") run --rm --no-TTY migrate"
  [ "$DRY" = 1 ] || dc "$rel" "$RELEASE_ENV" run --rm --no-TTY migrate || die "migrations failed on the restored database"
  step "start $cur"
  show "$(dc_show "$rel") up -d --wait --wait-timeout 300 master web backup"
  if [ "$DRY" = 0 ]; then
    dc "$rel" "$RELEASE_ENV" up -d --wait --wait-timeout 300 master web backup || true
    RESTART_ON_EXIT=''
    step "health gate"
    health_gate "$(image_ref "$rel" master)" "$(image_ref "$rel" web)" || die "$cur is unhealthy after the restore: $GATE_FAILURES"
    record "$cur" active "$(db_head)" "$BACKUP_ARG"
  fi
  out "OK: Remyral $cur runs on backup $BACKUP_ARG$([ "$DRY" = 1 ] && printf ' (dry run)')"
}
cmd_doctor() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  SKIP_CHECKS=1
  check_prereqs upgrade
  local rel cur rc=0
  cur="$(current_version)"
  rel="$RELEASES_DIR/$cur"
  step "control-plane diagnostics (remyral-master doctor)"
  [ -f "$rel/compose.yaml" ] || die "release $cur is missing from $RELEASES_DIR"
  dc "$rel" "$RELEASE_ENV" exec -T master remyral-master doctor || rc=$?
  if [ "$rc" = 64 ]; then
    # Releases before p16-doctor have no `doctor` mode in the master image.
    note "this release has no 'doctor' yet; 'remyral-ctl status' and Ayarlar → Sistem durumu show the health checks."
    rc=0
  elif [ "$rc" = 1 ]; then
    note "the doctor found errors (FAIL lines above); the full run with machine doctors: Ayarlar → Tanılama"
  fi
  # A worker installed on this host too (not the usual layout): its own doctor.
  if command -v remyral-worker >/dev/null 2>&1; then
    step "machine doctor on this host (remyral-worker doctor)"
    remyral-worker doctor || rc=$((rc > 0 ? rc : 1))
  fi
  return "$rc"
}
cmd_setup_token() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  local n
  n="$(owners_count)"
  [ "${n:-0}" = 0 ] || die "an account exists already: owners recover access with 'docker exec -it <master> remyral-master admin:reset' (docs/ops/admin-bootstrap.md)"
  issue_setup_token "$RELEASES_DIR/$(current_version)"
}
cmd_uninstall() {
  [ -f "$STACK_ENV" ] || die "nothing is installed in $DATA_DIR"
  local rel
  rel="$RELEASES_DIR/$(current_version)"
  if [ "$PURGE" = 1 ]; then
    confirm "Delete the stack AND every byte of data in $DATA_DIR (database, backups, keys)? This cannot be undone"
  else
    confirm "Stop and remove the Remyral containers (data in $DATA_DIR is kept)?"
  fi
  step "stop and remove the containers"
  if [ "$PURGE" = 1 ]; then run dc "$rel" "$RELEASE_ENV" down --remove-orphans --volumes
  else run dc "$rel" "$RELEASE_ENV" down --remove-orphans
  fi
  run docker network rm "$PROXY_NETWORK_NAME"
  if [ -f "$SYSTEMD_DIR/remyral-update-check.timer" ]; then
    run systemctl disable --now remyral-update-check.timer
    run rm -f "$SYSTEMD_DIR/remyral-update-check.timer" "$SYSTEMD_DIR/remyral-update-check.service"
  fi
  if [ -f "$SYSTEMD_DIR/remyral-apply-pending.timer" ]; then
    run systemctl disable --now remyral-apply-pending.timer remyral-apply-pending.path
    run rm -f "$SYSTEMD_DIR/remyral-apply-pending.timer" "$SYSTEMD_DIR/remyral-apply-pending.path" \
      "$SYSTEMD_DIR/remyral-apply-pending.service"
  fi
  if [ "$PURGE" = 1 ]; then
    [ -f "$STATE_DIR/current" ] || die "$DATA_DIR does not look like a Remyral data directory; not deleting it"
    run rm -rf "$DATA_DIR"
    run rm -f "$BIN_DIR/remyral-ctl"
    out "Removed. The images stay in Docker's cache: docker image prune -a"
  else
    out "Containers removed; $DATA_DIR is kept (re-install with: remyral-ctl install, or delete it with --purge-data)."
  fi
}
usage() { sed -n '2,26p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || out "remyral-ctl: see docs/ops/selfhost-install.md"; }

case "$CMD" in
  install) cmd_install ;;
  upgrade) cmd_upgrade ;;
  rollback) cmd_rollback ;;
  status) cmd_status ;;
  version) cmd_version ;;
  backup) cmd_backup ;;
  drill) cmd_drill ;;
  restore) cmd_restore ;;
  doctor) cmd_doctor ;;
  setup-token) cmd_setup_token ;;
  apply-pending) cmd_apply_pending ;;
  backup-change) cmd_backup_change ;;
  uninstall) cmd_uninstall ;;
  help) usage ;;
esac
