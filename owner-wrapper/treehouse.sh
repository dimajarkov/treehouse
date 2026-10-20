#!/bin/sh
set -eu

REAL="$HOME/.local/libexec/treehouse-bin"
EXPECTED="/Volumes/OWC Envoy Ultra/20_PROJECTS/Development/Treehouse"
LOGICAL="$HOME/.treehouse"

fail() {
  printf 'treehouse: external-storage guard refused to run: %s
' "$*" >&2
  exit 78
}

[ -x "$REAL" ] || fail "real Treehouse binary is missing at $REAL"

# Default invocation is the mutating get path and must enter admission.
[ "$#" -ne 0 ] || set -- get
[ "${1:-}" != update ] || fail "updates belong to the guarded installation owner"
case "${1:-}" in
  -h|--help|-v|--version|help|completion|init)
    exec "$REAL" "$@"
    ;;
esac

[ -L "$LOGICAL" ] || fail "$LOGICAL is not a symbolic link"
[ -d "$EXPECTED" ] || fail "OWC Envoy Ultra is not mounted at the expected location"
RESOLVED=$(/bin/realpath "$LOGICAL" 2>/dev/null) || fail "cannot resolve $LOGICAL"
[ "$RESOLVED" = "$EXPECTED" ] || fail "$LOGICAL resolves to $RESOLVED instead of $EXPECTED"

HOME_DEVICE=$(/usr/bin/stat -f '%d' "$HOME")
TREEHOUSE_DEVICE=$(/usr/bin/stat -L -f '%d' "$LOGICAL")
[ "$TREEHOUSE_DEVICE" != "$HOME_DEVICE" ] || fail "Treehouse resolves to the internal home filesystem"

REPO_ROOT=""
if COMMON_DIR=$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir 2>/dev/null); then
  case "$COMMON_DIR" in
    */.git) REPO_ROOT=${COMMON_DIR%/.git} ;;
  esac
fi

CONFIG="$HOME/.config/treehouse/config.toml"
if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/treehouse.toml" ]; then
  CONFIG="$REPO_ROOT/treehouse.toml"
fi

ROOT_VALUE=""
if [ -f "$CONFIG" ]; then
  ROOT_VALUE=$(/usr/bin/awk '
    /^[[:space:]]*root[[:space:]]*=/ {
      sub(/^[[:space:]]*root[[:space:]]*=[[:space:]]*/, "")
      sub(/[[:space:]]*#[^"]*$/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      if (($0 ~ /^".*"$/) || ($0 ~ /^'.*'$/)) {
        print substr($0, 2, length($0) - 2)
      } else {
        print "__TREEHOUSE_GUARD_UNPARSEABLE__"
      }
      exit
    }
  ' "$CONFIG")
fi

case "$ROOT_VALUE" in
  __TREEHOUSE_GUARD_UNPARSEABLE__)
    fail "cannot safely parse root in $CONFIG"
    ;;
  ""|'$HOME')
    POOL_PARENT="$HOME"
    ;;
  '$HOME/'*)
    POOL_PARENT="$HOME/${ROOT_VALUE#\$HOME/}"
    ;;
  /*)
    POOL_PARENT="$ROOT_VALUE"
    ;;
  *)
    [ -n "$REPO_ROOT" ] || fail "relative root in $CONFIG has no repository context"
    POOL_PARENT="$REPO_ROOT/$ROOT_VALUE"
    ;;
esac

POOL_ROOT="$POOL_PARENT/.treehouse"
POOL_RESOLVED=$(/bin/realpath "$POOL_ROOT" 2>/dev/null) || fail "configured pool root does not resolve: $POOL_ROOT"
[ "$POOL_RESOLVED" = "$EXPECTED" ] || fail "configured pool root resolves to $POOL_RESOLVED instead of $EXPECTED"

unset TREEHOUSE_INHERITED_ADMISSION
exec "$REAL" launch-admitted --guarded-root "$POOL_RESOLVED" -- "$@"
