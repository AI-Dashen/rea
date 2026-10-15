#!/data/data/com.termux/files/usr/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage: run-frida-attach-probe.sh --package PACKAGE --server FILE --module-root DIR --output-dir DIR

Runs one authorized, attach-only Frida probe against an already-running,
non-system Android application. Requires an existing Magisk su grant. The
server listens only on 127.0.0.1 and all server/helper files are isolated in a
unique /data/local/tmp directory that is removed on exit.
USAGE
}

PACKAGE=
SERVER_SRC=
MODULE_ROOT=
OUTPUT_DIR=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --package) PACKAGE=${2-}; shift 2 ;;
    --server) SERVER_SRC=${2-}; shift 2 ;;
    --module-root) MODULE_ROOT=${2-}; shift 2 ;;
    --output-dir) OUTPUT_DIR=${2-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$PACKAGE" in
  ''|android|com.android.*) echo "SYSTEM_TARGET_DENIED" >&2; exit 65 ;;
esac
printf '%s' "$PACKAGE" | grep -Eq '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$' || {
  echo "INVALID_PACKAGE" >&2; exit 65;
}
[ -f "$SERVER_SRC" ] || { echo "FRIDA_SERVER_NOT_FOUND" >&2; exit 66; }
[ -f "$MODULE_ROOT/build/frida_binding.node" ] || { echo "FRIDA_BINDING_NOT_FOUND" >&2; exit 66; }
[ -f "$MODULE_ROOT/build/src/frida.js" ] || { echo "FRIDA_WRAPPER_NOT_FOUND" >&2; exit 66; }
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P)
SERVER_SRC=$(cd "$(dirname "$SERVER_SRC")" && printf '%s/%s\n' "$PWD" "$(basename "$SERVER_SRC")")
MODULE_ROOT=$(cd "$MODULE_ROOT" && pwd -P)

su -c 'id -u' | grep -qx '0' || { echo "ROOT_UNAVAILABLE" >&2; exit 77; }
su -c "cmd package path '$PACKAGE'" | grep -q '^package:' || {
  echo "PACKAGE_NOT_INSTALLED" >&2; exit 69;
}

TARGET_PID=
for candidate in $(su -c "pidof '$PACKAGE'" 2>/dev/null || true); do
  cmd=$(su -c "tr '\\000' '\\n' < /proc/$candidate/cmdline" 2>/dev/null | awk 'NF{print $1; exit}')
  if [ "$cmd" = "$PACKAGE" ]; then
    TARGET_PID=$candidate
    break
  fi
done
[ -n "$TARGET_PID" ] || { echo "TARGET_NOT_RUNNING" >&2; exit 69; }
TARGET_UID=$(su -c "cat /proc/$TARGET_PID/status" | awk '/^Uid:/{print $2}')
case "$TARGET_UID" in ''|*[!0-9]*) echo "TARGET_UID_UNREADABLE" >&2; exit 70 ;; esac
[ "$TARGET_UID" -ge 10000 ] || { echo "SYSTEM_UID_DENIED" >&2; exit 77; }

su -c "ss -ltn 2>/dev/null | grep -q ':27042 '" && {
  echo "UNMANAGED_FRIDA_SERVER" >&2; exit 73;
}
if su -c "find /data/local/tmp -maxdepth 1 -type f -name 'frida-helper*' -print -quit" | grep -q .; then
  echo "UNMANAGED_FRIDA_HELPER" >&2; exit 73
fi

SESSION_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
REMOTE_ROOT="/data/local/tmp/rea-frida-$SESSION_ID"
SERVER_DST="$REMOTE_ROOT/frida-server"
SERVER_LOG="$REMOTE_ROOT/server.log"
SERVER_PID_FILE="$REMOTE_ROOT/server.pid"
LOCAL_SERVER_LOG="$OUTPUT_DIR/frida-server.log"
CLEANED=0

cleanup() {
  [ "$CLEANED" -eq 0 ] || return 0
  if su -c "test -s '$SERVER_PID_FILE'"; then
    server_pid=$(su -c "cat '$SERVER_PID_FILE'" 2>/dev/null || true)
    case "$server_pid" in
      ''|*[!0-9]*) ;;
      *)
        server_cmd=$(su -c "tr '\\000' '\\n' < /proc/$server_pid/cmdline" 2>/dev/null | awk 'NF{print $1; exit}' || true)
        if [ "$server_cmd" = "$SERVER_DST" ]; then
          su -c "kill '$server_pid' 2>/dev/null || true"
        fi
        ;;
    esac
  fi
  sleep 1
  su -c "cat '$SERVER_LOG' 2>/dev/null" > "$LOCAL_SERVER_LOG" || true
  su -c "rm -f /data/local/tmp/frida-helper-*.dex /data/local/tmp/frida-helper-*.dex.* 2>/dev/null || true"
  su -c "rm -rf '$REMOTE_ROOT'"
  CLEANED=1
}
trap cleanup EXIT INT TERM

su -c "mkdir -m 700 '$REMOTE_ROOT' && cp '$SERVER_SRC' '$SERVER_DST' && chown root:root '$SERVER_DST' && chmod 700 '$SERVER_DST'"
SOURCE_HASH=$(sha256sum "$SERVER_SRC" | awk '{print $1}')
REMOTE_HASH=$(su -c "sha256sum '$SERVER_DST'" | awk '{print $1}')
[ "$SOURCE_HASH" = "$REMOTE_HASH" ] || { echo "SERVER_HASH_MISMATCH" >&2; exit 74; }

su -c "'$SERVER_DST' -d /data/local/tmp -l 127.0.0.1:27042 >'$SERVER_LOG' 2>&1 & echo \$! >'$SERVER_PID_FILE'"
sleep 2
su -c "ss -ltnp 2>/dev/null | grep '127.0.0.1:27042'" > "$OUTPUT_DIR/listener.txt"
printf '%s\n' \
  "package=$PACKAGE" \
  "pid=$TARGET_PID" \
  "uid=$TARGET_UID" \
  "cmdline=$PACKAGE" \
  "server_sha256=$SOURCE_HASH" \
  "remote_root=$REMOTE_ROOT" > "$OUTPUT_DIR/target-identity.txt"

timeout 60s node "$(dirname "$0")/frida-attach-probe.mjs" \
  --module-root "$MODULE_ROOT" \
  --endpoint 127.0.0.1:27042 \
  --package "$PACKAGE" \
  --pid "$TARGET_PID" \
  --output "$OUTPUT_DIR/frida-real-app-attach.json"

su -c "kill -0 '$TARGET_PID'"
su -c 'for n in zygote zygote64 system_server surfaceflinger; do for p in $(pidof $n 2>/dev/null); do printf "%s %s " "$n" "$p"; grep "^TracerPid:" /proc/$p/status; done; done' > "$OUTPUT_DIR/post-attach-system-tracers.txt"
if grep -Ev 'TracerPid:[[:space:]]*0$' "$OUTPUT_DIR/post-attach-system-tracers.txt" | grep -q .; then
  echo "SYSTEM_RUNTIME_TRACED" >&2
  exit 75
fi

cleanup
trap - EXIT INT TERM
su -c "test ! -e '$REMOTE_ROOT'"
! su -c "ss -ltn 2>/dev/null | grep -q ':27042 '"
printf '%s\n' 'ATTACH_PROBE_VERIFIED'
