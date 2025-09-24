#!/system/bin/sh

MODDIR=${0%/*}
LOGTAG=sfrotate
LOGFILE="$MODDIR/sfrotate.log"

# Make sure PATH is sane for toys like pidof/ps/log
export PATH=/system/bin:/system/xbin:/apex/com.android.runtime/bin:$PATH

INJECTOR="/system/bin/sfrotate_dlopen64"
LIB="/system/lib64/libsf_rotate.so"

# Fallback to module overlay paths if /system overlay not visible yet
[ -x "$INJECTOR" ] || INJECTOR="$MODDIR/system/bin/sfrotate_dlopen64"
[ -f "$LIB" ] || LIB="$MODDIR/system/lib64/libsf_rotate.so"

say() {
  log -t "$LOGTAG" "$@"; echo "$(date +'%F %T') $@" >>"$LOGFILE";
}

wait_for_sf() {
  local pid
  for i in $(seq 1 120); do
    pid=$(/system/bin/pidof surfaceflinger 2>/dev/null)
    [ -n "$pid" ] && { echo "$pid"; return 0; }
    sleep 1
  done
  return 1
}

already_injected() {
  local pid="$1"
  grep -q "libsf_rotate.so" "/proc/$pid/maps" 2>/dev/null
}

inject_once() {
  local pid="$1"
  if [ -z "$pid" ] || [ ! -r "/proc/$pid/maps" ]; then
    say "inject: bad pid '$pid' or cannot read /proc/$pid/maps"
    return 1
  fi
  if already_injected "$pid"; then
    say "already injected into pid $pid"
    return 0
  fi

  say "injecting: pid=$pid  injector=$INJECTOR  lib=$LIB  ctx=$(id -Z) selinux=$(getenforce)"
  # Capture injector stdout/stderr to log
  "$INJECTOR" surfaceflinger "$LIB" 2>&1 | while IFS= read -r line; do
    say "[injector] $line"
  done
  local rc=${PIPESTATUS[0]}
  if [ $rc -eq 0 ]; then
    say "inject OK (pid $pid)"
  else
    say "inject FAILED rc=$rc"
  fi
  return $rc
}

loop_reinject() {
  local last=""
  while true; do
    sleep 5
    pid=$(/system/bin/pidof surfaceflinger 2>/dev/null) || pid=""
    [ -z "$pid" ] && continue
    if [ "$pid" != "$last" ]; then
      say "surfaceflinger pid change: $last -> $pid"
      inject_once "$pid"
      last="$pid"
    fi
  done
}

main() {
  say "service start (uid=$(id) ctx=$(id -Z) selinux=$(getenforce))"
  say "paths: INJECTOR=$INJECTOR  LIB=$LIB"
  [ -x "$INJECTOR" ] || say "WARN: injector not executable"
  [ -f "$LIB" ] || say "WARN: lib not found"

  pid="$(wait_for_sf)" || { say "surfaceflinger not found within timeout"; exit 0; }
  say "found surfaceflinger pid=$pid"
  inject_once "$pid"

  # --once mode for manual testing exits after first attempt
  if [ "$1" = "--once" ]; then
    say "--once specified, exiting"
    exit 0
  fi

  loop_reinject
}

# Run in background so Magisk doesn’t block; keep logs flowing
main "$@" &
