#!/bin/bash
set -euo pipefail

# --- Config ---
OUTPUT_ZIP="${OUTPUT_ZIP:-sfrotate-standalone.zip}"
INJECTOR_BIN="build/dlopen64"          # your compiled injector
HOOK_SO="build/libsf_rotate.so"        # your compiled hook .so

# --- Sanity checks ---
[[ -f "$INJECTOR_BIN" ]] || { echo "Missing $INJECTOR_BIN"; exit 1; }
[[ -f "$HOOK_SO" ]]      || { echo "Missing $HOOK_SO"; exit 1; }

# --- Temp module root ---
ZIP_DIR="$(mktemp -d)"
trap 'rm -rf "$ZIP_DIR"' EXIT

# --- Create module layout ---
mkdir -p \
  "$ZIP_DIR/system/bin" \
  "$ZIP_DIR/system/lib64" \
  "$ZIP_DIR/system/etc/init"

# module.prop
cat > "$ZIP_DIR/module.prop" <<'PROP'
id=sfrotate
name=sfrotate (standalone autoinject)
version=1.0
versionCode=1
author=mdbell/matt123337
description=Autoload libsf_rotate.so into SurfaceFlinger on boot/restart
PROP


install -m 0755 magisk/service.sh "$ZIP_DIR/service.sh"

# --- Drop binaries ---
cp "$INJECTOR_BIN" "$ZIP_DIR/system/bin/sfrotate_dlopen64"
cp "$HOOK_SO"      "$ZIP_DIR/system/lib64/libsf_rotate.so"

chmod 0755 "$ZIP_DIR/system/bin/sfrotate_dlopen64"
chmod 0644 "$ZIP_DIR/system/lib64/libsf_rotate.so"

# --- Build the zip ---
(
  cd "$ZIP_DIR"
  zip -r9 "$OLDPWD/$OUTPUT_ZIP" .
)

echo "Built $OUTPUT_ZIP"
echo
echo "Install with:"
echo "  adb push $OUTPUT_ZIP /data/local/tmp/"
echo "  adb shell su -c 'magisk --install-module /data/local/tmp/$OUTPUT_ZIP'"
echo "  adb shell su -c 'rm /data/local/tmp/$OUTPUT_ZIP'"
echo "  adb reboot"
