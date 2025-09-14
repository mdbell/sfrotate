# Install Instructions

Note: This runs a program that gives anything that has access to `adb` complete access to all processes and their memory.

These instructions are just the commands I did on my PC, and some commands run on the Odin

## Odin Setup

1. Save the `frida.sh` file to `/sdcard/frida.sh`
2. Download `frida-server-17.2.17-android-arm64.xz` from (here)[https://github.com/frida/frida/releases]
3. extract the binary from the above file, and save it to `/data/local/tmp/frida`
4. Run the `frida.sh` script via the Odin's root script options
5. Enable developer settings on your device
  - Tap build number 7 times in a row (in "About handheld console" in the settings app)
6. In "Developer Options" enable wireless debugging, and setup adb with your PC (there's better guides out there then whatever I can write)

## PC setup

1. `pip install frida-tools` - python command, I used the one that shipped with my linux machine (may work on windows, YMMV)
2. Save `rotate.js` from this repository to your PC
3. Connect to your odin from your PC via adb (`adb connect ODIN_IP_HERE:PORT_FROM_WIRELESS_DEBUGGING_SETTINGS)`)
4. run the command `frida -U -n surfaceflinger -l rotate.js`

You should see output like:
```
[*] Using module: surfaceflinger 0x5bc4380000 size 6471680
[+] hook isSupported HIDL @ 0x5bc44b9e2c
[+] replace getPhysicalDisplayOrientation (out*) HIDL @ 0x5bc44c03d4
[+] hook isSupported AIDL @ 0x5bc448f204
[+] replace getPhysicalDisplayOrientation (out*) AIDL @ 0x5bc44b0440
[+] replace HWComposer::getPhysicalDisplayOrientation (ret) impl @ 0x5bc44d9ed0
[+] Installed: correct Transform bitflags; primary=0°, non-primary=forced
```

If you do, disconnect and reconnect the external display. It should be rotated correctly.
