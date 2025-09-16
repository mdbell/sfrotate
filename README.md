# sfrotate

This is a solution to the retroid dual screen being 'sideways' on AYN Odin devices. It will perform two seperate patches to [SurfaceFlinger](https://source.android.com/docs/core/graphics/surfaceflinger-windowmanager#surfaceflinger)

1. Force the hardware compositor to report that `OptionalFeature::PhysicalDisplayOrientation` is supported
2. Replace the contents of `getPhysicalDisplayOrientation` to always report:
   - The primary display has a rotation of 0 (no rotation)
   - External displays will report a rotation of 270 (configurable, uses the same prop as specfied by Retroid [here](https://github.com/RetroidPocket/Retroid_Dual_Screen_Add-on_Support) - `persist.panel.rds.orientation`)

All changes are done in-memory, so there is minimal risk to the Android OS. The downside to this is that the root script(s) will need to be re-run after every reboot.

## Native injector

This is the preffered method of using sfrotate - as it requires no PC or commands to be entered over abd.

1. Download the latest release from [here](https://github.com/mdbell/sfrotate/releases)
2. Extract to the root of your Odin sdcard
    - You should have `/sdcard/inject.sh` and `/sdcard/sfrotate/` now on your sd card
3. On your device, nativate to `System Settings` -> `Odin Settings` -> `Run script as Root`
4. Select the `inject.sh` to run it
5. After the script has completed, disconnect and reconnect the retroid display.

If the inject script has worked as intended, your display should now be correctly rotated. Any changes to the rotation via the prop will also require a disconnect/reconnect to be applied. The inject script does _not_ need to be run a second time.

## Frida

Frida scripts are no longer recommended for the end-user, and should only be used for development purposes.