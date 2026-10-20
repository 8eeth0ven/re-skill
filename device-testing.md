# Real-Device Dynamic Testing (Auto-runs on Plug-in · Protects Real Devices)

> Goal: once a phone/microcontroller is plugged into the computer, a single trigger sentence runs the full real-device dynamic verification automatically. **Iron rule: no operation may affect the device's normal operation** — no flashing / no bootloader unlock / no burn-overwrite / no touching system partitions; the computer (the daily work machine) does user-mode and read-only operations only; kernel experiments go into VMs only.

## 0. Hardware Probing (run first every time, to see what got plugged in)

```bash
adb devices -l                                   # Android phone (USB debugging on)
system_profiler SPUSBDataType | grep -E "Product|Vendor|Serial"   # USB devices
ls /dev/cu.* | grep -v Bluetooth                  # Serial ports (microcontrollers / USB-to-serial)
```

After a device is detected, first re-run `python3 pipeline/env_scan.py` to save a snapshot with phone details (root/app list), then enter the chains below.

## I. Phones (Android Real-Device Chain)

Trigger: "phone plugged in, run real-device validation". The executor walks autonomously in order, saving each step's artifacts to `输出/真机-<日期>/`:

1. **Identify**: `adb shell getprop ro.product.cpu.abi ro.build.version.release ro.build.id` + installed package count; record the device fingerprint (as field evidence for the device-fingerprinting article)
2. **frida-server deployment (touch only /data/local/tmp, never the system)**:
   - `adb push <tools-env downloaded frida-server-<abi>> /data/local/tmp/fs` → `adb shell chmod 755 /data/local/tmp/fs`
   - Rooted device: start it after `adb root`; non-root: use **gadget injection**, or verify at the emulator layer only for now (don't force it without root)
   - Verify: `.venv/bin/frida-ps -U | head`
3. **Three dynamic live shots** (against a **self-installed test APK** such as F-Droid; injecting into system apps or real apps like WeChat is forbidden):
   - frida hook at the Java layer (following any article in `techniques/02-frida/java-layer/`, e.g. hook onCreate and print)
   - frida-trace at function level (attach to the test app, trace open-style calls; cross-reference `techniques/13-trace/`)
   - Stalker at block level with volume capping (following the trace-practice.md script, limited to N blocks)
4. **Wrap-up (mandatory, restore original state)**: `adb shell kill <frida-server pid>`; uninstall the test APK (`adb uninstall org.fdroid.fdroid`); `adb kill-server`; confirm `ps | grep fs` is empty; per test-values.md §III, grep [RE]/re_ prefixes to confirm zero test residue on device and artifacts
5. Report: key real outputs of the three shots + a table of differences versus emulator results

**Red lines**: no rooting (unless the device is already rooted) / no recovery flashing / no Magisk / no touching the user-data partition / no injecting into non-test apps.

## II. Microcontroller / Serial-Device Chain

Trigger: "microcontroller plugged in, run serial validation":

1. **Identify (fully read-only)**: list serial ports; `esptool.py --port <p> chip_id` (ESP-family read-only) / read MAC/flash_id; for non-ESP use pyserial baud-rate scanning (9600-921600, read 1s each) to find a port+rate with output
2. **Listen (read-only)**: continuously read logs to disk (pressing the reset button is a physical operation → leave a to-do for the human)
3. **Analyze**: firmware version/chip model in the logs → cross-reference the article list in `platforms/07-iot/` to pick follow-up (e.g. for an IoT chip, evaluate per the firmware breach table)
**Prohibitions**: `write_flash/erase_flash/write_reg` are all forbidden; driving NES/RESET pins is forbidden (physical).

## III. Computer (This Machine) Discipline and Verified Items

- **Verified** (user-mode safe, don't re-risk): frida spawn/attach on local CLI processes, Stalker, the full jadx/r2/androguard set — see `techniques/05-toolbox/tool-field-notes.md`
- **Forbidden**: kernel extension loading (SIP/kext), changing system configuration, any kernel-mode experiments → Windows/Linux VMs only (toolchain in `platforms/01-windows/win-vuln/toolchain-setup.md`)

## IV. Hookup

Unattended trigger sentence: "real device plugged in, run real-device / serial validation" → follow this document autonomously; if no device is detected, report "not detected, plug in and retry" instead of spinning idle.
