# Real-Device Dynamic Testing (Protect the Device and Restore Task-Owned Changes)

> Trigger: "real device plugged in, run real-device / serial validation". Complete the selected chain autonomously and persist measured evidence. **No operation may affect normal device operation**: no flashing, bootloader unlock, burn-overwrite, system-partition writes, rooting, recovery flashing, or Magisk installation. On the daily computer, use user-mode/read-only operations; kernel experiments belong in Windows/Linux VMs only.

## 0. Identify Hardware and Record the Baseline

```bash
adb devices -l
# macOS USB and serial inventory; use the platform's read-only equivalent elsewhere.
system_profiler SPUSBDataType | grep -E "Product|Vendor|Serial"
ls /dev/cu.* | grep -v Bluetooth
```

Rerun `python3 pipeline/env_scan.py` for the portable tool/version inventory and serial-port descriptors only; it does not read live phone identity, root status, application lists, or firmware details. Record live Android identity, root evidence, and application state separately through the explicit steps in §I.1–§I.2 and the change register below, or through the runner's device profile with an exact identity and `device-read` scope. Select the intended device serial and include `adb -s "$RE_DEVICE_SERIAL"` in every subsequent device command. With multiple devices, use the task's named device; never guess. If no device is detected, record "not detected; physical connection required" and finish without idle polling.

Before any mutation, write a task-owned change register under `输出/真机-<date>/`: selected serial, package existence/version, files copied by this task, spawned PIDs, and pre-existing frida/adb state. The existing output directory name is retained for compatibility. Do not overwrite a pre-existing temporary file or update a pre-existing user application merely to run the self-test.

## I. Android Phone Chain

Trigger: "phone plugged in, run real-device validation". Persist each step before proceeding.

1. **Identify**: query properties separately (a single `getprop` invocation does not read three property names):

   ```bash
   adb -s "$RE_DEVICE_SERIAL" shell getprop ro.product.cpu.abi
   adb -s "$RE_DEVICE_SERIAL" shell getprop ro.build.version.release
   adb -s "$RE_DEVICE_SERIAL" shell getprop ro.build.id
   adb -s "$RE_DEVICE_SERIAL" shell getprop ro.build.fingerprint
   adb -s "$RE_DEVICE_SERIAL" shell pm list packages -3
   adb -s "$RE_DEVICE_SERIAL" shell id
   ```

   Record installed package count and fingerprint as evidence for the device-fingerprinting article. Existing `su`/Magisk/KernelSU evidence is a candidate for root availability, not proof that `adbd` runs as root. Do not attempt to obtain root.

2. **Deploy frida-server only when existing root is available**:
   - Map Android ABI to release architecture (`arm64-v8a` → `arm64`, `armeabi-v7a` → `arm`, `x86_64` → `x86_64`), then select the matching server/client version under `tools-env/frida-server/`. Do not invent a missing binary name.
   - Copy the task's server only to a new `/data/local/tmp/re_fs` (or a task-unique `re_` name), then `chmod 755` that exact file. Register its path before starting and record its actual PID. Never write the system partition or unrelated user application data; the explicit temporary test directory is the only permitted deployment area.
   - On an already-rooted device, first check `adb shell id`; use the already available `su` route when appropriate. `adb root` is allowed only on the selected test device when its build supports root adbd; it restarts adbd, so preserve other active sessions and do not assume that the presence of `su` makes it succeed. If unavailable, use a gadget in a self-installed test APK or an emulator; do not force root.
   - Verify using `tools-env/.venv/bin/frida-ps -D "$RE_DEVICE_SERIAL"` (Windows: `.venv/Scripts/frida-ps.exe`). If the CLI needs a TTY, use the Python API: `frida.get_device(serial, timeout=10).enumerate_processes()` rather than repeatedly retrying the CLI.

3. **Run three dynamic checks on a self-installed test APK** (for example F-Droid only when it was absent before this task; otherwise choose a distinct test package). Injecting into system applications or non-test applications such as WeChat is forbidden:
   - Java-layer frida hook, such as `onCreate`, following a named article in `techniques/02-frida/java-layer/`.
   - Function-level `frida-trace` on the same test application, such as open-family calls; see `techniques/13-trace/`.
   - Block-level Stalker with an explicit `N`-block cap from [trace-practice.md](techniques/13-trace/trace-practice.md). Read its **Bundled driver scope** note first. Record the task-owned test APK's existing PID as `RE_TEST_PID`, a positive block limit as `RE_BLOCK_LIMIT`, and a task-local output path as `RE_TRACE_OUT`. Run `tools-env/.venv/bin/python techniques/13-trace/scripts/stalker_trace.py --device-serial "$RE_DEVICE_SERIAL" --pid "$RE_TEST_PID" --events block --limit "$RE_BLOCK_LIMIT" --out "$RE_TRACE_OUT"`. The adapter validates the selected process/main TID; use `--thread-id` only for a verified target thread. The limit counts received block events before filtering, so fewer rows may be persisted. Device mode has offline mock coverage, not a physical-device success claim; if transport/thread selection or execution cannot be verified, mark the check partial/unexecuted with its reason. Never run an unbounded trace.

4. **Mandatory cleanup: restore the recorded baseline**:
   - Stop only the exact frida/hook PIDs started by this task, after rechecking ownership. Keep any pre-existing service intact.
   - Remove only the exact temporary files copied/created by this task. Do not use a wildcard delete against all `re_*` files: another task may own them.
   - Uninstall the test APK only if this task installed it and it did not exist beforehand. Never unconditionally run `adb uninstall org.fdroid.fdroid`.
   - Stop adb only if this task started an otherwise unused adb server. Do not globally run `adb kill-server` while other sessions/devices use it.
   - Check the selected device's process/file register against its baseline and apply `test-values.md` §III: task-owned `[RE]`/`[REPROBE]`/`re_`/`REPROBE-` values must leave no live-device residue; retained task logs are evidence and remain on disk.

5. **Report**: include the three checks' measured outputs, cleanup results, and a comparison with emulator observations. Partial capability is explicitly marked with its reason.

## Apple/iOS: State-Preserving Evidence Collection

This route is read-only and separate from the Android test-APK chain. Select the exact UDID
and preserve the existing pairing, application, signing, and debugging state. Use already
available trusted interfaces only; inventory absence is not permission to prepare the device.

1. With an existing paired/trusted connection and installed `ideviceinfo`, collect identity via
   `ideviceinfo -u "<exact-udid>"`, or `re-run analyze --asset "ios://<exact-udid>" --type device`
   with a scope allowing that exact locator and `device-read`. The runner records identity only;
   it does not collect decrypted applications or prove instrumentation capability.
2. Inspect an existing user-supplied IPA/App/decrypted artifact offline. Retain original hashes,
   bundle/version/UUID, encrypted ranges, and any acquisition provenance. Do not infer a matching
   runtime image from a filename alone. Existing exported logs may be copied/read when that
   collection is within the task; preserve their source state and redact shared evidence.
3. If the task requires dynamic/decrypted evidence, report the exact missing interface,
   entitlement, authorized test build, or existing debug session. Missing pairing/trust, debug
   access, or decrypt capability is blocked/requires-environment with a concrete human setup
   action. A trust-dialog click, pairing change, or app installation is not an automatic fallback.
4. Do not copy or re-sign debugserver, change entitlements, re-sign/repackage an application,
   install Frida/Gadget/Tweaks, inject into an application, launch/kill it, jailbreak, or deploy
   a debugging service as part of this state-preserving route. Those methods in
   [iOS fundamentals](platforms/04-ios/ios-re-fundamentals.md) describe separate laboratory
   workflows and require a task that actually requests those changes on a suitable test setup.
5. Report measured identity/offline evidence, missing prerequisites, and the unchanged-state
   check. Do not describe an Android emulator or descriptor mock as iOS device validation.

## II. Microcontroller / Serial Chain

Trigger: "microcontroller plugged in, run serial validation".

1. **Read-only identification**: list ports; for ESP-family devices use `esptool.py --port <port> chip_id` / MAC / flash ID reads. For other devices, use read-only pyserial baud scanning from 9600 to 921600, reading 1s at each rate. Preserve DTR/RTS state; do not drive reset lines while opening a port.
2. **Read-only listening**: persist the logs continuously. A reset-button press is a physical operation; leave a to-do for the human.
3. **Analyze**: extract firmware/chip details and open the relevant article by name via `platforms/07-iot/` and the firmware playbook.

**Forbidden**: `write_flash`, `erase_flash`, `write_reg`, driving reset/enable pins, firmware burning, or any write that changes device state. The original prohibition on driving the documented `NES/RESET` pins is retained; do not interpret a misspelled pin label as permission to reset another pin.

## III. Daily Computer and Verified Items

- Previously measured user-mode checks: frida spawn/attach on local test CLI processes, Stalker, jadx/r2/androguard; dated evidence is in `techniques/05-toolbox/tool-field-notes.md`. Historical results are not a current availability probe.
- Forbidden on the daily machine: kernel extensions/SIP/kext loading, system-configuration changes, kernel-mode experiments. Use isolated Windows/Linux VMs and `platforms/01-windows/win-vuln/toolchain-setup.md` for those experiments.
