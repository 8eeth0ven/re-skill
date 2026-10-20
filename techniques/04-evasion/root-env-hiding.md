# Root and Environment Hiding

> Topic: the hiding principles of Magisk/Zygisk/Shamiko/KernelSU/APatch, each one's ceiling, and the order of solutions for finance-grade detection stacks.

## 1. How Magisk + Zygisk + Shamiko interlock

### 1.1 Magisk's systemless foundation

- Magisk does not touch the /system partition; it **patches boot.img** (modifies the ramdisk, drops in init scripts and magiskinit). After boot:
 - `/data/adb/magisk/` is the main body; `magiskd` (daemon) stays resident;
 - It uses **overlay/bind mounts** to lay module files on top of `/system` (systemless modification); uninstall restores the original;
 - `su` requests go through `magiskd` → `magisk.db` (the grant database) for the verdict; the prompt appears in the Manager app.
- Weaknesses (from the detector's viewpoint): the mount table (/proc/mounts), the `/data/adb` path, and the replaced zygote (the app_process hijack history) are all scannable traces.

### 1.2 Zygisk: the official injection and hiding framework

- Zygisk = **Zygote + Magisk injection**: magiskd injects a loader into the zygote process; every time zygote forks an app process, the loader checks the DenyList:
 - Process on the DenyList → **injects nothing** and **unmounts (restores)** the mounts Magisk created for that process;
 - Not on it → injects the zygisk runtime, and each module (like Shamiko) gets a chance to run inside that app process.
- The DenyList's native semantics (built into Magisk, active with "Enforce DenyList" checked): **merely "no injection + unmount of system modifications"** — very shallow hiding of Magisk itself: magiskd is still alive, /data/adb is still there, props still leak.

### 1.3 Why MagiskHide died

- MagiskHide (v23 and earlier): did "unmount + environment cleanup" for target processes; it was the main force for passing SafetyNet/bank detection back then;
- v24+ upstream **removed it entirely**: the official reasons were that countering detection (especially Google Play Integrity grade) is an endless arms race, maintenance cost was high, and some hiding tricks conflicted with system stability; the weakened "no injection" behavior was left to the DenyList, and deep hiding was handed to the community (hence Shamiko).
- Status (2026): **MagiskHide is dead; the equivalent capability = Zygisk + Shamiko**. The community open-source replacement DenylistUnmount only restores mounts and is weaker than Shamiko.

### 1.4 Shamiko: deep hiding, closed-source

- Made by the LSPosed family, a **closed-source Zygisk module** that borrows the DenyList as its config (note: **turn OFF "Enforce DenyList"** — leaving it on actually conflicts; the Shamiko status must show a smiley face for it to work);
- Two modes:
 - **Blacklist mode** (default): for processes on the DenyList, hides more thoroughly than the native unmount — beyond unmounting it also hides Zygisk's own traces of existence (native bridge state, injection residue, some mount/props signals);
 - **Whitelist mode**: logic inverted — **all apps get root fully hidden by default (system apps included)**; only apps authorized via su can perceive/use root. A global one-size-fits-all approach with no per-app list maintenance; best for bank-type apps (die-hards like the 12123 traffic-management app). To grant an app under whitelist mode: `su <app uid> -c su` triggers the authorization prompt.
- Principle level (black-box observation + community RE, not official docs; details marked as such): Shamiko works at the instant zygote forks the target process — switching the mount namespace, umounting the magisk trees, cleaning props, faking state, so the detection code "sees a world" that is un-rooted; because it all happens before the app's first instruction executes, the app has no timing window to observe "the restoration process" first.
- Detecting Shamiko itself requires **indirect signals**: anomalous mount topology (the count/positioning of tmpfs in /proc/mounts deviating from the official-ROM statistical model), holes in the mount-id sequence of `/proc/self/mountinfo`, the tiny timing differences caused by Zygisk having injected then hidden — Medium has a 2025 "Detecting Shamiko" writeup (arnavsinghinfosec), whose approach is mount-namespace behavior statistics rather than signature matching.

## 2. How KernelSU / APatch differ from Magisk

### 2.1 KernelSU: kernel-space su

- Principle: **modify the kernel directly** — hook `execve`/`syscall` in the kernel (kprobe on GKI kernels or edit the source and compile); the su authorization verdict happens in kernel space:
 - app requests root → triggers the hook registered in the kernel → the kernel checks the authorization table (written by the manager) → executes directly with root credentials;
 - **No su binary in userspace, no magiskd, no overlay mounts** — ordinary root detection (scanning files/mounts/processes) has no target in userspace.
- Cost: needs a matching kernel (friendly on GKI 2.0 devices; painful on old models/modded kernels); once root is in the kernel it cannot be removed from userspace; poor support for old kernels (<4.14).
- Ecosystem: the module system is compatible with the Magisk module format; pair with **ZygiskNext** (an independent zygisk implementation, not dependent on magiskd) to complete the zygisk ecosystem.

### 2.2 APatch: KernelPatch + modularity

- Principle: **KernelPatch (KP)** — no kernel recompile; it directly **patches the kernel image** to inject capabilities (like Magisk patching boot.img, but "patching kernel.img"), achieving kernel-space root;
- Features: APM (APatch modules) + **KPM (Kernel Patch Module)** — can hook inside the kernel (syscall level); the key to counter when "the detector moves to svc";
- The usage experience aims at Magisk parity: patch boot and go, Manager UI, module ecosystem.

### 2.3 Cost-benefit verdict (2026 view)

| Solution | Detection surface | Onboarding cost | Fits |
|------|------|------|------|
| Magisk + Zygisk + Shamiko | mounts/props/package names (Shamiko covers most) | low (one-flash install) | most finance/risk-control apps |
| KernelSU + ZygiskNext | nearly no su traces in userspace | medium (find a matching kernel; low on GKI devices) | when detection is fierce / Magisk is ruled out |
| APatch | same as KSU + KPM kernel-hook bonus | medium | when kernel-space confrontation is needed |
General order: **Magisk+Shamiko first (cheap); if that fails switch to KernelSU (quieter); for kernel-grade offense-defense go APatch**.

## 3. HideMyApplist / Zygisk-Assistant

### 3.1 HideMyApplist (HMA)

- Positioning: an **Xposed/LSPosed module** hooking the `android.content.pm.PackageManager` family:
 - `getInstalledPackages` / `getInstalledApplications` (full enumeration — filter Magisk/LSManager/supersu package names out of the results);
 - `getPackageInfo` / `getApplicationInfo` (pointed probes — throw NameNotFoundException directly);
 - `queryIntentActivities` / `queryServices` / `getInstalledProviders` (the intent side channel);
 - `getPackagesForUid`, `getPermissionGroupInfo` and other long-tail APIs.
- Configuration granularity: per "detector app" templates (which batch of package names to hide from which app, blacklist/whitelist templated).
- **Ceiling**: only blocks the Java-layer PackageManager. It cannot stop:
 - the native layer directly listing the `/data/app` directory (root needed to list others' dirs, but it can stat-guess paths);
 - `pm list packages` via `Runtime.exec` → that goes through the pm command (whose output ultimately also comes from system_server's PMS — LSPosed's hook is inside the app process, pm is another process, **HMA cannot block the pm command**; you need a paired exec hook or a system-side solution);
 - non-PMS signals like `/proc/mounts` and props.

### 3.2 Zygisk-Assistant

- Positioning: a Zygisk module used alongside Shamiko; its core role is **reinforcing DenyList spawn isolation**:
 - handles the inherited-traces problem of "child processes forked/su-launched by DenyList processes";
 - makes the unmount more complete for listed processes (some scenarios Shamiko can't reach: secondary users / isolated processes);
- Relation to Shamiko: the common community combo against finance apps is the four-piece set "Zygisk + Shamiko + Zygisk-Assistant + HMA"; the Assistant turns off its own module signature, reducing the indirect signal "a Zygisk module exists".
- Details change fast between versions; defer to the project README (Dr-TSNG/Zygisk-Assistant).

## 4. The detections Shamiko cannot handle, and patches

### 4.1 Mount detection (residual surface)

- Shamiko restores mounts only for DenyList processes; **processes off the list (or authorized ones in whitelist mode) still see magisk traces in mounts**;
- Deeper detection: `statfs`/`statx` (svc-ized) reading `/system`'s filesystem magic and mount source; overlay traits (`overlay` fs magic 0x794c7630) and read-only tmpfs both work as signals;
- Patch direction: kernel-space solutions (KSU/APatch naturally have fewer mounts) or a KPM altering `statfs` returns; no userspace answer (svc is not hookable).

### 4.2 SELinux state

- Detection: `security_getenforce` / reading `/sys/fs/selinux/enforce`; the fiercer variant looks at the context in `/proc/self/attr/current` — a magisk-spawned process context may be `u:r:magisk:s0`;
- Shamiko does not change SELinux policy. Patch: `setenforce 1` to stay Enforcing + fine-grained `magiskpolicy` allowances (newer Magisk does this by default); do not go globally permissive.

### 4.3 props signatures (resetprop / MHPC)

High-risk props (detection = comparison):

```
ro.debuggable=1        → resetprop ro.debuggable 0
ro.secure=0            → resetprop ro.secure 1
ro.build.tags=test-keys → resetprop ro.build.tags release-keys
ro.boot.verifiedbootstate=orange → resetprop ro.boot.verifiedbootstate green
ro.boot.vbmeta.device_state=unlocked → locked
ro.boot.flash.locked=0 → 1
```
- Tool: `resetprop` (built into Magisk; changes prop values directly in memory — cleaner than editing build.prop; system props live in the `__properties` memory region, and resetprop changes the runtime view);
- **MagiskHide Props Config (MHPC)**: as a Magisk module, ships a fingerprint library of certified builds (swaps the whole build fingerprint per device model), countering "fingerprint blacklist" style detection (Play Integrity device integrity).
- Limitation: `ro.boot.*` comes from the kernel cmdline/boot stage; some detection reads `/proc/cmdline` directly (readable via svc), and resetprop cannot change the cmdline itself — a known residual surface.

### 4.4 Signature/package-name residuals

- The Manager's randomized package name counters pointed probes; but "full enumeration followed by APK-signature/trait recognition" requires HMA to block the enumeration itself;
- The `pm` command path: native `Runtime.exec("pm list packages -f")` — HMA cannot block it; hook `execve` and filter arguments (frida era) or use a system-side module.

## 5. Typical finance-app detection stacks and the solution order

### 5.1 Typical stack (bottom to top)

```
① Packer shell (Bangcle/Ijiami/Tencent Legu/Naga/Bangcle/360) — anti-debug + anti-injection + dex extraction
② In-house/commercial SDK environment sweep: root+frida+xposed+emulator+multi-instance+hook frameworks (Bangcle SecShell, Naga SecNeuro, NetEase Yidun, Dingxiang, Shumei, TongDun)
③ SSL pinning (okhttp+native dual layer, some mTLS)
④ Device fingerprint and risk-control reporting (even if you pass everything, an anomalous fingerprint still gets tagged)
```

### 5.2 Recommended solution order (environment first, injection second; cost increasing)

1. **Clean the environment layer first**: Magisk+Zygisk+Shamiko (whitelist mode) + HMA + Zygisk-Assistant, resetprop for props; installing KernelSU is even better — if the environment is dirty, however fancy your injection tools, they won't survive the first screen;
2. **De-featurize the injection layer**: zygisk-frida or an embedded gadget (frida-anti-detection.md §3); a bare frida-server is the last resort; pair with strongR/self-compiled de-featurization;
3. **Pass the shell**: patch/bypass the shell's anti-debug and anti-injection first (frida-anti-detection.md §2.3/§4.3), then do the dex dump;
4. **Pass pinning**: handle the network layer last (the layered scripts in ssl-pinning-bypass.md);
5. **Risk-control residuals**: passing ≠ leaving no trace; high-frequency operations still get tagged by behavioral fingerprints — keep the testing rhythm restrained.

## 6. Troubleshooting quick reference (symptom table for misconfigurations)

| Symptom | Common cause | Fix |
|------|------|------|
| Shamiko status not smiling (in the LSPosed manager) | "Enforce DenyList" is on | Turn the switch off and reboot |
| App can't get root under whitelist mode | Authorization flow not done | `su <uid> -c su` to trigger the prompt |
| After adding a system-cert module, capture breaks for the target app | DenyList unmount also restores the cert mounts | Take the target app out of the DenyList or exclude the module path |
| HMA configured but Magisk still visible | Detection goes through the pm command or native scanning | hook execve / switch to a system-side solution |
| 12123-class app still flash-exits | mounts or props residuals | §4 resetprop + MHPC; if still failing, switch to KernelSU |

## References

- Community post "Comparison and Deep Dive into Mainstream Android Root Solutions: Magisk and KernelSU"
- Medium "Detecting Shamiko" (2025)
