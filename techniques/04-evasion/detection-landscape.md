# Detection Landscape

> A map of Android anti-analysis detection principles, organized by "the detecting side". Written all the way down to the syscall / memory-layout layer.

## 0. Overview: the layer a detection fires from decides how hard it is to bypass

```
Difficulty increases downward (the lower, the harder to bypass):
Java API  <  JNI wrappers  <  libc/syscall wrappers (NR_xxx)  <  direct svc syscalls (inline asm)
   |            |                 |                                  |
 hookable    hookable           hooking must cover the             cannot be intercepted with frida Interceptor
 (ART layer) (RegisterNatives)  so's dependencies (PLT/GOT)        only patch instructions or go kernel-side
```

Rules of thumb for telling them apart:
- Detection logic written in Java (`PackageManager`, `System.getProperty`, `Debug.isDebuggerConnected`) → Java layer; frida `Java.use` kills it in one shot.
- Detection lives in a so but calls libc functions such as `fopen/open/strstr` → native layer over libc wrappers; `Interceptor.attach(Module.findExportByName("libc.so","open"))` can intercept it.
- The so contains `svc #0` inline asm plus hand-built syscall numbers (x86_64 `rax=2` is open, arm64 `x8=56` is openat) → direct svc syscalls; every userspace hook is dead, you must change approach (patch the so / rewrite instructions with Stalker / kernel space).
- The same check is often written once per layer (a round in Java, another in native, svc at the critical spots); bypassing only the Java layer gets you nothing but a "false negative".

## 1. Anti-debug detection

### 1.1 The ptrace family (native layer)

**Self-attach (self-ptrace)**: at process startup, fork a child; the child calls `ptrace(PTRACE_TRACEME, 0, 0, 0)` and then attaches to the parent. Linux allows only one tracer per process at a time — afterwards IDA/gdb/frida attaching fails outright (`Operation not permitted`).

```c
// typical self-attach skeleton
pid_t child = fork();
if (child == 0) {
    ptrace(PTRACE_ATTACH, getppid(), 0, 0); // occupy the parent's tracer slot
    waitpid(getppid(), NULL, 0);
    for(;;) ptrace(PTRACE_CONT, getppid(), 0, 0);
}
```

**PR_SET_DUMPABLE**: `prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)` marks the process non-dumpable. Effect: processes that are neither root nor same-uid cannot ptrace it, and files such as `/proc/<pid>/maps` become unreadable (EACCES). That is what a debugger sees before attaching. Bypass: hook `prctl`, or in a root environment simply SIGKILL the watchdog process.
**/proc/self/status TracerPid**: read `/proc/self/status`, find the `TracerPid:` line; a non-zero value means the process is being debugged. On the libc layer it is `open/read`; on the Java layer it is `FileInputStream`. Source-code anchor: this line is generated live by the kernel's `fs/proc/array.c` `task_state()` (proc files are not on-disk files; every read assembles the content on the spot), so userspace cannot change the "source". The bypass can only launder "the copy the detector reads": hook `read`/`fgets` and rewrite the returned buffer, or hook `open` and redirect the path to your own forged status file; a version that reads via direct svc openat is the same story — the forgery must land at the buffer layer (patch so / Stalker). There is no userspace shortcut to "changing the kernel's output".
**Signal probing**:
- SIGTRAP: proactively `raise(SIGTRAP)`; if the process is being debugged and no handler is set, the debugger swallows the signal and the expected behavior never happens — used to probe software breakpoints (`int3` / `brk #0`).
- Software-breakpoint detection: the anti-debug side `mprotect`s its own critical function addresses and byte-reads the function prologue, comparing against the original instructions (same principle as the inline-hook detection in §2.6).
- SIGPIPE / timing deltas: timestamp around a breakpoint; `ptrace` single-stepping introduces millisecond-level delay, detected via the `clock_gettime(CLOCK_MONOTONIC)` delta.

### 1.2 Java layer

- `android.os.Debug.isDebuggerConnected` / `waitingForDebugger`: reads the ART internal global `Dbg::gRegistry` state. Just hook it to return false.
- `ApplicationInfo.FLAG_DEBUGGABLE`: `getApplicationInfo.flags` checks whether the manifest enabled debuggable. When frida spawns a release package the bit is still 0, but the check is usually stacked with the `ro.debuggable` system property (`SystemProperties.get`).
- With `android:debuggable=true`, ART runs in the JIT-debuggable mode and `jdwp`-related threads appear in `/proc/self/maps`; a more low-level equivalent check is natively scanning `/proc/self/task/<tid>/comm` for the `JDWP` thread name.

### 1.3 Native debug ports

JDWP goes over `adb forward tcp:PORT jdwp:<pid>` by default. Detection: search `/proc/net/tcp` for LISTEN loopback ports, or try `connect` to 8700 (the ddms base port). A process jdb can attach to = a debuggable process.

## 2. Frida detection (the core)

### 2.1 Network layer: ports and protocol signatures

- frida-server listens on **27042** by default (control) and 27043. Detection code `connect(fd, 27042)` succeeding is a hit; the cruder variant sweeps the entire `127.0.0.1:27000-27100` range.
- `/proc/net/tcp` (the kernel-maintained socket table): column 2, local_address, is `HEX:69A2` (27042=0x69A2); the native layer uses `fopen("/proc/net/tcp")` and strstr's each line. **Hooking connect does not block this path** — it never sends a packet, it only reads the kernel table.
- Protocol layer: the frida control channel is a **private D-Bus variant**. Send a malformed D-Bus AUTH message to 27042 and frida-server's error reply carries the word `frida` (the `frida:rpc` RPC identifier appears during session negotiation). xxr0ss/AntiFrida's implementation is exactly this: connect, then receive and match signatures.
- Bypass: frida-server `-l 0.0.0.0:<random port>` / `fs -l` to change the listen address; see frida-anti-detection.md.

### 2.2 Filesystem layer: /proc/self/maps scanning (most common)

After frida attaches, the target process's `/proc/self/maps` necessarily gains lines like these:

```
7e8b4b1000-7e8b4b3000 r-xp 00000000 fd:01 ... /data/local/tmp/frida-agent-64.so  (on-disk path in older versions)
7a2c000000-7a2c200000 rwxp 00000000 00:00 0                                    (frida-agent anonymous mmap, rwxp!)
```

Detection implementations (watch both layers):

```java
// Java layer: read the file line by line
BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
while ((line = br.readLine()) != null)
    if (line.contains("frida") || line.contains("gadget")) return true;
```

```c
// Native layer: fopen + fgets + strstr; advanced versions use direct svc openat to bypass hooks (see 2.9)
FILE* f = fopen("/proc/self/maps", "r");
while (fgets(buf, sizeof buf, f))
    if (strstr(buf, "frida-agent") || strstr(buf, "re.frida.server")) hit();
```

Advanced signature: **anonymous executable mappings with rwxp and file offset=0**. A normal app almost never has an anonymous segment that is readable, writable and executable at the same time (the ART JIT segment is rwx but has a name/alignment signature); frida-agent, gadget, and most injection-style hook frameworks all land via `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`. This check is filename-independent — renaming the so does not fool it; you must change the loading method (see "renaming in memory" and the soinfo unhooking in the countermeasures doc).

### 2.3 Memory layer: signature-string scanning

Even if the maps entry is renamed, the memory content still carries the stock strings. The detector:
1. Parses maps to find suspicious segments (rwxp / or all readable segments);
2. Scans page by page via `pread`/direct pointer dereference, searching for:
 - `"frida:rpc"` — the RPC protocol magic (hardcoded in frida-core/lib/interfaces/session.vala);
 - `"LIBFRIDA"`, `"frida-agent-64.so"`, `"frida-gadget"`;
 - `"re.frida.server"` — frida-server's working-directory name (server.vala);
 - `"linjector-"` — the temporary pipe prefix created at injection time (linux-host-session.vala);
 - `"FridaScriptEngine"`, `"GLib-GIO"`, `"GDBusProxy"`, `"GumScript"` — GType class names registered by Glib/Gum.
The corresponding bypass is the community post's de-featurization checklist: when self-compiling, replace all these strings with equal-length random strings, or replace them in memory at runtime (countermeasures doc §1.3).

### 2.4 Thread layer: enumerating thread names under /proc/self/task

After frida injects, the process gains these extra pthreads whose `comm` names are fixed:

| Thread name | Origin |
|------|------|
| `gmain` | GLib main event loop (GMainContext) |
| `gum-js-loop` | Gum JS engine message loop (frida script runtime) |
| `gdbus` | GLib D-Bus thread (the frida control channel uses a D-Bus variant) |
| `pool-frida` | GLib GThreadPool worker threads |
Detection: `opendir("/proc/self/task")`, iterate every tid, read `/proc/self/task/<tid>/comm`, or use `pthread_getname_np`. The native opendir may also be svc-ized. Bypass: hack the frida source to change prgname/thread names, or hook `prctl(PR_SET_NAME)` (pthread_setname_np bottoms out in it).

### 2.5 Symbol layer: dlsym / so symbol-table iteration

- `dlsym(RTLD_DEFAULT, "frida_agent_main")`: the entry symbol exported by frida-agent; non-NULL is a hit. Bypass: strip/rename the exported symbol.
- Hand-parse the ELF header of every so in maps: a so that `dlopen` does not need can still be `open`ed + `pread` to read `.dynsym/.dynstr`, looking for `frida`, `gum_`, `g_hook` prefixed symbols. **Note it calls no dynamic-linking libc API — pure static file parsing**, so hooking dlsym is useless.
- `dl_iterate_phdr` enumerates the loaded so list (both glibc and bionic have it); more "orthodox" than reading maps, and the returned `dlpi_name` contains the frida path.

### 2.6 inline hook detection (function-prologue CRC)

How frida `Interceptor.attach` works: it replaces the first few instructions of the target function with a trampoline (on arm64 typically `ldr x17, #8; br x17; <8-byte target address>`, i.e. a 16-byte shellcode jump). The detector verifies the critical functions (its own detection functions in the so, libc's open/read/strstr):
1. At startup, hash (CRC32/custom hash) the first N bytes of the function and store it;
2. Recompute periodically; a mismatch = inline-hooked;
3. Or match the instruction pattern directly: first 4 bytes of the function == `0x58000051` (the ldr x17 signature) on arm64, `0xE9` (jmp rel32) / `0xFF 0x25` (jmp [rip+xx]) on x86.
Bypass: use Stalker instead of Interceptor (leaves original instructions untouched), or `mprotect`-restore before calling (countermeasures doc §4).

### 2.7 System layer: ps process iteration

Native `popen("ps -ef", "r")` or reading `/proc/<pid>/cmdline` iterates all processes, matching keywords like `frida-server`, `gum-js-loop`, `gdbserver`, `gdb`. Bypass: rename frida-server to something innocuous (`crond`, `dhd`). Note frida-server's thread names also leak in `ps` output (`ps -T`); if renaming the process name alone is not thorough, use `setsid + rewrite argv[0]`.

### 2.8 JNI layer: RegisterNatives / loadLibrary detection

- Hook `RegisterNatives` (ART's `art::JNI::RegisterNatives`) to watch whether registered native methods have been rewritten: frida's `Java.use.method.implementation = ...` does not touch the RegisterNatives table (it goes through ART's CodeItem replacement / entrypoint rewriting), but it leaves traces on the ArtMethod.
- Detect whether a native method is still native code: take the ArtMethod's entry_point_from_jni_ pointer and compare whether the function prologue was modified (back to the CRC idea of §2.6, only the object is now an ART method entry).
- When `System.loadLibrary` has been replaced by a self-implemented dlopen (some packers ship their own linker), frida's Java hooking depends on symbols in libart; a self-implemented linker makes frida's Java bridge binding fail — that is one way "packers kill frida's Java layer".

### 2.9 Direct svc syscalls: the detector's ultimate form

Every libc-based detection above (`fopen`/`strstr`/`opendir`/`connect`) can be hooked by frida. So advanced detections issue the critical syscalls directly with inline asm:

```c
// arm64: direct openat + read of /proc/self/maps, without going through libc.open
long raw_openat(const char *path) {
    long fd, path_adr = (long)path;
    asm volatile(
        "mov x8, 56\n"        // __NR_openat
        "mov x0, -100\n"      // AT_FDCWD
        "mov x1, %0\n"
        "mov x2, 0\n"         // O_RDONLY
        "svc #0\n"
        "mov %0, x0\n"
        : "+r"(fd) : "r"(path_adr) : "x0","x1","x2","x8");
    return fd;
}
```

`svc #0` traps straight into the kernel; there is no userspace function call left to hook. Only three counter paths remain:
1. **frida Stalker** traces the instruction stream and rewrites dynamically at the svc instruction (countermeasures doc §4.1);
2. **patch the so**: statically NOP out the detection function (locate it first, with IDA);
3. **kernel-space interception** (KernelSU + KPM hooking sys_openat results) — research-grade.
xxr0ss/AntiFrida's complete implementation is exactly "svc-ized maps scanning + in-memory search for frida:rpc" — usable as a detector-side sample codebase.

## 3. Root detection

### 3.1 File layer

- **su file sweep**: a hardcoded list of paths probed one by one with `access(F_OK)`: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/system/sd/xbin/su`, `/system/app/Superuser.apk`, `/data/local/xbin/su`, `/data/local/bin/su`… Java layer `File.exists`, native layer `access/stat` (which may also be svc-ized).
- **which/busybox**: `Runtime.exec("which su")` and check output; the mere existence of a busybox binary is itself a weak signal.
- **magisk files**: `/data/adb/magisk/`, `/data/adb/magisk.db` (the grant database), `/data/magisk`, the randomized-package-name magisk manager APK path. After MagiskHide the official side already supports package-name randomization; detection mostly relies on the mounts and properties below.

### 3.2 Mount layer (the key against systemless root)

Magisk's systemless modifications **sit on top of /system via overlay/bind mounts**, so `/proc/mounts` (the userspace view of the kernel mount table) leaks:
- anomalous mounts containing `magisk`, or `tmpfs on /sbin` types;
- overlay entries: `overlay / ... upperdir=/data/adb/...`;
- tmpfs mounted by Magisk showing up at non-standard mount points.
Detection implementation: `open("/proc/mounts")` then strstr each line ("magisk" / "core/mirror" / "core/modules"). **This is exactly why MagiskHide/Shamiko's core move is unmounting** (see root-env-hiding.md §1). Cross-checking stat against mounts: `stat("/system/bin/su")` reports it exists, but once the corresponding overlay in `/proc/mounts` is unmounted it no longer does.

### 3.3 Property layer

`__system_property_get` / `SystemProperties.get`:
- `ro.debuggable=1` (userdebug/eng builds);
- `ro.secure=0` (adb running as root);
- `ro.build.tags=test-keys` (unofficial-signed ROM; release builds are release-keys);
- `ro.build.selinux=0`;
- `ro.boot.verifiedbootstate=orange` (bootloader unlocked; locked is green) — Google Play Integrity uses this same batch of signals.
- `ro.hardware` doubles as an emulator check (§4).

### 3.4 SELinux state

`getenforce` equivalent: `security_getenforce` (libselinux) reads `/sys/fs/selinux/enforce`. Rooting solutions often set SELinux permissive to get things through, so `Enforcing` becoming `Permissive` is a weak signal. Newer Magisk no longer forces permissive (it punches holes with magiskpolicy), so "permissive = root" is no longer reliable, but it remains a common detection point.

### 3.5 PackageManager layer

Java-layer enumeration of installed packages (the root & framework governance entry):
- Historical package names: `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.koushikdutta.superuser`, `de.robv.android.xposed.installer`, `org.lsposed.manager`;
- Detection methods: full iteration of `getInstalledPackages` / per-name probing with `getPackageInfo(pkg, 0)` / `queryIntentActivities(new Intent("de.robv.android.xposed..."))`.
- Magisk "Hide the app" = randomized package name + label; effective against `getPackageInfo(<specific name>)`, ineffective against "full iteration followed by heuristically recognizing manager traits (versionName, APK signature, activity structure)". HideMyApplist hooks exactly this layer (countermeasures doc §3, root-env-hiding.md).

### 3.6 Signature and integrity

- APK signature verification: read own `PackageManager.GET_SIGNATURES` and compare against a hardcoded signature hash, against repackaging (adding detection code means re-signing, and re-signing gets noticed). Counter: hook `getPackageInfo` to return a forged signature, or natively read the memory mapping of base.apk in `/proc/self/maps` and compute the hash yourself (bypassing the Java hook).
- `/proc/self/cmdline` + `Settings.Secure.ANDROID_ID` and similar combinations build a device fingerprint used by risk control to tag "this device was found carrying injection tools".

## 4. Emulator detection

### 4.1 CPU/hardware fingerprint

- `/proc/cpuinfo`: the `Hardware` field containing `goldfish`, `ranchu` (Android Studio AVD); `GenuineIntel` + specific microcode is also used to identify cloud real-devices/sandboxes.
- `ro.hardware` = `ranchu`/`goldfish`/`vbox86`/`dolphin` (SDK emulator images); `ro.product.model` = `sdk_gphone64_x86_64` etc.
- `ro.kernel.qemu=1` (the qemu flag), `ro.bootmode=unknown`, `ro.factorytest`.

### 4.2 Sensors and battery (behavioral layer)

- Light sensor/accelerometer stuck at constant values, or the set of readings has only a few discrete values (the emulator feeds fake data);
- Battery `ACTION_BATTERY_CHANGED`: emulators usually report a constant `STATUS_CHARGING` + fixed level (50%), zero voltage/temperature;
- `TelephonyManager.getDeviceId` returns an all-0 / all-A IMEI, `getNetworkOperatorName` empty. Cloud real-devices (Red Finger etc.) have fake data for all of these; you must rely on statistical features of sensor noise (entropy). The detector's advanced approach runs Fourier/entropy analysis on accelerometer samples.

### 4.3 qemu pipes and network

- Existence of `/dev/qemu_pipe`, `/dev/socket/qemud`, `/dev/goldfish_pipe` = hard evidence of the qemu family (AVD uses them for host-guest communication).
- Network range: under emulator NAT the gateway is fixed at `10.0.2.2` (the host) and DNS `10.0.2.3`. Detect via `NetworkInterface.getInterfaceAddresses` or just `connect`-testing.
- `ethernet` interface named `eth0` with no `wlan0` (real devices always have wlan); MAC prefix `08:00:27` (VirtualBox).

## 5. Environment detection (VPN/proxy/Xposed/accessibility/screen recording)

### 5.1 Proxy and VPN

- Proxy: `System.getProperty("http.proxyHost")` / `"http.proxyPort"` (one line in the Java layer); the native layer reads the `http_proxy` environment variable; OkHttp follows `ProxySelector.getDefault` by default — the moment a capture tool turns on the system proxy it hits. Bypass: frida-hook `System.getProperty` + `ProxySelector.select` to return DIRECT, or objection's proxy-related hooks.
- VPN: `ConnectivityManager.getActiveNetwork`'s `NetworkCapabilities` contains `TRANSPORT_VPN`; `NetworkInterface.getNetworkInterfaces` shows `tun0`/`ppp0` (Burp/surtru/Sentinel all create tuns). **Bypassing tun0 detection is harder than bypassing proxy detection**: hooking `getNetworkInterfaces` means forging the whole enumeration chain, and the native layer can also `ioctl(SIOCGIFCONF)` to ask the kernel directly.

### 5.2 Xposed / LSPosed

- Stack-trace detection: search `Log.getStackTraceString(new Throwable)` for `de.robv.android.xposed.XposedBridge` — the hookMethod call stack leaks when Xposed hooks (LSPosed already scrubs stacks).
- Class existence: `Class.forName("de.robv.android.xposed.XposedBridge")`; hooking `getClassLoader` blocks the full sweep.
- Native layer: scan maps for `riru`, `lspd`, zygisk injection traces; anomalous `epoll` fds (extra listeners in zygote after Riru injection).
- `deoptimizeXxx` traces: Xposed makes methods fall back from JIT-compiled state to the interpreter (de-optimization); the detector reads ART's `kAccCompileDontBother` flag to tell whether a method was touched. This is a whitebox-layer detection idea.

### 5.3 Accessibility and debug state

- Accessibility services: `Settings.Secure.getString(ACCESSIBILITY_ENABLED)` = "1", and automation tools (auto.js/airtest) appearing in the `ENABLED_ACCESSIBILITY_SERVICES` list; a key check in finance apps' anti-fraud-warfare.
- `adb_enabled`: `Settings.Global.getInt("adb_enabled")` (developer options - USB debugging).
- USB connection state: `BatteryManager`'s BATTERY_PLUGGED_USB + `UsbManager` device list, combined with "charging but constant current" to tell it hangs off a computer.

### 5.4 Screen recording and FLAG_SECURE

- After an app sets `FLAG_SECURE` itself, screenshots/recording return a black frame; detectors use it the other way around: periodically self-check `MediaProjection` screenshots for being recorded (rare).
- The usual direction is detecting "screen sharing in progress": `Display.getFlags & FLAG_PRESENTATION`, multi-display enumeration (scrcpy creates a virtual display) — scrcpy detection = `getDisplays` showing an `Overlay #0` virtual screen.

## 6. Layered difficulty table (which detection is hardest to bypass)

| Detection | Common layer | Escalated form | Bypass cost |
|------|------|------|------|
| isDebuggerConnected | Java | JDWP thread name (native) | low |
| TracerPid | libc file read | svc openat read | low→high |
| frida port 27042 | Java connect | /proc/net/tcp read | low |
| maps scan for frida | libc fopen | svc + rwxp unnamed segments | medium→high |
| thread names gmain/gum-js-loop | opendir | svc getdents64 | medium |
| memory string frida:rpc | pread | direct pointer dereference | high (de-featurization mandatory) |
| inline hook CRC | self code check | - | high (stalker/patch) |
| root file sweep | Java File | svc access | low→high |
| mounts scan for magisk | libc file read | statfs/statx | medium (Shamiko handles it) |
| property ro.debuggable | __system_property_get | native direct read | low (resetprop) |
| emulator multi-signal | multi-layer | sensor entropy analysis | depends on signal count |
| VPN tun0 | Java | ioctl to the kernel | medium→high |
**One rule of thumb**: direct svc syscalls > hand-parsed files (ELF/self-read memory) > libc wrappers > JNI > Java API. If the target so contains `svc #0` with `/proc` paths as arguments, give up on the "hook everything" approach immediately and switch to patching the so or a kernel-space plan.

## 7. RASP-grade detection (countermeasures in rasp-bypass.md)

§1–§5 above cover "point detections"; commercial RASP (DexProtector/DexGuard/Promon/Arxan/Talsec freeRASP/Zimperium, domestic packers) turns detection into an **interlocking system** that adds three things: key binding, prologue integrity scanning, and self-destruction. This section covers only the detection forms; the bypass methodology lives entirely in rasp-bypass.md.

### 7.1 The native read of TracerPid (the fopen/fgets chain)

RASP's anti-debug workhorse is not Java's `Debug.isDebuggerConnected` but the native layer reading `/proc/self/status` itself:

```c
FILE* f = fopen("/proc/self/status", "r");
while (fgets(buf, sizeof buf, f))
    if (strncmp(buf, "TracerPid:", 10) == 0) {
        pid_t t = atoi(buf + 10);
        if (t != 0) hit();   // any tracer: gdb/lldb/frida (IDA remote) all count
    }
```

Key points:
- The version going through libc `fopen`/`fgets` is interceptable with Interceptor (just rewrite that one digit in the returned buffer; be careful not to change the buffer length);
- Advanced versions use direct svc `openat(2)`+`read`, or a positioned `pread` — userspace hooks are dead (§2.9);
- Stealthier equivalent signals: `/proc/self/wchan`, the 3rd column of `/proc/self/task/<tid>/stat` (state containing t = being traced), `waitpid` error codes. When bypassing, do not patch status alone — RASP often reads several files and cross-checks.

### 7.2 Prologue integrity scanning (not limited to the PLT)

§2.6 covered "the detector CRCs the prologues of functions it cares about". The RASP-grade difference is **scope and target**:
- **Not limited to its own so, not limited to PLT imports**: RASP can prologue-check any function in the process — libc's `open`/`read`/`fgets`, the linker's `rtld_db_dlactivity` (normally an empty function containing only `ret`; a frida hook leaves a trampoline there), even libart's JNI entries. DexProtector directly feeds that function's machine code as **input to key derivation** — hooking it = wrong key = the app silently bricks.
- Implementation: hash/CRC a set of address ranges at startup, recompute periodically; or match instruction patterns directly (the arm64 `ldr x17,#8; br x17` trampoline signature, x86 `0xE9`/`0xFF 25`). Hand-parsing ELF to read memory and dereference pointers bypasses any hookable API path, same story (§2.3/§2.5).
- Countermeasure implication: **the moment Interceptor attaches you may step on a mine**; the tools against this layer are Stalker (leaves original instructions untouched) or altering the "expected value" of the check (the X23=X0 identity method of patching the so, see rasp-bypass.md §2.1).

### 7.3 Self-destruct mechanisms (versus "alerting")

An ordinary detection responds with a dialog/`System.exit` — block exit and you win. RASP's response is **corrupt data without alerting**:
- Key poisoning: the key-derivation input is bound to the "environment normal" state; once a check hits, the key goes wrong → every later class decryption / asset decryption yields garbage. The symptom is "after bypassing detection the app installs and runs fine but the business is garbled/crashes" — easily misjudged as an incomplete bypass, sending you to keep grinding on the wrong layer;
- Delayed reaction: hits in early startup terminate immediately; hits mid-to-late are only recorded and surface later at a critical operation (payment/decryption) — when testing a bypass you must run the full business flow, not just stare at the home screen;
- Anti-dump: after decryption, unmap unused DEX regions so a full memory dump SEGV_MAPERRs outright; dynamic tables (relocations etc.) are zeroed after use;
- Hook-proof detection channels: raw Binder (bypassing PackageManager), custom dlsym trampolines (`Module.findExportByName` stops working).
**Rule of thumb**: after every visible detection point goes green, run the triple check "restart + full business flow + dump-artifact verification" to confirm no self-destruct fired in the dark (checklist in rasp-bypass.md §4).

## References

- Community post "frida self-compilation and de-featurization" (frida:rpc / re.frida.server / linjector / thread-name signature list)
- xxr0ss/AntiFrida (svc-ized detection samples)
- hzzheyang/strongR-frida-android (de-featurization patch set)
