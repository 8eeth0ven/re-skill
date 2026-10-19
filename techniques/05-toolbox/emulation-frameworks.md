# Emulation Frameworks (unidbg-Centered)

> Core conclusion: **the endgame tool for risk-control/signature algorithm restoration is unidbg**; frida active invocation is for verification; unidbg is for scaled recomputation off the device.

## I. Why Emulated Execution Is Needed

When signing happens in the Java layer, reading the logic in jadx suffices; but once the key algorithm sits inside `libnative.so` with parameters obfuscated through JNI, pure static restoration gets extremely expensive. Emulated execution takes another road: **don't understand it - feed it parameters and let it compute** - drop the so into an emulator, and reuse inputs/outputs as a black box. Typical scenarios:

- Risk-control signature restoration (`libsscronet`, `libsgmain`, `libmetasec_ml` and other Alibaba/ByteDance risk-control so files).
- Batch generation of encrypted parameters (turn the app's algorithm into your own HTTP signing service, paired with unidbg-boot-server).
- Offline detonation of sample malicious behavior (no real device touched).

## II. Tool Matrix

| Tool | Positioning | Status | When to pick |
|---|---|---|---|
| **unidbg** | An Android/iOS so emulation framework written in Java (Unicorn engine + ART/JNI environment simulation) | Active (continuously maintained by zhkl0228) | Default first choice; most community material |
| unidbg-boot-server | unidbg wrapped as an HTTP service (Spring Boot), invoking emulated algorithms remotely | Active (same author) | Productizing after the algorithm works / handing it to the business side |
| AndroidNativeEmu | Early so emulation in Python | Unmaintained (superseded by unidbg) | Old samples, idea reference |
| qiling | Cross-platform advanced emulation (rootfs+syscall level) | Active | When you need the whole environment (files/syscalls), not just JNI |
| unicorn | Pure CPU-instruction emulation engine (the foundation of unidbg/qiling) | Active (2.x) | DIY: instruction-level execution only, no JNI environment |
| frida-il2cpp-bridge | Unity il2cpp structure restoration and invocation | Active | Game specials (Unity) |
| WinDbg | Windows/kernel debugging | Active (Microsoft) | Marginal for Android; cross-use only |

## III. unidbg Usage Essentials

### 3.1 Project Skeleton

```java
public class SignDvm extends AbstractJni {                    // override the JNI gaps
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    public SignDvm() {
        emulator = AndroidEmulatorBuilder.for64Bit()           // match the so's ABI
            .setProcessName("com.target.app")                  // some risk controls check the process name
            .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));    // system so version (SDK number)

        // 1) Install the APK first (resources, manifest, multi-so dependencies get used)
        vm = emulator.createApkEnvironment(
                new File("unidbg-android/src/test/resources/target.apk"));
        vm.setJni(this);                                       // JNI gaps go through our overrides
        vm.setVerbose(true);                                   // open during debugging

        // 2) Load the target so
        DalvikModule dm = vm.loadLibrary("sgmain", true);      // true = run JNI_OnLoad
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);                           // declarative registration must be triggered
    }
}
```

### 3.2 Handling the Two JNI Registration Styles

- **Static registration** (`Java_com_xxx_nativeMethod`): call directly by exported symbol via `module.callFunction/emulate`.
- **Dynamic registration** (`RegisterNatives` inside `JNI_OnLoad`): you must `callJNI_OnLoad(emulator)`; then read the method names/addresses/signatures printed by `[RegisterNatives]` in the console log, and either `module.callFunction(address, ...)` or - recommended - `vm.resolveClass` + `callStaticJniMethod` through the DVM layer (the JNIEnv gets filled in automatically).

### 3.3 Environment-Stubbing (AbstractJni Overrides) - Common Pitfalls

The emulator provides only the "shell"; every call the app makes to system services must be answered by hand - the so-called environment stubbing:

1. **Reflection-call whitelist**: inside `getStaticObjectField/callStaticObjectMethod`, return fabricated values case by case for `android.os.Build`, `Build$VERSION`, `android.telephony.TelephonyManager` (deviceId/imei), `Settings$Secure` (android_id), `Resources` (getString resource ids) via a `switch`; miss one and it throws `unsupported`. The `FindClass: xxx` / `GetStaticFieldID` lines in the log are your gap list.
2. **Resources and assets**: `createApkEnvironment` makes in-APK resources resolvable; external files (like configs `libsscronet` depends on) get mounted via `vm.addFile`/`emulator.getFileSystem().virtual`.
3. **Signature validation**: many so files read back `PackageManager.GET_SIGNATURES` to use the APK signature as a key factor - unidbg's APK environment uses **the original package's real signature**; don't casually build the environment from a repackaged APK, or the keys come out simply wrong.
4. **JNI threads and TLS**: `pthread_create`/`pthread_key_create` are mostly emulated already; on hangs, turn on `vm.setVerbose(true)` + `emulator.traceCode()` to see which so's spin-wait it died in - usually a missing callback.
5. **File/network-class detection**: so files read `/proc/self/maps`, `/system/build.prop` - unidbg provides a virtual filesystem interface; `emulator.getSyscallHandler().addIOResolver` redirects and feeds fake content.
6. **Instruction-trace locating**: `emulator.traceCode(begin, end)` outputs the instruction stream; cross-reference against IDA/Ghidra static addresses to find mod points (look at the trace before OLLVM deflattening).
7. **Version pitfalls**: libc differences across `AndroidResolver(23/19/...)` affect so initialization - on `dlopen` failures, try another SDK number first; after unidbg upgrades, old projects breaking is routine (a high-frequency issue) - pin one commit and don't upgrade casually.
8. **64/32-bit**: the so's ABI must match the emulator (`for64Bit()/for32Bit()`); running an `armeabi-v7a` so under 64-bit emulation blows up instantly.

### 3.4 Pairing with frida Active Invocation (the Recommended Pipeline)

1. frida first hooks the target function on a real device, recording the **real inputs/outputs** (parameter structures, the JNIEnv call sequence).
2. unidbg emulates with the same inputs and compares outputs; mismatch -> environment gap - stub per 3.3.
3. Once complete, the unidbg side freely varies parameters for batch computation, off the device.
4. Need an online service -> unidbg-boot-server wraps the HTTP endpoint (deployment notes: add caching on the algorithm nodes, manage so files per app version).

## IV. unidbg vs frida Active Invocation

| Dimension | unidbg (emulated execution) | frida active invocation (real device) |
|---|---|---|
| Environment | Pure software emulation; no device/root needed | Needs a real device + frida injection (dodging detection) |
| Stability | 100% reproducible once the environment is stubbed | Depends on device state, randomness, time |
| Performance | Batch high concurrency (spin up servers freely) | Single-box limited, easily trips risk control |
| Coverage | Everything below the JNI layer runs; system services via stubs | Everything real; sensor/environment values natively real |
| Risk | Heavy environment-stubbing workload (grows with so weight) | Device fingerprint getting risk-flagged |
| Fits | The endgame of algorithm restoration, batch signing, offline analysis | Quickly verifying algorithm location and I/O formats |

**Rule of thumb**: first frida to scout (function locating + parameter capture), then unidbg to solidify (recomputation + scale). For one-off analysis frida alone suffices; to produce signatures/encrypted parameters off the app, unidbg is mandatory.

## V. When to Use Emulated Execution (the Criteria)

- **Strong signal**: core parameters computed by an so, parameters vary with time/device, mass concurrent generation needed -> unidbg.
- **Medium**: Unity game values/protocols (frida-il2cpp-bridge dumps structures first) -> semi-emulation.
- **Weak signal/not advised**: pure Java-layer algorithms (read directly in jadx); algorithms depending on strong device fingerprints (sensors, TEE, attestation) - emulation costs more than farming a real-device pool.
- **Combat note**: 2024-2026 risk-control so files commonly add anti-emulation checks (reading unicorn signatures, in-so self-checks, TLS fingerprints); tracing + IDA to locate the check point and then patching (`emulator.attach()` breakpoints altering return values inside unidbg) is a daily operation.

## VI. Common Errors -> Fixes Quick Reference

| Error/symptom | Cause | Fix |
|---|---|---|
| `unsupported: xxx` thrown by AbstractJni | An environment-stubbing gap (a reflection/JNI call not overridden) | Read the class/method name in the log; add a branch in AbstractJni returning a fabricated value |
| `dlopen failed` / so crashes on load | System-library version mismatch | Switch `AndroidResolver(19/23/...)`; confirm the ABI is 32/64-bit |
| Hangs with no output | In-so spin-wait on a callback/thread | Locate via `vm.setVerbose(true)` + `emulator.traceCode()`; stub the pthread-related return values |
| Computed values differ from the real device | Missing device factors (imei/android_id/signature/time) | Check item by item against the real inputs captured by frida and stub them; verify the APK signature is the original package's |
| `RegisterNatives` printed addresses but calling crashes | Direct callFunction lacks the JNIEnv | Switch to `vm.resolveClass(...)` + `callStaticJniMethod` (the VM layer manages the JNIEnv) |
| Old project breaks after a unidbg upgrade | Upstream behavior change (high-frequency issue) | Pin the commit/version; diff the official test cases and adapt |

## VII. The Debugging Three Basics

1. **Instruction trace**: `emulator.traceCode(0xbase, 0xend)` to a file, cross-referenced against IDA static addresses.
2. **Breakpoints**: `emulator.attach().addBreakPoint(module.base + 0xoffset)`; read registers in the callback via `context.getLongByReg(Reg.X0)`.
3. **Hook syscalls/IO**: `emulator.getSyscallHandler().addIOResolver(...)` intercepts `/proc` and `/sys` read requests, feeding tailored content to pass environment checks.

## VIII. Learning/Reference Resources

- The official repository's test cases (the best documentation is the risk-control so samples under `unidbg-android/src/test/java`).
- The community's "安卓逆向这档事" unidbg course and the oacia.dev unidbg notes - the main Chinese-language on-ramp.
- unidbg-boot-server: after the algorithm works, reuse the same environment-stubbing code on a service directly.

## Install Quick Reference

> For the Python family, install into this repo's tools-env virtualenv (sandbox pitfall: with a read-only HOME, uv's default cache path breaks):
> `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p re/tools-env/.venv/bin/python <package>`
> Every `uv pip install` below means this method. Note: keystone is incompatible with py3.13 - failing to install it in tools-env is normal.

| Tool | Install |
|---|---|
| unidbg | github.com/zhkl0228/unidbg (clone, then pull it into a gradle test project) |
| unidbg-boot-server | github.com/zhkl0228/unidbg-boot-server |
| vardoger | `uv pip install vardoger-vm` (PyPI name, LGPL-3.0) |
| qiling | `uv pip install qiling` |
| unicorn | `uv pip install unicorn` |
| AndroidNativeEmu | github.com/strazzere/AndroidNativeEmu (unmaintained, archaeology backup) |
| frida-il2cpp-bridge | `npm i frida-il2cpp-bridge` (github.com/vfsfitvnm/frida-il2cpp-bridge) |
| Il2CppDumper | github.com/Perfare/Il2CppDumper |
| Zygisk-Il2CppDumper | github.com/Perfare/Zygisk-Il2CppDumper (Magisk module) |
| WinDbg (Preview) | `winget install Microsoft.WinDbg` |
