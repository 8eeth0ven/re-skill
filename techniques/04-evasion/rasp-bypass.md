# RASP Bypass

> The full workflow for countering commercial RASP (Runtime Application Self-Protection): identify → locate the check points → pick the bypass layer → verify the self-destruct is disarmed.

## 0. What RASP is, and how it differs from ordinary anti-debug

RASP = a commercial SDK that packs detection, response, encryption and integrity checking into the app runtime (Talsec freeRASP, DexProtector, DexGuard, Promon SHIELD, Arxan, Zimperium anti-tamper, domestic packers, etc.). It is not "a snippet of anti-debug code" but an **interlocking system**:

| Dimension | Ordinary anti-debug/root detection | Commercial RASP |
|------|------|------|
| Number of check points | 1–5, concentrated in one so/class | dozens, interlocking across Java/native/kernel signals |
| Check outcome | dialog/exit; single point of failure = total failure | detect → change key → silent data corruption, **it does not tell you it noticed** |
| Integrity check | verifies the manifest signature | verifies its own so instruction bytes, linker state, DEX partitions, assets |
| Self-destruct | none, or exit | key derivation poisoned → decrypts garbage → looks like it runs fine but the business is broken |
| Key binding | none | key derived from APK signature + unprotected DEX + config + **its own code content** |
| Reporting | local logs | raw Binder / dedicated reporting channel; the server blacklists the device |
| Aftermath of a bypass | bypass = win | bypassing point A trips point B; miss one check → silent self-destruct that is hard to trace |
The core cognitive gap: **ordinary anti-debug is about bypassing "detection"; RASP is about bypassing "keys and the chain of trust"**. DexProtector derives part of the decryption key from the machine code of the linker function `rtld_db_dlactivity` — the moment frida hooks that function the key is wrong, the second stage never decrypts, and the process neither crashes nor pops a dialog. That is the essence of RASP-grade confrontation: every patch you make may be a key input.
Therefore the RASP-bypass methodology is **restore the chain of trust first, then act**, not "hook whatever moves". Decide which tier you face:

```
Symptom triage (run once through first, then pick your play):
A. Check hit → dialog/flash-exit          → ordinary detection; just block exit / change return values (this doc §2.1/§2.4)
B. Check hit → app still runs but business is garbled / data won't decrypt → key-grade self-destruct; go to §2.3 key derivation
C. Process vanishes the instant you attach, no logs → early svc detection + suicide; go to §2.2/§2.5
D. Everything normal but the server blacklists you → check results go out the reporting channel; block the report + forge responses
```

## 1. Identification layer: confirm which RASP you face first

### 1.1 Automatic identification

- **APKiD** (rednaga): `apkid apk.apk` outputs packer/obfuscator/compiler tags, covering most commercial packers and DexProtector.
- **mobile-security-mcp** (npm `mobile-security-mcp`, Serhatcck): an MCP server that scans APK/IPA for manifest/permissions/endpoints/hardcoded keys.
 - Note: the repo's current tools are `apk_manifest_analyzer` / `apk_permissions_checker` / `android_api_extractor` / `android_secrets_scanner` etc.; it does **not** include `rasp_identify` / `rasp_bypass` tools, nor a Zimperium/DexGuard/Promon/Arxan identification library. Start the service and check the actual tool list before use.
- **strings + so-name manual match**: the most reliable identification of RASP is still so filenames and string signatures (table below).

### 1.2 Manual identification signature table (per-vendor RASP / packer fingerprints)

| Vendor | so / file signature | Extra identification points |
|------|------|------|
| DexProtector (Licel) | `libdexprotector.so`, `libdpboot.so`; after unpacking the payload carries the `DPLF` magic or hides in the last PT_LOAD; custom ELF header (non-standard e_ident) | manifest injects a `ProtectedXxx` Application class; assets contain `classes.dex.dat`, `se.dat`, `resources.dat`, `dp.mp3` |
| DexGuard (Guardsquare) | pure Java/Kotlin obfuscation+encryption, no dedicated so; string-encryption class names randomized, `javax.crypto` keys assembled at runtime | paired with the Guardsquare commercial obfuscator; extremely high DEX-layer entropy |
| Arxan (Guardsquare/Verimatrix) | native code virtualization + self-modifying code; masses of opaque predicates and control-flow flattening inside the so | function-body hash self-checks throughout the so |
| Promon SHIELD | the `libpns.so` / `libpnx.so` family | common in Nordic banks/finance |
| Zimperium (z9 anti-tamper) | `libziks.so`, `libziFunctions.so` and other z-prefixed names | tied to MTD (mobile threat defense) enterprise deployments; detection reports go server-side |
| Talsec freeRASP | Flutter/RN integration; on the Android side a native library + the `talsec.app/freerasp/events` reporting domain | callbacks `onRootDetected` / `onHookDetected` |
| GarudaDefender | user material: core detection in `libkikypspro.so`; the business shell `libcrackme.so` provides a custom dlsym trampoline | when dlsym is wrapped by an in-so trampoline, `Module.findExportByName` fails; you must manually resolve real addresses from the trampoline table |
| Domestic big-vendor RASP samples | `libmsaoaidsec.so` (Douban-class apps etc.: frida detection, corroborated by a CSDN 2026-04 analysis post); Ijiami/Bangcle/360/Tencent Legu/NetEase Yidun each with their own so | see detection-landscape.md §2 |
Write the identification results into a list: so names + Application class + reporting domain + order of magnitude of detection functions — this decides which layer you attack next.

## 2. The layered bypass methodology (from low to high confrontation level)

The five layers are not parallel options but a **progressive attempt order**: try the high layer first (small change, small side effects); if the self-destruct is not disarmed, drop down.

### 2.1 ① Patch the check point: make the integrity check always equal (GarudaDefender case)

Applies when the check logic is the structure "compute hash → CMP against an expected value in a register/memory → take the alert branch if unequal".
**Chain-restoration methodology (dig backwards from the dialog — the universal routine)**:
1. The Java layer shows the alert entry is a native method (e.g. `SystemAlert.onCreate` declared native) → the real implementation is not in the dex;
2. That method lands in the real business so via the so's JNI registration table/trampoline (user material: `libkikypspro.so+0x37A754`);
3. Follow RegisterNatives / the custom dlsym trampoline to the implementation function; decompile and see **who calls it**: the dialog is the UI outcome, walk up to the dispatch layer (user material: `sub_68BD10` dispatches → `sub_64B840` builds and shows the AlertDialog);
4. Go one level up to find **why it was dispatched** — a detection function returned an abnormal value / a hash check failed (user material: inside `sub_AB31A0`, `0xAB3C7C: BL hash_crc` computes the actual value into X0, `0xAB3C80: CMP X23, X0`; X23 is the expected value stored at startup);
5. Conclusion: the check layer is `sub_AB31A0`; the dialog chain is only downstream. **Patch the check layer, do not touch the dialog layer** (touching the dialog layer leaves more surface for secondary checks).
The concrete IDA steps (mapping to the 5 steps above):

```
1. jadx search SystemAlert / onCreate → copy down the native method name
2. Open the business so in IDA; locate the JNI implementation via string/export-table search; not found → see where the Java_ prefix symbols went
   (custom dlsym trampoline = string table + function pointer array; search the method-name string directly, xref to the trampoline entry)
3. On the implementation function press X for xrefs → the upper dispatch layer (who calls it under what condition)
4. One level above the dispatch layer = the verdict function; inside it find the triple "value-computing BL → CMP → B.NE alert branch"
5. Patch at the CMP (not the B.NE) — changing CMP affects all downstream branches; changing B.NE misses the else path
```

**The bypass (two approaches on the same target)**:
- **IDA static patch**: change `CMP X23, X0` (and the following B.NE) into `MOV X23, X0` followed by unconditionally taking the equal branch, or straight NOP the B.NE. Note the repacked APK's signature changes; if the RASP also verifies the APK signature, feed the original package per §2.2.
- **frida dynamic patch**: hook at the return of `BL hash_crc` and set context X23 to X0, making the CMP always equal:

```js
const base = Module.findBaseAddress("libkikypspro.so");
Interceptor.attach(base.add(0xAB3C80), {          // at CMP X23, X0 (offset from user material)
    onEnter() { this.context.x23 = this.context.x0; }
});
```

The dynamic way does not modify files and triggers no signature change; but against an RASP that CRC-checks function prologues, the attach itself steps on the prologue scan (see detection-landscape.md §7.2) — first confirm the target function's prologue is not checked, or switch to Stalker.
**Unified detection-function return value**: in that case the return values of 14 environment-check functions (root/frida/debug/emulator etc.) were uniformly replaced with `0x64` (the "environment normal" status code) — sturdier than hooking each one is finding their **common return path** (the register/argument in the dispatcher that receives the status code); change it once and the whole chain takes effect:

```js
// Sketch: change the status-code argument at the dispatcher entry instead of hooking 14 functions
Interceptor.attach(base.add(SCHEDULER_OFFSET), {
    onEnter(args) { /* find the argument/register carrying the "environment status" and uniformly set 0x64 */ }
});
```

### 2.2 ② syscall-layer forgery: feed the RASP fake files (freeRASP case)

Applies when the RASP directly reads its own APK / key files in the native layer for integrity checking and hooking `getPackageInfo` in Java is useless.
The idea (the bypass described in user material; mechanism-level sound): intercept the three syscalls `openat` / `read` / `fstat` (libc functions or the svc layer); when the RASP opens `base.apk`:
- `openat`: redirect the fd to a **pre-stored original APK** (keep a copy before repackaging);
- `fstat`: forge size/mtime to match the original package;
- `read`/`pread`: read from the original package fd; the returned buffer is the original package's bytes.
The RASP thus always reads an "untampered" APK, and hash/signature checks pass naturally. On the freeRASP side, the strength of the countermeasure: Talsec's official article admits frida detection is the core of the offense-defense game, and the community already has public scripts (see §3.2); syscall-level details depend on the official discussion and the actual target.
frida implementation skeleton:

```js
const origApk = "/data/local/tmp/original.apk";   // pre-stored original package
let fakeFd = -1;
Interceptor.attach(Module.getExportByName("libc.so", "openat"), {
    onEnter(args) {
        const p = args[1].readCString();
        if (p && p.endsWith("base.apk")) {
            fakeFd = -1;
            const fd = new File(origApk, "rb");    // remember the redirect relation (mapped by original fd)
            // in production use fs.open to keep the fd table; sketch only
        }
    }
});
// read/pread: read from the original package via the mapping table; fstat: return the original package's size/ino/mtime
```

Implementation notes:
- If the RASP uses inline svc openat (see detection-landscape.md §2.9), the libc hook is dead → switch to frida Stalker rewriting registers at the svc instruction, or kernel-space interception (§2.5, 07-kernel).
- The fake file must be a full set: the mapping range of base.apk in `/proc/self/maps`, the `fstat` inode/size all have to line up; advanced RASP cross-verifies.
- The same idea applies to feeding `/proc/self/status` (zero TracerPid), `/proc/net/tcp` (erase 27042), `/proc/mounts` (erase magisk) — one redirection framework wraps every detection file.

### 2.3 ③ Key derivation: decrypt without running the app (DexProtector case)

Applies when the commercial packer builds "anti-analysis" into the key itself — the moment you hook, the key goes wrong and the app silently bricks. At that point you should stop bypassing detection and instead **derive the key offline and decrypt the data directly**.
DexProtector's full chain of trust:
1. Startup chain: the manifest-injected `ProtectedLiveNetTV` Application → loads `libdpboot.so` → JNI loads `libdexprotector.so` (custom ELF loader) → decrypts and maps the payload (`DPLF` magic or the last PT_LOAD segment), executes from `DT_FINI_ARRAY`, and zeroes the used dynamic-table region after use (anti-dump).
2. **Key bound to code**: the payload's 32-byte decryption key = a static salt inside the library + **the runtime machine code of the linker function `rtld_db_dlactivity`**. That function is normally empty (only a `ret`); when frida-server hooks it, a trampoline is injected — **the key is corrupted outright** and the second stage never executes. The textbook implementation of "key-grade anti-dynamic-analysis".
3. The master key (generated inside the decrypted `libdp.so`) binds: APK signature + the unprotected DEX files + the DexProtector config + **its own code content** — hooking any function of libdp.so can break it.
4. Self-destruct: the final manifestation of tampering is a dead master key → class decryption/asset decryption all broken. The threat corrupts the key or kills the process outright when found early at startup; otherwise it records and reacts later. Class encryption is also paired with anti-dump (unmap unused DEX regions; a full dump triggers SEGV_MAPERR); string decryption is bound to the native function's own address (countering RegisterNative replacement); RASP checks go over raw Binder, bypassing PackageManager.
5. The break (verified against 10 finance apps):
 - develop an instrumentation method that "does not trigger the corruption mechanism" to hook `libdp.so`, and **compute a legitimate master key offline (without running the app)**;
 - the master key derives sub-keys that unlock `classes.dex.dat` / `se.dat` / `resources.dat` / `dp.mp3`;
 - use self-written Redex passes (StringEncryption / RecoverHiddenAccess) to restore `ProtectedX.s` string calls and `LibX.i` native calls into clean DEX;
 - core criticism: the scheme is a generic post-build artifact; break one = break all.
Methodology distilled: **when you see "after bypassing detection the app installs fine but the business is garbled/crashes", immediately suspect the key was poisoned by key-grade detection**. Countermeasure: stop fighting the runtime; go static/offline — dump the encrypted artifacts + restore the key-derivation algorithm + decrypt offline. Value assessment: this class of scheme is generic post-build encryption; **an algorithm derived once is reusable for all apps of the same version** (Romain Thomas demonstrated 10).

### 2.4 ④ Unified detection-function return values: close it at the Java layer (React Native finance app case)

Applies when the RASP's detection results converge into a few Java methods/constant tables, and the detection runs only once at startup (pass once, pass forever).
SecureNexus case — three protection layers, ~90 lines of frida bypassing all:
- **Static side (key recovery)**: disassemble the Hermes bytecode `assets/index.android.bundle` to restore the JS logic → in module 632 (crypto helper) a **hardcoded 64-bit hex string = an AES-256-CBC key**, identical on every device; module 624 (axios interceptor) gives the wire format: first 32 hex = random IV, the rest = ciphertext, wrapped as `{"payload":"<hex>"}`. Write mirror encrypt/decrypt with pycryptodome and validate against real traffic (the account in the login form decrypts cleanly out of the ciphertext).
- **Three hook groups on the RASP side** (all inside `Java.perform`):
 1. Six static methods `a`–`f` of the in-house detection class `com.target.utils.RootDetector` (covering frida port 27042/27015 scanning, frida-server on disk, su paths, test-keys, XposedBridge class loading, magisk/busybox) → `.implementation` uniformly returns `false`;
 2. RootBeer native: `com.scottyab.rootbeer.RootBeerNative.checkForRoot` returns `0` (neutralizes the JNI check in `libtoolChecker.so`);
 3. JailMonkey (official RN ecosystem): besides forcing the two low-level methods to `false`, also **rewrite `JailMonkeyModule.getConstants`** — call the original first, change `isJailBroken` / `hookDetected` / `canMockLocation` / `AdbEnabled` all to `Boolean.valueOf(false)`, then return. Key insight: **RN's JS layer reads detection results from the constants map; poisoning at the source is more thorough than hooking one by one**.
- **Pinning side**: do not touch `CertificatePinner` / TrustManager; instead hook the RN bridge **above TLS**: `NetworkingModule.sendRequest` (grab method/URL/body before the request) + `ResponseUtil.onDataReceived` (grab plaintext after the response). Pinning still verifies the real server cert at the OkHttp layer; reading one layer higher never crosses the confrontation surface.
- The app's structural weakness: detection **runs only once at startup**, hits call `System.exit(0)` immediately (just block exit), and there is no emulator detection.
Methodology distilled: for cross-framework apps (RN/Flutter) the RASP verdict's final state is often a **constant table / single callback**; closing it there = one bypass for the whole chain; plus the layered idea of "picking hook points in the framework layer rather than the confrontation layer".

### 2.5 ⑤ OS-grade instrumentation: strike from outside the process (ANDROID-MRI)

Applies when the RASP detects or key-poisons every in-process instrumentation (frida/xposed/self-implemented hooks) and userspace has no answer.
ANDROID-MRI:
- Embeds trace directly into the **Android kernel/OS layer**, tracking the runtime, ROM loader, root interfaces — it injects no code into the app process, so the app's anti-tamper/root detection/frida detection **cannot see it**;
- Tested on 50 popular apps with ≥1M installs each: **bypasses 97.6% of RASP protections, versus only 52.4% for frida**; incidentally found 17 undisclosed sensitive-data-resident-in-memory issues;
- It is positioned as a research tool (deployed on production ROMs with vendor signatures); the lesson for authorized testing: **the ceiling of userspace RASP is inside the process; OS-grade observation is naturally outside the detection surface** — which numerically explains why heavily hardened targets ultimately sink into the kernel.
Practical hookup: the equivalent path in an authorized environment = kernel-space interception (KernelSU + KPM hooking sys_openat etc.) or custom ROM/emulator-layer instrumentation; details in `../07-kernel/cross-platform-kernel.md`. The frida-side fallback = Stalker (leaves original instructions untouched, dodges prologue CRC) + a de-featurized build (frida-anti-detection.md).

## 3. Case quick-reference table

| Case | RASP/packer | Bypass layer | Core actions |
|------|------|------|------|
| GarudaDefender crackme | libkikypspro.so (+ libcrackme.so dlsym trampoline) | ①patch check point | X23=X0 identity + 14 detection functions uniformly 0x64 |
| freeRASP (Talsec) | Flutter/RN integration | ②syscall forgery + ④return values | openat/read/fstat feed the original package; the public CodeShare script intercepts File/Runtime.exec/isDebuggerConnected/System.exit/killProcess + cuts the events report |
| DexProtector | libdpboot.so/libdexprotector.so | ③key derivation | offline master-key recovery + Redex DEX restoration; counters the rtld_db_dlactivity key binding |
| React Native finance app | RootDetector+RootBeer+JailMonkey | ④return-value convergence | six methods false + checkForRoot=0 + getConstants poisoning; the AES key read straight from the Hermes bundle; hook the RN bridge to bypass pinning |
| ANDROID-MRI | various vendors' RASP across 50 popular apps | ⑤OS grade | trace embedded in the kernel, observation from outside the process, 97.6% bypass rate |

## 4. Generic RASP-bypass checklist

```
[ ] 1. Identify: APKiD + so-name/signature table → write a list (so, Application class, reporting domain, order of magnitude of detection surface)
[ ] 2. Rough probe: run once through without bypassing anything — record which functions break (distinguish "blocked" vs "silent self-destruct")
       installs fine but business garbled/crashes = key poisoned → go straight to step 6 (key derivation)
[ ] 3. Locate the check point: backtrack from the visible symptom (dialog/exit/garbling) —
       Java alert method nativized → JNI registration table/trampoline → dispatch layer → hash/CMP check layer
       Write down: check input (who computes the actual value) vs check expectation (X23/constant) — patch the expectation side
       IDA triple search: value-computing BL → CMP → B.NE; patch the CMP, not the B.NE
[ ] 4. Pick a layer (low to high; verify after each change, do not stack them all at once):
       Java convergence (one constant table/callback governs everything?) → unified detection-function return values
       → libc hooks (feed fake data for files/environment; openat/read/fstat consistent as a full set)
       → static so patch (X23=X0 identity; note repackaging triggers signature checks, pair with feeding the original package)
       → svc/Stalker (when detection goes through svc)
       → OS grade (when userspace is all dead, 07-kernel)
[ ] 5. Counter secondary detection:
       prologue CRC (function-prologue byte scan, not limited to the PLT) → use Stalker, or restore first then call
       custom dlsym trampoline → findExportByName fails; manually parse the trampoline table
       raw Binder detection → hook libbinder transactions or go kernel-side
       rtld_db_dlactivity key binding → do not hook the linker; go offline derivation
[ ] 6. Verify the self-destruct is disarmed:
       a. after all check points are green, run the full business flow (login→transaction→file read/write), not just the home screen
       b. restart the app and run again (one-shot detection vs periodic detection)
       c. dump DEX/memory to confirm decrypted artifacts are valid (dumping SEGVs on DexProtector class encryption
          = the unmap anti-dump is active = you are still inside its detection surface)
       d. capture traffic to confirm the data is readable plaintext (if the AES key is hardcoded in the bundle, just decrypt offline)
[ ] 7. Persist: RASP fingerprint + bypass layer + pitfalls into this wiki for reuse on re-scans
```

### 4.1 Common failure modes and troubleshooting

| Symptom | Most likely cause | Troubleshooting |
|------|------|------|
| All bypass points green but the app white-screens/garbles | Key-grade self-destruct already fired (§2.3) | Stop fighting the runtime; switch to offline key derivation |
| The process is gone the instant frida attaches | Early svc detection + immediate suicide | Enter in spawn+suspend mode, patch early init first; or §2.5 |
| Flash-exit after patching and repackaging | APK signature check (another integrity layer) | §2.2 feed the original package, or switch to dynamic patching that touches no files |
| Hook works for a few seconds, then caught | Periodic prologue CRC rescan | Replace Interceptor with Stalker; or patch the scan function itself |
| `findExportByName` returns null | Custom dlsym trampoline / stripped symbols | Search the method-name string in IDA; manually resolve the real address from the trampoline table |
| Server blacklists you after the bypass | Check results go out the reporting channel | Block the reporting domain (freeRASP: talsec.app/freerasp/events) + forge success responses |

## Related

- detection-landscape.md §2/§7/§6, frida-anti-detection.md, root-env-hiding.md, `../07-kernel/cross-platform-kernel.md`
