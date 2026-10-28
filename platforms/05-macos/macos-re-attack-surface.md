# macOS RE and Attack Surfaces (platform/05-macos)

> Positioning: the main file of the standalone macOS area. Mach-O hands-on / dyld injection / toolchain / desktop attack surfaces (TCC·XPC·persistence·notarization) / hardening and the detection surface.
> Kernel-level (XNU/IOKit/SIP/Mach IPC) is not duplicated → `../../techniques/07-kernel/cross-platform-kernel.md` §2 §3; the iOS same-origin toolchain → `../04-ios/ios-re-fundamentals.md`; capture confrontation (Flutter etc.) → `../../techniques/04-evasion/capture-all-scenarios.md`.
> **Local test environment**: macOS 26.6.2 (25G83) arm64, SIP enabled, Gatekeeper assessments enabled, native processes (proc_translated=0). Commands marked `[local-tested]` all ran in this environment; output highlights are verbatim excerpts.

## §0 Quick Start: size up a mac in five minutes

```bash
sw_vers                          # Version; the build number determines kernel-structure offsets
uname -m                         # arm64: account for arm64e pointer authentication
csrutil status                   # SIP state: whether restrictions have already been disabled on the analysis machine
spctl --status                   # Gatekeeper
sysctl sysctl.proc_translated    # 1 means this process runs under Rosetta; relevant when analyzing Intel samples
```

The macOS↔iOS relationship: **the same XNU + Mach-O + ObjC/Swift + LLDB/Frida**; the difference is that a mac can install any tools, disable SIP, and do two-machine kernel debugging — "a debuggable amplified iOS" for research purposes. The migration table from Android is in the cross-platform kernel quick ref §3.3.

## §1 Mach-O RE Hands-On `[local-tested]`

### 1.1 The three basics: otool -L / -l / codesign

Using the system binary /usr/bin/file as the example (universal, 3 architectures: x86_64 + arm64 + arm64e):

```
$ otool -L /usr/bin/file
	/usr/lib/libbz2.1.0.dylib (compatibility version 1.0.0, current version 1.0.8)
	/usr/lib/libz.1.dylib    /usr/lib/liblzma.5.dylib
	/usr/lib/libSystem.B.dylib          ← LC_LOAD_DYLIB entries, listed individually (similar to ldd)

$ codesign -dv /usr/bin/file
	Format=Mach-O universal (x86_64 arm64e arm64)
	CodeDirectory v=20400 flags=0x0(none) hashes=10+2
	Platform identifier=26            ← Platform-binary flag used to determine dyld environment-variable exemptions (§2)
	Signed Time=Aug 1, 2026 ...
```

`otool -l` shows the full Load Command set — during RE focus on scanning these:

| Load Command | What to look at | Measured value (/usr/bin/file) |
|---|---|---|
| LC_SEGMENT_64 | segment layout: `__PAGEZERO` (a 4GB cavity blocking NULL derefs)/`__TEXT` (r-x)/`__DATA` (rw)/`__LINKEDIT` | __TEXT vmaddr 0x100000000, initprot 0x5 (r-x) |
| LC_MAIN | entry offset (absent LC_ENTRYPOINT, this is dyld's handoff point before main) | entryoff 83812 |
| LC_LOAD_DYLIB | dependency libraries (≈DT_NEEDED) | libbz2/libz/liblzma/libSystem |
| LC_CODE_SIGNATURE | where signature data lives | dataoff 154528 |
| LC_LOAD_DYLINKER | the loader | /usr/lib/dyld |

Sample-analysis routine: diff the LC set against a normal system binary — an extra LC_LOAD_DYLIB (loading a suspicious /tmp library), a stripped LC_CODE_SIGNATURE, or an abnormal __TEXT initprot (turned writable = self-modifying code) are all strong signals.

### 1.2 arm64e special topic: __auth_stubs and PAC

Locally verified: /usr/bin/file's __TEXT segment contains an `__auth_stubs` section (reserved2=16): under arm64e, **external-function stubs carry pointer authentication**, jumping via `braa/braz` (signed, authenticated jumps) instead of bare `blr`. RE impact:
- In arm64e binaries the traditional forged-function-pointer/GOT route is blocked by PAC; bypass ideas (PAC gadgets/signature-cache reuse) are in the cross-platform kernel quick ref §1.1;
- For generic samples, first `lipo -thin arm64` to extract the non-arm64e slice (most third-party apps are still plain arm64).

### 1.3 fat binaries and architecture choice

```
$ file /usr/bin/file
Mach-O universal binary with 3 architectures: [x86_64] [arm64] [arm64e]
$ lipo -thin arm64 /usr/bin/file -o /tmp/file_arm64   # Extract one architecture before opening in IDA/Ghidra/r2
```

For Intel-emulator/sample analysis, mind Rosetta: a process running translated has `sysctl sysctl.proc_translated=1`; breakpoint behavior and memory layout differ.

### 1.4 Symbols and ObjC/Swift metadata

```
$ nm -undefined-only /usr/bin/file      # Imported symbols; defined=0 because the system binary was stripped
                 U _BZ2_bzDecompress / ___assert_rtn / ___chkstk_darwin ...
```

- **The ObjC information dividend**: `otool -o` prints class structures directly. Locally verified on Terminal.app: the isa/superclass/baseMethods pointer chains inside `__objc_classlist` are visible — class-dump-class tools just walk this table to generate headers. Third-party mac apps' method/property names are mostly plaintext; dump classes first, then locate check functions by name in static analysis.
- **Swift metadata**: symbols mangled into the `$s` prefix (swift-demangle restores); the cross-platform kernel quick ref §2.2 has the TypeMetadata/VWT structure essentials. The core Swift-RE pitfall is **value semantics and vtable dispatch**: method calls go through the VWT instead of ObjC's objc_msgSend, so hook-point selection is completely different.
- System-side symbols: platform binaries like /usr/bin/file are stripped down to undefineds; full symbols require the Kernel Debug Kit (KDK) or dSYMs.

## §2 The dyld Chain and Injection, Tested `[local-tested]`

### 2.1 DYLD_INSERT_LIBRARIES, a three-way comparison (the core conclusion)

Environment: SIP **enabled**. Self-compiled target hello_mac (adhoc-signed, containing a license check `strcmp(input,"MAC-RE-DEMO-2026")`) + an interpose dylib (a `__DATA,__interpose` section hooking strcmp to always return 0):

| Target | Result | Reason |
|---|---|---|
| Self-compiled adhoc binary | **Injection succeeds**: the license always passes; even strcmp during dyld/libSystem startup gets intercepted (`strcmp("hello_mac","launchd_sim")` and other startup-log-grade output) | adhoc + no library validation, dyld does not strip the environment variables |
| Platform binary /bin/ls | **silently ignored** (no injection traces, the program runs as usual) | a platform binary's (Platform identifier) DYLD_* are all discarded by dyld, without even an error |
| SIP-off machine | platform binaries injectable as well | the restriction chain = SIP protecting dyld + AMFI checking; disable SIP and it lifts |

Conclusion to memorize: **DYLD_INSERT_LIBRARIES ≈ LD_PRELOAD, but the exemption matrix = "platform binaries / notarized apps with library validation" are rejected; the rest (self-compiled / third-party without hardened runtime) inject fine even with SIP on**. The malware abuse surface = the large population of non-notarized third-party apps.

### 2.2 Unpacking the modern restriction chain

- **SIP**: protects /usr/bin, dyld itself, system files — the old "patch dyld to strip restrictions" route is infeasible with SIP on; `csrutil disable` requires recovery mode.
- **Restricted-binary variable stripping**: dyld outright empties DYLD_INSERT_LIBRARIES/DYLD_LIBRARY_PATH etc. for restricted processes (the measured silent discard of /bin/ls is exactly this).
- **AMFI** (AppleMobileFileIntegrity): the amfid daemon + kernel kext validate code signatures/entitlements; unsigned kexts basically cannot install on modern macOS (kexts heading for retirement, DriverKit taking over — see the cross-platform kernel quick ref §1.4).
- **Hardened Runtime + Library Validation**: with an app's defaults (anything other than `com.apple.security.cs.disable-library-validation`), only same-TeamID libraries may inject; only the `allow-dyld-environment-variables` entitlement explicitly permits DYLD_*. Before analysis, check these two switches with `codesign -d --entitlements :- <app>`.

### 2.3 Practical injection/diagnostic commands

```bash
DYLD_PRINT_LIBRARIES=1 ./target           # Print every loaded library, including dlopen loads omitted by otool -L
DYLD_PRINT_ENV=1 ./target                 # Environment received by dyld and whether variables were stripped
DYLD_INSERT_LIBRARIES=./inter.dylib ./t   # Interpose injection (see 2.1)
```

Alternative injection routes (when the target is blocked by library validation): Frida (goes task_for_pid + entitlement, runs directly on macOS, one notch lower barrier than iOS research)/patch the binary then re-sign with `codesign -f -s -`/LLDB attach. For trace-grade observation see `../../techniques/13-trace/trace-practice.md` (incl. macOS spawn pitfalls).

## §3 Toolchain and LLDB, Tested

### 3.1 The tool matrix (from this mac's viewpoint)

| Tool | Local status | Use/essentials |
|---|---|---|
| otool/lipo/nm/codesign/dsymutil | system stock | the whole §1 kit, zero-cost start |
| **r2/radare2** | local 6.2.4 (Homebrew) | see the 3.2 test; first pick for scripted batch analysis |
| LLDB | local 1403.0.17 (CLT) | the §3.3 full workflow; `po`/`expr`/ObjC-runtime aware |
| Hopper | not installed | the signature mac-RE GUI: pseudocode + ObjC annotation + built-in LLDB, priced far below IDA; the first commercial pick for the mac |
| Ghidra | not installed | the free heavy cannon; mature Mach-O/ObjC support, arm64e decompilation usable |
| IDA | not installed | the strongest general-purpose; native mac GUI |
| Frida | ecosystem-compatible | macOS process injection shares the Android script set (native layer interchangeable) |
| ipsw (blacktop) | a must for kernel research | kernelcache unpacking/symbol restoration, see the cross-platform kernel quick ref §6 |

### 3.2 One r2 flow, tested `[local-tested]`

```
$ r2 -q -c 'ie; iM' /bin/ls          # Entry points
0x00010960 0x100000960 ... program   # entry0
$ rabin2 -I /bin/ls                  # Binary fingerprints
bintype mach0  class MACH064  machine arm64e  compiler clang
canary true  nx true  pic true  stripped true  os macos
```

Essentials: one shot gets the canary/nx/pic protection bits + the compiler fingerprint — the first step of sample triage; afterwards the usual `aaa; afl; pdf @ main` flow. r2's Mach-O LC coverage (rabin2 -e for entries/exports) complements otool.

### 3.3 The full LLDB reversing of the self-compiled hello `[local-tested]`

Goal: bypass hello_mac's license check. One batch command demonstrates the three steps "breakpoint → read argument → force the return value":

```
$ lldb --batch \
    -o 'breakpoint set -n check_license' \
    -o 'run BADKEY-123' \
    -o 'register read x0 x1' \
    -o 'memory read -f s $x0' \
    -o 'thread return 1' \
    -o 'continue' -- /tmp/hello_mac
Breakpoint 1: where = hello_mac`check_license, address = 0x0000000100003eac
* thread #1, stop reason = breakpoint 1.1
      x0 = 0x000000016fdff26f            ← ARM64 first argument
0x16fdff26f: "BADKEY-123"                 ← memory read -f s displays the string directly
(lldb) thread return 1                    ← Force the function to return 1, bypassing the license check
input=BADKEY-123 result=1                 ← Verification was bypassed
```

Flow essentials (macOS-specific):
- ARM64 calling convention passes arguments in x0-x7; `memory read -f s $x0` shows string arguments;
- **`thread return <value>` is the shortest no-patch path around a check** (the equivalent of x64dbg's edit-EAX+ret); combined with `b -n <function>` it works for ObjC method names too (`b "-[ClassName methodName]"`);
- `expr`/`po` can call the ObjC runtime right at a breakpoint (`po [self someState]`);
- Anti-debug confrontation (PT_DENY_ATTACH/sysctl P_TRACED) exists on macOS as well; bypass quick table → `../04-ios/ios-offense-defense.md` (same-origin APIs);
- Kernel-mode debugging: KDK + `kdp-remote udp://...` (boot-args adding debug=0x144), detailed in the cross-platform kernel quick ref §5.

## §4 Desktop Attack Surfaces (TCC / XPC / Persistence / Notarization)

### 4.1 TCC (the privacy-authorization framework)

**Verified database locations** (two coexisting):

| DB | Path | Verified contents |
|---|---|---|
| User-level | `~/Library/Application Support/com.apple.TCC/TCC.db` | the access table: service (kTCCService*) + client (bundle id) + auth_value + csreq (signing-requirement blob) + last_modified, all columns |
| System-level | `/Library/Application Support/com.apple.TCC/TCC.db` (root, SIP-protected) | same schema; REG.db records registration behavior |

Verified: tccd runs as dual resident instances (one in the system domain, one in the gui domain). Attack-surface essentials:
- The anchor of authorization decisions is the **csreq blob** (code-signing requirement), not a bare bundle id — forging a client means passing the signature too;
- Bypass surfaces (path races/daemons trusting client-claimed identity/environment injection) and the instancing model → cross-platform kernel quick ref §3.2;
- Red-team view: TCC.db is a **forensic goldmine** — SELECT directly reveals who got screen-recording/accessibility/full-disk-access grants; `auth_value` 2 = allowed;
- High-frequency malware targets: kTCCServiceAccessibility (keyboard/mouse listening), kTCCServiceScreenCapture, kTCCServiceSystemPolicyAllFiles.

### 4.2 XPC service-endpoint enumeration `[local-tested]`

```
$ launchctl list | wc -l        # 534 lines in the recorded local run: label + pid + last exit code
$ launchctl print system/com.apple.tccd.system | grep -E "program|state"
	program = /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
$ launchctl print gui/$(id -u)/com.apple.tccd | grep -A5 endpoints
	endpoints = { "com.apple.tccd" = { port = 0x53663, active = 1 ... } }
```

The audit routine: **launchctl list the full label set → print each one for its program path (system domain = root-privileged daemons) → read the plists (LaunchDaemon directories) for MachServices endpoint names → reverse that daemon's `shouldAcceptNewConnection` validation logic** (checks the Entitlement? the Audit Token? or nothing at all). The missed-check pattern = a privileged daemon validating only "a connection exists", not "who connected" — the classic desktop-EoP surface. plist locations:
- /System/Library/LaunchDaemons (system, SIP-protected), /Library/LaunchDaemons (third-party root, **the high-risk persistence zone**)
- /Library/LaunchAgents, ~/Library/LaunchAgents (user-level persistence)
- A LaunchAgent's RunAtLoad/KeepAlive + a binary pointing into /tmp or a user-writable path = the malicious-persistence fingerprint.

### 4.3 Gatekeeper and notarization

```
$ spctl --status     # assessments enabled
```

- The chain: downloaded files carry a quarantine xattr → Gatekeeper checks the notarization ticket (notarization = issued after Apple's cloud scan) → first-run user confirmation → afterwards the CDHash is checked;
- Bypass research surfaces: clearing the quarantine attribute (xattr -d com.apple.quarantine, for old files from non-app-store channels)/right-click-open for un-notarized apps past the first gate/handler hijacking;
- Commonly seen in malware samples: DMG-embedded symlinks, app translocation (an app run from quarantine gets moved to a randomized read-only mount — during analysis, mind that the real path was swapped).

### 4.4 Browsers and other desktop surfaces

- Browsers (Chrome/Safari) are the number-one malware delivery entry on mac: sandbox escape → XPC EoP → TCC harvesting is a common chain; when analyzing the browser surface, look first at helper processes and the Native Messaging host list;
- dmg/pkg delivery: a pkg's pre/postinstall scripts are plain bash, the main carrier of social-engineering samples (`pkgutil --expand` to unpack and audit the scripts);
- Peripherals: the Thunderbolt/USB physical surface belongs to the wireless-hardware area → `../07-iot/wireless-hw/hw-interfaces.md`.

### 4.5 Closing the attack surface: a desktop-chain quick table

```
Delivery (quarantined dmg/pkg/browser download) → initial Gatekeeper/notarization check
  → User-mode execution: LaunchAgent persistence (§4.2 locations)
  → Privilege escalation/detection evasion: missing checks in a privileged XPC daemon (§4.2) → root
  → Data access: induced TCC grants (§4.1)/keychain/browser data
  → Persistence: LaunchDaemon (root) + client-identity spoofing surfaces
```
Detection handles per link: what the EDR (§6) sees = persistence footholds + outbound traffic; what forensics sees = TCC.db authorization records + launchctl state.

## §5 App Hardening and RE Essentials

- **Swift RE**: demangle mangled symbols with swift-demangle; VWT dispatch makes hook points differ from ObjC; the async/await state machine (compiler-generated resume function chains) is the main obstacle to restoring control flow.
- **ObjC protections**: method-name obfuscation (class-dump yields garbage)/swizzle detection (whether method-implementation addresses sit inside the expected image)/anti class-dump (hiding the classlist until runtime registration). The confrontation is essentially the same as Android hardening — push the dump moment to runtime.
- **Metal shaders**: the GPU code of game/rendering apps lives in .metallib (AIR bytecode); the analysis toolchain is far less mature than the CPU side; the RE focus shifts to **the shader↔CPU command stream** (an MTLDebugCommandEncoder hook can record the command stream, akin to Android's GPU trace).
- **Post-notarization hash checks**: notarization binds the CDHash to Apple's ticket; **patching the binary = CDHash changes = notarization void + Gatekeeper blocks** — so mac cracking always goes the "patch + adhoc re-sign (`codesign -f -s -`) + de-quarantine" triple. The bypass for app self-checks (reading its own CDHash to compare) = hook the check function or alter the comparison result, same shape as Windows CRC self-checks.
- The hardening-awareness order (run once before analysis): codesign to see whether hardened runtime / entitlements contain library-validation exceptions → otool -l for an LC_ENCRYPTION_INFO encryption bit (rare on desktop, common on iOS) → strings for anti-debug traces (PT_DENY_ATTACH/sysctl).

## §6 The Detection Surface: EDR on mac Today

| Detection layer | Representative | RE/adversarial view |
|---|---|---|
| Network monitoring | Little Snitch-class (outbound firewall) | Before analyzing malware, confirm whether it's installed — outbound alerts will expose the C2; red-team-wise it is "the first user-mode-visible warning" |
| Endpoint EDR | CrowdSense/CrowdStrike/SentinelOne/Defender for Endpoint etc. | the kernel-kext route is dead (System Extensions took over): network-content filtering/endpoint-security frameworks are all user-mode agents + system extensions; bypass research = the System Extension API trust boundary |
| The system itself | XProtect (signature matching, silent)/Gatekeeper/notarization | XProtect's YARA rules match known samples; evasion thinking is same-shaped as Windows but the library is far shallower |
| Enterprise | MDM-pushed policies/certificates | attack surface = the MDM enrollment flow and config-profile forgery |

Public techniques of mac malware against EDR: killing/disabling the EDR's privileged XPC services (the XM Cyber pattern, annotated in the cross-platform kernel quick ref §3.1), tcc resets inducing users to re-authorize, LaunchDaemon footholds hunting EDR blind spots (user-level).

## §7 Migration and cross-link master table

| What you want to do | Where to go |
|---|---|
| Kernel bugs (XNU/Mach IPC/IOKit/SIP bypasses/TCC bypass patterns) | techniques/07-kernel/cross-platform-kernel.md §2 §3 |
| The iOS same-origin toolchain (ObjC runtime/jailbreak detection/fishhook) | ../04-ios/ios-re-fundamentals.md, ios-offense-defense.md |
| Capture confrontation (Flutter/BoringSSL/QUIC; equally applicable on mac) | techniques/04-evasion/capture-all-scenarios.md §2.7, vendor-capture-countermeasures.md |
| trace/frida pitfalls on mac (spawn limits) | techniques/13-trace/trace-practice.md, techniques/05-toolbox/tool-field-notes.md |
| Flutter so offset locating (this machine's IDA flow) | techniques/04-evasion/ssl-pinning-bypass.md §3.3 |
| Mach-O vs ELF field-by-field comparison, historical platforms | ../03-linux/other-platforms.md (this area's predecessor, pointer kept) |
