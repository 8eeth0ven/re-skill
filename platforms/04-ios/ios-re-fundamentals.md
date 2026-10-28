# iOS RE Fundamentals (Mach-O / runtime / dumping / debugging / Hook / signing / jailbreak and Tweak)

> Knowledge base 04-iOS security · file 1 of 2. File 2: [ios-offense-defense.md](ios-offense-defense.md) (anti-debug/jailbreak detection/hardening/malware/protocols/kernel/localization).
> Cross-platform links: the Android-side methodology is at `re/techniques/` (Frida quick refs/unpacking/evasion); for overlapping content this file gives anchors only, no expansion.

## 1. Overview: the iOS RE technology stack at a glance

iOS RE is isomorphic to Android RE; the differences concentrate in "the strong constraints of a closed ecosystem": App Store distribution must be signed + FairPlay-encrypted, the system volume is read-only, and the runtime is OC/Swift rather than Java/Kotlin. The typical workflow:

```
Obtain IPA (dump from a jailbroken device / capture an App Store package) → decrypt FairPlay → unpack Payload/*.app
  → Static analysis (class-dump headers + Mach-O in Hopper/IDA)
  → Dynamic analysis (lldb attached through debugserver / Frida hooks)
  → Modify (re-sign/repackage / inject Tweak) → handle detection (see the second article)
```

Compared with Android (detailed methodology cross-linked at `../../techniques/05-toolbox/tool-master-table.md`):

| Stage | Android | iOS |
|---|---|---|
| Package format | APK (zip+DEX) | IPA (zip+Mach-O) |
| Store encryption | none (vendor hardening instead) | FairPlay (LC_ENCRYPTION_INFO) |
| Unpacking | memory-dump the DEX (see techniques library area 03) | dump the decrypted __TEXT after "decryption" |
| Header export | jadx decompiles Java | class-dump exports OC headers |
| Runtime hook | Xposed/Frida Java layer | Method Swizzle/Frida/Substrate |
| native hook | GOT/inline (Dobby/ShadowHook) | fishhook (lazy/external symbols)/Dobby inline |
| Debugging | IDA/Android Studio + gdbserver | lldb + debugserver |
| root | Magisk | jailbreak (unc0ver/Dopamine) |

## 2. The Mach-O File Format (basic-theory/file-format nodes)

### 2.1 Overall layout

```
+------------------------+ File offset 0
| Mach-O Header (32B)    | magic (cffaedfe=64-bit little-endian)/cputype/cpusubtype
|  filetype/ncmds/       | ncmds=number of Load Commands
|  sizeofcmds/flags/reserved
+------------------------+
| Load Commands         | sizeofcmds bytes; each starts with cmd+cmdsize
| LC_SEGMENT_64 __TEXT   | → Mapped segment permissions and Section table
|  LC_SEGMENT_64 __DATA   |
| LC_DYLD_INFO_ONLY      | → bind/lazy-bind relocation information
| LC_SYMTAB/LC_DYSYMTAB  | → Symbol table/dynamic symbol table
| LC_LOAD_DYLIB ×N       | → Dependent dynamic libraries
| LC_CODE_SIGNATURE     | → Signature blob
| LC_ENCRYPTION_INFO_64  | → cryptoff/cryptsize/cryptid (key fields for decryption)
+------------------------+
| __TEXT segment (r-x)  | __text/__stubs/__stub_helper/__objc_methname...
| __DATA segment (rw-)  | __got/__la_symbol_ptr/__objc_classlist/__cfstring...
| __LINKEDIT (read-only)| Symbol/string tables, signatures, function-address table
+------------------------+
```

Essentials:
- **The segment is the memory-mapping unit** (page-aligned 16KB/4KB); sections are logical partitions inside a segment; `__LINKEDIT` holds no code, just the metadata dyld needs.
- `otool -h/-l/-L`, `lipo -info`, MachOView are the quick-reference trio; for a systematic compare-and-contrast of Mach-O vs ELF see the corpus posts "Mach-O from the ground up" (2020; the full chain from the kernel's `load_machfile` to dyld loading) and "First notes on Mach-O" (Header/ncmds/sizeofcmds/flags field by field).
- Loading flow: the kernel parses the mach-o → maps __TEXT → hands off to dyld → dyld processes LC_LOAD_DYLIB dependencies → rebase/bind (patching `__DATA` pointers) → calls init. During RE, the bind info (LC_DYLD_INFO) directly tells you "which external symbol was written into which address" — a shortcut to locating API calls.

### 2.2 Fat Binary (multi-architecture)

Store packages are usually FAT: after the `FAT_HEADER(magic 0xcafebabe, nfat_arch)` come n `fat_arch{cputype, cpusubtype, offset, size, align}`. Before analysis, extract the target slice with `lipo -thin arm64 xx -output xx.arm64`, or tools may parse the wrong architecture. For the same tree directory, compare the handling of multi-architecture Android ELF so (techniques library area 05).

### 2.3 LC_ENCRYPTION_INFO and FairPlay

```c
struct encryption_info_command_64 {
  uint32_t cmd;        // LC_ENCRYPTION_INFO_64 = 0x2C
  uint32_t cmdsize;
  uint32_t cryptoff;   // Encrypted region file offset (inside __TEXT)
  uint32_t cryptsize;  // Number of encrypted bytes
  uint32_t cryptid;    // 0=unencrypted self-built package; 1=App Store FairPlay encryption
  uint32_t pad;
};
```
When `cryptid=1`, the `cryptsize` bytes starting at `cryptoff` are FairPlay ciphertext, decrypted by the kernel only at load time into memory — so static tools see ciphertext on disk; this is the root cause of "you must dump the decrypted binary" (§5).

## 3. The Objective-C Runtime (reverse-analysis node)

### 3.1 objc_msgSend message dispatch

OC method calls compile to `objc_msgSend(id self, SEL _cmd, ...)`; on arm64 it is hand-written assembly (no stack frame); the flow:

```
objc_msgSend:
  LDR  x16, [x0]           ; x0=self; load isa → class (apply ISA_MASK)
  LDR  x11, [x16, #CACHE]  ; Method-cache buckets
  ... cache hit → tail-call IMP
  Cache miss → __objc_msgSend_uncached → lookUpImpOrForward
    ① class_rw_t method list, including categories ② walk the superclass chain
    ③ Still missing → _objc_msgForward → message forwarding (resolvesInstanceMethod/
       forwardingTargetForSelector/methodSignatureForSelector+forwardInvocation)
```

RE value:
- **Method names are all plaintext**: the `__objc_methname` section stores SEL strings; `strings`/class-dump restore the full class-method-property map directly — even when the C side is stripped, the OC surface is unaffected.
- The three message-forwarding stages are the usual hiding place for "detection-class" logic; a breakpoint on `_objc_msgForward` catches every forwarded call.
- IMP addresses can be computed straight from `class_rw_t->methods`, paired with batch annotation in IDA (IDAPython walking `__objc_classlist`; see the tools-plugins/IDA node).

### 3.2 class_ro_t / class_rw_t / cache_t

```
objc_class ──ISA──> metaclass
   │ DATA()
   ▼
class_rw_t (runtime writable)     class_ro_t (compile-time read-only)
  flags/version                     class name/layout
  methods/properties/protocols       baseMethods (base list for category merging)
  demangledName
  ro ────────────────────────────►
cache_t: masked buckets (SEL→IMP), concurrent reads/writes,
  Dumping it during analysis reveals the methods actually invoked
```
- Categories merge into `class_rw_t` at runtime via `attachCategories`, so **static Mach-O analysis must scan `__objc_catlist`**, or you miss logic hidden in categories (anti-debug often hides there).
- Swift classes also bridge through the OC runtime (`swift_unknownObjectRetain` etc.), but method dispatch prefers vtables/static dispatch; see §4.

## 4. Swift RE (TypeMetadata / VWT)

Swift build artifacts are unfriendly to RE: symbols mangled (`_$s4main4CalcV3addyySiF` and the like), value types skip OC messaging, and release builds specialize generics + optimize structures apart. Essentials:

| Structure | Role | RE significance |
|---|---|---|
| TypeMetadata | type metadata (Kind/Name/field descriptors/superclass) | demangle `$s…mangledName` (`swift demangle`/IDA plugin) to restore the type hierarchy; the `__swift5_types` section is the entry |
| ValueWitnessTable (VWT) | value-type init/copy/destroy function table | struct lifecycle hook points; enum/optional tag discrimination is also on VWT-related paths |
| Protocol Witness Table | protocol dispatch table | the actual landing point of protocol method calls (like a vtable) |
| ContextDescriptor | module/type/extension/anonymous-function descriptors | `__swift5_fieldmd` restores field names (less info than the OC era but usable) |

Calling convention: Swift passes arguments in registers by default (from x0; self's position follows context); only @objc/exported items are visible to class-dump. Intro posts: "Swift RE: Better to Teach Fishing Than to Hand Out Fish" (2025-12, incl. the "how to start on another app" methodology), "Reverse analysis of a Swift-written app" (2018, the Prisma case). Repairing argument calling conventions after obfuscation (compile-optimization-induced x0-x7 misalignment) is an advanced pitfall.

## 5. Decryption-Dump Principles and Tools (decryption-techniques node)

### 5.1 Principle

FairPlay encrypts only the on-disk file; the kernel/AMFI decrypts it into physical pages at load. So dumping = **let the app run → dump the decrypted __TEXT from process memory → repair the Mach-O → set cryptid to 0**.

```
On disk: cryptid=1 (ciphertext) ──kernel load+AMFI decryption──> plaintext in memory
                                           │
                    frida attach / debugserver / ptrace
                                           ▼
              memory read cryptoff~cryptsize → write to the same file offsets
              header: cryptid=1→0 (otherwise the loader expects further decryption)
              Optional: re-sign/strip LC_CODE_SIGNATURE
```

### 5.2 Tool matrix

| Tool | Principle | Traits |
|---|---|---|
| dumpdecrypted | the cycript-era classic; dylib injection then decrypt-dump | still works on old systems (A9/32-bit), basically retired on new iOS |
| frida-dump / frida-ios-dump | frida attach → locate the module via `_dyld_image` → Memory.read the segments | the current mainstream; paired with SSL Kill Switch 2 the capture chain is complete |
| Clutch | pure native, fast | one command on a jailbroken phone |
| Bagbak / flexdecrypt etc. | node/CLI wrappers | batch-oriented |
| vesper (agent platform) | MCP platform + agent skill wrapping SSH/Frida/optional licensed IDA: reused-session frida-ios-dump decryption, UIKit view-tree inspection/screenshots, ObjC runtime headers, batched UI automation, LLDB/Frida debugging, headless-IDA decompile, Theos tweak build/deploy/verify | rootless jailbreaks are the primary target, frida 17.5+ host/device must match; the agent-era one-stop shell over the tools above (`uv pip install` from the repo, macOS/Linux host) |

Flow (frida-ios-dump): on the Mac `python dump.py -H <phone IP>`, frida-server installed on the jailbroken phone; zip the dumped `.app` directly into an analyzable IPA. Isomorphic with Android memory-dumping DEX; methodology cross-linked at `re/techniques/03-unpacking/`. To verify the dump is clean: `otool -l` shows `cryptid 0` + Hopper can disassemble the plaintext `__text`.

## 6. Static Analysis Tools (tools-plugins/IDA node)

| Tool | Positioning | iOS-specific use |
|---|---|---|
| class-dump (-z for swift support) | export OC headers | the first shot after dumping: the full class/method/property/protocol map |
| Hopper | value-for-money disassembler | arm64 + OC runtime annotation, pseudocode; native to macOS |
| IDA | deep static | load after FAT unpacking; IDAPython walks `__objc_classlist` to auto-name IMPs; rich Mach-O plugins (tree node 1001484) |
| Ghidra | free alternative | paired with Swift demangle scripts |
| MachOView / otool / lipo | structure quick reference | Load Commands/segments/encryption info |
| ipsw / class-dump-swift | supplements | kernel research in file 2 |

Selection: quick class-relationship scan class-dump → medium-depth Hopper → deep logic/scripting IDA. The isomorphic Android comparison is at `../../techniques/05-toolbox/static-analysis-tools.md`.

## 7. Dynamic Debugging: lldb + debugserver (debugging node)

The standard chain on a jailbroken phone (unsigned errors require re-signing debugserver, see §9):

```
1) Device: /usr/lib/debugserver (bundled on jailbreaks; newer systems require copying it out and using ldid
   to sign platform-application+get-task-allow before placing it back)
2) debugserver 127.0.0.1:1234 -a "TargetApp" (attach), or -w to wait for spawn
3) USB forwarding: iproxy 1234 1234
4) Mac: lldb → process connect connect://127.0.0.1:1234
```

Common command quick reference:
```
image list -o -f        # Modules and ASLR slides
br s -a 0x1000+0x1234   # Breakpoint using the slide
br set -n "-[Class sel:]"  # Breakpoint on an Objective-C symbol; requires unstripped symbols or class-dump reconstruction
register read / x/32xw 0x...   # Registers/memory
expr -- (void)method...  # Dynamic Objective-C invocation
```
Kernel debugging (KDP) and traceless confrontation: file 2 §6 and `../../techniques/07-kernel/cross-platform-kernel.md`. Anti-debug confrontation (sysctl P_TRACED/svc inline ptrace) in full in file 2 §1.

## 8. Hook Techniques (Hook-techniques node)

### 8.1 fishhook: __DATA symbol rebinding

Principle: Mach-O lazy/external symbol references live in `__DATA`'s `__la_symbol_ptr` (lazy)/`__nl_symbol_ptr` and the GOT; at dyld `bind` time real addresses are written per LC_DYLD_INFO. fishhook walks every image's indirect symbol table at runtime, swapping the slots of target symbols (like `open`/`stat`/`sysctl`) for its own functions while saving the originals:

```
Call stat() ──► __DATA,__la_symbol_ptr[idx] ──► my_stat (fishhook rebinding)
                                      │ save original
                                      ▼
                              Original libsystem_kernel stat
```
- It can only hook **external C functions that go through the symbol table** (system-library calls); it cannot hook OC methods/static inlines/direct syscalls — which is also the fundamental reason fishhook gets bypassed (the target calls svc directly; see file 2 §1.3).
- Typical uses: intercepting file/network checks in a Tweak, covering the jailbreak-detection surface.

### 8.2 Method Swizzling / CaptainHook

At the OC layer, `method_exchangeImplementations` swaps IMPs, or the CaptainHook macro suite (the `CHOptimizedMethod` series) makes swizzling declarative. Most used inside jailbreak Tweaks; combined with Logos's `%hook` syntax (§11) it is essentially the same. Detectors commonly check "whether the IMP still points into a __TEXT whitelist range" (file 2 §2).

### 8.3 The Substrate family and inline hooks

| Framework | Layer | Notes |
|---|---|---|
| Cydia Substrate (MsHookFunction) | inline | the traditional jailbreak standard, commercial closed source |
| Substitute / ElleKit | inline | open-source replacement; Dopamine (rootless) defaults to ElleKit, Substrate-API compatible |
| Dobby | inline | cross-platform arm64 inline hook, usable from Tweaks and standalone injection; same origin on Android (comparison in techniques library area 05) |
| libhooker | inline | the CoolStar lineage of the rootless era |

Inline hooks on arm64e (PAC) devices must handle pointer authentication (A12+); the mainstream frameworks have it built in; hand-written hooks need `pacibsp/braa` semantics alignment (see file 2 §6 PAC).

### 8.4 Hook detection and countermeasures
IMP whitelists, `dladdr` to check address ownership, fishhook self-checks (whether `__la_symbol_ptr` slots sit in system-library ranges) — the full confrontation in file 2 §1/§2.

### 8.5 Frida (iOS)
Install frida-server on a jailbroken phone for full functionality: at the OC layer `ObjC.classes.xxx['- method:']` hooks directly (usage isomorphic to the Android Java layer; quick refs cross-linked at `re/techniques/02-frida/java-layer/`); at the native layer `Module.findExportByName('libsystem_c', 'open')` corresponds to the fishhook surface. Tree node 1001407. iOS-specific pitfall: on arm64e, when hooking system libraries is restricted by PAC, switch to the Dobby/substrate route.

## 9. Signing and Re-signing (signing node)

### 9.1 Signature structure

```
IPA ── _CodeSignature/CodeResources (resource-hash inventory)
  └─ Mach-O LC_CODE_SIGNATURE → CMS blob
       ├─ CodeDirectory (hash slots: SHA256 for each 4KB page)
       ├─ entitlements (keys: application-identifier/teamid/
       │    get-task-allow/keychain-access-groups/aps-environment…)
       └─ Certificate chain + Provisioning Profile (embedded.mobileprovision)
```
- `get-task-allow=true` is the debugging switch — mandatory for re-signed debug builds; store packages have it false, and ldid cannot mint equal force (Apple root certificate); the only three real paths are developer certificates/enterprise certificates/AltStore free certificates.
- entitlements decide the capability boundary (extensions/VPN/multitasking); `CS_KILLED` errors during hooking/debugging are usually missing entitlements.

### 9.2 Tools and the three exception paths

| Tool/scheme | Usage | Limits |
|---|---|---|
| codesign (Xcode built-in) | `codesign -f -s "Apple Development: …" --entitlements ent.plist xx.app` | needs Mac + certificate |
| ldid (the jailbreak standard) | `ldid -e xx` (view entitlements)/`ldid -Sent.plist xx` (inject entitlements) | pseudo-signing; works in jailbreak/TrollStore environments |
| AltStore / Sideloadly / SideStore | sideloading without a paid developer account (7-day re-signs; free accounts capped at 3 apps) | SideStore can renew without a computer |
| TrollStore (CoreTrust bug) | permanently signs any IPA with entitlements, no jailbreak | limited to version windows like iOS 14.0~17.0 (same-origin bug as Dopamine, see §10) |

Community field posts: "iOS signing notes (II)" (2020; ldid -e to inspect entitlements/signing details), "A short talk on using the signing tools ldid and codesign" (2017; the complete operation of signing get-task-allow onto debugserver). Re-signing flow template: dumped IPA → change Bundle ID → swap embedded.mobileprovision → `codesign`/`ldid` re-sign every Mach-O (mind signing each Frameworks/PlugIns subdirectory one by one) → zip repackage.

## 10. The Jailbreak Landscape

| Generation | Tool | Type | Mechanism essentials |
|---|---|---|---|
| Classic | redsn0w/evasi0n/Pangu series | untethered/tethered | bootrom/iBoot bugs; sealed by hardware into history |
| checkra1n | checkm8 (A5~A11) | tethered semi-perfect | the bootrom bug cannot be sealed; nothing after A11 |
| unc0ver / Taurine | kernel bugs | rootful semi-untethered | writes the / filesystem; re-jailbreak after reboot; the Sileo/Cydia ecosystem |
| Fugu15 → **Dopamine** | CoreTrust + kernel chain | **rootless** semi-untethered | maintained by opa334, iOS 15~18.x (updated per version); does not write the root partition, jailbreak files live in /var/jb, Tweaks must be compiled rootless; paired with the **Procursus** package repo + Sileo |
| palera1n | checkm8 (A8~A11) + iOS15+ | rootless optional | the Checkra1n successor |
| TrollStore | CoreTrust | non-jailbreak | only permanently signs IPAs; no system-level injection |

The security-research meaning of rootless: jailbreak traces shrink drastically (`/`, `/usr` untouched read-only), directly relevant to jailbreak-detection confrontation (file 2 §2). Procursus is a cross-distro package base whose isolated design lowers the risk of plugins polluting /usr.

## 11. Tweak Development: theos + Logos (programming-development node)

Environment: `brew install ldid` + theos → `nic.pl`, pick the tweak template. Makefile sets `TARGET = iphone:clang:16.5:15.0` (rootless adds `THEOS_PACKAGE_SCHEME=rootless`).

Logos syntax (compiles into `_logos_register` + method swizzle/inline hook):

```objc
%hook TargetClass
- (BOOL)isJailbroken {
  return NO;                       // Change the return value directly
}
%new(addGroup)                      // Add a method
- (void)hookedNewMethod { ... }
%end

// Constructor registers automatically; fishhook/inline hooks can supplement the ctor
%ctor {
  %init(TargetClass);
}
```

Console output: `%log` prints the call stack; install: `make package install` (scp to the device's /var/jb or the classic path). Debugging: a Tweak is essentially a dylib (injected by Substitute/ElleKit under MobileSubstrate/Dopamine), and logic errors crash with the host — swizzle in small steps first, then add complex logic. Intro post: [iOS RE and security] A lightning introduction to iOS plugin development (2022-12).

## 12. Master reference table

| Topic | Item | Link |
|---|---|---|
| Mach-O full chain | Mach-O from the ground up (2020) |  |
| Mach-O primer | First notes on Mach-O |  |
| Swift RE methodology | Swift RE: teaching fishing (2025) |  |
| Swift field case | Reverse analysis of a Swift-written app (2018) |  |
| Signing | iOS signing notes (II) (2020) |  |
| Signing tools | Using ldid and codesign (2017) |  |
| Hook panorama | The ultimate iOS hook arsenal (2025) |  |
| Board entry | The iOS security board (1478+ topics) |  |
| Jailbreak tools | Dopamine (rootless) |  |

> frida-ios-dump is the current mainstream dumping tool; search the board for "dump/decryption" to extend the chain.
