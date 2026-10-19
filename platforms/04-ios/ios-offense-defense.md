# iOS Offense and Defense, Advanced (anti-debug & anti-injection / jailbreak detection / hardening / malware / protocols / kernel / localization)

> Knowledge base 04-iOS security · file 2 of 2. File 1: [ios-re-fundamentals.md](ios-re-fundamentals.md) (Mach-O/runtime/dumping/debugging/Hook/signing/jailbreak).
> Positioning: file 1 is "how to take it apart"; this file is "how it blocks you while you take it apart + the deeper kernel surface".

## 1. Anti-Debug and Anti-Injection (following file 1 §7/§8)

### 1.1 sysctl detecting P_TRACED (the classic)

```c
struct kinfo_proc info; size_t sz = sizeof(info);
sysctl((int[]){CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}, 4, &info, &sz, 0, 0);
if (info.kp_proc.p_flag & P_TRACED) { /* 被 ptrace 附加 → 自杀/降级 */ }
```
- Countermeasure: hook `sysctl` and rewrite the flag bit in the returned buffer (fishhook can intercept it, because it goes through a symbol); or fix it at the kernel layer — bypassing anti-debug by hooking the kernel ptrace function via xnuspy (2024-06: read the corresponding xnu-7195.50.7.100 source `bsd/kern/mach_process.c`, use the pongoOS module xnuspy to hook a kernel function from user mode). Tool: xnuspy (repo address and supported iOS 13/14 versions in its repository).
- A 2026-era countermeasure example: an in-depth look at device-environment bypass on a QP platform (2026-03; verification checklist: pthread_getname_np thread-name spoofing/sysctl P_TRACED cleanup/filesystem leftovers).

### 1.2 ptrace (PT_DENY_ATTACH)

```c
ptrace(PT_DENY_ATTACH, 0, 0, 0);   // 之后任何 attach 被 kernel 拒绝
```
- Bypass: hook `ptrace` to turn the PT_DENY_ATTACH (31) call into a NOP; or race it by attaching before the call; in lldb, break `symbolic breakpoint ptrace` and change the return value.

### 1.3 svc inline (detection and counter-detection both escalated)

The target inlines `svc #0x80` to call `SYS_sysctl/SYS_ptrace` directly, bypassing the symbol table → fishhook fails (fully isomorphic to Android's direct svc calls; methodology cross-linked to the svc-interception chapter of `../../techniques/09-function-map/hook-fallback-playbook.md`). Defeats:
- lldb assembly breakpoints, NOP them one by one (traditional);
- Frida `Stalker`/hardware breakpoints intercepting svc;
- universal tools: the iOS anti-anti-debug assistant (instead of writing per-APP plugins/nops); anti-debug and bypass with HookZz (ptrace/syscall/inline svc, the full spectrum).
- Community field work: bypassing svc-based anti-dynamic-analysis by searching assembly on iOS (360 SRC, 2023-01; the board search reaches it by title).

### 1.4 Anti-debug techniques × bypass quick table (summary)

| # | Detection | Code surface | First-choice bypass | Fallback |
|---|---|---|---|---|
| 1 | sysctl P_TRACED | sysctl(KERN_PROC_PID) | fishhook/Tweak patching the buffer | xnuspy kernel layer |
| 2 | PT_DENY_ATTACH | ptrace(31,0,0,0) | hook ptrace NOP | pre-emptive attach race |
| 3 | svc inline direct call | inline svc #0x80 | lldb nop / Stalker | hardware breakpoints |
| 4 | timing-difference detection | delta of two mach_absolute_time reads | hook the time source (mind the vDSO-isomorphic pit, see techniques library area 09) | make breakpoints hardware breakpoints (zero pause) |
| 5 | exception self-check | raise(SIGTRAP) and see if a debugger swallows it | hook signal/the handling chain | Frida forwarding original semantics |
| 6 | debug symbols/ports | detect port 1234/debugserver process name | change the debugserver port + rename | — |

> Techniques 4/5 are fully isomorphic to Android (SignalTrap self-tests, timing anti-debug); principles cross-linked at `../../techniques/04-evasion/detection-landscape.md` §layered-difficulty table — the same "svc>libc>framework>language" layering becomes "svc>libSystem>OC/Swift" on iOS.

### 1.5 Anti-injection (detection-surface checklist)

| Detection | Code surface | Countermeasure |
|---|---|---|
| dylib injection enumeration | `dladdr(&fn)` to check whether an IMP lands in an expected image; walk `_dyld_image_count` against a whitelist | hook the enumeration functions to forge returns; or inject at the Dobby layer then unhook the dyld chain (isomorphic to the techniques-library so chain-unlinking) |
| Environment variables | `getenv("DYLD_INSERT_LIBRARIES")` | newer dyld ignores it; detection is mostly historical inertia |
| Method hook self-check | whether the IMP address sits inside this module's __TEXT range | point the swizzled IMP back into the original range (inline trampoline laid out inside the module) |
| fishhook self-check | read whether `__la_symbol_ptr` slots point at system libraries | use static linking/direct syscalls, or hook its verification function |

## 2. Jailbreak Detection and Bypass

### 2.1 The detection surface (an attacker's checklist; numerous but all thin)

A typical file-path detection implementation (fishhook can intercept it; listed for recognizing signatures):

```objc
// 典型检测代码(逆向时在 class-dump 头里常见 isJailbroken/canOpenURL 特征)
NSString *paths[] = { @"/Applications/Cydia.app", @"/usr/sbin/sshd",
                      @"/bin/bash", @"/private/var/lib/apt/", @"/etc/apt" };
for (p in paths) if ([[NSFileManager defaultManager] fileExistsAtPath:p]) return YES;
if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]) return YES;
pid_t p = fork(); if (p >= 0) { if (p == 0) exit(0); return YES; }  // 沙盒内 fork 必败,非负即越狱
if (dlsym(RTLD_DEFAULT, "MSGetSessionIdentifier")) return YES;  // Substrate 痕迹
```

1. **Files/paths**: `/Applications/Cydia.app`, `/usr/sbin/sshd`, `/bin/bash`, `/private/var/lib/apt`… (largely ineffective under rootless jailbreaks — the files simply are not at the traditional paths; the main reason detection difficulty spiked in the Dopamine era).
2. **Symlinks**: `/usr/sbin/sshd → /usr/libexec/sshd` (jailbreak relocation traces).
3. **Sandbox-escape checks**: whether writing to jailbreak-common directories outside the `/private/` root partition succeeds.
4. **fork/exec**: `fork` fails by default inside the app sandbox; success = abnormal environment.
5. **dylib list** (see §1.4).
6. **System-API behavior**: `UIApplication.shared.canOpenURL("cydia://")`; `system` return values.
7. **Symbol presence**: `dlsym(RTLD_DEFAULT, "MSGetSessionIdentifier")` (Substrate traces).

### 2.2 The bypass ecosystem

- **One-click Tweak family** (hook the detection functions inside the target app's process): A-Bypass, Liberty Lite (blinded by the light), Shadow, Choicy (per-app selective injection disabling). Principle = the swizzle/fishhook of §8, closing off the detection functions' return values.
- **The rootless jailbreak's innate advantage**: file-surface detection fails en masse; residual detection relies on the dylib/behavior surface, then closed off with Tweaks.
- **No-jailbreak route**: dump + re-sign + statically patch the detection functions (with file 1 §9); or the TrollStore flavor of jailbreak-free tweaks.
- Verification tool: the jailbreak-detection app — "The iOS jailbreak-detection app and beating detection with frida" (2023-06-06). That crackme covers 6 detection classes + matching frida bypasses — ① stat checking sensitive paths (`/Applications/Cydia.app`, `/usr/sbin/sshd`; hook `stat` to return -1); ② `_dyld_get_image_name` walking dylibs matching jailbreak libraries (hook and return a legitimate dylib name); ③ `-[UIApplication canOpenURL:]` probing cydia (when hooking, beware BOOL return-value replace crashing often; the author field-tested changing retval in onLeave); ④ `fileExistsAtPath` for jailbreak files/directories; ⑤ writability of `/private/` private paths (root after jailbreak; creating a file without error means flagged — when hooking, build a fake NSError via `ObjC.classes.NSError.alloc` and write it into the detection pointer); ⑥ lstat checking whether a path is a symlink (jailbreak relocation trace).
- Risk-control grade (device fingerprinting/consistency checks) is fully isomorphic to Android; cross-linked at `../../techniques/04-evasion/device-fingerprint-risk.md`.

## 3. Hardening and Obfuscation (hardening-techniques/obfuscation-and-deobfuscation nodes)

### 3.1 The commercial hardening matrix

| Vendor | iOS approach |
|---|---|
| Ijiami | local-data encryption/code obfuscation/program-structure shuffling |
| Dingxiang | deep executable obfuscation + VMP virtual-machine protection |
| NetEase Yidun | class/method/string obfuscation, anti class-dump |
| Tencent WeTest | atomic-level obfuscation matrix |
| 360 Tianyu/Baidu | packing + anti-re-signing + anti-repackaging |

iOS "packing" ≠ Android DEX packers: the iOS store mandates FairPlay which is already whole-file encryption; vendors focus on **source/link-time obfuscation + runtime anti-debug anti-injection + integrity checks (anti-re-signing/anti-Tweak)**. The RE teardown: deobfuscation methodology is fully isomorphic to Android OLLVM (control-flow flattening/bogus control flow/junk instructions), cross-linked to the four routes of `../../techniques/10-algo-restore/deobfuscation-practice.md`.

### 3.2 Open-source obfuscation: Hikari/OLLVM (iOS)

"iOS RE and security: obfuscating your source with OLLVM" (2023-02) is a starter sample of integrating OLLVM into Xcode; **Hikari** (an OLLVM fork) source reading: "Hikari source analysis - AntiDebug" (2024-01) — the obfuscator's own anti-debug pass instruments at compile time; the teardown = the generic anti-anti-debug of §1.

### 3.3 String/data encryption
Keychain, SQLite (SQLCipher), encrypted plists, resource protection (crypto trailers) — for grabbing keys, prioritize hooking CommonCrypto (`CCCrypt`/`CC_MD5`) and `SecItemCopyMatching`; the universal crypto self-extracting script idea is cross-linked at `../../techniques/02-frida/java-layer/crypto-and-self-dump.md` (on iOS, swap the objects for ObjC/CommonCrypto).

## 4. Malware (malware node)

The history of iOS malware and its representative surfaces:

| Event | Era | Mechanism | Analysis source |
|---|---|---|---|
| **XcodeGhost** | 2015 | tainted non-official-channel Xcode → compile-time implanting → thousands of App Store apps hit (WeChat/NetEase Cloud Music etc.); exfiltrated UDID/infection parameters; weak protocol encryption allowed MITM takeover | Antiy/Tencent analyses |
| WireLurker | 2014 | Mac-side infection of iOS over USB (enterprise-certificate mis-signing) | Palo Alto |
| Golduck/AceDeceiver etc. | 2016+ | enterprise-certificate re-signing distribution, certificate phishing | various vendor blogs |
| mDNS/Shortcuts/config-profile abuse | recent years | mostly social-engineering surfaces, not binary bugs | — |

Analysis essentials: iOS malware is almost all **user-mode + certificate abuse**, rarely memory-corruption; the analysis flow = dump (enterprise-signed/store package) → class-dump the reporting logic → capture the C2 protocol (§5). The XcodeGhost lesson (supply chain: developer toolchain contamination) maps directly onto SRC supply-chain audit surfaces.

## 5. Protocol Analysis (protocol-analysis node · cross-linked to the techniques library)

The difference between iOS capture and Android is only "the certificate system and tool names"; the methodology is fully shared, **main entry cross-linked** at `../../techniques/04-evasion/capture-all-scenarios.md` (the 13-scenario matrix) and `../../techniques/04-evasion/ssl-pinning-bypass.md`. iOS-specific surfaces:

| Surface | The iOS way |
|---|---|
| HTTPS capture | Charles/mitmproxy + **SSL Kill Switch 2** on the jailbroken phone (≈ Android's JustTrustMe); or a Frida script hooking `SSLHandshake`/SecTrustEvaluate |
| All traffic (no jailbreak) | Mac `rvictl -s <UDID>` creates an RVI virtual NIC → tcpdump/Wireshark (official doc: Recording a Packet Trace); cellular/WiFi/non-HTTP all captured, but TLS contents stay ciphertext |
| VPx/proxy-detection bypass | the Charles+Clash+Shadowrocket combo (2024-07) |
| Mutual auth / certificate pinning | dump the client certificate at the hook layer, same as the techniques-library ssl-pinning mTLS chapter |
| Private protocols | the r0capture idea transfers: hook `SSL_write/SSL_read` or the `nw_` Network.framework send/receive for plaintext |

Representative posts: reversing a news app's md5+aes on iOS (2024-04: jailbreak + frida + SSL Kill Switch 2 → Charles → md5-signature + aes-encryption restoration, a complete closed loop); "iOS RE first look - analysis and restoration of a variant AES encryption" (2023-06); "A novice's RE road, iOS capture bypassing SSL certificate validation" (2024-04). For Apple's own protocols (gsa/iTunes login) see the board's ppbb series (2017/2020, an improved SRP6a) — advanced protocol + cryptography references.

## 6. iOS Kernel Security (vulnerability nodes · index only, no expansion)

> **Cross-linked with `../../techniques/07-kernel/cross-platform-kernel.md` §2 (iOS/XNU), which already has the three-layer detail tables (attack surface/data structures/tools: KTRR/KDP/ipsw etc.); this file only keeps the index + iOS-exclusive essentials.**

| Topic | Essentials | Where to go deeper |
|---|---|---|
| XNU attack surface | Mach IPC (the mach_port permission matrix/send-once races), BSD syscalls (~540), IOKit cleanup paths, the kext→DriverKit migration | cross-platform quick ref §2 |
| **PAC** (ARMv8.3/A12+) | function-pointer + return-address signing; bypasses: PAC gadgets (trusted code co-signing), signature reuse, unprotected indirect jumps JOP | USENIX'23 "Demystifying PAC on Apple M1"; BH'23 "Apple PAC, Four Years Later"; P0 2019's first iPhone XS analysis |
| KTRR | kernel read-only protection of the A10/A11 era; A11 bypassed via external debug registers (KTRW) | cross-platform quick ref |
| PPL/SPTM/TXM/Exclaves | the next-generation convergence after PAC: page-table management/sensitive interrupts moved into higher-privilege layers | the alphaxiv "Modern iOS Security Features" survey (2025) |
| Kernel hooks | xnuspy (pongoOS module, hooks kernel functions from user mode, iOS 13/14) | the §1.1 post |
| Jailbreak and kernel chains | unc0ver (rootful kernel EoP) → Dopamine (CoreTrust + arm64e chain) | file 1 §10 |

Community posts: "The ultimate iOS hook arsenal" (2025: a layered roadmap from OC swizzle to ARM64e PAC bypass and kernel-level hijacking; the advanced sequel to §1/§6 of this file); a failed attempt at traceless hooking (ttxx 2023-08, board search — a pitfall log of kernel traceless confrontation, isomorphic to the techniques-library area-07 traceless chapter).

## 7. Game Localization (game-localization node)

iOS game localization is isomorphic to the Windows kind (knowledge-base tree 1000254/1000277); the differences are the resource formats and signing:

```
1) 拿 IPA(砸壳,见第1篇 §5) → 解包 Payload/*.app
2) 定位文本:
   - plist/json/sqlite/plain 字符串(多数 Unity/Cocos 转 iOS)
   - 资源打包:Unity 的 resources.assets/AssetBundle 用 UnityPy;
     自研格式 → IDA 逆加载函数定位索引结构
   - 本地化目录:*.lproj(官方多语言框架,改 zh-Hans.lproj 最省)
   - 字体:ttf/otf 缺字需补字形表(中文扩 A 免不了)
3) 改文本(等长/变长看索引是否有长度字段/哈希校验)
4) 重打包 + 重签(第1篇 §9 codesign/ldid/AltStore) → TrollStore/越狱机分发
5) 崩溃排查:完整性校验(CRC/CodeResources)→ 重签;文本越界 → 溢出
```
For Unity/IL2CPP games, logic-layer RE is fully same-origin with Android (the same IL2CPP/AssetBundle set), cross-linked to the techniques-library toolbox; under tree node 1001405 the digest post "Reverse engineering in Galgame localization" (1001486) has a directly transferable methodology: locate the font → pointer table → backfill.

## 8. Learning Path and Closing the "Others" Node

- Beginner: file 1 §2 Mach-O → class-dump your own app → dump one store app → attach lldb.
- Intermediate: a Tweak (file 1 §11) patching one detection function; Frida hook CommonCrypto to self-extract keys (§5).
- Advanced: anti-anti-debug (§1) → deobfuscation (§3) → xnuspy/kernel (§6).
- Isomorphic transfer: iOS↔Android hook-degradation/risk-control/capture are nearly one-to-one, see techniques-library areas 04/09; macOS is "a debuggable amplified iOS" (SIP can be disabled), cross-platform quick ref §4.

## 9. Reference table (this file)

| Topic | Item |
|---|---|
| Kernel ptrace bypass | xnuspy hooking kernel ptrace (2024-06) |
| Anti-anti-debug | the iOS anti-anti-debug assistant |
| Anti-debug full spectrum | anti-debug and bypass with HookZz |
| Environment bypass (2026) | device-environment bypass on a QP platform |
| Protocol restoration | reversing a news app's md5+aes on iOS (2024-04) |
| Advanced hooking | the ultimate iOS hook arsenal (2025) |
| Malware | XcodeGhost analysis (Antiy) |
| PAC academic | USENIX'23 M1 PAC |
| PAC black hat | Apple PAC Four Years Later |
| RVI official | Recording a Packet Trace |
| Jailbreak-detection app + frida bypass | the iOS jailbreak-detection app and beating detection with frida |
| svc anti-debug bypass | bypassing iOS ptrace anti-debug based on svc 0x80 (2022-07); also see "bypass svc 0 PTRACE_TRACEME" |
| Tweak intro | Tweak development: adding vibration feedback to volume changes |
| Traceless hooking | implementing an SVC TraceHook sandbox & traceless-hook ideas (2022-06; ptrace+seccomp intercepting inline SVC) |
| Jailbreak detection (discussion) | using AI to bypass iOS jailbreak detection (third-party SDKs GeoComply/Incognia/Sift, 2026-04) |
| iOS inlinehook vs anti-debug | beating anti-debug with iOS inlinehook |
| Jailbreak-free hooking | tampering the dynamic symbol table to hook without a jailbreak |
| Dumping | dumping an iOS app with one command / ios-dumpdecrypted |
