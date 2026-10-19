# Techniques Branch Master Index (one of the re entry points · read-only routing)

> Usage: the entry point is the branch routing in ../../SKILL.md; per task, open 1-2 named files from the table below — reading the whole library is forbidden.
> Structure: technique dimension (frida/unpacking/evasion/toolbox/kernel/functions/algorithms/chains/decisions); platform and domain knowledge goes through the ../platforms/ branch.
> Code files can be copied and used directly; **when your hook gets killed, open 12-bypass first**.

## 01-methodology

| File | When to open |
|------|-----------|
| [r0re-architecture.md](01-methodology/r0re-architecture.md) || Want to understand the engineering of multi-LLM-session collaborative APK reversing: the four-piece set / swarm loop / verification gates / prompt highlights |
| [llm-reverse-orchestration.md](01-methodology/llm-reverse-orchestration.md) || Replicating it with ZCode subagents: three roles / blackboard / sharding / **copy-paste DAG template** / anti-patterns |

## 02-frida

| File | When to open |
|------|-----------|
| [env-and-quickstart.md](02-frida/env-and-quickstart.md) || Setting up the environment, spawn/attach, custom ports, frida-trace |
| **java-layer/** (subdirectory, 6 files, use by domain) | | |
| [java-layer/network-and-webview.md](02-frida/java-layer/network-webview.md) || okhttp/URL/Uri/WebView/loadUrl/addJavascriptInterface |
| [java-layer/crypto-and-self-dump.md](02-frida/java-layer/crypto-and-self-dump.md) || Cipher/Mac/MessageDigest/Signature/**crypto self-dump all-in-one** |
| [java-layer/storage-and-system.md](02-frida/java-layer/storage-and-system.md) || SP/ContentResolver/package names/**PMS signature forgery**/screen-capture protection removal/hidden packages/accessibility/OAID |
| [java-layer/ui-and-navigation.md](02-frida/java-layer/ui-and-navigation.md) || Toast/Dialog/Activity navigation/Intent construction/goto_activity |
| [java-layer/strings-and-json.md](02-frida/java-layer/strings-and-json.md) || StringFactory/StringBuilder/org.json/fastjson |
| [java-layer/sslpinning-and-certificates.md](02-frida/java-layer/sslpinning-and-certificates.md) || SSLContext.init/dump client certificate p12/certificate locator |
| [native-hook-quick-ref.md](02-frida/native-hook-cheatsheet.md) || so layer: NewStringUTF/dlsym/dlopen/pthread/clone/strstr/RegisterNatives/init_array + utility functions |
| [frida-api-in-depth.md](02-frida/frida-api-reference.md) || Process/Memory/NativeFunction type tables/Java($h/$l/$p/ArtMethod offsets/fromJni proactive invocation) |
| **advanced/** (subdirectory, 6 files, advanced topics per theme) | | |
| [advanced/stalker.md](02-frida/advanced/stalker.md) || Stalker principles/transform/hang troubleshooting/putCallout/register modification/log buffering |
| [advanced/gothook.md](02-frida/advanced/gothook.md) || GOT hook, two complete routes: ELF header parsing to find the GOT + the soinfo-based GotHook |
| [advanced/patch-and-memory.md](02-frida/advanced/patch-and-memory.md) || patchCode/Arm64Writer(nop/ret) |
| [advanced/yahfa-and-art-hook.md](02-frida/advanced/yahfa-and-art-hook.md) || yahfa full loading wrapper + ARTHookScripts ShadowFrame mechanism |
| [advanced/so-soinfo-ops.md](02-frida/advanced/so-soinfo-ops.md) || soinfo unlink soListRemove (details in gothook and the 03 area) |
| [advanced/detection-bypass-snippets.md](02-frida/advanced/detection-bypass-snippets.md) || usb/adb detection bypass/removing rwxp/vpn proxy bypass/TrustManagerImpl precise locating/CertificatePinner source highlights |

## 03-unpacking

| File | When to open |
|------|-----------|
| [dex-unpacking.md](03-unpacking/dex-unpacking.md) || DexFile constructor method/DefineClass method/finding the classLoader/scheme selection (FART fails on A12-16) |
| [ebpf-unpacking-deep.md](03-unpacking/ebpf-unpacking-deep.md) || **deepest scheme**: eBPF stealth/ART entry shapes (DexFile::DexFile x1=DEX begin)/-rs repair pipeline/comparison against frida |
| [so-repair-dump.md](03-unpacking/so-repair-dump.md) || soinfo offset table/solist traversal/dumpSoFromSoInfo/segment backfill |

## 04-evasion

| File | When to open |
|------|-----------|
| [detection-landscape.md](04-evasion/detection-landscape.md) || **evasion starts by picking the layer**: anti-debug/frida/root/emulator/VPN/RASP detection down to the syscall layer + layered difficulty table |
| [rasp-bypass.md](04-evasion/rasp-bypass.md) || Commercial packer evasion: identification signature table/five-layer bypass methodology/cases/checklist |
| [frida-anti-detection.md](04-evasion/frida-anti-detection.md) || Changing signatures/hooking detection functions/taking gadget underground/escalating the arms race + four-phase checklist |
| [root-env-hiding.md](04-evasion/root-env-hiding.md) || Magisk+Shamiko/KSU/APatch/residual-surface handling/finance-grade detection stacks |
| [ssl-pinning-bypass.md](04-evasion/ssl-pinning-bypass.md) || Five pinning classes, locating and bypass scripts/Flutter offsets/mTLS |
| [capture-all-scenarios.md](04-evasion/capture-all-scenarios.md) || **General traffic-capture main entry**: 13-scenario matrix (certificates/VPN chains/QUIC/Flutter/encrypted payloads/private protocols) |
| [vendor-capture-countermeasures.md](04-evasion/vendor-capture-countermeasures.md) || **Per-vendor specials**: ByteDance/Alibaba/WeChat/Meituan/JD/Xiaohongshu/Kuaishou/Pinduoduo etc. in 16 sections; each vendor's network stack/locking layer/**key functions and so files**/capture-path gradient + universal patterns (switch-to-RPC decision points/give-up signals) |
| [device-fingerprint-risk.md](04-evasion/device-fingerprint-risk.md) || 66 collection surfaces/consistency checks/L1-L4 forgery/risk-control SDK cases/captcha/JA3 self-check |

## 05-toolbox

| File | When to open |
|------|-----------|
| [tool-master-table.md](05-toolbox/tool-master-table.md) || **Selection entry**: master table of 100+ tools + decision tree for picking a toolchain by target |
| [dynamic-hook-frameworks.md](05-toolbox/dynamic-hook-frameworks.md) || frida ecosystem/Xposed family/inline-hook trio (Dobby/ShadowHook/Renef)/version compatibility matrix |
| [static-analysis-tools.md](05-toolbox/static-analysis-tools.md) || Decompiler shoot-out/ROSAL deobfuscation/SnikrFlow symbolic execution/DexKit/packer identification |
| [emulation-frameworks.md](05-toolbox/emulation-frameworks.md) || unidbg usage/environment-patching pitfalls/comparison against frida |
| [tool-field-notes.md](05-toolbox/tool-field-notes.md) | Command-level hands-on: jadx all flags (single class in seconds/--fallback deprecated/--deobf ruins non-obfuscated packages)/r2 workflow (the aflj key-name pitfall)/androguard reusable scripts/frida local spawn·attach (macOS can only spawn CLI targets) |
| [tool-detection-and-modding.md](05-toolbox/tool-detection-and-modding.md) | **Tools × evasion three-column master table** (19 tools: detection surface/modification paths)/frida four-signature audit/repackaging chain and V1·V2 signature bypass/four-layer modification methodology (L1 deployment→L4 replacement)/zero-detection-surface checklist and the "go offline whenever you can" decision rule |
| [recon-and-specials.md](05-toolbox/recon-and-specials.md) || **First minute with an unknown APK**: APKiD/apkleaks/DIE/UltraSina etc. |

## 07-kernel

| File | When to open |
|------|-----------|
| [android-kernel-ebpf.md](07-kernel/android-kernel-ebpf.md) || GKI/Binder·Futex·io_uring attack surfaces/bpftrace three practical scripts/boot.img symbol extraction/KGDB |
| [kernel-hook-stealth.md](07-kernel/kernel-hook-stealth.md) || ftrace/kprobe/fentry/LSM comparison/wxshadow shadow pages fully explained/"why it cannot be detected" |
| [kernel-symbol-locating.md](07-kernel/kernel-symbol-locating.md) || Five symbol routes/KASLR bypass/binder location in six steps/svc_hook/perf_event hardware breakpoints |
| [kernel-exploit-fuzzing.md](07-kernel/kernel-exploit-fuzzing.md) || Primitive chains/Dirty Frag family/syzkaller/"when to drop to the kernel" decision tree |
| [cross-platform-kernel.md](07-kernel/cross-platform-kernel.md) || iOS/macOS/Windows/generic kernel attack surface comparison |

## 08-ai-re

| File | When to open |
|------|-----------|
| [ai-re-tools.md](08-ai-re/ai-re-tools.md) || REA/MobileRE-Skill/LSPilot/jniq/dexllm/frida-mcp shoot-out + selection decision tree |
| [ai-re-workflows.md](08-ai-re/ai-re-workflows.md) || analyze→hook→verify→replay pipeline/3 copy-paste prompts/five pitfalls and five acceptance gates |

## 09-function-map

| File | When to open |
|------|-----------|
| [android-function-layers.md](09-function-map/android-function-layers.md) || **Foundation of the whole library**: 12 functional domains mapped over five layers (Java→JNI→libc→syscall→kernel) + syscall number quick reference |
| [hook-fallback-playbook.md](09-function-map/hook-fallback-playbook.md) || hook killed→four-death-cause decision tree→six downgrade cases (runnable code)→svc interception compendium |

## 10-algo-restore

| File | When to open |
|------|-----------|
| [algo-restoration-methodology.md](10-algo-restore/algo-restoration-methodology.md) || Three-layer route/algorithm fingerprinting/white-box AES+DFA/three-step modification method/12-parameter case/unidbg environment patching |
| [deobfuscation-practice.md](10-algo-restore/deobfuscation-practice.md) || 8 obfuscation classes/flattening four routes + unicorn·angr skeletons/VMP five steps/decision tree |
| [jsvmp-vmp-lifter.md](10-algo-restore/jsvmp-vmp-lifter.md) || **Lifter hands-on layer**: JSVMP five-piece anatomy/handler semantics extraction via two routes (static babel + dynamic differential probe)/translator + replay diff, three interlocking scripts/dex VMP four-step engineering/JSVMP·dex·native VM locating and the RPC decision |
| [protocol-offline-rpc.md](10-algo-restore/protocol-offline-rpc.md) || **Offline-ization main entry**: three-stage rocket/frida RPC engineering (JS+Python skeleton)/protobuf black-boxing/anti-replay/JA3 preservation |
| [ollvm-internals-and-passes.md](10-algo-restore/ollvm-internals-and-passes.md) || **Obfuscator generation side**: Flattening/SplitBBlocks Pass source in six steps/instruction bloat·junk-code insertion/logic-equivalence formulas (the nor universal gate)/branch encryption (Hikari vs Goron)/three generations of string encryption compared + writing your own Pass/arm landing shapes |
| [deobf-cases-static.md](10-algo-restore/deobf-cases-static.md) || **Static restoration, 8 cases**: junk-code signature checklist and patch scripts/Hex-Rays two-step BCF kill/Binary Ninja deflattening with HLIL extraction/ARM64-specific three-round iteration/initArray string decrypt-and-backfill/IDA&FRIDA joint debugging |
| [deobf-cases-dynamic.md](10-algo-restore/deobf-cases-dynamic.md) || **Dynamic restoration, 7 cases**: Unicorn deflattening (arm32 TBB/TBH)/full-instruction trace to a C reimplementation/AES·MD5 hook chain reasoning/MBA negation simplification/Xposed brute force; case parameters·hook points·pitfalls ready to adapt |

## 11-syscall-chain

| File | When to open |
|------|-----------|
| [observation-matrix.md](11-syscall-chain/observation-matrix.md) || **The collection point — check here first for any "where do I hook" question**: 35-row × 7-column observation-point matrix + 20 reverse task lookups |
| [file-attr-chain.md](11-syscall-chain/file-attr-chain.md) || openat→do_sys_openat2→pagecache/proc pseudo-files/property shared memory/IO transparent decryption/mmap page faults |
| [network-chain.md](11-syscall-chain/network-chain.md) || socket/connect/send/recv/NF five hooks/tcpdump kernel tap/VPN tun/DNS |
| [binder-signal-chain.md](11-syscall-chain/binder-signal-chain.md) || binder bidirectional sequence/ServiceManager/ptrace/signals (SIGTRAP self-test)/exit chain |
| [dex-load-exec-chain.md](11-syscall-chain/dex-load-exec-chain.md) || ClassLoader→mmap→DefineClass→nterp/JIT/JNI→OAT/VDEX + version symbol difference table |
| [process-memory-chain.md](11-syscall-chain/process-memory-chain.md) || zygote fork full timeline/injection-race timeline/thread clone/scudo/page faults and mprotect |

## 12-bypass

| File | When to open |
|------|-----------|
| [bypass-playbook.md](12-bypass/bypass-playbook.md) || **Open this first when "the function is detected / the approach stopped working"**: two iron-law decision trees (four hook death causes / the detection layer decides the minimum viable bypass), a 14 detection points × 4-6 bypasses matrix (applicability + failure signatures + recommended order), five resource tiers, the "what matters most in this situation" three criteria, 24 failure-signal quick list |

## 13-trace

| File | When to open |
|------|-----------|
| [trace-practice.md](13-trace/trace-practice.md) || **Any "trace the execution flow / who called X / what's the syscall surface" task**: 11-tool comparison table (syscall/function/block/instruction level) + frida-trace·Stalker·syscall-simulation, three scripts tested locally (macOS spawn pitfalls/three volume-control parameters/65k events-per-second ceiling/1.48x slowdown and other hard numbers) + call-tree post-processing + scenario decision tree + the trace tools' own detection surface |

## 14-game-frameworks

| File | When to open |
|------|-----------|
| [unity-il2cpp.md](14-game-frameworks/unity-il2cpp.md) || **Unity game main entry**: determine the APK shape→Il2CppDumper full flow (dump.cs/IDA script attach/RVA fix)→frida-il2cpp-bridge hook practice→mono straight to dnSpy→global-metadata encrypted variants (header checks/dump timing/Zygisk version)→three practical opening shots |
| [ue-cocos.md](14-game-frameworks/ue-cocos.md) || UE: repak/FModel unpacking pak (AES key locating)/utoc→GNames GObjects reflection dump (UEDumper approach)/lua hot update; Cocos: three routes to locate the jsc xxtea key and decrypt/luajit bytecode decompilation/opcode-modification recovery |
| [rn-flutter-re.md](14-game-frameworks/rn-flutter-re.md) || RN: Hermes version header→hbctool unpack-edit-repack/hermes-dec near-source/string table locating/pure JS bundle+source map; Flutter: **blutter+dae dual toolchain** (libapp.so symbol restoration→frida hook dart functions→so-layer encrypted-parameter locating, end to end) |
| [framework-detection-counter.md](14-game-frameworks/framework-detection-counter.md) || Game-specific detection: engine integrity self-checks (il2cpp/pak/script hash)/in-game risk control (input streams·timestamps·server-side statistics)/why emulator detection is strong (sensor entropy + GPU fingerprint)/single-player value editing vs MMO ban boundary |

## 15-anti-cheat

| File | When to open |
|------|-----------|
| [anti-cheat-countermeasures.md](15-anti-cheat/anti-cheat-countermeasures.md) || **Anti-cheat engine analysis (authorized context, boundary statement at the top of the file)**: ACE architecture (driver + user-mode + cloud, honeypots/DMA countermeasures/pre-launch)/EAC·BattlEye loading chain and signatures/Vanguard and other engine identification table/universal three-layer principles (kernel read-write·obfuscated communication·cloud behavior models)/trace diffing to locate detection rules/test-machine isolation (three VM-detection root causes: RTC timing·GPU·firmware chain)/own-game test delivery checklist/cheat development and distribution legal risks stated explicitly |

## 16-quick-ref

| File | When to open |
|------|-----------|
| [quick-reference.md](16-quick-ref/quick-reference.md) || **The simplest, most-used layer**: 16-row function-locating master table (root/frida/signatures/crypto keys/packer signatures… anchors + commands)/NOP and forced-return byte tables (five architectures, 12/12 tested locally)/branch·smali·so patch workflows/10 simple vulnerability-pattern quick entries; companion self-verification script verify_patch.py |
| [verify_patch.py](16-quick-ref/verify_patch.py) || Patch-byte self-verification: capstone disassembly checks + unicorn demo of return 0→1 (run it first when editing the byte tables) |

## Maintenance conventions

- New content goes into the matching category md (or subdirectory), then a row is added back to this index; this index stores no body content
- Body text **carries no external links/source attributions/names/verification dates** — only ideas and code; when a source is needed, go through the `../data/` corpus index
- When in conflict with `~/.zcode/rules`, rules take precedence
