# HarmonyOS RE and Attack Surfaces (platform/05-macos/harmonyos)

> Positioning: the standalone HarmonyOS file (formerly filed under "other platforms", now its own section). hap format/ArkTS·ArkCompiler bytecode/signing and debugging/tool status/Android interop/attack surfaces (distributed SoftBus·atomic services)/vulnerability reporting.
> Kinship: the application layer descends from Android (HAP ≈ an APK variant; signing/permissions/distribution isomorphic), the language layer from the JS/TS ecosystem (abc bytecode ≈ a closed-source flavor of V8 bytecode). Much of the Android techniques library transfers → `../../techniques/` (frida/evasion/capture).
> Status statement: the HarmonyOS ecosystem is heavy on closed-source parts and the public RE toolchain is far less mature than Android's; **entries marked "to-verify" must be self-tested before use**; this file leads with the framework, entries get filled as the ecosystem evolves.

## §1 Ecosystem and Version Overview

- Two lines: **OpenHarmony** (the open-source foundation, the device-side mainline) + **HarmonyOS NEXT** (Huawei's commercial build; from 5.0 it drops the AOSP compatibility layer, pure HarmonyOS, commercial in 2024). Older HarmonyOS (4.x and earlier) = an AOSP base + the HarmonyOS framework — **still Android at heart; every Android technique applies directly**; only NEXT is a "new platform".
- Target shapes: phones/tablets/wearables/automotive/smart screens/IoT modules; kernels are Linux kernel (LM)/LiteOS-A/M (lightweight devices).
- App types: **HAP** (the main form, an Ability package)/**atomic services** (install-free atomic services, card-entry)/quick services.

## §2 The HAP Format Teardown

### 2.1 Package structure

HAP = a **signed ZIP** (same idea as APK; unzip directly):

```
xxx.hap (zip)
├── pack.info                 # 打包元信息(module 列表)
├── module.json               # ≈ AndroidManifest.json:ability/权限/API 版本
├── assets/ 或 ets/           # 前端资源
│   └── modules.abc           # ★ ArkTS 编译产物(方舟字节码,本篇主角)
├── libs/{arm64-v8a,...}/     # native .so(NAPI,C/C++ 产物,标准 ELF)
│   └── libentry.so / libace_napi.z.so ...
├── resources/                # 资源索引(resources.index)
└── META-INF/                 # 签名块(CERT.SF 系,华为证书链)
```

Companion packages: .har (static shared package, ≈AAR), .hsp (dynamic shared package), .app (the multi-HAP aggregation upload format). There must be exactly one Entry-type HAP; Feature types can be split.

### 2.2 Signing and distribution

- The signing chain: debug certificates (applied for in DevEco)/release certificates (issued on Huawei's AGC platform) — dual certificates + a Profile file (≈ Android's signature + a description file, an iOS-provisioning-like idea);
- The system enforces signature validation before install (hdc install passes the same check); **repackaging = must re-sign**, the flow is same-shaped as Android re-signing (replacing the signature block + the zipalign-equivalent step), but the certificate barrier is higher than Android self-signing;
- Distribution surface: AppGallery (Huawei's store) is the only legal channel; sideloading needs developer mode (closer to the current iOS sideloading situation).

## §3 ArkTS and the ArkCompiler

### 3.1 The compile chain

```
ArkTS(.ets) → [ArkTS 编译器(tsc 扩展)] → 方舟字节码 .abc(Panda/Ark IR)
                                   └→ AOT/JIT 运行时:方舟 RTS(ArkCompiler Runtime,ets_runtime)
C/C++ → NAPI → .so(ELF,标准工具链,但链接 bionic 替代品 musl 系)
```

- The `.abc` file: magics of the `pandasm`/`0sA0` family `[to-verify: current-version magic]`, containing the literal pool + records (record ≈ class) + method bytecode;
- The bytecode ISA: Ark's home-grown instruction set (a register machine with an accumulator acc), very different from Dalvik, but **the top-level concepts map**: record↔class, method_id↔method idx, the string pool is same-shaped;
- The runtime's dual modes: interpreter (bytecode) + AOT (machine-code cache); **the AOT cache is the analysis shortcut**: dumping the post-AOT machine code off a real device feeds straight into the IDA/Ghidra ARM64 flow.

### 3.2 The state of abc RE tools (2026)

| Tool | Form | Status |
|---|---|---|
| abc-decompiler | GUI decompiler (a JEB-style fork) | a community open-source project, abc→pseudocode/assembly, activity is mediocre `[to-verify: latest-version compatibility]` |
| abc2txt / ark_disasm | bytecode dump tools | shipped with the DevEco/OpenHarmony SDK toolchains (the pandasm toolchain), emitting instructions + literal arrays, no pseudocode |
| DevEco Studio | the official IDE | ships toolchains (signing/alignment/hdc); analyzing third-party hap needs abc2txt alongside |
| jadx/JEB | — | **no abc support** (dex only); the old Android toolchain does not carry over |
| IDA/Ghidra/r2 | native .so | fully applicable (NAPI so is standard ELF); abc itself unsupported |

The practical chain: `unzip hap → abc2txt modules.abc` (or open the abc-decompiler GUI) → locate business logic by record/method names → under obfuscation, anchor on literal-pool strings; core algorithms (encryption/protocols) most likely live in the .so, back to the regular ELF flow (frida hooking NAPI exports applies equally).

### 3.3 Obfuscation and hardening

- The official toolchain ships obfuscation (name obfuscation/property obfuscation; DevEco configures obfuscation rules), effectiveness ≈ Android ProGuard grade;
- Commercial hardening (Bangcle/Ijiami/Tencent Legu etc.) has shipped HarmonyOS editions, shaped ≈ packed abc + so shells; the confrontation is expected to follow the Android unpacking playbook (runtime abc dumps / bypassing shell checks), **few mature public solutions** `[to-verify]`;
- Anti-debug/anti-frida: NAPI so-layer confrontation reuses the Android techniques library directly (frida-anti-detection.md); abc-layer integrity self-checks = the runtime validating literal/bytecode hashes, with the hook point in the RTS.

## §4 Signing, Debugging, and On-Device Analysis

- **hdc** (HarmonyOS Device Connector, ≈adb): `hdc list targets / hdc shell / hdc install xxx.hap / hdc file send`; debugging goes hdc + DevEco's DAP debug protocol;
- **The HDC debug protocol**: based on the HDC Server (USB/TCP); the protocol has public reverse analyses (community hdc-protocol-parsing articles exist), so you can write your own automation client;
- On-device debug mode: a hap carrying the `debuggable` flag + a debug Profile is the only breakpointable kind; **non-debug third-party apps can only go the dynamic-injection route** (tool status: `[to-verify]`; frida has no official HarmonyOS support, community port attempts exist — the hdc-sideloading + symbol-tool ecosystem is far behind Android's);
- Emulators/cloud devices: DevEco Profiler + the local emulator (arm/x86 images) is the low-cost dynamic environment; for device farms use Huawei Cloud debugging.

## §5 Interop with Android

| Aspect | Status |
|---|---|
| Legacy compatibility | HarmonyOS 4.x and earlier carry the AOSP framework; APKs install directly; all Android techniques apply |
| The NEXT break | NEXT removes AOSP/APK execution; the official "cross-border conversion" tools (the Ark transpiler etc.) can convert Android apps to native HarmonyOS — the converted abc lets you infer the original dex structure and logic (the obfuscation mapping is same-origin) |
| Tool transferability | so layer ≈ 100% (ELF/ARM64/NAPI≈JNI); abc layer ≈ 0% (a new bytecode); signing/distribution thinking ≈ iOS (tight control) > Android |
| Dual-framework apps | The same app ships Android + HarmonyOS packages, keys/protocols often same-origin — **when the HarmonyOS package won't yield, switch to the Android package, reverse it, and pour the findings back**; currently the highest value-per-effort route |

## §5.1 Concept mapping table (Android → HarmonyOS)

| Android | HarmonyOS | Key differences |
|---|---|---|
| APK | HAP | both signed zips; HAP adds the Profile-file layer |
| Activity/Service | UIAbility/ExtensionAbility | the Ability model; lifecycle callback names differ |
| AndroidManifest.xml | module.json | structured json; field names are more readable |
| JNI | NAPI | different interface set (node-api pedigree); so is a regular ELF |
| dex | abc (Ark bytecode) | new ISA; needs abc2txt/abc-decompiler |
| ART (interpreter + AOT) | ArkCompiler RTS (interpreter + AOT/JIT) | the dual AOT caches can be dumped |
| Binder IPC | RPC/SoftBus + SAMGR service registry | no binder; the nose swaps to the service registry |
| adb | hdc | near-identical command style, independent protocol (community-reversed) |
| Play Store | AppGallery | single distribution channel; sideload needs developer mode |
| dex obfuscation (ProGuard) | SDK-built-in obfuscation | name/property obfuscation same-shaped |
| Hardening (Bangcle etc.) | HarmonyOS-edition hardening | few public HarmonyOS solutions `[to-verify]` |

## §5.2 Compared with iOS (the parts that feel "iOS-like")

- Tight signing control: release certificates issued by the vendor platform + a Profile description-file mechanism ≈ provisioning;
- Restricted sideloading: developer mode + certificate expiry mechanics; ecosystem closedness sits between Android and iOS, leaning iOS;
- Analysis takeaway: iOS's signing/re-signing/jailbreak-detection confrontation experience (→ `../04-ios/`) transfers to NEXT's signing and debugging confrontation better than the Android experience does.

## §6 Attack Surfaces

### 6.1 The distributed SoftBus

HarmonyOS's signature feature = cross-device networking (phones/tablets/automotive/wearables auto-discovering and interconnecting); attack surfaces:
- The discovery protocol: Wi-Fi CoAP/multicast broadcast `[to-verify: current-version discovery-stack details]`;
- Authentication: inter-device trusted networking (HiChain/device authentication); historical public research concentrates on **the unauthenticated discovery surface and auth bypasses**;
- Cross-device invocation (distributed task scheduling/cross-device migration): the semantic boundary of the permission model once it crosses devices (IDOR thinking: is the peer device ID sufficiently authenticated) is the high-incidence zone for logic bugs;
- Tools: the OpenHarmony repos (the SoftBus module source is readable) — closed-source NEXT and the open-source version have diverged; audit with the open source as the cognitive base and real-device behavior as the check `[to-verify: how far NEXT's SoftBus has diverged from the open version]`.

### 6.2 Atomic services

- Install-free, card-ready: the assumption that distribution checks are weaker than for full apps needs field verification; the service card's data channel (the card-refresh interface) is the logic surface;
- With package-size limits, atomic-service business is thin and the logic often lives in cloud APIs — **hitting the server interfaces + tampering card-client parameters** is the main route (interface-security matrix → the skill knowledge base's api-pentest).

### 6.3 Other surfaces

- The Web component: ArkWeb (Chromium-lineage kernel); Web-vulnerability research transfers; the JS bridge (postCardAction/javaScriptProxy) is the injection surface;
- IPC: the layers above SoftBus + local IPC (HiView/service registry) — **no Binder**; Android binder instincts must switch to the service-registry (SAMGR) surface;
- Kernel: Linux-LM kernel-bug research = the Linux flow (GKI difference: a Huawei-maintained branch); the LiteOS side/IoT modules → cross-linked at `../07-iot/`.

## §7 Vulnerability Reporting (HarmonyOS PSIRT)

- Entry: Huawei's Product Security Incident Response Team (PSIRT) official vulnerability-submission channel (the Huawei security PSIRT page on the official site), mailbox psirt@huawei.com `[to-verify: current process/SLA]`;
- Scope: HarmonyOS (incl. NEXT)/OpenHarmony/preinstalled Huawei-device software; **OpenHarmony open-source bugs can also go the OH community security process** (SIG-Security);
- Report format follows the library's standard two tables (vuln-report-format.md); HarmonyOS-specific essentials: system version (Build number)/device model/reproduction hdc logs;
- SRC view: Huawei's bug-bounty program (integrated with PSIRT); new NEXT surfaces (SoftBus/atomic services/the Ark runtime) price higher than mature Android surfaces.

## §8 Quick-start checklist (the first ten minutes with a hap)

```
1. file xxx.hap → unzip -d hap_out/                     # 解包
2. 读 module.json:ability 清单/权限列表/debuggable 标志
3. ls libs/*/ → .so 清单(第三方 SDK 指纹:加固/风控/统计)
4. abc2txt assets/ets/modules.abc > abc.txt             # 字节码 dump(或 abc-decompiler)
5. grep 字符量池:url/key/token/签名盐 → 定位网络与加密层
6. .so 进 IDA/r2:NAPI 导出(napi_module_register 起)→ 常规 ELF 流
7. 动态:DevEco 模拟器装包 + hdc 日志;抓包先试系统代理(ohos 支持 HTTP 代理设置)
8. 不通 → 切同 app Android 包逆向(双框架同源),结论回灌
```

## §9 The open-source cognitive base: using the OpenHarmony repos

Black-box research on closed-source NEXT uses the open-source version as the cognitive base, then diffs to verify:

| Repo module | What to analyze |
|---|---|
| ark/compiler (ark_runtime) | the abc format/ISA definition/interpreter implementation — the authoritative reference for reversing abc |
| foundation/communication (dsoftbus) | SoftBus discovery/authentication/networking protocols — the source base for attack-surface audits |
| security (device authentication/HiChain) | the trusted-networking auth flow — the reference implementation for bypass research |
| startup (app framework) | app startup/signature-validation chains — the basis for re-signing and debugging confrontation |

Two-step usage: ① locate the target mechanism in the open source (e.g. the signature-check function) → ② compare against real-device (NEXT) behavior (same-shaped or tightened?). Each divergence is a research delta.

## §10 To-verify list (the ecosystem changes fast; self-test before use)

| Entry | Uncertainty | How to verify |
|---|---|---|
| abc magic/format version | whether a NEXT major release changed the format | hexdump the head of any DevEco build product |
| abc-decompiler compatibility | coverage of new NEXT instructions | try dumping the latest hap |
| HarmonyOS frida/injection tools | usability of community ports | field-test on an ohos device + hdc sideload |
| SoftBus discovery-protocol details | NEXT-vs-open-source divergence | capture + open-source cross-check |
| PSIRT intake/SLA | whether the process changed | recheck the official security page |
| Official "cross-border conversion" tooling | conversion coverage (ABI/JNI/obfuscation) | dual-package diff verification |
