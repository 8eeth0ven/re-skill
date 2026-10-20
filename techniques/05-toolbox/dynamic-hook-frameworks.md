# Dynamic and Hook Frameworks In-Depth Comparison (frida ecosystem x Xposed family x native inline hook x the AI/MCP new wave)

> Core conclusions: **frida remains the absolute main force of dynamic analysis** (16.x final and 17.x usable in parallel); the Xposed family survives on LSPosed canaries for persistent Java-layer hooks; the three native inline hook players (Dobby/ShadowHook/Renef) cover the "hook without frida" scenarios; **the 2026 new trend is MCP/AI-driven hook toolchains** (frida-mcp/barbatos/R2Droid).

## I. Principle Comparison of the Two Big Systems

### frida: external injection + dynamic interpreted execution

- **Injection**: `frida-server` (root-resident) injects into the target via `ptrace`, writes `frida-agent` (an so) into target memory and runs it on a new thread; without root, use `frida-gadget` (stuff the so into a repackaged APK; loaded at app startup).
- **Hook mechanism**:
  - Java layer: scans `art::Class` on the ART runtime, replaces a method's entrypoint (FastNatives/native entry), rerouting calls into a JS callback. Supports instance methods/static methods/constructors; can proactively instantiate and invoke via `Java.use()`.
  - Native layer: `Interceptor` is based on **inline hook** (the Gum engine rewrites the function-entry instructions to jump to a trampoline); `Stalker` does instruction-level tracing (custom code generation, can report per-instruction/per-memory-event).
  - Scripts are JS (QuickJS/V8) delivered dynamically - **change hooks without restarting the process**; paired with `frida-reload`/hot-reload the experience is excellent.
- **Strengths**: both Java+Native ends, both spawn/attach modes, ecosystem (objection/medusa/r0capture/unpinning scripts all ride on it).
- **Cost**: extremely loud signatures (process name, port 27042, thread names `gum-js-loop`/`gmain`, the agent so in maps, export symbols, memory signature bytes) - anti-detection is the eternal topic (see area `04-evasion` and section 7 of the master table).

### The Xposed family: zygote pre-embedding + static modules

- **Injection**: the common thread across all forks - run inside the **zygote process** before any app code, placing the hook engine into every forked app process:
  - Original Xposed (rovo89): replaced `app_process`, requiring system-partition changes.
  - EdXposed: Magisk mounts `system` (systemless); engine YAHFA/SandHook selectable.
  - LSPosed: loaded via **Zygisk** (Magisk's zygote-injection mechanism); the Ririn->Zygisk evolution, module format still the Xposed API.
- **Hook mechanism**: `XposedHelpers.findAndHookMethod` swaps the target `Method`'s ART entry for a trampoline (per-engine implementations: YAHFA generates trampolines; SandHook/Pine use ArtMethod field replacement/entry jumping). Modules are **compiled dex/Java code** - good performance, no script-runtime signatures.
- **Strengths**: persistent (effective at boot, no external-to-host components), high performance, module ecosystem (HMA and assorted custom modules).
- **Cost**: Java layer only (no official native hook support); compatibility is tied to the ART version - every Android major upgrade needs engine adaptation, which is exactly why LSPosed's end-of-life leaves Android 15+ on canaries.

### Mechanism-Difference Quick Reference

| Dimension | frida | Xposed/LSPosed |
|---|---|---|
| Injection timing | Inject anytime into a running process (attach/spawn) | Pre-embedded at zygote time; hooked at app birth |
| Script form | JS delivered dynamically, hot-editable | Compiled module dex; changes need a restart |
| Layer coverage | Java + Native + instruction level (Stalker) | Java layer only |
| Performance | Interpreted execution; heavy hooks cost | Native trampolines; small overhead |
| Deployment | root pushing a server / gadget repackaging | root + Magisk+Zygisk + LSPosed |
| Detection surface | Large signature (process/port/thread/so) | Stealthy (no external process), but zygisk itself is scannable |
| Fits | RE analysis, rapid trial-and-error | Productized modules, long-term automation |

## II. frida Version Lines: 16.7.19 Final vs the 17.x Mainline

**frida 16.7.19**:
- **The last 16.x release**; 17.0.0 took over immediately after.
- The 16.x final pairs with **frida-tools 13.7.1**. Version-pairing discipline: `frida 16.7.x <-> frida-tools 13.7.x <-> frida-server 16.7.19` - all three ends on the same major version.
- 16.7.19's positioning: **the stable conservative line**. Some teams pin it on Android 12-14 legacy-device/old-ROM analysis machines because 17.0's Barebone backend differs from 16.x behavior (Gum codegen paths, Java bridge details); old scripts (especially ones touching ArtMethod offsets directly, like the ARTHookScripts family) need offset re-adaptation on 17.x.
- strongR-frida ships a 16.7.19 patch build in sync (still good enough for legacy-device anti-detection scenarios).

**frida 17.x mainline**:
- 17.0 -> 17.2.x -> 17.3.x -> 17.4.x ... -> 17.23.x (current latest).
- The 17 line's headline items: the Barebone backend, a package manager (`frida-pm`), fruity performance work.
- New toolchains assume 17.x (e.g. frida-mcp depends on `frida@17`; noxen defaults to `pip install frida==17.7.3`).

**Line-selection advice**: for new tasks always the latest 17.x; fall back to 16.7.19 + frida-tools 13.7.1 only when doing ART-internal offset work or legacy-device compatibility (the two can coexist in separate Python venvs). Note 16.7.19 has been unfreshed for a year and a half - security fixes only land in 17.x.

## III. frida Ecosystem Map (2026 State)

| Layer | Component | Status | Notes |
|---|---|---|---|
| Core | frida 17.x | Active (17.23.x) | Barebone backend, frida-pm, fruity |
| Core | frida 16.7.19 | Frozen final | The 16.x stable conservative line, pairs with frida-tools 13.7.1 |
| CLI | frida-tools | Active with the mainline (17 line; 16-line final 13.7.1) | `frida` REPL, `frida-trace`, `frida-ps` |
| Wrapper | objection | Slower maintenance | Quick security checks (SSL pinning bypass, root detection, keystore dump) |
| Wrapper | medusa | Active | 90+ modules + Mango CLI, the modern objection replacement |
| Capture | r0capture | Usable | Java+Native dual-layer capture into pcap; the immune-to-pinning fallback |
| Component interception | noxen | Active | Component-communication interception + attack-surface mapping (see section V) |
| MCP | frida-mcp | Active | Claude and other LLMs drive frida directly (see section IV) |
| Script library | frida-scripts (lasting-yang etc.) | Community-ongoing | Ready-made hooks for common Android spots |
| Anti-detection | strongR-frida-android | Active | Upstream-tracking auto-patched server |
| Anti-detection | undetected-frida (zer0def) | Active | Auto-patch + prebuilts |
| Bridge | frida-il2cpp-bridge | Active | Unity il2cpp structure dump and invocation |
| Servicization | frida-remote / gadget mode | Follows core | Cloud-device clusters use `frida -H` for remote debugging |
| Emulated execution | vardoger | Very new | Python-driven Android ARM64 emulation runtime (see section VI) |

**Version discipline** (important): `frida` (python package/CLI) and `frida-server` (device side) **must match on the major version**, otherwise `Failed to enumerate processes`-type errors. Same for strongR builds: strongR 17.3.x pairs with frida-tools 17.3.x. The 16.7.19 line is the full 16.7.19 + 13.7.1 set.

## IV. frida-mcp: LLM Directly Wired to frida

Note the distinction from dnakov/frida-mcp: that one is a much simpler attach/spawn sampler - don't confuse them.

- **Form**: a TypeScript MCP (Model Context Protocol) server designed for **Frida 17** (depends on `frida@17`, Node.js 20+, MIT).
- **Scale**: roughly **62 tools + 15 resources** (by category: devices 4, processes 6, sessions 5, script management 4, exports 1, memory 6, Java 6, native hooks 2, Android 6, docs 1, bootstrapping 2, recipes 8, static analysis 7, anti-detection 2).
- **Parameterized hook templates (the Recipe library)**:
  - `hook_okhttp_requests` - intercepts `Request$Builder.build` on every OkHttp client;
  - `hook_java_method_recipe` - hooks all overloads of a Java method, supports where predicates, max_emits, argument truncation;
  - `hook_native_export` - `Interceptor.attach` on an exported symbol;
  - `trace_class_methods` - the batch class-method trace equivalent of `frida-trace -j`;
  - `dump_mac_doFinal` - hooks `javax.crypto.Mac.doFinal` to grab HMAC keys/data;
  - `bypass_ssl_pinning` - multi-route unpinning across TrustAllCerts, OkHttp3, Conscrypt etc.;
  - `bypass_root_detection` - root-detection bypass (idea sourced from @dzonerzy/fridantiroot).
- **Install**: `claude mcp add frida-mcp -- npx -y frida-mcp@latest`; also manually via `.mcp.json` or building from source. Manual config example:

```json
{
  "mcpServers": {
    "frida-mcp": {
      "command": "npx",
      "args": ["-y", "frida-mcp@latest"]
    }
  }
}
```

- **Value positioning**: turns "writing a frida script" into "one sentence to Claude" - the LLM composes attach/hook/dump tools on demand; fits productizing RE experience into agent workflows (new project, early community adoption).

## V. noxen: Component-Communication Interception + Attack-Surface Mapping

(GPL-3.0.)

- **One line**: hooks a running Android process's Java methods via Frida, **mapping inter-component communication and the attack surface in real time** - turning the data flow of the four Android component types into a visible/editable/droppable interception panel.
- **Hook points**: `getIntent` (inbound), `startActivity`/`sendBroadcast`/`startService` (outbound), the PendingIntent creation paths (`getActivity` etc.).
- **Per-event display**: action, component, data URI, flags, categories, extras, PendingIntent flags, optional Java stack; plus the target component's **exported flag and required permissions (with protection level)**, distinguishing inbound receivers from outbound resolution targets; broadcasts also show receiverPermission - **effectively an auto-generated component attack-surface inventory**.
- **Info app tab**: an app snapshot (identity, build flags, signatures, permissions) + a searchable inventory of all components, classified open/weak/protected.
- **Intervention**: before forwarding, edit the intent's action/data/categories/flags/extras, or drop the intercepted intent outright - **a Burp Repeater for Intents**.
- **Engineering**: independent Intercept/History filters; sessions saved as `.noxen` project files; `noxen-analyze app.apk` pre-generates hook configs by analyzing the APK offline with androguard.
- **Usage**: after `pip install .`, run `noxen` (requires PC-side frida to match the device's frida-server version, e.g. `pip install frida==17.7.3`).
- **When to pick it**: hunting exported-component/implicit-intent/PendingIntent-hijack bugs (one shot at the full IPC surface for SRC work); pairing with manual intent-parameter fuzzing is an order of magnitude faster than purely static manifest reading.

## VI. r0capture and vardoger: the Two Legs of Grabbing Data and Running so Files

### r0capture

- Positioning: **dual-layer capture at the Java layer (SSLContext/okhttp/Conscrypt API points) + the native layer (SSL_write/SSL_read)**, outputting pcap; the fallback when the app uses cert validation or non-HTTP protocols (private protobuf, MQTT, etc.).
- Division with noxen: noxen intercepts component communication (Intent flows), r0capture intercepts network traffic (socket flows) - neither replaces the other.

### vardoger (a 2026 newcomer)

- PyPI package `vardoger-vm` (LGPL-3.0, C++ core + Python bindings; very new - adopt at your own risk).
- **Positioning**: a **Python-driven faithful Android ARM64 emulation runtime** - same lane as unidbg (offline so execution, no real device), but the interaction language is Python and the design goal is packer-agnostic.
- **Capabilities**:
  - `vm = VM(package="com.foo.bar", sdk=31)` to set up the environment; `vm.serve_apk("base.apk")` to feed the APK;
  - `so = vm.load("lib.so")` returns a Module (bias, jni_onload, size, init_array, lookup);
  - `vm.run_init(so)` runs `DT_INIT + .init_array` - **hardened so self-decryption happens right here**;
  - `vm.call(so.jni_onload, ...)` / call any function;
  - read/write memory and registers, hook code and memory, **allocate trampolines to implement libc/JNI stubs in Python and capture calls**, register Java methods, **capture DEX** (dump the decrypted dex while running a packer).
- **Implementation**: the backend is a C-ABI `libvardoger_capi.so`, driven purely via ctypes from Python (no pybind11, no compile-time fight).
- **Typical usage**:

```python
from vardoger import VM, Reg

vm = VM(package="com.foo.bar", sdk=31)
vm.serve_apk("base.apk")          # provide the APK to the loader for lookup locations

so = vm.load("lib.so")            # -> Module(bias, jni_onload, size, init_array, lookup)
vm.run_init(so)                   # DT_INIT + .init_array: hardened so self-decrypts here
ver = vm.call(so.jni_onload, ...) # call JNI_OnLoad to finish the registration flow
# Afterwards: read/write memory/registers, hook, implement libc/JNI stubs on the Python side, capture DEX
```

- **When to pick it**: unpacking (init_array self-decryption + DEX capture), offline signature-algorithm restoration (stubbing in Python beats unidbg's Java environment-stubbing), CI-automation sample runs. Risk: a single-maintainer new project with an unstable API.

## VII. barbatos / R2Droid / LSPilot: the AI-Debugger New Wave

- **barbatos**: a **zero-config Android runtime debugger with a built-in Frida API + MCP server**, slogan "Empowering AI Agents with dynamic instrumentation". A single native binary (macOS; curl install script, one shot), REST-style `POST /v0/api/<op>`; capabilities: live Java/Kotlin class enumeration, recursive object-graph traversal (fields/Maps/collections), method hooks with live behavior edits. The architecture is a Kotlin Multiplatform native bridge (CInterop statically linking Frida Core, injecting a JS agent into ART/ObjC). Designed for LLM-autonomous debugging (crash diagnosis, runtime exploration). macOS only for now; Linux/Windows planned.
- **R2Droid**: a **Radare2-family Android app (Kotlin + Compose)** doing native RE right on the phone: r2ghidra/r2dec/r2native/aipdg decompiler switching, Sugiyama-layout graphs (CFG/call graphs/xref graphs), ESIL debugging (breakpoints/single-step/registers), hex+patch, **built-in AI assistant (OpenAI-compatible API, streaming chat + `[[cmd]]`/`<js>` actions)**, **built-in r2frida connecting to live device processes**, Frida hook-template generation, Markdown/HTML/JSON report export. CI builds Full/Proot-only APKs. Effectively "r2 + frida + AI in your pocket".
- **LSPilot**: an AI-driven LSPosed dynamic-RE assistant (module form, resident from zygote time, complementing the frida family). This page only positions the framework; principles and usage live in the LSPilot dedicated page.
- **How the three relate**: frida-mcp (PC-side MCP->frida), barbatos (PC-side single-binary REST/MCP->frida), R2Droid (device-side GUI+r2+AI), LSPilot (device-side LSPosed module+AI) - projections of the same "LLM operates the runtime directly" trend onto four ecological niches.

## VIII. Three-Way native inline hook Comparison: Dobby / ShadowHook / Renef

First untangle the relationships: **frida's Interceptor is itself an inline hook** - the Gum engine writes a jump at the target function's entry, relocates the overwritten original instructions into a trampoline, then jumps back; on ARM64 it has a dedicated instruction analyzer for PC-relative instructions. So "with frida you don't need the three below" holds for most RE tasks; what the three solve is **having no frida runtime, needing to embed into your own so/module, or needing to dodge RASP's frida-signature detection**.

| Dimension | Dobby | ShadowHook | Renef |
|---|---|---|---|
| Repository | jmpews/Dobby (slower maintenance) | bytedance/android-inline-hook (continuously maintained) | Renef (Lua 5.4 scripting, rising star) |
| Origin | HookZz's successor, an indie/community project | ByteDance production-grade (used by Douyin/TikTok/Lark) | An independent tool inspired by frida + radare2 |
| Platforms | Multi-platform (iOS/Android/macOS/Windows/Linux), arm/arm64/x86 | **Android only**, thumb/arm32/arm64 | **Android ARM64 only** |
| Hook method | inline hook (instruction relocation + trampoline) | inline hook (entry rewrite + instruction fixups), billed as production-grade stable | **Dual route: PLT/GOT redirection + a Capstone-disassembly-driven inline trampoline** (relocation fixes original instructions) |
| Script interface | C/C++ API (compile-time linking) | C API + Java wrapper (Maven `com.bytedance.android:shadowhook`) | **Lua 5.4**, frida-like API (Module/Memory/Hook/Thread), hot-delivered at runtime |
| Java layer | None (pure native) | None (Java only with LSPlant) | Can intercept Java methods via **JNI** |
| Injection/deployment | Embed into your own so; eikarna/DobbyAndroid ships prebuilts | Embedded in apps (RASP/perf monitoring) or your own injector | **memfd + shellcode injection, no ptrace needed** (immune to ptrace detection); has a magisk-renef module (magisk-frida-style autorun), r2renef (a radare2 IO plugin for statically analyzing live processes), and a Gadget Mode |
| Android support | Community-paced; old issues hang for years (#20 hook detach, since 2018) | **Android 4.1-15 (API 16-35)**, MIT | ARM64 mainline; version matrix per the official docs |
| Sister projects | BepInEx/Dobby (a Windows-stability fork) | **ByteHook (a PLT hook library, same vendor)** - the other half of the PLT/GOT lazy route beyond ShadowHook | The magisk-renef / r2renef ecosystem |
| Fitting scenarios | iOS+Android dual-platform game modders, multi-platform injection frameworks | Production app instrumentation/RASP, stability-first commercial hooks | **RASP combat** (no frida signatures, no ptrace); radare2 users wanting to hook live processes |
| Relation to frida | An independent implementation outside frida; usable to backfill native hooks where frida fails | The "no-frida-runtime" replacement for frida's Interceptor; many domestic RASPs are literally built on it | A lightweight frida substitute; the project ships an official "Frida to Renef" migration guide |

**Renef quick start**: ships a Lua 5.4 engine with API naming deliberately aligned to frida (`Module`/`Memory`/`Hook`/`Thread`); migrating from frida is mostly swapping JS syntax for Lua; the `auto-watch` mode loads multiple scripts with hot reload; a bundled TUI memory scanner does interactive searching. Three deployment forms: direct-to-process (memfd injection), **Gadget Mode** (frida-gadget-like), and the **magisk-renef** module (autorun at boot on Magisk/KernelSU/APatch, in the spirit of magisk-frida); on the static side there is **r2renef** (a radare2 IO plugin; r2 commands analyze live process memory directly).

**Selection mnemonic**: embed into your own so cross-platform -> Dobby; Android production-grade stability/commercial -> ShadowHook (plus ByteHook for PLT); RASP staring down frida signatures, want Lua hot scripts -> Renef; just doing RE -> frida Interceptor, period.

**Cydia Substrate status**: effectively dead. Saurik brought it to Android in 2013; it **never adapted to ART** (the default runtime since Android 5.0) and was pulled from the Play Store in 2017-2018. On Android it was fully superseded by Xposed->LSPosed; on iOS by Substitute/libhooker etc. New projects should never pick it, except for archaeology.

## IX. ARTHookScripts: smali-level inline hook (the ShadowFrame mechanism)

- **One line**: frida runtime **parses smali and implements inline hooks at any position inside a Java method body** - breaking through frida `Java.use`'s method-entry-only limitation, achieving "break and modify at the Nth bytecode of a method".
- **Environment constraints**: Android 10 (Pixel XL / AOSP, BUILD_ID=QP1A.191005.007.A3) + frida 16.7.0 - because the ART struct offsets are mostly **hardcoded**; other versions need re-adaptation (the repo has since fixed Frida 17 compatibility). This corroborates section II's "16.7.x conservative line": scripts touching ART memory are most stable pinned to the old version.
- **Core APIs**: `pathToArtMethod("com.x.Y.z").showSmali()` (dump a method's smali), `.showOatAsm()`, `showNativeAsm("libfk.so!0xaa11a0")`, `getFunctionBoundary(addr)` (multi-level function-boundary detection via oat-header/symbol table/CFG).
- **Five approaches**:
  1. **JDB/JVMTI**: frida starts a jdwp thread and implements breakpoint debugging via JVMTI (the standard debug-protocol route);
  2. **Trace-function pattern matching**: locate libart's internal key trace functions by symbol and instruction format (referencing AOSP trace.h);
  3. **Inline Hook Smali (the signature trick)**: bytecode edits + ShadowFrame manipulation, mechanism chain below;
  4. **Fast execution (oat mode)**: parse oat binary symbols to improve disassembly readability; inline-hook at the binary level;
  5. **Custom smali interpreter**: port ART's `vmInterpret` (Execute swap-interpreter) implementation, with exported functions acting as a frida bridge fully proxying the system interpreter - best control flow, best cross-version compatibility.
- **The Inline Hook Smali mechanism chain** (full principles in the dedicated `../02-frida/advanced/yahfa-and-art-hook.md` section; quick notes here):
  `invoke-static` overwrites the original bytecode -> jumps into a JS callback registered via `Java.registerClass` -> walks **ManagedStack up to the parent fragment -> ShadowFrame** (= the caller Java method's execution context in the interpreter: ArtMethod + dex_pc + the VRegs register set) -> JS reads the live values at the hook point -> manually interprets and executes the overwritten original instructions -> **SetVReg rewrites the parent frame's registers** to advance execution. Preconditions: oat disabled (the method must go through the interpreter for a ShadowFrame to exist) + handling the dex cache.
- **Uses**: extraction-packer analysis (watching a method body decrypt instruction by instruction), mid-function variable tampering in risk-control functions, "in-method breakpoint" scenarios where a debugger cannot be attached.

### ART Internal-Structure Reference (AOSP source)

The three ART structures needed to understand the chain above (read AOSP `master` and they line up):

| Structure | Source location | Key fields/operations | Role in the chain |
|---|---|---|---|
| `ManagedStack` | `art/runtime/stack.h` | `PushShadowFrame()` / `PopShadowFrame()`, chaining the interpreter's ShadowFrame segments and the native QuickFrame segments | One per `art::Thread`; the frida callback walks it upward to get the "parent fragment" |
| `ShadowFrame` | `art/runtime/interpreter/shadow_frame.h` | `ArtMethod* method_`, `dex_pc`, `link_` (caller frame), **the VRegs virtual-register array** (two layouts: interpreter layout separates vregs from the reference array; can also be allocated on the native stack) | = the current Java method's complete execution context in the interpreter; register reads/`SetVReg` writes all land on it |
| Interpreter loop | `art/runtime/interpreter/interpreter_common.cc` | `Execute(ShadowFrame&, ...)` fetches and executes; `ArtInterpreterToCompiledCodeBridge` handles interpreter<->compiled-code jumps | "Manually executing" the overwritten instructions = simulating one round of this loop with JS-side ported interpretation logic |

**Why oat must be disabled**: AOT/JIT-compiled methods run machine code directly - the thread has only a QuickFrame, no ShadowFrame, and the registers sit in real CPU registers - so bytecode replacement never gets "executed". Disabled, the method falls back to the interpreter, the ShadowFrame exists, and the chain works. This is also why ARTHookScripts pins a specific Android version: `ShadowFrame`/`ArtMethod` field offsets drift across versions, and the script hardcodes them.

## X. frida_unpin.py and Android API 34

- **akabe1/my-FRIDA-scripts** collects four scripts (all **.js**, no .py, unmaintained): `frida_multiple_unpinning.js` (multi-route pinning bypass; **Case 1 alone replaces `SSLContext.init` with an accept-all TrustManager** - `Java.registerClass` registers an empty TrustManager implementation, then the init overload swaps the trustManager argument; the comment notes this Case targets the pre-Android-7 TrustManager usage), `frida_universal_pinning_bypasser.js` (recursive TrustManager), `frida_netsecconfig_bypass.js` (networkSecurityConfig pinning), `keystore_spy.js` (Keystore call analysis). OWASP MASTG lists it among the most comprehensive TLS pinning bypass scripts.
- The **.py filename** "frida_unpin.py" and the claim of "the only verified-working solution on API 34" have no public source; it is most likely a Python-driver wrapper around the same SSLContext.init-replacement idea. **API 34 (Android 14) field advice**: start with the general solutions - httptoolkit frida-android-unpinning or akabe1 multiple-unpinning (v2+ adds new Cases like TrustManagerImpl.verifyChain, Conscrypt); if both fail, bring in r0capture to take plaintext directly at the SSL_write layer, sidestepping the entire pinning problem.
- **Same-class alternatives**: SSLSlayer (codeshare) is likewise an SSLContext.init + allow-all TrustManager idea in a modern-maintained build - a viable API 34 candidate.

## XI. Xposed-Family Status Matrix (2026)

| Framework | Hook engine | Android support | Status | Conclusion |
|---|---|---|---|---|
| Xposed (original) | app_process replacement | <=8.x scenarios | Unmaintained (post-2017) | Archaeology |
| EdXposed | YAHFA / SandHook | Best on 5.0~10 | Unmaintained | Legacy-device fallback |
| TaiChi | Pine (magnet)/root-free virtualization | 8~12 | Unmaintained | Root-free route taken over by gadget |
| VirtualXposed | Virtual container + Epic | 5~10 | Unmaintained | Heavily detected; not advised |
| **LSPosed** | LSPlant (inline hook engine) | stable 8.1~14; **canary supports 15** | Officially ended; canaries still trickle out | The only main pick for persistent Java hooks (LSPilot on the AI line) |

**LSPosed timeline**: 2024-01 the LSPosed team announced development stopped -> community panic period -> internal builds kept supporting Android 15 -> the stable line currently sits at 8.1~14. **Action advice**: keep the main analysis machine on Android 14 running stable - most stable; 15 uses canary at your own risk; on 16 there is no reliable Xposed option - hooking needs go entirely through frida.

**Engine addendum**: LSPlant is the general-purpose ART hook library extracted from LSPosed (method replacement via inline hook), usable standalone; YAHFA/SandHook/Epic/Pine/FastHook form the historical evolution chain - don't build new projects on them. Persistent native-layer hooking needs connect to section VIII's ShadowHook/Dobby.

## XII. Coexistence and Mutual Exclusion

- **frida <-> LSPosed can coexist** (same Magisk+Zygisk machine): the common combo is LSPosed hanging HMA/hiding modules to pass detection while frida does the analysis injection. Notes:
  1. When both hook the same method, the later arrival overwrites the earlier one's entry - they can "eat" each other; avoid double-hooking the same function across frameworks, or accept "last hook wins".
  2. Some anti-detection modules (like Shamiko's DenyList) **hide/interfere with frida-server** (frida can't connect when the process is denied) - add `frida-server` to the exclusions or rename it before retrying.
  3. Stalker and LSPosed modules both touch ART entries; in extreme cases crashes - eliminate one by one.
- **frida-server <-> frida-gadget are mutually exclusive**: one process, one form; in gadget mode connect with `frida -U Gadget`.
- **frida <-> Renef**: theoretically injectable simultaneously (different agents), but both rewrite entry instructions - double inline hooking the same function will surely crash; Renef's positioning is "the fallback when frida is detected" anyway; pick one.
- **noxen/r0capture hung together**: both frida scripts; can run in parallel in one session - mind the interleaved logs.
- **Dual-instance/Parallel-Space containers + frida**: container process names carry a `:xxx` suffix; `frida-ps -Ua` - tell them apart.

## XIII. Android Version x Framework Compatibility Quick Reference

| Android | frida | LSPosed | native inline hook | Notes |
|---|---|---|---|---|
| 12/13 | Full-featured (both 16.7.19/17.x stable) | stable | ShadowHook native support | Golden analysis-machine versions |
| 14 | Full-featured | stable (the last stable line) | ShadowHook supported (API 34) | Recommended mainstay version |
| 15 | Full-featured (both 16.x/17.x) | Canary only, occasional crashes | ShadowHook officially supports to API 35 | For strict tasks fall back to 14 |
| 16 | Usable (17.x mainline keeps up; some models need the latest) | No reliable option | ShadowHook officially unconfirmed; Dobby/Renef community-paced | Hooking via frida; root via Magisk v30+/KSU |

**How the root foundation affects hook frameworks**:
- Magisk v30 (UI rewrite, stronger package-name hiding) bundles Zygisk -> LSPosed natively supported.
- KernelSU/APatch have no bundled Zygisk -> install **Zygisk Next** (closed-source since v1.2.2) or **ReZygisk** (open source, better SUSUFS-compatibility reputation) before hanging LSPosed.
- Zygisk itself gets scanned by some risk controls (`dlopen` whitelists/`__system_property` checks); in high-detection scenarios use the KernelSU+SUSUFS+ReZygisk kernel-level hiding combo; Renef's magisk-renef module likewise rides on Magisk/KSU/APatch.

## XIV. frida Common Commands Quick Reference (even veterans forget)

```bash
# Devices and processes
frida-ls-devices                     # list devices (USB/remote/cloud)
frida-ps -U                          # list USB device processes
frida-ps -Ua                         # list running apps only (with names)
frida-ps -D <device-id>              # designate a remote device (frida -H ip:port scenario)

# Injection
frida -U -f com.target.app -l hook.js --no-pause   # spawn: earliest timing, beats early checks
frida -U -n "AppName" -l hook.js                    # attach: onto a running process
frida -U Gadget -l hook.js                          # gadget repackaged mode
frida-trace -U -i "open" -i "*sscronet*"            # quickly trace native exports
frida-trace -U -j com.target.CryptoUtil            # quickly trace all methods of a Java class

# The 16.x conservative line (for ART-offset scripts)
pip install frida==16.7.19 frida-tools==13.7.1      # isolated venv, coexists with 17.x

# Server side (inside the device shell, paired with signature edits)
./fs16 -l 127.0.0.1:8899 &           # renamed frida-server + re-ported (kills the 27042 signature)
```

**spawn vs attach - choosing**:
- The target runs detection or decryption inside `Application.onCreate`/the so's `JNI_OnLoad` -> **spawn** (`-f`) is mandatory; attach arrives too late.
- Only analyzing running API calls -> attach is cheaper; don't restart willy-nilly and trip the risk control.
- In spawn mode remember `--no-pause` (default in newer versions), and consider delayed binding inside `Java.perform`.

## XV. Common Pitfalls (high-frequency issues)

| Symptom | Cause | Fix |
|---|---|---|
| `Failed to enumerate processes` | frida vs frida-server version mismatch | Align both ends' major versions (same for strongR; the 16.7.19 set pairs with 13.7.1) |
| No output after attach, app hangs | Target anti-debug ptrace self-attach | spawn mode + first hook `ptrace`/`dl_open` to return 0; or switch to Renef (memfd injection, no ptrace) |
| Instant crash on attach | frida signature detection (port/thread names/maps) | strongR-frida + rename/re-port + LIEF edits of so signatures |
| Hooking a Java class reports `ClassNotFoundException` | Wrong ClassLoader / class not yet loaded under a packer | spawn + `Java.choose`, or enumerate classloaders and switch |
| native `Module.findExportByName` returns null | so not loaded / symbols stripped | Confirm with `Process.enumerateModules`; when stripped, hook by base address + IDA offset |
| Hooks ineffective on recent Android | Toolchain too old (frida <16) | Upgrade to 17.x; use the latest on Android 15/16 |
| ARTHookScripts-family scripts crash / offsets scrambled | ART struct offsets changed across versions | Pin the Android 10 + frida 16.7.0 environment, or use its "custom smali interpreter" mode |
| noxen won't start | PC frida version != device frida-server | Both ends must match (e.g. 17.7.3); `pip install frida==<server version>` |

## XVI. Selection Mnemonic

- **Quick peek**: frida REPL, results in two minutes.
- **A full battery of automated checks**: medusa (new) > objection (old but well-documented).
- **Let the LLM drive**: PC-side frida-mcp (Claude/MCP ecosystem) or barbatos (single binary, REST); device-side R2Droid (r2+AI).
- **Component/IPC attack surface**: noxen (auto attack-surface inventory + intent rewriting).
- **Capture fallback**: r0capture (immune to pinning/private protocols).
- **Offline so runs/unpacking**: vardoger (Python feel) or unidbg (mature and steady - see the dedicated page).
- **Long-term resident on the device** (device farms/automation/personal modules): LSPosed modules, provided <=Android 15 (AI-assisted via LSPilot).
- **No root**: frida-gadget repackaging (with apktool + Uber Apk Signer).
- **Detection hell**: pass detection first (strongR-frida + rename/re-port + gadget); when frida signatures are RASP-marked, switch to Renef (Lua + memfd injection); only then talk about what to hook.
- **Native algorithms**: only frida (Interceptor/Stalker) or straight to unidbg/vardoger - the Xposed family can't help.
- **Production-grade native hooks** (self-built RASP/monitoring direction): ShadowHook (+ByteHook for PLT); don't touch Cydia Substrate (dead).

## Install Quick Reference

> For the Python family, install into this repo's tools-env virtualenv (sandbox pitfall: with a read-only HOME, uv's default cache path breaks):
> `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p re/tools-env/.venv/bin/python <package>`
> Every `uv pip install` below means this method; version discipline in section II (python package <-> frida-server major versions must match).

| Tool | Install |
|---|---|
| frida 17 line (default) | `uv pip install frida frida-tools` |
| frida 16.x conservative line | `uv pip install frida==16.7.19 frida-tools==13.7.1` (separate venv, coexists with the 17 line) |
| objection | `uv pip install objection` |
| medusa | unverified |
| frida-mcp (the 62-tool recipe edition) | `claude mcp add frida-mcp -- npx -y frida-mcp@latest` |
| noxen | source `pip install .` (repo unverified) |
| barbatos | github.com/victorlpgazolli/barbatos (macOS single binary, curl-script install) |
| Renef | github.com/Byterialab/renef (r2renef: github.com/Ahmeth4n/r2renef; magisk-renef module) |
| Dobby | github.com/jmpews/Dobby (embedded, self-compiled) |
| ShadowHook | github.com/bytedance/android-inline-hook (Maven `com.bytedance.android:shadowhook`) |
| LSPosed | github.com/LSPosed/LSPosed (Magisk module zip flash; canary supports 15) |
| LSPilot | GitHub Releases (LSPosed module; API docs lspilot.fun) |
| R2Droid | Direct APK install (repo unverified) |
| r0capture | github.com/r0ysue/r0capture |
| lamda | github.com/firerpa/lamda (device-side server) |
| strongR-frida-android | github.com/hluwa/strongR-frida-android (matching server under releases) |
| undetected-frida | github.com/zer0def/undetected-frida |
| httptoolkit unpinning scripts | github.com/httptoolkit/frida-interception-and-unpinning |
| akabe1 unpinning series | github.com/akabe1/my-FRIDA-scripts |
| stackplz | github.com/SeeFlowerX/stackplz (eBPF, root) |
| ReShift / reconbridge / Veridiff | unverified |
