# Android RE Tool Master Table

> Status criteria: Active = has had a version or code update within the past year; Unmaintained = officially announced or no updates for over a year; Superseded = a stronger successor exists.
> Install criteria (restored 2026-10): each tool lists **one easiest install method** - brew / `uv pip` (Python family; for installs into this repo's tools-env see each sub-page's "Install Quick Reference") / `npx` one-shot / repo shorthand (github.com/owner/repo); "unverified" = repository address not yet verified; official-website tools get a domain; "-" = no install needed (manual / ships with host).
> Companion deep pages: `static-analysis-tools.md` (decompilers/ROSAL/SnikrFlow/DexKit/dexllm/packer identification), `recon-and-specials.md` (APKiD/apkleaks/DIE/DroidLysis/androidReverse/LIEF/010 etc.); **full tutorial-grade workflows for game frameworks (Unity IL2CPP/UE/Cocos/RN Hermes/Flutter blutter/dae) live in the four pages under `../14-game-frameworks/`** - the IL2CPP/Flutter tool rows in this table cross-link with those.

## I. Master Table (Category | Tool | Purpose | Install | Status | Commentary)

### 1. Hook / Dynamic Frameworks

| Category | Tool | One-line Purpose | Install | Status | Commentary (when to pick it) |
|---|---|---|---|---|---|
| Hook | frida | De-facto standard for dynamic instrumentation; write hooks in JS and inject into processes | `uv pip install frida` | Active (17.x coexists with final 16.x release 16.7.19, both selectable) | Default first choice; covers both native and Java ends, largest ecosystem; ART-offset-dependent scripts pin 16.7.19 |
| Hook | frida-tools | frida CLI suite (frida/frida-trace/frida-ls) | `uv pip install frida-tools` | Active (17 line and 16 line coexist) | frida-trace traces functions in one shot, essential for quick entry-point location; keep versions aligned with the server mainline |
| Hook | objection | Runtime exploration toolkit built on frida (SSL bypass/memory dump/root-detection bypass) | `uv pip install objection` | Slower maintenance but usable | For quick pentest checks; for deep RE hand-written frida wins |
| Hook | medusa | Modular frida automation framework, 90+ modules + Mango CLI | unverified | Active | More frequent updates and more modules than objection; first choice to replace objection |
| Hook | **frida-mcp** | MCP server: LLM talks to frida directly (62 tools + 15 resources, parameterized hook recipes) | `npx -y frida-mcp@latest` | Active (depends on frida@17) | In Claude/MCP workflows one sentence is a hook (OkHttp/Mac.doFinal/SSL pinning/root bypass recipes etc.) |
| Hook | **noxen** | frida hooking of component communication (getIntent/startActivity/sendBroadcast etc.) + attack-surface mapping | source `pip install .` (repo unverified) | Active | One shot yields the full picture of exported-component/implicit-intent attack surfaces; intents can be modified or dropped |
| Hook | **ARTHookScripts** | frida runtime smali parsing, inline hook at any position inside a method body | unverified | Usable (Android 10 + frida 16.7.x offsets hardcoded; repo has fixed 17 compat) | Uses the ShadowFrame mechanism for "in-method breakpoints"; good for extraction-packers observation / mid-flight value tampering - principles in `02-frida/advanced/yahfa与arthook` |
| Hook | **Dobby** | Multi-platform native inline hook framework (iOS/Android/desktop) | github.com/jmpews/Dobby | Slower maintenance (community forks keep it alive) | When you need a cross-platform hook embedded in your own so; successor to HookZz |
| Hook | **ShadowHook** | ByteDance production-grade Android inline hook (thumb/arm32/arm64) | github.com/bytedance/android-inline-hook | Active (Android 4.1-15, used by Douyin/TikTok) | First choice for commercial/in-house RASP; pair the PLT route with the same vendor's ByteHook |
| Hook | **Renef** | Android ARM64 dynamic instrumentation: Lua 5.4 + PLT/GOT + inline trampoline, memfd injection without ptrace | github.com/Byterialab/renef | Active (rising star) | A fallback when RASP watches for frida signatures; r2renef/magisk-renef ecosystem |
| Hook | **Cydia Substrate** | Old-school hook framework (Saurik, came to Android in 2013) | Archaeological (Cydia source, do not freshly install) | Unmaintained (never adapted to ART) | Dead, replaced by Xposed->LSPosed; archaeology only |
| Hook | **barbatos** | Zero-config Android runtime debugger: Frida API + built-in MCP/REST, LLM-driven autonomous debugging | github.com/victorlpgazolli/barbatos | Active (macOS only) | Single binary, works out of the box; class enumeration/recursive object inspection/method hooks all over REST |
| Hook | **R2Droid** | Radare2-family Android app + AI RE assistant (OpenAI-compatible) + r2frida | Direct APK install (repo unverified) | Active | On-phone closed loop: r2ghidra/r2dec decompilation + ESIL debugging + Frida template generation |
| Hook | LSPilot | AI-driven LSPosed dynamic RE assistant (module form) | GitHub Releases (LSPosed module) | Active | zygote-resident AI-assisted dynamic analysis; complements the frida family |
| Hook | Xposed (original) | Old Java-layer hook framework, swaps the zygote bridge | github.com/rovo89/Xposed | Unmaintained (stuck in the Android 9 era) | Archaeology only; on new devices always LSPosed |
| Hook | EdXposed | Magisk + YAHFA/SandHook implementing the Xposed API | github.com/ElderDrivers/EdXposed | Unmaintained (superseded by LSPosed) | Still usable on Android 10 legacy devices; don't pick it on new systems |
| Hook | LSPosed | Zygisk-based modern Xposed, mainstay of the module ecosystem | github.com/LSPosed/LSPosed | Officially unmaintained but still shipping canaries (stable 8.1~14, canary supports 15) | Still first choice for persistent Java-layer hooks; use canary on Android 15 |
| Hook | TaiChi | Root-free Xposed compatibility (virtualization/magnet mode) | github.com/taichi-framework/TaiChi | Unmaintained (marginalized by the LSPosed+Zygisk ecosystem) | Root-free use cases have mostly moved to VirtualApp-family + frida-gadget |
| Hook | YAHFA | ART method hook (one of EdXposed's default engines) | github.com/PAGalaxyLab/YAHFA | Low activity | Engine outclassed by the Pine/SandHook family, rarely used standalone |
| Hook | SandHook | ART hook framework, dalvik/art method replacement | github.com/ganyao114/SandHook | Low activity | Old project; worth reading the source to understand hook internals |
| Hook | Epic | Virtual/non-virtual method hooking based on ART hook | github.com/tiann/epic | Low activity | The engine of the root-free era (SunFree/TaiChi-magnet etc.) |
| Hook | Pine | High-performance ART method hook (method-entry jump) | github.com/canyie/pine | Low activity | TaiChi's engine, good performance; new-system support depends on the community |
| Hook | FastHook | Lightweight ART hook (inline-hook approach) | unverified | Unmaintained | Archaeology |
| Hook | Dexposed | Alibaba's old hook (Dalvik/early ART only) | github.com/alibaba/dexposed | Unmaintained (historical artifact) | Archaeology |
| Hook | VirtualXposed | Run Xposed inside a root-free virtualization container | github.com/asLody/VirtualXposed | Unmaintained | Heavily detected; new approaches use frida-gadget repackaging |
| Hook | frida-gadget | frida as an so, repackaged into the APK for root-free injection | Ships with frida releases (github.com/frida/frida) | Active (follows frida) | The way out when root detection is impassable or cloud real-devices lack root |
| Hook | **ReShift** | Zygisk on-phone Frida script injection suite: no-PC script-repo management + IL2CPP SQLite inspector + on-device LLM inference | unverified | New | When you don't want a resident frida-server or have no PC; makes Unity IL2CPP inspection offline-capable |
| Hook | **reconbridge** | KernelSU universal RE backend: phone-side atomic abilities (pull packages/read so/inject/Java trace), PC-side Claude+MCP commanding | unverified | New (verified on a real device, Android 16) | A "real device runs errands, PC thinks" division of labor; Java trace + live tampering suits agent integration |
| Dynamic | **Veridiff** | Native dual-execution trace diffing: two frida Stalker tracks locate the exact basic block where results diverge | unverified | New (x86-64/ARM64) | The engine for locating "same function, two different results"; finds divergence even in obfuscated control flow (csel/jump tables) |
| Dynamic | **stackplz** | eBPF-based Android native stack tracing (call stacks without injection) | github.com/SeeFlowerX/stackplz | Active | Alternative stack-tracing route when injection-tool signatures get detected; composable into mcp-termux-style on-device MCP environments |
| Environment | **lamda** | Full-stack Android device control platform: device-side server (root/non-root) + WebRTC screen mirroring + UI/OCR automation + one-click MITM + built-in Frida (with stealth patches) + MCP, 160+ APIs | github.com/firerpa/lamda | Active (high heat) | The foundation for clustered multi-real-device automation, replacing the hand-stitched adb+uiautomator2+frida-server+mitmproxy stack; the built-in stealth-patched Frida is the selling point |

### 2. Unpacking / DEX Dump

| Category | Tool | One-line Purpose | Install | Status | Commentary |
|---|---|---|---|---|---|
| Unpacking | FRIDA-DEXDump | frida memory magic search, dumps whole DEX | github.com/hluwa/FRIDA-DEXDump | Usable (community-maintained) | First choice for first-gen whole-DEX packers, instant results; useless against extraction/VMP packers |
| Unpacking | BlackDex | On-app root-free unpacking (virtualization + active loading) | github.com/CodingGay/BlackDex | Usable (supports 5.0~12) | Fastest route on root-free real devices; compatibility declining on new systems |
| Unpacking | FART | ART-layer active invocation + dump, repairs extraction packers | github.com/hanbinglengyue/FART | Community continuation (original unmaintained, derivatives active) | Mainstay for method-extraction packers; pair with FartFixer for repair |
| Unpacking | FartFixer | FART result repair/merge tool | unverified | Active | When FART dumps a pile of fragments, this merges them |
| Unpacking | **unpack** | All-in-one unpacking: 24 packer vendors identified -> Memory/Frida/eBPF three engines auto-scheduled -> 7-step DEX repair -> quality verification | unverified | New | Solves "dumped then forgotten": repaired output goes straight into jadx/JEB; one command, no manual engine choice |
| Unpacking | Youpk | Whole-DEX fart-style unpacker (custom ROM/source) | github.com/Youlor/Youpk | Unmaintained (one of FART's inheritors) | Use it if you have a custom-ROM environment; otherwise use FART |
| Unpacking | frida_dump | frida per-class dump (find dex in memory) | unverified | Usable but long unfreshed | Same family as FRIDA-DEXDump, a backup option |
| Unpacking | dumpDex | Old xposed/frida dump tool | unverified | Unmaintained | Superseded by FRIDA-DEXDump |
| Unpacking | DexExtractor | ART-environment so-layer dump | unverified | Unmaintained | Old tool, archaeology |
| Unpacking | FUPK3 | Next-gen instruction-level packer combat (active invocation triggers decryption) | unverified | Community approach (idea spreading) | New packers that decrypt only right before instruction execution must be poked one by one via active invocation |
| Unpacking | Reflection Master | Export loaded classes/methods while hooking | unverified | Low activity | Helps locate encrypted classes; not the main force |
| Packer ID | various signature scripts | Identify packer vendor by so name/signature bytes | - (see the signature table in `static-analysis-tools.md`) | Updated anytime | Step one of unpacking is knowing the packer - see the signature table in `static-analysis-tools.md` |

### 3. Static Analysis

| Category | Tool | One-line Purpose | Install | Status | Commentary |
|---|---|---|---|---|---|
| Static | jadx / jadx-gui | De-facto standard dex->java decompiler | `brew install jadx` | Active (CLI has no fat jar; scripted calls need `-cp` + main class) | First stop for the Java layer; gui supports search/rename/scripting |
| Static | **ddc** | Rust DEX->Java decompiler: full decompile of huge APKs in seconds, 15 query subcommands answer in milliseconds, output passes javac validation | github.com/ejfkdev/ddc | New | Switch to it when jadx struggles with Weibo/QQ-scale multi-dex monsters; query-based on-demand decompilation suits scripts/agents |
| Static | **ASC** | "APK as a read-only database" zero-preprocessing decompiler: direct Deflate bitstream queries, millisecond cross-DEX xrefs, minimal-DEX rebuild on demand after a hit | unverified | New (BlackHat EU talk) | Second-scale global string xrefs on monster packages (hundreds of MB), ~300ms single-class decompile, ~100MB memory; a speed-first route designed for agents/mobile researchers, complementary in direction to ddc; pair full-pseudocode export with the same author's radguard |
| Static | **rust_ASC** | One-to-one Rust rewrite of ASC: zero preprocessing + mmap + no disk cache, CLI latency/memory roughly 10x better than the Python version | release binaries github.com/MG1937/rust_ASC | New | Sped-up ASC route: findrefs/getclass/export/getmanifest four basics, another notch faster for on-demand retrieval on monster packages; first pick for repeated robotic queries |
| Static | **DexSQL** | Query APK/DEX directly with SQL: classes/methods/strings/call references, no preprocessing, low memory, same binary serves both CLI and MCP server | release binaries github.com/LSPosed/dexsql-release (closed-source binaries, free license, LICENSE must sit next to the executable) | New (by LSPosed) | Standard-SQL predicates / two-hop caller queries over dex; agents go MCP without a GUI; same direction as ddc/ASC/rust_ASC - pick by feel among them for on-demand big-package retrieval |
| Static | **dae** | Dart AOT snapshot analyzer: locates embedded snapshots and exports blutter-compatible symbols/structs to IDA/r2/Frida | unverified | New | Step one of Flutter so RE is running it for symbols; purely static, never runs the target |
| Static | **hermit** | Hermes bytecode (HBC 94~96) decompiler + structured patching: CFG/DOT, deterministic JS restoration, instruction insert/delete/jump relocation/string-table rebuild, byte-identical round-trip | release binaries github.com/xV4L3x/hermit (two packages: REPL + hbc_* CLI; macOS unsigned, clear quarantine) | New | First choice for modifying Hermes on RN (0.73~0.83 and 0.84+ with Hermes V1 off); use it when hbctool can't reach your version; HBC 98 (RN 0.84+ default V1) unsupported for now, fallback remains hermes-dec |
| Static | JEB (Pro) | Commercial all-round decompiler (dex+native+MIPS+RISC-V) | Official site jeb.com (commercial) | Active (since 5.40 ships MCP headless + AI assistant vibre) | Strongest deobfuscation/path analysis, expensive; teams can buy |
| Static | **ROSAL** | Deterministic restoration of obfuscated APK standard-library class names (anchors = platform API references that cannot be renamed) | `uv pip install rosal` | Active but very new | When androidx is fully obfuscated, run it first for a Tiny mapping, then read jadx; see the dedicated section in `static-analysis-tools.md` |
| Static | **DexKit** | C++ high-speed dex retrieval, reverse lookup of obfuscated classes/methods/fields by signature strings | github.com/LuckyPray/DexKit | Active | After version updates, relocate obfuscated classes with old signature strings; standard equipment for Xposed modules |
| Static | **dexllm** (dex-analyzer-for-llm) | LLM-facing dex analyzer: DexKit Core + DAD-aligned decompiler + MCP/FastAPI | github.com/mobile-threat-hunter/dex-analyzer-for-llm | Active (new project) | Lets Claude directly query classes/decompile/follow xrefs; built-in multi-source priority loading for unpacked dumps and IOC extraction |
| Static | **ReArk** | Desktop RE+AI: HarmonyOS NEXT(.hap/.abc)/Android/iOS | unverified | Active | New mainstay for HarmonyOS RE; enumerates manifest/permissions/components/entry points + device integration |
| Static | Androguard | Python dex/APK parsing (CFG/inter-procedural/diff) | `uv pip install androguard` | Active | For Python batch scripting; slow on big packages - switch to dexllm if speed matters |
| Static | Quark Engine | Malicious-behavior scoring (API-combination + call-sequence rules, not signatures) | `uv pip install quark-engine` | Active | First-glance risk profile of an unfamiliar APK; Quark Script supports vuln-hunting scripts |
| Static | **SnikrFlow** | angr+Claripy automated so triage (audit->sinks->reach->solve->dataflow) | No public repo (write an angr equivalent yourself) | - | Native angr scripts can achieve equivalent symbolic reachability; see the dedicated section in `static-analysis-tools.md` |
| Static | Ghidra | NSA open-source SRE, decompiler included | `brew install --cask ghidra` | Active | Main free native-analysis workhorse, complete ARM64 support |
| Static | **Ryuumonbuchi** | 217-tool MCP service over headless Ghidra (persistent PyGhidra/JVM session, no GUI automation needed) | unverified | New | Currently the most complete MCP for LLM agents driving Ghidra; tool surface a full circle larger than early ghidra-mcp |
| Static | **JNIAnalyzer** | Ghidra static-analysis script for Android NDK libraries' JNI (JNI registration/call identification) | github.com/Areizen/JNIAnalyzer | Usable (long unfreshed but no replacement) | Use it first to statically map JNI registration tables and call relations inside an so, saving manual assembly reading |
| Static | IDA Pro | Commercial de-facto disassembler standard + Hex-Rays | hex-rays.com (commercial) | Active | Ceiling of so analysis; 9.4 adds SVE2/SME/Swift ABI |
| Static | IDA Free | Free IDA (9.x onward with cloud decompilation) | hex-rays.com (free edition) | Active | Start here on a budget; decompilation quality is limited |
| Static | 010 Editor | Binary template parsing (parse dex/so/protobuf) | Official site 010editor.com (commercial; 300+ format templates, built-in disassembler) | Active (commercial; 300+ format templates, built-in disassembler) | Magic tool for parsing custom file structures, paired with template scripts |
| Static | **imHex** | Free open-source hex editor + Pattern Language templates | `brew install --cask imhex` | Active | Free 010 alternative with a community template repo |
| Static | GDA | Lightweight Chinese-made decompiler, fast startup | Official site gda.wiki | Low activity (author updates occasionally) | Faster than jadx for quick class scans of huge APKs |
| Static | Bytecode Viewer | Multi-engine aggregated decompilation (includes cfr/procyon) | github.com/Konloch/bytecode-viewer | Low activity | Engine-swap backup when jadx fails to decompile |
| Static | MobSF | Mobile automated static+dynamic scanning platform | github.com/MobSF/Mobile-Security-Framework-MobSF | Active (OWASP project) | Quick health-check reports/component vuln surface; not enough for deep RE |
| Static | apktool | Unpack/repack APK (smali+resources) | `brew install apktool` | Active (3.x is the big aapt2-everywhere release) | Essential for repacking, manifest edits, smali patches |
| Static | AXMlEditor | Binary XML to readable | unverified | Usable | Quick manifest reads; jadx can do it too |
| Static | dex2jar / enjarify | dex->jar conversion, paired with jd-gui | github.com/pxb1988/dex2jar | Low activity (sh launcher is buggy; invoke directly with `java -cp lib/*`) | Legacy flow; use only when you need JD-GUI/other jar tooling |
| Static | smali/baksmali | smali assembler/disassembler | github.com/google/smali | Active (Google-maintained line) | apktool's core; fastest when changing a single method |
| Static | **CFR** | Java decompiler engine (strong on modern obfuscation/generics/lambdas) | github.com/leibnitz27/CFR | Stable | One of the first engine swaps when jadx chokes on a class |
| Static | **Vineflower** | Fernflower fork, strong control-flow restoration | github.com/Vineflower/vineflower | Active | Engine-swap backup; bundled inside Bytecode Viewer/androidReverse |
| Static | **Procyon** | Java decompiler engine (generics/old code) | github.com/mstrobel/procyon | Unmaintained | Weak on new Kotlin/obfuscation scenarios, archaeology use |
| Static | **Krakatau** | Bytecode-precise decompilation + assembler | github.com/Storyyeller/Krakatau | Active | Ground-truth cross-check when other engines' output looks suspicious |
| Static | radare2 / cutter | Open-source disassembler + GUI front end | `brew install radare2` / `brew install --cask cutter` | Active | Lightweight native quick look; return to Ghidra/IDA for depth |
| Signing | Uber Apk Signer | One-shot sign/align after repacking | github.com/patrickfav/uber-apk-signer | Usable | The final step paired with apktool repacking |
| Auxiliary | apkanalyzer / aapt2 | Official manifest/resource inspection | Android SDK cmdline-tools | Active (follows SDK) | Check component exports, SDK versions |

### 3b. Dedicated Recon (the first minute with an unfamiliar APK - see `recon-and-specials.md` for detail)

| Category | Tool | One-line Purpose | Install | Status | Commentary (when to pick it) |
|---|---|---|---|---|---|
| Recon | **APKiD** | One-shot packer/protector/obfuscator/compiler identification | `uv pip install apkid` | Active | Step one of packer identification; on a miss, go manual with the four basics |
| Recon | **apkleaks** | Full jadx decompile + regex hunt for keys/hidden URLs | `uv pip install apkleaks` | Usable (no new releases) | First shot at an unfamiliar APK's asset surface; on a cloud-key hit verify with TruffleHog |
| Recon | **TruffleHog** | General secrets scanning + 800+ validators checking keys online | `brew install trufflehog` | Active | Depth supplement to apkleaks; note that validation makes outbound connections - mind authorization |
| Recon | **DIE** (Detect It Easy) | Compiler/packer/protector identification for so/binaries | github.com/horsicq/Detect-It-Easy | Active | Native-layer profiling, complements APKiD |
| Recon | **DroidLysis** | Property extraction + suspicious-feature flagging report | github.com/cryptax/droidlysis | Usable (no official release) | Batch sample pre-analysis, produces a list of combat points |
| Recon | **UltraSina/androidReverse** | Pure on-Android-device RE suite (Radare2 JNI + 8 decompilers + rebuild/sign + MCP) | github.com/UltraSina/androidReverse | Active | Closed loop for no-PC/cloud-phone scenarios; Flutter/Unity il2cpp support |
| Recon | **hookerView** | (user material - see section 6 of `recon-and-specials.md`) | github.com/CreditTone/hooker | Usable | Closest real entity is CreditTone/hooker: frida CLI toolkit + in-process webserver, active |
| Parsing | **LIEF** | Cross-format binary parse+modify (ELF/PE/Mach-O/DEX) | `uv pip install lief` | Active | First choice for wiping so-layer frida signatures and patching ELF |
| Parsing | **pyelftools** | Pure-Python read-only ELF parsing | `uv pip install pyelftools` | Active | Lightweight zero-dependency batch read-only analysis |
| Recon | **apiaxess** | Recover the truly reachable API surface of an APK/webpage: traffic+code dual evidence annotation (confirmed/inferred), replay/fuzz/export capable | unverified | New | One shot at an unfamiliar app's API asset surface, replacing the manual "proxy + unpack + decompile" assembly |

### 4. Emulation / Algorithm Restoration

| Category | Tool | One-line Purpose | Install | Status | Commentary |
|---|---|---|---|---|---|
| Emulation | unidbg | Emulate ARM so execution on Unicorn, black-box signature algorithms | github.com/zhkl0228/unidbg | Active | Mainstay of risk-control/signature algorithm restoration - see the dedicated page |
| Emulation | **vardoger** | Python-driven Android ARM64 emulation runtime: load so, run init/JNI_OnLoad/arbitrary functions, capture DEX | `uv pip install vardoger-vm` | Very new | Python-feel replacement for unidbg: ctypes drives the C ABI directly, Python supplies libc/JNI stubs; handy for unpacking (init_array self-decryption) and CI automation; API not stable yet |
| Emulation | unidbg-boot-server | unidbg wrapped as an HTTP service for remote invocation | github.com/zhkl0228/unidbg-boot-server | Active (pairs with unidbg) | Productize after algorithm restoration: local so becomes a remote signing endpoint |
| Emulation | AndroidNativeEmu | Early so emulation (one of unidbg's predecessors) | github.com/strazzere/AndroidNativeEmu | Unmaintained (fully superseded by unidbg) | Old project; occasionally mined for ideas when unidbg fails |
| Emulation | qiling | Cross-platform advanced emulation framework (Android rootfs supported) | `uv pip install qiling` | Active | Emulates the whole execution environment (syscalls included); heavy but complete |
| Emulation | unicorn | CPU instruction emulation engine (foundation of unidbg/qiling) | `uv pip install unicorn` | Active | For building your own emulation/custom instruction analysis |
| Emulation | frida-il2cpp-bridge | Unity il2cpp game memory-structure restoration | `npm i frida-il2cpp-bridge` | Active | Must-install for Unity game RE: dump il2cpp structures + call Il2CppAPI |
| Emulation | **Il2CppDumper / Zygisk-Il2CppDumper** | Unity il2cpp symbol & structure dump (static version + Zygisk runtime version) | github.com/Perfare/Il2CppDumper (+Zygisk-Il2CppDumper) | Usable (de-facto standard, mainline long unreleased) | Step one of Unity RE: dump global-metadata for symbols, then hand off to IDA/frida-il2cpp-bridge |
| Debugging | WinDbg (Preview) | User/kernel-mode debugging (also for emulators/drivers) | `winget install Microsoft.WinDbg` | Active | Rare in Android RE; pairs with the Windows layer |
| Debugging | IDA remote debugging + frida | IDA attaches to an Android process to debug so | Ships with IDA | Active | Main path for native single-stepping - see the static-analysis page |

### 5. Traffic Capture

| Category | Tool | One-line Purpose | Install | Status | Commentary |
|---|---|---|---|---|---|
| Capture | r0capture | Universal frida-layer capture (Java+native, immune to SSL pinning) | github.com/r0ysue/r0capture | Usable | The fallback when the app has cert pinning or non-HTTP protocols |
| Capture | mitmproxy | Open-source HTTP(S) MITM proxy + scripting | `brew install mitmproxy` | Active | First choice for automated batch traffic rewriting, Python script ecosystem |
| Capture | Charles | Classic HTTP proxy capture | Official site charlesproxy.com | Active (commercial subscription) | Old-school and pleasant; paid + slow feature growth, being eaten by Reqable |
| Capture | Fiddler | Classic Windows capture | Official site telerik.com/fiddler | Slower maintenance (Fiddler Everywhere's subscription turn has a bad reputation) | Keep for old habits; for new tasks prefer Reqable/mitmproxy |
| Capture | HttpCanary | On-Android capture app (VPN mode) | Official site httpcanary.com | Low activity (pulled from CN app stores; downloadable from the official site) | Emergency use on a real phone without a PC; limited on recent systems |
| Capture | Reqable | Flutter-family new proxy (original Pipe team), HTTP/1-3+WebSocket | Official site reqable.com | Active | The most worthwhile Charles replacement of 2024-2026, CN-friendly |
| Capture | Burp Suite | Web/API security testing proxy | Official site portswigger.net | Active (commercial + community editions) | Essential for API-layer vuln testing on apps (replay/fuzz) |
| Capture | Wireshark | Link-layer all-protocol analysis | `brew install --cask wireshark` | Active | Ground truth at the TCP/UDP/custom-protocol layer; does not do HTTPS decryption |
| Capture | frida + SSL-universal-bypass | Universal SSL pinning bypass script | unverified | Active | Run it before bringing up a proxy; passes 90% of pinning |
| Capture | **frida-interception-and-unpinning** | httptoolkit-maintained Android/iOS traffic-rewrite + SSL unpinning script collection | github.com/httptoolkit/frida-interception-and-unpinning | Active | Preferred backup when old unpinning scripts die on new systems; rewrites traffic through MitM directly rather than only bypassing validation |
| Capture | **FlutterTap** | Zygisk module: redirects Flutter traffic to a proxy + BoringSSL validation bypass, no cert install/no repackaging/no frida tether | unverified | New | The perennial pain of Flutter's built-in TLS stack ignoring system certs; install once, resident at boot, pick targets in the manager on the phone |
| Capture | **akabe1 unpinning series** | multiple-unpinning (SSLContext.init + accept-all TrustManager etc., 20+ cases) and three other .js scripts | github.com/akabe1/my-FRIDA-scripts | Unmaintained | Unmaintained but with broad case coverage, still a general library; the same-named claim "frida_unpin.py is the only thing that works on API 34" has no public source (see `dynamic-hook-frameworks.md` Section 10); for API 34 prefer the httptoolkit version or SSLSlayer, then r0capture as the last resort |
| Environment | ProxyDroid / iptables | Global transparent proxy (root) | github.com/madeye/ProxyDroid | Usable | Force-takeover when the app ignores the system proxy |
| Environment | JustTrustMe | Xposed cert-trust module | github.com/JustTrustMe/JustTrustMe | Low activity | Still works on LSPosed; on new systems prefer frida approaches |

### 6. Root / Runtime Environment

| Category | Tool | One-line Purpose | Install | Status | Commentary |
|---|---|---|---|---|---|
| Root | Magisk | systemless root + Zygisk de-facto standard | github.com/topjohnwu/Magisk | Active | Default first choice; v30 series strengthens package-name hiding |
| Root | Kitsune Magisk (Magisk Delta) | Magisk fork with extra hiding features | github.com/HuskyDG/magisk-files | Community-fork continuation | Install when you want MagiskHide-style hiding; mainline ideas have been absorbed upstream |
| Root | KernelSU | Kernel-mode root (GKI/self-built kernels) | github.com/tiann/KernelSU | Active (supports new kernel mainlines) | Best stealth (no userspace su traces); needs kernel support |
| Root | APatch | Kernel-image patch root (based on KernelPatch/bmax121, not a KSU fork) | github.com/bmax121/APatch | Active (kernels 3.18-6.12, ARM64 only) | Kernel-mode option besides KernelSU; KPM modules are fun |
| Environment | Zygisk | Magisk's built-in process-injection mechanism | Ships with Magisk | Active (follows Magisk) | The foundation of the LSPosed/module ecosystem |
| Environment | Zygisk Next | Standalone Zygisk implementation (for KernelSU/APatch) | github.com/Dr-TSNG/ZygiskNext | Active but closed-source since v1.2.2 | Must-install for KernelSU users running LSPosed |
| Environment | ReZygisk | Open-source Zygisk Next replacement | github.com/PerformanC/ReZygisk | Active (good reputation on SUSUFS compatibility) | The community prefers it under KSU+SUSUFS combos |
| Hiding | Shamiko | Zygisk anti-detection hiding (DenyList enhancement) | LSPosed/LSPosed.github.io releases | Archived but releases still trickle out (v1.1+ passes ACE detection) | Standard kit for Magisk hiding; on KSU take the susfs route |
| Hiding | Zygisk-Assistant | Gap-filling hiding module alongside Shamiko | unverified | Active | Fills maps/status-detection gaps beyond Shamiko |
| Hiding | Hide My Applist (HMA) | Xposed module hiding the app list | github.com/Dr-TSNG/Hide-My-Applist | Usable | Passes app-list enumeration detection; maintained forks exist for new systems |
| Hiding | PlayIntegrityFix | Passes Google Play Integrity attestation | github.com/chiteroman/PlayIntegrityFix | Active (community keeps fighting) | For overseas-app risk-control combat; rare in CN scenarios |
| Environment | Waydroid / cloud real-devices / LDPlayer etc. | Emulator environments (root is easy to get) | Official sites, waydro.id etc. | Active | Cloud real-devices do better against device fingerprinting; emulator signatures are easy to detect |
| Debugging | scrcpy + adb | Screen mirroring/control and command channel | `brew install scrcpy` + `brew install --cask android-platform-tools` | Active | Bread-and-butter tooling |
| Debugging | **loupe** | Browser-based Android console: the page speaks the ADB protocol directly - mirroring/logcat/shell/Frida/memory dump + APK decompilation + security analysis | unverified | New | Single-tab environment with no drivers and no adb server; plug in USB and go for quick triage |

### 7. frida Anti-Detection Ecosystem

| Category | Tool | One-line Purpose | Install | Status | Commentary |
|---|---|---|---|---|---|
| Anti-detection | strongR-frida-android | frida-server auto-patched to track upstream, signature-stripped | github.com/hluwa/strongR-frida-android | Active (tracks frida releases) | Preferred modded build; remember to swap the frida-tools version along with it |
| Anti-detection | hluda | Manually compiled signature-stripped frida (tutorial route) | unverified | Tutorial approach | The do-it-yourself route when strongR lags behind |
| Anti-detection | undetected-frida (zer0def) | Auto-patch scripts + prebuilt artifacts | github.com/zer0def/undetected-frida | Active | Pick one of this and strongR; tracking speed is luck of the draw |
| Anti-detection | frida-server rename + re-port | Strips the `frida-server` process-name / port-27042 signatures | - (manual routine) | Manual routine | Baseline operation beneath all modding (`-l 0.0.0.0:other-port`) |
| Anti-detection | LIEF | Modify exported symbols/strings in so binaries | `uv pip install lief` | Active | Alter so-layer signatures like the `gum-js-loop`/`gmain` thread names |
| Anti-detection | frida-gadget silent injection | Enters the app as an so, no server process | Ships with frida releases | Active (follows frida) | All server signatures vanish; the cost is repackaging |
| Anti-detection | shadow frida / multi-instance isolation | One isolated frida instance per task, avoiding a resident one | - (manual approach) | Manual approach | Isolation thinking against "port-scan / maps-scan" style detection |

### 8. AI/Agent-Assisted RE (cross-platform, the 2026 new wave)

| Category | Tool | One-line Purpose | Install | Status | Commentary (when to pick it) |
|---|---|---|---|---|---|
| Agent | **REA** | "Reverse Engineer Anything": one MCP bridges binaries/apps/runtime behavior; the agent directly reads and modifies the RE target | `npx rea-agents setup` | New (explosive heat) | General foundation of agent RE; eleven and others grow on top of it; plug-and-play with Claude/Codex |
| Agent | **eleven** | Agent-first RE desktop app (ACP protocol): native goes through REA to Ghidra or Rizin; APKs/shaders/models all accepted | unverified | New | The desktop form of "watch the agent read/modify binaries and approve it"; supports Android APK |
| Agent | **recurse** | "Cursor for RE" desktop environment: Tauri + pluggable engines (Rust-native/r2/IDA) + VTIL-style deobfuscation IL + cross-platform debugger + headless MCP | unverified | New | Local GUI-style agent RE; the devirtualization IL and bundled debugger are the differentiators |
| Agent | **knife** | Rust single-binary RE toolbox: PE/ELF/Mach-O/Wasm parsing + triage + call-site-level audit, CLI/TUI/MCP tri-state | unverified | New | "Not just says memcpy is imported - points out which length comes from a subtraction"; lightweight quick look / CI-friendly |
| Agent | **r0re** | Android CTF automated RE workbench (Cairn rewritten in Java): Fact/Intent/Hint task graph + Docker workers + completion gating | unverified | New | Fully solves public Android CTF challenge sets; the gate stops agents passing off guesses as answers |
| Agent | **reverse-skill** | RE/pentest/security skill-routing package: AI auto-routing + on-demand toolchain bootstrapping + self-evolving experience base | github.com/zhaoxuya520/reverse-skill | New (explosive heat) | Skill-routing foundation for AI clients like Claude Code/Cursor; broader coverage than this repo's skill; its routing and self-evolution ideas are worth borrowing |
| Agent | **agent-device** | Mobile-app automation-verification trio (CLI/MCP/Node API): accessibility snapshots save tokens; iOS/Android/HarmonyOS/TV all covered | `npx agent-device` | New | The closing piece of "run it and see" after an agent modifies an app; device access coordinates across parallel agents |
| Agent | **reverify** | Anti-hallucination verification layer: AI proposes claims, deterministic tools adjudicate against artifacts (VERIFIED/REFUTED with evidence) + long-session rollover | `uv tool install reverify` | New | The gate on agent RE conclusions; in practice it stops LLM "textbook-style" false claims about binary structures |
| Agent | **ablation** | Self-contained firmware/binary RE framework: semantic function search in stripped firmware (embedding matching) + taint/integer-overflow/BYOVD/driver-IOCTL scans, paired with Claude Code into an autonomous RE system (no MCP dependency) | `uv pip install ablation-tool` (CLI: ablation) | New | Purpose-built agent piece for finding functions in unstripped-symbol-less firmware and inventorying kernel-driver attack surfaces; 14+ scan subcommands, semantic matching saves full reads |
| Agent | **jshookmcp** | JS/Web RE agent workbench (single MCP server, 735 tools/36 domains): page hooking + network capture + bundle deobfuscation + WASM disassembly + frida process instrumentation, search-first saves schema | github.com/vmoranv/jshookmcp (build from source, Node 22.22+) | New | One-stop MCP for JS RE: crypto-parameter location/deobfuscation/WASM analysis without stitching five or six tools; not on npm, must clone and build |

### 9. Classic Highly-Rated Scripts and Plugin Collections

| Category | Tool | One-line Purpose | Install | Status | Commentary (when to pick it) |
|---|---|---|---|---|---|
| frida scripts | **frida-scripts** | Instrumentation script collection for mobile-app/desktop RE | github.com/lasting-yang/frida-scripts | Active | General hook starter-template library, tweak and use |
| frida workbench | **Frida-Script-Runner** | Web-based Frida framework: script management + running + AI-assisted generation (Android/iOS) | unverified | Active | When unfamiliar with the frida API, let AI generate the script and run it in the webpage directly |
| Ghidra scripts | **ghidra-scripts** | Auxiliary script collection for RE and vuln research | unverified | Active | Starter material for anti-debug/anti-obfuscation assistance |
| IDA plugin | **Gepetto** | Call an LLM inside IDA: explain functions/guess variable names/write comments | github.com/0x6d69636b/Gepetto | Active | Lightweight AI-assist route without setting up MCP; predecessor of IDA-NO-MCP |
| IDA plugin | **lighthouse** | Code coverage explorer | github.com/gaasedelen/lighthouse | Usable | See obfuscation/dynamic-execution blind spots, find untaken branches |
| Debug sync | **ret-Sync** | Real-time cursor sync between debuggers (GDB/LLDB/x64dbg/WinDbg) and IDA/Ghidra/Binja | github.com/bootleg/ret-sync | Usable | While dynamic-debugging, the disassembler auto-follows PC - no address ping-pong |
| jadx plugin | **JADXecute** | Embedded scripting engine inside jadx-gui to dynamically manipulate decompiled output | unverified | Usable | Batch rename/rewrite of decompiler output |
| jadx plugin | **Jarida** | jadx plugin wired directly to Frida: trace/change method return values from the GUI | unverified | Active | Statically spot a suspicious method, right-click to verify dynamically - no frida CLI hopping |

## II. Toolchain Selection Decision Tree (you've got an APK - now what?)

### Scenario A: Look at the protocol (endpoints/params/encryption)
1. Start with **jadx** on the Java layer: OkHttp/Retrofit wrappers, signing function names (`sign`/`token`/`encrypt`).
2. Attach **Reqable/mitmproxy** as the proxy; blocked by SSL pinning -> **frida + an unpinning script** (or objection's `android sslpinning disable`).
3. Proxy won't fit (non-HTTP/mutual TLS locked down) -> **r0capture** collects plaintext right at the socket layer.
4. Params computed in native -> note the so and export name, switch to Scenario D.

### Scenario B: Unpacking
1. Identify the packer first (so name/signature - see the signature table in `static-analysis-tools.md`).
2. Whole-DEX packer (first gen) -> **FRIDA-DEXDump** (root+frida) or **BlackDex** (root-free, most reliable on Android <=12).
3. Extraction packer -> **FART + FartFixer** (active invocation backfills method bodies).
4. Instruction-level/VMP packer -> method bodies still missing after dumping -> you can only hook the call site (read decrypted memory in the frida `Interceptor` context), or pivot to native analysis (VMP's Java layer isn't worth fully restoring).

### Scenario C: Change logic (patch/persistent hook)
1. Small Java-layer edits -> **apktool decompile -> smali patch -> Uber Apk Signer**.
2. Long-running hooks needed -> **LSPosed module** (Android <=15; use canary on 15).
3. Temporary/flexible -> **resident frida script** (`frida -U -f` spawn).
4. No root -> **frida-gadget repackaging** or TaiChi-family virtualization (heavily detected - use with caution).

### Scenario D: Get past detection and run (root/frida/emulator detection)
1. Root: **Magisk v30 + Zygisk + Shamiko + Zygisk-Assistant(+HMA)**; harsh detection -> the **KernelSU + SUSUFS + ReZygisk** kernel route.
2. frida: **strongR-frida** (or self-compiled hluda) + rename/re-port; still scanned -> **gadget injection**.
3. Heavy emulator signatures -> switch to **cloud real-devices/secondhand real devices**.
4. After passing detection, return to Scenarios A/B/C for the main business.

### Scenario E: Algorithm restoration (signing/risk-control so)
1. **unidbg** pulls the so and runs it black-box (environment setup in the dedicated page `emulation-frameworks.md`).
2. Won't run or you need to see the logic -> **IDA/Ghidra** static + **frida active invocation** as cross-reference.
3. Productization needed -> **unidbg-boot-server** wraps it into an HTTP signing service.

## III. Trend Notes (2024-2026)

- DEX-layer unpacking of mainstream free packers (360/Legu/Bangcle/Ijiami) is highly automated; vendors have shifted focus to **Java2C + VMP + instruction-level encryption**, plus "anti-AI adversarial hardening" (anti-LLM-assisted RE).
- The frida ecosystem remains the absolute center of dynamic analysis; the Xposed family has entered "maintenance mode" (after LSPosed's official end-of-life it survives on canaries); new feature development happens almost exclusively on the frida side.
- The root-detection battle's main axis has moved from userspace (MagiskHide->Shamiko) to **kernel space** (KernelSU/APatch + SUSUFS).
- Traffic-capture landscape: Charles/Fiddler are in maintenance mode; **Reqable + mitmproxy** became the main combo after 2025.
- H2 2026: "agent-first RE" became a force - REA (the general MCP foundation) brought out a batch of tools like eleven/recurse/knife/r0re; workflows shifted from "humans use tools" to "agents use tools, humans accept the results"; Section 8 collects the core of this wave, with the tool radar tracked monthly.
- 2026-10 ecosystem moves: the Claude skill ecosystem exploded (ten-thousand-star skill packs like reverse-skill/android-reverse-engineering-skill); debugger MCPs filled in (WinDbg/x64dbg/Binja/r2 official families - see `../08-ai-re/ai-re-tools.md`); "APK as a database" zero-preprocessing decompilation (ASC) represents the performance route of the agent era; reverify opened the new category of "anti-hallucination verification layer".
