# Android Security Knowledge Map (tree node 1000943, 252 nodes, 23 second-level categories)

> Division of labor: **frida/hook/unpacking/packer confrontation/capture/risk control/kernel** are already covered in depth by the local `techniques/` library (12 areas, 63 files); this area only gives 3-5 line summaries + cross-links, no duplication; **programming development/compilers/file formats/system internals/viruses and trojans/CTF** are gaps not covered by the techniques library and are dug into depth here as full articles.

## 1. Programming & Development [1000953] — techniques-library gap, brief here

In one sentence: forward Android development ability is the foundation of reversing — if you cannot read how it is written, you cannot see how to break it.

Main nodes: NDK development [1001273] / secure development [1001361] / disk encryption [1001623] / sandbox [1001645] / others [1001343].

- **NDK/JNI development**: two routes for JNI function registration (static `Java_package_name_method_name` naming convention / dynamic `RegisterNatives`; the latter is the core surface for locating JNI implementations during RE — see the techniques library `../../techniques/02-frida/native-hook-cheatsheet.md` 1.x RegisterNatives hook); `CMakeLists.txt` + `externalNativeBuild` is the modern build entry. RE value: **only if you can write can you patch** — unidbg environment completion, frida active invocation, and so patching all require NDK-level C++ ability.
- **System signing system** (scattered under "secure development" in the tree): platform signature (sharedUserId="android.uid.system"), signature V1 (JAR)/V2 (APK Signing Block, whole-package verification)/V3 (key rotation)/V3.1/V4 (fs-verity incremental); verify with `apksigner verify --print-certs`; the signature change after repackaging is the root of "signature check" anti-cracking — the bypass is in the techniques library `../../techniques/02-frida/java-layer/storage-and-system.md` §9.2 hook_pkms signature forging.
- **AOSP build**: `repo init/sync` → `lunch` to pick a target → `make -j`; outputs system.img/boot.img/vendor.img; the GKI kernel is built separately (`build/build.sh`); boot.img structure and symbol-extraction practice are in the techniques library `../../techniques/07-kernel/android-kernel-ebpf.md`.
- Tools: Android NDK/JDK17+/CMake/Android Studio; representative posts: "Compiling .so dynamic libraries with the NDK", "NDK development on Android: file permissions and users", "Building a smooth NDK IDE with VS + VA", "Simple and fast JNI interface function obfuscation", "Notes on breaking at JNI_OnLoad and init_array".

## 2. Hook Frameworks [1000954] — fully covered by the techniques library, cross-linked

Main nodes: Hook types [1001308] (Dalvik Hook/Art Hook/SO Hook: GOT/Inline/LD_PRELOAD) / Hook injection frameworks [1001309] (Frida [1001312]/Xposed [1001318]/Unidbg [1001702]) / dynamic injection [1001310] (so injection/DEX injection) / Anti Hook [1001360].

3-line summary: Hooks split into three families by "layer" — the Java/ArtMethod layer (Xposed/LSPosed yahfa/sandhook, frida ART hook), the native SO layer (GOT table rewrite/inline trampoline/LD_PRELOAD), and the injection family (ptrace/zygisk/DEX injection). Principle differences and the selection matrix are fully covered by the techniques library `../../techniques/05-toolbox/dynamic-hook-frameworks.md` (307 lines): frida ecosystem vs Xposed family, three-way native inline hook comparison (Dobby/ShadowHook/Renef), Android-version × framework compatibility matrix. Frida script practice (java layer 6 domain quick-reference files/native layer 753-line quick reference), two complete GOT hook implementations (pure-JS ELF parsing + linker soinfo, `../../techniques/02-frida/advanced/gothook.md`) are in the techniques library `02-frida/` (java-layer/native/advanced three tiers, 16 files). **See the techniques library (same skill, re/techniques) for details; not duplicated here.**

## 3. Vulnerability Analysis [1000956] — kernel surface cross-linked, app surface one line here

Main nodes: linux low level [1001335] / Android low level [1001336] / hardware driver vulnerabilities [1001337] / vulnerability scanning [1001340] / related tools [1001552].

- Kernel/low-level vulnerabilities (binder/futex/io_uring/page-cache families) are already covered in depth with official CVE links in the techniques library `../../techniques/07-kernel/kernel-exploit-fuzzing.md`; the representative app-layer EoP case is CVE-2024-0044 (RunAnyApp UAF privilege escalation to read any app's private data).
- Perspective added in this area: the classic shape of an Android exploit chain is "generic kernel LLE + EoP + persistence"; the reasoning behind the narrowed attack surface after the app domain had io_uring sealed by seccomp is in [compiler-and-system.md](compiler-and-system.md) §5.

## 4. Viruses & Trojans [1000957] — techniques-library gap, dug into depth here

Main nodes: virus analysis [1001653] / trojan analysis [1001654] / malware [1001655].

In one sentence: the three monetization schools of Android malware (traffic fraud / premium charges / espionage) + Discord Stealer / fake dating / scam-app field analyses, the full chain (family traits → analysis workflow → IOC extraction) is developed in [malware-and-ctf.md](malware-and-ctf.md) §1-3 in this area.

## 5. Tools & Scripts [1000958] — fully covered by the techniques library, cross-linked

Main nodes: decompilers [1001292] / debuggers [1001293] / AXML parsing [1001295] / repackaging tools [1001359] / analysis systems (TaintDroid [1001642]) / Wallbreaker [1001663].

3-line summary: decompiler shoot-out (jadx/IDA/Ghidra/JEB/CFR/Vineflower + version pitfalls), APKiD packer identification, DexKit queries, Androguard scripting — fully covered by the techniques library `../../techniques/05-toolbox/static-analysis-tools.md` (270 lines) + `../../techniques/05-toolbox/recon-and-specials.md` (the first minute after taking over an unfamiliar APK); the 100+ tool master table is at `../../techniques/05-toolbox/tool-master-table.md`. Historical tools in the tree (Andbug/eclipse/Wallbreaker) have been replaced by the jadx+frida ecosystem and are only of archaeological interest. **See the techniques library (same skill, re/techniques).**

## 6. CTF [1001296] — techniques library has only an index, dug into depth here

In one sentence: the five Android CTF challenge families (Java-layer logic / so reversing / VMP / anti-debug anti-injection / composite packers) and the solving pipeline, including KCTF and the Android track of the Tencent game-security competition, are developed in [malware-and-ctf.md](malware-and-ctf.md) §4 in this area.

## 7. Compilers [1001297] — techniques library only has the chain, dug into depth here

Main nodes: Smali/Baksmali [1001598] / compilation [1001612] (OLLVM-framework builds [1001751]/front-end compilers [1001752]) / decompilation [1001636] (ApkTool [1001596]/JEB [1001597]/tips and experience [1001635]) / intro [1001750].

In one sentence: the whole compile-and-execute chain from javac→dx/d8→dex2oat→JIT/nterp, plus the principles of the OLLVM family of obfuscating compilers, is developed in [compiler-and-system.md](compiler-and-system.md) §1-2 in this area (the techniques library area 11 only covers the "load and execute" sequence; the compiler itself is a gap).

## 8. Security Apps / Secondary Development / Secure Development / MDM — small tree categories, merged into one line each

- **Security apps [1001330]**: a collection of development articles applying RE skills to protection products (app-hardening SDKs, antivirus engines); methodology is the mirror image of "obfuscation and packing".
- **Secondary development [1001558]**: adding features / changing behavior of an existing APK (the counterpart of the secondary-development chapter in the Windows area); core skills are repackaging + signing + defeating integrity checks.
- **Secure development [1001631]** overlaps the secure-development subcategory of programming: the engineering of writing security tools (frida script distribution, detection engines).
- **MDM [1001673]**: enterprise mobile device management (DeviceAdmin/DeviceOwner); offense-defense perspective = a preinstalled control surface — be alert for uninstall protection when you see a DeviceAdminReceiver during RE.

## 9. System Topics [1001344] — partly cross-linked, core dug into depth here

Main nodes: Android ROM [1001345] / system kernel [1001346] / root permissions [1001401] / Android runtime [1001602] (Dalvik [1001603] + instruction set [1001299]/ART [1001604]) / Android source study [1001615] / SEAndroid [1001626] / Magisk [1001754] / custom systems [1001771] / data structures [1001664].

Division of labor: kernel attack surface / ftrace hook / Magisk+Shamiko root hiding are already cross-linked to the techniques library (07-kernel five files + `../../techniques/04-evasion/root-env-hiding.md`); **the SEAndroid policy system, seccomp filtering, the binder driver protocol, and the Dalvik→ART evolution** are dug into depth in [compiler-and-system.md](compiler-and-system.md) §3-6 in this area — these four blocks are native content of the knowledge-base tree and the techniques library only mentions them in passing.

## 10. Debugging & Reversing [1001529] — fully covered by the techniques library, cross-linked

Main nodes: debugging and analysis [1001528] (static RE/dynamic debugging/profiler/IDA Pro [1001547]: dynamic debugging of DEX/SO/script plugins/junk code [1001772]/Android Studio/JEB/Unicorn/radare2) / anti-tracing [1001554] (Anti-Debug: blocking attach/multi-process protection/Hook detection/Root detection) / integrity checking [1001610] / SSL hijacking [1001385] / game analysis [1001630] (Unity 3D/Cocos 2D/Cry Engine 3) / Unidbg [1001755].

3-line summary: IDA dynamic debugging of so (remote android_server/debugserver), JEB debugging dex, the full anti-debug family (TracerPid/ptrace self-attach/multi-process mutual protection/svc inline detection) down to the syscall layer — layered once and for all by the techniques library `../../techniques/04-evasion/detection-landscape.md` (310 lines); RASP-grade commercial confrontation is in `../../techniques/04-evasion/rasp-bypass.md`. Game engines (Unity il2cpp dump/Cocos luajit/UE/RN/Flutter) entry points are in the techniques library `14-game-frameworks` (tool row index at `../../techniques/05-toolbox/tool-master-table.md`). **See the techniques library (same skill, re/techniques).**

## 11. Reverse Analysis [1001530] — brief here (base layer)

Main nodes: virtual functions [1001613] / smali syntax [1001656] / basics [1001747] / ARM basics [1001766] (ARM assembly language [1001284]/Thumb [1001605]/AArch64 [1001606]/SVC instruction [1001768]).

- **smali**: the human-readable form of Dalvik bytecode, `.smali` registers v0-vN (non-parameter registers + parameter registers), the invoke-{virtual/static/direct/interface/range} five families, the sget/sput field family; in the modern workflow "reading smali end to end" has been demoted to "jadx for Java + revisit smali for key methods to verify" — but **editing smali and recompiling** (apktool b) remains the main route for patching APKs.
- **ARM basics**: AArch64 (A64) and Thumb2 (A32/T32) dual instruction sets; RE essentials: BL/BLR calling convention with x0-x7 for arguments, x29 FP/x30 LR/SP; SVC #0 enters a syscall (x8 syscall number, x0-x5 arguments) — the complete convention table for catching svc when hooks degrade is in the techniques library `../../techniques/09-function-map/hook-fallback-playbook.md` (387 lines, incl. arm64 syscall number quick reference).

## 12. Obfuscation & Packing [1001532] — fully covered by the techniques library, cross-linked

Main nodes: obfuscation & deobfuscation [1001589] (source/template/AST/IR/DEX obfuscation + deobfuscation + SO obfuscation + JUMPOUT [1001622]) / packing & unpacking [1001590] (basic theory/Android software packers/SO hardening/anti-debug/runtime environment checking/packer detectors/secure keyboards/virtualization VM [1001356]/unpacking techniques [1001560]) / resource protection [1001611].

3-line summary: the three packer shapes (whole-file encryption packer / extraction packer (NOPed methods) / VMP virtualization), unpacking solution selection (JDex/BlackDex/dpt-shell/eBPF after FART broke) and dex repair (cdex→dex + SHA-1/Adler recomputation), techniques library `03-unpacking/` three files; 8 classes of so obfuscation traits, junk-instruction patching, four routes through control-flow flattening, and the five-step VMP restoration method are in the techniques library `../../techniques/10-algo-restore/deobfuscation-practice.md` (306 lines). **See the techniques library (same skill, re/techniques).**

## 13. File Formats [1001533] — techniques-library gap, dug into depth here

Main nodes: class bytecode [1001301] (incl. AOP: Javassist [1001575]/ASM [1001576]) / AXML [1001303] / ARSC [1001304] / DEX/ODEX [1001305] (file format/loading process/reassembly and repair/modification/parsing tools) / OAT [1001307] (layout/DEX extraction/smali conversion) / ELF and so [1001341] (format spec/dynamic loading/Linker analysis/Section/parsing tools) / apk files [1001539] (assets/res/META-INF/resources.arsc/AndroidManifest.xml) / library files [1001536] (jar/aar).

In one sentence: byte-level detail + comparison tables for the six major formats — dex (header/map_list/class_def/code_item), elf (so relocation/GOT/PLT/init_array), oat/vdex/cdex, arsc, AXML — are developed in full in [file-formats.md](file-formats.md) in this area.

## 14. Protocol Analysis [1001535] — fully covered by the techniques library, cross-linked

Main nodes: packet filtering and analysis [1001280] / analysis cases [1001357] / packet replay and analysis [1001546] / capture techniques [1001769] (tools [1001298]/environment setup [1001770]).

3-line summary: capture with the 10-breakpoint localization + 13-scenario matrix (Android7+/14+ certificates, VPN chain, QUIC, Flutter, mutual-auth p12 dump, encrypted-traffic Burp plaintext bridging) — the techniques library `../../techniques/04-evasion/capture-all-scenarios.md` (306 lines) is the main entry; locating and bypassing the five SSL-pinning classes is in `../../techniques/04-evasion/ssl-pinning-bypass.md` (263 lines); offline protocol work and replay (frida RPC/unidbg three-stage rocket) are in the techniques library `../../techniques/10-algo-restore/protocol-offline-rpc.md` (363 lines). **See the techniques library (same skill, re/techniques).**

## 15. Security Testing [1001557] — not covered by the techniques library, brief here

Main nodes: SDK testing [1001678] / Drozer testing framework [1001679] / data storage [1001680] / others [1001681].

- **Drozer**: the Android security testing framework (formerly Mercury), agent running on the device, console launching attacks — core modules `app.package`/`app.activity` (exported-component enumeration + Intent triggering)/`app.provider` (content-provider injection and directory traversal)/`app.broadcast`; sample command: `dz> run app.package.attacksurface com.x`. Community activity declined after the 2020s; MWR went to F-Secure→WithSecure, now maintained by Reversec Labs, still usable; the exported-component testing approach remains valid.
- **Data storage**: SharedPreferences/MMKV plaintext, SQLite (-wal residue), external storage, log leakage; testing = walk `/data/data/<pkg>` looking for sensitive plaintext (needs root or run-as on debuggable packages).

## 16. Secondary Development [1001558]

See the merged note in §8. Core skill chain: apktool d → edit smali/resources → apktool b → zipalign → apksigner re-sign → defeat signature checks (see techniques library `../../techniques/02-frida/java-layer/storage-and-system.md` §9.2).

## 17. Fundamentals [1001600] — brief here

Main nodes: analysis environment [1001561] (adb [1001651]/commands and configuration [1001668]) / learning methods [1001643] / security status [1001646].

- **adb must-know set**: `adb shell dumpsys activity top` (current stack)/`adb shell pm path <pkg>` (get APK path) + `pull`/`am start -n` (launch with extras)/`ps -A | grep` + `/proc/<pid>/maps`, `adb backup` extraction (when allowBackup=true), `adb shell settings get`.
- **Learning method**: the guide articles in the tree's "learning methods" subtree all point to the same conclusion: threading one real target through (unpack one packer → hook one encryption → restore one protocol) is an order of magnitude faster than reading the catalog end to end — consistent with the "no reading the whole library" rule of the techniques library INDEX.

## 18. Software Cracking [1001625] — community specialty, brief here

Main nodes: ad removal [1000947] / feature limits [1001624] / serial-number protection [1001629] / time limits [1001633] / others [1000948].

In one sentence: the mirror of Windows cracking culture on Android — ad removal (locate the ad SDK's initialization call and NOP/hook it), VIP feature limits (change the `isVip` return value / server-side checks switch to protocol forging), time limits (trial expiry checks, `System.currentTimeMillis` hook or smali patch), serial numbers (reverse the local-check algorithm; online checks go through capture + offline replay). Ethical boundary: own/authorized targets and CTF only. The methodology and hook tools all reuse the techniques library's two 02-frida quick-reference files.

## 19. Hot Patching / Instrumentation — one line each + cross-links

- **Hot patching [1001753]**: the Tinker/QZONE/AndFix/Sophix family — dex patch loading and ClassLoader queue-jumping; offense-defense perspective = a legitimate channel for swapping dex at runtime, heavily overlapping the unpacking-dump entry point (find the patch dex's ClassLoader and you have the plaintext).
- **Instrumentation [1001775]**: broadly = the frida/Stalker/QBDI/Unicorn family; the tiered observation-point ladder (symbol hook → inline → stalker instruction-level → kernel) decision is in the techniques library `../../techniques/11-syscall-chain/observation-matrix.md` (253 lines, a 35-row × 7-column matrix).

## Appendix: file index for this area

| File | Content |
|---|---|
| [android-knowledge-map.md](android-knowledge-map.md) (this file) | 23 second-level categories + routing one by one |
| [compiler-and-system.md](compiler-and-system.md) | ART/dex2oat/JIT/AOT full compile chain, SELinux, seccomp, binder |
| [file-formats.md](file-formats.md) | Byte-level detail for dex/elf/oat/vdex/cdex/arsc/AXML |
| [malware-and-ctf.md](malware-and-ctf.md) | Malicious families + field cases + CTF challenge patterns |

> Maintenance: when in conflict with `~/.zcode/rules`, rules win; when the techniques library (same skill, re/techniques) is updated, sync the cross-link rows in this file.
