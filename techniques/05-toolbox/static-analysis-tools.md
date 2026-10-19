# Static Analysis Tools (jadx / IDA / Ghidra / JEB and the Layered Toolchain)

> Core conclusions: on the Java layer **jadx rules them all**; on the native layer the **duo of Ghidra (free)/IDA Pro (commercial)**; JEB is the all-round commercial alternative; obfuscation combat adds two new routes - **ROSAL (deterministic deobfuscation mapping)** and **DexKit/dexllm (high-speed retrieval)**.

## I. Head-to-Head of the Four Mainstays

| Dimension | jadx | Ghidra | IDA Pro | JEB Pro |
|---|---|---|---|---|
| Positioning | dex->java decompiler | Open-source SRE (disassembly + decompilation) | Commercial disassembly standard | Commercial mobile all-rounder |
| Current version | 1.5.6 | 12 | 9.1->9.4 | 5.35->5.48 |
| Price | Free | Free | Commercial (expensive) | Commercial subscription |
| Java/dex | ***** | No dex support | No dex support | **** |
| ARM64 native | None | **** | ***** | *** |
| Decompilation quality | Best for Java | Usable C pseudocode | Hex-Rays is the ceiling | Stable, strong obfuscation restoration (dexdec IR optimizer iterates continuously) |
| Plugin ecosystem | Scripts (java/js) + community | Extremely rich | Richest (flirt/signature) | Medium (official samplecode library) |
| Scripting | jadx-gui scripting | Java/Python | IDAPython/IDC | Python/Java (native cpython3.x execution since 5.40) |

### jadx
- **1.5.6 highlights**: security fixes (zip entry path-traversal denial, gradle export script string sanitization); type-update queue change removes recursion; **new call-graph module**; GUI graph-view/code-area sync; Kotlin 1.9+ `$ENTRIES` enum restoration.
- **CLI usage pitfall**: v1.5.6's release assets are only `jadx-1.5.6.zip` / `jadx-gui-1.5.6-win.zip` / `jadx-gui-1.5.6-with-jre-win.zip`, **no single-file executable fat jar**. The distribution is a `bin/jadx` script + a pile of jars in `lib/`. To call `main()` directly from your own scripts/pipelines you must use `-cp` + an explicit main class; `java -jar` matches no jar:
  ```bash
  # Call the main class directly from the unpacked distribution (no fat jar, -jar unusable)
  java -cp "jadx-1.5.6/lib/*" jadx.cli.JadxCLI -d out app.apk
  # GUI main class
  java -cp "jadx-1.5.6/lib/*" jadx.gui.JadxGUI
  ```
  (For scripting, still prefer the `bin/jadx` wrapper script; use `-cp` only in environments where the wrapper is unavailable.)
- **Tips**: on huge APKs speed up with `--decompilation-mode simple` or `--no-res`; switch exploded classes to the smali view; after `Save all`, treat it as a gradle project and full-text search with an IDE/rg.

### Ghidra
- Free and full-featured: complete ARM64/Thumb, built-in decompiler, header files/type libraries, Version Tracking two-version diff, collaboration server; since 11.4 the debugger is mature (remote-attach Android with gdbserver).
- Community add-ons: GhidraFrida (exports frida skeletons), ghidra-android (ART structure recovery).

### IDA Pro
- 9.x: 9.1 ARM64 ILP32/MVE; 9.2 Golang decompilation enhancements; 9.3 native Linux ARM64; **9.4 Apple Dyld Shared Cache rework, Swift ABI, ARM SVE2/SME, Hexagon module**.
- Must-know for Android: FLIRT/lumina to recognize library functions; d-810/HexRaysDeOb (microcode deflattening); ida_frida to export `Interceptor.attach` skeletons; bindiff/Diaphora version diffing; gdbserver/lldb remote so debugging.

### JEB Pro
- **Version line**: 5.35 (dexdec emulator upgrade + stronger opaque-predicate resolution) -> ... -> 5.48.
- **Architecture coverage**: Dalvik (dexdec) + ARM (incl. SME/SME2, ARM 9.6 SIMD) + x86 + MIPS + **RISC-V (RV32I/RV64I, Pro since 4.5)** + WebAssembly (3.0) + Dart + EVM + Nvidia SASS.
- **Seamless Dalvik debugging**: JDWP Android debugger (5.42 major upgrade: field read/write watchpoints, hardened GDB/LLDB); "Pretend Debuggable" can debug non-debuggable packages (5.23).
- **Automation**: Python/Java client scripting and plugin API; dexdec IR-mode optimizer public API (5.38, match-and-replace); **since 5.40 MCP headless (`jeb -c --mcp`) + built-in AI assistant vibre (introduced 5.32, z.ai endpoint supported since 5.44)** - an LLM agent can drive JEB analysis directly.
- **Deobfuscation**: opaque-predicate/MBA resolvers (continuously strengthened in 5.19/5.26/5.35), unflattener (upgraded 5.47), generic unpacker (encrypted-resource recovery added 5.43).
- Fits: heavily obfuscated Java layers, pipeline automation needs, AI-assisted analysis. Downsides: expensive, less community material than IDA.

## II. Java Decompiler Engine Comparison (engine-swap backups + obfuscation combat)

Purpose: swap engines for classes jadx explodes; UltraSina/androidReverse (see the specials page) already packages these 8 engines as on-Android options.

| Engine | Version/Status | Strengths | Weaknesses |
|---|---|---|---|
| jadx built-in | 1.5.6 active | Best overall, dex goes straight in | Occasional Kotlin-structure crashes |
| **CFR** | 0.152 (long-stable) | **Strong on modern obfuscation (strings/control flow)**, good generics/lambda restoration | Only takes class/jar (dex must be converted first) |
| **Vineflower** | 1.12.0 (active) | Fernflower fork, **strong control-flow structure restoration**, actively maintained | Use with Bytecode Viewer/jd |
| Procyon | Dormant | Generics, old Java code | Unmaintained, poor new-syntax support |
| Krakatau | Active | **Bytecode-level precision** (strict constant-pool restoration, no guessing) + bundled assembler for re-assembly | Output is low-level, mediocre readability |
| JD-Core | Ships with JD-GUI | Fast, light | Unmaintained for years |

- In practice: `Bytecode Viewer` (aggregates CFR/Procyon/Fernflower) or UltraSina/androidReverse's engine switching; Krakatau serves as the ground-truth cross-check when "jadx/CFR both emit suspicious code".

## III. The APK -> smali -> java -> native Layered Toolchain

```
APK file
 ├─ Unpack/resources ── apktool d (manifest/arsc/resource XML made readable)
 │                      AXMLEditor (lighter when you only need the manifest)
 ├─ Java layer ──────── jadx / jadx-gui (first choice)
 │                      ├ failed methods → smali view (inside jadx) or baksmali
 │                      ├ engine swap → CFR/Vineflower/Krakatau (Bytecode Viewer, androidReverse)
 │                      └ obfuscation restore → ROSAL (standard-library mapping) → then read in jadx
 │                      └ high-speed retrieval → DexKit / dexllm (string reverse lookup of classes/methods)
 │                      └ legacy chain → dex2jar + JD-GUI (mostly obsolete)
 ├─ smali layer ─────── smali/baksmali (google line 3.0.6); fastest for single-method patches
 ├─ native layer ────── Ghidra / IDA (lib/arm64-v8a/*.so)
 │                      ├ entry/triage automation → SnikrFlow (angr symbolic execution, see dedicated section)
 │                      └ quick string scan → strings / rabin2 -zz
 ├─ Resources/misc ──── 010 Editor (template-parse dex/protobuf/private formats) / imHex
 └─ One-shot checkup ── MobSF / Quark (malicious-behavior scoring)
```

**Repackaging chain**: `apktool d` -> edit smali/resources -> `apktool b` -> zipalign -> sign with **Uber Apk Signer** (v2+ mandatory for high targetSdk).

### apktool
- 3.0.2->3.0.3 highlights: faster `resources.arsc`/binary-XML decoding (rewritten ResStringPool/ResPackage lookup), `android:* not found` fix, split-APK-as-library support, build-artifact naming switched to underscores.
- 3.x is the big version (aapt2 everywhere); 2.x-era scripts beware parameter compatibility.

### dex2jar
- The `d2j-dex2jar.sh` launcher fails in some environments with `Could not find or load main class com.googlecode.dex2jar.tools.Dex2jarCmd` (issue #170, open); typical cause is classpath expansion/path problems. Workaround:
  ```bash
  java -cp "dex-tools-v2.4/lib/*" com.googlecode.dex2jar.tools.Dex2jarCmd app.apk
  ```
- Positioning: superseded by jadx's direct decompilation; use only when you need the jar-ecosystem tools (procyon/decompiler comparison, bytecode instrumentation).

### smali/baksmali
- Google-maintained line; apktool 3.x bundles the same-line core. Single-method patch: `baksmali d classes.dex` -> edit -> `smali a` re-assemble - the fastest path.

## IV. ROSAL Deobfuscation Deep Dive (Deterministic Standard-Library Mapping)

**ROSAL (Reverse Obfuscated Standard Android Libraries)**, PyPI `pip install rosal` (**very new project - depend on it carefully, but the idea is spot-on**).

### Anchor Mechanism
- **Principle**: R8/ProGuard can rename every class/method/field the App owns, but **cannot rename references to platform APIs (`android/*`, `java/*`, `javax/*`)** - those symbols must be resolved by the OS at runtime, out of the obfuscator's reach.
- **Anchors**: every platform-API reference appearing in a method body = one "anchor". **Two methods with identical anchor sets are (with very high confidence) the same method**.
- **Determinism**: fully exact structural matching - **no heuristics, no similarity scoring, no AI**.
- **Library version alignment**: no fixed reference set. It reads the APK's `META-INF/*.version` markers to know exactly which group/artifact/version were bundled (androidx.activity 1.8.1 etc.), then fetches the corresponding `.dex` from the same-origin Maven repositories of the original build for comparison - so the mapping stays accurate across library-version drift.
- **Boundary**: restores **standard-library** class names only (RecyclerView/LiveData/Fragment/CompatActivity...), **does not map the App's own business classes**. In obfuscated apps androidx is usually obfuscated along with everything else; ROSAL restores that part of the "background noise" so business classes stand out in jadx.

### Usage
```bash
pip install rosal
# Dependencies: Androguard/loguru/tqdm auto-installed; needs Java + Android SDK (D8, platform-tools)
# The SDK must live at ~/Android/Sdk (the README explicitly warns it breaks otherwise)
rosal --apk target.apk                 # five phases: fetch→extract→catalog→matching→mapping
rosal --apk target.apk --work-dir ./w  # switch the work directory (default ~/rosal)
```

### Outputs and How to Wire Them In
- `matches.json`: class-level mapping + each method's `library_name <-> target_name` + descriptors (example: `androidx/activity/a <-> androidx/activity/Api34Impl`).
- **`matches.tiny`: Tiny v2 mapping format** (`obf -> named`), feedable directly to Enigma/Recaf-style remappers or your own scripts to batch-rename a jadx-exported project - **this is the key exit point for plugging it into an existing jadx workflow**.
- Practical advice: when app code is heavily obfuscated and androidx has all become `a.b.c`, run ROSAL first for the tiny mapping and then read the code, saving tons of "guess the superclass" time; business-class restoration still relies on jadx-gui manual renames + DexKit retrieval.

## V. SnikrFlow: angr Symbolic-Execution Triage Deep Dive (so Static-Analysis Automation)

> No public project anywhere: the command chain below is user material - verify the tool exists and its real parameters before use; the underlying angr/claripy are themselves reliable (claripy has been rewritten in Rust and merged into the angr package).

**Capability**: angr+Claripy automated triage, command chain:
```
snikrflow audit libfoo.so   # auto-discover all functions/JNI entries/security-sensitive sinks
snikrflow sinks             # list identified sensitive sinks
snikrflow reach --source <src> --sink <sink>   # symbolic reachability check
snikrflow solve             # symbolic-execution solving (construct inputs that reach the sink)
snikrflow dataflow          # taint-reachability check
```
**Positioning**: for symbol-less so files, quickly answers "which JNI entry can reach which sensitive call (e.g. execve/system properties/decryption functions)", handing manual cross-referencing work to symbolic execution.

### Replacement/Equivalent Route (native angr, write it yourself in Python)
```python
import angr, claripy
p = angr.Project("libfoo.so", auto_load_libs=False)
cfg = p.analyses.CFGFast(resolve_indirect_jumps=True)   # recover CFG + function list
# JNI entries: JNI_OnLoad exported functions + cfg.functions filtered for RegisterNatives call sites
# Symbolic reachability: explore toward the target address from the entry state
state = p.factory.call_state(entry_addr, claripy.BVS("args", 64*4))
sm = p.factory.simgr(state)
sm.explore(find=target_sink_addr)     # found means a reaching path exists; sat can solve for inputs
if sm.found:
    print(sm.found[0].solver.eval(claripy.BVS("args", 64*4), cast_to=bytes))
```
- Ready-made options for automated native-layer sink discovery: Ghidra scripts walking xrefs for `system/execve/open/dlopen`; or radare2 `/c` + `axt`. For symbolic-execution input solving use angr management (GUI) or the script above.

## VI. DexKit / dexllm: High-Speed dex Retrieval (Mainstay of Obfuscation Combat)

### DexKit
- C++ dex parsing + pybind11/Java bindings, **purpose-built for retrieval when "classes/methods/fields are obfuscated and names change every release"**; batch-optimized string queries that don't slow down linearly as query groups grow.
- Typical usage (an Xposed module or standalone JVM tool, Maven `org.luckypray:dexkit`):
  ```java
  DexKit bridge = DexKitBridge.create(apkPath);
  // Reverse-lookup classes by signature strings: version-independent location of obfuscated classes
  Set<DexKitDescriptor> hits = bridge.findClasses(
      batchFindClassesUsingStrings(
          BatchFindArgsUsingStrings.builder()
              .addQuery(GroupQuery.create("pay-manager",
                  Query.create(containsString(" getTotalFee"))
                      .add(containsString(" alipay"))
                      .add(containsString(" wechat")))).build())).get();
  // Method level: pin down obfuscated methods by "which APIs/strings they call"
  ```
- In practice: with a new APK release you needn't re-read all the code - use signature strings located in the old version (URL fragments, log TAGs, annotation values) to fish the class names back out; pair with frida using `DexKit(apk)` + runtime `classLoader` dual mode.

### dexllm (dex-analyzer-for-llm)
- **Positioning**: an APK/DEX static analyzer built for LLMs = **DexKit Core (pybind11) + a fully ported DAD-aligned C++ decompiler + MCP stdio server + FastAPI/SSE backend** (direct Claude tool-use connection); plus `dexllm-web`, a browser WASM demo (new project).
- **Measured figures (per README)**: APK load ~28ms (about 100x faster than androguard); ~520MB memory for a 39k-class app; C++ releases the GIL, genuinely multi-threaded decompilation in one process; decompilation quality aligned with androguard DAD.
- **Capabilities particularly useful for RE**:
  - **Unpacking workflow**: `DexKit([dump, apk])` multi-source ordered priority (decrypted dex first in, first to win - mirrors ART behavior); `add_dumped_dexes()` = the re-analyze-after-dump verb; `lenient=True` loads half-decrypted dumps too.
  - `extract_iocs()`: static URL/IP/domain/email/onion extraction, defang-aware (`hxxp://`/`[.]`), each IOC carries referencing methods.
  - `find_component_subclasses()`: full inheritance-chain enumeration for the nine manifest component types (including intermediate layers undeclared by the dex, like `MyTile->TileService->Service`).
  - `detect_permissive_tls()`: proof-grade permissive-TLS detection (`permissive` = proven to accept any hostname/certificate chain).
  - `permission_api_callers()`: signature-level permission-API correlation against AOSP metalava `@RequiresPermission`.
  - L1-L7 retrieval (names/strings/annotations/superclasses/API call sites/xrefs).
- Usage: treat it as "Claude's dex eyes" - with MCP attached, let the agent query classes, decompile, and follow xrefs itself; humans only judge.

## VII. Androguard Scripting Essentials

- The most complete dex/APK parsing library in the Python ecosystem (reox-maintained line; 4.x is the mip/dala-family rewrite).
- **The scripting three basics**:
  ```python
  from androguard.misc import AnalyzeAPK
  a, d, dx = AnalyzeAPK("app.apk")          # APK object + dex list + analysis context
  a.get_permissions(); a.get_activities()   # manifest surface
  for m in dx.find_methods(methodname="sign"):  # method retrieval
      print(m.get_method().get_class_name(), m.get_method().name)
  # CFG: method.get_xref_to()/get_xref_from() builds the inter-procedural reference graph
  ```
- **Two-version diff**: androguard ships androdiff/androlyze workflows (`dx2 = ...; from androguard.decompiler.decompiler import ...`; in practice use `androguard.misc.AnalyzeDex` and diff the class/method sets of the two versions).
- Note: pure Python, slow on big APKs (>50k classes) - for speed-sensitive work use dexllm (~100x faster) or DexKit.

## VIII. Quark Engine (Malicious-Behavior Scoring)

- **A behavior-detection model, not signature matching**: scores samples with "API combination + call-sequence relation" rules (the quark-rules repo updates continuously); insensitive to obfuscation (hits as long as the API calls are still there).
- BlackHat Asia 2021/2024 Arsenal project; **Quark Script** (BH Asia 2024) supports writing vuln-hunting scripts on top of the scoring (locate suspicious chains in a black-box app by rules, then verify dynamically).
- Usage: `quark -a app.apk -s` (report); for malicious-family clustering use `quark -a x.apk --classification`. As a "first-glance risk profile" of an unfamiliar APK it is finer-grained than MobSF's maliciousness dimension.

## IX. Packer Identification (Know the Shell Before You Act - APKiD Merged In)

### Signature Quick Reference (so names / file traits / strings)

| Packer | Typical so / file traits | Notes |
|---|---|---|
| 360 Jiagu (360 Reinforce) | `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so` | Free basic hardening still operating |
| Tencent Legu | `libshell*.so`, `libtup.so`, `libexec*.so`, `mix*.dex`, `libBugly` | Tencent Cloud API integration |
| Bangcle | `libsecexe.so`, `libsecmain.so`, `libDexHelper.so` | Mostly B2B |
| Ijiami | `libexec.so`, `ijiami.dat`, `libRSProtect.so` | Mostly B2B |
| NAGA | `libchaosvmp.so`, `libddog.so`, `libfdog.so` | Old-school VMP |
| Baidu | `libbaiduprotect.so` | Still seen in Baidu-family apps |
| NetEase Yidun | `libnesec.so` | Representative of "anti-AI adversarial hardening" |
| Tongfudun | `libegis*.so` | Faded from the mainstream |
| Shuzi Lianmeng (Digital Alliance)/Kiwi etc. | Their own signature so files | Community round-up posts exist |

### APKiD
- **Automatically identifies packer/protector/obfuscator/compiler**: one command covers most of the manual four basics above:
  ```bash
  pip install apkid
  apkid app.apk            # output: packer → bangcle / compiler → r8 ... etc.
  apkid path/              # batch-scan a directory
  ```
- Identification surface: packers (Bangcle/Ijiami/360/Tencent and dozens more), obfuscators (ProGuard/dexguard/obfuscapk...), compilers (javac/r8/d8/kotlinc), native (NDK version clues, OLLVM signatures).
- Community-continued maintenance (originally the rednaga line); rule base updating.
- **The four manual basics for identification (manual fallback)**: (1) `unzip -l` against the so table + odd dex files in assets; (2) manifest `android:name` pointing to the packer's stub Application; (3) `strings lib*.so | grep -iE "jiagu|secneo|ijiami|nesec|tup"`; (4) APKiD/MobSF auto-reporting. **Suggested order: APKiD one-shot first, manual four basics on a miss.**

### Action Mapping After Identifying the Packer
- Whole-DEX packer -> FRIDA-DEXDump / BlackDex (see `03-unpacking`).
- Extraction packer -> the FART family + FartFixer.
- VMP/Java2C -> even after dumping there is no complete logic; switch to "hook the call site + native analysis".
- **Trend (2024-2026)**: vendors moving to VMP+instruction-level+anti-LLM; static focus shifting to native/obfuscation combat (deterministic tools like ROSAL/DexKit are exactly the response).

## X. jadx CLI Common Parameters and Tips

```bash
jadx -d out app.apk                     # full export (resources included)
jadx --no-res -d out app.apk            # skip resources, big speedup on large packages
jadx --decompilation-mode simple app.apk  # simple mode (fast)
jadx --decompilation-mode fallback app.apk # fallback mode (most stable)
jadx -j 8 --threads-count 8 app.apk     # multi-threading
# Direct main-class invocation inside scripts (no fat jar in the distribution, -cp mandatory — see section I)
java -cp "jadx-1.5.6/lib/*" jadx.cli.JadxCLI --no-res -d out app.apk
# Batch processing: full export to disk, then rg for interfaces globally
rg -n "sgmain|getSign|x-sign" out/sources/
```
- Incompletely decompiled methods: jadx marks `/* Code decompiled incorrectly */` -> switch to the smali view, or feed CFR/Vineflower/Krakatau for an engine-swap cross-check.
- StringFog-style string encryption: search `decrypt(` call sites and script a batch restoration.
- **For obfuscated packages run ROSAL first, then read** (androidx noise elimination - see section IV).

## XI. Native-Layer Analysis Checklist (Common to Ghidra/IDA)

1. Start with `strings` + export-table scans: `JNI_OnLoad`, `RegisterNatives`, risk-control SDK names (`msaoaidsec`/`sscronet`/`sgmain`).
2. Follow `JNI_OnLoad` and `RegisterNatives` to get the dynamically registered Java<->native mapping (the most critical static-analysis step; frida printing is faster).
3. Stripped so: FLIRT (IDA)/Function ID (Ghidra) to recognize library functions first; JEB has Codematch (5.38) library matching.
4. OLLVM: IDA d-810/microcode deflattening; JEB unflattener/MBA resolvers; Ghidra community scripts or trace assistance.
5. Crypto-algorithm identification: constant signatures (AES S-box, SM4 S-box, CRC tables) locate the real implementation.
6. Version diffing: bindiff / Diaphora / Ghidra Version Tracking.
7. **Too many entries? Triage first**: the SnikrFlow approach (if usable) or angr scripts for reachability filtering (see section V), concentrating manual effort on entries that can reach sensitive sinks.

## XII. Practical Selection Advice

- **First glance**: APKiD (identify packer/obfuscator) -> apktool + jadx-gui (the manifest/entry/Application triple).
- **Java logic**: jadx as primary; on heavy obfuscation run ROSAL first for the tiny mapping; on explosions swap to CFR/Vineflower/Krakatau; to change a single spot, baksmali and patch directly.
- **Tracking obfuscated-version updates**: DexKit signature-string reverse lookup (version-independent location); hook dexllm to MCP and let the agent chase it itself.
- **so analysis**: IDA Pro 9.x / Ghidra 12; many entries -> symbolic-reachability filtering first; quick lightweight checks outside the budget via strings/rabin2.
- **Batch automation**: jadx CLI (mind direct `-cp` invocation) + rg; JEB scripting/MCP pipelines; androguard for Python scripts; Quark for behavior reports.
- **Supporting cast**: 010 Editor for private formats; IDA/Ghidra exporting frida skeletons - static location -> dynamic verification in one line.

## Install Quick Reference

> For the Python family, install into this repo's tools-env virtualenv (sandbox pitfall: with a read-only HOME, uv's default cache path breaks):
> `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p re/tools-env/.venv/bin/python <package>`
> Every `uv pip install` below means this method; the brew family is plain `brew install`. Note: keystone is incompatible with py3.13 - failing to install it in tools-env is normal.

| Tool | Install |
|---|---|
| jadx / jadx-gui | `brew install jadx` |
| apktool | `brew install apktool` |
| Ghidra | `brew install --cask ghidra` |
| radare2 / cutter | `brew install radare2` / `brew install --cask cutter` |
| ROSAL | `uv pip install rosal` (needs Java + Android SDK at ~/Android/Sdk) |
| Androguard | `uv pip install androguard` |
| Quark Engine | `uv pip install quark-engine` |
| DexKit | github.com/LuckyPray/DexKit (Maven `org.luckypray:dexkit`) |
| dexllm | github.com/mobile-threat-hunter/dex-analyzer-for-llm |
| ddc | github.com/ejfkdev/ddc |
| CFR | github.com/leibnitz27/CFR |
| Vineflower | github.com/Vineflower/vineflower |
| Procyon | github.com/mstrobel/procyon |
| Krakatau | github.com/Storyyeller/Krakatau |
| dex2jar / enjarify | github.com/pxb1988/dex2jar / github.com/Storyyeller/enjarify |
| smali/baksmali | github.com/google/smali |
| Uber Apk Signer | github.com/patrickfav/uber-apk-signer |
| Bytecode Viewer | github.com/Konloch/bytecode-viewer |
| MobSF | github.com/MobSF/Mobile-Security-Framework-MobSF |
| GDA | Official site gda.wiki |
| 010 Editor / imHex | Official site 010editor.com (commercial) / `brew install --cask imhex` |
| JEB | Official site jeb.com (commercial) |
| IDA Pro / IDA Free | hex-rays.com |
| JNIAnalyzer | github.com/Areizen/JNIAnalyzer (Ghidra script) |
| apkanalyzer / aapt2 | Android SDK cmdline-tools |
| ASC / dae / ReArk / Ryuumonbuchi / AXMlEditor | unverified |
