# Recon and Specials Tooling (The First Minute with an Unfamiliar APK)

> Positioning: no full decompilation - within minutes, answer four questions - **what packer/obfuscator is on it, what keys/URLs leaked, who compiled it, what's hidden in the resources**.
> This recon-and-specials tool chain complements `static-analysis-tools.md`.

## 0. The First-Minute Workflow (Overview)

```
Got an APK
 1. APKiD app.apk        → one-shot packer/obfuscator/compiler profile (identifying the packer decides the route)
 2. apkleaks app.apk     → leaked keys/hidden URLs/intranet addresses
 3. DIE lib*.so          → so architecture/compiler/packer (native-layer profile)
 4. DroidLysis --verbose → property-extraction report (permissions/components/suspicious-feature flags)
 5. Dig deeper as needed: 010/imHex for private formats; LIEF/pyelftools for scripted ELF parsing
 6. Stealth environment (no PC): UltraSina/androidReverse does all of it on the phone
```

## I. APKiD - Packer/Obfuscator/Compiler Identification

- Identification surface: packers (Bangcle/Ijiami/360/Tencent and dozens more), protectors, obfuscators (ProGuard/dexguard etc.), compilers (javac/r8/d8/kotlinc), anti-vm/anti-disassembly traces.
- **First-minute usage**:
  ```bash
  pip install apkid
  apkid app.apk          # single file
  apkid samples/         # batch-scan a directory
  apkid app.apk -j       # JSON output for scripts
  ```
- How to read it: a `packer ->` hit means take the unpacking route (see `03-unpacking`); `obfuscator -> dexguard` means prepare for ROSAL/DexKit combat; on a miss fall back to the manual four basics (so names/Stub Application/strings scanning).

## II. apkleaks - Key and Hidden-URL Mining

- Status: usable, not actively iterated.
- Principle: internally calls jadx to decompile the full source, then runs a regex rule base (URI/API key/IP/Email/secrets) to find hardcoded leaks.
- **First-minute usage**:
  ```bash
  pip install apkleaks
  apkleaks -f app.apk                       # report to default output
  apkleaks -f app.apk -o report.txt         # specify output
  apkleaks -f app.apk --pattern "AWS_KEY,firebase"   # run only the given rule groups
  ```
- Practical points: the **hidden backend URLs/debug endpoints/S3 buckets** in the output are step one of the black-box-testing asset surface; key hits must be validated (most are third-party-SDK public keys - false positives are common). For deep secrets scanning pair with TruffleHog (see section VIII) for entropy + dictionary double confirmation.

## III. DIE (Detect It Easy) - so/Binary Profiling

- Multi-engine (signatures + entropy + heuristics) identification of PE/ELF/Mach-O **compilers, linkers, packers, protectors**.
- **First-minute usage**:
  ```bash
  # GUI: drag lib/arm64-v8a/*.so into die.app
  diec libmsaoaidsec.so        # CLI single file
  diec -d -e libfoo.so         # deep scan + entropy analysis
  ```
- How to read it for Android: `clang/LLVM` version clues -> NDK generation; `UPX` -> unpack first, then look; high-entropy sections -> encrypted data/packer; complements APKiD's native dimension (APKiD profiles the whole APK, DIE profiles a single so).

## IV. DroidLysis - Property Extraction / Pre-Analysis

- No official release; run via `pip install` or from source.
- Positioning: an **Android app property extractor** - unpacking plus a battery of "feature probes" (root detection/anti-emulator/encryption signatures/suspicious permission combos), emitting a diffable property report that narrows scope for deep analysis.
- **First-minute usage**:
  ```bash
  python3 droidlysis.py -s samples/ --verbose     # batch a directory; verbose prints findings
  python3 droidlysis.py app.apk -o outdir         # output report + unpacked artifacts
  ```
- Highlights: properties with the `suspicious.` prefix in the report (e.g. `suspicious.isdebuggerdetected`) hand you a ready-made "combat-points list"; on batches of dozens of samples it beats manual apktool.

## V. UltraSina/androidReverse - A Pure On-Android-Device RE Suite

- Positioning: **an RE suite that runs entirely on an Android device - no PC, no ADB, no desktop tools**; from APK unpacking to native analysis, editing, and rebuild+sign, all on-device.
- Capability list:
  - **Native analysis**: embedded Radare2 engine (JNI bindings), interactive CFG canvas, call graph/xrefs, Pseudo-C decompilation, function renaming/annotation.
  - **8 Java decompiler engines switchable per class**: CFR / Procyon / JD-Core / Krakatau / Vineflower / Jadx / Jadx Fallback / Jadx IR.
  - **APK/resource handling**: universal unpacking of apk/xapk/split apks; anti-obfuscation AXML decoding (a reflection-based AXMLPrinter that beats modern manifest obfuscation); deep ARSC parsing; export/replace individual files.
  - **Editing and rebuild**: in-place AXML/manifest/smali/resource editing + APK rebuild-and-sign (the author also has DexAndJar-Converter for dex/jar/smali conversion).
  - **Built-in MCP server**: an MCP client (AI agent) can directly edit resources/AXML/manifest/smali; compile/rebuild stays manually triggered.
  - Supports Flutter and Unity il2cpp.
- **First-minute usage**: install on a phone/tablet with Termux -> open the target (an apk in storage or an installed app) -> Summary for manifest/permissions/components -> pick classes and switch across the 8 decompiling engines -> the native page for so files. Fits: travel/on-site without a computer, closed loops inside cloud phones, and "edit on-device and install right away" scenarios.

## VI. hookerView -> Closest Match: CreditTone/hooker

> No standalone project named `hookerview` exists anywhere; the closest is **CreditTone/hooker**: a **Frida-based Android RE toolkit** with a friendly CLI + a general hook script collection, supporting injection of a lightweight webserver into the target app's process (port 8080 by default, exposing built-in debug endpoints), auto-deploying patch.jar->dex, updated weekly-ish (`python3 hooker.py upgrade` to sync). If something else was meant, verify before use.

- CreditTone/hooker first-minute usage:
  ```bash
  python3 hooker.py            # list device processes, pick one to inject
  # After injection: hooker auto-attaches and unfolds common scripts (SSL/crypto/packer dump)
  # webserver: http://localhost:8080 inside the target app exposes debug endpoints
  ```

## VII. LIEF / pyelftools - Scripted so Parsing

| Tool | Positioning |
|---|---|
| LIEF | Cross-format (ELF/PE/Mach-O/DEX etc.) parse + **modify** library, C++ core with Python bindings |
| pyelftools | Pure-Python read-only ELF parsing, lightweight and dependency-free |

- **First-minute usage (LIEF)**:
  ```python
  import lief
  b = lief.parse("libfoo.so")
  print(b.header.machine_type, b.entrypoint)
  for s in b.sections: print(s.name, s.size, hex(s.virtual_address))
  print([f.name for f in b.exported_functions])        # export table = JNI entry candidates
  # Modification scenario (anti-detection): alter exported symbols/strings/add sections
  b.patch_hook(...)  # e.g. alter the gum-js-loop thread-name signature to beat frida detection
  b.write("libfoo_patched.so")
  ```
- **pyelftools** fits batch read-only analysis (dump .rodata, walk relocation tables to find GOT hook points); to **rewrite** an so (wipe frida signatures, patch ELF) use LIEF.
- Common uses: static detection-evasion (LIEF wiping so-layer frida signatures); parsing hardened so files' custom sections (packers often hide the encrypted dex in their own section or a trailing overlay - script the offset extraction).

## VIII. TruffleHog - Deep Secrets Scanning (General-Purpose, Pairs with apkleaks)

- Positioning: general-purpose key scanning (800+ detector validators, capable of **online key-validity verification**, not just regex hits).
- Android scenario: scan the exported decompiled source tree; or run directly on the unpacked directory:
  ```bash
  trufflehog filesystem --no-verification out/sources/   # report only, no verification (when outbound is a no-go)
  trufflehog filesystem out/                             # default verifies (hits external APIs — mind authorization)
  ```
- Division of labor with apkleaks: apkleaks is fast, focused, APK-oriented regex (URLs/hidden endpoints); TruffleHog is deep, with key-validity verification (AWS/GCP/SLACK...). In SRC scenarios, use apkleaks first to find the asset surface, then on suspected cloud keys bring in TruffleHog to verify.

## IX. 010 Editor / imHex - Private Formats and Binary Templates

| Tool | Notes |
|---|---|
| 010 Editor | Commercial ($149.95, home/academic $59.95); Binary Templates parse 300+ formats; Tree-sitter syntax for 45+; built-in x86/ARM/MIPS disassembly; 50GB files |
| imHex | Free open-source alternative, Pattern Language templates, community template repository |

- **First-minute usage**: drag files whose structure resists parsing (custom encrypted containers, dex variants, protobuf wire format, a packer's private dat) into 010 -> find an existing template (the official repo has dex/elf/dex-variant templates) or write one:
  ```c
  // 010 template example: a packer's private header
  typedef struct {
      uint32 magic;      // 0xDEX or a custom magic
      uint32 version;
      uint32 dataOffset; // data offset; afterwards parse segment by segment with while(!FEof())
  } PACKER_HEADER;
  ```
- Practical technique: locate by magic (`dex\n035` / `PK` / custom) -> structure the offset/size fields with a template -> edit fields right in the hex view (clear an encryption flag bit / change a length to fool the parser). The same idea applies to imHex in free scenarios (Pattern Language syntax differs slightly).

## X. Selection Quick Reference

| Question | Tool |
|---|---|
| Does this APK have a packer/which obfuscator? | APKiD (first choice) -> manual four basics |
| Any hardcoded keys/hidden URLs? | apkleaks -> TruffleHog to verify |
| Who compiled this so / is it packed? | DIE (diec) |
| Fast property reports for sample batches? | DroidLysis |
| Only a phone at hand? | UltraSina/androidReverse |
| Need to wipe frida signatures / patch an so? | LIEF (rewrite), pyelftools (read-only analysis) |
| Can't read a private binary format? | 010 Editor (commercial, many templates), imHex (free) |
| Need an AI agent in on-device editing? | androidReverse built-in MCP / dexllm MCP (see `static-analysis-tools.md`) |

## Install Quick Reference

> For the Python family, install into this repo's tools-env virtualenv (sandbox pitfall: with a read-only HOME, uv's default cache path breaks):
> `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p re/tools-env/.venv/bin/python <package>`
> Every `uv pip install` below means this method; the brew family is plain `brew install`.

| Tool | Install |
|---|---|
| APKiD | `uv pip install apkid` |
| apkleaks | `uv pip install apkleaks` |
| TruffleHog | `brew install trufflehog` |
| DIE (Detect It Easy) | github.com/horsicq/Detect-It-Easy |
| DroidLysis | github.com/cryptax/droidlysis (no official release, run from source) |
| UltraSina/androidReverse | github.com/UltraSina/androidReverse (install the APK in Termux) |
| hooker (closest entity to hookerView) | github.com/CreditTone/hooker |
| LIEF | `uv pip install lief` |
| pyelftools | `uv pip install pyelftools` |
| 010 Editor | Official site 010editor.com (commercial) |
| imHex | `brew install --cask imhex` |
| apiaxess | unverified |
