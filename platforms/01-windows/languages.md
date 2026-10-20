# Part 7: Languages — Reverse-Engineering Traits and Toolchains per Language

> Corresponding tree node: Windows Security [1000012] → Part 7: Languages [1000546] (32 child nodes).
> Main line: **given an unfamiliar PE/script, first identify the language, then pick the decompiler, then locate the key code by that language's runtime traits**.

## 1. Overview: Language Identification → Tool Selection (Fundamentals/Decompilation [1000547])

The first step of reversing a Windows program is not opening IDA but answering "what was it written in". Four identification elements:

```
The four-quadrant identification matrix (restored in text)
┌───────────────┬────────────────────────────────┐
│ ① Packer/language detection │ PEiD / DIE (Detect It Easy) signature libraries │
│ ② Import table │ runtime DLLs are the hardest fingerprints:    │
│               │  MSVBVM60.dll → VB6             │
│               │  rtl**.bpl/Borlndmm → Delphi     │
│               │  mscoree.dll(_CorExeMain)→ .NET │
│ ③ Entry-code shape │ entry stub, string-initialization patterns │
│ ④ Strings/resources │ error texts, form resources, section names (.text/.rsrc) │
└───────────────┴────────────────────────────────┘
```

The two layers of decompilation (Decompilation [1001255]):
- **Machine code → assembly/pseudo-C**: Hex-Rays (IDA), Ghidra, Binary Ninja, RetDec. Affected by compiler optimization, inlining, and vtables; you only get "approximate source".
- **Intermediate code/bytecode → source level**: languages with their own VM (P-Code, IL, pyc, a3x) can usually be restored nearly completely — this is the core of the Languages part: for any language with a VM, hit the VM layer first instead of grinding machine code.

The generic decision tree:

```
Unknown PE
 ├─ Packed (high entropy/entry in the last section) → unpack first (see Unpacking/packing techniques)
 ├─ Imports mscoree/_CorExeMain → the .NET flow (§2.4)
 ├─ Imports MSVBVM50/60 → the VB flow (§2.2, first decide P-Code/Native)
 ├─ Imports rtl*/BORLAND/emu → the Delphi flow (§2.1)
 ├─ Section names UPX0/ or resources hiding a3x/pyc/asar → unpack the script layer (§2.5-2.7)
 └─ otherwise → VC/MinGW/Gcc follow the ordinary C/C++ flow (the 32/64-bit reversing chapters)
```

## 2. Deep Dives on Key Languages

### 2.1 Delphi [1000569] (Basics/code location/Delphi reversing/Delphi cracking)

**Identification traits**
- Import table: `rtl*.bpl` (absent when statically compiled, replaced by inlined RTL code), `BORLANDMM`, sysutils unit error strings ("Invalid pointer operation", `EDivByZero` exception names).
- Section names: Delphi defaults to `CODE/DATA/BSS/.idata/.tls/.rdata/.reloc/.rsrc`; the uppercase CODE is a strong fingerprint.
- Entry: `TApplication.Initialize` → `Application.CreateForm` → `Application.Run`; the main sequence is highly templated, and event handlers all hang off the form class.
- Strings: Delphi's `string` is a **length-prefixed + reference-counted** structure (not zero-terminated); scanning raw ASCII with static tools misaligns; after Unicode (D2009+) it is length-prefixed UTF-16.

**Toolchain**
- **DeDe** (classic): parses Delphi PEs, restores the form-event table (addresses of OnClick/OnCreate), DFM form resources, published properties, directly giving the "button → handler address" mapping. Old versions support up to around Delphi 7.
- **IDR (Interactive Delphi Reconstructor)**: a Delphi-specific rebuilder on IDA; recognizes RTTI to restore class names/method names/event handlers, turning `sub_4012A0` back into `TForm1_Button1Click`. Best support for Delphi 5~2007; weak for newer Delphi (FMX).
- **DCU decompilation**: Delphi compiled units `.dcu` can be converted back to readable assembly/interfaces with DCU32INT (kb) and similar tools; useful when reversing commercial components (same for the tree node "static libraries").
- DFM resources: use Resource Hacker/IDR to extract the DFM text from RCDATA directly; look up control IDs → search the code for `Ctrl.Handle`/control-variable cross-references.

**Practical essentials (code location [1000571])**
1. Run IDR/DeDe first for the event table; 80% of registration checks sit in `btnRegClick`.
2. Delphi button messages dispatch through `TControl.WndProc`, with no dense IAT calls; to break on `MessageBox` you must break `MessageDlg` inside `Controls.TControl` (VCL self-drawn), not user32.MessageBox.
3. Registration codes mostly use `StrToInt/IntToStr/Length`; string comparisons use `@UStrEqual` (D2009+)/`@LStrCmp`; finding cross-references of these RTL helpers in IDA is faster than finding APIs.
4. Knowledge-base supplement: collected reversing-engineering notes [1000573] (the Delphi reversing series).

**Representative posts**: "Delphi Reverse Engineering", "Making Keygens with Delphi", "A Delphi Keygen Template", "Adding Feature Buttons to Delphi Programs ①②".

### 2.2 Visual Basic [1000588]

VB5/VB6 programs come in two compiled forms whose reverse routes differ completely; the first step must be telling them apart:

| Discriminator | P-Code | Native |
|---|---|---|
| Near the entry | `MSVBVM60!BASICrtIn` followed by the **opcode interpretation loop** (`rtc`-prefixed functions interpreted) | direct machine code calling `__vba*` helpers like `__vbaStrCmp` |
| Import table | little of MSVBVM60.dll + masses of `rtc*` runtime functions | MSVBVM60.dll + `__vba*` everywhere |
| Traits | after the entry `push ebp; ... call MSVBVM60.<rtc entry>` plus opcode-table dispatch (a giant switch jump table) | common `push xxx; call __vbaR8Str` float conversions |

- **P-Code**: VB's built-in bytecode VM. Reverse it with **VB Decompiler** (commercial, decompiles P-Code straight back to approximate VB source) or by hand-parsing the opcode table; the knowledge base specifically collected cyclotron's VB P-code series [1000591] (P-Code instructions analyzed one by one, a classic series).
- **Native**: reverse as ordinary machine code, but all string/array operations go through the `__vba*` runtime (`__vbaStrCopy/__vbaI4Str/__vbaFreeStr`); understanding the helper semantics recovers the high-level logic; the representative series is MengLong's VB6 Reverse Engineering [1000592].
- **SmartCheck [1000595]**: Numega's VB-specific runtime tracer, directly printing `Form1.Command1_Click`-level events and string comparisons — the first-choice dynamic tool for VB (especially Native) samples, halving the time of manual OD tracing.
- **VB3/4 [1000598]**: older versions; VB3 is purely interpreted (VBXX.DLL) and dedicated decompilers (VB Discompiler) can restore source directly.
- Common pitfalls: VB strings are BSTR (UNICODE, length-prefixed + \0); when patching registration-code comparisons in memory, note that `__vbaStrCmp`'s argument is a BSTR pointer; in OD, breaking on `rtcMsgBox` corresponds to VB's MsgBox.

**Representative posts**: the P-code series — "An Outline of Cracking VB P-CODE Programs", "P-code Visual Basic Miscellany", "A Beginner's Introduction to P-CODE Reverse Engineering of VB Programs", "How to Make a P-Code Debugger for VB", "VB P-code — The Art of the Virtual Machine", "VB P-code — The Debugger's Revolution", "VB P-code — The Mystery of Pseudocode", "Some Notes on VB P-CODE"; Native/tools — "VB6 Decompilation in Detail", "A Comparison of Several VB6 Decompilers", "VB Decompiler Pro 5.0 Keygen with source code".

### 2.3 EPL (Yi Yu Yan / Easy Programming Language) [1000613] (Reversing knowledge/case analysis)

A low-barrier Chinese development language, heavily used domestically in **game cheats, credential-stealing trojans, and captcha/assistant tools**; a mandatory language for Windows malware-sample analysis.

**The three compiled forms**
1. **Independent compilation**: ships `krnln.fnr` (the core runtime) and interprets; the fnr/e library files can be found beside the exe or in its resources; the entry initializes via `eInit`.
2. **Static compilation** (EPL 4.x+ / 5.x): compiled to pure machine code, no longer interpreted by krnln.fnr, but calling masses of statically linked core-library functions (string/window-operation patterns are fixed, fingerprints obvious). The community's analysis of "EPL 5.x statically compiled" programs is a classic subject (search "EPL 5.8 static compilation"; "A Brief Talk on EPL Compilation Modes (Distilled, Seven Errata)" clarifies that the first two forms are actually — **independent compilation**: the program + EPL support libraries packaged as a single exe, with the support libraries attached to the file tail as appended data (Overlay), PEID showing `Microsoft Visual C++ 6.0 [Overlay]`; on every launch the appended data is released to a temp directory (e.g., `%TEMP%\E_4`) and the krnln.fnr inside is loaded, failing which it errors out. **Non-independent compilation**: the exe is small, and at startup it first looks for krnln.fnr in the same directory; failing that, it consults the EPL install path in the registry; [Overlay] is not a protection mode — when packing you must tick "keep appended data", and manual unpacking that strips only the main body without carrying the support libraries naturally won't run — pitfall number one in EPL sample analysis).
3. **Compiled into** EPL modules/dll: the export table carries Chinese function names (possibly stripped under static compilation).

**Identification traits**
- Strings: masses of **UTF-16LE/GBK Chinese prompts** in the program, often directly containing "EPL" runtime error texts;
- Statically compiled samples have uniform section/entry patterns: `eInit`/`ECode` structures, core-library code like `文本_取空白` copied wholesale, so same-compiler-version artifacts look highly similar under diff tools;
- Resources/version info often leave "EPL" compiler traces, or `krnln.fne/fnr` filename remnants.

**Tools and practice**
- The veteran tool **E-Code Explorer (the EPL decompiler)**: targets independent compilation, restoring subroutine names/arguments/local variables, and can dump forms and data tables; limited support for new static compilation.
- Statically compiled samples: IDA + a hand-rolled fingerprint library (turn frequently used krnln function signatures into signatures, e.g., the `MessageBoxA` wrapper, text-operation helpers); once identified, read the pseudo-C with EPL semantics.
- Dynamic: break directly on WinAPI in OD/x64dbg (EPL ultimately still calls APIs), paired with Chinese string references to locate button events.
- Ecosystem essentials: cheat authors often use EPL + VMProtect/packers; after unpacking, first decide the form, then choose E-Code Explorer or the IDA fingerprint method.

**Representative posts**: "EPL 3.5", "Reverse Engineering the EPL runtime Loader", "A Brief Talk on EPL Compilation Modes (errata)", "The Structure, Packaging Principles, and Security of EPL Programs", "The EPL 5.11 Buffer Overflow Vulnerability", "A Simple Analysis of an EPL QQ Phishing Program", "Notes on Analyzing EPL Programs"; the "EPL 5.8 static compilation" dedicated thread is searchable on-site.

### 2.4 The .NET Platform [1000548]

**Identification**: the import table has only `mscoree.dll` and the entry is `jmp _CorExeMain`; the `CLR Header` (COM Descriptor, data-directory entry 15) is non-zero; the file is usually `.exe/.dll` mixing IL.

**Toolchain (by layer)**
- **Decompilers**: dnSpy (debugging + editing in one, the king of usability), ILSpy (open source, plugin ecosystem), dotPeek (JetBrains). IL → C# is nearly lossless.
- **Unpacking/deobfuscation [1000556-1000567]**: **de4dot** does it all (recognizes and cleans the signatures of hundreds of packers/obfuscators — .NET Reactor, Xenocode, MaxtoCode, DotFix, Babel, etc.: renaming, control-flow-flattening restoration, string decryption); the ConfuserEx family uses dedicated ConfuserEx-Unpacker/deepgrep approaches (dump the decrypted assembly first, then fix the metadata). The knowledge tree files nodes by packer: NET Reactor [1000558], MaxtoCode [1000559], Xenocode [1000560], CodeVeil [1000561], flow+name obfuscation [1000562].
- **Debugging**: dnSpy attaches to a process and breaks in methods; for heavy anti-debugging use `MegaDumper/ExtremeDumper` to dump the assembly from memory, then open in dnSpy.
- **Strong names [1000554]**: public-key signature verification; after recompilation either re-sign with sn or NOP the check.
- **Reflection [1000555]**: code hidden in resources, decrypted and loaded at runtime via `Assembly.Load` — invisible to static decompilation; break on `Assembly::Load`/`ResolveEvent` and dump the real assembly.

**Practical essentials**
1. First look at `AssemblyInfo` and the entry `Main`, then full-text search for key strings (registration succeeded/failed).
2. Crypter packers (MaxtoCode/Agile) replace IL with a native stub + JIT hook: the unpacking idea is to rebuild the metadata from memory after running (ExtremeDumper automates this well).
3. New forms: AOT (.NET Native/NativeAOT/R2R) has no IL and degrades to ordinary native reversing; the obfuscator .NET Reactor's Necrobit is the same (method bodies turned native), requiring runtime dumps.
4. **AOT/.NET Native**: what obfuscation vendors call "native compilation" is mostly pseudo-AOT that still keeps managed metadata; true NativeAOT is restored with IDA + symbols.

**Representative posts**: ".NET Reactor Analysis", "How to Crack .NET Reactor", "Core Source Code of a .NET Reflection Unpacker", ".NetReactor 3.6", "de4dot", "Encrypting C# Programs with Eziriz .NET Reactor".

### 2.5 Python [1000583]

Three major forms of Python samples on Windows:

1. **PyInstaller packaging**:
   - Identification: the exe's resources/overlay contain the `MEI` magic (a PyInstaller archive);
   - Unpacking: **pyinstxtractor** (extracts pyc and accompanying binaries per the archive TOC); with newer PyInstaller (≥2.1), when the main-script pyc lacks its header, patch in the magic.
   - Decompiling pyc: **uncompyle6** (≤3.8), **decompyle3** (3.7/3.8), **pycdc** (C++ implementation, half-restores newer versions); 3.9+ can only rely on pycdc or reading the dis assembly.
2. **py2exe / cx_Freeze**: unzip library.zip directly to get pyc, decompile as above.
3. **Embedded-interpreter form (C main program + python31.dll)**: find `.pyc/.pyd` resources or bytecode loaded after `Py_Initialize`; **Cython-compiled .pyd** is real machine code and degrades to ordinary native reversing (symbols often carry function names).

**Practical essentials**
- Decompilation reporting a magic error → version mismatch; first `xxd` the pyc header's 4 magic bytes against the Python version table;
- Packaging password (-p): the unpacking tool will prompt; the key is often hardcoded in the bootloader and can be patched out;
- Common malware patterns: main logic in Python, payload dropped after the fact; after unpacking, prioritize `main`/`__init__` and the base64/zlib layers.

**Representative posts**: "Python Reversing — PyInstaller Reverse Engineering", "Reversing the Source of PyInstaller-Packaged Programs and Their Protection".

### 2.6 Electron and JavaScript [1001776 / 1001261]

**Identification**: the directory contains `*.pak/resources/asar`, the main exe is an Electron shell (the ELECTRON version string), and the installer is huge (≥150MB).

**The reversing flow**
1. Find `resources\app.asar` (or the unpacked app/ directory);
2. **Unpack the asar**: `npx asar extract app.asar out` (or asar7zip); the core logic is in `out/main.js` (main process) and the renderer bundle;
3. The front-end bundle is usually webpack/terser minified and obfuscated: with a sourcemap (if a `.map` exists) restoration is one click; without one, deobfuscate with webcrack/jsbeautifier;
4. Focus: registration checks in `main.js`, auto-update URLs, nodeIntegration settings (if the renderer has node integration enabled, node command injection works directly);
5. **asar.integrity** (the newer Electron packaging integrity header): editing the js fails verification → also edit `package.json` to disable it, or recompute the integrity (hexdump electron `fuses`).
6. General JS reversing: for eval/Function-wrapped code, use breakpoints/rewrite-eval dumps; the obfuscator.io family deobfuscates with restringer/synchrony.

**Representative posts**: "Ideas for Reversing Electron-Built exes", "Learning Electron Security Offense and Defense from Typora", "Embedded Browser Security Miscellany — the Electron Framework".

### 2.7 AutoIt [1000575]

- **Identification**: `AutoIt v3` version resources/strings, few msvcrt imports, an `a3x` hidden in a section; or packed (AutoIt's official Aut2Exe ships compressed).
- **a3x bytecode**: Aut2Exe output is not pure machine code but AutoIt bytecode + an interpreter stub. Decompilers:
  - **MyAut2Exe** (classic, supports up to 3.2.x);
  - Newer versions (3.3.x+): community tools like au3-decompiler/exe2aut variants;
  - Fallback: run dynamically and monitor the script interpretation behavior (Process Monitor watching file/registry touchpoints), or extract the a3x and parse the token stream by hand.
- Malware note: AutoIt malware families (AutoIt/CVE-exploit loaders) often base64 + re-interpret the core payload — run a layer, dump a layer.
- The knowledge base also collects AutoIt-packer (Exe2Aut-related) analysis nodes under "Unpacking Techniques → Packer Instances → AutoIt [1000353]".

**Representative posts**: "The AutoIt3 Decompilation Engine", "AutoIt Program Self-Checks", "A Brief Analysis of Post-Unpack Self-Check Handling in AutoIt Programs", "An AutoIt Credential-Stealing Trojan", "Analysis of an AutoIT FUD Crypter Sample"

### 2.8 Quick Reference for the Remaining Languages (Tabulated)

| Language/form | Identification traits | First-choice tool/approach | Representative node/post |
|---|---|---|---|
| **MFC** [1000580] | imports mfc*.dll; the message map (a static structure generated by `BEGIN_MESSAGE_MAP`); AFX strings | IDA + MFC symbols from Fluorite/FB; locate handlers by message map; break on `AfxMessageBox` | on-site search "MFC message map reversing" |
| **QT** [1000584] | Qt5*.dll; QString (UTF-16 with length); moc-generated meta-object strings (`qt_metacall`) | IDA + qt symbols; signals/slots go through `QMetaObject::activate`, locate slots by the meta string table | on-site search "QT program reversing" |
| **Java** [1000578] | .jar (with exe4j/JSmooth shells, find the embedded jar); the `cafebabe` magic | jd-gui/CFR/Procyon decompilers; for exe4j extract the jar first | on-site search "java decompilation" |
| **Go** [1001256] | symbols usually complete (`runtime.main`); strings not \0-terminated, concatenated in blobs; pclntab | **GoReSym**/IDAGolangHelper restore function names; goroutine/defer patterns | on-site search "Go reversing symbol restoration" |
| **COM components** [1000568] | dll registration (regsvr32), IDL/TypeLib resources | oleview/dotPeek for the tlb; CoCreateInstance breakpoint to chase calls | on-site search "COM component reversing" |
| **PowerBuilder** [1000582] | pbd/pbl data windows; PBVM*.dll | PowerBuilder decompilers (PB Decompiler, the kraft kind) | on-site search "PowerBuilder" |
| **VFP** [1000585/100086 system] | the vfp9r.dll runtime; .pjx projects | VFP decompilation (ReFox) | tree: theory/cracking cases [1000586/1000587] |
| **NetBox** [1000581] | nb*.dll, script packaging | extract the embedded scripts (main.box) and deobfuscate as JS/VBS | on-site search "NetBox" |
| **Lua** [1000579] | lua5*.dll/luajit; bytecode headers `\x1bLua`/`J` | **unluac** (official Lua)/luajit-decompiler; game scripts are often encrypted → dump the decrypted chunk | on-site search "lua decompilation game scripts" |
| **Flash** [1000577] | .swf `FWS/CWS` headers | **JPEXS FFDec** (AS2/3 decompile + debug); CWS is zlib-compressed, decompress first | on-site search "swf decompilation" |
| **VBA/Excel macros** [1000576/1001265] | vbaProject.bin; macro protection | **olevba/pcodedmp** extract the P-code; `Attribute VB_Name` | on-site search "macro virus analysis" |
| **PowerShell** [1001393] | -enc base64 command lines; PS2EXE output | straight base64 -d; PS2EXE with the ps2exe decompiler/string extraction; AMSI obfuscation see the malicious-script chapters | on-site search "PowerShell obfuscation" |
| **php** [1001260] | phar/Zend Guard/SourceGuardian | ezdecompiler-class tools; Zend deobfuscation | on-site search "php decryption" |
| **XML** [1001426] | configuration/signatures | XML deserialization attack surface (the WEB chapters) | —— |
| **AnJian Jing Ling (quick macro)** [1000609] | .q macro scripts; packaged exe | unpack and extract the Q-language script (plaintext/simple encoding) | on-site search "AnJian Jing Ling unpacking" |
| **E-books** [1000610] | exe e-books (formerly CHM/bundled) | CHM decompiles with hh.exe -decompile; exe books use eBook Decompiler | on-site search "e-book unpacking" |
| **Installers** [1000604/1001364] | InstallShield/Inno/Setup Factory/Wise | **innounp** (Inno), **7-zip direct extraction** (Inno/NSIS/MSI), InstallShield with i5comp/i6comp or universal extractor | tree: installshield [1000605]/Setup Factory [1000606]/Wise [1000607]/Inno [1001364] |
| **Static libraries** [1000611] | .lib/.a/.dcu/.obj | once statically linked into an exe they cannot be stripped → filter library code by runtime fingerprints (IDA FLIRT signatures) | on-site search "FLIRT static libraries" |
| **Controls** [1000612] | ActiveX OCX | same as COM; after tstrip inspect the COM registration entry | on-site search "ActiveX reversing" |
| **CUDA** [1001777] | nvcuda/cudart; PTX/cubin sections | nvdisasm/ptxas disassemble the PTX; mining-sample fingerprint `cudaOccupancyMaxActiveBlocksPerMultiprocessor` | on-site search "CUDA reversing" |

## 3. IL2CPP [1001782] (Game Cross-Platform, Listed Separately)

Unity games convert C# IL to C++ then compile to native: `GameAssembly.dll` + `global-metadata.dat`.
- Tools: **Il2CppDumper** (parses the metadata to restore class/method names and generate IDA/Ghidra scripts), Il2CppInspector;
- Approach: dump symbols → run the scripts in IDA → read with C# semantics; encrypted metadata (hardening) needs unpacking and a plaintext dump first;
- The knowledge base also has Android-side U3D/IL2CPP nodes (Game Analysis → U3D [1001710]); PC single-player modding works the same (CheatEngine + symbols).
- **The Android tutorial-grade full flow** (determining APK form/mounting IDA scripts/metadata-encryption variants/frida-il2cpp-bridge practice) is in `../../techniques/14-game-frameworks/unity-il2cpp.md`, cross-linked with this section.

## 4. Methodology Summary

1. **Identify the form before reaching for tools**: the same language in different compiled forms (P-Code/Native, independent/static compilation, IL/AOT) has completely different toolchains.
2. **Runtime helpers are signposts**: VB's `__vba*`, Delphi's `@LStr*`, the EPL core library, Go's `runtime.*` — helper cross-references sit closer to business logic than API breakpoints.
3. **Prefer the script layer**: anything with a VM/packager (P-Code/a3x/pyc/asar) — unpack and decompile to the source level first; only fall back to machine code on failure.
4. **Obfuscation is the norm**: when a commercial packer still sits above .NET de4dot, JS synchrony, or Lua unluac, unpack first (see Unpacking) then return to the language layer.
5. **Accumulate fingerprints**: turn common compiler runtimes into IDA signature libraries (FLIRT/Lumina); recognition rate determines subsequent speed.

## 5. Practice, Chained End to End: Three Typical Scenarios in Full Flow

### 5.1 Cracking: Delphi Shareware Registration Check

```
DIE packer check → unpacked/Delphi fingerprints (rtl strings + uppercase CODE section)
→ IDR rebuild (the event table directly gives the btnRegClick address)
→ IDA jump to the handler → read pseudo-C: mostly "machine code → transform → StrCmp against the serial"
→ pick one of three:
   a. algorithm invertible → write a keygen (Unpacking, keygen writing [1000202])
   b. change the jump    → UE/IDA patch (Reconstruction, file patches [1000734])
   c. comparison in a DLL → decompile the DCU unit with DCU32INT
Failure paths: packed → go through unpacking techniques [1000288] first; VMProtect virtualized key functions
         → see Protection, virtual machines [1000711] (stop when cost exceeds benefit)
```

### 5.2 Malware: a PyInstaller-Delivered Loader

```
sample.exe (clean on VT)
→ DIE: PyInstaller archive (overlay MEI magic)
→ pyinstxtractor unpack → get main.pyc + dependencies
→ magic header matches Python 3.9 → pycdc decompiles (or hand-read dis)
→ main logic: base64(zlib(Cobalt Strike shellcode)) + VirtualAlloc/CreateThread
→ static restoration stops there; dynamically go sandbox/Unicorn emulation to decode the shellcode config
Note: a pyc packaging password → patch the bootloader to extract; the Cython .pyd form degrades to native reversing
```

### 5.3 Game/Commercial: .NET + ConfuserEx Hardening

```
Assembly-CSharp/main program .NET fingerprints (CLR Header)
→ open in ILSpy → all obfuscated names/scrambled control flow → de4dot detects ConfuserEx
→ de4dot processing: deobfuscates control flow + decrypts strings (some modules need --strtyp arguments)
→ proxy constants/anti-tamper it can't handle → debug in dnSpy: break Assembly.Load and dump the real body
→ re-sign/remove the strong name [1000554] → decompile in ILSpy/dnSpy and read the core logic
→ modification needs → dnSpy Edit Method (C#-level recompilation) or the Reflexil plugin to edit IL
```

### 5.4 Troubleshooting Quick Reference

| Symptom | Most likely cause | Action |
|---|---|---|
| IDR/DeDe fail to recognize | newer Delphi (FMX)/packed | unpack first; for FMX use generic RTTI tools Ghidra + C#-reflection-style recovery |
| pyc decompilation all wrong | version/headerless pyc | patch the magic; 3.9+ switch to dis reading or a newer pycdc |
| asar unpacks to an empty main | code lives in asar.unpacked/ or a bytecode pkg | check package.json's pkg/electron-builder config |
| VB P-Code VB Decompiler errors | non-standard compilation/packed | dynamic tracing with SmartCheck + cyclotron's manual-opcode chapters |
| E-Code Explorer won't open an EPL binary | statically compiled (5.x) | IDA + core-library fingerprints; search wide Chinese strings to locate |

## 6. Representative-Post Search Index (some with direct links; the rest via on-site search keywords)

- Delphi: "Delphi reverse-engineering notes", "IDR Delphi rebuild"
- VB: see the §2.2 list (the P-code trilogy etc.)
- EPL: see the §2.3 list
- .NET: see the §2.4 list
- Python: see the §2.5 list
- Electron: see the §2.6 list
- AutoIt: see the §2.7 list
- IL2CPP: "Il2CppDumper in practice" — no dedicated local post found
