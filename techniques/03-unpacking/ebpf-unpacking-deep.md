# eBPF unpacking deep dive (currently the deepest approach)

> Scope: a complete record of Android DEX unpacking via the eBPF/libbpf route. Covers the principle (why it is stealthier than frida), the dual implementations eBPFDexDumper (Go) and eBPFDexDumper-rs (Rust), empirical findings on ART hook entry shapes, the repair pipeline, comparison with frida dumping, and where FART/JDex/RePairip/BlackDex/dpt-shell sit in the ecosystem.

## 1. How eBPF unpacking works: why it is stealthier than frida

### 1.1 Loading and runtime mechanics

- The eBPF program is handed to the kernel via the `bpf(BPF_PROG_LOAD)` syscall, statically verified by the verifier, then executed by the kernel JIT — **not a single line of code is injected into the target process**. (Both repos' bpf.c are standard libbpf CO-RE style; the Go version uses the cilium/ebpf manager, the Rust version uses Aya)
- User-space probes (uprobes) are registered via `perf_event_open` at a given offset of the target so, with breakpoints managed uniformly by the kernel: the target process **gains no new mappings, no new threads, and is not ptrace-attached** — `/proc/<pid>/maps` and `/proc/<pid>/status` (TracerPid) show nothing out of the ordinary.
- Memory reads use `bpf_probe_read_user` (the user-space counterpart of `bpf_probe_read_kernel`): the kernel reads on its behalf — **the target process is unaware, and no syscall is produced**.
- Events travel back to user space asynchronously over a **ringbuf** (`bpf_ringbuf_reserve/submit`), bypassing all of the target process's IO.

### 1.2 frida's detection surfaces vs eBPF's missing surfaces

| Detection method | frida | eBPF |
|---|---|---|
| maps scan for frida-agent/gum signatures | hits (the agent is injected into the target) | no hit (zero injection) |
| thread names `gum-js-loop`/`gmain` | hits | no hit (no threads inside the target) |
| TracerPtr / self-ptrace-attach detection | hits | no hit (no ptrace) |
| port 27042 / frida-server process scan | hits | no hit (the user-space dumper listens on nothing) |
| inline-hook detection (scanning function heads for break/trap) | can hit | hard to hit (uprobe breakpoints are kernel-managed, so the target reading its own text still sees the original instruction semantics; discoverable only via root-required interfaces like `/sys/kernel/tracing`) |
| SELinux/kernel restrictions | essentially no barrier | needs root + the kernel built with `CONFIG_UPROBES`/BPF; some vendor kernels restrict perf_event_open |

### 1.3 Costs and boundaries

- **Read-only observation model**: eBPF cannot force the target to execute methods; an extraction packer only backfills "methods actually executed at runtime", and method bodies never reached are not obtained (the Go README states this limitation verbatim). Active invocation still requires a runtime-modifying or injecting solution like FART/JDex.
- Needs root to install uprobes + to read `/proc/<pid>/maps` and memory; the device must be ARM64 with a reasonably complete BTF kernel (both repos ship a min.btf fallback for a12-5.10-arm64 / rock5b-5.10 in their assets).

## 2. Tool-matrix quick reference

| Tool | Route | root | Status/version |
|---|---|---|---|
| eBPFDexDumper (LLeavesG, Go) | eBPF uprobe + memory read | yes | tested on A13/16, actively updated |
| eBPFDexDumper-rs (chinleez, Rust) | eBPF uprobe + ringbuf | yes | Android 13+ default layout, GPL-3.0 |
| BPFDex (paper) | kernel-mode eBPF unpacking | - | academic proposal |
| DEX-Tracer | eBPF intercepting syscall entry (grab arguments)/exit (grab the return value) | ? | **no public project found** |
| FART (hluwa) | modified-ART active invocation (flash) | flash | original stuck on old versions, **dead on Android 12-16** |
| JDex/JDex2 (J5now) | LSPosed injection + active invocation | no flash | main tool for extraction packers |
| BlackDex (CodingGay) | root-free virtualization + DexFile cookie | no | A5.0-12 |
| RePairip (ispointer) | Pairip (Google hardening) specialist | - | Java 17 |
| dpt-shell (luoyesiqiu) | function-extraction packer itself (RE target) | - | A5.0+ |

Note: the author of dpt-shell is **luoyesiqiu**, not quintubits.

## 3. eBPFDexDumper (Go version): usage and hook details

### 3.1 Build and commands

```bash
# Requires Go 1.19+ and the Android NDK
./build_env.sh && ./build.sh
adb push eBPFDexDumper /data/local/tmp/

# Main command: dump; -u is a UID, not a PID
eBPFDexDumper dump -n com.example.app            # Select by package name
eBPFDexDumper dump -u 10223                       # Filter by UID
# Common flags:
# --libart   default: /apex/com.android.art/lib64/libart.so
# --out      default: /data/local/tmp/dex_out
# --trace    trace method execution in real time
# --clean-oat  default true: delete /data/app/.../<pkg>/oat/ first to avoid cdex or empty results
# --auto-fix   default true: repair automatically on exit
# --execute-offset / --nterp-offset / --register-natives-offset: specify offsets manually
eBPFDexDumper fix    -d <dir>      # Repair the dumped DEX headers and structures
eBPFDexDumper dumpso -n <pkg> --watch   # Dump native shared objects; --lib filters libraries and --anon selects anonymous ELFs
eBPFDexDumper fixso  -d <dir> -s jni_symbols_xxx.txt   # Repair shared-object section tables and restore JNI symbols
```

Outputs: `dex_<begin>_<size>.dex`, `dex_..._code.json` (method bytecode), `fix/`, `so_<pid>_<base>_<size>_<name>.so`, `jni_symbols_<module>.txt`.

### 3.2 Probes actually attached by the dump subcommand

| probe | Role | Argument shape |
|---|---|---|
| `art::interpreter::Execute` | interpreter-execution entry, gets ShadowFrame→ArtMethod | PARM3=ShadowFrame* |
| `ExecuteNterpImpl` | Nterp fast-interpreter entry | PARM1(x0)=ArtMethod* |
| `nterp_op_invoke_*` (all sites attached) | invoke-instruction handling, fills the nterp blind spots | PARM1=ArtMethod* |
| `art::JNI<>::RegisterNatives` | JNI dynamic-registration symbol recovery | PARM3=JNINativeMethod*, PARM4=count |

The Nterp handler's source logic (go_bpf.c `uprobe_libart_executeNterpImpl`): take the ArtMethod from x0 → read dex_method_index at `+0x8` and declaring_class at `+0x0` (**4-byte compressed reference**) → `declaring+0x10` dex_cache → `dex_cache+0x10` DexFile (**after untag**) → `DexFile+0x8` begin (**after untag**) → `begin+0x20` file_size → validate the first byte `0x64` ('d') and size ∈ [0x70, 512MB] → `bpf_map_lookup_elem(dexFileCache_map)` dedup by begin → ringbuf emits `dex_event` + `submit_dex_chunks_partial` chunked streaming → `read_method_bytecode` grabs method bodies.

### 3.3 Automatic RegisterNatives offset identification (three tiers)

1. manual `--register-natives-offset`;
2. scanning libart's symbol table/dynsym (preferring the `art::JNI<false>` instantiation symbol);
3. string xref: the AOSP warning string `"This is slow, consider changing your RegisterNatives calls."` (on failure, another JNI warning string), parse the ADRP+ADD/ADR instructions at the referencing site to compute the address, and settle on **the slot adjacent to UnregisterNatives** in the JNINativeInterface function table.

Handler side (go_bpf.c `uprobe_libart_registerNatives`): walk the method array at the 64-bit 24-byte stride (`name+0 / sig+8 / fnPtr+16`, cap 512), sending `{fn_ptr, name, sig}` one by one over ringbuf; it uses the **TGID** (thread-group-leader lifetime) rather than the TID, so the Go side can still parse which module a fn_ptr belongs to from `/proc/<pid>/maps` afterwards. 32-bit targets (12-byte structs) are safely dropped on read failure instead of emitting wrong symbols.

### 3.4 dumpso / fixso

- `dumpso` **does not go through eBPF**: it parses `/proc/<pid>/maps`, merges the scattered r--/r-x/rw- mappings into a complete so and reads with `process_vm_readv`; self-decrypting so's in anonymous mappings are recognized by the `\x7fELF` magic; `--watch` polls periodically for modules decrypted only at runtime.
- `fixso` rebuilds the section header table from `.dynamic` (DT_SYMTAB/STRTAB/GNU_HASH/RELA/RELR/JMPREL) so IDA/Ghidra recognize the symbols; supports ARM64/ELF64, ARM32/ELF32, and APS2/RELR packed relocations; falls back to p_offset normalization when PT_DYNAMIC is missing. The approach pays homage to SoFixer. JNI symbols are injected via `fixso --symbols`.
- cdex: recognized and reported, but **no full cdex→dex conversion** is done; the README suggests turning to vdexExtractor.

## 4. ART hook entry shapes: the x1-DEX-begin findings

Based on the eBPFDexDumper-rs `src/art.rs` and `bpf/bpf.c` sources.

### 4.1 Entries sharing one BPF handler: "x1 = DEX begin"

The verbatim comment in rs_bpf.c `uprobe/libart_dexFileCtor`: *"DexFile::DexFile constructor. On AArch64 C++ ABI, x1 is base."* The handler only does `begin = PT_REGS_PARM2(ctx)`, then `looks_like_dex_header()` validates the magic/header before emitting the event.

Two symbols matching this shape (art.rs `is_art_dex_file_constructor_symbol`):

```text
_ZN3art7DexFileC1/C2   DexFile::DexFile(const uint8_t* base, size_t size, ...)
                       ABI: x0=this, x1=base, x2=size        -> x1 is the DEX start
_ZN3art13DexFileLoader7OpenOne
                       OpenOne(uintptr_t base, uint32_t size, OatDexFile const*, ...)
                       ABI: x0=this(DexFileLoader*), x1=base, x2=size
                       -> same x1=base shape as the constructor; reuse the same uprobe program
```

Key background (verbatim from a source comment): **Android 16/17 strips the DexFile constructor's symbol / inlines it away**, in which case it falls back to attaching `DexFileLoader::OpenOne`; note that in most stripped libart builds that symbol has `st_value=0` in dynsym (an import placeholder only), the attach is skipped, and it can only be attached when the ROM actually exports an address.

### 4.2 RegisterDexFile: reading from a DexFile*

`ClassLinker::RegisterDexFile(DexFile const&, ObjPtr<ClassLoader>)`: **PARM2(x1) = DexFile\*** (reference form — a bare pointer is passed); the handler reads begin/size from that pointer. The symbol match **pins the suffix** `_ZN3art11ClassLinker15RegisterDexFileERKNS_7DexFile` to prevent mis-attaching to the `unique_ptr<DexFile>` overload — in that overload x1 is not a bare DexFile*, and the ABI assumption would crash.

### 4.3 Nterp entries: a correction — x1 is not the DEX begin

Note: a claim making the rounds says "the Nterp interpreter entry also fits the shape where the DEX begin can be taken from the x1 slot" — **empirically false**:

- `ExecuteNterpImpl` / `ExecuteNterpWithClinitImpl` / `nterp_op_invoke_*`: **PARM1(x0) = ArtMethod\***; the DEX address requires chained dereferences: ArtMethod `+0` (4-byte compressed declaring_class) → Class `+0x10` dex_cache → DexCache `+0x10` DexFile → `+0x8` begin.
- `art::interpreter::Execute`: **PARM3 = ShadowFrame\***; the ArtMethod is obtained via the `shadow_frame.method` offset.
- The "x1 is directly the DEX begin" shape covers **the DexFile::DexFile ctor and DexFileLoader::OpenOne** (the two can share one BPF handler); note that on A15+ OpenOne's real first parameter is `size_t header_offset` (see the version-by-version symbol table of the dex chain in section 11), and on real devices the x1 semantics may drift across versions — verify the registers on the target ROM before writing BPF; RegisterDexFile is "x1 is a DexFile*" followed by a dereference. Do not mix the three shapes up.

### 4.4 The offset-probing fallback chain

Symbol matching (`name.contains("3art")&&contains("11interpreter")&&contains("7Execute")`) → on failure, string xref on `"Interpreting "` (same trick in IDA: search the string, pick the referencing function with 6 parameters) → on further failure, scan ARM64 byte patterns for the `ExecuteNterpImpl` prologue → `ExecuteNterpWithClinitImpl` is scanned from ExecuteNterpImpl's branches. Android 15+ strips / inlines `art::interpreter::Execute` into the nterp main entry — **Execute failing to attach is normal**; nterp already covers the main path; Android 13 has no separate WithClinit variant (the clinit barrier lives inside ExecuteNterpImpl).

### 4.5 Two iron rules of ART (mandatory when writing handlers)

1. **Compressed references**: on 64-bit ART, object references are 32-bit `HeapReference` (compressed) by default; ArtMethod's declaring_class may only be read as a `u32`, then zero-extended into a pointer — reading it as 8 bytes is always wrong.
2. **untag**: before every dereference, pass through `untag()` to clear the ARM64 top byte (MTE tag / PAC pointer code) — `begin`, `dex_file_ptr`, and code_item pointers must all go through it, or memory reads at tagged addresses simply fail.

## 5. eBPFDexDumper-rs: dataflow and repair pipeline

Implemented in Rust + Aya, Android 13+ default layout; on API 35 some ROMs locate JNI automatically but imprecisely, and need `--register-natives-offset` passed manually.

### 5.1 End-to-end dataflow

```text
uprobe hit: Execute/Nterp/dexFileCtor/RegisterDexFile/verifyClass/RegisterNatives
            + uprobes and uretprobes on libc memcpy/memmove/mmap/mprotect
  -> bpf_probe_read_user reads registers and userspace memory; BPF classifies DEX discovery/method capture/native buffers
  -> multiple ring buffers: method_events / events / chunks / debug / native
  -> Rust userspace continuously drains them
  -> deduplicate by DEX begin address -> assemble chunks -> fix.rs restores bytecode -> recompute checksums -> jadx/baksmali
```

Probes come in three modes: `full` (default: interpreter + lifecycle + libc, with some jank) / `lifecycle` (lifecycle only, imperceptible) / `maps-only` (no BPF loaded, pure maps scan). libc's memcpy/memmove get **uprobe+uretprobe attached in pairs** (arguments at entry, return value at exit) — that is how the "native buffer operations" observation points are implemented.

### 5.2 The seven-step repair pipeline

1. **Chunked reassembly**: read chunk by chunk with `DEX_READ_CHUNK=4096`; the `DEX_CHUNK_HEADER_SIZE=24` chunk header carries offset/size, so out-of-order arrival still reassembles;
2. **Missing-page fallback**: `bpf_probe_read_user` cannot trigger page faults — pages not resident at probe time are unreadable; user space re-reads the missed offsets with `process_vm_readv` (the Go version does the same: `[dex-fallback] eBPF read miss at offset ... trying process_vm_readv`);
3. **Dedup**: indexed by the DEX begin address; duplicate events do not rebuild entries;
4. **CodeItem back-scan**: `CODE_ITEM_BACKSCAN_LIMIT=64MB`, `STEP=0x1000`; when a method event's code_item pointer is 0, back-scan along the method's clues;
5. **Method bytecode backfill**: match the dumped `dex_..._code.json` against the DEX and write the executed methods' code_items back into the DEX (the fix subcommand);
6. **Checksum recomputation**: SHA-1 over `dex[32..]` (the signature field), Adler-32 over `dex[12..]` (the checksum field) — without recomputation jadx/baksmali just report a corrupt file;
7. **Structure validation**: `repair` only does bounded structural + checksum checks and reports failure with a non-zero exit code; outputs `fix/`, `final/`, and a `missed.json` coverage report. Per-process isolated naming `dex_<pid>_<begin>_<size>.dex` (hexadecimal); a fresh empty directory is recommended per run.

### 5.3 Subcommands

`dump` (default full mode, auto-repairs into `repair/` at exit), `fix` (backfills bytecode, aggregates into `final/`), `repair`, `dumpso`, `fixso` (fixes so section offsets), `offsets` (checks ART layout offsets). A normal exit drains the JNI/event queues; only a second stop signal interrupts the draining.

```bash
sh build_android.sh
adb push target/aarch64-linux-android/release/eBPFDexDumper /data/local/tmp/
adb shell su -c '/data/local/tmp/eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

## 6. Comparison with frida dumping (this repo's DefineClass method)

Compared against: section 4 of this wiki's `dex-unpacking.md` (hook `ClassLinker::DefineClass`, args[5]=DexFile, read begin_/size_ and dump).

| Dimension | frida DefineClass method | eBPFDexDumper / -rs |
|---|---|---|
| Injection form | frida-server + ptrace injects the agent into the target | loaded into the kernel via bpf(), zero injection into the target |
| Stealth | poor: maps/thread names/port/TracerPid are all scannable | good: all the above surfaces are missing, visible only via kernel tracing interfaces (root required) |
| Environment requirements | root or a debuggable app, frida toolchain | root + kernel CONFIG_UPROBES/BTF, ARM64, version-specific Android offsets |
| Attach points | the single point DefineClass; the symbol changes per version and needs manual edits | multiple points Execute/Nterp/dexFileCtor/OpenOne/RegisterDexFile/verifyClass + libc, with an automatic offset-identification chain |
| Extraction-packer method bodies | not obtained (unexecuted methods are nop) | likewise only the executed ones (but nterp_op_invoke covers all sites + method bytecode backfill, so coverage is high) |
| so/JNI dumping | write another script | dumpso/fixso/jni_symbols as a one-stop shop |
| Repair | manual magic/checksum fixes | automatic fix/repair + SHA-1/Adler-32 recomputation |
| Failure modes | anti-frida detection kills the process; symbol mismatch fails silently | wrong offset identification (manual offset needed); kernel unsupported; cdex not converted; full-mode jank perturbs timing |
| Onboarding cost | low (ready-made scripts) | medium (needs kernel/offset knowledge, version-sensitive) |

Conclusion: anti-frida / strong risk control on the target → eBPF; quick field work with no opposition → the frida script is fastest. The two artifacts complement each other (eBPF takes the stealthy dump, frida does the post-processing analysis).

## 7. Other tools in the ecosystem

### 7.1 FART: the Android 12-16 breakage

FART (the ART continuation of FUPK3, hluwa) works by **flashing a modified-ART build** and actively invoking every method inside `dumpArtMethod` before dumping CodeItems. Root causes of the breakage: (1) the `ArtMethod` field layout is hardcoded (`entry_point_from_quick_compiled_code_`, `dex_code_item_offset`, etc.), and Android 12+ changed the layout/access style completely (Accessor-ization); (2) the ClassLinker→Invoke execution chain changed, so the active-invocation timing no longer fires; (3) odex/vdex layout upgrades — the content may exist only in the vdex and as compact dex. The original's tested ceiling is Android 10 (LineageOS 17.1); 12-16 needs a re-port against new AOSP. Community routes: re-ports (cyrus-studio's repair write-up), MikRom integrated flashing, Youpk, or switching outright to BlackDex/FRIDA-DEXDump/eBPF approaches.

### 7.2 JDex/JDex2: LSPosed active invocation against extraction packers

**JDex/JDex2** (open source, J5now/JDex2): "an active-invocation unpacker against extraction packers based on Xposed/LSPosed". Flow: LSPosed injects into the target → reflect LoadedApk for the real ClassLoader → walk the DexPathList for all DexFiles → **actively call every class's constructors to trigger the packer's method-body backfill** → dump via mCookie at the native layer. Field-tested: LSPosed+JDex dumping after batch-triggering constructors defeats scenarios where Frida16/Xposed90 are countered.

### 7.3 RePairip: the Pairip (Google hardening) specialist

**RePairip** (Java 17, Apache-2.0): "dumps all VMRunner snapshots and repackages them completely, thoroughly removing the protection layer".

### 7.4 BlackDex: root-free

**BlackDex** (CodingGay): Android 5.0-12, a standalone app with zero dependencies (no Xposed/Frida/Magisk/root); VirtualApp-style virtualization + hooked system APIs; dual-route output `hook_xxxx.dex` (hook route) / `cookie_xxxx.dex` (DexFile-cookie route); deep mode writes the memory-pointed instructions back into the DEX to repair nop'd method bodies (experimental, slow, may crash); 32/64-bit are two separate apps. Limits: methods that only decrypt under active invocation cannot be repaired, and it does not fight environment detection.

### 7.5 dpt-shell: the extraction-packer target itself

**dpt-shell** (luoyesiqiu, A5.0+): "hollows out Dex method implementations and reconstructs them at runtime" — the function-extraction packer **itself**, the first-choice target for practicing on or validating unpackers. Companion countermeasures: `dpt-unpacker` (Python), `dpt-unpack` (Kotlin, static), `SuiAnc/dpt-tool` (restores the new-style extraction).

### 7.6 The BPFDex paper and DEX-Tracer

- BPFDex: "Enabling Robust Android Apps Unpacking via Android Kernel", kernel-mode eBPF unpacking, validated on both real devices and emulators.
- **DEX-Tracer** (from user material, no public project): claims "eBPF intercepting syscall entry (accessing the parameters) or exit (accessing the return value)". The same thread's full set — "scan the libc code segment for the ARM instruction signature `0xE1A0C007` (ARM32 `mov r12,r7`), extract the syscall number from the r7-loading instruction, install syscall interception on open/read/mmap2, trampoline the original function pointers, transparently decrypt IO (RC4/XOR 0xAA)" — is old-school inline-hook/syscall-hook technique; no public project is seen using it this way (the 0xE1A0C007 instruction semantics are verifiable per se; mov r12,r7 is common in syscall-number load sequences).

## 8. Picking a route

```text
Strong anti-Frida/risk controls, rootable device -> eBPFDexDumper (-rs has fuller repair; Go variant has fuller documentation)
No instrumentation defenses; need quick results -> Frida DefineClass route in dex-unpacking.md
Method-extraction packer with missing bodies after eBPF/black-box work -> JDex (LSPosed active invocation) or port FART again
Root-free / emulator / no flashing desired -> BlackDex (Android 5-12)
Pairip (Google protection) -> RePairip
Practice target -> apply dpt-shell to your own APK and reverse it
Academic deep dive -> BPFDex paper
```
