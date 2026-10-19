# Western corpus · Forum & Q&A digest (StackExchange / Reddit / classic forums)

> Positioning: top-voted community answers distilled to durable technique entries.
> Scope note: reverseengineering.SE mined via public API (top-voted + tag pages ida/android/debugging/obfuscation/vm); Reddit r/ReverseEngineering top digest mined through its legendary linked writeups (direct fetch blocked 403); Woodmann forum is dead (domain parked, archive unreachable) — no entries, marked blocked.
> Dedup: packer-specific shells (UPX/ASPack/PECompact/tElock/ASProtect SKE) and the Windows anti-debug matrix (PEB/NtQIP/rdtsc/ScyllaHide) live in the Kanxue corpus; this file only carries SE-side generic layers and Unix/ELF/obfuscation angles not covered there.

## Foundations

### Why is disassembly not an exact science? (src: reverseengineering.SE)
Author: 0xea (+ debray)
- Two engine families: linear sweep decodes sequentially from a start (SoftICE, WinDbg) — cannot tell code from data, trusts section metadata for boundaries; recursive traversal follows jumps/calls (IDA, OllyDbg) — knows reachability but misses code entered only via computed addresses.
- Fundamental ambiguities: a jump into the middle of an already-decoded instruction yields a second equally valid decoding; self-modifying code cannot be decoded statically at all; code-vs-data can depend on input (`mprotect(buf); goto buf`) — the disassembly is per-input, not per-binary. RISC is not immune: this is a code/data and path problem, not an encoding-width problem.
- Practice: treat any listing as a hypothesis — force re-decode at odd jump targets, and trust execution traces over static output wherever SMC is suspected.
> Same approach: the overlapping-instructions entry below is the offensive exploitation of exactly this property.

## ELF & Linux dynamic analysis

### What is PLT/GOT? (src: reverseengineering.SE)
Author: 0xea (+ Ciro Santilli)
- GOT is an indirection table so shared-library data/code can be relocated anywhere; PLT holds trampoline stubs for cross-library calls. The dynamic linker patches GOT, never the call sites — that indirection is why a static binary full of `call foo@plt` still runs anywhere.
- Lazy binding path: `call puts@plt` → PLT stub jumps indirect via the GOT slot → on first call that slot points back into the PLT, which pushes a reloc index and jumps to the resolver (`_dl_runtime_resolve`) → resolver writes the real address into the GOT slot → every later call goes straight to libc.
- x86-64 data access shape: `mov off(%rip),%rax` (load real address from GOT) then `mov (%rax),%reg` (dereference) — two memory accesses per globals read; recognize it instantly when reading disassembly.
- Full RELRO / `-fno-plt`: binding happens eagerly at load and GOT becomes read-only after relocation — reverser consequence: GOT slots hold final addresses from the first call, and lazy-GOT hook tricks don't apply.
> Same approach: Ian Lance Taylor's 20-part "Linkers" blog series is the canonical deep dive.

### What symbol tables survive strip in ELF? (src: reverseengineering.SE)
Author: perror
- Only dynamic symbols must survive: `.dynsym`/`.dynstr` plus the relocation tables `.rela.dyn` (data relocations, non-PLT) and `.rela.plt` (PLT slots). `.symtab` is pure convenience and is what `strip` removes; `sstrip`/`--strip-unneeded` push further, but `.dynsym` can never go or the loader breaks.
- Reverser angle 1: a "stripped" ELF still names every imported function — `readelf --dyn-syms` is the first recon step on Linux, equivalent to a free partial import table.
- Reverser angle 2: malware that wants even this gone resolves by hash ordinal (`dlopen`/`dlsym` chains or manual export-table walking) — absence of interesting `.dynsym` entries is itself a tell.
- Section-header removal (sstrip) hides segment layout from tools that trust them; parse from the program headers instead (IDA does).

### How to handle stripped binaries with GDB? (src: reverseengineering.SE)
Author: 0xC0000022L (+ Mega Tonnage)
- Ergonomics that matter under pressure: run `gdb -q`; ENTER repeats the last command (stepping rhythm); `b`/`c`/`n`/`ni` abbreviations; `layout asm` for TUI; tab completion; `help <cmd>`.
- `set disassembly-flavor intel` if you read Intel syntax; `display/i $pc` auto-prints the next instruction at every stop — poor man's single-step view.
- `call` can invoke inferior functions to force/probe behavior; `info proc mappings` replaces missing sections; `gcore` (or `generate-core-file`) freezes the process into a core you import into IDA/r2 for offline static work.
- Don't hand-roll: gdbinit-style kits (pwndbg/gef) give context windows, heap/TEB awareness without IDA.
> Same approach: the same workflow ports to radare2 (`r2 -d`) and to x64dbg on the Windows side.

### Break at the first instruction of a stripped PIE without disabling ASLR (src: reverseengineering.SE)
Author: Zach Riggle (+ Ruslan, p0tr3c)
- Pre-8.1 hack: `break *0` before `run` — inserting the breakpoint fails once the process maps (address 0 unmapped), and GDB's error path conveniently leaves you stopped at the very first instruction. A side effect used as a feature.
- GDB ≥ 8.1: `starti` does it officially — stops at the loader's entry (`_start` of ld.so, before the main executable's entry).
- `.gdbinit` macro to land on `main` of a stripped static binary: step once, `b __libc_start_main`, continue, `b *($rdi)` (main is passed in rdi), continue.
> Same approach: `set stop-on-solib-events 1` is the analogous trick for catching the first library load in dynamically linked targets.

### How can I analyse an executable with no read permission (setuid, chmod 0711)? (src: reverseengineering.SE)
Author: Gilles 'SO- stop being evil' (+ samuirai, Dougall)
- For setuid targets, ptrace, `/proc/pid/mem`, `LD_PRELOAD` and core dumps are all suppressed by the kernel; `strace` works but runs the binary unprivileged (fine for analysis, wrong for privilege-dependent behavior).
- Escape 1: your own ptrace wrapper — fork a child that execs the target, single-step it with `PTRACE_SINGLESTEP` from the parent; you see every instruction and can dump code even though the file itself is unreadable.
- Oracle for locating the heap: the `brk(0)` line strace prints gives you the heap base for free; single-step until EIP approaches that value, then dump the region.
- Escape 2: xocopy rebuilds a full ELF via ptrace using the ELF header the loader maps into memory (most compilers map it for the dynamic linker's use).
> Same approach: same idea drives modern process-dump tooling (procdump core flow, r2pm -d).

### How are the segment registers (fs, gs) used in Linux? (src: reverseengineering.SE)
Author: Mellowcandle (+ blabb)
- Protected mode: a 16-bit segment register holds a selector (13-bit table index, 1-bit GDT/LDT, 2-bit RPL); the hidden descriptor cache holds base/limit. Modern OSes run flat segments (base 0), so the registers only matter as base-address carriers for FS/GS.
- Linux roles: user TLS via FS (x86-64, set by `arch_prctl(SET_FS)`) or GS (x86-32); kernel per-CPU data via the other one; CS/DS/ES/SS ignored in 64-bit long mode.
- Windows mirror: GS = KPCR in kernel / PEB-TEB chain in user (x64), FS = TEB/PEB (x86) — the anti-debug PEB tricks are exactly this mechanism, which is why the same `gs:[x]` idiom shows up in shellcode cross-OS with different offsets.
- WinDbg `dg @fs` decodes the live descriptor — selector values themselves (0x08/0x30 vs 0x1B) separate kernel from user GDT slots.

## Generic unpacking (SE consensus layer)

### Unpacking binaries in a generic way (src: reverseengineering.SE)
Author: Igor Skochinsky (+ 94c3)
- Four stages: evade anti-analysis → find OEP → dump → restore imports. Run inside a VM/emulator first: it neutralizes most checks (rdtsc timing, debug-register tricks) without patching anything.
- OEP tricks beyond the ESP-law baseline: (a) hardware-execute breakpoint on the stack slot where the packer stashed the saved registers — it fires exactly at the restore-then-jump-to-OEP moment; (b) page-execution breakpoint on the memory range the stub is filling with unpacked code — fires only when that code first runs; (c) break on startup APIs (GetCommandLine/GetVersionEx) and walk the callstack back into user code.
- IDA-specific: no file dump needed — take a debugger memory snapshot into the IDB; mark VirtualAlloc'd regions as "loader" so they're included in the snapshot.
- Import restore: while the process is alive, rename the resolved pointers in the IAT by the functions they currently point at, then rebuild the table offline.
- Hard limit: virtualizing protectors never materialize the original code — the only exit is writing a disassembler/lifter for their bytecode.
> Same approach: this is the generic frame around the per-shell playbooks in the Kanxue packers corpus.

### Why dump precisely at OEP? Packer IAT-manipulation taxonomy (src: reverseengineering.SE)
Author: NirIzr (+ Nordwald)
- OEP matters to import reconstructors, not to the dump itself: they scan forward from OEP for "IAT-looking" pointer ranges, because the PE-declared import table is fake or gutted by design — the real one was built at runtime by the stub.
- Taxonomy: (1) packer leaves the IT alone — dumpers copy it, nothing to do; (2) inner hidden PE decrypted wholesale — its IAT is intact and comes out automatically; (3) packer runs its own loader/resolver — you must locate the alternative IAT and synthesize a fresh import table from where those pointers actually point, then force the rebuilt IAT to occupy the same addresses so relocated call sites still hit.
- Dumping slightly after OEP is harmless as long as all decrypt/decompress stages finished; any dumper lets you fix the entry point afterwards. Dumping before that risks dumping still-encrypted regions.

## Obfuscation & deobfuscation

### What is control-flow flattening? (src: reverseengineering.SE)
Author: nomilk (+ Igor Skochinsky)
- Recipe (Laszlo & Kiss paper): every basic block becomes a `case` in a `switch` wrapped in a `while`; a state variable written at the end of each block selects the next case; nesting level of the original CFG is erased into one flat loop.
- ASM shape: dispatcher loads the state var, bounds-checks, then jump-table dispatch (`addls pc, pc, r3,lsl#2` on ARM; `jmp [table+idx*4]` on x86); each block ends by storing a new state constant and branching back to the dispatcher.
- Field example: Apple FairPlay code — state is derived from a per-block constant added to a running register, so the raw case values aren't even directly visible (LDR of big immediates, `STR` of next state).
- Recovery: constant-propagate the state variable over the flattened CFG — replace each block's tail jump-to-dispatcher with a direct jump to the block selected by its state constant; iterate to fixpoint. Works because the state variable is the only live edge information.
> Same approach: the same fixed-point idea powers automated deflatteners in BitBlaze/Triton-style tools and D-810 rules.

### What is an opaque predicate? (src: reverseengineering.SE)
Author: Rolf Rolles (+ Ange, joxeankoret)
- Definition: a branch whose outcome is fixed by construction and known to the creator, but not resolvable a priori by the analyzer; "hardness" is deliberately excluded from the definition — even trivial-looking ones qualify if tools can't fold them.
- Field constructions: flags register is 0x246 at process entry (ZF always set → `jnz` never taken); `SetErrorMode(100); if (SetErrorMode(1024)==100)` — needs API semantics to fold; FPU transcendental iterations to starve emulators of cycles; jump targets computed as checksum-xor of code bytes.
- Theory anchor (Dalla Preda): whether an abstract interpreter breaks a predicate family is a property of domain completeness for the tested relation — mod-k families need domains complete for modular arithmetic.
- Practical counterplay: model entry-state constants in your emulator (kills the 0x246 class); execute both arms and diff; treat any always-one-way branch you can prove as a direct jump.
> Same approach: opaque predicates usually guard overlapping-instruction streams — clear one and the other surfaces.

### What is overlapping-instructions obfuscation (jump in the middle)? (src: reverseengineering.SE)
Author: Remko (+ Ange, joxeankoret)
- x86 decode can begin at any byte with execute permission; a jump into the middle of a displayed instruction starts a completely different instruction stream that linear/recursive disassemblers never show.
- Constructions: `EB 01` skips the `68` of a following push (hidden `C3` ret appears); wide instructions hide whole routines in their operands — `imul` with SIB+disp can reach 11 bytes, stuffing `push imm32; jmp` chains inside; `EB FF` overlaps itself (`FF C0` = inc eax from the same bytes).
- Cross-mode variant: same EIP executed under different CS (0x23 vs 0x33) — `63 D8` decodes as `arpl ax,bx` in 32-bit but `movsxd rbx,eax` in 64-bit, closed with a far `retf`; static tools assume one mode per region.
- Handling: re-disassemble from every jump/call target (r2 `pd @`, IDA force-analyze at the odd address after undefining); trust traces from real execution; be aware every multi-byte instruction in the listing is a potential host.
> Same approach: packer stubs and VM entries use this against initial auto-analysis; after OEP the streams usually re-converge.

### How common are virtualized packers in the wild? (src: reverseengineering.SE)
Author: Ange (+ pnX, thisismalicious)
- Rare in commodity malware, and usually misapplied: virtualizing the packer/wrapper only — bypass to the dumped code and the VM never mattered.
- Detection shortcut: pirated VMProtect/Themida licenses watermark their builds, so the protector itself fingerprints the sample regardless of what was virtualized.
- Smart uses to study: Clampi virtualized the whole viral body (Fallière whitepaper); FinFisher shipped a custom VM with only 11 opcodes — custom in-malware VMs are typically tiny; enumerate handlers, map semantics, write the lifter in a day.
- Canonical text: Rolf Rolles, "Unpacking Virtualization Obfuscators" (template-based handler recognition).
> Same approach: the VMProtect deep dives below are the industrial-strength version of the same attack.

### Why would a program call the address immediately after the call? (call $+5) (src: reverseengineering.SE)
Author: Dougall (+ newgre, 0xC0000022L)
- `call next; pop reg` is the position-independent idiom to materialize the instruction pointer — the call pushes next-instruction's address, the pop captures it; all later references are reg-relative offsets (Mach-O PIC and shellcode standard).
- Anti-disassembly variant: `call $+5; pop rdx; add rdx,8; push rdx; ret` — the ret jumps to an address you pushed, while a naive disassembler also treats that ret as a function terminator and mis-decodes the following bytes (e.g. `0F 5A 5B 59` parsed as cvtps2pd garbage).
- Craft repair: when IDA ends a function at a suspicious ret, undefine and re-decode starting from the mid-stream byte; a "ret that isn't returning" is a manual-analysis flag.
> Same approach: same idiom family as the EB-FF self-overlap and jmp-reg dispatchers of packer stubs.

### Analyzing highly obfuscated JavaScript (src: reverseengineering.SE)
Author: svent (+ Mick, peter ferrie)
- Tool philosophy (JSDetox author): don't chase full automatic deobfuscation — support manual analysis. Two engines: static constant folding of bloated expressions (`var x = -~-~'bp'[720094129.0.toString(2<<4)+""] * 8 + 2` resolves to `var x = 34`), and execution over an emulated DOM that intercepts eval()/document.write() and prints what would run — resolving the document.write-then-getElementById round-trips the obfuscator uses as state.
- Run it on V8 server-side, never in your browser; still isolate in a VM anyway.
- Catch-all fallback that never misses a stage-2 payload: execute in Firefox with eval() overridden by a proxy function that just prints its argument — even aliased eval use prints; the spec makes eval non-overridable in theory, in practice it fails safe.
> Same approach: same "emulate to the drop point, capture, iterate" loop as packer OEP hunting.

## VMProtect deep dives (Reddit-linked writeups)

### VMProtect 2 — virtual machine architecture (src: r/ReverseEngineering linked writeup)
Author: _xeroxz (back.engineering / aftermathlabs)
- Stack-machine VM (RISC-ish) over x86; during interpretation the native registers have fixed roles: RSI=VIP, RBP=VSP (real stack), RDI=scratch-register block (0x140 bytes on the native stack), R12=handler table (256 qword entries of encrypted RVAs), R13=module base, RBX=rolling decryption key, AL decrypts opcodes.
- Rolling key: seeded with the bytecode RVA; every operand is decrypted with it and the key is then updated from the decrypted operand — executing out of order or patching eagerly desynchronizes all later decryption (anti-tracing by construction).
- Dispatch (`calc_jmp`): decrypt 1-byte opcode → `mov rdx,[r12+rax*8]` → single constant-only transform → `add rdx,r13` → `jmp rdx`. VIP direction (forward/backward via inc/dec-style advances) varies per build — encode accordingly.
- vm_entry pushes an encrypted 32-bit RVA (exactly three transforms) plus all GPRs/rflags, ending with eight zero bytes; vm_exit is the inverse; scratch-register → native mapping is not preserved across exit. Handlers that grow the virtual stack relocate the scratch block (`rep movsb`) when VSP encroaches.
- Key structural fact: inside VM code the obfuscation is deadstore + opaque branching only — there are no legitimate conditional branches; both arms of every JCC converge on the same meaningful instruction, and deadstore removal is per-register read/write dependency tracking (never drop push/pop, they move RSP).
- Tracing hook: pick a handler-table slot, re-encrypt your own handler RVA with the table transform, swap it in — you now intercept that virtual opcode on every execution and can log (opcode index, rolling key, scratch regs, vstack top) or substitute semantics (spoof CPUID, etc.).
> Same approach: vmprofiler / vmprofiler-qt (author's static tooling), NoVmp + VTIL lineage for automatic lifting.

### Defeating VMProtect's import protection via emulation (src: r/ReverseEngineering linked writeup)
Author: mike1k (VMPImportFixer)
- Import protection rewrites every API call into near-relative calls inside the VMP section (default `.vmp0`, renamable): stub forms `push reg; call f` or `call f; ret`, each computing the true import address through chains of arithmetic that end with `mov [rsp],addr; ret`.
- Devious detail: some variants bump the return address by one byte so decompilers that assume a clean ret mis-parse the following instruction — the byte is skipped at runtime.
- Recovery: locate calls targeting the VMP section, emulate each stub with Unicorn until the stack write + RET, read the computed target, and patch the call back into a direct import. Emulation was chosen deliberately over debugger-bound lifting: trivially supports x86 and x64 from one binary.
- Operational notes: attach by PID/process name; `-mod:` picks the module to fix; no relocations on x86 targets yet.
> Same approach: any arithmetic-opaque API resolver yields to the same emulate-until-ret-and-read-stack pattern.

### Playing with VMProtect — automatic deobfuscation of pure functions (src: r/ReverseEngineering linked writeup)
Author: Jonathan Salwan (Triton)
- Model: a virtualized trace T' interleaves original-program instructions with VM machinery; symbolize only the function's inputs — everything the machinery computes is input-independent, so it concretizes to constants, and the surviving symbolic expression is the original semantics.
- Pipeline: PIN-tool trace of the virtualized region (any DBI/emulator works) → Triton replay with symbolized inputs → formula-level backward slicing prunes VM noise → Triton's synthesizer simplifies (25,085 executed instructions collapsed to `bvxor x y`).
- Lift the expression to LLVM-IR and run `opt -O3` — LLVM's optimizer dissolves the residual MBA obfuscation (~6 instructions out).
- Branching: no real `jcc` for virtual jumps, so branch conditions are found with heuristic flag markers on the trace; DSE produces a model steering execution down the unexplored path; traces merge into a path tree (shared prefix + C/¬C) from which LLVM rebuilds the CFG.
- Limits: few executable paths; no input-dependent memory accesses; loops unroll (size blowup).
> Same approach: same trace-concretize-simplify core as Pushan/Thalium-style trace-free devirtualization work.

## IDA / Ghidra workflow gems

### What is a FLIRT signature? (src: reverseengineering.SE)
Author: Igor Skochinsky (+ Peter Andersson)
- FLIRT matches known library functions: each function becomes a pattern of its first 32 bytes with variant bytes masked, so recompilations with different registers/opts still match; IDA applies signatures at load and labels CRT/runtime noise away.
- Craft multiplier: generate signatures from libraries you actually face — game engines, Delphi VCL, statically linked OpenSSL — with the FLAIR tools against the exact build; a malware family's shared internal library is also fair game (hundreds of functions named at once).
- Trap: signatures more generic than the code they match (plain push/mov prologues) generate false positives; verify on known-good pairs first.
> Same approach: Ghidra function-ID and r2 zignatures are the same concept; community FLIRT repos exist for common Windows libc builds.

### How to organize vtables in IDA Pro (C++ behemoths)? (src: reverseengineering.SE)
Author: Ray (+ Igor Skochinsky)
- Recreate classes as C structs and vtables as structs of function pointers; define them as code in the Local Types subview (pasteable C), not the Structures view — faster to iterate.
- Order matters: start from the base-most classes; a forgotten member in a widely inherited base means re-touching every descendant. Constructors are the anchor: they spoil both the vftable and the member layout; a constructor's caller reveals the total object size from its allocation/reservation.
- IDA 7.0+ auto-detects RTTI and marks vftables/hierarchies, but mis-assigns vtables to base classes under multiple inheritance — fix by hand or script before trusting the tree.
- Companion habit (Q87): put a repeatable comment on every vtable slot with the implementation's address, so applying the struct to any virtual-call site immediately offers the jump target.
> Same approach: the Recon 2011 talk "Practical C++ Decompilation" is the canonical write-up of this method.

### How is a structure located within a disassembled program? (src: reverseengineering.SE)
Author: user1354557 (+ Andrew, Yifan)
- Ground truth first: structs are a C-source abstraction — assembly only shows a pointer plus offsets; labeling is for your benefit, so never conclude the author "had" a struct, only that the access pattern is struct-shaped.
- Heuristics that find them: dereference at constant non-zero offsets from a pointer (`mov ecx,[eax+8]`); pointer-plus-offset fed to a library call (`add eax,0xC; push eax; push 0x30; call strncpy` implies a ≥0x30 char buffer at +0xC); the same offset cluster dereferenced by several functions (two functions both touching +0x10/+0x18/+0x14 = field access, not coincidence); mixed widths off one pointer; constant-offset reads suggest struct, loop-indexed reads suggest array.
- Payoff: define the struct once and apply it — every `[reg+off]` site lights up with field names across the whole database.
> Same approach: the offset-cluster logic is exactly what vtable-organization (above) automates for the function-pointer case.

### IDA ergonomics: unicode strings, DLL host debugging, detached tabs (src: reverseengineering.SE)
Author: Megabeets, josh, Kevin
- Unicode strings: Strings window (Shift+F12) → right-click Setup → check "Unicode" — otherwise every UTF-16 string is invisible in the listing.
- Debugging a DLL with IDA: load the DLL as the database, then Debugger → Process options → Application = host EXE, Input file = the DLL; F9 runs under the host and your DLL breakpoints hit (no injection needed).
- Detached tab rescue: drag the small gray bar just below the floating window's titlebar back onto the main window (it tooltips the same); Window → Reset desktop restores everything at once.
> Same approach: x64dbg equivalents — UTF-16 in string references; "Select DLL path" for host-run debugging.

### How can I diff two x86 binaries at assembly level? (src: reverseengineering.SE)
Author: Mick (+ jvoisan, joxeankoret)
- Tool ladder: BinDiff (commercial, IDA), DarunGrim (open, IDA), radiff2 (`-d` delta, `-g` graph diff, no IDA needed), Diaphora (pure-Python IDA plugin; the only one diffing Hex-Rays pseudo-code and importing/exporting structs/enums, actively maintained).
- Technique value, not just tooling: patch-diff a vendor's fix against the vulnerable build (MS15-0xx workflow) — the modified function set is the bug; match anchors survive heavy recompilation drift.
> Same approach: same anchor-proportional matching underlies BinDiff's "similarity" metric and Ghidra's Version Tracking.

## Compiler/language identification & odd formats

### How to know which language/compiler built an EXE? (src: reverseengineering.SE)
Author: Igor Skochinsky (+ PhoeniX, Andrew, Mike)
- Layered identification: imports first (mscorlib = .NET, Borland/Delphi unit imports, MFC internals), then packer-agnostic signature tools (DIE, TrID, PEiD), then FLIRT-style runtime-library matching, then metadata leftovers (`.comment` with GCC version strings, MSVC Rich header encodes toolchain history).
- Code idioms as fingerprints: MSVC passes args with `push`, GCC pre-allocates the frame and uses `mov [esp+x]`/`mov [rsp+x]`; Duqu's Visual C++ origin was guessed from idioms before confirmation. Academic keyword: "toolchain provenance" (Rosenblum).
- Practical ranking: language → compiler family → version; each step narrows the FLIRT set and the decompiler's expectations (calling conventions, exception style).
> Same approach: the Kanxue corpus keeps the Delphi/VB/MFC breakdown; this entry is the Western-tools pipeline (DIE/TrID/Rich).

### Reversing optimized integer division/modulo by constants (src: reverseengineering.SE)
Author: Peter Andersson (+ John Källén)
- Division by constant becomes `imul` by a magic number (0x92492493 for /7), take the high 32 bits, sign-fix (`add edx,edi` where edi holds the sign), then `sar` — a branchless exact quotient; modulo is reconstructed as `x - q*d` (watch for the trailing `imul` by the original divisor).
- The magic number is ceil/floor of 2^(32+s)/d with an error term engineered below one ULP of the shift; recognizing the 5-instruction shape (movabs magic, imul, add/sar, shr 0x1f, sar/add) is the pattern-match.
- To invert by hand: magic ≈ 2^(32+s)/d, try small s. Automated: the Reko decompiler recovers divisors by bracketing magic/2^32 with a mediant (Stern-Brocot style) rational search — small code, robust.
> Same approach: same reciprocal-multiply family appears formodulo and for "align" arithmetic; also the root of MBA-style lookalikes that aren't real obfuscation.

### Reversing PyInstaller EXEs and .pyc bytecode (src: reverseengineering.SE)
Author: Ange (+ Igor Skochinsky, Mick, rocky)
- PyInstaller layout: an appended archive (block starting with `PYZ`) holds the packed modules; extract with pyi-archive_viewer (ships with PyInstaller — read its source to know the exact container format), then decompile the extracted .pyc (uncompyle6 / pycdc for modern versions, uncompyle2 for 2.x). binwalk is a decent generic first pass for other bundlers.
- Anti-reversing twist seen in the wild (Dropbox): customized interpreter with changed opcode values or extra opcodes — countermeasure is to map the non-standard bytecode back to standard (a translation table), then use ordinary decompilers; or patch the decompiler to the variant.
- When on-disk bytecode is encrypted/checked, go dynamic: pyREtic recovers source from live in-memory objects, skipping the disk format entirely.
> Same approach: same extract-then-decompile flow for py2exe, cx_Freeze, Nuitka (real compiled code — different, no bytecode to recover).

### Reversing Android .so native libraries (src: reverseengineering.SE)
Author: Guntram Blohm (+ Cedric VB, Ole André Vadla Ravnås)
- The .so is just an ELF shared object (usually C/C++ via JNI): IDA with ARM support, or objdump from an ARM toolchain for a text dump; retdec gives a rough C sketch of the logic.
- Prerequisites that actually gate progress: ARM instruction set, JNI calling conventions (JNIEnv* first arg, signature mangling), and the platform ABI — without those no tool output is readable.
- Dynamic shortcut: Frida hooks JNI boundary and native crypto/comms functions, exposing arguments and return values live — often answers "what does this library do" without full static reversal; for DEX-side obfuscation, the .so is where the logic hid on purpose.
> Same approach: the Android corpus carries the smali/DEX layer; this entry is the native-ELF complement.

### Bypassing certificate pinning in Android (src: reverseengineering.SE)
Author: lulzpwner
- Xposed + JustTrustMe hooks the whole SSL stack's verification entry points from one module; read its Main.java for the canonical list of methods to neutralize (TrustManager/OkHttp/Conscrypt variants).
- Graduation path: Xposed first (learn the hook API), then Frida for runtime scripts without reboot/module installs — the modern default for layered, per-app pinning.
- When pinning survives both, the check is native or custom (hash comparison in .so, secondary channel) — take it to the .so with the Frida native flow above.
> Same approach: objection wraps the same Frida logic behind `android sslpinning disable`.

### Reversing a Windows 10 UWP app (src: reverseengineering.SE)
Author: TechLord
- The app's visible window is owned by ApplicationFrameHost, not the app process — Spy++ shows nothing useful; use the SDK Inspect/UI-Spy tools on the XAML elements, and attach the debugger to the app process itself.
- UWP quirk for injection: the injected DLL must grant Read+Execute to the "ALL APPLICATION PACKAGES" group (file properties or SetNamedSecurityInfo/EXPLICIT_ACCESS) or the loader rejects it; injected code also cannot create its own windows (no owned hwnd).
- Workflow that found the code: attach x64dbg to SystemSettings.exe with "break on DLL load" armed, click the button, land in SettingsHandlers_nt.dll loading — the per-page handler DLLs are the real logic; decision flows continued into MusUpdateHandlers.dll for update-triggered restarts.
> Same approach: WinRT handler-DLL pattern generalizes — find the SettingsHandlers/extension DLL named for the UI page you care about.

### Decompiling a 1990 16-bit DOS application (src: reverseengineering.SE)
Author: movAX13h (+ Anonymous, Ange)
- Modern route: run under DOSBox with its integrated debugger for dynamics while keeping the MZ open in IDA in parallel to annotate statically; Reko decompiler handles 16-bit DOS MZ and emits C.
- Era tools if you can find them: Sourcerer and Windows Codeback (the "IDA of their day"), SYMDEB/Turbo Debugger; pair with Ralf Brown's Interrupt List to decode int 21h-era semantics.
- For a data-format goal specifically, breakpoint the file-write interrupts and dump the buffer being written — often beats full static decompilation of 16-bit segmented code.
> Same approach: interrupt-list-driven breakpointing is the DOS analogue of "break on the API that touches your data".

## Anti-analysis escapes (Unix side)

### Anti-debug techniques on Unix platforms (src: reverseengineering.SE)
Author: Igor Skochinsky (+ Andrew)
- Unix-specific set beyond the ptrace-is-attached check: strip section headers (sstrip) — GDB refuses the file outright while IDA still parses; direct `syscall` instructions instead of libc ptrace() wrappers (breakpoints on the function miss them); anti-debug in `__attribute__((constructor))`/global ctors running before main, before GDB's default main breakpoint; sending yourself SIGTRAP (GDB stops unless `handle SIGTRAP nostop`); fork a child that ptrace-attaches to the parent, monopolizing the tracer slot.
- Escapes: break at the true entry (`info file` gives it, not main); trace the child instead; set `handle` policies per signal; emulate.
- The meta-answer: every software check is fakeable by the environment (perfect-emulation argument) — plan for evasion being a cost curve, not a wall.
> Same approach: the Windows PEB/DebugPort matrix in the Kanxue protection corpus is the sibling entry; this one is the POSIX toolkit.

### What is the purpose of mov edi, edi? (hotpatching) (src: reverseengineering.SE)
Author: QAZ (+ peter ferrie, rebel87)
- The 2-byte no-op at function start is the patchable slot for hotpatching: at runtime it is overwritten with a 2-byte short jump into the 5 bytes of intentional padding immediately before the function, which hold a `jmp rel32` to replacement code. Recognizing `mov edi,edi` + long nop run before a function = a ready-made trampoline site.
- Order-of-operations craft (from the answer, and load-bearing when you write your own hooks): write the 5-byte long jump into the padding first, then flip the 2-byte slot — the reverse order has a window where the slot jumps to garbage. Only cmpxchg8b writes more than 4 bytes atomically, hence the race.
- The /hotpatch compile option is what sprinkles these across Windows system DLLs; for the reverser they are also ideal mid-function hook real estate that requires zero relocation.
> Same approach: same first-instruction-slot concept as Detours-style inline hooks and the classic packer "stolen bytes" tricks (see Kanxue ASProtect entries).

## Sources
- Highest Voted Questions — https://reverseengineering.stackexchange.com/questions?sort=votes
- What is PLT/GOT? — https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got
- What symbol tables stay after strip in ELF — https://reverseengineering.stackexchange.com/questions/2539/what-symbol-tables-stay-after-a-strip-in-elf-format
- How to handle stripped binaries with GDB — https://reverseengineering.stackexchange.com/questions/1935/how-to-handle-stripped-binaries-with-gdb-no-source-no-symbols-and-gdb-only-shows
- Breakpoint at entry of stripped PIE without disabling ASLR — https://reverseengineering.stackexchange.com/questions/8724/set-a-breakpoint-on-gdb-entry-point-for-stripped-pie-binaries-without-disabling
- Analyse an executable with no read permission — https://reverseengineering.stackexchange.com/questions/98/how-can-i-analyse-an-executable-with-no-read-permission
- Segment registers (fs, gs) in Linux — https://reverseengineering.stackexchange.com/questions/2006/how-are-the-segment-registers-fs-gs-cs-ss-ds-es-used-in-linux
- Unpacking binaries in a generic way — https://reverseengineering.stackexchange.com/questions/72/unpacking-binaries-in-a-generic-way
- Why dump precisely at OEP while manual unpacking — https://reverseengineering.stackexchange.com/questions/14994/why-to-dump-precisely-at-oep-while-manual-unpacking
- What is control-flow flattening — https://reverseengineering.stackexchange.com/questions/2221/what-is-a-control-flow-flattening-obfuscation-technique
- What is an opaque predicate — https://reverseengineering.stackexchange.com/questions/1669/what-is-an-opaque-predicate
- What is overlapping instructions obfuscation — https://reverseengineering.stackexchange.com/questions/1531/what-is-overlapping-instructions-obfuscation
- How common are virtualized packers in the wild — https://reverseengineering.stackexchange.com/questions/1478/how-common-are-virtualized-packers-in-the-wild
- Why a call targets the following instruction — https://reverseengineering.stackexchange.com/questions/1654/why-would-a-program-contain-a-call-instruction-targetting-the-address-immediatel
- VMProtect 2 — Detailed Analysis of the Virtual Machine Architecture — https://aftermathlabs.net/blog/17/05/2021 (r/RE thread: https://www.reddit.com/r/ReverseEngineering/comments/nglk7w/)
- Defeating VMProtect's Import Protection via Emulation (VMPImportFixer) — https://github.com/mike1k/VMPImportFixer (r/RE thread: https://www.reddit.com/r/ReverseEngineering/comments/p2th02/)
- Playing with the VMProtect software protection (Triton) — https://github.com/JonathanSalwan/VMProtect-devirtualization (r/RE thread: https://www.reddit.com/r/ReverseEngineering/comments/sx8s97/)
- What is a FLIRT signature — https://reverseengineering.stackexchange.com/questions/175/what-is-a-flirt-signature
- How to organize vtables in IDA Pro — https://reverseengineering.stackexchange.com/questions/11811/how-to-organize-vtables-in-ida-pro
- Static analysis of C++ binaries — https://reverseengineering.stackexchange.com/questions/87/static-analysis-of-c-binaries
- Search for unicode strings in IDA — https://reverseengineering.stackexchange.com/questions/18041/how-do-you-search-for-unicode-strings
- How to debug the DLL of an EXE using IDA Pro — https://reverseengineering.stackexchange.com/questions/9328/how-to-debug-the-dll-of-an-exe-using-ida-pro
- How to reattach tabs in IDA — https://reverseengineering.stackexchange.com/questions/14196/how-to-reattach-tabs-in-ida
- Diff two x86 binaries at assembly level — https://reverseengineering.stackexchange.com/questions/1879/how-can-i-diff-two-x86-binaries-at-assembly-code-level
- How to know in which language/technology an .exe is written — https://reverseengineering.stackexchange.com/questions/3362/how-to-know-in-which-language-technology-program-exe-is-written
- Hints pointing to the compiler used — https://reverseengineering.stackexchange.com/questions/11/what-hints-in-machine-code-can-point-me-to-the-compiler-which-was-used-to-genera
- Reverse optimized integer division/modulo by constants — https://reverseengineering.stackexchange.com/questions/1397/how-can-i-reverse-optimized-integer-division-modulo-by-constant-operations
- Reverse engineer a PyInstaller EXE — https://reverseengineering.stackexchange.com/questions/160/how-do-you-reverse-engineer-an-exe-compiled-with-pyinstaller
- Decompiling .pyc files — https://reverseengineering.stackexchange.com/questions/1701/decompiling-pyc-files
- Reverse-engineer .so files in Android APKs — https://reverseengineering.stackexchange.com/questions/4624/how-do-i-reverse-engineer-so-files-found-in-android-apks
- Bypassing certificate pinning in Android — https://reverseengineering.stackexchange.com/questions/12212/bypassing-certificate-pinning-in-android
- Reverse engineer a Windows 10 UWP app — https://reverseengineering.stackexchange.com/questions/17127/how-to-reverse-engineer-a-windows-10-uwp-app
- Decompiling a 1990 DOS application — https://reverseengineering.stackexchange.com/questions/3074/decompiling-a-1990-dos-application
- Anti-debug techniques on Unix platforms — https://reverseengineering.stackexchange.com/questions/43/anti-debug-techniques-on-unix-platforms
- Why is disassembly not an exact science — https://reverseengineering.stackexchange.com/questions/2580/why-is-disassembly-not-an-exact-science
- Analyzing highly obfuscated JavaScript — https://reverseengineering.stackexchange.com/questions/1436/analyzing-highly-obfuscated-javascript
- How is a structure located within a disassembled program — https://reverseengineering.stackexchange.com/questions/4/how-is-a-structure-located-within-a-disassembled-program
- Purpose of mov edi, edi — https://reverseengineering.stackexchange.com/questions/250/what-is-the-purpose-of-mov-edi-edi
- r/ReverseEngineering top digest (mined via linked writeups; direct fetch blocked) — https://old.reddit.com/r/ReverseEngineering/top/?t=all
- Woodmann forum (blocked: domain parked/dead, archive.org timeout) — http://www.woodmann.com/forum/
