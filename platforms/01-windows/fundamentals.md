# Fundamentals (Root Category, Common Foundation of Reverse Engineering)

> Corresponding directory-tree node: Fundamentals [1000001] (24 child nodes, 25 nodes total by level).
> Positioning: the "foundation slab" of full-stack reverse engineering — CPU/assembly/PE/cryptography/OS/compiler toolchain. The foundations of every advanced chapter (Malware, Debugging, Unpacking) grow on this map.

## §1 CPU Architecture

### 1.1 x86/x64 Core Model

- **Register set (64-bit)**: `RAX RBX RCX RDX RSI RDI RBP RSP` + `R8-R15` + `RIP`; 32-bit view `EAX/…`, 16-bit `AX`, 8-bit `AL/AH`. x64 additions: R8-R15 and a changed set of non-volatile registers (RBX/RBP/RDI/RSI/R12-R15 preserved across calls).
- **Flags register RFLAGS**: for reverse engineering only `ZF` (equal/zero), `CF` (carry/unsigned less-than), `SF` (sign), `OF` (signed overflow) matter — the outcome of every conditional jump is decided by these four bits.
- **Instruction pointer RIP**: under x64 it cannot be read or written directly, only controlled indirectly (this is also the fundamental constraint behind ROP).
- **Microarchitecture common sense**: the impact of branch prediction and out-of-order execution on reverse engineering lies mainly in timing side channels (the meltdown/spectre family); see the "Binary Vulnerabilities" subtree.

### 1.2 ARM Overview (Cross-Reference)

Fixed 32-bit instruction length (A64 uses 32-bit encodings), load-store architecture (arithmetic never touches memory), specialized `PC/LR/SP`. Memorize by cross-reference when reversing Windows on ARM or mobile samples: `x0-x7` for arguments, `x29` frame pointer, `x30` return address.

### 1.3 The Three Pieces of "Reverse-Engineering Infrastructure" the CPU Provides

1. Debug registers (§2) — hardware breakpoints;
2. The single-step flag TF — the foundation of debugger stepping;
3. The breakpoint instruction `INT 3` (0xCC) — software breakpoints (the debugger swaps the target byte for CC and restores it after the hit).
   Anti-debugging exploits this in reverse: checking code sections for CC bytes, `INT 2D` anti-debug, TF detection (see the anti-tracing subtree of the Protection chapter).

## §2 Debug Registers (Node 1000003)

- **DR0-DR3**: four hardware breakpoint addresses (linear addresses);
- **DR6**: status register (which breakpoint fired, bits B0-B3);
- **DR7**: control register (2 enable bits per breakpoint + read/write/execute type + length of 1/2/4/8 bytes).
- **DR4/DR5**: aliases of DR6/DR7 respectively when CR4.DE=0; once DE=1 is set, accessing them raises #DB — a classic anti-debugging trick.
- **Why hardware breakpoints are strong**: they do not modify code bytes → CRC self-checking packers cannot detect them; the only downside is that there are just 4.
- From the debugger's perspective: the x64dbg "hardware breakpoint" option is essentially GetThreadContext setting Dr0-Dr7 in the CONTEXT structure; a packer detecting hardware breakpoints reads its own thread's CONTEXT for comparison.
- Single stepping: set the TF bit in RFLAGS, a #DB exception after every instruction → the debugger takes over step by step; trace/animated execution all rely on this.

## §3 Disassembly Engines

### 3.1 Two Algorithmic Routes (Disassembly Engine Principles 1001391)

| Route | Idea | Weakness |
|---|---|---|
| Linear sweep (linear) | Decode every instruction in order from the entry point | Data interleaved in code gets mis-decoded |
| Recursive descent | From the entry point, walk reachable code along control flow (call/jcc/ret) | Indirect jumps (function pointers/jump tables) become blind spots, requiring heuristic supplements |

IDA/Ghidra mainly use recursive descent + streaming patching; W32Dasm is the representative of the linear-sweep era. The knowledge-base classic posts "Build Your Own Disassembly Engine" (1000007) and "Notes on Developing a 32-bit Disassembly Engine" (1001473) are both hands-on tutorials for implementing ModRM/SIB decoding.

### 3.2 x86 Instruction Encoding Skeleton (Must-Know for Reverse Decoding)

```
[Prefix(66/F2/F3/REP…)] [Opcode 1-3B] [ModRM] [SIB] [Disp] [Imm]
ModRM = mod(2) | reg(3,register/opcode extension) | rm(3)
  mod=00 rm=101 → RIP-relative addressing (common x64 lea rax,[rip+xxx])
  mod=11 → direct register operation
SIB   = scale(2)|index(3)|base(3) → [base + index*2^scale + disp]
```

Variable-length instructions (1-15 bytes) are the soil for all x86 "junk-byte/overlapping-instruction" obfuscation (jmp into the middle of an instruction ahead of junk bytes, and linear disassembly immediately misaligns).

### 3.3 Mainstream Engine Selection

- **Capstone**: the de facto standard, lightweight with IDA lineage, Python bindings, first choice for scripted analysis;
- **Zydis**: modern C implementation, complete decode info (including implicit reads/writes);
- **distorm**: veteran, high performance;
- Self-build training route: per post 1000007, first hard-translate the one-byte opcode table → ModRM → prefixes → 16/32/64-bit contexts; a working prototype takes about two weeks.

## §4 Intel Manual Translation (Node 1000008)

The three volumes of the Intel SDM are the "constitution" of x86; the community organized a translation of all three volumes (three nodes in the tree):

- **Volume 1 Basic Architecture** (1001219): data types, registers, addressing modes — read through for beginners;
- **Volume 2 Instruction Set Reference A-Z** (1000009): per-instruction encoding formats and pseudocode — **the volume most frequently consulted during reverse engineering**, for ModRM semantics/edge behavior;
- **Volume 3 System Programming Guide** (1000010): segmentation and paging, interrupts and exceptions, VT-x, debug architecture — the foundation of kernel reversing and rootkit analysis.
- Practical advice: no need to read cover to cover. Build a retrieval-style usage habit of "look up instructions in Volume 2, mechanisms in Volume 3"; cross-check with the latest `Intel® 64 and IA-32 Architectures Software Developer's Manual` from the official site (the in-tree translation is based on an older edition; new instructions need collation).

## §5 Virtual Machine Applications (Node 1001202)

### 5.0 Virtualization Principles (How Virtualization Works 1001203 / Deep Dive into Virtualization 1001263)

- Two categories of "virtual machine" must be distinguished (both are called VM in a reverse-engineering context):
  1. **System virtualization**: VT-x (VMX non-root/root) + EPT second-level address translation, running a whole OS — VMware/Hyper-V/KVM;
  2. **Code virtualization (VM protection)**: translate x86 instructions into custom bytecode + an interpreter loop — VMProtect/Themida (see the virtual-machine subtree of the Protection chapter).
- Hardware virtualization core: sensitive instructions trigger VM-Exit into the hypervisor; EPT translates guest physical addresses through one more level; shadow page tables are obsolete.
- Detecting virtualization (the principle behind malware anti-sandboxing): CPUID leaf nodes, the hypervisor bit, the VMware backdoor (I/O port 0x5658), registry/driver/ACPI string fingerprints.

### 5.1 Virtual Machine Engine (1000713)

The in-tree positioning leans toward analyzing and writing "VM protection engines": handler table structure, dispatch loop (commonly `jmp [reg*4+table]`), virtual register context. Breaking approach: symbolic execution/trace comparison against the original instruction sequence (the classic three steps of VMProtect reversing: trace compression, handler identification, stack-balance verification).

### 5.2 bochs (1001204)

Pure-software full-system emulator (every instruction is interpreted, no hardware virtualization used) → the only tool capable of "physical-memory-level transparent debugging": 0day exploit debugging (no need to handle anti-debugging), MBR/Bootkit analysis (can break at the BIOS/boot stage), samples that detect VMProtect feel nothing under bochs. Price: 10-100x slower.

### 5.3 LLVM Obfuscation and the Qilin Framework (LLVM 1001397 / LLVM Obfuscation 1001372 / Armariris 1001373 / Qilin Framework 1001392)

- **OLLVM (Obfuscator-LLVM)**: works at the LLVM IR layer doing control-flow flattening (bogus-flow + dispatcher), bogus control flow, and instruction substitution (sub/xor triangular swapping). Injected once at compile time, extremely resistant to static analysis.
- **Armariris**: the community's open-source LLVM obfuscation framework (an upgraded and maintained OLLVM supporting newer LLVM versions, open-sourced on GitHub) — a dedicated in-tree node, representative of tools self-developed by the domestic reversing community.
- **Qilin framework**: an LLVM-based binary analysis/rewriting framework (tree node 1001392), used for binary instrumentation and symbolic-execution assistance.
- The three moves of deobfuscation: symbolic execution (angr, in-tree 1001369) + trace pruning (IDA plugins D810/deflat) / dynamic trace comparison to reconstruct the real CFG.

## §6 Decompilation Principles (Node 1001370)

- Input assembly → output C-like code; pipeline: disassembly (§3) → control-flow graph CFG → data-flow analysis (register/stack variable propagation) → type recovery → structuring (if/while reconstruction, loop detection + dominator tree) → syntax output.
- **Hex-Rays microcode**: IDA first lifts assembly to a machine-independent microcode layer and then optimizes; this layer is also open to plugins (its new API lets you write custom optimization passes for de-junking/de-flattening).
- Limitations: indirect calls cannot be recovered (cross information needed), C++ vtables/exceptions/templates are restored heuristically, self-modifying code fails outright.
- Peers: Ghidra (open source, SLEIGH processor description language), Binary Ninja (LLVM IR middle layer, the smoothest API), retdec (academic). The in-tree Ghidra node (1001389) contains two child nodes for scripting and techniques.

## §7 Compiler Principles (Node 1001614)

To "recognize" compiler output during reversing, you must understand the compilation chain:

```
Source → [lexical/syntax analysis] AST → [semantics] IR → [optimization] SSA/constant propagation/inlining/loop optimization
     → [backend] instruction selection/register allocation → assembly → assembler → object file → linker → PE/ELF
```

- **Optimization fingerprint identification** (for reverse attribution): under `O2` loops are unrolled/merged, `Release` builds have no stack frame (`push ebp;mov ebp,esp` missing → RBP is used as a general register), inlined functions have no call boundary — all side evidence for determining compiler/options/language.
- **Link-time essentials**: statically linked CRT (`__security_check_cookie`, the `_main` startup sequence), delay-load imports, relocations (ASLR companion, see §9 PE).
- C++ specifics: name mangling (`?func@@YAXH@Z` can be demangled directly to recover the signature), vtable structure, RTTI (the `type_info` chain can semi-automatically recover the class hierarchy — IDA's RTTI scan). The two C++ reversing posts (1000135/1000136) in the knowledge base's "32-bit Software Reverse Engineering" subtree are in-tree native deep-reading material.

## §8 General Reverse Engineering · Cryptography (Distilled from the Main Trunk of the Tree's "Encryption Algorithms" Subtree)

### 8.1 Symmetric Encryption

- **Block ciphers**: DES (64-bit block/56-bit key, obsolete), 3DES, **AES** (128/192/256-bit, standard in modern samples: ransomware session keys), Blowfish/IDEA/TEA/XTEA (favored by games and packers, extremely small footprint).
- **Modes**: ECB (same plaintext → same ciphertext → image encryption visibly leaks outlines, an identification clue), CBC/CTR/GCM; IV location and whether it is random are reverse-engineering priorities.
- **Stream ciphers**: RC4 (a regular in old RAT/protocol encryption, identified by the S-box initialization loop of 256 swaps), XOR streams (the favorite of illicit operators, commonly a fixed single byte or a rolling key).
- **Encoding, not encryption**: Base64 (trailing `=`, alphabet variants URL-safe/custom tables are common creators of an "encryption" illusion), hex.

### 8.2 Asymmetric

- **RSA**: big-number arithmetic (n/e/d, usually 1024-4096 bits); reverse identification: importing `BCryptEncrypt`/CryptoAPI's CALG_RSA_KEYX, or large integer constants appearing statically; ransomware = RSA public key encrypting the session key.
- **ECC/SM2**: mostly in commercial-cryptography-compliant products; SM2 has a dedicated in-tree node (1001270).
- **DH**: key agreement, common in protocol-type samples (C2 handshakes).

### 8.3 Hashes

- MD5 (128-bit, weakly collision-resistant but still widely used for checksums), SHA1/SHA256, CRC32 (file/network checksums, not a security hash). Identification: magic initialization constants — MD5's `0x67452301`, SHA1's `0x67452301 0xEFCDAB89`, SHA256's `0x6A09E667`, CRC32 table `0xEDB88320`. **Seeing these four constants immediately tells you what is being computed** — the number-one trick for identifying crypto algorithms in reverse engineering.
- Second trick: import table/signature APIs (`CryptAcquireContext`, `BCryptOpenAlgorithmProvider` — the parameter strings `"AES"`/`"SHA256"` leak it directly).
- Third trick: S-box constant tables (AES's 256-byte table starting `63 7C 77 7B F2 6B 6F C5…`; DES's PC1/PC2 permutation tables; TEA's delta `0x9E3779B9` — the most famous constant in the magic-number world).

### 8.4 Reverse-Engineering Workflow

1. Locate the algorithm by constants/APIs (the three tricks above) → 2. Parameters and mode (where the key comes from: hardcoded/derived/delivered online) → 3. Reproduce and cross-verify in Python/C (validate with a set of sample ciphertexts) → 4. Attack weaknesses (ECB replay, controllable IV, predictable keys, randomness using `rand(time(0))`). Keygen and ransomware "decryptable" analyses (e.g., the Solar LIVE post) all follow this flow.

## §9 PE In Depth (Corresponds to the Main Trunk of the Tree's "Internals — PE Format")

### 9.1 Overall Map

```
+---------------------+ 0x0
| DOS Header (MZ)     |  e_magic 'MZ'; e_lfanew → PE header offset
| DOS Stub            |  "This program cannot be run in DOS mode"
+---------------------+
| PE Signature 'PE\0\0'|
| File Header         |  Machine/NumberOfSections/TimeDateStamp/Characteristics
| Optional Header     |  AddressOfEntryPoint★/ImageBase/SectionAlignment/FileAlignment
|  (DataDirectory[16])|  EXPORT/IMPORT/RELOC/TLS/COM/RESOURCE… RVA+Size per directory
+---------------------+
| Section Headers[]   |  Name/VirtualSize/VirtualAddress/SizeOfRawData/PointerToRawData/Entropy
+---------------------+
| Sections .text/.data/.rsrc/.reloc …
| Overlay (appended data) |  Self-extractors/malicious payloads often hide here; the PE loader does not load it
+---------------------+
```

### 9.2 Five Must-Master Skills

1. **RVA↔VA↔file offset**: VA = ImageBase + RVA; file offset = RVA - section VirtualAddress + section PointerToRawData. Every "memory-breakpoint address can't produce a file patch" problem comes from not passing these three conversions.
2. **Import table (IAT)**: INT/IAT twin chains (Name/FirstThunk); bound imports (node 1001474) are a startup acceleration optimization; packed samples have a destroyed IAT → it must be rebuilt after unpacking (Scylla/ImportREC).
3. **TLS directory**: the favorite of anti-debugging — TLS callbacks execute **before** the entry point; functions in `AddressOfCallBacks` run ahead of the EP (the in-tree TLS node 1000154 is a dedicated topic). When analyzing a packer, always check TLS first.
4. **Relocation table (.reloc)**: when ASLR is in effect the loader fixes VAs per IMAGE_BASE_RELOCATION blocks; both DLLs and EXEs may carry it. Required coursework when manually relocating code/adding sections (the relocation node 1000768 of the Reconstruction chapter).
5. **Resources and Overlay**: the two big spots where droppers hide payloads; the file tail beyond `SizeOfImage` is the Overlay; one line of `pefile` `get_overlay_data` extracts it.

### 9.3 Quick Reference: PE Tricks Commonly Used by Malware

- Garbage section names/section attributes writable and executable (RWX) → packer/injection signature;
- `AddressOfEntryPoint` pointing at the last section → UPX-style compression packer;
- No import table + high-entropy sections → crypter;
- Certificate directory present but hash mismatch → signature forgery/grafting (routine for Silver Fox);
- Rich Header inconsistent with the declared compiler → forged PE headers to defeat attribution.
- Tools: 010 Editor + PE template (tree node 1001524), PE-bear, CFF Explorer, `pefile` for scripted batch processing.

## §10 x86/x64 Assembly Essentials (Reverse-Engineering View)

### 10.1 Calling Conventions (Check the Convention Before Reading a Function)

| Convention | Arguments | Stack cleanup | Scenario |
|---|---|---|---|
| cdecl | stack, right to left | caller | C default (32-bit), variadic |
| stdcall | stack, right to left | callee (ret n) | WinAPI (32-bit) |
| fastcall | ECX/EDX first, rest on stack | callee | MS extension |
| x64 (Microsoft) | RCX/RDX/R8/R9 + stack | caller, 32-byte shadow space | the only mainstream on Win x64 |
| x64 (SysV) | RDI/RSI/RDX/RCX/R8/R9 | caller | Linux/cross-platform |

x64 stack alignment is 16 bytes and the shadow space must be reserved — get this wrong in hook and injection code (Malware §4) and you crash.

### 10.2 Recognition Patterns for High-Level Structures

- **if/else**: `cmp/test` + `jcc` skipping one branch;
- **Loops**: counting down `dec ecx; jnz` / counting up `cmp i,n; jl`;
- **Array access**: `[reg + idx*4]` (SIB scale);
- **Virtual function call**: `mov rax,[rcx]` (fetch vtable) → `call [rax+offset]` — the first pattern to spot in C++ reversing;
- **Stack frames and locals**: `sub rsp,0x28` means a 0x28-byte local area reserved; under RELEASE, RSP-relative addressing replaces RBP;
- **String initialization**: long runs of `mov qword ptr [rsp+..], imm` mean an array/struct being constructed on the stack.

### 10.3 Practitioner Habits

If you can't read it, run it first: statically locate the function → break in x64dbg → watch the real arguments and return values, then come back to the code; cross-validate with IDA F5. Deep material: the in-tree "Instruction Encoding from the Ground Up" (1000019), "x64 Assembly" (1001396), "Learning C/C++ from the Assembly Perspective" (1001716).

## §11 Operating System Concepts (Underneath Windows)

### 11.1 Virtual Memory and Paging

- Every process gets 4GB (x64: 256TB) of independent virtual address space; `VirtualAlloc/VirtualProtect` are the cornerstone APIs of injection and packers.
- Paging: x86-64 four-level page tables (PML4→PDPT→PD→PT), page size 4KB (+2MB/1GB large pages); CR3 points to the page-table root.
- Conversion: `VA → (PML4, PDPT, PD, PT, Offset)` with 9 bits each; understanding page tables = the prerequisite course for understanding PatchGuard/hidden-process (DKOM) rootkits.
- Copy-on-Write, working sets, the PFN database — conceptual familiarity is enough.
- Practical links: a PE's SectionAlignment determines memory alignment (§9); ASLR works via the relocation table (§9.2-4).

### 11.2 Protection Rings (Ring0/Ring3)

- Ring3 user mode (default for applications/samples), Ring0 kernel mode (drivers/rootkits/AV core protection), Ring-1 hypervisor (VT virtualization, §5.0), SMM (an even deeper firmware layer).
- The privilege boundary relies on CPL + the page-table U/S bit + I/O privilege level; `syscall/sysenter` is the only legal upward channel (x64: syscall, MSR LSTAR points to KiSystemCall64 — the principle behind direct syscall calls for evasion, see Malware §4.2).
- SSDT (tree node 1000166): the System Service Descriptor Table; ntoskrnl exports `KeServiceDescriptorTable`, the classic battlefield of kernel hooks; after Win10+ the SSDT is no longer exported + PatchGuard protection, so the confrontation moved to kernel callbacks and driver filtering.

### 11.3 Interrupts and Exceptions

- **Interrupts** (asynchronous, hardware/software): IDT with 256 entries, `int n` indexes directly; the clock interrupt drives scheduling; `int 3` (0xCC)/`int 2d` is ground shared by debuggers and anti-debugging.
- **Exceptions** (synchronous, raised by CPU or software): #DE divide-by-zero, #PF page fault (copy-on-write/paging driven), #BP breakpoint, #GP protection violation.
- **SEH structured exception handling** (tree node 1000163): x86 chained via `FS:[0]` → exception registration records; x64 switched to table-driven (`RtlAddFunctionTable` + UNWIND_INFO unwind info, stack walking no longer depends on linked lists). Anti-debugging usage: SEH anti-debug (deliberate divide-by-zero, debugger detection inside the exception handler), VCH/VEH priority preemption. A packer's exception-driven decryption (raise an exception to trigger decoding) requires understanding this mechanism.
- Relationship with debuggers: the debugger seizes the exception first (first-chance/second-chance), and samples use this to probe for a debugger's presence.

## §12 Miscellaneous and Learning Path (Node 1000011 + Summary)

Miscellaneous nodes as fallback: character encodings (Appendix 1 common character tables), data formats (NTFS/PDF, Appendix 5), Windows System Call Table (Appendix 4) — lookup-type content, use as needed.

**The shortest loop from basics to practice**:

```
§10 assembly + §9 PE  ──→  open x64dbg/IDA without fear (Debugging / static analysis chapters)
§8  crypto identification ──→  crack keygens/recover C2 encryption (Unpacking / Malware chapters)
§11 OS concepts      ──→  injection/Hook/Rootkit no longer a black box (Programming chapter)
§3+§6 disassembly/decompilation principles ──→  write your own analysis tools (scripted auditing)
§5 virtualization   ──→  detection-free analysis environment + VMProtect-style packer offense and defense (Protection chapter)
```

## Summary of Representative Posts and References

| Topic | Node/Source | Origin |
|---|---|---|
| Build Your Own Disassembly Engine | Knowledge-base native node 1000007 | In-tree node |
| Notes on Developing a 32-bit Disassembly Engine | Knowledge-base native node 1001473 | In-tree node |
| Intel Manual Three-Volume Translation | Knowledge-base native nodes 1001219/1000009/1000010 | In-tree node |
| Iczelion's PE Tutorials | Knowledge-base native node 1000143 (child of PE Format Specification) | In-tree node |
| How Virtualization Works / Deep Dive into Virtualization | Knowledge-base native nodes 1001203/1001263 | In-tree node |
| Armariris (Amaryllis, LLVM obfuscation framework) | Knowledge-base node 1001373; GitHub GoSSIP-SJTU/Armariris (adds a string-obfuscation pass on top of OLLVM, now unmaintained) |
| Qilin Framework | Knowledge-base node 1001392 | In-tree node |
| Two C++ reversing posts (Learning C++ Reversing / C++ from a Reverse-Engineering Perspective) | Knowledge-base nodes 1000135/1000136 | In-tree node |
| Learning C/C++ from the Assembly Perspective | Knowledge-base node 1001716 | In-tree node |
| Capstone/Zydis engines | Official docs capstone-engine.org / zydis.re | General knowledge |
| Solar LIVE ransomware (cryptography case study) | See the Malware chapter | Cross-chapter reference |
