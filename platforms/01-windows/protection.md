# Protection (Part 5: Protection 1000616)

> Positioning: the full landscape of "anti-reverse-engineering" from the software author's perspective — anti-debugging, anti-tracing, junk-byte obfuscation, packers, virtual-machine protection — plus "anti-anti-tracing" from the researcher's perspective. Knowledge main line: every protection = detection principle → key APIs/structures → countermeasure techniques → representative posts.

## 1. Anti-Debugging Panorama (Node 1000672)

### 1.1 PEB / Process-Information Class (the Most-Used First Tier)

| Technique | Principle | Bypass |
|---|---|---|
| `IsDebuggerPresent` | reads PEB!BeingDebugged (fs:[30]+2) | zero the PEB byte; ScyllaHide |
| `CheckRemoteDebuggerPresent` | internally just NtQueryInformationProcess(ProcessDebugPort) | see below |
| `NtQueryInformationProcess(ProcessDebugPort=7)` | returns the debug port when debugged (non-0/-1) | change the return value/argument; an x64dbg plugin patches argument 7 |
| `NtQueryInformationProcess(ProcessDebugObjectHandle=0x1E)` | queries the debug-object handle; a valid handle is returned when debugged | hook it and clear the return value |
| `NtQueryInformationProcess(ProcessDebugFlags=0x1F)` | returns NoDebugInherit, which is 0 when debugged (mind the inverted logic) | make it return 1 |
| PEB!NtGlobalFlag (fs:[30]+0x68) | a debugger-created process sets FLG_HEAP_ENABLE_TAIL_CHECK etc. | zero it |
| PEB!ProcessHeap heap markers | Flags/ForceFlags grow because of the debug heap | restore normal values (0x02/…) |
| `NtSetInformationThread(ThreadHideFromDebugger=0x11)` | hides the thread from the debugger (exceptions no longer notified) | hook the call and NOP it |
| `NtQueryObject` object enumeration | a DebugObject-type handle appears in the process | hide the handle/rename the type |
| `NtQuerySystemInformation(SystemKernelDebuggerInformation)` | queries the kernel debugger (KdEnabled) | only trips under dual-machine debugging |

Representative posts: Learning Windows-Platform Anti-Debugging Techniques, Windows Anti-Debugging Techniques, A Simple Summary of Windows Software Anti-Debugging, Summary of Anti-Debugging Techniques, A First Look at the Windows Debugging Infrastructure.

### 1.2 Breakpoint/Context Class

- **INT3 detection**: self-checks of key function heads/code sections; spotting 0xCC means exit; CRC/byte-by-byte scans (see §5.2). Bypass: hardware breakpoints DRx instead of INT3; or patch the check first.
- **Hardware-breakpoint detection**: `GetThreadContext` reads DR0-DR7; non-zero means breakpoints exist. Bypass: ScyllaHide clears DRx / use a one-shot single-step restore.
- **Single-step detection**: check EFLAGS.TF; or a Trap Flag self-check (pushf, set TF, popf, triggering a self-exception).
- Inconsistent thread contexts: GetThreadContext on every thread; DebugReg is non-zero only on the thread holding the breakpoint.

### 1.3 Timing Detection (Node: same origin as Time Limits 1000231)

```
t1 = rdtsc / GetTickCount / QueryPerformanceCounter / timeGetTime
  …a stretch of dense computation…
t2 = same as above
if (t2 - t1 > threshold) → conclude single-stepping/breakpoint slowdown → self-destruct
```
- `rdtsc` (usable at privilege level 3, nanosecond resolution) is the most common; mind multi-core TSC drift.
- Bypass: hook rdtsc to return a fake delta (ScyllaHide's Fake rdtsc: replay "plausible deltas"); or patch the comparison jump.

### 1.4 Exception-Based Anti-Debugging

- **Int 3 / Int 2D**: when debugged, Int 2D makes the debugger "eat" one instruction (causing subsequent misalignment); the program installs its own SEH/VEH — without a debugger the exception returns to its own handler — the execution-path divergence is the detection.
- **Invalid handle**: `CloseHandle(0x1234)`/`RaiseException(STATUS_INVALID_HANDLE)` — the process receives this exception notification only when a debug object exists; the program branches accordingly.
- **INT 1 single-step chain**: run a stretch with continuously pushed single-step flags; any external takeover interrupts the chain.
- Counterplay: the debugger "passes all exceptions back to the program" (x64dbg: all-pass exception options; OD: ignore ranges), or ScyllaHide exception masquerading.

### 1.5 Exploiting OllyDbg Vulnerabilities (Anti-OD Node 1000673)

- Window detection: `FindWindowA(NULL,"OLLYDBG")`/by class name `OLLYDBG`; enumerate process names ollydbg.exe/x32dbg.exe/idag.exe/WinDbg… (window-method detection node 1000681).
- OD 1.x historical vulnerabilities exploited by programs: format-string crashes (e.g., OD's command bar/loaded DLL name handling), LoadDll plugin out-of-bounds, heap residue after Ctrl+F2 reload, crashes on special characters in paths, etc. — "crafting input that crashes the debugger" is Anti-OD.
- Counterplay: change window titles/process names; use phantOm/StrongOD/ScyllaHide; switch to x64dbg.

### 1.6 Anti-Anti-Debugging Tool Overview

ScyllaHide (x64dbg/OD plugin grade), phantOm, SharpOD, the TitanEngine hiding layer; kernel grade: TNB (old), Hypervisor-layer hiding (VT, echoing the Internals chapter's VT node). Principle = "forge normal values" at the detection points: PEB fields, NtQIP returns, rdtsc, handle enumeration, GetThreadContext's DRx.

## 2. Anti-Tracing and Anti-Environment (Anti-Trace/VM/Sandbox, Nodes 1000676-1000865)

- **Anti-Trace**: TF-flag detection, SEH anti-single-step (validating the return address inside the handler), code checks (see §5.2).
- **Anti-ICE** (SoftICE): `CreateFileA("\\\\.\\SICE")` (Win9x)/`"\\\\.\\NTICE"` (NT/2000) — a successful open (`<>INVALID_HANDLE_VALUE`) means it is loaded; close the handle and set the flag — full Delphi code in "Detecting SoftICE (Delphi edition)": `hFile:=CreateFileA('\\.\SICE',GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0)`; also "DS2.x Detecting SoftICE", "SoftICE Internals (1)". The classic `int 68h` (SoftICE occupies the INT 68h vector) and the int 1 single-step trap method are community oral traditions; the counterplay of hiding/renaming drivers is in §8 hidetoolz.
- **Anti-Loader**: detect how it was loaded (process handles held by the loader/non-explorer.exe parent/odd startup directory); aimed at "Loader-style" cracks (decrypted then launched by a Loader).
- **Anti-ImpREC/Anti-W32dasm**: ImpREC rebuilds the import table when repairing the IAT — the program detects the repaired import table (function addresses outside the shell's proxy region)/exploits W32dasm disassembly bugs to crash (e.g., malformed instructions).
- **Anti-VMware**: registry keys (`HKLM\HARDWARE\DESCRIPTION\System\BIOS` containing VMware), `CPUID` leaves, I/O port `in eax,dx` (0x5658 "VMXh"), sidt reading the IDT base to probe (red pill), MAC prefix 00:0C:29, svga/ioregistry files.
- **Anti-VirtualPC**: similar; port/instruction latency (VPC's CPUID is slow), the registry's Virtual Machine services.
- **Anti-sandbox** (1001489): detect small memory/few CPU cores, `IsDebuggerPresent`+parent process name, an unmoved mouse (`GetCursorPos` sampling), big `Sleep` loops to outlast sandbox timeouts, sandbox time-acceleration detection (implausible deltas between two GetTickCount calls), rarely-hit APIs (APIs never landing under virtual execution).
- General counterplay: environment-masquerading tools (VBox/VMware modification patches), or patch the jump at the detection branch directly; in dynamic analysis, do a "detection-point sweep" before talking logic.

## 3. Junk-Byte Obfuscation (Node 1000666)

### 3.1 Principle

Exploits the weakness of **linear-sweep disassemblers** decoding byte by byte: stuff junk bytes into the instruction stream to misalign it; at real execution time these bytes are either skipped or consumed as part of an instruction.

```
        call  $+5                 ; E8 00 00 00 00  → pushes the next address
        pop   eax                 ; eax = current address (fetch EIP)
        add   eax, 0x0C           ; compute the target
        jmp   eax                 ; jump away
        db    0xE8                ; ← junk: linear disassembly takes it as the start of a call operand
        ...                        ;   real control flow never executes here, but the disassembler misaligns the whole segment
```
Classic flavors: `jmp $+2` followed by junk bytes; `push immediate + ret` (jump to the immediate); overlapping instructions (the same byte is both the end of one instruction and the start of the next); equivalent-instruction substitution (xchg for mov, etc.) to scramble signatures.

### 3.2 Counterplay

1. By hand: in IDA patch the junk bytes to NOP (0x90) or U (undefine) then C (re-code);
2. Scripted: IDAPython/x64dbg scripts batch-patch by signature (`E8 00000000 58 83 C0 xx FF E0` etc.);
3. Recursive-descent disassemblers (IDA defaults to following control flow from the entry) are naturally immune to some junk bytes for "jump-reachable" code, but still get lost on indirect jumps (eax) → fill in the paths with dynamic tracing;
4. Take the real path from an execution trace (Unicorn/UnicornFlux-like) and backfill.

Representative posts: "Manually Removing Junk Bytes", "Some Junk Bytes in SVKP", "A Small Study of Junk Bytes", "A Script for Removing Junk Bytes", "Code for Removing Junk Bytes", "Randomly Generating Junk Bytes with Math Expressions", "Sharing a Few C-Language Junk-Byte Macros", "Recognizing Junk Bytes", "Removal-Resistant Junk Bytes", "A Study of Junk Bytes in TSSafeEdit", "Instruction Inflation and Junk-Byte Insertion".

## 4. Defeating Static Analysis (the Rest of Node 1000664)

- **SMC self-modifying code** (1000665): the code decrypts/encrypts itself at runtime (xor/stream cipher, decrypt a section, execute, destroy); analysis must be dynamic or dump the decrypted section first.
- **Information hiding** (1000667): strings never hit the string table — stack construction (`push 'x';push 'y'…`), runtime decryption (keygen authors often hide API names/prompts this way), resource encryption.
- **Code mutation** (1000668): the same functionality generates a different instruction sequence every time (mutation engines, originating from virus polymorphism), combined with garbage instructions.
- **Code obfuscation** (1000669): control-flow flattening (a switch dispatcher wrapping all basic blocks), bogus control flow, bogus jumps; the modern representative is OLLVM (1001421) and its Chinese branch Armariris — **Android .so obfuscation also uses OLLVM, but that part belongs to the Android chapter**; only Windows/general principles are collected here.
- **Polymorphic engines** (1000670): the decryption header mutates each generation (cross-reference to virus technology, details in the Malware chapter).

## 5. Software Protection Techniques (Node 1000617)

### 5.1 API Self-Implementation (1000620)

- Write your own `GetProcAddress`: walk the kernel32 export table (find the base via PEB_Ldr → PE header → export RVA → binary search by name/sequential with _hint) or compare by hash, dodging IAT breakpoints and string references;
- Write your own `LoadLibrary`/`GetModuleHandle` (1000622/1000623): forward directly to LdrLoadDll or find the module on the PEB_LDR_DATA chains;
- Reverse counterplay: researchers use lower-level breakpoints (NtMapViewOfSection/LdrLoadDll) or memory searches.

### 5.2 File-Integrity Checks (1000626)

- Self-check: at runtime read its own file/code section, compute CRC32/MD5, compare against an embedded value; anti-patch (both file patches and memory patches break it).
- **Anti-memory checks** (1000628): validate the in-memory code section (catching memory patches/inline hooks); paired with anti-memory-surveillance (1000629: detecting OpenProcess handles/traces of debugger memory reads).
- Cracking: locate the check function and patch it to always-true first; or use DRx patches that leave no bytes (see Reconstruction §2.3); the advanced countermeasure is "the check function itself wrapped in junk bytes + VM".

### 5.3 Dual-Process Protection (1000630)

```
Main process ←OpenProcess/shared memory/pipes→ guardian process
   mutual CRC checks of code sections, exchanged heartbeats
```
Cracking: kill both together (hang breakpoints on the IPC), sever the communication (plug the named pipes/events), or DLL-hijack both sides LD_PRELOAD-style. Game protection (TP/HS/GPK) is its industrial-strength version (§6.5).

## 6. Packer Protection: Principles, Unpacking, and Writing Packers (Node 1000697 + the Unpacking Chapter's Packer Tree)

### 6.1 Packer Classification and Execution Flow

```
Packed file:  [packer code section (new entry)] [compressed/encrypted original program] [original resources/relocations…]
Execution:
 OEP' = packer entry
  ① Anti-debugging/anti-VM self-checks
  ② VirtualAlloc memory → decompress/decrypt each original section
  ③ Process relocations (if the base changed)
  ④ Rebuild/parse the IAT (LoadLibrary+GetProcAddress one by one, or redirect the IAT to shell proxies)
  ⑤ Restore TLS/resources/stolen-bytes backfill
  ⑥ jmp OEP (the original program's real entry)  ← the unpacker's moment
```

- Compression packers (UPX/ASPack/PECompact/nSpack): goal is smaller size, weak protection; crypter packers (ASProtect/ACProtect/Armadillo/Enigma/Safengine): the full anti-debugging suite + stolen code + IAT obfuscation; VM packers (Themida/VMProtect/Code Virtualizer): key functions turned into bytecode (§6.6).
- **Driver packers** (1000709): the ring0 segment participates (driver loading, SSDT/process protection); confrontation requires kernel debugging.
- **Spoofing packer detection** (1000699): forge section names/entry signatures/fake bytes at the EP region so PEiD/DIE misidentify.

### 6.2 The Generic Unpacking Flow (the Confrontation Main Line)

1. **Finding the OEP** (1000291): memory access breakpoints ("access after write" on the .text region), the ESP trick (pairing the shell entry's `pushad`/`popad`), Run trace, `bp GetVersion/GetCommandLine` as common OEP outposts; with stolen code the OEP itself is stolen and needs manual restoration;
2. **Dump** (1000292-1000294): at the OEP use a tool (PETools/Scylla) to grab the memory image; mind SizeOfImage/alignment;
3. **Rebuild the import table** (1000295): ImpREC/Scylla find the real IAT (distinguishing shell-proxy forwarding), trim invalid entries, generate a new import table;
4. **Fix relocations/export table/appended data** (1000296-1000299); PE optimization (1000302).
5. **Anti-Dump counterplay**: the shell wipes the PE header (DOS/NT headers zeroed) → refill the header by hand; shrink ImageSize in the PEB → restore it; the shell makes section attributes weird → restore. The anti-anti-tracing node (1000684) is exactly this.
- Unpackers (1000303-1000305): static (the UPX-official -d kind)/dynamic (scripted runs of the flow).

### 6.3 The Packer-Writing Route (Shell-Writing Nodes)

Ordinary packers (1000707): section merging/compression engine (aPLib/LZMA) → shell-entry assembly → load-and-restore logic; advanced: stolen-code generation (1000700), IAT protection (1000702), resource handling (1000704), PE loader (1000705), driver packers (1000709). The "software protection packer special topic" (1000710)/"notes on learning to write a compression packer" (1000708) are the entry main line.

### 6.4 Confrontation Notes per Packer Generation (the Unpacking chapter's packer-instance tree, by version)

UPX (1000461)/ASProtect (1000335, SDK+Stolen+Advanced Import)/ACProtect (1000311)/Armadillo (1000326, dual process+CopyMem)/Themida (1000458, VM)/Enigma (1000372)/SafeDisc (1000439, CD)/SecuROM (1000444)…… the knowledge base collected offense-defense posts version by version; the ideas are variations of §6.2.

### 6.5 Commercialized Protection (Node 1000688)

- Hardware dongles: Feitian, SenseLock, Sentinel HASP, Aladdin, Wibu — API interaction + hardware algorithms; cracking = emulating the dongle (SRW-class tools) or patching the communication layer;
- Flexlm (1000648): license files + machine fingerprint; the LM_X (grace/emergency) crack is a classic;
- Game protection (1000654): nProtect GameGuard, TP (Tencent), HackShield, XTrap, GPK, NGS, XIGNCODE3 — driver-grade anti-debugging + anti-memory-read + anti-injection; the confrontation lives at the ring0 and VT layers (details involve kernel confrontation; the main posts belong to the Programming chapter/drivers).

### 6.6 The VMProtect Special Section (Node 1000716)

**Principle**: compile the protected function's native instructions into custom bytecode, interpreted by an outer handler loop:

```
       VMEntry: save the native context (general registers/flags) into the VM Context (VBKI/VFrame)
          │
          ▼
   ┌─────────────────────────────┐
   │ VMLoop:  fetch bytecode     │
   │   decode (scrambled operands/rolling key/instruction aliases)
   │   dispatch → handler N      │  ← the handler order changes every compiled generation
   │   a handler executes one "virtual instruction" │     (push/pop/arithmetic/memory/flow control)
   │   update the VIP (virtual IP)│
   └─────────────────────────────┘
          │
          ▼
       VMExit: restore the context, return to native code
```

- Protection levels: Virtualization (pure VM)/Mutation (mutated but native)/Ultra (both stacked); the SDK marks regions with `VMProtectBegin/End` (or the Ultra marker); the licensing SDK binds to the machine.
- **Analysis approach** (the main line of the knowledge-base VMProtect reversing node 1000718):
  1. Start from the VMEntry; recognize the Context layout and the bytecode pointer;
  2. Extract the handler table (often via jump tables/computed indices); classify each handler's semantics;
  3. Write a trace: record the (VIP, handler, stack-effect) sequence → restore the virtual instructions → return to native logic; Unicorn-emulated execution can automate this;
  4. For the Mutation parts, de-junk first (§3) then read;
  5. In practice full disassembly is often unnecessary: locate the key comparison point (e.g., the license check), then patch the decision site/bypass the VM call boundary.
- Peers: Code Virtualizer (Oreans, same family as Themida), the Themida VM (node 1000723 has a 1.8 Demo VM analysis post), the Safengine VM.
- Searches: VMProtect — "A Small Peek at the VMProtect Virtual Machine", "Another Small Peek at the VMProtect Virtual Machine", "VMProtect Usage Tips", "A Simple Analysis of VMProtect", "VMProtect Entering the Virtual Machine", "A Different Approach: Analyzing VMProtect", "A Collection of VMProtect 1.2x Tricks", "VMProtect 1.20 Pseudo-Instruction Summary"; Themida — "Themida V1.1.1.0", "Themida Kernel Reverse-Engineering", "The Themida VM Decoder", "A Brief Introduction to the Themida Virtual Machine", "Themida VM Analysis — Mutated-Code Cleanup", "A Preliminary Study of Themida (the ANTI part)".

## 7. Anti-Anti-Tracing (Node 1000682)

- Anti-Anti-Debug (1000683) = the §1.6 toolbox;
- Anti-Anti-Dump (1000684) = step 5 of §6.2 (restore the wiped PE header/Size);
- hidetoolz (1000685): hide designated processes/handles (driver grade) so the target cannot enumerate the analysis tools;
- Hiding regmon/filemon (1000686): rename the drivers to dodge detection — "changing names" is the generic move against tool-signature detection.

## 8. Representative Posts and Search Index

- Learning Windows-Platform Anti-Debugging Techniques — IsDebuggerPresent/NtQIP bypass, x64dbg hands-on
- Windows anti-debugging techniques
- A simple summary of Windows software anti-debugging
- Summary of anti-debugging techniques
- A first look at the Windows debugging infrastructure

Junk-byte counterplay → the §3.2 list; SMC self-modification → "SMC Tutorial", "SMC Reflections", "Multi-Layer SMC Technology Injection in the Akala Password Shell", "An ASP Component with a Two-Layer SMC Compression Shell", "A Few SMC Code Samples"; packer OEP location → "The OEP of ASPack", "Finding the OEP via Stack Balance", "An Idea for Discovering the OEP", "ACProtect 1.21: Hunting the Fake OEP", "Principle Analysis of Generic OEP Finder"; IAT repair → "Asprotect 2.x OEP+IAT Repair"; Armadillo dual process → "①Armadillo 1.8x-2.x", "Armadillo 3.x: Finding the OEP and Repairing the Code"; Anti-VMware → "Detecting Whether a Program Runs Under VMware", "Two Virtual-Machine Detection Techniques", "A Small Try at anti-VMware", "The VMware Backdoor"; old anti-sandbox posts are few; modern posts dominate.

Related chapters: Internals (the PEB/SEH/system-call foundation), Reconstruction (patches versus self-checks), Debugging (the tool side, by another author).
