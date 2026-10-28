# Knowledge Base · Windows Security · Part 1: Basics

> The main line derives from the *Encryption & Decryption* system. This part covers the entire foundation needed for reverse engineering on the Windows platform: assembly, PE structure, Windows core data structures, the API system, disassembly engines, and static analysis techniques.

## 1. Assembly Basics (Tree Nodes 1000014~1000024)

### 1.1 Concept

x86/x64 assembly is the "mother tongue" of Windows reverse engineering. The knowledge base splits assembly basics into six child nodes: assembly knowledge, assembly instructions, assembly topics, assembly tutorials, instruction encoding from the ground up, and inline assembly. Learning assembly from a reverse-engineering perspective differs from forward development: the emphasis is on **recognizing the instruction-level shapes of high-level language structures** (calling conventions, stack frames, loop patterns, virtual function table calls), not on being able to write it.

### 1.2 Key Registers and Common Instructions

```
General-purpose registers (x86): EAX EBX ECX EDX ESI EDI EBP ESP
Special registers: EIP (instruction pointer) EFLAGS (flags)
Segment registers: CS DS ES FS GS        ; x86: FS=[TEB], x64: GS=[TEB]
Debug registers: DR0~DR3 (breakpoint addresses) DR6 (status) DR7 (control)  ; see the Debugging chapter
Control registers: CR0 (PE bit/PG bit) CR2 CR3 (page directory) CR4
```

| Instruction | Reverse-engineering meaning |
|---|---|
| `mov/cmovcc/xchg` | Data movement; `cmov` is a trace of branchless optimization |
| `lea` | Address computation, often used for "multiply/add" optimization (lea eax,[eax+eax*4]) |
| `push/call/ret/add esp,N` | The keys to calling-convention identification |
| `test/jz`, `cmp/jcc` | Branching and validation logic |
| `imul/idiv` | Multiply/divide; division by a constant becomes magic-number multiplication |
| `rep stosd/movsd` | Struct/buffer initialization and copying |
| `cdq+idiv` | Standard for signed division |

### 1.3 Calling Conventions (Core to Identifying Compilers and Recovering Function Signatures)

| Convention | Argument location | Stack cleaner | Typical scenario |
|---|---|---|---|
| __cdecl | stack, right to left | caller (`add esp,N`) | VC/C runtime default |
| __stdcall | stack, right to left | callee (`ret N`) | the vast majority of Win32 API |
| __fastcall | ECX/EDX first two, rest on stack | callee | Borland/some drivers |
| thiscall | ECX=this, rest on stack | callee | VC member functions |
| x64 System V / Win64 | RCX/RDX/R8/R9 (Win64) + stack | caller (shadow space 0x20) | all of x64 |

Reverse-engineering essentials: whether `call` is followed by `add esp`, whether `ret` carries an immediate, whether ECX holds an object pointer — the combination of the three pins down the calling convention, and from there the argument count.

### 1.4 Stack Frame Structure (Main Line of the Assembly Tutorials)

```
High address
  ┌──────────────┐
  │ Caller locals │
  │ Arguments (pushed in reverse) │
  ├──────────────┤
  │ Return address pushed by CALL │ ← where ESP points (the instant the function is entered)
  ├──────────────┤
  │ PUSH EBP      │
  │ MOV EBP,ESP   │ ← EBP becomes the frame base
  ├──────────────┤
  │ Local variables │ EBP-4, EBP-8 ...
  │ Saved EBX/ESI/EDI │
  ├──────────────┤
  │ Temporary arguments before CALL │ incoming arguments start at EBP+C
Low address
```

Function identification experience: `push ebp; mov ebp,esp` is the standard prologue; VC6 commonly shows `sub esp,N; push ebx; push esi; push edi; lea edi,[ebp-xxx]; mov ecx,N/4; mov eax,0xCCCCCCCC; rep stosd` (Debug-build int3 fill).

### 1.5 Instruction Encoding (Instruction Encoding from the Ground Up 1000019)

x86 variable-length instructions are 1~15 bytes, in the format:

```
[Legacy prefixes][REX(x64)][Opcode 1~3B][ModRM][SIB][Disp 0/1/2/4][Imm 0/1/2/4]
ModRM = Mod(2) | Reg(3) | R/M(3);  SIB = Scale(2) | Index(3) | Base(3)
```

Reverse-engineering value: hand-patching machine code (patches/patching out checks), recognizing junk bytes (inserting equivalent prefixes to create misalignment), hand-writing a disassembly engine (§5). Examples: `EB 05` (jmp +5) and junk bytes after `E8` are common packer interference; `0x0F 0x8x` are two-byte jcc near forms.

### 1.6 x64 Assembly Differences (IA-64 Architecture 1000022 → x64 Assembly 1001396)

- 16 general-purpose registers RAX~R15; the default operand size is 32-bit (writing EAX auto zero-extends).
- Arguments moved to registers (RCX/RDX/R8/R9); the caller reserves a 32-byte shadow space.
- The vast majority of `push/pop` stack passing disappears; stack alignment is 16 bytes.
- `RIP-relative` addressing: `lea rax,[rip+0x1234]` replaces absolute addresses, in tandem with ASLR.
- x86 programs run on x64 systems via WoW64 (tree node 1001482, see the Internals chapter).

### 1.7 Data Alignment (1000020)

Struct members are aligned to their own size (`#pragma pack` changes this); x86 allows unaligned access (slow), while verification instructions (e.g. `movdqa`) that force alignment will fault. Used in reverse engineering to: **restore struct layouts**, diagnose "pointer 4-byte/8-byte" truncation errors, and analyze residual data in alignment padding.

### 1.8 Floating-Point Formats (1000021)

The x87 FPU stack (ST0~ST7, 80-bit extended precision) has ceded to SSE (XMM0~XMM7, 128-bit). IEEE754 single/double layouts: `[sign 1][exponent 8/11][mantissa 23/52]`. Recognizing floating-point comparisons: the `ucomiss/ucomisd + seta/setb` family; `fld qword ptr [x]` is the old compilers' constant load of choice. Must-know for game/graphics reversing.

### 1.9 Practical Essentials

1. When facing an unfamiliar code section, first read the "prologue + stack cleanup" to pin the calling convention and argument count.
2. `rep stosd` bulk 0xCC/0x0 fill → Debug build, symbol-friendly, prioritize static reading.
3. Big divisions replaced by magic-number multiplication (e.g. an `imul` + `shr` combo); when restoring, use `/magic` to back out the divisor.
4. Control-flow recovery: for small loop bodies, first count the `jcc` back-edges.

### 1.10 Representative Posts

- The "Instruction Encoding from the Ground Up" series — knowledge-base node 1000019; "Parsing the x86 Instruction Encoding Format", "Notes on Learning Intel 32-bit Instruction Encoding", "Floating-Point Processing and Instruction Encoding"
- "Assembly Topics" — knowledge-base node 1000017
- "C++ from a Reverse-Engineering Perspective" (1000136) — the classic on recognizing C++ structures at the assembly layer
- Implementing an LLIL-based x86/x64 static analysis framework (a newer post from around 2025; reference for x86/x64 instruction-layer analysis engineering)
- Modern supplement: knowledge-base search terms "instruction encoding" and "calling convention"; the chm-search page locates them directly

## 2. PE Structure (Tree Node 1000141, formerly under Part 4)

### 2.1 Concept

PE (Portable Executable) is the unified format of Windows executables (EXE/DLL/SYS/OCX), derived from COFF. The four big reverse-engineering needs: repairing the PE after unpacking, hand-crafting a PE (patching/adding sections), recognizing packed/mutated binaries, and writing parsers. The knowledge base's PE Format node contains: Iczelion's PE Tutorials (1000143), basic concepts (COFF/PE alignment/PE checksum/RVA-VA 1000144~1000148), sections, the import table, the export table, the relocation table (ASLR), resources, TLS, appended data, PE file loading, writing PE analysis tools, and hand-crafting a PE.

### 2.2 Overall Layout (ASCII Restoration)

```
+------------------------+  offset 0
| MS-DOS Header (0x40B)  |  e_magic 'MZ'; e_lfanew → NT header offset
+------------------------+
| DOS Stub ("This prog..")|
+------------------------+  at e_lfanew
| Signature 'PE\0\0'     |
| IMAGE_FILE_HEADER      |  Machine/NumberOfSections/TimeDateStamp/
|   (20B)                |  PointerToSymbolTable/SizeOfOptionalHeader/Characteristics
| IMAGE_OPTIONAL_HEADER  |  Magic(0x10B=PE32/0x20B=PE32+)
|   PE32: 0xE0 B         |  AddressOfEntryPoint★/ImageBase★/SectionAlignment/
|                        |  FileAlignment/SizeOfImage/Subsystem/DllCharacteristics/
|                        |  NumberOfRvaAndSizes(16) + DataDirectory[16]★
+------------------------+
| Section Headers ×N     |  IMAGE_SECTION_HEADER (40B each):
|  .text .data .rsrc ... |  VirtualSize/VirtualAddress★/SizeOfRawData/
|                        |  PointerToRawData★/Characteristics(RWX)
+------------------------+
| Sections raw data (.text)| File Offset ↔ RVA conversion:
|  .data .rdata .rsrc    |  RVA = VA - ImageBase
|  .reloc ...            |  within a section: Offset = RVA - SectionVA + SectionRaw
+------------------------+
| Overlay (appended data 1000155)| appended at file tail, e.g. self-extractor/signature; the loader does not map it
+------------------------+
```

RVA→file-offset conversion is the first hurdle in manually repairing a packer-dumped PE: section-table alignment (FileAlignment usually 0x200, in-memory SectionAlignment usually 0x1000) mismatches, and packers often deliberately corrupt SizeOfRawData so the dump won't run directly.

### 2.3 The Data Directory Table (1001252)

```
IMAGE_DATA_DIRECTORY[16]: {VirtualAddress, Size} pairs
 0 EXPORT   export table (.edata)     1 IMPORT  import table★
 2 RESOURCE resources (.rsrc)          3 EXCEPTION exceptions (.pdata, x64 SEH table)
 4 SECURITY certificate (file offset!) 5 BASERELOC relocations★
 6 DEBUG    debug directory (pdb path!) 7 ARCHITECTURE 8 GLOBALPTR
 9 TLS★     TLS directory            10 LOAD_CONFIG (CFG/security cookie)
11 BOUND_IMPORT bound imports (1001474) 12 IAT★ (the import address table itself)
13 DELAY_IMPORT delay-load imports     14 CLR (.NET metadata)
15 reserved
```

Reverse-engineering essentials: the DEBUG directory directly exposes the build machine's pdb path and GUID — use it to pair symbols; the IAT directory's Size is the verification baseline for IAT repair (Unpacking chapter); packers often zero out the import-table directory to hide dependencies.

### 2.4 The Import Table / Import Address Table (1000150, the Most Critical Table in Reverse Engineering)

```
Before loading (in file):                   After loading (in memory):
IMAGE_IMPORT_DESCRIPTOR array               IAT entries overwritten by the loader:
  OriginalFirstThunk(INT/RVA)→   INT/IAT array            IAT array
  TimeDateStamp                   [0x77xxxxxx]→user32.MsgBox  [real address of MessageBoxW]
  ForwarderChain                  [0x77yyyyyy]→kernel32.  [real address of LoadLibraryA]
  Name(RVA)→"USER32.dll"          ...
  FirstThunk(IAT/RVA)★            last entry 0 terminator
terminated by an all-zero Descriptor
```

- Twin bridges: OriginalFirstThunk (INT, preserves names) and FirstThunk (IAT, overwritten with real function addresses after loading). Old linkers may have only FirstThunk.
- IMAGE_IMPORT_BY_NAME: {Hint(2B), Name(ASCIIZ)}.
- **Bound imports (1001474)**: addresses pre-written + timestamp verification; the loader skips resolution for speed — a nuisance when unpacking.
- Delay-load imports (DELAY_IMPORT): resolved via `__delayLoadHelper` on first call.
- Repairing the IAT (essential for unpacking): see Unpacking §3.5.

### 2.5 The Export Table (1000151)

```
IMAGE_EXPORT_DIRECTORY:
  Characteristics / TimeDateStamp / Name(RVA→"MyLib.dll")
  Base (ordinal base) ★NumberOfFunctions / NumberOfNames
  AddressOfFunctions (RVA array, indexed by ordinal-Base)
  AddressOfNameOrdinals (ordinal array) / AddressOfNames (name RVA array)
Name→address lookup: binary search/walk Names → index → Ordinals[index] → Functions[ord]
```

Reverse-engineering value: constructing export tables when writing DLL hijacks/forwarders; a packer's export forwarding (ASProtect SDK); interposing forwarders (a Forwarder RVA pointing to a "dll.func" string).

### 2.6 The Relocation Table (1000152, ASLR 1001425)

```
IMAGE_BASE_RELOCATION: {VirtualAddress (page base), SizeOfBlock}
followed by a number of WORD entries: high 4 bits = type (3=HIGHLOW, 10=DIR64), low 12 bits = in-page offset
at load time, if actual base ≠ ImageBase: *target += delta
```

- EXEs usually load at the preferred base and need no relocation; DLLs/SYS always have `.reloc`.
- ASLR (Vista+, DllCharacteristics DYNAMIC_BASE) randomizes the load base every time.
- After a packer dump, if you dump straight at the new base, `.reloc` becomes invalid or must be recomputed — fix entries by hand.

### 2.7 TLS (1000154)

Thread-local storage callbacks: the AddressOfCallBacks array in the TLS directory is invoked **before the main entry point** (once per thread start/exit). The classic anti-debugging location (breaks earlier than the EP); also the hook for a packer's second-stage decryption. Two parallel lines: static TLS via `#pragma data_seg`/`__declspec(thread)` and dynamic TLS via `TlsAlloc`.

### 2.8 PE File Loading (1000156) and Hand-Crafting a PE (1000158)

The loader (ntdll `LdrpInitializeProcess` line): create the section mappings (VA/alignment) → process relocations → parse the import table and recursively load dependencies → write the IAT → TLS callbacks → jump to AddressOfEntryPoint. Hand-crafting: modify the section table to add a section (Characteristics|RWX), move the EP, append shellcode — the common prototype of patches and packers. The checksum (1000147, IMAGE_OPTIONAL_HEADER.CheckSum) is strictly verified only for kernel drivers.

### 2.9 Tools

- PE tools: LordPE (classic, dump/rebuild), PEditor, CFF Explorer, PE-bear, 010 Editor (PE template, tree node 1001524), StudyPE, `dumpbin /all`
- Writing your own parser: Python `pefile` (now the de facto standard); the knowledge base's "Writing PE Analysis Tools" series

### 2.10 Practical Essentials

1. First step of packer identification: whether the EP points at the last section/odd section names/an import table with only Kernel32.GetProcAddress+LoadLibraryA.
2. If the dumped program won't run, 90% of the time the section table's SizeOfRawData/PointerToRawData is inconsistent with the memory image; rebuild the section table per the in-memory SectionAlignment.
3. Don't lose the Overlay: self-extractors/installers put data at the file tail.
4. The x64 `.pdata` (EXCEPTION directory) is the exception unwind table; when patching code you must update it in sync or exception traversal crashes.

### 2.11 Representative Posts

- "Iczelion's PE Tutorials" Chinese edition (1000143) — the first PE lesson of the Chinese community; "Parsing the PE Export Table", "Writing Programs with Custom PE Structures"
- PE data directory table parsing (item-by-item breakdown of the data directories)
- ELF file format analysis (comparative reading, cross-platform PE/ELF)
- Repairing the IAT via x64dbg scripting (hands-on import-table repair)
- The "Hand-Crafting a PE" series — knowledge-base node 1000158; search for "hand-crafted PE"
- "A Brief Talk on Dump Techniques in Unpacking" (1000293) — dump repair from the PE perspective, linked with the Unpacking chapter

## 3. Windows Data Structures (Tree Node 1000164, formerly under Part 4)

### 3.1 Concept

The watershed where reverse engineering upgrades from "reading code" to "reading the system" is mastering three maps: user-mode TEB/PEB (per-thread/per-process, reached directly via the fs/gs segments), kernel-mode EPROCESS/KPROCESS (ntoskrnl global linked lists), and the handle mechanism spanning both modes. The knowledge-base node also covers NTFS (1000170), HIVE (1000171, registry hives), cache structures (1000172), object data structures (1000174), GDT (1000167), SSDT (1000166).

### 3.2 TEB (1000168, Thread Environment Block)

```
Locating: x86  mov eax, fs:[0x18]   ; x64  mov rax, gs:[0x30]
TEB (excerpt, high-frequency fields for reversing):
  +0x00 NT_TIB.NtTib.ExceptionList  ; head of the current SEH chain (x86)★
  +0x08 NT_TIB.StackBase / +0x0C StackLimit  ; stack bounds
  +0x18 NT_TIB.Self                 ; self pointer (fs:[0x18])
  +0x30 ProcessEnvironmentBlock     ; → PEB★
  +0x34 LastErrorValue
  +0xF18 (x86) / dynamic (x64) GDI/user callback area
```

The first step of exception dispatching (x86) is fetching the SEH chain via `fs:[0]` — making it the most contested memory location in packer/anti-debugging confrontations (forging the SEH chain to detect debuggers). After x64, SEH became table-driven (`.pdata`+`UNWIND_INFO`); `gs:[0]` no longer holds a chain.

### 3.3 PEB (1000169, Process Environment Block)

```
Locating: x86 fs:[0x30] / x64 gs:[0x60]
PEB (excerpt, x86/x64 offsets listed separately):
  +0x02 BeingDebugged ★          ; the whole truth of IsDebuggerPresent (same on x86/x64)
  +0x0C(x64+0x18) Ldr ★         ; → PEB_LDR_DATA: the three InLoadOrder/
  ;    InMemoryOrder/InInitializationOrderModuleList module chains (walk to find the kernel32 base)
  +0x10(x64+0x20) ProcessParameters ; → RTL_USER_PROCESS_PARAMETERS (command line/ImagePathName)
  +0x18(x64+0x30) ProcessHeap    ; header contains Flags/ForceFlags debugging traces
  +0x68(x64+0xBC) NtGlobalFlag ★ ; debugger heap flags (FLG_HEAP_ENABLE_TAIL_CHECK etc.)
  ;    the remaining fields (OSBuildNumber etc.) have version-drifting offsets; verify live with dt nt!_PEB
```

The main battlefield of anti-debugging and anti-anti-debugging (see the Protection chapter); the `PEB.Ldr` three chains are the standard posture for shellcode to locate APIs without an import table (tree node: API self-implementation 1000620).

### 3.4 EPROCESS/KPROCESS (1000173 Structures of Processes and Threads)

```
KPROCESS (prefix of EPROC, scheduler-visible):
  +0x00 DispatcherHeader / +0x18 DirectoryTableBase(CR3)★
  +0x5A~ ThreadListHead / ...
EPROCESS (excerpt; offsets drift violently across Windows versions — hardcoding is forbidden, verify live with `dt nt!_EPROCESS`):
  UniqueProcessId / InheritedFromUniqueProcessId ; process identity
  ActiveProcessLinks ★            ; doubly linked list walking all system processes (the unlink point of hidden processes)
  ImageFileName[15]               ; the process name in Task Manager
  Token(EX_FAST_REF) ★            ; privilege escalation target (tree node 1001479)
  VadRoot                         ; virtual address descriptors (for memory walking/dumps)
  Peb / ObjectTable / ProcessLock etc.
```

Essentials: offsets change across OS versions; hardcoding will break. The knowledge base's "win10 1909 Reversing" series (1001705) is organized precisely around modern system structure evolution. Same for ETHREAD (ThreadListEntry, StartAddress, Win32StartAddress — the side channel for locating the real OEP thread entry when unpacking).

### 3.5 Handles (1000165)

```
_OBJECT_HEADER: PointerCount/HandleCount/TypeIndex/SecurityDescriptor/Body...
Handle table EPROCESS.ObjectTable → _HANDLE_TABLE:
  TableCode low 2 bits = level (0/1/2-level tables), each entry 8B HANDLE_TABLE_ENTRY:
  low 32 bits (kernel) &~7 = object body pointer | high bits flags (locked/protected)
Handle = handle-table index << 4 (a per-process value, invalid across processes → DuplicateHandle to copy across processes)
```

Reverse-engineering scenarios: game multi-instance detection often walks handle tables looking for mutexes; security software removes handles to kill protected processes; handle debuggers (handle.exe/Process Hacker/Process Explorer).

### 3.6 SSDT/GDT/Protected Mode (1000166/1000167/1000023/1000162)

```
SSDT (System Service Descriptor Table):
  KeServiceDescriptorTable → ServiceTable (RVA array)/ServiceLimit/ParameterTable
  Ring3 API → ntdll!Zw* (mov eax, service number; sysenter/syscall)
           → KiSystemService → SSDT[service number] → the real nt!Nt*
  Hooking the SSDT = modifying table entries → the contested ground of rootkits/security software (tree: Hook Techniques, SSDT Hook 1000843)
GDT/protected mode: segment selectors CS=0x1B DS=0x23 etc. index the GDT → segment descriptors;
  Windows flat model, segment offset = linear address; paging CR3 → PDE→PTE (large pages 2MB/4MB)
  → physical page; Windbg `!process`/`!pte` walks this chain
```

### 3.7 NTFS/HIVE/Cache (1000170~1000172)

- NTFS: MFT records/attributes (B+ directories) — forensics and file-hiding (ADS streams) reversing.
- HIVE: registry hives (`WINDOWS\system32\config\*`), cell-based structure; `regedit` is only a shell; offline HIVE parsing is basic forensics.
- Cache management: system cache views/shared views, crossing over with the memory chapters of *Software Debugging*.

### 3.8 Practical Essentials

1. In user mode always fetch the PEB/TEB via fs/gs; never trust fixed addresses.
2. Verify EPROCESS field offsets live with `dt nt!_EPROCESS` (WinDbg); don't copy tables.
3. Anti-debugging detection points concentrate in the PEB (BeingDebugged/NtGlobalFlag/heap Flags); read the raw structures before engaging.
4. When walking ActiveProcessLinks, mind the offset conversion from EPROCESS to the list entry (`CONTAINING_RECORD`).

### 3.9 Representative Posts

- The "Windows Data Structures" series (under knowledge base 1000164: TEB 1000168/PEB 1000169 child nodes, a group of older posts)
- The "win10 1909 Reversing" series (1001705) and others
- Reverse-engineering analysis of the CreateRemoteThread and CreateThread flows from R3 to R0
- Confronting process hiding
- Principles and breaking of process masquerading
- #30-day writing challenge# Privilege escalation via Token in the kernel
- Heap structures and unlink analysis under Windows 10

## 4. The API System (Tree Nodes 1000175 API Secret Archive / 1000176 Process Creation Analysis)

### 4.1 The Three-Layer API Map

```
Application layer      Win32 API (KERNEL32/USER32/GDI32/ADVAPI32/COMCTL...)
                       │  (mostly simple forwarding)
                      ▼
System services layer  Native API (ntdll.dll): Zw*/Nt* prefixes
                       │  mov eax,service number; mov edx,7FFE0300 (KUSER_SHARED_DATA)
                       ▼                    ; sysenter / syscall
Kernel layer           nt!Nt* (ntoskrnl.exe/win32k.sys)
  Environment subsystems: POSIX/OS2 (POSIX removed in Win10), WoW64 (1001482)
  KUSER_SHARED_DATA (0x7FFE0000, user-mode read-only mapping): TickCount/SystemRoot/
    SystemCallStub — a regular in dual-machine debugging and import-less shellcode
```

Reverse-engineering view: watching only the Win32 layer gets you fooled by API hooks (security software hooking kernel32!CreateFileW); go down to the ntdll Zw layer or even the kernel Nt layer. Walking `PEB.Ldr` + brute-force searching `mov eax,idx; syscall` to obtain syscall numbers is the modern import-less standard technique (tree: API self-implementation).

### 4.2 Quick Reference: Common Debugging-Breakpoint APIs (Main Line of the API Secret Archive)

| Purpose | API |
|---|---|
| File operations | CreateFileA/W, ReadFile, WriteFile, SetFilePointer |
| Registry | RegOpenKeyExA/W, RegQueryValueExA/W |
| Networking | WSAStartup, socket, connect, send, InternetOpenA |
| Windows/messages | FindWindowA/W, GetWindowTextA/W, MessageBoxA/W |
| Time limits | GetSystemTime, GetLocalTime, GetTickCount, SetTimer |
| Process/thread | CreateProcessA/W, CreateRemoteThread, OpenProcess, VirtualAlloc (injection) |
| Anti-debugging regulars | IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess |

### 4.3 The Process Creation Chain (1000176, Key Content of Part 4 of *Encryption & Decryption*)

```
CreateProcessW (kernel32)
  → CreateProcessInternalW
    → ntdll!NtCreateUserProcess (one call creates both process + main thread)
      pre-Vista: NtCreateProcessEx → NtCreateThread (two steps)
    Kernel: KiInitializeProcess/EPROCESS setup → PEB initialization
  → ntdll!LdrInitializeThunk (APC injected as the new process's main-thread user-mode start)
    → LdrpInitializeProcess:
       map EXE → ntdll → manifest (SxS) → recursively load import-table DLLs (per init chain)
       → TLS callbacks → jump to OEP (EXE entry)
```

Reverse-engineering value: API choke points (hook CreateProcess to catch child processes), DLL hijack timing, a packer's second-stage entry after Ldr; combined with `gflags + loader snaps` you can make the loader narrate the whole process.

### 4.4 Practical Essentials

1. Breakpoint strategy: when the origin of a string is unclear, first `bp CreateFileW`/`RegQueryValueExW` and inspect the backtrace.
2. Detecting "stolen APIs": compare the first bytes of ntdll Zw* (inline hook detection, tree node 1000849).
3. KUSER_SHARED_DATA 0x7FFE0000 is user-mode readable: anti-debugging reads SystemRoot to build paths, reads TickCount to counter VMs.

## 5. Disassembly Engines (Tree Node 1000005, Fundamentals Part)

### 5.1 Concept

Two flagship knowledge-base series: "Build Your Own Disassembly Engine" (1000007) and "Notes on Developing a 32-bit Disassembly Engine" (1001473). Writing your own disassembly engine is complete training in "instruction encoding → instruction semantics", and the foundation of automated reverse engineering (unpackers, code diffing, VM restoration tools).

### 5.2 Two Scanning Strategies

```
Linear Sweep:   decode sequentially from the entry, fast; drifts on data/junk bytes
                (primary in OllyDbg/W32Dasm)
Recursive Descent: follow control flow (jcc/call/jmp) marking reachable code,
                resistant to interleaved data; needs heuristics for indirect jumps (primary in IDA)
Best practice = combine both + cross-validation (capstone supports per-instruction start/address mode)
```

### 5.3 Engine Layering (Main Line of the 32-bit Disassembly Engine Development Notes)

```
① Prefix parsing (66/67/F2/F3/REX)
② Opcode-table driven (one/two-byte 0F xx, three-byte 0F 38 xx / 0F 3A xx)
③ ModRM/SIB resolve operand shapes (register / memory base+index+displacement)
④ Output formatting (AT&T vs Intel syntax; AT&T: source on the left, registers get %, immediates get $)
⑤ Instruction-length computation (for linear-sweep stepping / stealth breakpoint alignment)
```

### 5.4 Tools

- **Capstone** (now the de facto standard, same-lineage engine as IDA, multi-architecture: X86/X64/ARM/MIPS)
- udis86/distorm (x86 family); Zydis (modern x64 engine, most complete REX/AVX handling)
- The old generation: the PEiD authors' tool family with built-in homegrown engines

### 5.5 Practical Essentials

1. For unpackers/instruction tracers, prefer capstone `cs_disasm` per-instruction + length advance; don't hand-write the full table.
2. Detecting junk bytes: clusters of "abnormal instruction boundaries + invalid opcodes (UD2/garbage prefixes)" in disassembly output mark the junk region.
3. For x64 engines, focus on REX prefix handling and RIP-relative address computation (target = next instruction's address + disp32).

### 5.6 Representative Posts

- Notes on Developing a 32-bit Disassembly Engine Step.5: Variable-Length Instructions Revisited 2 — Instruction Prefixes
- Notes on Developing a 32-bit Disassembly Engine Step.6: Engine Core — Function Wrapping
- "Build Your Own Disassembly Engine" (1)~(8) — the full series; same topic: "Analyzing the ADE32 Disassembly Engine", "The LDE32 Disassembly Engine", "Building a Length Disassembler", "Table-Lookup Disassembler Source Code"
- Implementing an LLIL-based x86/x64 static analysis framework
- Analysis in Practice, Reading Notes 11: Fighting Disassembly
- What Is the Strongest Junk-Byte Removal

## 6. Static Analysis Techniques (Tree Node 1000100, formerly under the Debugging Part)

### 6.1 Tool Genealogy (by Knowledge-Base Node)

| Tool | Node | Positioning |
|---|---|---|
| IDA Pro | 1000101 | Recursive-descent disassembly + decompilation (Hex-Rays), de facto standard; IDC/IDAPython scripting, FLIRT signatures, remote debugging |
| W32Dasm | 1000119 | Veteran static + simple dynamic; intuitive string/import cross-references (a teaching classic) |
| Hiew | 1000122 | Hex + embedded assembly patching; the patching essential of its day |
| Ghidra | 1001389 | NSA open source; free decompiler alternative; scripting (1001490)/practical tips (1001491) |
| angr | 1001369 | Symbolic execution platform (VEX IR); automatic path-constraint solving (a tool for solving keygen constraints) |
| Miasm | 1001455 | French CEA symbolic execution/JIT framework |
| 010 Editor | 1001524 | Binary templates (syntax-highlighted parsing of PE/ELF/custom formats) |
| Data-flow analysis | 1001709 | Taint/data flow, automated tracking |
| KLEE | 1001718 | The progenitor of symbolic execution (LLVM family) |
| hutrace | 1001763 | Instruction-level tracing tool |
| AI-assisted | 1001783 | LLM-assisted reversing (a new node from 2023+) |

### 6.2 IDA Pro Essentials (Basic Operations 1000102 / The IDA Pro Book 1000103)

```
Core flow: load (pick PE/processor) → auto analysis (A) → inspect entry/strings (Shift+F12)/
  imports/cross-references (X) → F5 decompile → change types (Y)/signatures → script-ify conclusions
FLIRT signatures (1000105): identify statically linked runtimes, restoring thousands of sub_ to strcpy etc.
IDAPython (1000111): the idc/idaapi/idautils trio;
  common: for f in Functions(): decompile-and-walk pattern matching (digging packer entries/algorithm constants)
Signature files/processor modules/plugin development (1000109~1000117) as needed
Tenet (1001708): record/replay-style trace browsing (IDA companion); GhidraDec (1001712): integrate the Ghidra decompiler into IDA
```

### 6.3 Ghidra Essentials (1001389)

- Free decompiler; the Headless Analyzer supports batch scripting (`analyzeHeadless` + Java/Python(Jython) scripts).
- Complements IDA: large files/batch/cross-architecture; weaknesses are decompilation precision and obfuscation resistance.
- Knowledge base: "Ghidra 101 Re-introduction (Part 1) — The Ghidra Architecture".

### 6.4 angr and Symbolic Execution (1001369)

```
Idea: turn the program into formulas → let an SMT solver (Z3) solve for the input
Automated keygens: at the "validation passed" branch, add the constraint == success; the solver spits out a valid serial directly
Limits: degrades under path explosion/obfuscation/VM packers; same idea as Miasm (1001455)
```

### 6.5 Practical Essentials

1. Static first: scan strings and constant tables (MD5 init 0x67452301, the Base64 table) first; they often locate the algorithm in one step.
2. When IDA loads a packed program you only see the packer entry — don't grind; alternate static and dynamic (Debugging chapter).
3. Cross-references (X) are the shortcut of "finding the cause from the result": backtrace from the error-message string's references to the validation function.
4. Script repeated judgments with IDAPython: walk functions looking for `imul`+`xor`+64 rounds of looping (MD5/DES signatures).

### 6.6 Representative Posts

- The "The IDA Pro Book" reading series — knowledge-base node 1000103 (by Chris Eagle, Chinese translation *The Authoritative Guide to IDA Pro*)
- Ghidra 101 Re-introduction (Part 1) — The Ghidra Architecture
- The hutrace tool series, part 1: basic functionality overview
- The "IDA Pro Feature Modifications" series — knowledge-base node 1000115
- The "AI-Assisted Reverse Engineering" discussion thread — knowledge-base node 1001783 (added after 2023)

> Related chapters: [01-windows/debugging.md](debugging.md), [01-windows/unpacking.md](unpacking.md).
