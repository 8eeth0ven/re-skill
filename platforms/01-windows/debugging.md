# Knowledge Base · Windows Security · Part 2: Debugging

> The main line derives from Part 2 of *Encryption & Decryption*. Coverage: file type analysis (packer detection), debugger principles (software/hardware breakpoints, single stepping, exception dispatch), debugger development (the Debug API), the four generations of debuggers — WinDbg/OllyDbg/x64dbg/SoftICE — debug symbols, and kernel debugging.
> Prerequisites: see [basics.md](basics.md) (PE/assembly/data structures).

## 1. File Type Analysis (Packer Detection, Tree Node 1000026)

### 1.1 Concept

The first step of reverse engineering is always "know your opponent": what language it was written in, whether it is packed, and with what packer. The knowledge-base node collects the three old tools PEiD, Fi, and Quick unpack.

### 1.2 Packer-Detection Principles

```
Signature matching: scan the entry point/specific sections against a packer signature database (PEiD 5000+ entries)
Entry-point traits: EP falling in the last section/odd section names (UPX0/ASPack/.themida) → packer
Section attributes: RWX sections, VirtualSize>>SizeOfRawData (compressed, pending expansion) → compression packer
Barren import table: only kernel32.LoadLibraryA + GetProcAddress → crypter packer
Entropy analysis: section entropy >7.2 → compressed/encrypted data; <6 → ordinary code (the modern generic criterion)
```

### 1.3 Tools

- **PEiD** (1000027): packer detection + plugins (PE encryption identification/entry scripts); discontinued, but the signature-database idea lives on.
- **Fi**, **Quick unpack** (1000028/1000029), Language2000 (language identification); modern replacements: Detect It Easy (DIE, entropy+signatures), `file`, EXEinfo PE.
- Companion: PE-bear/CFF to inspect the EP and section table (Basics §2).

### 1.4 Practical Essentials

1. PEiD reporting "Nothing found" ≠ no packer; the packer may have altered its signatures (spoofing packer detection, see Protection node 1000699).
2. The detection result decides the route: compression packers go through the standard unpacking flow (Unpacking §3); virtualized packers go straight to trace/symbolic execution.
3. For .NET programs first check the CLR directory (Basics §2.3, entry 14) and use dnSpy rather than OllyDbg.

## 2. Dynamic Analysis Techniques and Debugger Overview (1000031)

Dynamic analysis = making the program confess. The timeline of the four great debuggers:

```
SoftICE (Ring0 fullscreen, the king of the 9x/NT era, DOS graphics) → TRW2000 (a Chinese author's work, Ring0/Ring3 switching)
→ OllyDbg (Ring3 user mode, plugin ecosystem, the cracking standard 2000~2010)
→ x64dbg (open source, OllyDbg's spiritual successor, x64 native) / WinDbg (official, user+kernel+TTD)
```

Selection logic: user-mode patching/unpacking → x64dbg; kernel/drivers/system mechanisms → WinDbg; malware sample forensics → WinDbg+TTD/x64dbg+sandbox; 9x nostalgia and anti-debugging archaeology → SoftICE (run inside a VM).

## 3. Breakpoint Principles (Tree Node 1000093 / "Breakpoints — Everything You Need to Know" 1001258)

### 3.1 Software Breakpoints (INT3)

```
Setting: the debugger saves the first byte at the target address and rewrites it to 0xCC (INT3)
Trigger: CPU executes 0xCC → #BP exception → kernel KiDebugRoutine decides a debugger is attached
      → reported to the debugger as EXCEPTION_BREAKPOINT (0x80000003)
Recovery: the debugger restores the original byte, rewinds IP by 1, single-steps the original instruction, then re-plants 0xCC
Limits: execution breakpoints only; the code rewrite can be caught by CRC self-checks (Protection 1000244);
      multiple debuggers/multiple breakpoints conflict at the same address
```

### 3.2 Hardware Breakpoints (DRx)

```
DR0~DR3: four breakpoint linear addresses (hence at most 4)
DR6: status (which of B0~B3 fired / BD debug-register access / BS single step)
DR7: control — 2 bits per breakpoint for local/global enable + 2 bits condition (R/W: 00 execute, 01 write, 10 IO, 11 read/write)
      + 2 bits length (1/2/4/8 bytes)
Trigger: address hit and access type matched → #DB exception (0x80000004, same code as single step)
Advantages: no code modification (passes CRC checks), can break on "memory write" (watchdog on data sources)
      Traps: task switches clear the DR local bits; packers use GetThreadContext to read DRs and detect the debugger
```

### 3.3 Single Step and Memory Breakpoints

- Single step (Trap Flag): EFLAGS.TF=1, #DB after every instruction. The essence of the debugger's `t/p` commands; anti-debugging uses TF self-trapping to detect (the single-step exception taken over by the program itself).
- Memory breakpoints (Watch): x64dbg/OllyDbg implement them as page-attribute changes (PAGE_NOACCESS/GUARD) → a guard exception fires → the debugger compares the landing point. Not a CPU feature but an application of exception dispatch (§4.6).

### 3.4 Breakpoint Selection in Practice

| Scenario | Breakpoint | Rationale |
|---|---|---|
| Locating the validation function | software bp + string-reference backtrace | simple and direct |
| Code CRC self-check | hardware bp | touches no bytes |
| Tracing "who changed this flag" | hardware write bp/memory bp | data watch |
| OEP capture | memory breakpoint (execute) + section attributes, or the ESP trick | see Unpacking |
| Anti-debug-dense regions | hardware bp + bypass (anti-anti-tracing 1000682) | INT3 gets detected |

## 4. Debugger Development (Tree Node 1000097, Writing a Simple Windows Debugger 1000098)

### 4.1 Windows Debug API Core

```
CreateProcess(..., DEBUG_PROCESS/DEBUG_ONLY_THIS_PROCESS, ...)  // start under debugging
DebugActiveProcess(pid) / DebugSetProcessKillOnExit(FALSE)      // attach
WaitForDebugEvent(&DBEv, timeout)   // blocking event receive
ContinueDebugEvent(pid, tid, DBG_CONTINUE | DBG_EXCEPTION_NOT_HANDLED)
In-process read/write: ReadProcessMemory / WriteProcessMemory
Thread context: Get/SetThreadContext(CONTEXT*, includes Dr0~Dr7/SegFs/EFlags)
Breakpoint management: SuspendThread → restore IP → SetThreadContext → ResumeThread
```

### 4.2 The Debug Event Loop (the Skeleton of All Debuggers)

```c
while (WaitForDebugEvent(&ev, INFINITE)) {
    switch (ev.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:  // image base/prelude to the initial breakpoint
    case LOAD_DLL_DEBUG_EVENT:        // record module bases (symbolization)
    case CREATE_THREAD_DEBUG_EVENT:
    case EXIT_THREAD/EXIT_PROCESS_DEBUG_EVENT:
    case OUTPUT_DEBUG_STRING_EVENT:   // capture OutputDebugString
    case RIP_EVENT:
    case EXCEPTION_DEBUG_EVENT:       // the core
        switch (ev.u.Exception.ExceptionRecord.ExceptionCode) {
        case EXCEPTION_BREAKPOINT:    // 0x80000003 INT3/initial breakpoint
        case EXCEPTION_SINGLE_STEP:   // 0x80000004 TF/DRx
        default:                      // delegate to the debuggee → NOT_HANDLED
        }
    }
    ContinueDebugEvent(...);
}
```

### 4.3 Breakpoint Object Model (Essentials of Writing Your Own Debugger)

```
class Breakpoint { addr; original_byte/DR slot; type(SW/HW); condition; hit_count; }
INT3 hit flow: event arrives → IP-1 matched against the bp table → restore the original byte → write IP-1 back to the context
  → single-step over the original instruction → re-plant 0xCC (three SetThreadContext cycles)
Conditional breakpoints = evaluate an expression inside the debugger after a hit (x64dbg command conditions/expression functions)
```

### 4.4 Exception Dispatch and Its Relationship with Debuggers (Key Point, Main Line of *Encryption & Decryption*)

```
CPU exceptions (#DE/#BP/#GP/#PF...)
  → kernel KiDispatchException:
     ① First offer to the debug port (KiDebugRoutine): debugger present → delivered as first-chance
        debugger returns DBG_CONTINUE → swallowed, the program never knows ★ the SEH anti-debugging principle of packers, in reverse
     ② Debugger declines (NOT_HANDLED) → switch to user mode:
        x86: KiUserExceptionDispatcher
          → VEH first (AddVectoredExceptionHandler, 2000+)★
          → then the SEH chain: fs:[0], node by node, __except_handler
             __try{...}__except(filter){...} unwinding
          → nobody handles it → second-chance offered to the debugger again → still nobody → process crash WER
        x64: table-driven: .pdata/RUNTIME_FUNCTION → UNWIND_INFO unwinding
     ③ Kernel-mode exceptions: after the first two hops, BSOD (captured by dual-machine debugging)
```

Classic anti-debugging (SEH use and counterplay): the packer deliberately triggers an exception (divide-by-zero/access violation) with its own SEH handler installed to continue execution; if the debugger "helpfully" handles the first-chance, the flow diverges and is discovered — countermeasure: set the debugger to "pass all exceptions to the program". VEH precedes SEH and gets installed before it, so packers often use it to hook the exception flow. Tree nodes: structured exception handling 1000163, SEH-mechanism hooking 1000848.

### 4.5 Debugger Development, Advanced

- Multi-threaded debugging (tree node 1001374): dispatch events per tid, freeze other threads, thread-safe breakpoint tables.
- Attaching to a running process: after DebugActiveProcess, inject an initial breakpoint (ntdll initial-bp behavior changed after XP).
- Non-standard: debug-port principles (Lpc/ALPC DebugObject), Wow64 debugging (a 64-bit debugger debugging a 32-bit program bridges automatically).
- Knowledge-base posts: "Writing a Simple Debugger from 0"; "Make a Windbg By Yourself" — (a homegrown WinDbg-like kernel-debugging front end, a classic); the OllyDBG analysis report (1000925).

### 4.6 Practical Essentials

1. Start your own debugger from "attach + INT3 + event loop" in 300 lines; don't build the UI first.
2. When debugging packers, set the first-chance policy correctly (x64dbg: exceptions → tick the pass-through ranges), or the packer will use exceptions as control flow and you will drown in junk exceptions.
3. `GetThreadContext` reading SegFs/Dr* is the only proper way for ring3 to fetch the TEB/debug registers.

## 5. The WinDbg Family (Tree Nodes 1000063~1000070/1001350)

### 5.1 Positioning and Getting Started (Getting Started with WinDbg, the Windows Debugging Tool, 1000065)

The official debugger: user mode, kernel mode, dumps, and TTD in one; a command-line culture (complementing OllyDbg's mouse-driven style); backed by the symbol server, it is the only right choice for analyzing system components/drivers/crashes. Classic textbooks: Zhang Yinquui's *Software Debugging* and *Grid Assembly* (knowledge-base node groups "Software Debugging Fundamentals" 1001222, "Debug Tutorial" 1000096).

### 5.2 Command Classification Quick Reference

```
Standard commands: g (go) t (trace into) p (step over) gu (step out) k/kb/kv (stack) r (registers)
  d* db/dw/dd/dq (dump) e* (edit memory) u/uf (disassemble) bp/bc/bd (breakpoints) x (lookup symbols)
  lm (modules) !lmi; ~ (threads) | (processes) .frame (switch frame) dv (locals) wt (trace calls)
Meta-commands (starting with .): .sympath .reload .symfix; .exepath; .source; .wtitle; .lastevent
  .childdbg; .ttime; .dmpash
Extension commands (starting with !, a plugin ecosystem):
  !analyze -v (one-stop crash analysis) !process !thread !object !handle !pte !irpfind
  !pool !vm !csrf !dps !heap -s !dlls !imgreloc; !sym noisy
```

### 5.3 Symbols (Tree Node 1000092, Details in §9) and Source Debugging

`.sympath srv*C:\symbols*` plus `.reload` is enough to fully resolve symbols like `nt!NtCreateFile`; kernel-debugging efficiency rises tenfold.

### 5.4 Scripting (Tree Node 1000067)

- Language: a C-like preprocessor (`$$>a<`), aliases (`${}`), blocks `.if{} .else{}`, loops `.for/.while`, `$t0~$t19` pseudo-registers.
- Common postures: walking linked lists (`!list -t nt!_LIST_ENTRY.Flink -x "dt nt!_EPROCESS @$extret"`), batch conditional breakpoints (`bp addr ".if (@eax==0x10) {} .else {g}"`), log replay (`.logopen/.logclose`).
- Advanced: JS scripting (Chakra built into WinDbg), pykd (Python bindings).

### 5.5 Plugins and Modifications (1000068/1000070)

SOS (.NET), SOSEX, !analyze extensions; WinDbg Preview (JS plugins/time-travel UI); the knowledge-base post "Introduction to Writing WinDbg Plugins and Loading Extensions in Nano Code"; the GDK7 (tree node 1001711, Zhang Yinquui's team's ARM hardware debugging box) discussion thread.

### 5.6 Dual-Machine Kernel Debugging (1000069/1000094)

```
Target machine: bcdedit /debug on; bcdedit /dbgsettings net port:50000 key:1.1.1.1 (network kd)
       (old school: serial COM1 115200 / 1394 / USB2)
Debugger machine: windbg -k net:port=50000,key=1.1.1.1 → target reboot → "Break" (Ctrl+Break)
Scenarios: driver debugging, rootkit detection, a packer's Ring0 portion, blue-screen dump correlation
Knowledge-base posts: "Getting Started with Dual-Machine Kernel Debugging"; "Setting Up an HEVD Dual-Machine Debugging Environment (mac)"
```

### 5.7 TTD and DTrace (Tree Nodes 1001780/1001745)

- **TTD (Time Travel Debugging)**: record the execution stream, single-step backwards (`g-`/`t-`) and replay — a revolutionary tool for "reconstructing the accident backwards"; automate with ttd-bindings. Knowledge-base post: "TTD Debugging and ttd-bindings Reverse-Engineering Practice".
- **DTrace for Windows**: dynamic probes (function boundary/FBT); knowledge-base post ("DTrace Research").

## 6. The OllyDbg Family (Tree Nodes 1000033~1000062/1001374)

### 6.1 Positioning

The Ring3 reversing debugger (2000~2014, Oleh Yuschuk), the flagship tool of the 2nd/3rd editions of *Encryption & Decryption*. The knowledge-base child nodes are extremely detailed: loading/configuration/breakpoints/Run trace/plugins (writing + finished ones: CMDBAR/watch/OllyScript/OllyMachine/OllyHTML/LastBranchRecord/Olly Advanced/CustomTools/SkyPatch/phantOm/syntax highlighting), principles, source debugging, loaddll, modifications, multi-threaded debugging.

### 6.2 Core Operations (Basic Operations 1000034)

```
Loading pauses three times (system breakpoint/EP/TLS callback — the third is the most useful, specialized against packer prelude)
F2 breakpoint / F7 step into / F8 step over / F9 run / Ctrl+F9 execute till return / F4 run to here
Shift+F9 (pass exceptions straight through)★ essential for packer debugging
C command window: bp GetDlgItemTextA; Run trace tracking (Ctrl+F11) + Trace-into conditions
Memory-window breakpoints (access/write/execute) → common for the OEP; right-click Search for → All referenced strings
Plugin shortcuts: forced SPLash (Scylla), phantom (anti-anti-debugging), OllyScript (automated unpacking scripts)
```

### 6.3 OllyScript (1000047~1000050)

An assembly-like scripting language: var/eob/loge/mem/bp/gmemi/findop/fill/asm …… the de facto standard of automated unpacking scripts back in the day (ASProtect/Themida scripts everywhere); its successor x64dbg's script syntax is of the same lineage. The tutorial nodes are split into: scripting tutorials/usage tips/script examples.

### 6.4 Modifications and Multi-Threading (1000062/1001374)

Modded builds (Hidden Debug/AAoM anti-anti-debug build), SDK secondary development, multi-threaded debugging limits (thread events serialized, struggling with highly concurrent samples) — the root cause of its replacement by x64dbg.

### 6.5 Knowledge-Base Posts

- "Cracking from Zero with OllyDbg (Completed)" — knowledge base 1001216, the vault-keeper series tutorial
- Same series "Chapter 10 — Breakpoints"; "Chapters 51/52: Unpacking ASProtect v2.3.04.26" — thread-11794

## 7. The x64dbg Family (Tree Nodes 1001288/1001492/1001713/1001778)

### 7.1 Positioning and the Getting-Started Series (x64dbg Getting-Started Series 1001492)

Open source (MIT), dual-architecture x32dbg/x64dbg, the de facto standard of the 2020s. UI/shortcuts inherit OllyDbg, the core rewritten: true x64, modular commands (`SetBPX/bphws/bpgoto`), an expression engine, a built-in assembler (assemble).

### 7.2 Key Enhancements over OllyDbg

```
Command line: bpx VirtualAlloc; bp SetWindowTextW; bphwc (clear hardware breakpoints)
  SetBreakpointCommand attaches a hit script — the core of automated unpacking
Fine-grained exception policy (pass/stop by exception-code range)★
Memory map + section permissions at a glance; Trace (record-to-file/conditional trace) with a built-in database viewer
Persistent labels/comments/bookmarks; symbol module pdb support
```

### 7.3 Plugin Ecosystem (1001713)

Scylla (dump + IAT repair integrated, the unpacking exit), x64dbgpy (Python), quick-call finder, MapoAnalyzer (1001714); knowledge-base posts: "x64dbg — Usage Experience", "x64dbg — Scylla", "x64dbg — x64dbgpy", "The x64dbg Quick Call-Finder Plugin", "A Beginner's Blessing — The x64dbg Perfect Tracing Scheme", "Basics of Writing x64dbg Plugins".

### 7.4 Practical Essentials

1. Template unpacking flow: follow to the OEP in x64dbg → Scylla dump + IAT fix (see Unpacking §3).
2. Chasing API calls: command `bp GetWindowTextW` + watch arguments in the stack window; faster than OllyDbg's Search.
3. Semi-automated unpacking with scripts: trace recording + post-processing (IDA/scripts) comparison, for handling VM packers in a targeted way.

## 8. Other Debuggers (Tree Nodes 1000071~1000090)

- **SoftICE** (1000076): Ring0 fullscreen debugger, the king of kernel debugging in the 9x/NT era; command manual (1000085)/dual-machine (1000079)/plugins IceExt (1000082), IceDump (1000083); faded away after DriverStudio's demise, but its principles are still worth reading.
- **TRW2000** (1000086): written by a Chinese author, one-key Ring3/Ring0 switching, a memory of the pmake era.
- **SyserDebugger** (1000090): a post-SoftICE kernel debugger.
- **bochs** (1000072): emulator-grade debugging (for dead-packers/MBR viruses, paired with the virtual-machine node in the Fundamentals part).
- **VC Debug** (1000071): source level, paired with IDA PDB cross-checking.
- **ADPlus** (1000075): scripted dump capture (a cdb wrapper), standard for server hangs.
- **PaiMei** (1000073): a Python reverse-engineering framework (an old group of Python posts).
- **Process Monitor** (1000088): file/registry/process behavior chains — the first shot of dynamic analysis.

## 9. Debug Symbols (Tree Node 1000092)

```
PDB structure: MSF stream file; DBI stream (modules/compilands) | TPI (types) | global symbol stream
  Lookup chain: EXE DEBUG directory (RSDS GUID+Age) → local/server path match → download
Symbol server: _NT_SYMBOL_PATH=srv*C:\sym*https://msdl.microsoft.com/download/symbols
Source server (SrcSrv): a.dll → a.pdb → fetch source from svn/git — source reproduction
Private symbol stripping: stripping (public OS symbols vs full symbols), mandatory for kernel dump analysis
```

Reverse-engineering for personal use: generate pdbs for your own programs to pair IDA/WinDbg source debugging; for symbol-less targets use symbol inference (type recovery, IDA `Local Types` + struct annotation); verify with `SGEN`/`symchk`. Knowledge-base post: "Generating Libs for Undocumented APIs and Integrating with MSBuild" (a symbol/Lib workflow).

## 10. Kernel Debugging (Tree Nodes 1000094/1001350)

```
Path A: WinDbg dual-machine (§5.6) —— kd kernel mode: !process 0 0 / .process /i to switch processes
  ba e1 addr (kernel hardware breakpoint) / !drvobj / !devstack / !irp
Path B: local kernel debugging (LKD, LiveKD) —— read-only snapshot, low risk
Path C: VM + kdnet (VMware bridged) —— the daily-development standard
Targets: driver-load breakpoints (Sxe ld:mydrv), SSDT/IDT modification tracing, CR3 switching (kpt,
  after Win10 KPTI, !process needs /i with two address-space switches)
```

Knowledge-base posts: "Hello, R3 into R0"; "Learning Windows Kernel Vulnerabilities — The HEVD Series: Setting Up a Dual-Machine Debugging Environment (mac)"; "Analysis of the Windows Kernel Privilege-Escalation Vulnerability CVE-2018-8120"; "Make a Windbg By Yourself".

## 11. Debugging Techniques and Mindset (Tree Node 1000095)

The two series main lines of "Debug Tutorial"/"Software Debugging Fundamentals" (Zhang Yinquui): breakpoint design, stack walks, heap investigation, deadlock analysis. Reverse-engineering-oriented experience:

1. **The entry three-move combo**: the strings window, the import table, the loops near the EP — characterize first (NAG/registration dialog/feature lock) before acting.
2. **Start from messages**: if the button does nothing, first `bp MessageBoxA/W`, `bp DialogBoxParam` and backtrace the caller.
3. **Start from data**: a memory value changed/jumped → a hardware write breakpoint catches the writer directly.
4. **Exceptions are clues**: packers use exceptions heavily for control flow; set the pass ranges correctly and stop only at the exception right before "about to reach the OEP".
5. **Run trace/Trace recording**: under static obfuscation (reordering/junk bytes), offline analysis after a trace is an order of magnitude faster than manual single-stepping (x64dbg trace files + IDA Tenet).

## 12. Link to Reverse Analysis Techniques (Tree Nodes 1000123/1001462)

The 32-bit/64-bit software reverse-engineering series (overview/calling conventions/variables/constants/startup functions/functions and arguments/data structures/control statements/math operators/virtual functions/file format analysis/case studies/Reverse Me/R4ndom tutorial/Cracking from Zero with OllyDbg) is "code reading" training; its prerequisites are exactly this part + Basics. The 64-bit part (registers/functions/data structures/control statements/loops/operators/virtual functions/case studies) corresponds to the new x64 shapes. Not expanded here; see [basics.md](basics.md) §1 and knowledge-base nodes 1000123~1000139/1001464~1001471.

## Appendix: Related Chapters

> Related chapters: [01-windows/basics.md](basics.md), [01-windows/unpacking.md](unpacking.md)
