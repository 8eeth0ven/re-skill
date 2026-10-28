# Knowledge Base · Windows Security · win-vuln · PE Reverse Engineering and Symbol Analysis (the Vulnerability-Hunting Workflow)

> Positioning: Basics covers PE structure and static-analysis principles, Debugging covers debugger principles and symbol fundamentals — this part assembles the two into a **vulnerability-hunting pipeline**: given an unknown PE/driver → type identification → symbols → static audit (Ghidra/IDA) → vulnerability hypotheses → dynamic verification (WinDbg/x64dbg) → POC. All commands verified against the current versions as of 2026-10: Ghidra 12.1.4 / IDA 9.4 / WinDbg 1.26 (winget `Microsoft.WinDbg`). PE field meanings are not restated; see Basics §2.

## 0. Version and Tool Baseline (Verified 2026-10)

| Tool | Current version | Source | Vulnerability-hunting use |
|---|---|---|---|
| Ghidra | 12.1.4 (2026-09) | github.com/NationalSecurityAgency/ghidra/releases | the free decompilation mainstay + headless batch auditing |
| IDA Pro | 9.4 (2026-09) | hex-rays.com subscription | close reading + IDAPython + MCP automation |
| WinDbg | 1.26 (`winget install Microsoft.WinDbg`) | Store/winget, WinDbg MCP built in | the only right choice for kernel debugging/dump analysis |
| x64dbg | snapshot | x64dbg.io | user-mode verification/POC driving |
| DIE / symchk / kdnet | — | DIE official site / WDK Debuggers | type & packer identification / symbol download / KDNET auto-configuration |

JDK baseline: Ghidra 11.3+ requires **JDK 21+**. The macOS/Linux side can also run headless (for cross-auditing).

## 1. Reverse-Engineering Workflow Overview

### 1.1 Flow Chart (the Standard Pipeline)

```
Unknown PE/SYS (sample/driver dump/vendor component)
   │
   ① Type identification (§1.2): EXE/DLL/SYS? .NET? 32/64? subsystem?
   │      ├─ .NET (CLR directory non-zero) → dnSpy/ILSpy, not this flow
   │      └─ Native → continue
   ② Packer detection (entropy/EP/import table, Debugging §1) → packed → unpack (Unpacking §3) → back to ①
   │
   ③ Symbols first (§4): DEBUG directory GUID/Age → symchk fetches the PDB → a hit decides 3x efficiency afterwards
   │
   ④ Static audit (§2 Ghidra / §3 IDA)
   │      ├─ auto-analysis + type recovery → scripts batch-scanning sinks (xref lists)
   │      └─ manual decompilation of hotspots: entry surfaces (IOCTL/exported functions/callback registrations/parsers)
   ▼
⑤ The vulnerability-hypothesis list (each entry = location + type + trigger condition + confidence)
   │
   ⑥ Dynamic verification (§5 WinDbg kernel / §6 x64dbg user mode): breakpoints/trace/crash reproduction
   │
   ⑦ POC construction → controllability proof (crash = minimum bar, read/write/RIP = full chain) → report
```

### 1.2 Type Identification (Copy-Pasteable Commands)

```powershell
# DIE CLI: identify packer/compiler/language together
diec.exe C:\samples\target.sys

# Use pefile for precise classification (Subsystem=1 means a NATIVE driver)
pip install pefile
python -c "import pefile; pe=pefile.PE(r'C:\samples\target.sys'); \
 print(hex(pe.FILE_HEADER.Machine), 'dll' if pe.is_dll() else 'exe/drv', \
 'subsys', pe.OPTIONAL_HEADER.Subsystem, \
 'CLR', pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress, \
 'ep', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))"
```

Reading the output: Machine 0x8664=x64 / 0x14c=x86; Subsystem 1=NATIVE (a driver; no CRT in its 4 layers, can use `/MT` static); a non-zero CLR directory → .NET, go with dnSpy; driver + no relocations (empty `.reloc`) → loading must fail; suspect truncation/forgery.

### 1.3 The "Input-Surface" Priority for Vulnerability Hunting (Decide Where to Look Before the Static Audit)

| Target type | Input surfaces (attack surfaces) | Audit first |
|---|---|---|
| Kernel driver .sys | every CTL_CODE of DeviceIoControl, read/write dispatch (IRP_MJ_READ/WRITE), FastIo | handler length validation, user-pointer Probe, pool lifetime |
| System-service DLL/EXE | RPC/ALPC interfaces, named pipes, local DCOM | deserialization, integer overflow, permission-check timing |
| Ordinary applications | file parsers (images/documents), network protocol stacks | parser loop bounds, UAF |
| Printing/fonts/kernel callbacks | winspool, gdi, OB_CALLBACK | trust in callback arguments |

The entry-surface list directly determines which sinks the §2.4 scripts scan.

### 1.4 The Vulnerability-Hypothesis List Template (the Work Product Running Through This Part)

```
| # | Location (module+RVA/function) | Hypothesis | Trigger | Confidence | Verification (§/command) |
| 1 | mydrv.sys+0x11230 IoctlHandler | METHOD_NEITHER without Probe | CTL 0x222023 | High | WinDbg bp + a user pointer |
```

## 2. The Ghidra Workflow (the Free Mainstay)

### 2.1 Installation and Headless Start

```bat
:: 1) JDK 21
winget install Microsoft.OpenJDK.21

:: 2) Extract Ghidra 12.1.4 and start the GUI
C:\ghidra_12.1.4_PUBLIC\ghidraRun.bat

:: 3) Headless batch analysis (create the project directory first)
mkdir C:\proj C:\scripts
C:\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat C:\proj vulnproj ^
  -import C:\samples\target.sys ^
  -scriptPath C:\scripts ^
  -postScript find_dangerous_xrefs.py > C:\proj\audit.log 2>&1

:: 4) Rerun scripts on imported programs without re-analysis
analyzeHeadless.bat C:\proj vulnproj -process target.sys -noanalysis ^
  -scriptPath C:\scripts -postScript find_ioctl_dispatch.py
```

Parameter essentials: `-processor x86:LE:64:default` can be omitted (PE auto-detected); `-analysisTimeoutPerFile 900` guards against huge drivers hanging; `-deleteProject` for one-shot batch runs; since 11.3+, `.py` scripts preferably go through PyGhidra (native CPython, can import capstone/requests); legacy Jython syntax still works.

### 2.2 Import and Auto-Analysis Options (Driver-Specific)

In the import wizard (`File→Import File`) for a .sys: choose Language `x86:LE:64:default`, Format **PE**; after import, the Auto Analysis dialog pops — for driver scenarios keep/enable:

- `Decompiler Parameter ID` (parameter recovery, must-enable)
- `Decompiler Switch Analysis` (switch → IOCTL dispatch-table restoration)
- `Function Start Search` + `Instruction` **Separator** mode (restoring function boundaries on symbol-stripped drivers)
- `Windows x86 PE RTTI`, `Demangler` (C++ drivers)
- `Stack` frame variables (the foundation of local buffer-overflow auditing)

### 2.3 Symbols and Type Recovery

1. PDB: set `setx _NT_SYMBOL_PATH srv*C:\symbols*https://msdl.microsoft.com/download/symbols` then reopen Ghidra → `File→Load PDB File…→Advanced>>→tick Symbol Server→Search All`; a hit gives full symbols+types (details in §4).
2. ntoskrnl structures (`_EPROCESS/_IRP/_IO_STACK_LOCATION`): driver PDBs carry the types; without a PDB, use `llvm-pdbutil dump -types ntoskrnl.pdb` to transcribe by hand, or maintain a ghidra `.gdt` type library from ReactOS/WRK headers (`File→Parse C Source` eating WDK headers directly is the fastest path).
3. After applying the PDB, `Search→For Strings` + `Window→Functions` show readable function names; IOCTL-handler-type functions are often named with `Ioctl/Dispatch/DeviceControl`.

### 2.4 Audit Scripts (the Core of Batch Processing)

**Script one: dangerous-sink cross-reference list** (C:\scripts\find_dangerous_xrefs.py):

```python
# -*- coding: utf-8 -*-
# find_dangerous_xrefs.py — postScript: list all callers of sensitive kernel APIs
SENSITIVE = [
  # Probe APIs: presence provides audit context; absence suggests unprotected user pointers (useful negative evidence)
  "ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages",
  # MDL/mapping APIs: signs of METHOD_NEITHER or direct user-memory access
  "MmGetSystemAddressForMdlSafe", "MmMapLockedPagesSpecifyCache", "IoAllocateMdl",
  # Copy APIs: audit the length source (is InputBufferLength trusted?)
  "RtlCopyMemory", "memcpy",
  # Pool APIs: UAF/double-free/overflow
  "ExAllocatePoolWithTag", "ExAllocatePool2", "ExFreePoolWithTag",
  # Reference APIs: races in reference release
  "ObReferenceObjectByHandle", "ObDereferenceObject",
  # Completion APIs: locate candidate handlers
  "IofCompleteRequest",
]
st = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()
for name in SENSITIVE:
    hits = 0
    for sym in st.getSymbols(name):
        for ref in getReferencesTo(sym.getAddress()):
            caller = fm.getFunctionContaining(ref.getFromAddress())
            print("[%s] <- %s @ %s" % (name,
                  caller.getName() if caller else "?", ref.getFromAddress()))
            hits += 1
    if hits == 0:
        print("[%s] NO XREF (Probe 缺失则全用户输入皆裸奔)" % name)
```

**Script two: IOCTL dispatch location** (C:\scripts\find_ioctl_dispatch.py):

```python
# -*- coding: utf-8 -*-
# find_ioctl_dispatch.py — locate DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]
# Offsets: x64 = 0x70 + 0x0E*8 = 0xE0; x86 = 0x34 + 0x0E*4 = 0x6C (IRP_MJ_DEVICE_CONTROL=0x0E)
from ghidra.program.model.scalar import Scalar

OFFSETS = {0xE0: "x64", 0x6C: "x86"}
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

it = currentProgram.getSymbolTable().getExternalEntryPointIterator()
while it.hasNext():
    f = fm.getFunctionContaining(it.next())
    if f is None:
        continue
    print("entry func: %s @ %s" % (f.getName(), f.getEntryPoint()))
    for ins in listing.getInstructions(f.getBody(), True):
        # Common DriverEntry pattern: lea rax,[handler]; mov [rcx+0xE0],rax
        if ins.getMnemonicString().lower() not in ("mov", "lea"):
            continue
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                if isinstance(o, Scalar) and o.getValue() in OFFSETS:
                    print("  %s dispatch store @ %s : %s" %
                          (OFFSETS[o.getValue()], ins.getAddress(), ins))
```

Follow-up: enter the handler; after `Switch Analysis`, in the Graph view every case is one CTL_CODE; for every immediate where `(code & 3)==3` → a METHOD_NEITHER candidate — enter it in the hypothesis list.

### 2.5 Practical Essentials

1. Let headless finish the full run, then open the GUI to read the script results; don't sit in the GUI waiting for manual analysis clicks.
2. The caller set of `IofCompleteRequest` ≈ the full pool of IRP handler candidates — more complete than chasing dispatch from DriverEntry (it also covers FastIo/callbacks).
3. In decompile windows, tag the `PoolWithTag` tag constants and `CTL_CODE` immediates directly with the `L` key, linked to the hypothesis list.
4. Cross-version diff: build projects for the vendor's old and new .sys each; align functions with the `Version Tracking` tool — the patched functions = historical vulnerability scenes (a gold mine of 0day leads).

## 3. The IDA Workflow

### 3.1 Driver Loading (Kernel Relocations/Segments)

Drag in the .sys: PE hits 64-bit; in Loading tick **Manual load**; accept the ImageBase prompt defaults (the driver preferred base is x64 commonly `0x1C0000000`/x86 `0x10000`; IDA 9 handles it automatically). Essentials:

- Kernel drivers get no import-table parser assistance (only ntoskrnl/hal imports), yet IDA still lists Imports — `MmGetSystemAddressForMdlSafe` and friends are directly searchable.
- Runtime rebase: get the actual base from WinDbg `lm vm mydrv`, then IDA `Edit→Segments→Rebase program` (or the command `rebase(0xFFFFF80…)`), making IDA addresses match debugger addresses so breakpoint addresses can be copied straight over.
- For CFG/CET drivers inspect the `LOAD_CONFIG` directory; a missing `.pdata` (no SEH table made) is itself a clue.

### 3.2 FLIRT/Signatures

`File→Signature file` (`Shift+F5`) loads `vc64*.sig` (static CRT restoration, thousands of sub_ become `memcpy`); for WinDDK-compiled drivers you can make your own FLIRT: compile a minimal project with the same WDK version, produce a sig with the `flair` toolchain — a one-time investment that pays back long-term.

### 3.3 An IDAPython Audit Skeleton (Missing ProbeForRead / METHOD_NEITHER)

```python
# ida_audit_neither.py — IDA 9.x IDAPython,IDA Python console: exec(open(r'C:\scripts\ida_audit_neither.py').read())
import idaapi, idautils, idc, ida_funcs, ida_name, ida_segment

PROBES = ("ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages")

def ea_of(name):
    return ida_name.get_name_ea(idaapi.BADADDR, name)

# 1) Collect an allowlist of functions that call Probe
probed = set()
for n in PROBES:
    e = ea_of(n)
    if e != idaapi.BADADDR:
        for x in idautils.XrefsTo(e):
            f = ida_funcs.get_func(x.frm)
            if f: probed.add(f.start_ea)

# 2) Candidate handlers = callers of IofCompleteRequest
handlers = {}
comp = ea_of("IofCompleteRequest")
if comp != idaapi.BADADDR:
    for x in idautils.XrefsTo(comp):
        f = ida_funcs.get_func(x.frm)
        if f: handlers[f.start_ea] = idc.get_func_name(f.start_ea)

# 3) A handler with a METHOD_NEITHER-like immediate ((ctl&3)==3) outside the Probe allowlist is high priority
import ida_ua, ida_bytes
BAD = []
for start, name in handlers.items():
    if start in probed:
        continue
    hits = []
    for ea in idautils.FuncItems(start):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            for op in insn.ops:
                if op.type == ida_ua.o_imm and (op.value & 3) == 3 \
                   and op.value > 0x1000:   # Exclude small constants
                    hits.append((ea, op.value))
    if hits:
        BAD.append((name, start, hits))

for name, start, hits in BAD:
    print("%s @ %x NO-PROBE + NEITHER-likely: %s" %
          (name, start, [(hex(e), hex(v)) for e, v in hits]))
    idc.set_cmt(start, "AUDIT: METHOD_NEITHER candidate, no Probe in func", 1)
```

Companion notes: `Alt+T` searching `85 c0 74` (test/jz after probes) is only folklore; the real criterion is a direct dereference of `Type3InputBuffer` in the decompilation; read each candidate function with `F5` — a `Parameters.DeviceIoControl.Type3InputBuffer` of `(IO_STACK_LOCATION*)Irp->Tail.Overlay.CurrentStackLocation - 1` without a `__try` wrapper is a smoking-gun lead.

### 3.4 Automation with MCP (LLM-Driven IDA)

This environment's `ida-pro-mcp` plugin (or an isomorphic open-source version) exposes IDA to the agent; the typical audit loop no longer writes one-off scripts but drives conversationally:

```
check_connection                      → Confirm that IDA is online
list_strings_filter "IOCTL|\\\\Device\\\\"   → Obtain device names/CTL strings
get_function_by_name "SubIoctlHandler" → Locate the function
decompile_function <addr>              → Read pseudocode and identify vulnerability patterns
get_xrefs_to <ProbeForRead ea>         → Negative evidence: callers that do not use it
set_comment <addr> "AUDIT: UAF 假设#2" → Persist the conclusion
rename_function <addr> "vuln_read_oob" → Function names become report evidence
```

Essentials: the MCP loop suits interactive auditing of "discover → verify → annotate"; full-volume batch still goes through headless (§2.4); the two complement each other.

## 4. The Symbol System

### 4.1 The Microsoft Public Symbol Server (Syntax Unchanged as Verified 2026)

```
_NT_SYMBOL_PATH = srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

Three-segment semantics: `srv*local cache directory*upstream server`. Setup:

```bat
:: Persistent user-level setting (inherited by newly opened WinDbg/Ghidra/IDA)
setx _NT_SYMBOL_PATH srv*C:\symbols*https://msdl.microsoft.com/download/symbols

:: Session-level setting (current cmd)
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

Multi-level chaining (your own symbols first): `C:\mysym;srv*C:\symbols*https://msdl.microsoft.com/download/symbols`.

### 4.2 symchk Batch Downloads (the WDK Debuggers Directory)

```bat
:: Single file (automatically match the DEBUG-directory GUID)
symchk.exe C:\samples\mydrv.sys /s srv*C:\symbols*https://msdl.microsoft.com/download/symbols

:: Fetch kernel symbols together (ntoskrnl/hal/win32k...)
symchk.exe C:\Windows\System32\ntoskrnl.exe /om C:\sym_manifest.txt > nul

:: Verify cached symbols
symchk.exe /v C:\symbols\ntkrnlmp.pdb
```

### 4.3 Manual PDB Downloads (URL Construction)

The PDB lookup chain sits in the EXE's DEBUG directory (the RSDS record): `PDB name + GUID (dashes stripped) + Age`.

```
# Extract from pefile
python -c "import pefile; pe=pefile.PE(r'C:\Windows\System32\ntoskrnl.exe'); \
 d=[e for e in pe.DIRECTORY_ENTRY_DEBUG if e.struct.Type==2][0]; \
 print(d.entry.PdbFileName, d.entry.Signature_Guid, hex(d.entry.Age))"

# URL = server/{pdbname}/{GUID without hyphens, lowercase}{Age in hexadecimal}/{pdbname}
curl -O https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/9c1c8a4b1234abcd1/ntkrnlmp.pdb
```

Applicability: msdl allows direct directory-link downloads (no auth); if the target driver's PDB sits on the vendor's HTTP server (the URL often leaks in the DEBUG directory's path string, e.g. `\\buildsvr\drops\xxx.pdb`), append `srv*C:\sym*https://vendor.example/pdb` to `_NT_SYMBOL_PATH`.

### 4.4 Mounting in the Three Tools

- **WinDbg**: `.sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols` + `.reload /f mydrv.sys`; `lm vm mydrv` showing a matching `PDB signature` means a hit. Kernel sessions fetch automatically per each module's GUID.
- **Ghidra**: `File→Load PDB File…→Advanced→Search All` (honors `_NT_SYMBOL_PATH`); in headless, if the PDB URL is set, it attempts automatically at import.
- **IDA**: the PDB download prompt at load time (honors `_NT_SYMBOL_PATH`); re-attach via `File→Load file→PDB file`; types go into `Local Types` (Shift+F1) where `Insert from PDB` is available.

### 4.5 When Symbols Are Missing (Closed-Source/Stripped Drivers)

1. **Export-anchor method**: function addresses in the driver's export table (`dumpbin /exports mydrv.sys` / pefile) are reliable anchors; name non-exported functions in IDA manually by their relative offsets (RVA deltas) from the anchors.
2. **Cross-version anchoring**: old version has a PDB (or a historical leak) + new version doesn't → align export tables + migrate symbols with a `Binary diff` (Diaphora/BDiff/Ghidra Version Tracking).
3. **On the WinDbg side**: `lm k` shows unsymbolized module bases; `!dh mydrv -f` dumps the PE header directly to find the DEBUG directory and read the PDB path string; breakpoints use `bp mydrv+RVA` (compute the RVA in IDA).
4. **The relocation trap**: in IDA address = preferred base + RVA; in WinDbg = runtime base + RVA; keep a conversion script handy: `rva = ida_addr - ida_imagebase`.

## 5. The WinDbg Workflow (the Kernel Main Battlefield)

### 5.1 Dual-Machine Kernel Debugging (KDNET, the Current Standard Posture)

```bat
:: Target machine (a VM is sufficient; administrator cmd)
bcdedit /debug on
:: Generate the key automatically (recommended; kdnet.exe is in the WDK Debuggers directory and checks NIC support)
C:\Debuggers\amd64\kdnet.exe 192.168.56.1 50000
:: Outputs a key such as key=1.2.3.4 (or 2.0.spbrt... format) and writes dbgsettings automatically
:: Manual equivalent:
bcdedit /dbgsettings net hostip:192.168.56.1 port:50000 key:1.1.1.1
:: Select an adapter on multi-NIC hosts (Device Manager → network adapter → Details → Location information):
bcdedit /set "{dbgsettings}" busparams 0.25.0
shutdown /r /t 0
```

```bat
:: Debugger machine (host)
winget install Microsoft.WinDbg
:: GUI: File → Kernel Debug → Net; enter port 50000 + key
:: CLI equivalent:
windbgx -k net:port=50000,key=1.1.1.1
```

Once connected, `Ctrl+Break` breaks in, `g` continues; `qd` or the target's `bcdedit /debug off` exits. VM bonus: **take snapshots** — after a fuzz crash, rollback and retest in seconds.

### 5.2 Command Quick Reference (Vulnerability-Verification Oriented)

```
!analyze -v                 # Crash triage: symbols/stack/bucket; first command after each BSOD
dt nt!_EPROCESS             # Check the structure in the target build; never copy offsets from an old table
dt nt!_IO_STACK_LOCATION    # Obtain the Type3InputBuffer offset from the target structure
!process 0 0                # All processes; .process /i <EPROC> switches address space (two-stage KPTI)
!thread / !irp <addr>       # IRP details: issuer/IOCTL/buffer location
!pool <addr> / !poolused 2  # Trace pool tags to attribute a UAF or overflow
!devobj <name|addr> / !drvobj mydrv 7   # Device stack and driver dispatch panorama; lists dispatch functions directly
bp mydrv+0x1234 / ba e1 mydrv!Handler  # Breakpoint by RVA or symbol
ed <addr> <val>             # Modify memory to bypass a check or retest a changed length
uf mydrv!Handler            # Disassemble the full function; k/cvn inspects the stack
!verifier 3                 # Driver Verifier status
.bugcheck / .lastevent      # Review the bugcheck code and initial cause
!address / !pte <addr>      # Inspect page tables: valid PTE? user or kernel page?
lm k / lmvm mydrv           # Module bases for rebasing / module details
```

`!drvobj mydrv 7` prints the MajorFunction table directly — the dynamic counterpart of statically finding the dispatch (the verifier of the §2.4 script results).

### 5.3 Conditional Breakpoints and Scripting

```bat
:: Classic conditional breakpoint: stop only on IOCTL 0x222023
bp mydrv+0x11230 ".if (poi(@rdx+0xb8+0x20+0x18) == 0x222023) {} .else {g}"
:: x64 handler(DeviceObject@rcx, Irp@rdx); verify offsets with dt before hardcoding them

:: WinDbg 1.x syntax (/w = Data Model filter; stops only on a match and is faster than .if):
bp /w "myctl(@rdx)" mydrv+0x11230

:: Data breakpoint to catch a kernel read from a user pointer:
ba r1 <user_addr>

:: Pool-tag condition:
bp ExAllocatePool2 "/w (poi(@rcx+8)==0x20206656)"
```

WinDbg JS (built-in Chakra/Data Model; `C:\scripts\ioctllog.js`):

```javascript
// .scriptload C:\scripts\ioctllog.js
// Usage: dx @$scriptContents.RunCmd("!irp @rdx")
function RunCmd(cmd) {
    let ctl = host.namespace.Debugger.Utility.Control;
    let out = ctl.ExecuteCommand(cmd);
    for (let line of out) { host.diagnostics.debugLog(line + "\n"); }
}
function initializeScript() {
    return [new host.functionAlias(RunCmd, "RunCmd")];
}
```

Pair the script with a `bp … ".if(…) {} .else {g}"` whose body calls `dx @$scriptContents.RunCmd("…")` to log every hit automatically. Heavier automation uses pykd; the 2026 version additionally ships **WinDbg MCP** (AI clients connect straight into the live debug session, driving commands in natural language — the proper road to agentic kernel debugging, same idea as §3.4's ida-pro-mcp).

### 5.4 Crash-Dump Analysis (the fuzz→dump→locate Main Path)

```bat
:: Live two-machine debugging: a crash stops in KD; run !analyze -v directly
:: Offline: configure target-machine dumps (System Properties → Advanced → Startup and Recovery, or registry)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 2 /f
:: d=2 kernel dump, 7 automatic memory dump, 3 small dump (only a 64K stack, less information)

:: Analysis
windbgx -z C:\Windows\MEMORY.DMP
kd -z C:\Windows\Minidump\*.dmp
```

The localization routine (fixed order):

```
!analyze -v            → Does FAILURE_BUCKET_ID point to mydrv+offset? → RVA=offset-ImageBase
kb                     → Find frames belonging to the target driver
!irp <arg2寄存器存的irp> → Confirm this is our IOCTL (ctl code/process)
dq/bl 数据指针          → Check for a user address or pool-boundary violation
!pool <fault_addr>     → A free pool block indicates UAF; check tag ownership
```

**Industrializing the fuzz loop**: VM snapshot + an IOCTL fuzzer (homegrown/ioctlbf-class tool) varying lengths and values per CTL → crash → snapshot rollback → archive dumps and batch `!analyze -v` (`kd -z -c "!analyze -v; q"` scripted).

### 5.5 Driver Verifier (Turning "Silent Memory Corruption" into "Loud Crashes")

```bat
verifier /standard /driver mydrv.sys
:: Enable Special Pool alone (one page per allocation + guard page; overflows/dangling accesses cause immediate BSOD):
verifier /flags 0x8 /driver mydrv.sys
shutdown /r /t 0
:: In KD: !verifier 3; disable with verifier /reset
```

Of greatest value to UAF hypotheses: under Special Pool a freed block gets painted `0xF0EEF0EE…`; the crash then lands exactly on **the instruction that re-accesses the freed object** — the scene wasn't unfindable, it was too late; Verifier pulls the scene back to the first scene.

## 6. x64dbg User Mode (PE Vulnerability Verification)

### 6.1 Breakpoints and Conditional Breakpoints

```
bp DeviceIoControl                          ; Symbol breakpoint (x64: rcx=h, rdx=code, r8=inBuf)
SetBreakpointCondition DeviceIoControl, "rdx==0x222023"   ; Condition
SetBreakpointCommand DeviceIoControl, "log \"code={x:rdx} in={p:r8} len={x:r9}\"; run"
g
bphws <addr>, w                             ; Hardware write breakpoint to observe reclaimed UAF slots
bphwc *                                     ; Clear hardware breakpoints
```

Logging: `View→Log`; persistent tracing: `Trace→Trace Into→Stop condition`+`Log File`. Align argument observation with the x64 calling-convention registers (rcx/rdx/r8/r9); don't memorize pseudo-APIs.

### 6.2 Scripting and Plugins

- **x64dbgpy**: drop the GitHub release into `plugins\x64dbgpy`; after start, `Plugins→PythonConsole`; API: `Dbg.bpSet(addr)`, `Dbg.memRead`, `Dbg.cmdExec("g")` — write "break → read structure → decide continue" as a Python state machine.
- **Scylla**: not needed at the POC stage; for packed-target verification use dump+IAT (already covered in Debugging §7).
- Script command files (`.x64dbg` text, `Script→Load`): combinations of `bp`/`cond`/`log`/`run` cover 90% of the logging needs of driver-host EXEs.

### 6.3 The Three Moves of User-Mode Vulnerability Verification

1. **Argument observation**: bp the target API, log all arguments + the first 32 bytes of the buffer (`db r8 L20` inside the command).
2. **Data-flow tracking**: who changed an object field — hardware write breakpoints; when an object gets freed — bp `HeapFree`/custom Free with conditional hits.
3. **Exceptions are clues**: a crash deep inside your own DLL → no `!analyze`; use x64dbg's exception window (access-violation address + RIP) and map it straight back to the IDA RVA.

## 7. The Static→Dynamic→POC Loop (Two Complete Walk-Throughs)

### 7.1 Walk-Through A: A User-Mode UAF (a Protocol-Parsing DLL)

**Background**: `netsdk.dll` is loaded by a host EXE and exports `SdkOpen/SdkClose/SdkPoll`.

1. **Static (Ghidra)**: headless import + the §2.4 scripts → the `RtlHeapFree` xref list; decompile `SdkClose`:
   ```c
   SdkClose(ctx) { Free(ctx->pkt); Free(ctx); /* timer is not killed and still holds ctx */ }
   ```
   In `SdkPoll` the timer callback still dereferences `ctx` → **Hypothesis #1: Poll after Close = UAF read**, high confidence. Record: the free instruction RVA 0x2f10, the Poll callback's fetch of ctx->pkt RVA 0x3a44.
2. **Dynamic (x64dbg)**:
   ```
   bp netsdk.SdkClose           ; Break inside Free; step until it returns and record ctx address=0x1a4b3c20
   bphws 0x1a4b3c20, r          ; Set a hardware read breakpoint on the freed address
   g                            ; Trigger the timer by waiting or injecting an event
   → Stops at netsdk+0x3a44 reading [ctx+0x18] ← confirmed UAF: read from freed heap memory
   ```
3. **Occupancy controllability**: spray the same size (`ctx` size 0x48):
   ```
   : A host script or injected DLL repeatedly calls HeapAlloc(0x48) and fills with 0x41414141…
   bphws followed by g → breakpoint shows an indirect call such as RIP←[0x41414141…] → RIP control established
   ```
4. **POC solidification** (single file: LoadLibrary→SdkOpen→start a spraying thread→SdkClose→SdkPoll); a crash dump/EIP=0x41414141 completes the report's evidence chain.
5. **Wrap-up**: tag the two RVAs in Ghidra (`vuln_uaf_free`/`vuln_uaf_use`); mark the hypothesis verified.

### 7.2 Walk-Through B: A Driver's METHOD_NEITHER (No Probe)

**Background**: `mydrv.sys` creates `\\Device\\MyVulnDev` + a symbolic link; the §2.4 script two locates dispatch = the `mov [rcx+0xE0], rax` inside DriverEntry → handler RVA 0x11230.

1. **Static (IDA, the §3.3 script)**: the handler is on the NO-PROBE list + the case constant `0x222023` (CTL_CODE(0x8000,0x808,METHOD_NEITHER,FILE_ANY_ACCESS)); decompile that case:
   ```c
   in = stack->Parameters.DeviceIoControl.Type3InputBuffer; // Raw user pointer
   len = stack->Parameters.DeviceIoControl.InputBufferLength;
   RtlCopyMemory(kbuf, in, len);          // No ProbeForRead/__try
   ```
   **Hypothesis #2: arbitrary user pointers read directly by the kernel → crash/info leak; a double dereference = the raw material for TOCTOU arbitrary write**.
2. **Dynamic (WinDbg dual-machine, §5.1 already connected)**:
   ```bat
    :: Debugger machine
   lm vm mydrv                     ; Record base 0xFFFFF805`40000000 → handler=+0x11230
   bp mydrv+0x11230 ".if (poi(@rdx+0xd8) == 0x222023) {} .else {g}"  ; Verify the offset with dt
   g
   ```
   Run the minimal trigger program on the target (below) → hit → `!irp @rdx` confirms Type3InputBuffer = our user pointer → `t`/`p` step to `RtlCopyMemory` and watch the direct `mov rax,[user address]` with no Probe whatsoever.
3. **Crash proof**: point the input buffer at a **freed/guarded user page** (first `VirtualFree`, then pass it):
   → BSOD `PAGE_FAULT_IN_NONPAGED_AREA`; `!analyze -v`'s `SYMBOL_NAME=mydrv+XXX`, the stack top inside `RtlCopyMemory`, `!irp` showing ctl=0x222023 → a complete evidence chain.
4. **POC solidification** (`poc_neither.c`):
   ```c
   #include <windows.h>
   #include <stdio.h>
   #define CTL(c) CTL_CODE(0x8000, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
   int main(void) {
       HANDLE h = CreateFileW(L"\\\\.\\MyVulnDev", GENERIC_READ|GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
       if (h == INVALID_HANDLE_VALUE) { printf("open %lu\n", GetLastError()); return 1; }
       char *in = (char*)VirtualAlloc(NULL, 0x100, MEM_COMMIT, PAGE_READWRITE);
       memset(in, 0x41, 0x100);
       DWORD br; DWORD code = CTL(0);
       DeviceIoControl(h, code, in, 0x100, in, 0x100, &br, NULL);
       printf("err %lu\n", GetLastError());
       return 0;
   }
   ```
   Compile with `cl /W4 poc_neither.c`; the escalation direction for the report's "potential impact": two-thread TOCTOU — thread A repeatedly repoints Type3InputBuffer, the kernel dereferences twice with the pointer swapped in between → an arbitrary kernel-address read/write primitive.
5. **Wrap-up**: the hypothesis list verified; the `!drvobj mydrv 7` output cross-checked against the static dispatch, screenshotted into the report.

### 7.3 Loop Discipline (Distilled from the Two Walk-Throughs)

```
Static analysis produces hypotheses, not conclusions; dynamic analysis verifies hypotheses; any newly found surface returns to the static inventory
Each hypothesis requires all three: RVA + type + trigger parameters before dynamic verification
Three crash evidence items: !analyze symbol location + !irp request attribution + a stack trace back to user input
Minimize the PoC to reproduce; add heap spraying/RIP control as required by the reporting standard
At each round end: persist Ghidra/IDA comments and update the hypothesis state (pending→verified/refuted)
```

## Appendix: Related Chapters and External Anchors

> This part covers only the "how to hunt" pipeline; for structural principles see [basics.md](../basics.md) (PE/data structures/static analysis); for debugger principles see [debugging.md](../debugging.md) (breakpoints/exception dispatch/symbol fundamentals); for unpacking see [unpacking.md](../unpacking.md); for confrontation see [protection.md](../protection.md).
> External verification sources (2026-10): Ghidra Releases (github.com/NationalSecurityAgency/ghidra), Hex-Rays Release Notes (docs.hex-rays.com/release-notes), WinDbg docs and Release Notes (learn.microsoft.com/windows-hardware/drivers/debugger, …/windbg-release-notes), KDNET configuration (learn.microsoft.com → setting-up-a-network-debugging-connection), the official Ghidra PDB README_PDB.
