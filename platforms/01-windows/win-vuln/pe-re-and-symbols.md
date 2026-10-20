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
# DIE 命令行:壳/编译器/语言一次出
diec.exe C:\samples\target.sys

# pefile 精确判型(Subsystem=1 即 NATIVE 驱动)
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
| # | 位置(模块+RVA/函数名) | 假设类型 | 触发条件 | 置信度 | 验证方式(§/命令) |
| 1 | mydrv.sys+0x11230 IoctlHandler | METHOD_NEITHER 无 Probe | CTL 0x222023 | 高 | WinDbg bp + 传用户指针 |
```

## 2. The Ghidra Workflow (the Free Mainstay)

### 2.1 Installation and Headless Start

```bat
:: 1) JDK 21
winget install Microsoft.OpenJDK.21

:: 2) 解压 Ghidra 12.1.4,GUI 起步
C:\ghidra_12.1.4_PUBLIC\ghidraRun.bat

:: 3) headless 批量分析(注意先建项目目录)
mkdir C:\proj C:\scripts
C:\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat C:\proj vulnproj ^
  -import C:\samples\target.sys ^
  -scriptPath C:\scripts ^
  -postScript find_dangerous_xrefs.py > C:\proj\audit.log 2>&1

:: 4) 对已导入程序二次跑脚本(不重分析)
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
# find_dangerous_xrefs.py — postScript: 对敏感内核 API 列出全部调用者
SENSITIVE = [
  # 探针类:有=审计上下文;无=用户指针裸奔嫌疑(重要负证据)
  "ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages",
  # MDL/映射类:METHOD_NEITHER/直接访问用户内存的信号
  "MmGetSystemAddressForMdlSafe", "MmMapLockedPagesSpecifyCache", "IoAllocateMdl",
  # 拷贝类:长度来源审计(信任 InputBufferLength?)
  "RtlCopyMemory", "memcpy",
  # 池类:UAF/双 free/溢出
  "ExAllocatePoolWithTag", "ExAllocatePool2", "ExFreePoolWithTag",
  # 引用类:竞态降引用
  "ObReferenceObjectByHandle", "ObDereferenceObject",
  # 完成类:handler 候选定位
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
# find_ioctl_dispatch.py — 定位 DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]
# 偏移:x64 = 0x70 + 0x0E*8 = 0xE0;x86 = 0x34 + 0x0E*4 = 0x6C(IRP_MJ_DEVICE_CONTROL=0x0E)
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
        # DriverEntry 常见形态: lea rax,[handler]; mov [rcx+0xE0],rax
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

# 1) 收集"调用了 Probe 的函数"白名单
probed = set()
for n in PROBES:
    e = ea_of(n)
    if e != idaapi.BADADDR:
        for x in idautils.XrefsTo(e):
            f = ida_funcs.get_func(x.frm)
            if f: probed.add(f.start_ea)

# 2) handler 候选 = IofCompleteRequest 调用者
handlers = {}
comp = ea_of("IofCompleteRequest")
if comp != idaapi.BADADDR:
    for x in idautils.XrefsTo(comp):
        f = ida_funcs.get_func(x.frm)
        if f: handlers[f.start_ea] = idc.get_func_name(f.start_ea)

# 3) handler 里出现 METHOD_NEITHER 形态立即数((ctl&3)==3)且不在 Probe 白名单 → 高危
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
                   and op.value > 0x1000:   # 排除小常量
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
check_connection                      → 确认 IDA 在线
list_strings_filter "IOCTL|\\\\Device\\\\"   → 拿设备名/CTL 字串
get_function_by_name "SubIoctlHandler" → 定位
decompile_function <addr>              → 读伪码找漏洞形态
get_xrefs_to <ProbeForRead ea>         → 负证据:谁没用
set_comment <addr> "AUDIT: UAF 假设#2" → 结论落库
rename_function <addr> "vuln_read_oob" → 命名即报告素材
```

Essentials: the MCP loop suits interactive auditing of "discover → verify → annotate"; full-volume batch still goes through headless (§2.4); the two complement each other.

## 4. The Symbol System

### 4.1 The Microsoft Public Symbol Server (Syntax Unchanged as Verified 2026)

```
_NT_SYMBOL_PATH = srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

Three-segment semantics: `srv*local cache directory*upstream server`. Setup:

```bat
:: 用户级永久(新开的 WinDbg/Ghidra/IDA 全吃到)
setx _NT_SYMBOL_PATH srv*C:\symbols*https://msdl.microsoft.com/download/symbols

:: 会话级(当前 cmd)
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

Multi-level chaining (your own symbols first): `C:\mysym;srv*C:\symbols*https://msdl.microsoft.com/download/symbols`.

### 4.2 symchk Batch Downloads (the WDK Debuggers Directory)

```bat
:: 单文件(按其 DEBUG 目录 GUID 自动匹配)
symchk.exe C:\samples\mydrv.sys /s srv*C:\symbols*https://msdl.microsoft.com/download/symbols

:: 一次拉齐内核全家桶(ntoskrnl/hal/win32k…)
symchk.exe C:\Windows\System32\ntoskrnl.exe /om C:\sym_manifest.txt > nul

:: 校验已缓存
symchk.exe /v C:\symbols\ntkrnlmp.pdb
```

### 4.3 Manual PDB Downloads (URL Construction)

The PDB lookup chain sits in the EXE's DEBUG directory (the RSDS record): `PDB name + GUID (dashes stripped) + Age`.

```
# 从 pefile 提取
python -c "import pefile; pe=pefile.PE(r'C:\Windows\System32\ntoskrnl.exe'); \
 d=[e for e in pe.DIRECTORY_ENTRY_DEBUG if e.struct.Type==2][0]; \
 print(d.entry.PdbFileName, d.entry.Signature_Guid, hex(d.entry.Age))"

# URL = 服务器/{pdbname}/{GUID去连字符小写}{Age十六进制}/{pdbname}
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
:: 目标机(VM 即可;管理员 cmd)
bcdedit /debug on
:: 自动生成 key(推荐,kdnet.exe 在 WDK Debuggers 目录;同时校验网卡支持)
C:\Debuggers\amd64\kdnet.exe 192.168.56.1 50000
:: 它会输出形如: key=1.2.3.4 (或 2.0.spbrt... 格式),并直接替你写好 dbgsettings
:: 手动等价:
bcdedit /dbgsettings net hostip:192.168.56.1 port:50000 key:1.1.1.1
:: 多网卡时指定(设备管理器→网卡→详细信息→位置信息):
bcdedit /set "{dbgsettings}" busparams 0.25.0
shutdown /r /t 0
```

```bat
:: 调试机(宿主)
winget install Microsoft.WinDbg
:: GUI: File→Kernel Debug→Net, 填 port 50000 + key
:: 命令行等价:
windbgx -k net:port=50000,key=1.1.1.1
```

Once connected, `Ctrl+Break` breaks in, `g` continues; `qd` or the target's `bcdedit /debug off` exits. VM bonus: **take snapshots** — after a fuzz crash, rollback and retest in seconds.

### 5.2 Command Quick Reference (Vulnerability-Verification Oriented)

```
!analyze -v                 # 崩溃一站式:符号/栈/桶号(每次 BSOD 第一条)
dt nt!_EPROCESS             # 结构现场核对(禁止抄旧表)
dt nt!_IO_STACK_LOCATION    # Type3InputBuffer 偏移现场拿
!process 0 0                # 全进程; .process /i <EPROC> 切地址空间(KPTI 两跳)
!thread / !irp <addr>       # IRP 四要素: 谁发的/什么 IOCTL/缓冲区在哪
!pool <addr> / !poolused 2  # 池标签回溯——UAF/溢出的归属判定
!devobj <name|addr> / !drvobj mydrv 7   # 设备栈/驱动分发函数全景(直接列 dispatch!)
bp mydrv+0x1234 / ba e1 mydrv!Handler  # 断点(RVA 或符号)
ed <addr> <val>             # 改内存(修补校验跳过/篡改长度复测)
uf mydrv!Handler            # 整函数反汇编;k/cvn 查栈
!verifier 3                 # Driver Verifier 状态
.bugcheck / .lastevent      # 回看崩溃码与首因
!address / !pte <addr>      # 页表走查(PTE 有效? 用户/内核页?)
lm k / lmvm mydrv           # 模块基址表(rebase 计算)/模块详情
```

`!drvobj mydrv 7` prints the MajorFunction table directly — the dynamic counterpart of statically finding the dispatch (the verifier of the §2.4 script results).

### 5.3 Conditional Breakpoints and Scripting

```bat
:: 经典条件断点: 只停 IOCTL 0x222023 的请求
bp mydrv+0x11230 ".if (poi(@rdx+0xb8+0x20+0x18) == 0x222023) {} .else {g}"
:: x64 handler(DeviceObject@rcx, Irp@rdx); 用 dt 现场核对偏移再写死!

:: WinDbg 1.x 新语法(/w = Data Model 过滤器,命中才断,比 .if 快):
bp /w "myctl(@rdx)" mydrv+0x11230

:: 访问断点抓用户指针被内核读:
ba r1 <user_addr>

:: 池标签条件:
bp ExAllocatePool2 "/w (poi(@rcx+8)==0x20206656)"
```

WinDbg JS (built-in Chakra/Data Model; `C:\scripts\ioctllog.js`):

```javascript
// .scriptload C:\scripts\ioctllog.js
// 用法: dx @$scriptContents.RunCmd("!irp @rdx")
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
:: 双机在线: 崩溃自动断在 KD,直接 !analyze -v,最省事
:: 离线: 配置目标机 dump(系统属性→高级→启动与恢复;或注册表)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 2 /f
::   d=2 kernel dump, 7 自动 memory dump, 3 small(只有 64K 栈,信息少)

:: 分析
windbgx -z C:\Windows\MEMORY.DMP
kd -z C:\Windows\Minidump\*.dmp
```

The localization routine (fixed order):

```
!analyze -v            → FAILURE_BUCKET_ID 指向 mydrv+offset? → RVA=offset-ImageBase
kb                     → 栈里自己驱动帧
!irp <arg2寄存器存的irp> → 确认是我们的 IOCTL(ctl code/进程)
dq/bl 数据指针          → 是否用户地址/池块越界特征
!pool <fault_addr>     → Free 的池 = UAF; 标签归属
```

**Industrializing the fuzz loop**: VM snapshot + an IOCTL fuzzer (homegrown/ioctlbf-class tool) varying lengths and values per CTL → crash → snapshot rollback → archive dumps and batch `!analyze -v` (`kd -z -c "!analyze -v; q"` scripted).

### 5.5 Driver Verifier (Turning "Silent Memory Corruption" into "Loud Crashes")

```bat
verifier /standard /driver mydrv.sys
:: 单开 Special Pool(每次分配独页+护栏页,溢出/野指针当场 BSOD):
verifier /flags 0x8 /driver mydrv.sys
shutdown /r /t 0
:: KD 里查: !verifier 3 ; 关: verifier /reset
```

Of greatest value to UAF hypotheses: under Special Pool a freed block gets painted `0xF0EEF0EE…`; the crash then lands exactly on **the instruction that re-accesses the freed object** — the scene wasn't unfindable, it was too late; Verifier pulls the scene back to the first scene.

## 6. x64dbg User Mode (PE Vulnerability Verification)

### 6.1 Breakpoints and Conditional Breakpoints

```
bp DeviceIoControl                          ; 符号断点(x64: rcx=h, rdx=code, r8=inBuf)
SetBreakpointCondition DeviceIoControl, "rdx==0x222023"   ; 条件
SetBreakpointCommand DeviceIoControl, "log \"code={x:rdx} in={p:r8} len={x:r9}\"; run"
g
bphws <addr>, w                             ; 硬件写断点(UAF 换占位观察)
bphwc *                                     ; 清硬件断点
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
   SdkClose(ctx) { Free(ctx->pkt); Free(ctx); /* timer 未 Kill,持 ctx */ }
   ```
   In `SdkPoll` the timer callback still dereferences `ctx` → **Hypothesis #1: Poll after Close = UAF read**, high confidence. Record: the free instruction RVA 0x2f10, the Poll callback's fetch of ctx->pkt RVA 0x3a44.
2. **Dynamic (x64dbg)**:
   ```
   bp netsdk.SdkClose           ; 断在 Free 调用内: 单步到 Free 返回,记 ctx 地址=0x1a4b3c20
   bphws 0x1a4b3c20, r          ; 对 free 后地址下硬件读断点
   g                            ; 触发 timer(等待/注入事件)
   → 断在 netsdk+0x3a44 读 [ctx+0x18]  ← UAF 实锤(读已释放堆)
   ```
3. **Occupancy controllability**: spray the same size (`ctx` size 0x48):
   ```
   : 宿主脚本或注入 DLL 循环 HeapAlloc(0x48) 填 0x41414141…
   bphws 后 g → 断点显示 RIP←[0x41414141…] 类间接调用 → 控制 RIP 达成
   ```
4. **POC solidification** (single file: LoadLibrary→SdkOpen→start a spraying thread→SdkClose→SdkPoll); a crash dump/EIP=0x41414141 completes the report's evidence chain.
5. **Wrap-up**: tag the two RVAs in Ghidra (`vuln_uaf_free`/`vuln_uaf_use`); mark the hypothesis verified.

### 7.2 Walk-Through B: A Driver's METHOD_NEITHER (No Probe)

**Background**: `mydrv.sys` creates `\\Device\\MyVulnDev` + a symbolic link; the §2.4 script two locates dispatch = the `mov [rcx+0xE0], rax` inside DriverEntry → handler RVA 0x11230.

1. **Static (IDA, the §3.3 script)**: the handler is on the NO-PROBE list + the case constant `0x222023` (CTL_CODE(0x8000,0x808,METHOD_NEITHER,FILE_ANY_ACCESS)); decompile that case:
   ```c
   in = stack->Parameters.DeviceIoControl.Type3InputBuffer; // 用户裸指针
   len = stack->Parameters.DeviceIoControl.InputBufferLength;
   RtlCopyMemory(kbuf, in, len);          // 无 ProbeForRead/__try
   ```
   **Hypothesis #2: arbitrary user pointers read directly by the kernel → crash/info leak; a double dereference = the raw material for TOCTOU arbitrary write**.
2. **Dynamic (WinDbg dual-machine, §5.1 already connected)**:
   ```bat
   :: 调试机
   lm vm mydrv                     ; 记基址 0xFFFFF805`40000000 → handler=+0x11230
   bp mydrv+0x11230 ".if (poi(@rdx+0xd8) == 0x222023) {} .else {g}"  ; 用 dt 校偏移
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
静态只产"假设",不产"结论";动态只验"假设",不产"新面"(新面回静态清单)
每条假设 = RVA + 类型 + 触发参数 三要素齐才进动态
崩溃三证: !analyze 符号定位 + !irp 请求归属 + 栈回溯到用户输入
POC 最小化: 能复现即可,堆喷/RIP 控制按报告级别加码
每轮结束: Ghidra/IDA 注释落库 + 假设清单状态机(pending→verified/refuted)
```

## Appendix: Related Chapters and External Anchors

> This part covers only the "how to hunt" pipeline; for structural principles see [basics.md](../basics.md) (PE/data structures/static analysis); for debugger principles see [debugging.md](../debugging.md) (breakpoints/exception dispatch/symbol fundamentals); for unpacking see [unpacking.md](../unpacking.md); for confrontation see [protection.md](../protection.md).
> External verification sources (2026-10): Ghidra Releases (github.com/NationalSecurityAgency/ghidra), Hex-Rays Release Notes (docs.hex-rays.com/release-notes), WinDbg docs and Release Notes (learn.microsoft.com/windows-hardware/drivers/debugger, …/windbg-release-notes), KDNET configuration (learn.microsoft.com → setting-up-a-network-debugging-connection), the official Ghidra PDB README_PDB.
