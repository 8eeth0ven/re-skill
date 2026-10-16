# 知识库 · Windows 安全 · win-vuln · PE 逆向与符号分析(漏洞挖掘工作流)

> 定位:基础篇讲 PE 结构与静态分析原理,调试篇讲调试器原理与符号基础——本篇把两者组装成**漏洞挖掘流水线**:拿到未知 PE/驱动 → 判型 → 符号 → 静态审计(Ghidra/IDA)→ 漏洞假设 → 动态验证(WinDbg/x64dbg)→ POC。所有命令针对 2026-10 现版核对:Ghidra 12.1.4 / IDA 9.4 / WinDbg 1.26(winget `Microsoft.WinDbg`)。PE 字段含义不重述,查基础篇 §2。

## 0. 版本与工具基线(2026-10 核对)

| 工具 | 现版 | 获取 | 漏洞挖掘用途 |
|---|---|---|---|
| Ghidra | 12.1.4(2026-09) | github.com/NationalSecurityAgency/ghidra/releases | 免费反编译主力 + headless 批量审计 |
| IDA Pro | 9.4(2026-09) | hex-rays.com 订阅 | 精读 + IDAPython + MCP 自动化 |
| WinDbg | 1.26(`winget install Microsoft.WinDbg`) | Store/winget,已内置 WinDbg MCP | 内核调试/dump 分析唯一正选 |
| x64dbg | snapshot | x64dbg.io | 用户态验证/POC 驱动 |
| DIE / symchk / kdnet | — | DIE 官网 / WDK Debuggers | 判型查壳 / 符号下载 / KDNET 自动配置 |

JDK 基线:Ghidra 11.3+ 需要 **JDK 21+**。macOS/Linux 侧同样可跑 headless(交叉审计用)。

## 1. 逆向工作流总览

### 1.1 流程图(标准管线)

```
未知 PE/SYS(样本/驱动 dump/厂商组件)
   │
   ① 判型(§1.2):EXE/DLL/SYS? .NET? 32/64? 子系统?
   │      ├─ .NET(CLR 目录非 0)→ dnSpy/ILSpy,不走本流程
   │      └─ Native → 继续
   ② 查壳(熵/EP/输入表,调试篇 §1)→ 有壳 → 脱壳(解密篇 §3)→ 回 ①
   │
   ③ 符号先行(§4):DEBUG 目录 GUID/Age → symchk 下 PDB → 命中率决定后面 3 倍效率
   │
   ④ 静态审计(§2 Ghidra / §3 IDA)
   │      ├─ 自动分析 + 类型恢复 → 脚本批量扫 sink(xref 清单)
   │      └─ 人工反编译热点:入口面(IOCTL/导出函数/回调注册/解析器)
   ▼
⑤ 漏洞假设清单(每条 = 位置 + 类型 + 触发条件 + 置信度)
   │
   ⑥ 动态验证(§5 WinDbg 内核 / §6 x64dbg 用户态):断点/trace/崩溃复现
   │
   ⑦ POC 构造 → 可控性证明(崩=最低配,读/写/RIP=完整链)→ 报告
```

### 1.2 判型(命令可复制)

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

判读:Machine 0x8664=x64 / 0x14c=x86;Subsystem 1=NATIVE(驱动,4 层无 CRT 可用 `/MT` 静态);CLR 目录非 0 → .NET 走 dnSpy;驱动 + 无重定位(.reloc 空)→ 加载必失败,可疑残缺/伪造。

### 1.3 漏洞挖掘的"输入面"优先级(静态审计前先想好看哪)

| 目标类型 | 输入面(攻击面) | 优先审 |
|---|---|---|
| 内核驱动 .sys | DeviceIoControl 的每个 CTL_CODE、读写 dispatch(IRP_MJ_READ/WRITE)、FastIo | handler 长度校验、用户指针 Probe、池生命周期 |
| 系统服务 DLL/EXE | RPC/ALPC 接口、命名管道、本地 DCOM | 反序列化、整数溢出、权限检查时序 |
| 普通应用 | 文件解析器(图片/文档)、网络协议栈 | 解析循环边界、UAF |
| 打印/字体/内核回调 | winspool、gdi、OB_CALLBACK | 回调参数信任 |

入口面清单直接决定 §2.4 脚本扫什么 sink。

### 1.4 漏洞假设清单模板(贯穿本篇的工作产物)

```
| # | 位置(模块+RVA/函数名) | 假设类型 | 触发条件 | 置信度 | 验证方式(§/命令) |
| 1 | mydrv.sys+0x11230 IoctlHandler | METHOD_NEITHER 无 Probe | CTL 0x222023 | 高 | WinDbg bp + 传用户指针 |
```

## 2. Ghidra 工作流(免费主力)

### 2.1 安装与 headless 起步

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

参数要点:`-processor x86:LE:64:default` 可省(PE 自动识别);`-analysisTimeoutPerFile 900` 防大驱动卡死;`-deleteProject` 一次性批处理;`.py` 脚本 11.3+ 优先经 PyGhidra(原生 CPython,可 import capstone/requests),传统 Jython 写法仍兼容。

### 2.2 导入与自动分析选项(驱动专用)

导入向导(`File→Import File`)对 .sys:Language 选 `x86:LE:64:default`,Format 选 **PE**;导入后弹 Auto Analysis,驱动场景保留/加开:

- `Decompiler Parameter ID`(参数恢复,必开)
- `Decompiler Switch Analysis`(switch → IOCTL 分发表还原)
- `Function Start Search` + `Instruction` **Separator** 模式(剥离符号的驱动补函数边界)
- `Windows x86 PE RTTI`、`Demangler`(C++ 驱动)
- `Stack` 栈帧变量(局部缓冲区溢出审计地基)

### 2.3 符号与类型恢复

1. PDB:设置 `setx _NT_SYMBOL_PATH srv*C:\symbols*https://msdl.microsoft.com/download/symbols` 后重开 Ghidra → `File→Load PDB File…→Advanced>>→勾 Symbol Server→Search All`,命中即全量符号+类型(详见 §4)。
2. ntoskrnl 结构(`_EPROCESS/_IRP/_IO_STACK_LOCATION`):驱动 PDB 自带类型;无 PDB 时用 `llvm-pdbutil dump -types ntoskrnl.pdb` 对照手抄,或从 ReactOS/WRK 头维护一个 ghidra `.gdt` 类型库(`File→Parse C Source` 直接吃 WDK 头是最快路径)。
3. 应用 PDB 后 `Search→For Strings` + `Window→Functions` 里函数名直接可读,IOCTL handler 类函数常名含 `Ioctl/Dispatch/DeviceControl`。

### 2.4 审计脚本(批量化核心)

**脚本一:危险 sink 交叉引用清单**(C:\scripts\find_dangerous_xrefs.py):

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

**脚本二:IOCTL 分发定位**(C:\scripts\find_ioctl_dispatch.py):

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

跟进:进入 handler,`Switch Analysis` 后 Graph 视图每个 case 即一个 CTL_CODE;对每个立即数 `(code & 3)==3` → METHOD_NEITHER 候选,记入假设清单。

### 2.5 实战要点

1. headless 全量跑完再开 GUI 读脚本结果,不要 GUI 里等人肉点分析。
2. `IofCompleteRequest` 的调用者集合 ≈ 全部 IRP handler 候选池——比从 DriverEntry 追 dispatch 更全(还有 FastIo/回调)。
3. 反编译窗口里 `PoolWithTag` 的 Tag 常量、`CTL_CODE` 立即数,直接 `L` 键加标签,假设清单联动。
4. 跨版本 diff:同厂商新旧 .sys 各建项目,`Version Tracking` 工具对齐函数,补丁函数=历史漏洞现场(0day 线索金矿)。

## 3. IDA 工作流

### 3.1 驱动加载(内核重定位/段)

拖入 .sys:PE 命中 64-bit,Loading 勾 **Manual load**;ImageBase 提示默认接受(驱动 preferred base x64 常为 `0x1C0000000`/x86 `0x10000`,IDA 9 自动)。要点:

- 内核驱动无导入表解析器辅助(仅 ntoskrnl/hal 导入),IDA 仍列 Imports——`MmGetSystemAddressForMdlSafe` 等直接可搜。
- 运行时 rebase:从 WinDbg `lm vm mydrv` 拿实际基址,IDA `Edit→Segments→Rebase program`(或命令 `rebase(0xFFFFF80…)`),让 IDA 地址与调试器地址一致,断点地址可直接复制。
- CFG/CET 驱动看 `LOAD_CONFIG` 目录;`.pdata` 缺失(未做 SEH 表)本身是线索。

### 3.2 FLIRT/签名

`File→Signature file`(`Shift+F5`)加载 `vc64*.sig`(静态 CRT 归位,几千 sub_ 变 `memcpy`);WinDDK 编译驱动可自制 FLIRT:同一 WDK 版本编最小工程,`flair` 工具链产 sig,一次投入长期回本。

### 3.3 IDAPython 审计骨架(ProbeForRead 缺失 / METHOD_NEITHER)

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

配套:`Alt+T` 搜 `85 c0 74`(探针后 test/jz)只是玄学,真判据是反编译里 `Type3InputBuffer` 的直接解引用;对候选函数逐个 `F5` 人读——`(IO_STACK_LOCATION*)Irp->Tail.Overlay.CurrentStackLocation - 1` 的 `Parameters.DeviceIoControl.Type3InputBuffer` 无 `__try` 包裹即实锤线索。

### 3.4 与 MCP 的自动化(LLM 驱动 IDA)

本环境 `ida-pro-mcp` 插件(或同构开源版)把 IDA 暴露给 agent,典型审计循环不再写一次性脚本,而是对话式驱动:

```
check_connection                      → 确认 IDA 在线
list_strings_filter "IOCTL|\\\\Device\\\\"   → 拿设备名/CTL 字串
get_function_by_name "SubIoctlHandler" → 定位
decompile_function <addr>              → 读伪码找漏洞形态
get_xrefs_to <ProbeForRead ea>         → 负证据:谁没用
set_comment <addr> "AUDIT: UAF 假设#2" → 结论落库
rename_function <addr> "vuln_read_oob" → 命名即报告素材
```

要点:MCP 循环适合"发现→求证→落注"的交互审计;全量批量仍走 headless(§2.4),两者互补。

## 4. 符号体系

### 4.1 Microsoft 公共符号服务器(语法 2026 核对不变)

```
_NT_SYMBOL_PATH = srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

三段语义:`srv*本地缓存目录*上游服务器`。设置:

```bat
:: 用户级永久(新开的 WinDbg/Ghidra/IDA 全吃到)
setx _NT_SYMBOL_PATH srv*C:\symbols*https://msdl.microsoft.com/download/symbols

:: 会话级(当前 cmd)
set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

多级串联(自家符号优先):`C:\mysym;srv*C:\symbols*https://msdl.microsoft.com/download/symbols`。

### 4.2 symchk 批量下载(WDK Debuggers 目录)

```bat
:: 单文件(按其 DEBUG 目录 GUID 自动匹配)
symchk.exe C:\samples\mydrv.sys /s srv*C:\symbols*https://msdl.microsoft.com/download/symbols

:: 一次拉齐内核全家桶(ntoskrnl/hal/win32k…)
symchk.exe C:\Windows\System32\ntoskrnl.exe /om C:\sym_manifest.txt > nul

:: 校验已缓存
symchk.exe /v C:\symbols\ntkrnlmp.pdb
```

### 4.3 手动下载 PDB(URL 拼法)

PDB 查找链在 EXE 的 DEBUG 目录(RSDS 记录):`PDB 名 + GUID(去连字符)+ Age`。

```
# 从 pefile 提取
python -c "import pefile; pe=pefile.PE(r'C:\Windows\System32\ntoskrnl.exe'); \
 d=[e for e in pe.DIRECTORY_ENTRY_DEBUG if e.struct.Type==2][0]; \
 print(d.entry.PdbFileName, d.entry.Signature_Guid, hex(d.entry.Age))"

# URL = 服务器/{pdbname}/{GUID去连字符小写}{Age十六进制}/{pdbname}
curl -O https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/9c1c8a4b1234abcd1/ntkrnlmp.pdb
```

适用:msdl 按目录直链可下(无鉴权);目标驱动若 PDB 在厂商 HTTP 服务器(URL 常泄在 DEBUG 目录 path 字符串里,如 `\\buildsvr\drops\xxx.pdb`),把 `srv*C:\sym*https://vendor.example/pdb` 追加进 `_NT_SYMBOL_PATH`。

### 4.4 三工具挂载

- **WinDbg**:`.sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols` + `.reload /f mydrv.sys`;`lm vm mydrv` 看 `PDB signature` 一致即命中。内核会话自动按各模块 GUID 拉取。
- **Ghidra**:`File→Load PDB File…→Advanced→Search All`(吃 `_NT_SYMBOL_PATH`);headless 中 PDB URL 已设则导入时自动尝试。
- **IDA**:加载时弹 PDB 下载(吃 `_NT_SYMBOL_PATH`);重挂:`File→Load file→PDB file`;类型进 `Local Types`(Shift+F1)可 `Insert from PDB`。

### 4.5 符号缺失时(闭源驱动/被剥离)

1. **导出锚点法**:驱动导出表(`dumpbin /exports mydrv.sys` / pefile)中的函数地址是可靠锚;非导出函数按与锚点的相对偏移(RVA 差)在 IDA 里手工命名。
2. **跨版本锚定**:旧版有 PDB(或历史泄露)+ 新版无 → 导出表对齐 + `Binary diff`(Diaphora/BDiff/Ghidra Version Tracking)迁移符号。
3. **WinDbg 侧**:`lm k` 看无符号模块基址;`!dh mydrv -f` 直接 dump PE 头找 DEBUG 目录看 PDB 路径字符串;断点用 `bp mydrv+RVA`(IDA 里算好 RVA)。
4. **重定位陷阱**:IDA 里地址=preferred base+RVA,WinDbg 里=运行基址+RVA;换算脚本常备 `rva = ida_addr - ida_imagebase`。

## 5. WinDbg 工作流(内核主战场)

### 5.1 双机内核调试(KDNET,现版标准姿势)

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

连上后 `Ctrl+Break` 断下,`g` 继续;`qd` 或目标 `bcdedit /debug off` 退出。虚拟机加分项:**拍快照**——fuzz 崩溃后秒回滚重测。

### 5.2 命令速查(漏洞验证向)

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

`!drvobj mydrv 7` 直接打印 MajorFunction 表——静态分析找 dispatch 的动态对照(§2.4 脚本结果的验证器)。

### 5.3 条件断点与脚本

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

WinDbg JS(内置 Chakra/Data Model;`C:\scripts\ioctllog.js`):

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

脚本再配 `bp … ".if(…) {} .else {g}"` 内 `dx @$scriptContents.RunCmd("…")` 即可自动化记录每次命中。更重的自动化用 pykd;2026 版另内置 **WinDbg MCP**(AI 客户端直连活动调试会话,自然语言驱动命令——agent 化内核调试的正路,与 §3.4 的 ida-pro-mcp 同思路)。

### 5.4 崩溃转储分析(fuzz→dump→定位 主路径)

```bat
:: 双机在线: 崩溃自动断在 KD,直接 !analyze -v,最省事
:: 离线: 配置目标机 dump(系统属性→高级→启动与恢复;或注册表)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 2 /f
::   d=2 kernel dump, 7 自动 memory dump, 3 small(只有 64K 栈,信息少)

:: 分析
windbgx -z C:\Windows\MEMORY.DMP
kd -z C:\Windows\Minidump\*.dmp
```

定位套路(顺序固定):

```
!analyze -v            → FAILURE_BUCKET_ID 指向 mydrv+offset? → RVA=offset-ImageBase
kb                     → 栈里自己驱动帧
!irp <arg2寄存器存的irp> → 确认是我们的 IOCTL(ctl code/进程)
dq/bl 数据指针          → 是否用户地址/池块越界特征
!pool <fault_addr>     → Free 的池 = UAF; 标签归属
```

**fuzz 循环工程化**:VM 快照 + IOCTL fuzzer(自研/ioctlbf 类工具)逐 CTL 变长变值 → 崩 → 快照回滚 → dump 归档批量 `!analyze -v`(`kd -z -c "!analyze -v; q"` 脚本化)。

### 5.5 Driver Verifier(把"隐性内存破坏"变"显性崩溃")

```bat
verifier /standard /driver mydrv.sys
:: 单开 Special Pool(每次分配独页+护栏页,溢出/野指针当场 BSOD):
verifier /flags 0x8 /driver mydrv.sys
shutdown /r /t 0
:: KD 里查: !verifier 3 ; 关: verifier /reset
```

对 UAF 假设价值最大:Special Pool 下 freed block 被改成 `0xF0EEF0EE…` 模式,崩溃即出现在**被 freed 对象再访问的那一条指令**——不是事发现场找不到,是现场太晚;Verifier 把现场拉回第一现场。

## 6. x64dbg 用户态(PE 漏洞验证)

### 6.1 断点与条件断点

```
bp DeviceIoControl                          ; 符号断点(x64: rcx=h, rdx=code, r8=inBuf)
SetBreakpointCondition DeviceIoControl, "rdx==0x222023"   ; 条件
SetBreakpointCommand DeviceIoControl, "log \"code={x:rdx} in={p:r8} len={x:r9}\"; run"
g
bphws <addr>, w                             ; 硬件写断点(UAF 换占位观察)
bphwc *                                     ; 清硬件断点
```

日志:`View→Log`;持久 trace:`Trace→Trace Into→Stop condition`+`Log File`。参数观察对齐 x64 调用约定寄存器(rcx/rdx/r8/r9),别背伪 API。

### 6.2 脚本与插件

- **x64dbgpy**:GitHub release 放 `plugins\x64dbgpy`,启动后 `Plugins→PythonConsole`,API:`Dbg.bpSet(addr)`、`Dbg.memRead`、`Dbg.cmdExec("g")`——把"断下→读结构→决定继续"写成 Python 状态机。
- **Scylla**:POC 阶段不需要;带壳目标验证时 dump+IAT(调试篇 §7 已述)。
- 脚本命令文件(`.x64dbg` 文本,`Script→Load`):`bp`/`cond`/`log`/`run` 组合即可覆盖 90% 驱动宿主 EXE 的记录需求。

### 6.3 用户态漏洞验证三板斧

1. **参数观测**:bp 目标 API,log 全参数+缓冲区前 32 字节(`db r8 L20` 进命令)。
2. **数据流跟踪**:对象字段被谁改——硬件写断点;对象何时被释放——bp `HeapFree`/自定义 Free 条件命中。
3. **异常即线索**:崩在自家 DLL 深处 → `!analyze` 不存在,用 x64dbg 异常窗(访问违规地址+RIP)直接对回 IDA RVA。

## 7. 静态→动态→POC 闭环(两个完整走例)

### 7.1 走例 A:用户态 UAF(某协议解析 DLL)

**背景**:`netsdk.dll` 宿主 EXE 加载,导出 `SdkOpen/SdkClose/SdkPoll`。

1. **静态(Ghidra)**:headless 导入+§2.4 脚本 → `RtlHeapFree` xref 列表;反编译 `SdkClose`:
   ```c
   SdkClose(ctx) { Free(ctx->pkt); Free(ctx); /* timer 未 Kill,持 ctx */ }
   ```
   `SdkPoll` 里 timer 回调仍解引用 `ctx` → **假设#1:Close 后 Poll=UAF 读**,置信度高。记录:free 指令 RVA 0x2f10,Poll 回调取 ctx->pkt RVA 0x3a44。
2. **动态(x64dbg)**:
   ```
   bp netsdk.SdkClose           ; 断在 Free 调用内: 单步到 Free 返回,记 ctx 地址=0x1a4b3c20
   bphws 0x1a4b3c20, r          ; 对 free 后地址下硬件读断点
   g                            ; 触发 timer(等待/注入事件)
   → 断在 netsdk+0x3a44 读 [ctx+0x18]  ← UAF 实锤(读已释放堆)
   ```
3. **占位可控性**:喷同 size(`ctx` size 0x48):
   ```
   : 宿主脚本或注入 DLL 循环 HeapAlloc(0x48) 填 0x41414141…
   bphws 后 g → 断点显示 RIP←[0x41414141…] 类间接调用 → 控制 RIP 达成
   ```
4. **POC 固化**(单文件:LoadLibrary→SdkOpen→起线程喷→SdkClose→SdkPoll),崩溃转储/EIP=0x41414141 即报告证据链完整。
5. **收尾**:Ghidra 里两处 RVA 加标签(`vuln_uaf_free`/`vuln_uaf_use`),假设清单置 verified。

### 7.2 走例 B:驱动 METHOD_NEITHER(无 Probe)

**背景**:`mydrv.sys` 创建 `\\Device\\MyVulnDev`+符号链接;§2.4 脚本二定位 dispatch=DriverEntry 内 `mov [rcx+0xE0], rax` → handler RVA 0x11230。

1. **静态(IDA,§3.3 脚本)**:handler 在 NO-PROBE 名单 + case 常量 `0x222023`(CTL_CODE(0x8000,0x808,METHOD_NEITHER,FILE_ANY_ACCESS));反编译该 case:
   ```c
   in = stack->Parameters.DeviceIoControl.Type3InputBuffer; // 用户裸指针
   len = stack->Parameters.DeviceIoControl.InputBufferLength;
   RtlCopyMemory(kbuf, in, len);          // 无 ProbeForRead/__try
   ```
   **假设#2:任意用户指针被内核直接读 → 崩溃/信息泄露;双解引用=TOCTOU 任意写原料**。
2. **动态(WinDbg 双机,§5.1 已连)**:
   ```bat
   :: 调试机
   lm vm mydrv                     ; 记基址 0xFFFFF805`40000000 → handler=+0x11230
   bp mydrv+0x11230 ".if (poi(@rdx+0xd8) == 0x222023) {} .else {g}"  ; 用 dt 校偏移
   g
   ```
   目标机跑最小触发程序(见下) → 命中 → `!irp @rdx` 确认 Type3InputBuffer=我们的用户指针 → `t`/`p` 步进到 `RtlCopyMemory` 看直接 `mov rax,[用户址]` 无任何 Probe。
3. **崩溃实证**:把输入缓冲指向**已释放/保护用户页**(先 `VirtualFree` 再传):
   → BSOD `PAGE_FAULT_IN_NONPAGED_AREA`;`!analyze -v` 的 `SYMBOL_NAME=mydrv+XXX`、栈顶在 `RtlCopyMemory`、`!irp` 显示 ctl=0x222023 → 完整证据链。
4. **POC 固化**(`poc_neither.c`):
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
   编译 `cl /W4 poc_neither.c`;升级利用方向(报告写"潜在影响"):双线程 TOCTOU——线程 A 反复改 Type3InputBuffer 指向、内核两次解引用间被换 → 任意内核地址读写原语。
5. **收尾**:假设清单 verified;`!drvobj mydrv 7` 输出与静态 dispatch 对照截图入报告。

### 7.3 闭环纪律(两条走例提炼)

```
静态只产"假设",不产"结论";动态只验"假设",不产"新面"(新面回静态清单)
每条假设 = RVA + 类型 + 触发参数 三要素齐才进动态
崩溃三证: !analyze 符号定位 + !irp 请求归属 + 栈回溯到用户输入
POC 最小化: 能复现即可,堆喷/RIP 控制按报告级别加码
每轮结束: Ghidra/IDA 注释落库 + 假设清单状态机(pending→verified/refuted)
```

## 附:相关篇目与外部锚点

> 本篇只讲"怎么挖"的流水线;结构原理查《基础篇》(PE/数据结构/静态分析),调试器原理查《调试篇》(断点/异常分发/符号基础),脱壳查《解密篇》,对抗查《保护篇》。
> 外部核对源(2026-10):Ghidra Releases(github.com/NationalSecurityAgency/ghidra)、Hex-Rays Release Notes(docs.hex-rays.com/release-notes)、WinDbg 文档与 Release Notes(learn.microsoft.com/windows-hardware/drivers/debugger、…/windbg-release-notes)、KDNET 配置(learn.microsoft.com → setting-up-a-network-debugging-connection)、Ghidra PDB 官方 README_PDB。
