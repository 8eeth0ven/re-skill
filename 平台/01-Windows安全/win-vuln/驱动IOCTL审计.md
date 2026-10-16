# Windows 驱动 IOCTL 审计(白盒定位漏洞手册)

> 分工边界:`编程篇.md §5` 已讲驱动怎么写(IRP/IOCTL 基础、安全红线三句话),`11-漏洞根因学/内核漏洞根因案例.md` 已讲内存错误为什么发生;**本篇只回答「攻击面在哪、审计查什么、用什么工具、怎么从 BSOD 走到可利用原语」**。环境搭建(IDA/Ghidra/双机调试)见同目录 `工具链搭建.md`。
> 事实核对:CTL_CODE 位布局对照 Microsoft 头文件与本地帖 125640(IOCTL 解码程序);SDDL/设备对象安全对照 learn.microsoft.com(SDDL for Device Objects / Named Device Objects);fuzzer 清单与 BYOVD 案例于 2026-10-16 联网复核。

## 0. 心法与流程总览

**一句话**:驱动漏洞 = 「用户态够得着的入口」 × 「入口上没做对的检查」。IOCTL 是其中最宽的一条入口——每个 CTL_CODE 都是一个暴露给任意用户态进程的内核函数调用。

标准审计流水线(六步,后面各节展开):

```
① 枚举暴露面:设备名/符号链接/ACL —— 哪些设备我(低权限)能 CreateFile 打开?
② 提取 IOCTL 码:逆向分发函数/字符串/常量 cmp —— 一共暴露了几个功能号?
③ 拆码定性:每个码的 Method(BUFFERED/DIRECT/NEITHER)+ Access 位 —— 高危面排序
④ Checklist 逐条过分发链(§3 七条 + 附加三条)—— 正反例比对
⑤ Fuzzer 轰一遍(§4.3)—— 补静态漏网
⑥ BSOD → !analyze -v → 定位 handler → 最小复现 → 判可利用性 → 报告
```

**价值排序**(力气先砸哪):METHOD_NEITHER 未探针 > 敏感功能任意用户可开(读 MSR/物理内存/内核读写) > 长度/整数校验缺失 > 双取 > 输出溢出 > 异步/引用计数。白盒审计时 ③ 拆码定性直接决定 ④ 的审查强度,别平均用力。

---

## 1. 驱动暴露面枚举

### 1.1 命名空间:设备对象、符号链接与 `\\.\`

- 内核侧真名:`\Device\xxx`(IoCreateDevice / WdfDeviceCreate 创建)。
- 用户态可见:`\??\xxx` / `\Global??\xxx`(Vista 起 session 隔离,全局符号链接在 `\Global??`),由 `IoCreateSymbolicLink(L"\\DosDevices\\xxx", L"\\Device\\xxx")` 建立。
- 用户态打开写法:`CreateFile("\\\\.\\xxx", ...)`,等价 `\Device\xxx` 的符号链接;**没有符号链接也能打**——`\\.\GLOBALROOT\Device\xxx`(NtCreateFile 直接穿到对象目录),审计时别只盯 `\\.\`。
- 代码层识别(白盒):在 DriverEntry 里找三件套——`IoCreateDevice*`(或 WDF 的 `WdfDeviceInitSetName`/`WdfDeviceCreate`)、`IoCreateSymbolicLink`、`RtlInitUnicodeString` 的字符串常量(`\Device\`、`\DosDevices\` 直接 strings/grep 就出)。UMDF 驱动设备在 `\Device\_`...? 不常见于攻击面,先跳过。

**快速判断「这驱动有没有面」**:strings 搜 `\Device\` 与 `\DosDevices\`;一个 `.sys` 没有任何设备名 → 无直接 IOCTL 面(可能是过滤驱动 minifilter/回调型,审计面转 IRP 过滤/回调注册,不在本篇)。

### 1.2 ACL/SDDL:谁能打开设备

创建时可以指定安全描述符(SDDL 字符串)。**没指定 ≠ 安全**,要看默认值与 INF 覆盖:

| 创建路径 | API | 效果 |
|---|---|---|
| WDM 裸 `IoCreateDevice` | 无 SDDL 参数 | 命名设备走 I/O 管理器默认(取决于 `FILE_DEVICE_SECURE_OPEN` 与 INF);默认基本是 System/Admin 全权 |
| WDM 安全创建 | `IoCreateDeviceSecure`(wdmsec.h,链 wdmsec.lib) | 显式给 SDDL |
| KMDF | `WdfDeviceInitAssignSDDL`(必须在 `WdfDeviceCreate` **之前**) | 显式给 SDDL |
| INF | `DEVICE SECURITY` 段 / 注册表 `Security` 值 | **优先级最高,覆盖上面一切**(OSR《Making Device Objects Accessible and Safe》) |

预定义串(learn.microsoft.com《SDDL for Device Objects》):`SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RX_RES_RWX` = SYSTEM 全权、Admins RWX、**Everyone 只读执行**。要让普通用户能 open+发 IOCTL(写访问),厂商必须自己写 `D:P(A;;GA;;;WD)` 这类放水串——**搜索目标:SDDL 里出现 `;;;WD)`(Everyone 拿 GA/RWX)= 任意用户全权开设备**。

反例(肥面典型, Dell dbutil 一族形态):

```c
// 反例:未指定安全 + 符号链接全局可见 → 低权限用户可开可发
RtlInitUnicodeString(&dev, L"\\Device\\DBUtil");
IoCreateDevice(drv, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
RtlInitUnicodeString(&lnk, L"\\DosDevices\\DBUtil");
IoCreateSymbolicLink(&lnk, &dev);
```

正例:

```c
// 正例:显式 SDDL,Everyone 无权;敏感功能走 FILE_READ_DATA|FILE_WRITE_ACCESS 的 CTL_CODE
RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"); // 仅 SYSTEM/Administrators
status = IoCreateDeviceSecure(drv, 0, &dev, FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, NULL, &devObj);
```

检测方法(白盒):grep `WdfDeviceInitAssignSDDL|IoCreateDeviceSecure|SDDL_DEVOBJ`,没有 → 查 INF;仍没有 → 动态验证(§1.4)。另注意 `Exclusive=TRUE` 只防并发开,不是 ACL。

### 1.3 Access 位与 IOCTL 权限的联动(常被忽略)

CTL_CODE 的 Access 位(FILE_ANY_ACCESS=0/READ=1/WRITE=2/BOTH=3)决定**打开句柄所需的访问权**,I/O 管理器在 `IofCallDriver` 前校验。写了 `FILE_ANY_ACCESS` 的敏感功能码 = 只要能开设备就能调——配合放水 SDDL 双重失守。审计:拆出每个码的 Access 位,「任意物理内存读写 + FILE_ANY_ACCESS」直接标红。

### 1.4 用户态定位可开设备(黑盒侧印证)

- **WinObj**(Sysinternals):GUI 浏览 `\??`、`\GLOBAL??`、`\Device`,右键看安全描述符(谁有什么权限一目了然)。
- **DeviceTree**(OSR):按驱动列设备对象,白盒逆向完拿它对账。
- 脚本化:自写 20 行 `NtQueryDirectoryObject` 枚举器遍历 `\Device` 与 `\Global??`(PowerShell 原生列不了对象目录);`driverquery /FO LIST /V` + `Get-CimInstance Win32_SystemDriver` 先圈驱动集合。
- **试开判定矩阵**(最直接):

```
CreateFile("\\\\.<name>", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
→ SUCCESS          :低权限可写开 —— 面成立,进 §2
→ ERROR_ACCESS_DENIED:ACL 拦(GENERIC_READ 再试一次,部分设备只读可开)
→ ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND:名字错或无符号链接,试 GLOBALROOT\Device\ 路径
```

---

## 2. IOCTL 分发链与 CTL_CODE 拆解

### 2.1 完整链路

```
用户态 DeviceIoControl(hDev, ctl, inBuf, inLen, outBuf, outLen, &ret, NULL)
  → ntdll → NtDeviceIoControlFile → IO 管理器组 IRP(MajorFunction=IRP_MJ_DEVICE_CONTROL=0x0E)
  → 按句柄找到设备对象 → 驱动的 DriverObject->MajorFunction[0x0E](WDM)
    / KMDF: WdfIoQueue 的 EvtIoDeviceControl 回调
  → dispatch 读 IoGetCurrentIrpStackLocation(irp)->Parameters.DeviceIoControl.IoControlCode
  → switch(ctl) 或跳表 分发到子函数
```

WDM dispatch 骨架(审计以此为入口函数,本地帖 86002《windows驱动漏洞发现与利用》有完整版):

```c
NTSTATUS IoctlDispatch(PDEVICE_OBJECT dev, PIRP irp) {
    PIO_STACK_LOCATION ios = IoGetCurrentIrpStackLocation(irp);
    ULONG ctl = ios->Parameters.DeviceIoControl.IoControlCode;
    switch (ctl) {
    case IOCTL_READ_SOMETHING: ... // 逐 case 审计
    default: status = STATUS_INVALID_DEVICE_REQUEST;
    }
    irp->IoStatus.Status = status; irp->IoStatus.Information = ret;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
```

### 2.2 CTL_CODE 位拆解(拆码是定性第一步)

`#define CTL_CODE(DT, FN, METHOD, ACCESS) ((DT<<16)|(ACCESS<<14)|(FN<<2)|METHOD)`

| 位段 | 含义 | 审计注意 |
|---|---|---|
| 31-28 | 常见设备类型高位(0x22=UNKNOWN 最常见) | 0x22/自定义 0x8000+ = 三方驱动典型 |
| 27-16 | DeviceType(12 位) | FILE_DEVICE_UNKNOWN=0x22、FILE_DEVICE_DISK=0x07 等 |
| 15-14 | Access(0=ANY/1=READ/2=WRITE/3=BOTH) | **敏感功能配 ANY_ACCESS = 标红** |
| 13-2 | Function(12 位) | **0-2047 微软保留,0x800+(2048-4095)用户区——三方码的指纹** |
| 1-0 | Method(0=BUFFERED/1=IN_DIRECT/2=OUT_DIRECT/3=NEITHER) | **决定缓冲区语义,§2.3** |

拆码工具:本地帖 **125640《IOCTL 解码程序》**(cppcoffee,精华11,照 OSR 在线 DECODE 写的 Win32 小工具)给出现成实现。手算算例(Dell dbutil 读原语码):
`0x9B0C1F40 → DT=(v>>16)&0xFFF=0xB0C(自定义类型)、Access=(v>>14)&3=0(FILE_ANY_ACCESS)、Fn=(v>>2)&0xFFF=0x7D0、Method=v&3=0(BUFFERED)`——拆完即见「高危功能 + 任意访问位」的组合。易错点:**逐位用脚本拆,别心算**(十六进制对不齐时极易错 DT/Fn)。

### 2.3 四种 Method 的内存语义与风险(核心表)

| Method | 输入 | 输出 | 谁分配/拷贝 | 主要风险 |
|---|---|---|---|---|
| 0 METHOD_BUFFERED | `irp->AssociatedIrp.SystemBuffer`(内核副本) | 同一 SystemBuffer | IO 管理器:入向 Probe+拷入;完成时按 OutputBufferLength 拷回 | **长度不校验/整数溢出;写回超出 OutputBufferLength**;SystemBuffer 在完成后归还,异步再用=UAF |
| 1 METHOD_IN_DIRECT | SystemBuffer | `irp->MdlAddress`(锁定用户页,`MmGetSystemAddressForMdlSafe` 取内核地址) | 入向拷贝;出向 MDL 锁页 | 写 MDL 映射时仍要自己核 OutputBufferLength;MDL 生命周期 |
| 2 METHOD_OUT_DIRECT | SystemBuffer | 同上(输出方向) | 同上 | 同上 |
| 3 METHOD_NEITHER | `ios->Parameters.DeviceIoControl.Type3InputBuffer`=**原始用户指针** | `irp->UserBuffer`=**原始用户指针** | **IO 管理器完全不管**——驱动拿到的是裸用户态地址 | **全裸:不 Probe=任意地址读写;Probe 后 TOCTOU;double-fetch;跨线程改内容** |

记忆锚点(帖 86002 原话意译):BUFFERED/DIRECT 由 IO 管理器代管缓冲区、相对安全;NEITHER「IO_Manager 未对缓冲区进行任何检测」,把用户指针原样递给内核函数——**一切 NEITHER case 都是高危审查点,无一例外**。

### 2.4 KMDF 面

WDF 驱动收口到 `EvtIoDeviceControl(WDFQUEUE, WDFREQUEST, size_t ctl, size_t inLen, size_t outLen, ULONG_PTR timeout)`;缓冲区取用 `WdfRequestRetrieveInputBuffer/OutputBuffer`(框架仍按 Method 处理,NEITHER 时 `WdfRequestRetrieveUnsafeUserInputBuffer` 等)。
审计等价性:checklist §3 同样适用,只换入口名;另查队列分发配置(`WdfIoQueueDispatchSequential` 能天然串行化,竞态类问题概率降)。

### 2.5 静态定位 handler 的特征

- `MajorFunction[0x0E]` 赋值:DriverEntry 里对 `DriverObject+0x70+8*0x0E`(x64 偏移,`MajorFunction` 在 DRIVER_OBJECT 偏移 0x70)的写 —— IDA 里找 DriverEntry 对 `+0xE0` 处 mov。
- 分发函数体内:`cmp/sub eax, imm32` 链、`jmp qword ptr [rax*4+table]` 跳表、或 `shr eax, 2` 后按 Function 位分发。
- 立即数指纹:Function 字段 ≥ 0x800 的 32 位常量(见 §4.1 脚本)。

---

## 3. 审计 Checklist(每条:反例→正例→检测→原语)

### 3.1 METHOD_NEITHER:Type3InputBuffer/UserBuffer 裸用未 Probe

```c
// 反例( CVE-2007-5756 WinPcap NPF 一族形态,帖 86002 案例)
case IOCTL_SET_MODE: {
    PNEITHER_IN in = (PNEITHER_IN)ios->Parameters.DeviceIoControl.Type3InputBuffer;
    devExt->Mode = in->Mode;            // 未 ProbeForRead 直接解引用用户指针
    devExt->Target = in->Target;        // in->Target 若再被解引用 → 用户给内核地址
}
```

危害:用户传 `0xFFFF8000_xxxxxxxx` 内核地址 → 内核读用户指定地址(信息泄露/SMAP 下直接 #PF);若作为写入目标 → **任意地址写**。
正例:

```c
// 正例:PreviousMode 为用户 + Probe + SEH + 锁页(三选一,MDL 最稳)
PNEITHER_IN in = (PNEITHER_IN)ios->Parameters.DeviceIoControl.Type3InputBuffer;
if (Irp->RequestorMode != KernelMode) {
    __try {
        ProbeForRead(in, sizeof(*in), TYPE_ALIGNMENT(NEITHER_IN));
        NEITHER_IN local = *in;         // 立即快照到内核栈,后续只用 local(防 double-fetch)
        ...
    } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}
```

检测:逆向搜 `Type3InputBuffer`/`UserBuffer` 引用(x86 偏移 0x14/0x8 于 IO_STACK_LOCATION),路径上无 `ProbeForRead/ProbeForWrite/MmProbeAndLockPages/MmCopyMemory/RtlCopyMemory+__try` 即命中。注意 x64 SMEP/SMAP 只让「执行用户页 shellcode」变难,**数据面任意读写依旧成立**。

### 3.2 SystemBuffer 长度不校验 / 整数溢出

```c
// 反例:B 区没有最小长度检查
case IOCTL_QUERY: {
    PREQ req = (PREQ)irp->AssociatedIrp.SystemBuffer;
    out = req->Index * req->Count;      // Index/Count 用户可控
    for (i=0;i<req->Count;i++) sink(req->Data[i]);  // 越读 SystemBuffer 外的池内存
}
// 反例:分配长度加法溢出
len = hdr->Count * sizeof(ITEM);        // ULONG 乘法回绕 → 小池分配
memcpy(pool, SystemBuffer+1, hdr->Count*sizeof(ITEM)); // 大拷贝 → 池溢出
```

正例:

```c
PIO_STACK_LOCATION ios = IoGetCurrentIrpStackLocation(irp);
ULONG inLen  = ios->Parameters.DeviceIoControl.InputBufferLength;
ULONG outLen = ios->Parameters.DeviceIoControl.OutputBufferLength;
if (inLen < sizeof(REQ)) return STATUS_INVALID_PARAMETER;          // 入向最小长度
if (outLen < sizeof(RESP)) return STATUS_BUFFER_TOO_SMALL;         // 出向最小长度
SIZE_T need; if (!NT_SUCCESS(RtlSizeTMult(hdr->Count, sizeof(ITEM), &need))
              || need > inLen - FIELD_OFFSET(REQ, Data)) return STATUS_INVALID_PARAMETER; // 溢出安全乘
```

检测:每个 case 入口比对 `InputBufferLength/OutputBufferLength` 与 `sizeof(结构)`;搜乘法/加法参与长度运算且类型窄于 SIZE_T(`ULONG * ULONG` 喂给分配/拷贝)。

### 3.3 Probe 缺失、Probe 长度错、Probe 后 TOCTOU

```c
// 反例 A:Probe 了但用错长度(探 4 字节,读 8)
ProbeForRead(u, sizeof(ULONG), 1);  value = *(PULONG64)u;   // 后 4 字节未探
// 反例 B:TOCTOU —— Probe 完又从用户指针取值(经典 double-fetch 变体)
ProbeForRead(ub, len, 1);
KeDelayExecutionThread(...);              // 或任何让出执行的机会
copy_len = ub->len;                       // 第二次读用户内存,竞态窗口已被攻击线程改写
RtlCopyMemory(kbuf, ub->data, copy_len);
```

正例:Probe 与实际访问**同一 __try 块内一次完成**,数据先快照进内核内存;跨调用使用就 `MmProbeAndLockPages` + `MmGetSystemAddressForMdlSafe`(锁页后用户改不动映射)。Probe 必须 PASSIVE_LEVEL/APC_LEVEL 且判 `Irp->RequestorMode`。

检测:数 Type3InputBuffer/UserBuffer 的**解引用次数**(跨基本块/跨函数各算);Probe 调用的 len 参数与后续拷贝 len 参数比对是否同一表达式。

### 3.4 Double-fetch(双取用户内存)

```c
// 反例:校验一次、使用一次,两次都走用户内存(NEITHER 或 fastio 直通形态)
if (ub->count > MAX) return STATUS_INVALID_PARAMETER;  // 第一次取(校验)
p = ExAllocatePool2(POOL_FLAG_NON_PAGED, ub->count * 8, TAG); // 第二次取(使用)
RtlCopyMemory(p, ub->items, ub->count * 8);
// 攻击:线程 A 在两取之间改 count → 校验过 8,拷贝用 0x10000 → 池溢出
```

正例:`count = ub->count;`(一次快照到内核栈)后只使用局部变量;或整块 `MmCopyMemory` 进内核再解析嵌套字段。
检测:同 3.3——**任何用户地址的同一字段出现 ≥2 次读**即命中;注意 struct 嵌套指针(第二层指针也常是 double-fetch/任意解引用点)。

### 3.5 输出缓冲溢出(写回超出 OutputBufferLength)

```c
// 反例:不看 OutputBufferLength,按输入声称的长度写回
PREQ req = SystemBuffer;
memcpy(irp->UserBuffer, kdata, req->OutLen);   // OutLen 用户给,Buffered 下也可写爆 SystemBuffer
irp->IoStatus.Information = req->OutLen;
```

本地帖 85008《浅析Mj前辈的内核任意地址写入漏洞》(weolar)是同构模式的系统调用版教材:win32k `NtUserQueryInformationThread` 的 `*(LPDWORD)ThreadInformation = pti->TIF_flags;`——**输出指针未检测 + 写入内容可控(TIF_flags 可先 Set 成想要值)**,三步 Query/Set/Query 拼出「向任意地址写受控 4 字节」(MJ0011 0day,帖 84984)。IOCTL 的 NEITHER `UserBuffer` 写回完全同构:`memcpy(UserBuffer, src, n)` 无 Probe 无长度校验 = 同款任意写。
正例:`outLen >= 实际写入字节数` 先查;`IoStatus.Information` 只设真实写入量。

### 3.6 任意指针解引用(用户给内核指针当写入目标)

```c
// 反例:「写哪里、写什么」全由输入结构说了算
PREQ req = SystemBuffer;            // Buffered 也不救:字段本身是"地址"
*(PULONG)req->Addr = req->Value;    // 用户直接指定内核地址 → 原生 write-what-where
```

这是 BYOVD 全家(RTCore64/dbutil/WinRing0)的功能设计级漏洞:**驱动把「任意地址读写」当正常功能提供给用户态**。检测:输入结构里的字段被 cast 成指针解引用,且无「目标必须在某池/某结构内」的白名单校验。正例不存在于「功能即漏洞」的驱动——修复 = 重新设计接口(见 §6 案例)。

### 3.7 引用计数与异步完成(IoCompleteRequest 后再用)

```c
// 反例:pending 后双路径都 Complete
IoMarkIrpPending(irp); ExQueueWorkItem(...); return STATUS_PENDING;
// 工作线程: process(); IoCompleteRequest(irp, ...); return;
// 超时路径: IoCancelTimer...; IoCompleteRequest(irp, ...);  // 双完成 → IRP UAF
// 反例:Complete 后还碰 SystemBuffer
IoCompleteRequest(irp, IO_NO_INCREMENT);
DbgPrint("%s", SystemBuffer);       // IO 管理器可能已释放
```

正例:IRP 所有权一次一主(pending 后原路不得再 Complete);完成后不再引用 IRP 与其缓冲;cancel 例程配 `IoSetCancelRoutine` 原子摘链。
检测:搜 `IoCompleteRequest` 的调用点数(>1 处于同一 IRP 生命周期)+ `STATUS_PENDING` 返回路径;WDF 侧看 `WdfRequestComplete` 后是否再 `WdfRequestRetrieve*`。

### 3.8 附加三条(快过)

- **Access 位错配**:危险功能 CTL_CODE 用 FILE_ANY_ACCESS(§1.3),配合弱 SDDL 双雷。
- **设备对象 Flags**:漏清 `DO_DEVICE_INITIALIZING`、`DO_DIRECT_IO/DO_BUFFERED_IO` 与 Method 不一致导致语义混用。
- **内嵌指针/变长头**:输入结构里 `PVOID`/偏移字段直接当对象用(3.6 的变体),`FIELD_OFFSET` 计算处 `inLen` 必须先查(3.2)。

---

## 4. 审计工具与脚本

### 4.1 IDA/Ghidra 批量定位 IOCTL handler 与码表

特征:① DriverEntry 对 `MajorFunction+0x70+0x8*0x0E`(x64 `+0xE0`)的赋值;② dispatch 内 `cmp/sub eax, imm32` / 跳表;③ 码的 Function 位 ≥0x800。

IDAPython 骨架(思路:全函数扫立即数 → 按位拆 → 过滤三方指纹):

```python
import idaapi, idautils, idc

def decode_ctl(v):
    return ((v >> 16) & 0xFFF, (v >> 14) & 3, (v >> 2) & 0xFFF, v & 3)  # DT,Access,Fn,Method

def looks_like_ioctl(v):
    dt, ac, fn, m = decode_ctl(v)
    return fn >= 0x800 and ac in (0,1,2,3) and m in (0,1,2,3) \
           and dt in (0x22, 0x07, 0x08, 0x09, *range(0x8000, 0x8100))   # 三方常见 DT

for f in idautils.Functions():
    hit = {}
    for ea in idautils.FuncItems(f):
        for i in range(2):
            if idc.print_insn_mnem(ea) in ("cmp","sub","mov"):
                v = idc.get_operand_value(ea, 1)
                if 0x10000 <= v <= 0xFFFFFFFF and looks_like_ioctl(v):
                    hit[v] = ea
    if hit:
        print("func %s @ %s" % (idc.get_func_name(f), hex(f)))
        for v, ea in sorted(hit.items()):
            print("  ctl=%08x DT=%x AC=%d FN=%x M=%d  @%s" % (v, *decode_ctl(v), hex(ea)))
```

产出 `func → [ctl码]` 表后:**M=3(NEITHER)的码优先人审**,M=0 的查长度链。Ghidra headless 同理(对反编译文本 regex 立即数即可,环境见 `工具链搭建.md §2.2`)。

### 4.2 码表解码与对账

- 逆向拿到的裸码用 §2.2 表或本地帖 125640 的解码程序转 `DT/AC/FN/Method` 四元组。
- 对账法:厂商应用层 DLL/EXE 里 `grep` 这些常量(DeviceIoControl 第二参数),能定位「应用怎么构造输入结构」→ 结构体还原快一倍;再拿 IoctlHunter(§4.3)抓真实调用的缓冲区内容当样板。

### 4.3 现役 fuzzer 与追踪工具矩阵(2026-10 复核)

| 工具 | 形态 | 用途 | 备注 |
|---|---|---|---|
| [IoctlHunter](https://github.com/Z4kSec/IoctlHunter)(Z4kSec) | CLI hook | 抓用户态软件对驱动发的 IOCTL + 缓冲区 | 对账输入结构的利器,现役 |
| [IOCTL-Hammer](https://github.com/netskopeoss/ioctlhammer)(Netskope) | fuzz harness | 参数中心的定向 IOCTL fuzz,轻量 | 现役,适合白盒拿到码表后定向轰 |
| [ioctlbf](https://github.com/koutto/ioctlbf)(koutto) | 暴力扫描 | 枚举有效码 + 逐码轰炸 | 2012 年代经典,兜底用 |
| [ioctlfuzzer](https://github.com/cr4sh/ioctlfuzzer)(cr4sh) | hook+fuzz | 老牌 IOCTL 自动化测试 | 经典,少维护 |
| [SKID](https://github.com/luke-goddard/skid)(Luke Goddard) | 结构化 fuzz | DIFUZE 式接口感知 | 结构感知思路值得抄 |
| IoSpy/IoAttack(微软,WDK 内) | 官方 | 记录 IOCTL 调用 → 回放变异 | 《Driver Test》文档,兼容老 |
| 1-Click Fuzz(CODE BLUE 2024) | 符号执行+WDM | 自动提取接口并 fuzz | 论文级,公开 100+ bug,批量挖第三方可上 |

Fuzz 纪律:**先白盒拆码表再定向 fuzz(IOCTL-Hammer)效率远高于盲扫(ioctlbf)**;输入结构按逆向还原的字段给合理值域,长度字段给边界值(0/1/MAX/回绕点);跑批必在可崩快照 VM + 内核调试管道开着(§4.4)。

### 4.4 BSOD 定位 → !analyze → 漏洞确认闭环

```
① VM 快照 + 网络内核调试开着(bcdedit /debug on + host kd, 配法见 工具链搭建.md §1.2)
② fuzzer/手发 IOCTL → 蓝屏
③ kd> !analyze -v        → FAULTING_MODULE/IMAGE_NAME(哪个 .sys)、EXCEPTION_RECORD、崩溃偏移
④ kd> .trap <addr> / kv  → 崩溃现场栈 + 寄存器(RCX/RDX 常是 IRP/缓冲指针)
   kd> !irp <addr>       → IRP 四元组:ctl 码/inLen/outLen/buffer 地址 —— 直接对上你发的哪一个码
⑤ IDA 里按崩溃偏移(base 用 lm 查)定位到 handler 具体行,回 §3 checklist 归类根因
⑥ 最小复现:单独一个 DeviceIoControl 重放该码+该缓冲 → 稳定崩
⑦ 可利用性判定:
   - 写入地址/内容部分可控(3.1/3.5/3.6)→ write-what-where → 高危,继续原语化(token/PreviousMode)
   - 仅越读(3.2)→ 信息泄露,评估泄露内容定级
   - NULL 解引用/纯 DoS(帖 88782 Win7 RC win32k gptiCurrent 空 deref 即此类)→ 低危,记录
```

`!analyze` 输出里的 `SYMBOL_NAME`/`MODULE_NAME` 与 `!irp` 的 ctl 码是两个最强锚点——**崩溃模块 ≠ 一定是责任模块**(被坏驱动污染共享池时先崩在别人家),以 `!irp`+调用栈顶层为准。

---

## 5. 第三方驱动攻击面(BYOVD:为什么是肥肉)

**为什么肥肉**:① 厂商驱动有 **WHQL/attestation 签名**(加载无阻)但代码质量普遍差——签名≠安全评审;② 硬件控制需求天然导向「读写 MSR/物理内存/IO 端口」这类**高危功能型接口**,一旦 ACL 放水就是全套内核原语;③ 攻击者自带落地(Bring Your Own Vulnerable Driver):拷贝 .sys → `SCM`/服务注册加载 → 打开设备 → 原语到手;④ **过期/吊销证书的驱动仍可加载**(VMware 2023 研究),补丁追不上存量;⑤ 即使微软拉黑(§5.3),老系统/未开 HVCI 机器照样吃。

### 5.1 现役武器库清单(10+,均已被实战滥用)

| 驱动 | 来源 | 暴露功能(IOCTL 能力) | 代表 CVE |
|---|---|---|---|
| RTCore64.sys | MSI Afterburner | `\\.\RTCore64`;0x80001848 任意内核读 / 0x8000184C 任意写(用户给地址+值) | CVE-2019-16098(BlackByte 杀 EDR) |
| WinRing0x64.sys | OpenLibSys(风扇/超频全家桶) | 0x9C402xxx 族:MSR 读写、物理内存映射(MapPhysToLinear)、IO 端口 | CVE-2020-14979 等 |
| gdrv.sys | 技嘉 | 0xC350xxxx 族:物理内存读写/映射、MSR、IO 端口 | CVE-2018-19310 等 |
| dbutil_2_3.sys | Dell(预装 2009-2021) | 0x9B0C1F40 起一族的任意内核读写;设备清理缺失,删了驱动照样打 | CVE-2021-21551 |
| iqvw64e.sys | Intel 网卡工具 | 物理内存/MSR 读写 | CVE-2015-2291 |
| Asusgio64.sys / AsUpIO64.sys | 华硕 | 任意内存读写 | LOLDrivers 在册 |
| MsIo64.sys | MSI 工具 | 任意读写 | 微软黑名单在册 |
| cpuz141.sys 等族 | CPUID CPU-Z | 物理内存/MSR(WinRing0 血缘) | 黑名单在册 |
| mhyprot2/3.sys | 米哈游反作弊 | 弱 ACL + 内核读写原语(被勒索家族滥用) | 2021 滥用事件 |
| ProcExp64.sys 族 | Sysinternals | 句柄操作原语(历史版本) | 黑名单历史在册 |
| (查询入口) | — | 新增每月出 | loldrivers.io / 微软黑名单 |

### 5.2 对审计者的含义

- **白盒审计第三方驱动 = 最高产出/成本比**:体积小、无混淆、码表十分钟提完、命中 §3 任一条就是完整链(签名现成、加载合法)。
- 现代缓解边界要心里有数:**SMEP/SMAP** 挡用户页 shellcode,挡不住数据面原语(写 token/PreviousMode);**HVCI/内存完整性 + 微软脆弱驱动黑名单(VDBL,Win10 1809 起可选、随 HVCI 默认开)** 挡的是「已知名单内」驱动加载——新挖的/小厂驱动不在名单内照进。Connor McGarr 的 dbutil 利用文讨论过 VBS 语境下的利用边界。

### 5.3 漏洞数据库查询法

- [微软推荐驱动黑名单](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)(含各驱动 CVE 对应)——先查目标在不在册,在册换目标,不在册=蓝海。
- [loldrivers.io](https://www.loldrivers.io)(LOLDrivers 项目):现役清单+哈希+能力矩阵,比微软名单激进。
- MSRC Update Guide / NVD:按 `CWE-781( IOCTL 地址校验不当)` 检索 Windows 与三方驱动历史;Kaspersky Securelist 季度 exploit 报告看在野使用。
- OSR(osr.com)NT-Insider《Making Device Objects Accessible and Safe》:设备 ACL 设计侧反查。

---

## 6. 案例三则(驱动/码/根因/原语/修复)

### 6.1 CVE-2024-26229 —— csc.sys(微软自家系统驱动)

- **驱动**:csc.sys(Offline Files / Client-Side Caching),CVSS 7.8,CWE-781。
- **入口**:低权限用户 `NtCreateFile` 打开 `\Device\Mup\;Csc\.\.` 拿 CSC 驱动句柄;发 **IOCTL 0x001401a3(CSC_DEV_FCB_XXX_CONTROL_FILE)**,输入缓冲为精心构造的结构。
- **根因**:handler 对输入中的地址字段**校验缺失**(improper address validation in IOCTL),直接以用户提供的内核地址作目标操作——§3.6 原生形态。
- **原语/利用**:构造缓冲指向 `KTHREAD->PreviousMode - 0x18` → 把 PreviousMode 改成 KernelMode → `NtWriteVirtualMemory` 变身**任意内核地址写** → DKOM 把 SYSTEM(PID 4) 的 EPROCESS->Token(偏移 0x4B8,19041-19045 实测)拷给自身 → 恢复 PreviousMode → SYSTEM 落地(公开 BOF:0xGunrunner/CVE-2024-26229-BOF;Kaspersky Q2-2024 报告见在野流通)。
- **修复**:2024-04 补丁(KB5036892 族)对输入地址做 Probe/白名单校验。

### 6.2 CVE-2021-21551 —— dbutil_2_3.sys(Dell,BYOVD/预装面)

- **驱动**:Dell 固件更新驱动,2009 年起随机型预装,量级数亿(CVSS 8.8)。
- **根因**:**双重放水**——设备 ACL 不足(insufficient access control,§1.2 反例现实版,任意用户可开)+ IOCTL 直接提供任意内核读写(0x9B0C1F40 起一族,§3.6);**且驱动卸载后残留可打的设备接口**(Dell 官方公告 DSA-2021-088 承认)。
- **原语**:任意内核读写 → 常规 token 替换提权;Connor McGarr 文还演示了越出 data-only 的利用与 VBS 相关边界。
- **修复**:Dell 以新驱动替换+黑名单;微软 VDBL 收录。审计启示:**「加载与否」不是边界,「设备接口还在不在」才是**——审计预装机器先枚举 `\Device`(§1.4)。

### 6.3 CVE-2019-16098 —— RTCore64.sys(MSI Afterburner,BYOVD 标杆)

- **入口**:`\\.\RTCore64`(弱 ACL,任意认证用户可开)。
- **功能即漏洞**:0x80001848 = 「读任意内核地址 32 位」、0x8000184C = 「向任意内核地址写 1 字节」——输入就是 {地址, 值},§3.6 教科书式。
- **原语**:4 次写拼 32 位、逐字节凑值即可完整读写 → 修 token/KPROCESS 提权;BlackByte 勒索用它摘 EDR 内核回调/杀进程(Sophos 2022)。
- **修复**:无真正的代码修复——微软 VDBL 拉黑 + 厂商新版收紧(2024 年同族又出 CVE-2024-1460 信息泄露,说明存量风险持续)。

### 6.4 本地语料延伸(根因深读)

- 帖 84984/85008(精华10):MJ0011 win32k 任意写 0day + weolar 逆向解析——§3.5 输出指针模式的系统调用版完整攻击链。
- 帖 88782(精华10):Win7 RC win32k 共享临界区致 gptiCurrent 失效 DoS——「锁语义改变唤醒休眠假设」的根因样本(接 `11-漏洞根因学` 视角)。
- HEVD 三部(精华18:218838/218868/218963):练手靶场,配合本 checklist 逐关过。
- 提取命令(精华1-13 为裸文件名,14+ 带 `pediyNN/` 前缀):
  `cd ~/Documents/看雪精华2024合集版/kanxue.com && 7z x pediy10.chm "86002.html" -o/tmp/kx_w -y`

---

## 7. 收尾纪律

- 每个审完的驱动落一行结论:`驱动 | 设备 | ACL | 码表 | 命中条款(§3.x) | 原语 | 定级`——空手也要记 N/A+原因,防重复劳动。
- 命中即回到 `src-value`/报告格式出报告;BSOD 复现视频/最小 PoC 是定级证据。
- 交叉引用:驱动编程基础 `编程篇.md §5`;根因分析 `11-漏洞根因学/内核漏洞根因案例.md §6(cldflt)`;环境 `工具链搭建.md`。
