# Windows Driver IOCTL Auditing (A White-Box Vulnerability-Location Manual)

> Division of labor: `programming.md §5` already covers how to write drivers (IRP/IOCTL basics, the security red lines in three sentences), and `../../11-root-cause/kernel-vuln-root-cause-cases.md` covers why memory errors happen; **this part answers only "where is the attack surface, what does the audit check, which tools, and how to get from BSOD to a usable primitive"**. Environment setup (IDA/Ghidra/dual-machine debugging) is in [toolchain-setup.md](toolchain-setup.md) in the same directory.
> Fact-checking: CTL_CODE bit layout verified against Microsoft headers and local post 125640 (the IOCTL decoder program); SDDL/device-object security verified against learn.microsoft.com (SDDL for Device Objects / Named Device Objects); the fuzzer list and BYOVD cases re-verified online on 2026-10-16.

## 0. Mindset and Process Overview

**One sentence**: a driver vulnerability = "an entry point user mode can reach" × "a check not done right on that entry". IOCTL is the widest such entry — every CTL_CODE is a kernel function call exposed to any user-mode process.

The standard audit pipeline (six steps, expanded in later sections):

```
① 枚举暴露面:设备名/符号链接/ACL —— 哪些设备我(低权限)能 CreateFile 打开?
② 提取 IOCTL 码:逆向分发函数/字符串/常量 cmp —— 一共暴露了几个功能号?
③ 拆码定性:每个码的 Method(BUFFERED/DIRECT/NEITHER)+ Access 位 —— 高危面排序
④ Checklist 逐条过分发链(§3 七条 + 附加三条)—— 正反例比对
⑤ Fuzzer 轰一遍(§4.3)—— 补静态漏网
⑥ BSOD → !analyze -v → 定位 handler → 最小复现 → 判可利用性 → 报告
```

**Value ordering** (where to throw the first punch): unprobed METHOD_NEITHER > sensitive functions openable by any user (read MSR/physical memory/kernel read-write) > missing length/integer validation > double-fetch > output overflow > async/reference counting. In white-box auditing, ③ code decomposition directly decides the review intensity of ④ — don't spread effort evenly.

---

## 1. Enumerating the Driver's Exposed Surface

### 1.1 Namespaces: Device Objects, Symbolic Links, and `\\.\`

- The kernel-side real name: `\Device\xxx` (created by IoCreateDevice / WdfDeviceCreate).
- User-mode visible: `\??\xxx` / `\Global??\xxx` (sessions isolated since Vista; global symbolic links live in `\Global??`), established by `IoCreateSymbolicLink(L"\\DosDevices\\xxx", L"\\Device\\xxx")`.
- User-mode open syntax: `CreateFile("\\\\.\\xxx", ...)`, equivalent to the symbolic link of `\Device\xxx`; **it can still be hit without a symbolic link** — `\\.\GLOBALROOT\Device\xxx` (NtCreateFile tunnels straight into the object directory); don't stare only at `\\.\` when auditing.
- Code-level identification (white box): in DriverEntry look for the trio — `IoCreateDevice*` (or WDF's `WdfDeviceInitSetName`/`WdfDeviceCreate`), `IoCreateSymbolicLink`, and the string constants of `RtlInitUnicodeString` (`\Device\`, `\DosDevices\` pop right out with strings/grep). UMDF driver devices in `\Device\_`...? Uncommon as attack surfaces; skip for now.

**Quick judgment of "does this driver have a surface"**: strings-search for `\Device\` and `\DosDevices\`; a `.sys` with no device names at all → no direct IOCTL surface (it may be a filter driver minifilter/callback type; the audit surface shifts to IRP filtering/callback registration, outside this part).

### 1.2 ACL/SDDL: Who Can Open the Device

A security descriptor (an SDDL string) can be specified at creation. **Unspecified ≠ safe** — check the defaults and INF overrides:

| Creation path | API | Effect |
|---|---|---|
| Bare WDM `IoCreateDevice` | no SDDL parameter | named devices go through I/O manager defaults (depends on `FILE_DEVICE_SECURE_OPEN` and the INF); basically System/Admin full rights |
| WDM secure creation | `IoCreateDeviceSecure` (wdmsec.h, link wdmsec.lib) | explicit SDDL |
| KMDF | `WdfDeviceInitAssignSDDL` (must come **before** `WdfDeviceCreate`) | explicit SDDL |
| INF | the `DEVICE SECURITY` section / the registry `Security` value | **highest priority, overrides everything above** (OSR, "Making Device Objects Accessible and Safe") |

Predefined strings (learn.microsoft.com, "SDDL for Device Objects"): `SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RX_RES_RWX` = SYSTEM full, Admins RWX, **Everyone read-execute only**. For ordinary users to open + send IOCTLs (write access), the vendor must write a permissive string like `D:P(A;;GA;;;WD)` — **the search target: an SDDL containing `;;;WD)` (Everyone granted GA/RWX) = any user with full rights on the device**.

The bad example (a typical fat surface, the Dell dbutil family shape):

```c
// 反例:未指定安全 + 符号链接全局可见 → 低权限用户可开可发
RtlInitUnicodeString(&dev, L"\\Device\\DBUtil");
IoCreateDevice(drv, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
RtlInitUnicodeString(&lnk, L"\\DosDevices\\DBUtil");
IoCreateSymbolicLink(&lnk, &dev);
```

The good example:

```c
// 正例:显式 SDDL,Everyone 无权;敏感功能走 FILE_READ_DATA|FILE_WRITE_ACCESS 的 CTL_CODE
RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"); // 仅 SYSTEM/Administrators
status = IoCreateDeviceSecure(drv, 0, &dev, FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, NULL, &devObj);
```

Detection method (white box): grep `WdfDeviceInitAssignSDDL|IoCreateDeviceSecure|SDDL_DEVOBJ`; absent → check the INF; still absent → dynamic verification (§1.4). Also note `Exclusive=TRUE` only prevents concurrent opens — it is not an ACL.

### 1.3 The Access Bits and IOCTL Permissions Interlocking (Often Overlooked)

The CTL_CODE Access bits (FILE_ANY_ACCESS=0/READ=1/WRITE=2/BOTH=3) decide **the access rights required to open the handle**, validated by the I/O manager before `IofCallDriver`. A sensitive function code written with `FILE_ANY_ACCESS` = callable by anyone who can open the device — doubly lost when paired with a permissive SDDL. Audit: decompose every code's Access bits; "arbitrary physical-memory read-write + FILE_ANY_ACCESS" goes straight to red.

### 1.4 User-Mode Location of Openable Devices (Black-Box Cross-Check)

- **WinObj** (Sysinternals): GUI browsing of `\??`, `\GLOBAL??`, `\Device`; right-click for security descriptors (who has what, at a glance).
- **DeviceTree** (OSR): lists device objects by driver; after white-box reversing, reconcile with it.
- Scripting: write a 20-line `NtQueryDirectoryObject` enumerator walking `\Device` and `\Global??` (native PowerShell can't list object directories); `driverquery /FO LIST /V` + `Get-CimInstance Win32_SystemDriver` to bound the driver set first.
- **The try-open decision matrix** (most direct):

```
CreateFile("\\\\.<name>", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
→ SUCCESS          :低权限可写开 —— 面成立,进 §2
→ ERROR_ACCESS_DENIED:ACL 拦(GENERIC_READ 再试一次,部分设备只读可开)
→ ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND:名字错或无符号链接,试 GLOBALROOT\Device\ 路径
```

---

## 2. The IOCTL Dispatch Chain and CTL_CODE Decomposition

### 2.1 The Complete Chain

```
用户态 DeviceIoControl(hDev, ctl, inBuf, inLen, outBuf, outLen, &ret, NULL)
  → ntdll → NtDeviceIoControlFile → IO 管理器组 IRP(MajorFunction=IRP_MJ_DEVICE_CONTROL=0x0E)
  → 按句柄找到设备对象 → 驱动的 DriverObject->MajorFunction[0x0E](WDM)
    / KMDF: WdfIoQueue 的 EvtIoDeviceControl 回调
  → dispatch 读 IoGetCurrentIrpStackLocation(irp)->Parameters.DeviceIoControl.IoControlCode
  → switch(ctl) 或跳表 分发到子函数
```

The WDM dispatch skeleton (auditors enter here; local post 86002, "Discovering and Exploiting Windows Driver Vulnerabilities", has the full version):

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

### 2.2 CTL_CODE Bit Decomposition (Decomposition Is the First Step of Characterization)

`#define CTL_CODE(DT, FN, METHOD, ACCESS) ((DT<<16)|(ACCESS<<14)|(FN<<2)|METHOD)`

| Bit field | Meaning | Audit notes |
|---|---|---|
| 31-28 | common device-type high bits (0x22=UNKNOWN most common) | 0x22/custom 0x8000+ = typical third-party drivers |
| 27-16 | DeviceType (12 bits) | FILE_DEVICE_UNKNOWN=0x22, FILE_DEVICE_DISK=0x07, etc. |
| 15-14 | Access (0=ANY/1=READ/2=WRITE/3=BOTH) | **sensitive functions with ANY_ACCESS = red flag** |
| 13-2 | Function (12 bits) | **0-2047 Microsoft-reserved, 0x800+ (2048-4095) the user zone — the third-party code fingerprint** |
| 1-0 | Method (0=BUFFERED/1=IN_DIRECT/2=OUT_DIRECT/3=NEITHER) | **decides buffer semantics, §2.3** |

Decomposition tool: local post **125640 "The IOCTL Decoder Program"** (cppcoffee, Essential 11, a Win32 gadget written after OSR's online DECODE) provides a ready implementation. A hand-calc example (the Dell dbutil read-primitive code):
`0x9B0C1F40 → DT=(v>>16)&0xFFF=0xB0C (custom type), Access=(v>>14)&3=0 (FILE_ANY_ACCESS), Fn=(v>>2)&0xFFF=0x7D0, Method=v&3=0 (BUFFERED)` — decomposed, the "high-risk function + any-access bit" combination shows itself. Pitfall: **decompose bit by bit with a script, never in your head** (with misaligned hex it's extremely easy to get DT/Fn wrong).

### 2.3 The Memory Semantics and Risks of the Four Methods (the Core Table)

| Method | Input | Output | Who allocates/copies | Main risks |
|---|---|---|---|---|
| 0 METHOD_BUFFERED | `irp->AssociatedIrp.SystemBuffer` (a kernel copy) | the same SystemBuffer | the I/O manager: inbound Probe + copy-in; on completion, copies back per OutputBufferLength | **unvalidated lengths/integer overflow; writing back beyond OutputBufferLength**; the SystemBuffer is returned after completion — reusing it asynchronously = UAF |
| 1 METHOD_IN_DIRECT | SystemBuffer | `irp->MdlAddress` (locked user pages; get the kernel address with `MmGetSystemAddressForMdlSafe`) | copy-in inbound; MDL-locked pages outbound | when writing MDL mappings you must still self-check OutputBufferLength; MDL lifetime |
| 2 METHOD_OUT_DIRECT | SystemBuffer | same (output direction) | same | same |
| 3 METHOD_NEITHER | `ios->Parameters.DeviceIoControl.Type3InputBuffer` = **raw user pointer** | `irp->UserBuffer` = **raw user pointer** | **the I/O manager does nothing whatsoever** — the driver receives bare user-mode addresses | **fully exposed: no Probe = arbitrary-address read/write; TOCTOU after Probe; double-fetch; content changed across threads** |

The memory anchor (a paraphrase of post 86002's own words): BUFFERED/DIRECT have the I/O manager manage the buffers, relatively safe; NEITHER — "the IO_Manager performs no checks whatsoever on the buffer" — hands the user pointer to kernel functions as-is — **every NEITHER case is a high-risk review point, no exceptions**.

### 2.4 The KMDF Surface

WDF drivers converge on `EvtIoDeviceControl(WDFQUEUE, WDFREQUEST, size_t ctl, size_t inLen, size_t outLen, ULONG_PTR timeout)`; buffers via `WdfRequestRetrieveInputBuffer/OutputBuffer` (the framework still handles per Method; for NEITHER, `WdfRequestRetrieveUnsafeUserInputBuffer` etc.).
Audit equivalence: the §3 checklist applies unchanged, only the entry name differs; additionally check queue dispatch configuration (`WdfIoQueueDispatchSequential` naturally serializes, lowering the odds of race-class issues).

### 2.5 Static Fingerprints for Locating the Handler

- The `MajorFunction[0x0E]` assignment: in DriverEntry, writes to `DriverObject+0x70+8*0x0E` (x64 offset; `MajorFunction` sits at offset 0x70 of DRIVER_OBJECT) — in IDA, find the mov to `+0xE0` in DriverEntry.
- Inside the dispatch function: chains of `cmp/sub eax, imm32`, jump tables `jmp qword ptr [rax*4+table]`, or dispatching on the Function bits after `shr eax, 2`.
- Immediate fingerprints: 32-bit constants whose Function field ≥ 0x800 (see the §4.1 script).

---

## 3. The Audit Checklist (Each Item: Bad Example → Good Example → Detection → Primitive)

### 3.1 METHOD_NEITHER: Type3InputBuffer/UserBuffer Used Raw Without Probe

```c
// 反例( CVE-2007-5756 WinPcap NPF 一族形态,帖 86002 案例)
case IOCTL_SET_MODE: {
    PNEITHER_IN in = (PNEITHER_IN)ios->Parameters.DeviceIoControl.Type3InputBuffer;
    devExt->Mode = in->Mode;            // 未 ProbeForRead 直接解引用用户指针
    devExt->Target = in->Target;        // in->Target 若再被解引用 → 用户给内核地址
}
```

Harm: the user passes a `0xFFFF8000_xxxxxxxx` kernel address → the kernel reads the user-specified address (information leak/straight #PF under SMAP); if used as a write target → **arbitrary-address write**.
The good example:

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

Detection: reverse-search references to `Type3InputBuffer`/`UserBuffer` (x86 offsets 0x14/0x8 in IO_STACK_LOCATION); a path without `ProbeForRead/ProbeForWrite/MmProbeAndLockPages/MmCopyMemory/RtlCopyMemory+__try` is a hit. Note that x64 SMEP/SMAP only make "executing shellcode on user pages" harder — **arbitrary read/write on the data plane still stands**.

### 3.2 SystemBuffer Length Not Validated / Integer Overflow

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

The good example:

```c
PIO_STACK_LOCATION ios = IoGetCurrentIrpStackLocation(irp);
ULONG inLen  = ios->Parameters.DeviceIoControl.InputBufferLength;
ULONG outLen = ios->Parameters.DeviceIoControl.OutputBufferLength;
if (inLen < sizeof(REQ)) return STATUS_INVALID_PARAMETER;          // 入向最小长度
if (outLen < sizeof(RESP)) return STATUS_BUFFER_TOO_SMALL;         // 出向最小长度
SIZE_T need; if (!NT_SUCCESS(RtlSizeTMult(hdr->Count, sizeof(ITEM), &need))
              || need > inLen - FIELD_OFFSET(REQ, Data)) return STATUS_INVALID_PARAMETER; // 溢出安全乘
```

Detection: at every case entry compare `InputBufferLength/OutputBufferLength` against `sizeof(struct)`; search for multiplication/addition feeding length arithmetic with types narrower than SIZE_T (`ULONG * ULONG` fed to allocations/copies).

### 3.3 Missing Probe, Wrong Probe Length, TOCTOU After Probe

```c
// 反例 A:Probe 了但用错长度(探 4 字节,读 8)
ProbeForRead(u, sizeof(ULONG), 1);  value = *(PULONG64)u;   // 后 4 字节未探
// 反例 B:TOCTOU —— Probe 完又从用户指针取值(经典 double-fetch 变体)
ProbeForRead(ub, len, 1);
KeDelayExecutionThread(...);              // 或任何让出执行的机会
copy_len = ub->len;                       // 第二次读用户内存,竞态窗口已被攻击线程改写
RtlCopyMemory(kbuf, ub->data, copy_len);
```

The good example: complete the Probe and the actual access **once, inside the same __try block**, snapshotting the data into kernel memory first; for cross-call use, go `MmProbeAndLockPages` + `MmGetSystemAddressForMdlSafe` (after page-locking, the user can no longer change the mapping). Probe must run at PASSIVE_LEVEL/APC_LEVEL and check `Irp->RequestorMode`.

Detection: count the **dereference count** of Type3InputBuffer/UserBuffer (across basic blocks/functions, each counts); compare whether the Probe call's len argument and the later copy's len argument are the same expression.

### 3.4 Double-Fetch (Reading User Memory Twice)

```c
// 反例:校验一次、使用一次,两次都走用户内存(NEITHER 或 fastio 直通形态)
if (ub->count > MAX) return STATUS_INVALID_PARAMETER;  // 第一次取(校验)
p = ExAllocatePool2(POOL_FLAG_NON_PAGED, ub->count * 8, TAG); // 第二次取(使用)
RtlCopyMemory(p, ub->items, ub->count * 8);
// 攻击:线程 A 在两取之间改 count → 校验过 8,拷贝用 0x10000 → 池溢出
```

The good example: after `count = ub->count;` (a one-time snapshot onto the kernel stack), use only the local; or `MmCopyMemory` the whole block into the kernel, then parse nested fields.
Detection: same as 3.3 — **any user-address field read ≥2 times is a hit**; mind nested struct pointers (second-level pointers are also frequent double-fetch/arbitrary-dereference points).

### 3.5 Output Buffer Overflow (Writing Back Beyond OutputBufferLength)

```c
// 反例:不看 OutputBufferLength,按输入声称的长度写回
PREQ req = SystemBuffer;
memcpy(irp->UserBuffer, kdata, req->OutLen);   // OutLen 用户给,Buffered 下也可写爆 SystemBuffer
irp->IoStatus.Information = req->OutLen;
```

Local post 85008, "A Brief Analysis of Senior Mj's Kernel Arbitrary-Address Write Vulnerability" (weolar), is the system-call edition textbook of the same pattern: win32k's `NtUserQueryInformationThread` doing `*(LPDWORD)ThreadInformation = pti->TIF_flags;` — **an unchecked output pointer + controllable written content (TIF_flags can be Set to the desired value first)**; the three-step Query/Set/Query assembles "write a controlled 4 bytes to an arbitrary address" (the MJ0011 0day, post 84984). An IOCTL's NEITHER `UserBuffer` write-back is fully isomorphic: `memcpy(UserBuffer, src, n)` with no Probe and no length validation = the same arbitrary write.
The good example: check `outLen >= the actual bytes written` first; set `IoStatus.Information` only to the truly written amount.

### 3.6 Arbitrary Pointer Dereference (The User Hands the Kernel a Pointer as the Write Target)

```c
// 反例:「写哪里、写什么」全由输入结构说了算
PREQ req = SystemBuffer;            // Buffered 也不救:字段本身是"地址"
*(PULONG)req->Addr = req->Value;    // 用户直接指定内核地址 → 原生 write-what-where
```

This is the BYOVD family's (RTCore64/dbutil/WinRing0) design-level vulnerability: **the driver offers "arbitrary-address read/write" to user mode as a normal feature**. Detection: a field of the input structure cast to a pointer and dereferenced, with no "the target must be within some pool/structure" whitelist validation. No good example exists for "the feature is the vulnerability" drivers — the fix = redesign the interface (see the §6 cases).

### 3.7 Reference Counting and Async Completion (Reusing After IoCompleteRequest)

```c
// 反例:pending 后双路径都 Complete
IoMarkIrpPending(irp); ExQueueWorkItem(...); return STATUS_PENDING;
// 工作线程: process(); IoCompleteRequest(irp, ...); return;
// 超时路径: IoCancelTimer...; IoCompleteRequest(irp, ...);  // 双完成 → IRP UAF
// 反例:Complete 后还碰 SystemBuffer
IoCompleteRequest(irp, IO_NO_INCREMENT);
DbgPrint("%s", SystemBuffer);       // IO 管理器可能已释放
```

The good example: IRP ownership has exactly one owner at a time (after pending, the original path must not Complete again); after completion, never reference the IRP or its buffers again; the cancel routine pairs with `IoSetCancelRoutine` for atomic unlinking.
Detection: search the call-site count of `IoCompleteRequest` (>1 within one IRP lifecycle) + `STATUS_PENDING` return paths; on the WDF side, check whether `WdfRequestRetrieve*` is called after `WdfRequestComplete`.

### 3.8 Three Additional Items (Quick Pass)

- **Access-bit mismatch**: dangerous functions' CTL_CODE using FILE_ANY_ACCESS (§1.3), paired with a weak SDDL — a double mine.
- **Device-object Flags**: failing to clear `DO_DEVICE_INITIALIZING`; `DO_DIRECT_IO/DO_BUFFERED_IO` inconsistent with the Method, causing semantic mixing.
- **Embedded pointers/variable-length headers**: `PVOID`/offset fields of the input structure used directly as objects (a variant of 3.6); where `FIELD_OFFSET` arithmetic appears, `inLen` must be validated first (3.2).

---

## 4. Audit Tools and Scripts

### 4.1 Batch-Locating IOCTL Handlers and Code Tables in IDA/Ghidra

Fingerprints: ① the assignment to `MajorFunction+0x70+0x8*0x0E` in DriverEntry (x64 `+0xE0`); ② `cmp/sub eax, imm32` / jump tables inside the dispatch; ③ codes with Function bits ≥0x800.

The IDAPython skeleton (idea: scan all functions' immediates → decompose bits → filter third-party fingerprints):

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

Once the `func → [ctl codes]` table is produced: **codes with M=3 (NEITHER) get human review first**; M=0 ones get their length chains checked. Ghidra headless works the same (regex the immediates from decompiled text; environment in `toolchain-setup.md §2.2`).

### 4.2 Code-Table Decoding and Reconciliation

- Convert raw codes from reversing into `DT/AC/FN/Method` quadruples with the §2.2 table or local post 125640's decoder.
- Reconciliation: `grep` these constants in the vendor's user-mode DLL/EXE (the second DeviceIoControl parameter) to locate "how the application builds input structures" → struct restoration twice as fast; then use IoctlHunter (§4.3) to capture the buffer contents of real calls as templates.

### 4.3 The Active Fuzzer and Tracing Tool Matrix (Re-verified 2026-10)

| Tool | Form | Use | Notes |
|---|---|---|---|
| [IoctlHunter](https://github.com/Z4kSec/IoctlHunter) (Z4kSec) | CLI hook | captures IOCTLs + buffers user-mode software sends to drivers | a gem for reconciling input structures; active |
| [IOCTL-Hammer](https://github.com/netskopeoss/ioctlhammer) (Netskope) | fuzz harness | parameter-centric targeted IOCTL fuzzing, lightweight | active; suited to targeted hammering once the white box has the code table |
| [ioctlbf](https://github.com/koutto/ioctlbf) (koutto) | brute scan | enumerates valid codes + hammers one by one | a 2012-era classic; fallback use |
| [ioctlfuzzer](https://github.com/cr4sh/ioctlfuzzer) (cr4sh) | hook+fuzz | the veteran of automated IOCTL testing | classic, lightly maintained |
| [SKID](https://github.com/luke-goddard/skid) (Luke Goddard) | structured fuzz | DIFUZE-style interface awareness | the structure-aware idea is worth copying |
| IoSpy/IoAttack (Microsoft, in the WDK) | official | records IOCTL calls → replay with mutation | the Driver Test docs; compatible with the old |
| 1-Click Fuzz (CODE BLUE 2024) | symbolic execution + WDM | auto-extracts interfaces and fuzzes | paper-grade; 100+ public bugs; viable for batch third-party hunting |

Fuzz discipline: **white-box code-table extraction first, then targeted fuzzing (IOCTL-Hammer), is far more efficient than blind sweeping (ioctlbf)**; give the input structures sensible value ranges per the reverse-restored fields, and length fields boundary values (0/1/MAX/wrap points); batch runs must be on a snapshot-able VM with the kernel-debug pipe open (§4.4).

### 4.4 BSOD Location → !analyze → Vulnerability Confirmation Loop

```
① VM 快照 + 网络内核调试开着(bcdedit /debug on + host kd, 配法见 toolchain-setup.md §1.2)
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

The `SYMBOL_NAME`/`MODULE_NAME` in `!analyze` output and the ctl code from `!irp` are the two strongest anchors — **the crashing module ≠ necessarily the responsible module** (when a bad driver pollutes a shared pool, the crash first lands in someone else's home); trust `!irp` + the top of the call stack.

---

## 5. The Third-Party Driver Attack Surface (BYOVD: Why It's Fat Game)

**Why it's fat game**: ① vendor drivers carry **WHQL/attestation signatures** (loading unimpeded) yet code quality is generally poor — a signature ≠ a security review; ② hardware-control needs naturally lead to "read/write MSR/physical memory/IO ports" type **high-risk functional interfaces** — once the ACL leaks, it's the full set of kernel primitives; ③ the attacker brings their own landing (Bring Your Own Vulnerable Driver): copy the .sys → load via `SCM`/service registration → open the device → primitives in hand; ④ **drivers with expired/revoked certificates can still load** (2023 VMware research), and patches can't catch up with the installed base; ⑤ even after Microsoft blacklists (§5.3), old systems/machines without HVCI still eat them.

### 5.1 The Active Arsenal List (10+, all abused in the field)

| Driver | Source | Exposed functionality (IOCTL capabilities) | Representative CVE |
|---|---|---|---|
| RTCore64.sys | MSI Afterburner | `\\.\RTCore64`; 0x80001848 arbitrary kernel read / 0x8000184C arbitrary write (user supplies address+value) | CVE-2019-16098 (BlackByte killing EDR) |
| WinRing0x64.sys | OpenLibSys (fan/overclocking family) | the 0x9C402xxx family: MSR read/write, physical-memory mapping (MapPhysToLinear), IO ports | CVE-2020-14979 etc. |
| gdrv.sys | Gigabyte | the 0xC350xxxx family: physical memory read/write/mapping, MSR, IO ports | CVE-2018-19310 etc. |
| dbutil_2_3.sys | Dell (preinstalled 2009-2021) | arbitrary kernel read/write starting at the 0x9B0C1F40 family; device cleanup missing — deleted drivers still hit | CVE-2021-21551 |
| iqvw64e.sys | Intel NIC tools | physical memory/MSR read/write | CVE-2015-2291 |
| Asusgio64.sys / AsUpIO64.sys | ASUS | arbitrary memory read/write | registered in LOLDrivers |
| MsIo64.sys | MSI tools | arbitrary read/write | on Microsoft's blacklist |
| cpuz141.sys and family | CPUID CPU-Z | physical memory/MSR (WinRing0 lineage) | blacklisted |
| mhyprot2/3.sys | miHoYo anti-cheat | weak ACL + kernel read/write primitives (abused by ransomware families) | the 2021 abuse incidents |
| ProcExp64.sys family | Sysinternals | handle-operation primitives (historical versions) | historically blacklisted |
| (query entries) | — | new additions monthly | loldrivers.io / Microsoft's blacklist |

### 5.2 What This Means for Auditors

- **White-box auditing of third-party drivers = the best output/cost ratio**: small size, no obfuscation, the code table extracted in ten minutes, and any hit on a §3 item is a complete chain (signature ready-made, loading legal).
- Know the modern mitigation boundaries: **SMEP/SMAP** block user-page shellcode, not data-plane primitives (writing token/PreviousMode); **HVCI/memory integrity + Microsoft's vulnerable-driver blocklist (VDBL, optional since Win10 1809, default-on with HVCI)** blocks only "known, listed" driver loading — newly dug/small-vendor drivers aren't on the list and walk right in. Connor McGarr's dbutil exploitation write-up discusses exploitation boundaries under VBS.

### 5.3 Vulnerability Database Query Methods

- [Microsoft's recommended driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) (with each driver's CVE mapping) — first check whether the target is listed; if listed, switch targets; if not = blue ocean.
- [loldrivers.io](https://www.loldrivers.io) (the LOLDrivers project): the active list + hashes + capability matrix, more aggressive than Microsoft's.
- MSRC Update Guide / NVD: search Windows and third-party driver history by `CWE-781 (IOCTL improper address validation)`; Kaspersky Securelist quarterly exploit reports for in-the-wild usage.
- OSR (osr.com) NT-Insider "Making Device Objects Accessible and Safe": the device-ACL design side, in reverse.

---

## 6. Three Case Studies (Driver/Code/Root Cause/Primitive/Fix)

### 6.1 CVE-2024-26229 —— csc.sys (Microsoft's Own System Driver)

- **Driver**: csc.sys (Offline Files / Client-Side Caching), CVSS 7.8, CWE-781.
- **Entry**: a low-privilege user `NtCreateFile`-opens `\Device\Mup\;Csc\.\.` to get a CSC driver handle; sends **IOCTL 0x001401a3 (CSC_DEV_FCB_XXX_CONTROL_FILE)** with a carefully constructed input buffer.
- **Root cause**: the handler's **missing validation** of the input's address field (improper address validation in IOCTL), operating directly on the user-supplied kernel address — the native form of §3.6.
- **Primitive/exploitation**: construct the buffer to point at `KTHREAD->PreviousMode - 0x18` → flip PreviousMode to KernelMode → `NtWriteVirtualMemory` becomes **arbitrary kernel-address write** → DKOM copies SYSTEM's (PID 4) EPROCESS->Token (offset 0x4B8, measured on 19041-19045) to itself → restore PreviousMode → SYSTEM landed (public BOF: 0xGunrunner/CVE-2024-26229-BOF; Kaspersky's Q2-2024 report observed it circulating in the wild).
- **Fix**: the 2024-04 patch (KB5036892 family) added Probe/whitelist validation of input addresses.

### 6.2 CVE-2021-21551 —— dbutil_2_3.sys (Dell, the BYOVD/preinstalled surface)

- **Driver**: Dell's firmware-update driver, preinstalled with machines since 2009, at the hundreds-of-millions scale (CVSS 8.8).
- **Root cause**: **double leakage** — insufficient device ACL (insufficient access control, the real-life version of the §1.2 bad example, openable by any user) + the IOCTL directly offering arbitrary kernel read/write (the family starting 0x9B0C1F40, §3.6); **plus a residual, hittable device interface after driver uninstall** (Dell's official advisory DSA-2021-088 acknowledged this).
- **Primitive**: arbitrary kernel read-write → the usual token-swap escalation; Connor McGarr's write-up also demonstrated exploitation beyond data-only and VBS-related boundaries.
- **Fix**: Dell replaced with a new driver + blacklisting; Microsoft's VDBL included it. Audit lesson: **"whether loaded" is not the boundary, "whether the device interface still exists" is** — when auditing preinstalled machines, enumerate `\Device` first (§1.4).

### 6.3 CVE-2019-16098 —— RTCore64.sys (MSI Afterburner, the BYOVD Benchmark)

- **Entry**: `\\.\RTCore64` (weak ACL, openable by any authenticated user).
- **The feature is the vulnerability**: 0x80001848 = "read 32 bits at any kernel address", 0x8000184C = "write 1 byte to any kernel address" — the input is just {address, value}, textbook §3.6.
- **Primitive**: four writes assemble 32 bits; assembling values byte by byte gives full read-write → patch token/KPROCESS for escalation; BlackByte ransomware used it to strip EDR kernel callbacks/kill processes (Sophos 2022).
- **Fix**: no true code fix — Microsoft's VDBL blacklisted it + the vendor's new version tightened (in 2024 the same family produced CVE-2024-1460, an information leak, showing the stock risk persists).

### 6.4 Local Corpus Extensions (Root-Cause Deep Reads)

- Posts 84984/85008 (Essential 10): MJ0011's win32k arbitrary-write 0day + weolar's reverse analysis — the system-call edition of the §3.5 output-pointer pattern as a complete attack chain.
- Post 88782 (Essential 10): Win7 RC win32k shared critical section causing gptiCurrent invalidation DoS — a root-cause specimen of "changed lock semantics waking dormant assumptions" (linking to the `11-root-cause` viewpoint).
- The HEVD trilogy (Essential 18: 218838/218868/218963): the practice range, worked through level by level with this checklist.
- Extraction commands (Essentials 1-13 are bare filenames, 14+ carry the `pediyNN/` prefix):
  `cd ~/Documents/看雪精华2024合集版/kanxue.com && 7z x pediy10.chm "86002.html" -o/tmp/kx_w -y`

---

## 7. Wrap-Up Discipline

- Every audited driver gets one line of conclusion: `driver | device | ACL | code table | items hit (§3.x) | primitive | rating` — even empty hands record N/A + reason, to prevent duplicated labor.
- On a hit, return to `src-value`/the report format for reporting; BSOD reproduction video/minimal PoC are the rating evidence.
- Cross-references: driver-programming basics `programming.md §5`; root-cause analysis `11-root-cause/kernel-vuln-root-cause-cases.md §6 (cldflt)`; environment `toolchain-setup.md`.
