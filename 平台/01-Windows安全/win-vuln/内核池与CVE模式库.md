# Windows 内核池利用与 CVE 模式库

> 定位:**Windows 侧专用**——内核池(Executive Pool)布局演进 × 池风水 × 原语构造 × 缓解成本曲线 × CVE 模式表。
> 根因视角(逐案代码级)→ `../../11-漏洞根因学/内核漏洞根因案例.md`(其 §6 cldflt 族与本篇 §5 互链);
> glibc 堆(tcache/House of 全家)→ `../../06-二进制漏洞/堆利用与防护.md`——**两套体系完全不同**,勿混:ptmalloc 攻击 chunk 元数据/bin 链,Windows 池攻击 POOL_HEADER/邻接对象/重占时机;
> HEVD 入门与 Token 窃取 shellcode → `../../06-二进制漏洞/漏洞类型与利用.md` §4。
> 本地语料引用:`[精华N-<tid>] 标题`,经 `../../../data/精华全量索引.md` 反查。
> 联网核对:2026-10-16(池布局版本变化与 CVE 细节,来源见 §7;不确定处标「待核」)。

---

## 0. 一代池,一代利用(总览)

| 时代 | 池形态 | 攻击者拿什么 | 代表利用 |
|------|--------|------------|---------|
| ≤Win7(2009) | 经典池:lookaside+ListHeads,块可合并,池可执行 | 溢出改相邻 free block Flink/Blink → 任意写;池内 shellcode | MS10-058/Mandt 论文时代 |
| Win8/8.1(2012) | 无合并+链表编码进池头+NX 池 | 只能打「相邻已分配对象」本体,ROP/劫持回调 | CVE-2014-4113 世代 |
| Win10 early(2015) | 沿用 Win8 池;KASLR 泄露面收紧 | data-only(token/PreviousMode)成主流 | CVE-2016-0095 族 |
| **Win10 19H1(1903)** | 池后端换 **segment heap**(kLFH/VS),quarantine | 同尺寸同类型才能相邻;重占概率化 | CVE-2021-31956/31969 |
| Win10 2004+ | +Secure Pool(VTL1 hypervisor 写保护) | 不可再篡改受保护对象 | dynamic KDP |
| Win11/Server2022+ | 全面 segment heap 化+隔离+延迟复用 | 池 grooming 成本指数上升 → 在野转向 CLFS/cldflt/appid 解析面、逻辑洞(PrintNightmare)、BYOVD | 2022 后在野样本 |

**一句话**:微软把「邻接布置」从一门手艺变成了抽奖;利用重心因此从 *堆布局技巧* 迁移到 *找数据流复杂的新攻击面*。

---

## 1. Windows 内核池布局演进

### 1.1 Win7 经典池(lookaside / ListHeads / POOL_HEADER / 块合并)

来源:Tarjei Mandt《Kernel Pool Exploitation on Windows 7》(REcon 2011)+ Valasek/Mandt《Windows 8 Heap Internals》(BH 2012)前半部回顾。

**架构**:每类池一个池描述符 `_POOL_DESCRIPTOR`(NonPaged/Paged/NonPagedSession/…),配 per-CPU lookaside 快路径:

```
ExAllocatePoolWithTag(NonPagedPool, size, tag)
   │
   ▼
 ① per-CPU lookaside list(_POOL_LOOKASIDE_LIST,深度上限~256,无锁快路径,精确尺寸命中)
   │ miss
   ▼
 ② 池描述符 ListHeads[512]:按尺寸索引的双向空闲链(8/16 字节粒度)
   │ 精确 miss → 找更大块 **切割**(split),空闲时与前后邻块 **合并(coalesce)**
   ▼
 ③ 池 VA 扩张(MmAllocatePagesForPool);≥页大小走 Big Pool(VirtualAlloc,PoolBigPageTable 跟踪)

x64 池块(已分配):
 +0x00  PreviousSize(9b)|PoolIndex(7b)   ┐
 +0x02  BlockSize(9b)   |PoolType(7b)    ├ _POOL_HEADER(0x10 字节)
 +0x04  PoolTag(4 字符,如 'Ufdp')        │  块尺寸以 16 字节为单位
 +0x08  ProcessBilled ∪ AllocatorBackTraceIndex|PoolTagHash ┘(free 时此槽复用存链指针)
 +0x10  ──── 用户数据 ────
 x86 头 0x08 字节,8 字节粒度

空闲块(Win7):数据区头 8 字节 = Flink/Blink → **溢出改相邻空闲块的链指针 = 经典任意写**
```

**关键攻击性质(Win7)**:
- 空闲链摘链**无 safe-unlink 校验**(对比 glibc unlink 的 FD->bk 检查)——伪造 Flink/Blink 即任意写;
- 块可合并 → 改 POOL_HEADER 的 BlockSize/PreviousSize 可诱导 overlapping(类似 glibc chunk extend);
- 池默认**可执行** → 溢出后直接把 shellcode 喷进池里,ret 到池内;
- win32k 对象住 Session Pool(独立池描述符),同一套打法换地址空间。

### 1.2 Win8(2012):池重设计——第一轮绞杀

来源:Valasek & Mandt《Windows 8 Heap Internals》(BH USA 2012,内核池章)。

- **取消块合并**:free 块不与邻居合并,尺寸分桶隔离 → 改 BlockSize 制造 overlapping、打相邻空闲块的元数据路径整体作废;
- **空闲链指针搬进 POOL_HEADER 并编码**(与随机值相关,社区称 freelist/`Flink` 编码;后续 HITCON scwuaptx《Segment Heap in Windows Kernel》 deck 亦确认 freed chunk 编码)→ 伪造链指针需要先泄露编码 cookie;
- **NX 池默认**(执行池需显式请求)→ 池内 shellcode 死;
- 分配顺序确定性下降(微软 Win8 缓解清单方向的池随机化;细节以 BH2012 论文为准)。
- **对利用的影响**:目标从「池元数据」转向「**相邻已分配对象的本体**」——函数指针对象(KTIMER 内嵌 KDPC 的 DeferredRoutine、WorkItem/GDI 对象)与 data-only 目标(EPROCESS.Token)成为主角。

### 1.3 Win10 19H1(1903):池后端 = segment heap(kLFH/VS)

来源:McGarr《Swimming in the (Kernel) Pool》(2021)、Bayet & Fariello《Scoop the Windows 10 pool!》(SSTIC 2020)、Synacktiv《Windows kernel SegmentHeap Aligned Chunk Confusion》。

> 任务原文写「Win10 19H1+ LFSC?」——**无 LFSC 一说**(LFH 是用户态堆概念);实际变化是:19H1 起内核池由 **segment heap 后端**供块。

```
_SEGMENT_HEAP(每池一个)
 ├─ kLFH(内核低碎片堆,RtlHpLfhContextAllocate)
 │    129 个 bucket;服务 1 ~ 16368 字节
 │    同尺寸连续 16 次分配 → 该 bucket 激活(LFH 化)
 │    粒度:小 bucket 16B 级 → 大 bucket 512B 级
 │    无合并;free 槽位等下一次同尺寸分配直接复用
 │    块仍带 0x10 _POOL_HEADER(未编码)→ 但要求 **同尺寸+同池类型** 才相邻
 ├─ VS(Variable Size,RtlHpVsContextAllocateInternal)
 │    块头换 _HEAP_VS_CHUNK_HEADER(带额外编码)→ 改头难度再上一档
 ├─ Segment Alloc(RtlHpSegAlloc)
 └─ Large Alloc(RtlHpLargeAlloc)

POOL_HEADER.ProcessBilled:与随机 cookie 异或存储(配额记账)→ 伪造池头还需 cookie 泄露
```

- **quarantine(隔离/延迟复用)+ decommit**:释放的子分配先进隔离区,随后才回收/接触合(SSTIC 2020 首次系统化;STAR Labs CVE-2021-31969(2023-11)实战中实测 quarantine/decommit 行为)→ **UAF 重占从「立刻喷」变成「概率等窗口」**;
- Synacktiv Aligned Chunk Confusion:利用「对齐差异的类型混淆」在 PagedPool/NonPagedPoolNx 双池通用化池溢出利用(实测稳定区间 0x130~0x300)——19H1 后池溢出仍有解,但工程量大增。

### 1.4 Win10 2004(20H1):Secure Pool(动态 KDP)

来源:windows-internals.com《Secure Pool Internals: Dynamic KDP Behind The Hood》。

- Secure Pool 由 **SecureKernel.exe 在 VTL 1 管理**,VTL 0(普通内核)只能读;写入须经安全调用(ExCreatePool / ExAllocatePool3 / ExSecurePoolUpdate / ExFreePool2);
- 固定硬编码地址 0xFFFF9B0000000000(secure kernel 侧),VTL 0 侧持 SecurePoolBase/End + delta 翻译;
- 每块前 0x10 SK_SECURE_POOL_HEADER,签名 = Cookie ^ Handle ^ Tag;hypervisor 经 EPTE 提供物理级写保护(需 VBS+SLAT);
- **对利用的影响**:即便拿到 VTL 0 任意写,放进 secure pool 的对象(凭据类敏感数据)也摸不动——把「改 token/改凭据」这类收口的一部分封死;
- 早期实现(build 20124)三个设计缺陷被赏金猎人各拿 $20k(基址泄露/句柄可推算/头可伪造致 double-free),20161 修复——**新缓解自身先被猎一遍**是常态。

### 1.5 Win11 / Server 2022+:全面 segment heap 化 + 池隔离 + 延迟复用

社区共识(MSRC 2022-03 博客《Exploring a New Class of Kernel Exploit Primitive》主题、SSTIC/STAR Labs 观测、多家 writeup 交叉):

- 内核池全面沿用并扩展 segment heap;**敏感内核对象(token/EPROCESS 等)逐步隔离到专用池**——跨类型同池重占(spray token 偷换类)可靠性下降(细节随 build 变动,**待核**当前 build 的具体名单);
- quarantine/zeroing 覆盖面扩大:释放后延迟复用 + 清零,「释放→立刻喷同型对象」的老节奏失效;
- 常用喷射原语被逐个点名收紧(IoCo 移除、WorkerFactoryExtension 限制,见 §2.2);
- **净效果**:邻接溢出(要求同尺寸同类型同 bucket)与 UAF 重占(等隔离窗口)双双概率化——这正是 2022 年后在野攻击几乎不再靠「经典池利用」、而转向 CLFS/cldflt/appid 等解析面漏洞 + BYOVD 的结构原因。

### 1.6 分配 API 演进(驱动侧可见面)

| API | 引入/状态 | 要点 |
|-----|----------|------|
| `ExAllocatePool` | 最老 | 无 tag,已废 |
| `ExAllocatePoolWithTag` | Win2000~,**现正式 deprecated** | 老驱动/漏洞驱动主力;审计时的第一 grep 点 |
| `ExAllocatePoolZero/Uninitialized/QuotaZero/QuotaUninitialized` | 2004 前目标兼容层 | 显式表达清零语义 |
| **`ExAllocatePool2(Flags, Size, Tag)`** | **Win10 2004+** | **默认零初始化**(除非 `POOL_FLAG_UNINITIALIZED`);POOL_FLAG_NONPAGED/PAGED 取代池类型参数;Tag=0 非法;默认失败返回 NULL(`POOL_FLAG_RAISE_ON_FAILURE` 才抛异常);配额改 `POOL_FLAG_USE_QUOTA` |
| `ExAllocatePool3` / `ExCreatePool` / `ExSecurePoolUpdate` / `ExFreePool2` | 2004+/Win11 时代 | 池实例化+优先级语义;Secure Pool 的 VTL 调用面 |

审计含义:`ExAllocatePool2` 默认清零 → **新驱动里「未初始化池内存泄露」类洞天然减少**;仍以 `ExAllocatePoolWithTag` 分配且内容含指针/长度字段的驱动,是 0day 白盒首选面。

---

## 2. 池风水(spraying)

### 2.1 邻接布置原理(以 19H1 kLFH 为例)

```
目标:让 [受害对象 V][牺牲对象 S] 物理相邻
 ① 同 tag/同尺寸大量分配把桶填实(排空旧洞)
 ② 隔一放一释放(poke holes)——制造可控空洞
 ③ 触发漏洞使 V 落入空洞
 ④ 释放/占用 S → 溢出 V 改 S,或 UAF 后用 S' 重占
19H1 后约束:V 与 S 必须 **同尺寸 bucket + 同池类型**(如都 NonPagedPoolNx)
  + 同 bucket 需 16 次连续分配激活 kLFH + quarantine 延迟
→ 每一步都在缩小可选对象集
```

### 2.2 喷射原语演进史(被微软逐个修的编年)

| 时期 | 原语 | 特性 | 结局 |
|------|------|------|------|
| Win7 | user objects(CreateEvent/Semaphore 等) | 固定小尺寸,内容半可控 | 池随机化后确定邻接失效 |
| Win7 | win32k Session Pool 对象(菜单 tagMENU/AppendMenu) | 内容可控 | 同上,win32k 加固后收窄 |
| Win8-10 | `NtAllocateReserveObject`(IoCompletion,0x60) | 尺寸固定,内容不可控,纯占位 | **19H1 移除**(社区 writeup 一致记载) |
| Win8-10 | Pipe 属性(DATA_ENTRY,Np* 系列) | paged pool,内容可控 | 长期可用 |
| Win10 | ALPC 连接消息 | paged pool,内容可控,大量 | ALPC 加固(2018 CVE-2018-0824 族)后受限但仍是主力 |
| ~2021 | **`NtSetInformationWorkerFactory(WorkerFactoryExtension)`** | 可控大小+内容的内核分配 → 喷假对象神器 | 流行后被**收紧/失效**(无单一权威公告,散见 exploit 工具链 changelog;MSRC 2022-03 博客即此类「常用原语评估与缓解」的信号) |
| 2021+ | WNF State Data(`NtCreateWnfStateName` 等) | 尺寸多档,StateData 部分可控 | CVE-2021-31956 公开利用的基石(NCC Group) |
| 常青 | CreateEvent(0x80 含头) | 5000 个量级稳定占位(McGarr HEVD 演示) | 仍可用,内容不可控 |
| 2024 | 受限环境(低完整性/AppContainer)原语筛选 | — | 3sjay《CVE-2021-31956 Part1》(2024)专论 |

**规律**:喷射原语的寿命 = 「文档化 → 大量公开 exploit 引用 → MSRC 定点阉割」;挖新洞前先测目标 build 上原语是否还活着,是第一课。

### 2.3 当前(2024-2026)稳态可用面

- 纯占位:Event/Timer 对象、Semaphore(不可控内容,靠大量铺);
- 可控内容:Pipe DATA_ENTRY、WNF StateData、(视 build)ALPC 消息;
- 特定尺寸 UAF:win32k 对象(见 §3.2)、Token 对象(隔离化中,**待核**各 build 可靠性);
- 喷不动时的替代:**不追重占,追数据面**——找「溢出只改一个长度/标志位就能放大」的对象(如 31969 的 restrictive chunk grooming,STAR Labs 范式)。

---

## 3. 利用原语构造

### 3.1 溢出 → 改相邻对象(按目标分类)

1. **打池头(Win7 限定)**:改相邻空闲块 Flink/Blink(无 safe-unlink)→ 任意写;改 BlockSize/PreviousSize → overlapping 切割。Win8+ 链表编码+无合并后死亡。
2. **改函数指针(拿 RIP)**:相邻对象带内核回调,溢出改之,等触发:
   - WaitableTimer(内嵌 KDPC:`DeferredRoutine`/`DpcContext`,定时器到期触发)——HEVD 时代教科书;
   - GDI/USER 对象(palette/bitmap/surface 类,含函数指针与 `pfn*` 域)——经典 palette spray 一鱼两吃(既当喷射又当劫持目标);
   - 各类 WorkItem/IoCompletion 回调对象。
   SMEP/SMAP 后需接 ROP/stack pivot(§4)。
3. **data-only(不碰执行流,现代主流)**:
   - 相邻恰好是 **EPROCESS** → 直接改 Token 指针(偷 System token);
   - 改对象内**长度/引用计数字段**制造二次原语(如改相邻对象的 size → 越界读写放大);
   - 改配额相关 ProcessBilled(让目标进程替你背账,多用于干扰与组合)。
   「Process-Bitmap」类位图目标(GDI 句柄位图/`_RTL_BITMAP` 容器)同属此列:改位图基址/长度 → 把「按位图校验」变成「按你写的位图放行」。

### 3.2 UAF 重占(占位对象选型)

| 场景 | 首选占位 | 理由 |
|------|---------|------|
| 需要内容全可控(伪造结构体) | Pipe DATA_ENTRY / WNF / ALPC | 用户态可写满 |
| 需要对象本身合法可信(token 偷换) | 另一进程的 Token 对象 | 「真凭证住进洞里」——Windows 版 DirtyCred 思路;池隔离推进中,**逐 build 验证** |
| win32k UAF(tagWND 族) | 二次窗口对象/可控 extra-bytes | CVE-2021-1732 范式:让 `xxxClientAllocWindowClassExtraBytes` 回调返回**攻击者指定地址** → tagWND 的 extra 指针指向用户内存 → 任意读写(SMEP 无关的 data-only) |
| 只求占住不让别人拿 | Event 大量铺 | 内容无所谓 |

19H1+ 注意:先激活同尺寸 kLFH bucket(≥16 连续同尺寸分配),再谈重占;quarantine 期间释放块不出现——**释放与重喷之间要留窗口**(STAR Labs 31969 的实测节奏)。

### 3.3 从任意写到 SYSTEM 的三条路

1. **EPROCESS.Token 直改(经典首选)**
   定位:current `_KTHREAD→ApcState.Process` 或 `PsGetCurrentProcess`;遍历 `_EPROCESS.ActiveProcessLinks` 双链找 System(pid 4),抄其 Token 指针。
   细节:Win10+ Token 指针低 4 位是 EX_FAST_REF 引用计数——**复制时保留低 4 位**或做 `& ~0xF` 对齐处理;偏移逐 build 变(1EPROCESS 偏移表要随版本维护)。
2. **KTHREAD.PreviousMode 置 KernelMode**
   把当前线程 `_KTHREAD.PreviousMode` 写 0,随后用户态直接 `NtReadVirtualMemory/NtWriteVirtualMemory` 打内核任意地址,用完改回 1。比换 token 更「外科手术」:不产生新句柄、不碰对象校验;HVCI/kCFG 全不影响(纯数据)。
3. **KPROCESS/EPROCESS 链表操作**
   - ActiveProcessLinks 摘链(隐藏/嫁接进程);
   - 或不找 System:借链表遍历任一 SYSTEM 上下文进程抄凭证;
   - 变体:不换 Token 只拉满 `_SEP_TOKEN_PRIVILEGES`(Present/Enabled 全 1)——保 token 对象本体,校验器更难发现。
   其他路(历史/条件):HalDispatchTable+`NtQueryIntervalProfile`(≤Win7 古董);DirectoryTableBase(CR3)交换(借 System 地址空间,KPTI/HVCI 下受限)。

---

## 4. 缓解与绕过(每层把成本抬到哪)

| 缓解 | 时间 | 封死什么 | 绕过/残余 | 成本抬升 |
|------|------|---------|----------|---------|
| NX 池 | Win8(2012) | 池内 shellcode | RIP 劫持到内核 .text+ROP | 溢出≠执行 |
| 取消合并+链表编码 | Win8 | 打池元数据 | 只打对象本体 | 「喷 free block」死 |
| SMEP | 2012(Ivy Bridge)/Win8 起 | ret2usr、用户态 fake 对象当代码 | stack pivot+内核 ROP | 必须 leak 内核基址 |
| SMAP | ~2015(Broadwell+)/Win10 | 内核解引用用户内存 | KVA shadow gadget/全内核侧伪造 | fake 对象必须住内核 |
| KASLR 泄露面收紧 | Win8.1/10 | `NtQuerySystemInformation`/`EnumDeviceDrivers` 低 IL 拒 | 对象头/数据面泄露(如 HEVD 越界读邻接符号指针) | 无 leak 不成链 |
| KPTI | 2018-01(Win10 1709,Meltdown) | 用户页表含内核 | — | ROP 链跨页成本↑ |
| kCFG(内核 CFG) | Win10 后期逐步,+Win11 硬件 CET/IBT(CPU 支持) | 间接调用跳非合法目标 | 只调合法函数(COP/data-only) | 函数指针劫持面收窄 |
| HVCI/VBS | Win10 1607 可选,**Win11 出厂普及默认** | 无签名代码执行(ROP 也难落 shellcode) | 纯 ROP 或纯数据攻击 | 「执行流利用」近乎死,数据面成唯一主路 |
| segment heap 池 | 19H1(2019) | 跨尺寸邻接、改 VS 头 | Aligned Chunk Confusion 等精细手法(0x130-0x300 稳定) | grooming 工程量×10 |
| quarantine/zeroing | 19H1 起,Win11 扩大 | 释放即重占 | 等窗口/换占位策略 | UAF 利用概率化 |
| Secure Pool | 2004(2020) | VTL0 写敏感对象 | 无(需 VTL1 漏洞) | 凭据类收口封死 |
| 池对象隔离/原语阉割 | 2021-2022+(IoCo 移除等) | 跨类型 spray、假对象 | 逐 build 重测 | 公开 exploit 半衰期缩短 |

**成本曲线结论(哪年后必须有 chain)**:
- 2012 前:单洞单 exploit(溢出→池内 shellcode→token)一天活;
- 2012-2016:需要「洞 + 泄露 + ROP」三件套;
- 2017-2018(SMEP/SMAP/KPTI 全开):**在野利用开始普遍是 chain**(浏览器/Office RCE + 内核 LPE 两段);
- 2019+(19H1):池利用本身要 10×工程量,公开 exploit 数量肉眼下降;
- 2021+(HVCI 默认+原语阉割+逻辑洞崛起):内存破坏 LPE 让位给 **CLFS/NTFS/cldflt/appid 等驱动解析面 + 逻辑洞(PrintNightmare)+ BYOVD**——这就是 §5 表里 2021 后行的构成原因。

---

## 5. CVE 模式库(核心表)

> 2026-10-16 联网逐条核对。「公开利用」= 有公开 exploit/PoC 或完整 writeup。**勘误栏见表后**(任务清单里 4 个编号归属有误,已核实改正)。

| CVE | 年 | 组件 | 根因类 | 利用原语 | 公开利用 | 模式一句话 |
|-----|----|------|--------|---------|---------|-----------|
| CVE-2014-4113 | 2014 | win32k.sys | UAF(弹出菜单) | 重占+token 窃取 | 有(多份;本地语料 5 篇) | 菜单循环里用户回调销毁 popup 对象 → 回来继续用(MS14-058;Sandworm 与 CVE-2014-4114 OLE 链用、Hurricane Panda 独立用) |
| CVE-2018-8453 | 2018 | win32k.sys | UAF(xxxCreateWindowEx 路径) | tagWND 重占→任意读写 | 有(奇安信全文) | 同族第一响:窗口创建回调期间对象被毁 |
| CVE-2018-8639 | 2018 | win32k.sys | UAF(xxxCreateWindowEx 回调族) | 同上 | 有(本地语料 2 篇) | 12 月补丁;在野经 Flash SWF 嵌入投放 |
| CVE-2021-1732 | 2021 | win32k.sys | 回调可控地址(xxxClientAllocWindowClassExtraBytes) | extra-bytes 指向用户内存→任意读写 | 有(chompie PoC;P0 RCA) | 用户态回调返回值未验证 → data-only 全链 |
| CVE-2022-21882 | 2022 | win32k.sys | **1732 补丁绕过** | 同上 | 有(在野,Unit42 深析) | 每次修 win32k 必重审:offset 检查加宽仍留路径 |
| CVE-2021-31956 | 2021 | ntfs.sys | 池 UAF/溢出(paged pool) | WNF 重占→token 窃取 | 有(NCC 双部曲+3sjay 2024) | 解析面 UAF+可控喷射原语的标准合流;在野(Nokoyawa 勒索) |
| CVE-2021-31969 | 2021 | cldflt.sys | 池溢出(受限尺寸) | grooming+邻接改写→任意读写 | 有(STAR Labs 全文) | 「喷不动就精修」:restrictive chunk 下的池溢出范本 |
| CVE-2023-36036 | 2023 | cldflt.sys | 解压输出长度未复核→OOB | 池越界写 | 有(根因+bindiff 全公开) | 校验的元素与消费的元素不同批(根因库模式 9/10) |
| CVE-2024-26229 | 2024 | cldflt.sys | UAF | symlink/对象滥用 | 有 PoC;**在野**(Kaspersky Q2'24) | 同一驱动三年三洞:攻击面常年肥 |
| CVE-2021-34527 | 2021 | spoolsv(Print Spooler) | RPC 鉴权/路径逻辑错 | 远程 SYSTEM(驱动 DLL 加载) | 有(PrintNightmare 海量) | SYSTEM 服务复制+加载客户端指定文件;逻辑洞无视一切内存缓解(§6 全拆) |
| CVE-2022-21999 | 2022 | Print Spooler | 目录/junction 处理 | 本地 SYSTEM | 有(SpoolFool,PoC 全公开) | Spooler 攻击面续命:补完 RPC 还有目录链 |
| CVE-2022-24521 | 2022 | clfs.sys | CLFS 结构字段校验缺失(逻辑错) | token 窃取 | 有(P0 RCA;KEV 在野) | CLFS 恶梦起点:自解析日志格式=内核里的一门语言 |
| CVE-2022-37969 | 2022 | clfs.sys | 同族后续 | 同上 | 有(社区 PoC 多) | 24521 模板复用,CLFS 成 22-23 年 LPE 提款机 |
| CVE-2024-21338 | 2024 | appid.sys(AppLocker) | IOCTL 输入校验(admin→kernel) | 内核读写→token | 有(nero22k/crowdfense 全文) | Lazarus 0day(加载 FudModule 前置);7 月同驱再来 CVE-2024-38041 |
| CVE-2024-30090 | 2024 | Microsoft Streaming Service(内核流服务驱动族) | 权限管理不当(CWE-269) | 本地→SYSTEM | 有 PoC | 7 月补丁;流服务=又一常青解析面(IBM X-Force 2023 已开箱同族) |
| CVE-2019-16098 | 2019(BYOVD) | MSI RTCore64.sys | 驱动任意内核读写接口 | 直改内核 | 有;在野(BlackByte 勒禁 EDR) | BYOVD:签名漏洞驱动当工具,池风水全部免修 |
| CVE-2021-21551 | 2021(BYOVD) | Dell dbutil(DBUtilDrv2.sys) | 访问控制缺失 | 任意物理/内核读写 | 有 | 同上;Dell 官方 DSA-2021-152 |
| gdrv.sys / WinRing0x64.sys | 常年(BYOVD) | Gigabyte / OpenLibSys | 任意读写/MSR 接口 | 直改内核 | 有;多起勒索/APT 滥用 | 微软靠脆弱驱动黑名单(Microsoft recommended driver block list)补救;**CVE 编号散乱待核** |

**勘误(任务清单核实结果,勿再传抄)**:
- **CVE-2021-36942 ≠ win32k**——实为 **PetitPotam(LSA Spoofing,MS-EFSR 强制认证)**,2021-08 补丁,NTLM relay 链组件(NVD/SentinelOne 核实);
- **CVE-2022-22005 ≠ Windows 内核 LPE**——实为 **SharePoint RCE**(2022-02,Rapid7 核实);打印池后续应记 CVE-2022-21999(SpoolFool);
- **CVE-2014-4113 ≠ tagTRACKMOUSEEVENT**——实为 **TrackPopupMenuEx 弹出菜单路径 UAF**(MS14-058);
- **CVE-2022-24521 ≠ win32k CBWF**——实为 **CLFS 驱动**(P0 RCA 分类 logical error)。

---

## 6. 从模式到新洞:PrintNightmare(CVE-2021-34527)完整拆解

选它做样板:**逻辑洞范式**——不碰内存、无视 SMEP/HVCI/池缓解全家,且攻击面(SYSTEM 服务复制+加载客户端文件)在 Windows 里是一整类。

### 6.1 定位(攻击面从哪来)

- Print Spooler 服务(spoolsv.exe,**SYSTEM** 权限,域控/工作站默认开)暴露两个 RPC 接口:MS-RPRN(`\\pipe\\spoolss`)与 MS-PAR;
- 打印体系允许「驱动文件来自客户端」(Point-and-Print 的历史遗产):服务端从客户端指定的路径(UNC)拉取驱动文件,复制进服务端 DriverStore,**并把配置/接口 DLL 加载进 spoolsv.exe 进程**。

### 6.2 根因

- `RpcAddPrinterDriver(Ex)` 的权限/路径校验错位:Point-and-Print 的策略放宽路径与「管理员才可装驱动」的语义在 RPC 层拼装时出缝——**非管理员(有凭据或借 NTLM relay)可远程调用并指定驱动文件来源**;
- 服务端以 SYSTEM 落盘+`LoadLibrary` 任意 DLL:装的是「打印驱动」,执行的是任意代码;
- 本质假设被打破:**「客户端提供的文件路径」被当作可信安装源**,与「服务端本地 DriverStore 唯一来源」的设计前提冲突。

### 6.3 原语与利用形态

- **远程 RCE**:有效域凭据/SMB 中继 → 目标 spooler 以 SYSTEM 加载攻击机 SMB 上的恶意 DLL(公开 PoC 如 cube0x0 的 impacket 实现:构造 GUID 驱动目录+`RpcAddPrinterDriverEx`);
- **本地 LPE**:普通用户对本机 spooler 同样可达(装驱动不需提权路径);
- 约束与扩展:需 spooler 运行、目标可达 445/SMB(取回驱动文件);与凭据窃取/relay(PetitPotam 类)组合成域控沦陷链——2021 年它成为域环境头号梦魇的结构原因。

### 6.4 补丁 diff 逻辑(公开时间线整理)

1. 2021-06-08 常规补丁(CVE-2021-1675,当时标 EoP)——**未覆盖 RPC 远程路径**;
2. 2021-06-21 研究者(Zhiniang Peng & Xuefeng Li)公开披露(误以为已修,放出 PoC 后撤回未及),社区迅速复现——**PrintNightmare 得名**;
3. 2021-07-01 微软 OOB 发布 **CVE-2021-34527** 补丁:校验驱动文件必须来自服务端本地/DriverStore,拒绝远程 UNC 来源,收紧 `RpcAddPrinterDriverEx` flag 语义;
4. **首版补丁再被绕过**(路径规范化/UNC 变形类 trick,公开绕过文随即出现),7 月中旬与后续 8/9 月补丁轮次继续封 variant——「补丁—绕过—再补」打了小半年;2022-02 还有 SpoolFool(CVE-2022-21999)证明该服务攻击面远未挖完。
5. 防御侧并行:禁用 Spooler(`Stop-Service Spooler`)、阻断出站 SMB 445、Point-and-Print 策略收紧(`NoWarningNoElevationOnInstall=0` 等)。

### 6.5 同类面还有哪里可挖(方法论输出)

按「SYSTEM 服务 + 复制/加载客户端指定文件」的形状找:
- **Spooler 自身剩余面**:MS-PAR 接口、splwow64(跨会话 print)、打印处理器/驱动 .gpd/.ppd 解析、spool 目录 junction(21999 已证);
- **同形状服务**:一切「安装即搬运」的 RPC/WMI 提供者(Win32_Printer 类操作)、旧 Windows Installer 自定义路径场景、远程注册表/任务计划等 SYSTEM IPC;
- **模式迁移**:内存缓解封死执行流后,**「让 SYSTEM 替你 LoadLibrary」是官方允许的执行流**——逻辑洞的 ROI 系统性高于池利用,这也是 §5 表 2021 年后构成比的直接原因;
- 挖法:接口枚举(impersonation level/权限断言 grep)→ 客户端可控路径参数清单 → 服务端落点与加载点核对——纯白盒可做,无需碰堆。

---

## 7. 语料互链 / 来源 / 待核清单

### 7.1 本地语料(经 `精华全量索引.md` 反查 tid)

- CVE-2014-4113 ×5:精华15-193465(分析摘要)、精华16-198194(分析及 Exploit 逆向)、精华17-207996(本地提权分析)、精华23-275621/271809(UAF 分析/学习笔记);
- CVE-2018-8639 ×2:精华20-251400(EXP 分析)、254305(分析与复现);
- PrintNightmare:精华23-271241(复现分析);
- HEVD 系列/内核入门:精华18-218838/218868(初学内核利用一二)、129143/9132(内核漏洞利用技术文章集合)、精华16-206423(Windows 内核漏洞初探)、202605(用户模式回调的内核漏洞分析——**win32k 回调族的本地理论源头**);
- EPROCESS/Token 基础:9988(EPROCESS 地址获取)、10048-10049、10464(ActiveProcessLinks 偏移);
- 池老文:精华15-187402(《POOL 驱动的梗》)。

### 7.2 本次联网核对来源(2026-10-16)

- 池演进:Mandt《Kernel Pool Exploitation on Windows 7》(2011);Valasek/Mandt《Windows 8 Heap Internals》(BH 2012);McGarr connormcgarr.github.io(2021);Bayet & Fariello《Scoop the Windows 10 pool!》SSTIC 2020;Synacktiv SegmentHeap-Aligned-Chunk-Confusion;windows-internals.com《Secure Pool Internals》;MS Learn ExAllocatePool2 文档;STAR Labs CVE-2021-31969(2023-11);NCC Group 31956 双部曲;Unit42《Inside Win32k Exploitation》;P0 0days-in-the-wild RCA(CVE-2021-1732/CVE-2022-24521);MSRC 博客《Exploring a New Class of Kernel Exploit Primitive》(2022-03);
- CVE 归属勘误:NVD/CVE.org、SentinelOne VulnDB、Rapid7、Trend Micro、Qianxin、CrowdStrike、ZDI 月评。

### 7.3 待核清单(下次更新先打这里)

- [ ] Win11 当前 build 池隔离/专用池的具体对象名单(token/EPROCESS 是否全部迁移);
- [ ] quarantine 的精确参数(延迟窗口、随机化)随 build 变化;
- [ ] `NtSetInformationWorkerFactory` 收紧的确切版本与形式(社区散记,无官方公告);
- [ ] gdrv.sys / WinRing0x64.sys 的权威 CVE 编号(gdrv 常引 CVE-2018-19320、WinRing0 常引 CVE-2020-14979,**均待核**);
- [ ] CVE-2024-30090 驱动级根因(组件=Microsoft Streaming Service 已核,函数级细节未公开核);
- [ ] CLFS 族(CVE-2022-37969 及 2023 系)白盒根因——本地无专帖,值得单开一篇(对标 Linux 侧 cldflt 的待遇)。
