# 内核 Hook 与无痕对抗

> 定位:frida 的一切特征(maps/rwxp/线程/gadget)都在用户态,最强 RASP 能看光;把 hook 挪进内核(改入口指令/页表/影子页),app 的视野里就什么都不存在。本篇:四种内核 hook 机制对比、KernelPatch 系(KPM/wxshadow 无痕断点)详解、VoidLink、android-kernel-hacking-toolkit、ANDROID-MRI 思路,以及「为什么检测不到」的原理收口。

## 1. 四大内核 Hook 机制对比

| 机制 | 原理 | 入口 | 性能 | 检测面(app 可见?) | 依赖 |
|---|---|---|---|---|---|
| **ftrace** | 编译器在每个内核函数入口插 `__fentry__`(ARM64 上为 `BL` 到 ftrace_caller);开跟踪时把调用槽改成跳转 | `tracefs`(debugfs/tracefs);`ftrace_set_filter` 过滤目标函数 | 低开销,可 livepatch 级复用 | 只能读 tracefs 的才可见;app 无权读 → **不可见** | CONFIG_FUNCTION_TRACER |
| **kprobe** | 目标地址指令替换为断点指令(x86 `int3`,ARM64 `BRK #0x1`),命中走异常处理器单步原指令 | `register_kprobe`;post-5.7 常用来解 `kallsyms_lookup_name` | 陷阱+单步,较慢 | 同上,**不可见**;但 `/sys/kernel/debug/kprobes` 可列出(root 才可读) | CONFIG_KPROBES |
| **eBPF fentry/fexit** | BPF trampoline:直接把 fentry 调用槽 JIT 成跳到 trampoline,进/出都拿参数与返回值,**无陷阱** | `BPF_PROG_TYPE_TRACING` + `attach_fentry`(bpftrace `fentry:func`) | 比 kprobe 快一个量级 | **不可见**(app 无 bpf 权限);审计面在 root 侧 | CONFIG_BPF+BTF(fentry 必须) |
| **LSM hook(bpf_lsm)** | 内核安全路径上的固定 hook 点(`file_open`/`task_alloc`/`bprm_check_security`…) | `BPF_PROG_TYPE_LSM`;或传统 LSM 注册 | 路径级 | **不可见**;属于框架合法能力 | CONFIG_BPF_LSM |
**要点**:
- kprobe 解 `kallsyms_lookup_name`:5.7 起不再导出 → 用 kprobe 注册同名符号取 `kp.addr`(android-kernel-hacking-toolkit、无数 LKM 的标准起手式,见 §5);
- fentry 需要 BTF:GKI 新内核有,老内核/无 BTF 场景退回 kprobe;
- 这四者对 **app 进程完全不可见**——app 无 CAP_SYS_ADMIN、无 debugfs/bpf 访问权;「检测面」只存在于另一个 root 观察者(对抗性 root 扫描)视角。

## 2. KernelPatch 系:从 boot 镜像到无痕断点

### 2.1 KernelPatch / KPM

**仓库**: bmax121/KernelPatch(GPL-2.0,~1.6k stars)
- 能力:仅凭 stripped 内核镜像(无需源码/符号)做:全量符号提取(基于 vmlinux-to-elf 思路)、静态 patch 内核镜像、运行时向内核注入任意代码、**inline hook + syscall 表 hook**、"Additional SU for Android"(即 APatch 的 root);
- 平台:仅 arm64,内核 3.18–6.6(理论),要求 CONFIG_KALLSYMS=y;感谢 android-inline-hook(arm64 指令修复);
- **SuperKey**:APatch 体系的口令——调用被 hook 的 syscall 时带上超级密钥才触发 root 授权,普通调用走原逻辑;
- **KPM(KernelPatch Module)**:运行时加载的内核模块(独立于 KMI 的 .ko 体系),自带 SDK;APatch 是其官方 Android 前端。
**Inline Hook vs Inline Wrap**(用户材料术语,与 KP README 的 inline hook/syscall hook 对应):
- Inline Hook:直接改目标内核函数入口前 N 条指令为跳转(ARM64 常用 `LDR X16,#8; BR X16; addr` 16 字节方案),原指令搬进 trampoline 修复 PC 相对寻址后执行——frida Interceptor attach 的内核版;
- Inline Wrap:不直接改目标,包一层 wrapper(trampoline 里先跑用户逻辑再跳原函数)——onEnter/onLeave 语义。

### 2.2 「KernelHook」框架

线索:「KernelHook:Android ARM64/GKI 内核 LKM Hook 框架,源自 KernelPatch」→ 核实结论:
- GitHub 搜 "KernelHook" 命中的全是 **Windows** 内核 hook 框架(adrianyy/kernelhook 312★、smallzhong/KernelHook 190★),Android/GKI 同名 LKM 框架未见公开仓;
- 判断:该名大概率指 KernelPatch 生态的 hook 能力或某私有项目名。**按能力理解即可,勿引用为独立项目**。

### 2.3 wxshadow:W^X 影子页无痕断点

**仓库**: wxshadow(KPM 模块;另有 PoC 仓 18★ 与融合发行版)
**技术源头**:社区帖「shadow-memory hook」。
**能力事实**(README 测试矩阵,OnePlus Android 16 / Linux 6.12.23 / 4KiB 页 / va_bits=39 闭环):
机制(无痕断点的完整生命周期):

```
设断点: 分配影子物理页 = 目标页副本,在目标地址写入 BRK #0x7
        把用户 PTE 重定向到影子页(BBM 原子 PTE 写)
执行取指: CPU 走影子页 → 命中 BRK #0x7 → 异常进 handler
        → 寄存器全捕获(x0–x30/sp/pc/pstate)
        → PTE 翻回原始页 → 单步原指令 → 重装影子 PTE → 继续跑
读取者: 始终解析到原始页 → 永远看到原始字节,BRK 不可见
```

两条「读隐藏」证据链(README 测试矩阵原文):
- **/proc/PID/mem 读取隐藏**:读目标地址返回原始指令(`ff0301d1`),不是 BRK;
- **GUP 隐藏**:hook `follow_page_pte`,`process_vm_readv`/`ptrace`(走 get_user_pages→follow_page)同样拿原始页。
其余能力:多断点、影子页任意 patch(改指令)、寄存器改写(x0 注入)、跨进程 hook(客户端 `wxshadow_client -p <pid> -a <addr>`,prctl 分发)、fork 保护(hook `uprobe_dup_mmap`,子进程不继承影子)、`exit_mmap` hook 清理、`tlbi vaale1is` 广播 TLB 失效、100/100 稳定性。
**Linux 6.12 适配的关键工程点**(对做同类工具极有价值,均 README 原文):
- 6.12 的 `find_vma` 带 `WARN_ON_ONCE(rwsem_is_locked(&mm->mmap_lock))` 且 `mmap_read_lock` 是 static inline → 运行时路径**完全弃用 find_vma**,改 `get_user_pte` 锁less 页表行走 + PFN 验证;
- `page->mm`(set_bp 时从 `get_task_mm` 捕获)是权威 owner,不信 `vma_mm(vma)`;
- THP(2MiB block)目标返回 `-14` 拒绝(需可靠探测 `mm->mmap_lock` 偏移才能 split);
- `wxshadow_exit` 若未走 5 阶段 unhook,dangling hook 指向已卸载模块代码 → 下次 syscall 重启。
**为什么无痕(原理收口)**:断点只存在于**影子物理页**;所有读取路径(页表遍历者被 hook 的 GUP、/proc/mem)看到的是原 PFN;唯一差异是执行流瞬时走影子页,而这一窗口内 PTE 又被翻回。用户态任何「读自身代码段比对哈希」的自检全部命中原始字节。**这是对「inline patch 自检」类 RASP 的结构性碾压。**

### 2.4 mkpms-stealth:四合一作战模块

 —— `stealth.kpm` 一次加载四能力:
- **hide-maps**:过滤 `/proc/<pid>/maps|smaps|map_files`,按关键词/地址区间藏注入 so(明确「做不到」内存扫描/dl_iterate_phdr/solist,需 so 自摘);
- **kload**:内核 dlopen 劫持,**无 ptrace 注入** so(prctl 0x4B4C);
- **wxshadow**:§2.3;
- **dbc-rw**:内核跨进程读写(syscall 41 埋点)。
→ 组合即「注入不可见 + 断点不可见 + 读写不落用户态」的完整栈,面向 APatch/KP。

## 3. VoidLink rootkit

**实体**:VoidLink 内核 rootkit 隐藏模块 POC(仓库无 README,代码细节需自行核读)。
**用户线索部分**(LKM ftrace 系统调用 hook + eBPF 改 Netlink 响应缓冲区隐藏网络连接):具体实现未验证。但该技术路线本身是社区已知通用手法:
- ftrace hook syscall:见 §1,标准做法是 ftrace 直接 ops 改 syscall 入口(内核侧),对 `ss`/`netstat` 的用户态读取无感;
- eBPF 改回包:`BPF_PROG_TYPE_TRACEPOINT`/kprobe 挂 `inet_diag`/sock_diag 路径,用 `bpf_probe_write_user` 重写 netlink 响应缓冲区里的端口/地址项,把监听端口从 `ss`/`netstat` 输出里抹掉——eBPF 写用户态缓冲的经典应用(与 Cilium 早年 hide-port demo 同型);
- 结论:**项目存在已证、技术路线可行已证、该仓库的具体实现未证**。

## 4. android-kernel-hacking-toolkit

**仓库**: (中英双语 README)
四个 LKM 模块(ioctl 的 /dev 设备交互),全部针对 Android aarch64 5.4+ 现代缓解:

| 模块 | 功能 | 关键实现 |
|---|---|---|
| filecopy | 内核态复制文件(绕 SELinux 对用户态 IO 的约束) | kallsyms 解出 `filp_open/kernel_read/kernel_write`,CFI 绕过包装 |
| hideproc | 按 PID 藏进程 + 防杀 | hook `openat`(挡 /proc/<pid>/*)等系统调用 |
| propedit | 改 Android 系统属性 | 内核态物理内存写用户页 |
| syscall_hijack | 伪造 `sysinfo` 返回 | sys_call_table 劫持 |
**对抗现代缓解的四板斧(README 原文,做 LKM 必备)**:
1. `kprobe` 取 `kallsyms_lookup_name` 地址(≥5.7 不导出的解法,§1);
2. `__attribute__((no_sanitize("cfi")))` 包装函数指针绕 CFI 间接调用校验;
3. **mmuhack**:直接页表操作临时解除内核内存(sys_call_table)写保护——绕 rodata RO/CONFIG_STRICT_KERNEL_RWX;
4. 物理内存写改用户页(propedit 场景)。

## 5. ANDROID-MRI:OS 级 instrumentation 思路

**核实**:公开检索未见「50 个 ≥100 万安装 app、绕过 97.6% RASP(frida 对比 52.4%)、trace runtime / ROM loader / root interface 三模块」的论文或项目,按思路借鉴处理:
- 核心主张:不在用户空间注入(那是 RASP 的雷达区),而在**厂商签名的生产 ROM 上做 OS 级插桩**——系统层看起来完全正常,签名、完整性、属性全过;
- 三模块想象:`trace runtime`(ROM 内建追踪,等价系统级 frida 但无 frida 任何特征)、`ROM loader`(刷入/装载插桩 ROM)、`root interface`(如 /system/bin/sh 的受控 root 出口);
- 现实落地路径(用上述组件拼):APatch/KernelPatch(KPM=trace runtime 的内核侧)+ wxshadow(无痕断点)+ 自己编 ROM 或 magisk boot patch(loader)+ KPM 提供的 su(root interface)——能力上等价,只是没有「97.6%」这种量化背书。

## 6. 为什么内核级 Hook 检测不到(原理总结)

用户态检测的**全部信息来源**逐条对照:

| RASP 检测手段 | frida 下 | 内核 hook 下 |
|---|---|---|
| 读 /proc/self/maps 找 rwxp/so | 命中 | 无(无注入,hide-maps 再兜底) |
| 扫代码段 prologue 哈希/比对 | patch 命中 | **wxshadow:读路径见原页,不命中** |
| 查线程名(gum-js-loop)/线程数 | 命中 | 无新线程(kprobe/BRK 在异常上下文) |
| 查文件(magisk/frida-server/属性) | 命中 | APatch/KPM 无这些面 |
| ptrace 自检 TracerPid | frida attach 命中 | 不用 ptrace(wxshadow 明确 GUP 隐藏) |
| syscall 内联 svc 直调比对返回 | 可能命中(改的是 libc 层) | hook 在内核,svc 直调也被 hook |
| perf_event/时序侧信道 | 理论可测 | 仍可测(陷阱开销)——**唯一残留检测面** |
一句话:**检测的本质是「读取自己看不到的状态」,而内核 hook 把状态改在 app 永远读不到的层(页表影子页、内核入口指令);剩余风险只有性能侧信道与另一名 root 观察者(反 root 扫描)——那已是 root 对抗,不是 app 对抗。** 配合 `root与环境隐藏.md`(04 区)与 KPM hide 能力闭环。

## 7. 机制深潜(读懂无痕的底层)

### 7.1 ARM64 断点指令与异常解码(wxshadow 为什么选 `BRK #0x7`)

- ARM64 没有 x86 的 `int3`,通用软件断点是 `BRK #imm16`:AArch64 上 `BRK` 触发 EC=0x3C(BRK 异常,ESR_EL1.EC=111100);
- imm16 是立即数空间,内核 kprobe 惯用 `BRK #0x1`/`#0x2`(kprobe/kgdb 各占),**选 `#0x7` 避开内核自用号段**,异常处理器按 imm 分发到 KPM 的 handler;
- 单步:`PSTATE.SS`(Software Step,MDSCR_EL1.SS 使能)——wxshadow 翻回原页后靠硬件单步执行原指令,再重装影子 PTE;
- TLB 一致性:改 PTE 后必须失效,wxshadow 用广播 `tlbi vaale1is`(inner-shareable,全 ASID,带 VA)——多核下其他核的 TLB 残留是这类工具最常见的翻车点。

### 7.2 ftrace 直改 IP 的 LKM hook(通用型,不依赖 KP)

x86 经典写法(社区 ftrace-hook 模板):`ftrace_ops` 注册到目标函数地址,`IP_MODIFY` 声明,在回调里改 `regs->ip` 指向 wrapper(等价于改返回地址,目标函数没跑就被劫走);ARM64 无 `regs->ip` 等价物,社区做法改为 **fentry 跳板**或直接 KernelPatch inline hook(§2.1)。检测面:root 观察者读 tracefs 可见——对 app 依然隐形。

### 7.3 KPM 最小骨架(理解 KPM 与 .ko 的差别)

```
KPM:KernelPatch Module,由 KP 的 kpatch 工具加载(kpm load),不走内核 module_load,
     因此不依赖 KMI 版本、不落 /proc/modules 常规路径、无 module 签名校验环节。
接口形态(概念):hook 原语 + 符号解析(extra_symbol)+ 事件回调;
wxshadow 的 KPM 化 = 模块 init 时装好 BRK handler/页表工具,prctl 留用户态控制通道。
```

与 insmod .ko 对比:`.ko` 走正式 loader(有 module signature/lockdown 校验,Android GKI 上 vendor_dlkm 域外加载受限);KPM 由 KP 自己的 patch 引擎装——这也是 APatch 能在锁定 boot 链的设备上工作的原因(前提是有解锁 bootloader 或漏洞写入 boot 分区)。

### 7.4 APatch vs KernelSU vs Magisk(root 隐藏面对比)

| | Magisk | KernelSU | APatch(KP) |
|---|---|---|---|
| 原理 | ramdisk 修补 + su 客户端 | 内核态 su(GKI 模块/集成内核) | KernelPatch 内核镜像 patch + SuperKey |
| 检测暴露面 | 常被扫(magisk 属性/文件) | 较少 | 最少 + 可叠 KPM hide 栈 |
| 模块生态 | 最大 | Zygisk 兼容层 | KPM(内核态,本篇主角) |
| 配套 | Zygisk+Shamiko | 内建 | stealth.kpm(hide-maps+kload+wxshadow+dbc-rw) |
定位:APatch/KP 是「内核 hook 栈」的地基;Magisk/KSU 是常规 root;三者互斥安装,选型细节见 04-对抗攻防/root与环境隐藏.md。

## 8. 反向视角:另一个 root 观察者如何发现这些(红队自查)

- **kprobe/ftrace 检测**:`/sys/kernel/debug/kprobes`、tracefs 的 enabled 列表、`/proc/kallsyms` 中 ftrace trampoline 常驻符号;
- **wxshadow 残留面**:影子页是额外物理页 → 内存总量/伙伴系统统计异常;页表项 PFN 与 `page->mapping` 期望不符(需内核侧遍历);dmesg 可能留 pr_info(好的实现静默);per-process 例外:BRK 窗口内单步异常在 perf_event(PERF_COUNT_HW_INSTRUCTIONS 突刺)上可见——**时序侧信道是唯一普适残留检测面**;
- **KPM 检测**:kpm load 后 boot 分区 hash 与运行态不一致(需要再攻一层才能查);sys_call_table/入口指令与 vmlinux 静态比对(root 拿静态镜像 diff 运行内存)是终极自查法;
- 结论:**app 层无解;root-vs-root 才是对抗前沿**。写工具时按此清单收敛痕迹。

## 9. 选用决策

**wxshadow 客户端速查**(README 原文命令):

```
wxshadow_client -p <pid> -a <addr>                 # 设断点(寄存器全捕获)
wxshadow_client -p <pid> -a <addr> -r x0=<val>     # 断点 + 改寄存器
wxshadow_client -p <pid> -a <addr> --patch <hex>   # 影子页改指令
wxshadow_client -p <pid> --release                 # 全部释放
```

部署链(OnePlus Android 16 实测路径,README 原文):push 到 /sdcard → su cp 到 /data/local/tmp(KernelSU 重定向坑)→ `kpatch kpm load wxshadow.kpm`。
**一句话选型**:
- 要 hook 内核函数/syscall 且环境可控:kprobe 起步(兼容性最好)→ fentry(BTF 有时);
- 要对**目标 app 进程**无痕断点/改参:wxshadow(KPM)或 mkpms-stealth;
- 要隐藏网络面:VoidLink 路线(ftrace+eBPF 写 netlink 回包,原理已证);
- 要整套 root+隐藏:APatch(KP)+ KPM 模块栈;
- 只是想理解机制:android-kernel-hacking-toolkit 四模块代码量小,是最好的教材。
