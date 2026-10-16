# Android 内核与 eBPF 攻击面全景

> 定位:frida/RASP 对抗打到天花板后,下一层就是内核。本篇覆盖 GKI/KMI 内核形态、三大经典内核攻击面(Binder/Futex/io_uring)的数据结构与漏洞模式、bpftrace 在 Android 上的实战(含 JNI 边界解析)、BPF 读内核绕 KASLR、内核调试配置。

## 1. GKI 与 KMI:Android 内核的形态

**GKI(Generic Kernel Image,通用内核镜像)**- Google 从 Android 11(内核 5.4)开始推、Android 12+ 强制的内核交付方式:Google 构建统一的 `boot.img` 内核,厂商功能全部走 **GKI 模块**(.ko,放在 vendor_boot/vendor_dlkm)。
- 意义:同一代 Android 所有设备内核代码主体一致 → 一个内核洞 = 全设备通杀;逆向时符号/偏移可跨设备复用。
**KMI(Kernel Module Interface,内核模块接口)**
- GKI 内核导出符号的稳定 ABI(用符号版本 CRC 锁定)。boot.img 内核不变、vendor 模块按 KMI 编译 → **加载任意满足 KMI 的 .ko 成为可能**,这是 KernelPatch 系 KPM、LKM rootkit(android-kernel-hacking-toolkit)能落地的基础。
- 逆向视角:目标机 `cat /proc/kallsyms`(root)或从 boot.img 提取 vmlinux(用 vmlinux-to-elf / KernelPatch 的符号提取)拿符号表。
**root 后能干什么**:`kpatch` 加载 KPM、insmod 自编译 .ko、改 `/proc/sys/kernel/*`、BPF 全家桶(见 §4)。

## 2. Binder:Android 最大内核攻击面

**为什么重要**:每个 app 的每次 IPC(startActivity/ContentProvider/Service/AIDL)都走 `/dev/binder` 的 ioctl 进内核。攻击面 = 内核里解析用户提交的结构体 + 跨进程对象寻址。
**调用链**

```
用户态 ioctl(fd, BINDER_WRITE_READ, &bwr)
  → binder_ioctl()                     // drivers/android/binder.c
    → binder_thread_write()            // 解析 BC_TRANSACTION 等命令
      → binder_transaction()           // 核心:分配 buffer、拷贝数据、fixup 引用
```

源码(android-mainline):
头文件:`include/uapi/linux/android/binder.h`(同仓库)。
**关键数据结构** `struct binder_transaction_data`(uapi,逆向时在 32/64 位与 binder.h 版本间注意布局差异):

```c
union { __u32 handle; binder_uintptr_t ptr; } target; // 目标:handle(代理)或 ptr(本地节点)
binder_uintptr_t cookie;      // 本地对象的私有数据
__u32 code;                   // 方法号(AIDL 里的 transaction code)
__u32 flags;                  // TF_ONE_WAY / TF_ACCEPT_FDS ...
pid_t sender_pid; uid_t sender_euid;   // 内核回填的发送者身份
binder_size_t data_size; binder_size_t offsets_size;  // flat_binder_object 偏移数组
union { struct { binder_uintptr_t buffer; binder_uintptr_t offsets; } ptr;
        __u8 buf[8]; } data;
```

**经典漏洞模式**(都是 binder_transaction 处理用户数据时的解析/fixup 逻辑):
1. `offsets[]` 数组越界/未校验 → OOB 读写(历史:2017 binder 提权系列,CVE-2017-7296 等);
2. `binder_fixup_parent` 修复嵌套 binder_buffer 指针时的边界算错 → 任意写;
3. BINDER_TYPE_FDA(flat_binder_object 文件描述符数组)安放失败路径的 refcount/UAF;
4. 事务 buffer 生命周期(BC_FREE_BUFFER 与异步事务竞争)→ UAF。
5. 厂商私有 binder 设备(/dev/hwbinder、/dev/vndbinder)权限配置错 → 跨域提权(黑盒 SRC 上也常是面)。
**逆向/检测视角**:追一个 app 的 IPC 面,可在内核层 hook `binder_transaction`(见 07-内核级/内核Hook与无痕对抗.md §2 kprobe/BPF fentry),按 `target.handle + code` 过滤,dump `data.ptr.buffer` 里的 parcel——比 Java 层 hook 更难被 RASP 发现。

## 3. Futex 与 PI 链:rtmutex 的老 bug 栈

**接口**:`futex(2)`(man7 手册):
- `FUTEX_LOCK_PI/UNLOCK_PI/TRYLOCK_PI`:PI(优先级继承)锁,内核走 rtmutex;
- `FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI`:让等待者从 futex1 迁移到 futex2 的 PI 锁,迁移由内核的 **PI 链(proxy-lock/代理锁回滚)** 完成——历史 bug 全在这条回滚路径。
**CVE-2026-43499 "GhostLock"**
- rtmutex/futex-PI 的 UAF,位置在 `kernel/locking/rtmutex.c` 的 `remove_waiter`,修复把 proxy-lock 回滚时的判断从 `current` 改为 `waiter::task`;
- CVSS 7.8,标记**在野利用**;NebuSec 把它归入 "IonStack"——一组存在约 15 年的 rtmutex/futex-PI 链式 requeue 利用 bug 栈;Positive Technologies 以 PT-2026-42456 跟踪。
- 利用链形态(社区 writeup):futex requeue 缺陷 → rt_mutex_waiter UAF → 内核堆布局 → 任意内核写 → cred/SELinux 改写(完整原语链见 07-内核级/内核利用与Fuzzing.md §1)。
**用户线索对齐**:「FUTEX_WAIT_REQUEUE_PI/FUTEX_CMP_REQUEUE_PI 竞态,PI 链 UAF,CVE-2026-43499」为 2026 年活跃在野利用洞。Android GKI 内核同源该代码,修复随 GKI 安全更新下发——逆向场景中这代表「目标 ROM 内核版本 < 补丁月即可能可打」。

## 4. io_uring 在 Android 上的真实状态

**结论:代码在、门关着。**- GKI 内核源码树里 `fs/io_uring.c` 存在、`CONFIG_IO_URING=y` 保留;
- 2023 年中起,Google 因 io_uring 安全记录,在 Android 用 **seccomp-bpf 过滤器把 io_uring_* syscall 对 app 域整个封死**(仅个别信任系统进程可用);ChromeOS 与 Google 服务器侧直接禁用。
- 逆向含义:app 进程(甚至 adb shell 域)调 io_uring_setup 直接被 seccomp SIGSYS;要打 io_uring 面(如用户线索的 io_uring_poll 空指针,syzkaller 捕获 [线索·未定位具体 syzbot 报告])需 root 后换 seccomp 域或打系统进程。通用 Linux 服务器上 io_uring 仍是 LPE 富矿,Android 上优先级低。

## 5. bpftrace on Android 实战

**可落地性**- bpftrace 依赖:内核 BPF(kprobe/tracepoint/uprobe)+ 建议 BTF(`CONFIG_DEBUG_INFO_BTF`,GKI 5.15+ 带)。NDK 交叉编译补丁集;
- root(推荐 APatch/KernelPatch 环境,见 07-内核级/内核Hook与无痕对抗.md §3)+ push 静态二进制到 /data/local/tmp 即可跑;
- 也可用 kernelSU 环境 + `BTF=/sys/kernel/btf/vmlinux`。
**场景 A:追踪纯 Native C++ 函数(uprobe)**

```bash
# app 的 so 里函数符号(未 strip 时):
bpftrace -e 'uprobe:/data/app/.../libtarget.so:decryptkey { printf("arg0=%s\n", str(arg0)); }'
# strip 过:用 IDA 里函数偏移,uprobe:libtarget.so:0x1234(ARM64:x0-x7=arg0-arg7,栈上其余)
# 追系统进程/框架:
bpftrace -e 'uprobe:/system/lib64/libart.so:_ZN3art3JNI21GetStringUTFCharsEP7_JNIEnvP8_jstringPh* {...}'
```

ARM64 调用约定:x0-x7 依次传参,返回值 x0;bpftrace 的 `arg0..argN`/`retval` 自动映射。
**场景 B:JNI 边界函数 + 解析 Java 参数**
- 挂 `RegisterNatives`(frida 层经典)在内核层等价于 uprobe `libart.so` 的 `art::JNI::RegisterNatives`(C++ mangled);`JNIEnv*` 就是 x0——**JNIEnv 是 `struct JNINativeInterface* const*`**(指向函数表指针的指针):
 - `*(u64*)x0` = 函数表基址;`((u64*)x0)[index]` = 具体 JNI 函数指针(index 按 JNINativeInterface 声明序,`RegisterNatives` 是表内第 215 项左右,随版本浮动,查 art_jni_impl.h);
- `jobject/jstring`(x1)在 ART 上是 **32 位间接引用句柄(IndirectRef)**,不是裸指针——bpftrace 里不能直接 deref,两条正路:
 1. 不解内容,只 trace `GetStringUTFChars/CallObjectMethodV` 等 JNI 函数表调用(bpftrace kprobe/uprobe 挂 libart 内部符号),看 x1 句柄流向;
 2. 需要字符串内容时,挂 `art::JNI::GetStringUTFChars` 的返回(uprobe + uretprobe),`str(retval)` 直接拿 UTF-8(返回值才是 char*)。
- 这套「JNI 边界解析」思路在 frida 侧等价物是 hook JNIEnv 函数表;内核 uprobe 版本对目标进程零注入、零 maps 残留。
**场景 C:BPF_FUNC_probe_read_kernel 与绕 KASLR(root 机分析内核)**
- CO-RE/bpftrace 里读内核指针必须 `probe_read_kernel`/kptr(@)——`bpf_probe_read#113`(旧)/`bpf_probe_read_kernel#114`(新)helper;用户态地址用 `probe_read_user`。
- **绕 KASLR 的三条路**:
 1. root 下 `/proc/kallsyms` 本来就是真值(kptr_restrict=0 时)——先 `bpftrace -l 'kprobe:*'` 列符号;被 hide 的场景用 2;
 2. 已知任一符号运行时地址(如 kprobe 挂上的点)± 已知偏移(boot.img 里提的静态偏移)→ 反推 slide;
 3. eBPF 从已知全局变量读:如 ARM64 的 `kimage_voffset`(va→pa 换算)、`page_offset_base` 等价物,kprobe 上下文里 `kptr("...")` 取。
- 例子:root 机 dump 目标内核关键结构

```bash
bpftrace -e 'kprobe:binder_transaction { $t=(struct binder_transaction*)arg2;
  printf("target_handle? code=%d\n", $t->code); }'   # 需 BTF;无 BTF 用手算偏移+probe_read_kernel
```

**内核层 trace 与 frida 的分工**:Java 参数内容 → frida(方便);so 内算法/时机 → uprobe;跨进程/binder/系统调用 → kprobe/tracepoint;要无痕 → 见下一篇。

## 6. 内核调试配置(自建靶机)

**AOSP 自编译(userdebug/eng)才有的面**:
- `bootconfig`/cmdline:`nokaslr`(关 KASLR,配合 GDB 调试必开)、`kgdboc=ttyMS0,115200`(串口)或 `kgdboc=kbd`(USB/虚拟);
- KGDB/KDB 文档见 kernel.org 文档树(docs. 路径近期调整,用站内搜索进入);
- KASAN+KCOV 调试内核:`CONFIG_KASAN=y CONFIG_KCOV=y CONFIG_DEBUG_INFO=y`,配合 syzkaller(07-内核级/内核利用与Fuzzing.md §3);
- GDB 远程:`gdb vmlinux` → `target remote /dev/ttyUSB0`(或 USB gdbserver 模式);断 `binder_transaction` 单步跟 fixup,是理解 §2 漏洞模式最快的路;
- 选购/准备:Google Pixel(AOSP 官方支持树内)+ android-mainline GKI,或 Cuttlefish 虚拟设备(内核参数随便改,跑 KASAN 不心疼)。
**生产机只读分析**:boot.img 拉下来(magiskboot unpack)→ vmlinux-to-elf 或 KernelPatch 符号提取 → IDA/Ghidra 静态比对 KMI 版本与补丁月(判断 §3/§4 洞是否在)。

## 7. 速查表

| 攻击面 | 入口 | 关键结构/命令 | 2026 状态 |
|---|---|---|---|
| Binder | /dev/binder ioctl | binder_transaction_data、offsets[]、BC_TRANSACTION | 常青;RASP 盲区 IPC 追踪首选 |
| Futex PI | futex(2) | FUTEX_WAIT_REQUEUE_PI、rt_mutex_waiter | CVE-2026-43499 GhostLock 在野 |
| io_uring | io_uring_setup/enter | io_uring_sqe/cqe | Android app 域被 seccomp 封;服务器富矿 |
| eBPF | bpf(2) | BPF_PROG_LOAD、probe_read_kernel | root 后全量可用;bpftrace NDK 补丁集 |
| GKI/KMI | boot.img + vendor .ko | KMI CRC | LKM/KPM 加载基础 |

## 8. 附录 A:从 boot.img 到符号表(生产机静态分析实操)

```bash
# 1. 拉 boot 分区(root)
adb shell su -c "dd if=/dev/block/by-name/boot$(adb shell getprop ro.boot.slot_suffix) of=/sdcard/boot.img"
# 2. 解包
magiskboot unpack boot.img          # 得到 kernel(可能 gz/lz4 压缩)
magiskboot decompress kernel kernel.raw   # 按打印的压缩格式
# 3. 提符号(三选一)
vmlinux-to-elf kernel.raw vmlinux  # 社区标准工具
# KernelPatch 工具链(自带符号提取,arm64 最准):
#   https://github.com/bmax121/KernelPatch  tools/ 下 extra_symbol
# 4. 进 IDA/Ghidra:找补丁月比对(GKI 安全公告 vs 目标 build 日期)
```

判定口径:目标安全补丁级别(SPL,`getprop ro.build.version.security_patch`)< 漏洞修复进入 android-common 的月份 → 该洞大概率在。

## 9. 附录 B:BPF 在 Android 的程序类型与权限速查

| 程序类型 | 用途 | Android 注意 |
|---|---|---|
| kprobe/kretprobe | 函数进出参/返回 | root 即可用,无需 BTF |
| tracepoint | 稳定内核事件(sched_switch 等) | GKI tracepoint 齐全 |
| fentry/fexit | 无陷阱进出 hook | 需 BTF(GKI 5.15+ 带) |
| uprobe/uretprobe | 用户态 so 函数 | 目标进程无需被修改,零注入 |
| perf_event | 周期采样/软中断 | 侧信道观察(检测 RASP 自检频率) |
| bpf_lsm | 安全决策点 | 需 CONFIG_BPF_LSM |
| socket filter/cgroup | 网络面 | VoidLink 路线用(见 07/内核Hook与无痕对抗.md §3) |
权限面:`bpf(2)` 受 SELinux 管(Android 12+ 有专门 bpf 域);root(APatch/KP/su -c)下全通。`/sys/kernel/debug/tracing`(tracefs)与 `/sys/kernel/btf/vmlinux` 是 root 后第一眼要看的两个文件。

## 10. 附录 C:bpftrace 实战脚本三例

**C1. 内核侧 dump binder parcel(RASP 盲区 IPC 追踪)**

```bash
bpftrace -e '
#include <linux/android/binder.h>
kprobe:binder_transaction
/comm == "target_app"/
{ $d = (struct binder_transaction_data*)arg3;   // 布局随内核版本,先在 IDA 对 binder.h
  printf("code=%d data_size=%d\n", $d->code, $d->data_size);
  printf("first16: %r\n", buf($d->data.ptr.buffer, 16)); }'
```

(bpftrace 头包含 BTF 场景;无 BTF 时手算偏移 + probe_read_kernel。arg 序号以实际寄存器映射为准,x0=proc,x1=thread,x2=dest_node…,在源码对一遍。)
**C2. so 加密函数入参自吐(替代 frida Interceptor)**

```bash
bpftrace -e 'uprobe:/data/local/tmp/target/libcrypt.so:0x27A4C
{ printf("key=%r in=%r\n", buf(arg1,32), buf(arg2,64)); }'
# IDA 定位:§4 特征表(AES S-box `63 7C 77 7B` 常量交叉引用)
```

**C3. root 机绕 KASLR 读内核指针(probe_read_kernel 家族)**

```bash
bpftrace -e 'kprobe:do_sys_openat2 { printf("path=%s\n", str(arg1)); }'
# 深读内核结构:一律 kptr/(@[kaddr]) 语法触发 probe_read_kernel;
# slide 反推:已知 kprobe 命中符号运行时地址 - boot.img 静态地址 = slide,后续符号全部 +slide
```

## 11. 附录 D:futex PI 链机制细节(读懂 GhostLock 需要)

- PI futex 在内核侧对应 `struct rt_mutex`(rtmutex.c);等待者排队用 plist(优先级有序链表);
- `FUTEX_CMP_REQUEUE_PI`:唤醒者把 futex1 上的 waiter **直接搬到** futex2 的 rtmutex 等待链,事务中途失败要走 **proxy-lock 回滚**——把 waiter 从链上摘除并恢复状态;
- 历代洞的形态:回滚时用了错误的任务指针(`current` vs `waiter::task`)、requeue 与 lock/timeout 并发 → waiter 已被释放仍在链上 → UAF;
- CVE-2026-43499 修复要点即 `remove_waiter` 改用 `waiter::task`(AlmaLinux/CIQ 公告,详见 §3);
- rtmutex 设计文档:内核文档树 `Documentation/locking/rt-mutex-design.html`(docs. 路径近期迁移,用站内搜索进入);
- 复现/研究价值:该代码 15 年未大动(NebuSec "IonStack" 论断),老洞栈持续产新 CVE——逆向时遇到锁重度使用的系统进程,值得单独评估。

## 12. 附录 E:版本对照与调试参数速查

**Android × 内核 × 能力对照**(估算用,以目标 build 为准):

| Android | 常见 GKI 内核 | BTF | fentry | 备注 |
|---|---|---|---|---|
| 12 | 5.10 | 部分 | 需查 | GKI 1.0 |
| 13 | 5.10/5.15 | 是 | 可用 | GKI 2.0 起点 |
| 14 | 5.15/6.1 | 是 | 可用 | |
| 15 | 6.1/6.6 | 是 | 可用 | |
| 16(Baklava+) | 6.6/6.12 | 是 | 可用 | wxshadow 验证机即 6.12.23 |
**内核调试常用参数(cmdline/bootconfig,自编内核用)**:

```
nokaslr                    # 关地址随机化,GDB 断点地址才稳
kgdboc=ttyMS0,115200       # KGDB over 串口(真机)
kgdbwait                   # 启动时等待 GDB 连接
earlycon=uart8250,mmio32,0x...   # 早期串口
initcall_debug ignore_loglevel   # 日志全开
audit=0                    # 关 audit 少噪声
```

**GDB 远程三步**:

```
(gdb) set architecture aarch64
(gdb) file vmlinux
(gdb) target remote /dev/ttyUSB0     # 或 hvc/kgdb nmi 途径
(gdb) b binder_transaction           # 符号来自附录 A 提取
```

**SELinux 内核侧速记**(root 后收口用):enforcing 开关在 `selinux_state`(新)或 `selinux_enforcing`(老)全局;avc 决策缓存 avc_cache 可被"污染"绕过(进阶);用户态等价 `setenforce 0`。
