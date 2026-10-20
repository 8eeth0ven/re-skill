# Android Kernel and eBPF Attack Surface Panorama

> Positioning: once frida/RASP confrontation hits the ceiling, the next layer down is the kernel. This piece covers GKI/KMI kernel shapes, the data structures and vulnerability patterns of the three classic kernel attack surfaces (Binder/Futex/io_uring), bpftrace in real Android practice (including JNI boundary parsing), BPF kernel reads to bypass KASLR, and kernel debugging configuration.

## 1. GKI and KMI: the shape of the Android kernel

**GKI (Generic Kernel Image)** - the kernel delivery model Google started pushing with Android 11 (kernel 5.4) and enforcing from Android 12+: Google builds a unified `boot.img` kernel, and all vendor functionality ships as **GKI modules** (.ko, placed in vendor_boot/vendor_dlkm).
- Why it matters: the kernel code base is essentially identical across all devices of the same Android generation -> one kernel bug = hits every device; when reversing, symbols/offsets can be reused across devices.
**KMI (Kernel Module Interface)**
- A stable ABI of the GKI kernel's exported symbols (locked with symbol-version CRCs). The boot.img kernel stays unchanged while vendor modules are compiled against the KMI -> **loading any .ko that satisfies the KMI becomes possible**, which is the foundation the KernelPatch family's KPMs and LKM rootkits (android-kernel-hacking-toolkit) are built on.
- Reversing view: on the target device run `cat /proc/kallsyms` (root), or extract vmlinux from boot.img (symbol extraction via vmlinux-to-elf / KernelPatch) to get the symbol table.
**What root buys you**: `kpatch` loading KPMs, insmod of a self-compiled .ko, tweaking `/proc/sys/kernel/*`, and the whole BPF toolkit (see sec.4).

## 2. Binder: Android's largest kernel attack surface

**Why it matters**: every IPC of every app (startActivity/ContentProvider/Service/AIDL) goes through `/dev/binder` ioctls into the kernel. The attack surface = kernel-side parsing of user-submitted structs + cross-process object addressing.
**Call chain**

```
用户态 ioctl(fd, BINDER_WRITE_READ, &bwr)
  → binder_ioctl()                     // drivers/android/binder.c
    → binder_thread_write()            // 解析 BC_TRANSACTION 等命令
      → binder_transaction()           // 核心:分配 buffer、拷贝数据、fixup 引用
```

Source (android-mainline):
Header: `include/uapi/linux/android/binder.h` (same repo).
**Key data structure** `struct binder_transaction_data` (uapi; when reversing, watch layout differences between 32/64-bit and binder.h versions):

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

**Classic vulnerability patterns** (all in binder_transaction's parsing/fixup logic for user data):
1. `offsets[]` array out-of-bounds/unvalidated -> OOB read/write (history: the 2017 binder privilege-escalation series, CVE-2017-7296 etc.);
2. `binder_fixup_parent` miscalculates bounds while fixing up nested binder_buffer pointers -> arbitrary write;
3. BINDER_TYPE_FDA (flat_binder_object fd array) refcount/UAF on the installation-failure path;
4. Transaction buffer lifetime (BC_FREE_BUFFER racing async transactions) -> UAF.
5. Vendor-private binder devices (/dev/hwbinder, /dev/vndbinder) with wrong permission config -> cross-domain privilege escalation (also a common surface in black-box SRC work).
**Reversing/detection view**: to track an app's IPC surface, hook `binder_transaction` at the kernel layer (see 07-kernel/kernel-hook-stealth.md sec.2 kprobe/BPF fentry), filter on `target.handle + code`, and dump the parcel inside `data.ptr.buffer` - harder for RASP to spot than Java-layer hooks.

## 3. Futex and the PI chain: the rtmutex legacy bug stack

**Interface**: `futex(2)` (man7 manual):
- `FUTEX_LOCK_PI/UNLOCK_PI/TRYLOCK_PI`: PI (priority inheritance) locks, handled by the kernel's rtmutex;
- `FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI`: PI locks that migrate waiters from futex1 to futex2; the migration is done by the kernel's **PI chain (proxy-lock rollback)** - the historical bugs all live on this rollback path.
**CVE-2026-43499 "GhostLock"**
- A rtmutex/futex-PI UAF located in `remove_waiter` in `kernel/locking/rtmutex.c`; the fix changed the proxy-lock rollback check from `current` to `waiter::task`;
- CVSS 7.8, flagged **exploited in the wild**; NebuSec groups it under "IonStack" - a bug stack of chained rtmutex/futex-PI requeue exploits that has existed for roughly 15 years; Positive Technologies tracks it as PT-2026-42456.
- Exploit chain shape (community writeups): futex requeue flaw -> rt_mutex_waiter UAF -> kernel heap grooming -> arbitrary kernel write -> cred/SELinux rewrite (full primitive chain in 07-kernel/kernel-exploit-fuzzing.md sec.1).
**User-lead alignment**: "FUTEX_WAIT_REQUEUE_PI/FUTEX_CMP_REQUEUE_PI race, PI-chain UAF, CVE-2026-43499" is an actively exploited in-the-wild bug of 2026. Android GKI kernels share this code, and fixes roll out with GKI security updates - in reversing terms this means "if the target ROM's kernel predates the patch month, it may be exploitable".

## 4. io_uring's real status on Android

**Verdict: the code is there, but the door is shut.** - the GKI kernel source tree still has `fs/io_uring.c` with `CONFIG_IO_URING=y`;
- Since mid-2023, citing io_uring's security track record, Google **blocks all io_uring_* syscalls for the app domain on Android with a seccomp-bpf filter** (only a few trusted system processes may use them); ChromeOS and Google's server side disable it outright.
- Reversing implication: an app process (even the adb shell domain) calling io_uring_setup gets killed by seccomp SIGSYS immediately; to hit the io_uring surface (e.g. the user-lead io_uring_poll null dereference captured by syzkaller [lead : specific syzbot report not located]) you need root to switch seccomp domain or to attack a system process. On generic Linux servers io_uring remains an LPE goldmine; on Android it is low priority.

## 5. bpftrace on Android in practice

**Feasibility** - bpftrace needs: kernel BPF (kprobe/tracepoint/uprobe) + BTF recommended (`CONFIG_DEBUG_INFO_BTF`, present in GKI 5.15+). NDK cross-compile patch set;
- root (APatch/KernelPatch environment recommended, see 07-kernel/kernel-hook-stealth.md sec.3) + push a static binary to /data/local/tmp and it runs;
- A KernelSU environment also works + `BTF=/sys/kernel/btf/vmlinux`.
**Scenario A: tracing pure native C++ functions (uprobe)**

```bash
# app 的 so 里函数符号(未 strip 时):
bpftrace -e 'uprobe:/data/app/.../libtarget.so:decryptkey { printf("arg0=%s\n", str(arg0)); }'
# strip 过:用 IDA 里函数偏移,uprobe:libtarget.so:0x1234(ARM64:x0-x7=arg0-arg7,栈上其余)
# 追系统进程/框架:
bpftrace -e 'uprobe:/system/lib64/libart.so:_ZN3art3JNI21GetStringUTFCharsEP7_JNIEnvP8_jstringPh* {...}'
```

ARM64 calling convention: x0-x7 pass arguments in order, return value in x0; bpftrace's `arg0..argN`/`retval` map automatically.
**Scenario B: JNI boundary functions + parsing Java arguments**
- Hooking `RegisterNatives` (a frida classic) is equivalent at the kernel layer to a uprobe on `art::JNI::RegisterNatives` (C++ mangled) in `libart.so`; the `JNIEnv*` is x0 - **JNIEnv is a `struct JNINativeInterface* const*`** (a pointer to a pointer to the function table):
 - `*(u64*)x0` = function-table base; `((u64*)x0)[index]` = a specific JNI function pointer (index follows the JNINativeInterface declaration order; `RegisterNatives` is around entry 215, drifting between versions - check art_jni_impl.h);
- A `jobject/jstring` (x1) on ART is a **32-bit indirect reference handle (IndirectRef)**, not a raw pointer - you cannot deref it directly in bpftrace; two proper routes:
 1. Don't unpack the contents; just trace calls through the JNI function table (`GetStringUTFChars/CallObjectMethodV` etc., bpftrace kprobe/uprobe on internal libart symbols) and watch where the x1 handle flows;
 2. When you need the string contents, hook the return of `art::JNI::GetStringUTFChars` (uprobe + uretprobe); `str(retval)` gives you the UTF-8 directly (the return value is the char*).
- The frida-side equivalent of this "JNI boundary parsing" approach is hooking the JNIEnv function table; the kernel uprobe version does zero injection into the target process and leaves zero maps residue.
**Scenario C: BPF_FUNC_probe_read_kernel and KASLR bypass (analyzing the kernel on a rooted device)**
- In CO-RE/bpftrace, kernel pointers must be read via `probe_read_kernel`/kptr(@) - the helpers `bpf_probe_read#113` (old) / `bpf_probe_read_kernel#114` (new); user-space addresses use `probe_read_user`.
- **Three routes to defeat KASLR**:
 1. With root, `/proc/kallsyms` already holds the truth (when kptr_restrict=0) - first `bpftrace -l 'kprobe:*'` to list symbols; if it is hidden, use route 2;
 2. Knowing the runtime address of any single symbol (e.g. a kprobe attach point) +/- a known offset (the static offset extracted from boot.img) -> derive the slide;
 3. eBPF reads from known globals: e.g. ARM64's `kimage_voffset` (va->pa conversion), `page_offset_base` equivalents, fetched with `kptr("...")` in a kprobe context.
- Example: dump key kernel structures on a rooted device

```bash
bpftrace -e 'kprobe:binder_transaction { $t=(struct binder_transaction*)arg2;
  printf("target_handle? code=%d\n", $t->code); }'   # 需 BTF;无 BTF 用手算偏移+probe_read_kernel
```

**Division of labor between kernel-layer trace and frida**: Java argument contents -> frida (convenient); algorithms/timing inside a so -> uprobe; cross-process/binder/syscalls -> kprobe/tracepoint; for stealth -> see the next piece.

## 6. Kernel debugging configuration (self-built target device)

**Surfaces only a self-compiled AOSP (userdebug/eng) build has**:
- `bootconfig`/cmdline: `nokaslr` (disables KASLR, a must with GDB debugging), `kgdboc=ttyMS0,115200` (serial) or `kgdboc=kbd` (USB/virtual);
- KGDB/KDB docs live in the kernel.org doc tree (the docs. path changed recently; use site search to get in);
- KASAN+KCOV debug kernel: `CONFIG_KASAN=y CONFIG_KCOV=y CONFIG_DEBUG_INFO=y`, paired with syzkaller (07-kernel/kernel-exploit-fuzzing.md sec.3);
- GDB remote: `gdb vmlinux` -> `target remote /dev/ttyUSB0` (or USB gdbserver mode); breaking on `binder_transaction` and single-stepping through the fixup is the fastest way to understand the sec.2 vulnerability patterns;
- Shopping/prep: a Google Pixel (inside the AOSP official support tree) + android-mainline GKI, or a Cuttlefish virtual device (kernel parameters change freely, running KASAN costs nothing).
**Read-only analysis on production devices**: pull boot.img (magiskboot unpack) -> vmlinux-to-elf or KernelPatch symbol extraction -> IDA/Ghidra static comparison of KMI version vs patch month (to judge whether the sec.3/sec.4 bugs are present).

## 7. Quick reference table

| Attack surface | Entry | Key structures/commands | 2026 status |
|---|---|---|---|
| Binder | /dev/binder ioctl | binder_transaction_data, offsets[], BC_TRANSACTION | Evergreen; first choice for RASP-blind IPC tracing |
| Futex PI | futex(2) | FUTEX_WAIT_REQUEUE_PI, rt_mutex_waiter | CVE-2026-43499 GhostLock in the wild |
| io_uring | io_uring_setup/enter | io_uring_sqe/cqe | Sealed off by seccomp for the Android app domain; goldmine on servers |
| eBPF | bpf(2) | BPF_PROG_LOAD, probe_read_kernel | Fully available after root; bpftrace NDK patch set |
| GKI/KMI | boot.img + vendor .ko | KMI CRC | Foundation for LKM/KPM loading |

## 8. Appendix A: from boot.img to a symbol table (production-device static analysis walkthrough)

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

Verdict rule: if the target's security patch level (SPL, `getprop ro.build.version.security_patch`) is older than the month the fix landed in android-common -> the bug is most likely present.

## 9. Appendix B: BPF program types and permissions on Android

| Program type | Use | Android notes |
|---|---|---|
| kprobe/kretprobe | Function entry/exit args/return | Works with root alone, no BTF needed |
| tracepoint | Stable kernel events (sched_switch etc.) | GKI tracepoints are complete |
| fentry/fexit | Trap-free entry/exit hooking | Requires BTF (GKI 5.15+ ships it) |
| uprobe/uretprobe | User-space so functions | Target process untouched, zero injection |
| perf_event | Periodic sampling/soft interrupts | Side-channel observation (detect RASP self-check frequency) |
| bpf_lsm | Security decision points | Requires CONFIG_BPF_LSM |
| socket filter/cgroup | Network side | Used by the VoidLink route (see kernel-hook-stealth.md sec.3) |
Permission surface: `bpf(2)` is governed by SELinux (Android 12+ has a dedicated bpf domain); under root (APatch/KP/su -c) everything passes. `/sys/kernel/debug/tracing` (tracefs) and `/sys/kernel/btf/vmlinux` are the first two things to look at once you have root.

## 10. Appendix C: three practical bpftrace scripts

**C1. Kernel-side binder parcel dump (RASP-blind IPC tracing)**

```bash
bpftrace -e '
#include <linux/android/binder.h>
kprobe:binder_transaction
/comm == "target_app"/
{ $d = (struct binder_transaction_data*)arg3;   // 布局随内核版本,先在 IDA 对 binder.h
  printf("code=%d data_size=%d\n", $d->code, $d->data_size);
  printf("first16: %r\n", buf($d->data.ptr.buffer, 16)); }'
```

(bpftrace header inclusion is for the BTF case; without BTF, compute offsets by hand + probe_read_kernel. The arg index follows the actual register mapping - x0=proc, x1=thread, x2=dest_node... - verify against the source.)
**C2. Self-revealing inputs of a so's encryption function (an frida Interceptor replacement)**

```bash
bpftrace -e 'uprobe:/data/local/tmp/target/libcrypt.so:0x27A4C
{ printf("key=%r in=%r\n", buf(arg1,32), buf(arg2,64)); }'
# IDA 定位:§4 特征表(AES S-box `63 7C 77 7B` 常量交叉引用)
```

**C3. Reading kernel pointers with KASLR bypass on a rooted device (probe_read_kernel family)**

```bash
bpftrace -e 'kprobe:do_sys_openat2 { printf("path=%s\n", str(arg1)); }'
# 深读内核结构:一律 kptr/(@[kaddr]) 语法触发 probe_read_kernel;
# slide 反推:已知 kprobe 命中符号运行时地址 - boot.img 静态地址 = slide,后续符号全部 +slide
```

## 11. Appendix D: futex PI chain mechanism details (what you need to understand GhostLock)

- A PI futex corresponds to `struct rt_mutex` on the kernel side (rtmutex.c); waiters queue on a plist (a priority-ordered list);
- `FUTEX_CMP_REQUEUE_PI`: the waker moves waiters on futex1 **directly onto** futex2's rtmutex wait chain; a mid-transaction failure must run the **proxy-lock rollback** - dequeue the waiter and restore its state;
- The shape of the historical bugs: the rollback used the wrong task pointer (`current` vs `waiter::task`), or requeue raced lock/timeout -> the waiter was already freed but still on the chain -> UAF;
- The CVE-2026-43499 fix is exactly `remove_waiter` switching to `waiter::task` (AlmaLinux/CIQ advisories, see sec.3);
- rtmutex design doc: kernel doc tree `Documentation/locking/rt-mutex-design.html` (the docs. path migrated recently; use site search to get in);
- Reproduction/research value: this code has not changed much in 15 years (NebuSec's "IonStack" thesis), and the old bug stack keeps producing new CVEs - when reversing system processes that make heavy use of locks, it deserves separate assessment.

## 12. Appendix E: version matrix and debug parameter quick reference

**Android x kernel x capability matrix** (for estimation; the target build is authoritative):

| Android | Typical GKI kernel | BTF | fentry | Notes |
|---|---|---|---|---|
| 12 | 5.10 | Partial | Check needed | GKI 1.0 |
| 13 | 5.10/5.15 | Yes | Available | GKI 2.0 starting point |
| 14 | 5.15/6.1 | Yes | Available | |
| 15 | 6.1/6.6 | Yes | Available | |
| 16 (Baklava+) | 6.6/6.12 | Yes | Available | wxshadow verification device is 6.12.23 |
**Common kernel debug parameters (cmdline/bootconfig, for self-built kernels)**:

```
nokaslr                    # 关地址随机化,GDB 断点地址才稳
kgdboc=ttyMS0,115200       # KGDB over 串口(真机)
kgdbwait                   # 启动时等待 GDB 连接
earlycon=uart8250,mmio32,0x...   # 早期串口
initcall_debug ignore_loglevel   # 日志全开
audit=0                    # 关 audit 少噪声
```

**GDB remote in three steps**:

```
(gdb) set architecture aarch64
(gdb) file vmlinux
(gdb) target remote /dev/ttyUSB0     # 或 hvc/kgdb nmi 途径
(gdb) b binder_transaction           # 符号来自附录 A 提取
```

**SELinux kernel-side notes** (for post-root containment): the enforcing toggle is the `selinux_state` (new) or `selinux_enforcing` (old) global; the avc decision cache avc_cache can be "poisoned" to bypass (advanced); the user-space equivalent is `setenforce 0`.
