# Process Timeline and Memory Chains (zygote fork -> linker -> init_array -> JNI_OnLoad -> the full memory/fault chains)

> Positioning: expands the complete timeline of "an app from birth to its first line of native code", together with the user-space allocation chain and the page-fault chain, down to the kernel side.
> Uses: (1) deciding "which layer, which beat, the thing I want to intercept actually happens on"; (2) the essential analysis of detection/injection races; (3) back-deriving attack surfaces from observation points.
> Baseline: kernel/fork.c v5.4 / v5.10, the LLVM Scudo official docs, bionic fork/pthread/scudo, the linker (dlfcn/linker.cpp) source structure. Uncertain items marked `[unverified]`.
> All syscall numbers are arm64: x8=call number, x0-x5=args. Register conventions in [hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md) sec.3.1.

## 0. The global picture: how the five chains string together

```
链1 进程诞生            链2 so加载                 链4 内存分配
AMS → zygote fork  →   System.loadLibrary     ←   malloc/new
  (kernel_clone)         → dlopen → mmap         → scudo → mmap(链5补页)
       │                     │ relocate            │
       ▼                     ▼ init_array          ▼
Application.onCreate     JNI_OnLoad ←──────── 缺页第一次访问(链5)
  │ Thread.start(链3)       │
  ▼                         ▼
Activity.onCreate      RegisterNatives / 自解密 / 自检
```

One-sentence version: fork builds the shell (the address space inherits zygote via COW), dlopen lays the road (segment mapping + relocation), init_array/JNI_OnLoad starts the race (the packer's self-checks and decryption usually live here), malloc/faults feed the runtime (all dynamic behavior ultimately lands on the two kernel entrances vm_mmap_pgoff / do_page_fault).

## Chain 1: the full timeline of app process birth (AMS -> zygote fork -> Application -> JNI_OnLoad -> Activity)

### 1.1 Timeline diagram (indentation = call depth)

```
system_server(AMS)
└─ ActivityManagerService.startProcessLocked
   └─ Process.start() → ZygoteProcess.start
      └─ 写 /dev/socket/zygote(本地 socket,非 binder;binder 面见 07 区 eBPF 篇)
         请求体:uid/gid/gids、seinfo、niceName、ABI、rlimit、seccomp policy、mountMode…
zygote(64 位主 zygote;32 位 app 走 secondary zygote)
└─ ZygoteServer.runSelectLoop(epoll 等 socket)
   └─ ZygoteConnection.runOnce
      ├─ 读参数列表、校验 uid
      └─ forkAndSpecialize
         └─ nativeForkAndSpecialize(com_android_internal_os_Zygote.cpp)
            └─ bionic fork()(libc/bionic/fork.cpp:先跑 pthread_atfork prepare 链)
               └─ svc __NR_clone(220),flags 仅 SIGCHLD   ←★ 不是 CLONE_VM!
                  └─ sys_clone → kernel_clone(kernel/fork.c v5.10:2415 行,实测核对)
                     ├─ copy_process(2456 行)
                     │  ├─ dup_task_struct(slab 分配 task_struct,复制父进程字段)
                     │  ├─ copy_creds:fork 无 CLONE_THREAD → 新 cred(此刻仍同 zygote)
                     │  ├─ copy_files:无 CLONE_FILES → 复制 fd 表
                     │  ├─ copy_mm(1379 行):无 CLONE_VM → dup_mm → dup_mmap
                     │  │  └─ copy_page_range(593 行):逐 VMA 复制 PTE,可写页只读化 = COW
                     │  │     (zygote 预加载的类/资源页从此父子共享,app 启动快的根因)
                     │  ├─ copy_thread:设子进程返回上下文(子进程 fork 返回 0)
                     │  ├─ sched_fork:初始化调度实体(CFS/EEVDF)
                     │  └─ 分配 pid/tid
                     ├─ trace_sched_process_fork(2466 行)   ←★ eBPF tracepoint 挂点
                     └─ wake_up_new_task(2480 行)→ 入运行队列
   ───────────── 内核返回,父子分道 ─────────────
子进程(仍带 zygote 全部权限)
└─ ZygoteConnection.handleChildProc / specializeAppProcess
   ├─ SpecializeCommon(native):
   │  ├─ setgroups / setresgid / setresuid(降权到目标 uid)
   │  ├─ setrlimit(ASLR 位域、内存上限)
   │  ├─ capset 丢弃多余 capabilities
   │  ├─ 安装 seccomp filter(按 seccomp policy;io_uring 即在此被 app 域封)
   │  ├─ prctl(PR_SET_PDEATHSIG, SIGKILL)(zygote 死则子进程陪葬)
   │  ├─ SELinux setcon(切到 untrusted_app 域;具体调用序随版本,待验证)
   │  └─ 按 mountMode:unshare(CLONE_NEWNS)+ 存储 remount(细节待验证)
   ├─ ZygoteInit.childZygoteInit / RuntimeInit.commonInit
   └─ findStaticMain(ActivityThread.main)→ MethodAndArgsCaller.run()
      └─ ActivityThread.main
         ├─ Looper.prepareMainLooper
         └─ attach → binder 调 AMS.attachApplication(IActivityManager)
            (AMS 侧 attachApplicationLocked → 把 bindApplication/activity 队列推回来)
app 主线程(handleBindApplication)
└─ ActivityThread.handleBindApplication
   ├─ LoadedApk / ContextImpl 构建
   ├─ createAppClassLoader → PathClassLoader(BaseDexClassLoader)  ← so 的可见域由它定
   ├─ makeApplication → new Application → app.attach(context)
   │  └─ Application.attachBaseContext   ←★ 检测 SDK 最早 init 点(比 onCreate 早)
   ├─ installContentProviders → ContentProvider.onCreate  ←★ 同样早于 Application.onCreate
   │    (不少安全 SDK 在 provider 里起检测线程,别只盯 Application)
   └─ Instrumentation.callApplicationOnCreate
      └─ Application.onCreate
         └─ static { System.loadLibrary("xxx") } 或 onCreate 里首次 loadLibrary
            └─ → 链2:dlopen → init_array → JNI_OnLoad(见 §2)
AMS 侧 scheduleTransaction → app 主线程
└─ Activity.onCreate(在 Application.onCreate 之后;JNI_OnLoad 通常更早)
```

### 1.2 Key ruling: is the zygote fork a "special fork"?

- **It is an ordinary fork**: the flags carry only SIGCHLD, no CLONE_VM/CLONE_FILES. The so-called "sharing" is **PTE-level COW** via copy_mm->dup_mm->copy_page_range, not thread-style mm sharing. Verified line-by-line at v5.10 fork.c 1379-1413: the shared branch is taken only when `clone_flags & CLONE_VM` is true - zygote doesn't take it.
- What is "special" all happens in the **post-fork specialization** (privilege drop/seccomp/SELinux/mounts), not in the clone flags.
- The USAP pool (Android 10+): zygote pre-forks a batch of "unspecialized" suspended processes; when AMS wants a process it grabs one and specializes it, saving fork cost; whether it is on by default varies by build/version, **`[unverified]`**. When observing app births, note the pid may predate the AMS request moment.
- OpenHarmony's appspawn is a separate implementation (independent, same fork+specialize model) - don't confuse it with Android's zygote; this document covers Android only.

### 1.3 The injection/detection race timeline (who beats whom)

| Injection means | Relative timing of the injection point | Earliest event visible |
|---|---|---|
| Zygisk (Magisk/ZN) | so injected into **zygote itself**; children inherit it naturally at fork | everything before the start of specialization (theoretically the earliest) |
| frida spawn (-f) | the process is forked by zygote and gated-suspended **before any app code runs**, the agent ptrace-injected, then resumed (frida 17.6 behavior: spawn gating withholds the ACK until the script is ready) | Application.attachBaseContext and the system phases before it |
| Gadget (repackaged) | the app's own loadLibrary load point (placement can precede the target so's init_array) | before the target so's init_array (dependencies ordered correctly) |
| frida attach | after onCreate, usually during business runtime | only calls after the attach moment |
**Corollary**: attach mode cannot catch early detection (init_array/JNI_OnLoad/attachBaseContext have already run); that is the timing essence of "attach misses early detection" - not a matter of hook-writing style. Conversely, the earlier the packer places its detection (attachBaseContext/provider/init_array), the better its attach immunity; spawn immunity instead depends on ptrace self-checks/status scans inside init_array.

### 1.4 Version differences (chain 1)

- Kernel entry names: **GKI 5.4 (Android 11) = `_do_fork` (5.4 already dropped the old do_fork wrapper); 5.10+ (Android 12 onward, 5.10/5.15/6.1/6.6) = `kernel_clone`**. kprobe hook names must match the GKI version (both v5.4/v5.10 raw sources verified). The sys_clone/sys_clone3 syscall numbers don't change (clone=220, clone3=435).
- 32-bit apps: the primary zygote (64-bit) spawns the secondary zygote (32-bit), which in turn forks 32-bit apps (two-level fork).
- Android 10+: the USAP pool (see above, default status).

### 1.5 Observation points (chain 1)

| Observation point | Layer | What to watch | Means |
|---|---|---|---|
| sys_clone (kprobe) | L5 | the zygote-side fork storm, the moment a child is born | bpftrace `kprobe:kernel_clone` (5.10+)/`_do_fork` (5.4) |
| sched_process_fork (tracepoint) | L5 | every process/thread birth (the steadiest, symbol-agnostic) | eBPF tracepoint; area 07's eBPF piece has the hands-on |
| zygote socket | L3 | the process parameters AMS sends down (niceName/uid) | strace/frida attach zygote reading sendmsg (root needed) |
| AMS binder (attachApplication) | L5 | the app<->system_server rendezvous | see the binder chapter of [android-kernel-ebpf.md](../07-kernel/android-kernel-ebpf.md) |
| Application.attachBaseContext | L1 | the detection SDK's init starting point | frida Java hook (invisible to attach mode, visible to spawn) |

## Chain 2: the linker's full so-loading timeline (System.loadLibrary -> dlopen -> init_array -> JNI_OnLoad)

### 2.1 Timeline diagram

```
Java 层
└─ System.loadLibrary("native-lib")
   └─ Runtime.loadLibrary0 → ClassLoader.findLibrary(so 名→全路径)
      └─ Runtime.nativeLoad → libart JavaVMExt::LoadNativeLibrary
         └─ android_dlopen_ext(path, RTLD_NOW, &extinfo)(libdl.so 只是转发壳)
libdl → linker64(bionic linker,自实现,非 glibc ld.so)
└─ __loader_android_dlopen_ext → do_dlopen
   ├─ 解析 caller 的 linker namespace(classloader 命名空间,Android 7+ 隔离)
   └─ find_library_internal
      ├─ 已在 solist(全局 so 链表)→ 命中缓存直接返回 handle
      └─ load_library
         ├─ openat(svc 56)打开 so 文件 → 读 ELF header / phdr
         ├─ mmap(svc 222)总跨度 reserve(PROT_NONE)
         ├─ phdr_table_load_segments:逐 PT_LOAD mmap(按 PF_R/W/X 分离:
         │    r--(rodata/relro)、r-x(text)、rw-(data/bss);file offset 页对齐;
         │    bss 尾部匿名补零映射)             ←★ 段权限在这里定型
         ├─ 分配 soinfo、记 soname/base/大小,链入 namespace solist
         └─ 递归处理 DT_NEEDED(依赖 so 同样流程;zygote 预加载的走缓存)
   ──────────── 重定位(relocate,soinfo::relocate)────────────
   ├─ 遍历 .rela.dyn / .rela.plt(RELR/RELA 按版本)
   ├─ 每个符号经 soinfo_do_lookup:查本 so + 依赖链 dynsym/dynstr
   ├─ patch GOT 表项 / 直接重定位目标地址      ←★ "patchelf 过程"的运行时版
   └─ phdr_table_protect_gnu_relro:mprotect(svc 226)把 RELRO 区改 r--
   ──────────── 构造函数(call_constructors)────────────
   └─ soinfo::call_constructors(libc++ demangle 后符号 __dl__ZN6soinfo17call_constructorsEv)
      ├─ 先跑全部依赖 so 的构造(依赖先于本体)
      ├─ 执行 DT_INIT(init 函数,老式)
      └─ 执行 DT_INIT_ARRAY:按地址升序逐个调用
         └─ ★壳的自检/解密/反调试线程常驻此;也是抢注入的黄金窗口
   ──────────── 返回 Java 层 ────────────
└─ dlopen 返回 handle(libart 侧)
   └─ dlsym(handle, "JNI_OnLoad")
      └─ 调用 JNI_OnLoad(JavaVM*, void*)   ←★ 在所有 init_array 之后
         └─ 动态注册:RegisterNatives(02 区 1.14 的 hook 点)
```

Key points:
- **JNI_OnLoad comes after init_array**. Hooking JNI_OnLoad catches the registration functions, but the decryption inside init_array has already run; to catch "pre-decryption" you must go earlier (call_constructors' onEnter, inside dlopen).
- dlsym is the lookup channel for "statically registered symbols" (packers that obfuscate the export table use it in reverse to locate hidden functions, area 02 1.2).
- A second loadLibrary of the same so hits the solist directly; init_array does not re-run.

### 2.2 Kernel crossovers

- Every segment mapping is one svc mmap (222) -> sys_mmap -> vm_mmap_pgoff -> mmap_region: only the VMA and the page-cache association are created, **no full read-ahead**; the first execution of text / first read of rodata goes through the fault chain (sec.5) to fill from the page cache (see chain 5, the K1 fault chain).
- relro's mprotect (226) is the natural signal that "relocation is complete".

### 2.3 The "inject before the packer's self-check" timeline (the basis of the playbook)

```
早 ←───────────────────────────────────────────→ 晚
zygisk(zygote fork 后立刻,fork 前 agent 已在地址空间)
 > frida spawn(进程在,app 代码未跑,gating 挂起注入)
 > gadget(作为依赖 so 排在目标 so 前加载,init_array 先跑)
 > hook android_dlopen_ext onEnter(目标 so 还没进 load_library)
 > hook call_constructors onEnter(段已映射、重定位未完,02 区 1.15)
 > hook init 函数首地址(壳自检函数第一行)
 > attach(onCreate 后,只能收尸)
```

### 2.4 Observation points (chain 2)

| Observation point | Layer | What to watch | Notes |
|---|---|---|---|
| android_dlopen_ext / dlopen | L3 | every so load event (below 8.0 it's dlopen, higher android_dlopen_ext - the area 02 1.3 double hook) | under attach mode the target so may be long loaded; the hook never fires |
| __dl__ZN6soinfo17call_constructorsEv | L3 | init_array execution timing, the so name (get_soname) | ready-made code at area 02 1.15 |
| dlsym | L3 | static-registration symbol resolution | area 02 1.2 |
| openat filtering .so | L3/L5 | kernel-side so file opens (direct calls can't escape) | tracepoint sys_enter_openat |
| mmap events filtering PROT_EXEC | L5 | new executable mappings (the signature of the packer's self-unpacking/fortified segments: rwx) | kprobe vm_mmap_pgoff reading prot |
| mprotect events | L5 | relro permission drops, packer page-permission changes | kprobe do_mprotect_pkey; a packer flipping text from r-x to rw- and back to r-x during self-decryption exposes itself fully here |

## Chain 3: the full thread-creation chain (Java Thread -> pthread -> clone -> kernel task)

### 3.1 Timeline diagram

```
Java 层
└─ Thread.start()
   └─ ART JVM_StartThread → Thread::CreateNativeThread
      └─ pthread_create(libc/bionic/pthread_create.cpp)
         ├─ mmap(svc 222, RW, ANON|STACK)分配线程栈 + TLS 块
         ├─ guard page:mprotect 一页 PROT_NONE(栈溢出保护)
         └─ clone(__pthread_start, child_stack, flags, …)
            flags = CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND
                  | CLONE_THREAD|CLONE_SYSVSEM
                  | CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
            └─ svc __NR_clone(220)
               └─ sys_clone → kernel_clone → copy_process
                  ├─ CLONE_VM → copy_mm 走共享分支(get_mm,引用计数,不复制页表)
                  ├─ CLONE_FILES → copy_files 共享 fd 表
                  ├─ CLONE_THREAD → 加入父线程组:tgid 不变,tid 新分配
                  ├─ copy_creds:CLONE_THREAD → 直接共享 cred(无新 cred)
                  ├─ copy_thread:CLONE_SETTLS → 设 tpidr_el0(TLS 寄存器)
                  ├─ ctid 记录(CLONE_CHILD_CLEARTID:线程退出时内核清 *ctid
                  │   并 futex-wake —— pthread_join 的底层)
                  └─ wake_up_new_task + tracepoint sched_process_fork
                     └─ ret_from_fork → 返回用户态 __pthread_start
                        └─ 跑 start_routine(routine(arg))→ 结束 pthread_exit → exit
```

### 3.2 Direct clone calls bypassing pthread hooks (parameter differences, citing area 09 case 6)

Packer/detection code can skip pthread_create and go straight to `syscall(__NR_clone)` or a hand-written `svc 0` (x8=220). Differences from pthread_create:

| Item | pthread_create | direct clone |
|---|---|---|
| Stack | allocated by libc mmap + a guard page | caller-supplied (often a ready static buffer) |
| TLS/tpidr_el0 | initialized automatically | none (without CLONE_SETTLS, pthread_self is unusable in the new thread) |
| Exit semantics | pthread_exit cleanup | exit via raw syscall; ctid/ATOMIC_CLEARTID at the caller's whim |
| Visibility to hooks | a libc export - hookable | only L4 (Stalker catching x8==220)/L5 (tracepoint) |
The full playbook of area 09 case 6: getdents64 filtering /proc/self/task entries + Stalker catching svc + eBPF `sched/sched_process_fork` - see [hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md) case 6.

### 3.3 How packer detection threads work (the reverse view)

- Enumerate `/proc/self/task` (getdents64) -> read `<tid>/comm` looking for `gum-js-loop`/`gmain`/`pool-frida-`/`linjector`.
- Thread names ultimately go through `prctl(PR_SET_NAME)` (arm64 __NR_prctl=167; bionic wraps it in pthread_setname_np).
- frida's own threads already exist at the attach moment; a `pthread_create` hook only intercepts "future creations", not "existing ones" -> you must fall back to the file surface (getdents64/read filtering).
- **Kernel-side fact**: threads and processes both go through the same kernel_clone/copy_process, differing only in flags; the `sched_process_fork` tracepoint fires for both. Distinguish process vs thread by flags (CLONE_THREAD) or by pid!=tgid.

### 3.4 Observation points (chain 3)

| Observation point | Layer | What to watch |
|---|---|---|
| pthread_create / __pthread_start | L3 | thread entry-function address, owning so (area 02 1.7/1.8/1.9) |
| clone (libc export) | L3 | clone calls that bypass pthread (the area 02 1.10 replace interception) |
| Stalker catching x8==220 | L4 | direct svc clone (packers starting threads in assembly) |
| sched_process_fork tracepoint | L5 | every new task, **the steadiest observation point** (eBPF, direct-call-proof) |
| kprobe kernel_clone reading flags | L5 | distinguishing process forks (SIGCHLD) vs threads (CLONE_THREAD etc.) |

## Chain 4: the user-space allocation chain (Java new / native malloc -> scudo -> mmap)

### 4.1 Timeline diagram

```
Java 对象
└─ new → ART heap 自己的空间(region space / bump 指针 TLAB;
   │     card table 记跨代引用写屏障 + 并发拷贝 GC,一句话带过,不走 malloc)
   └─(仅 off-heap/direct buffer/Bitmap 像素数据等)→ 进 native 分配
native
└─ malloc / new / operator new(libc/bionic)
   └─ scudo(bionic 默认分配器,Android 11 起;A10 及以前 jemalloc)
      ├─ CombinedAllocator::allocate
      │  ├─ 小分配(阈值随配置,约 ≤64KiB,待验证)→ Primary
      │  │   SizeClassAllocator64:
      │  │   - 按 size class 分 region(启动时一次性预留巨大 VA,同样走 mmap,
      │  │     但只 reserve;用多少 commit 多少 → 缺页按需给物理页,见链5)
      │  │   - 每 chunk 前带 header:校验和(cookie)+class id+state+offset
      │  │     (打包约 8 字节,位域随版本,待验证)
      │  └─ 大分配 → Secondary(LargeMmapAllocator):
      │      每次分配单独 mmap(svc 222 → sys_mmap → vm_mmap_pgoff → mmap_region),
      │      头部放页前的元数据;释放 = munmap
      │      ※ Android 堆基本不用 brk(svc 214);观测堆活动盯 mmap 别盯 brk
      ├─ MTE 设备(Android 12+)上分配时打 tag
      └─ 返回用户指针
free(ptr)
└─ scudo Deallocate
   ├─ 校验 header(防破坏/UAF 的一部分)
   └─ 进 quarantine(隔离区延迟复用,防 UAF:释放块先雪藏,
      │  按随机递减计数/容量上限逐批回池;期间内容可能被毒化)
      └─ 到点归还 Primary 对应 region / Secondary 直接 munmap
```

### 4.2 The detection view and the dump view

- **Packers scanning the heap for known structures**: walk their own address space for the dex magic (`dex\n035\0`) to locate in-memory dex, or for frida-agent signature bytes. Countermeasures: keep key structures encrypted at rest, destroy after use, place them in large Secondary blocks + periodic integrity checks (scudo's header check can't stop "contents being read" - it only guards structure tampering).
- **The dump view (finding heap-block boundaries from an arbitrary pointer)**:
 - primary blocks: read the scudo chunk header at `ptr-8`, take the class id -> look up the size-class table for the block size, aligning front/back neighbors accordingly;
 - secondary blocks: just look at the standalone anonymous mapping in `/proc/self/maps` - the mapping bounds are the block bounds;
 - the ART heap: a separate system (card table, region layout) - take the ART-entrance approach of [dex-unpacking.md](../03-unpacking/dex-unpacking.md); don't apply scudo rules there.
 - so dumps (the in-memory state of fortified so files) go through solist->soinfo->segment info, see [so-repair-dump.md](../03-unpacking/so-repair-dump.md).
- **The adversarial meaning of quarantine**: a post-free pointer grab dumps "not yet reused" old data; conversely, the UAF exploitation window is stretched by quarantine with added uncertainty (not eliminated). Synacktiv/USENIX WOOT'24 has a systematic bypass analysis (see the verification record at the end).

### 4.3 Version differences (chain 4)

- Android 11: scudo becomes the default (replacing jemalloc).
- Android 12+: scudo tags on MTE devices; GWP-ASan sampling integrated (default-on status varies by version).
- Android 14+: scudo rolls with LLVM upstream; configuration-macro trimming differs from early versions; **behavioral specifics `[unverified]`** (the core Primary/Secondary/quarantine structures unchanged).

### 4.4 Observation points (chain 4)

| Observation point | Layer | What to watch |
|---|---|---|
| malloc/free (same for operator new/delete) | L3 | allocation flow, call stacks; for high-volume targets use Stalker/sampling - full Interceptor hooks drag performance |
| mmap filtering prot=RW | L5 | Secondary large allocations + Primary region growth (the anonymous-mapping growth curve) |
| brk (214) | L5 | basically never seen on the heap (Android's allocator doesn't use it) - seeing it is itself anomalous |
| the ART heap | L2 | libart symbols (heap walking), see the dex-unpacking piece |

## Chain 5: the fault and memory-protection chain (first access -> kernel -> PTE -> re-execution)

### 5.1 The fault timeline (arm64)

```
用户态 EL0
└─ 第一次 load/store/取指一个刚 mmap 的地址(如新 so 的 text)
   └─ MMU 页表 walk:PTE 不存在(或权限不符)
      └─ 触发 Data Abort / Instruction Abort,陷入 EL1
         └─ 异常向量表 el0t_64_sync → el0_da(entry-common.c;6.x 拆 handler,名随版本待验证)
            └─ do_mem_abort(按 ESR.EC 分发:0x24=data abort low EL)
               └─ do_page_fault(mm/memory.c 一族)
                  ├─ 读 far_el 拿出错地址、ESR 拿读写/指令信息
                  ├─ 找 VMA(lock_mm_and_find_vma);无 VMA → SIGSEGV
                  └─ handle_mm_fault → handle_pte_fault,按 PTE/VMA 状态分派:
                     ├─ 匿名 VMA、PTE 空、只读访问
                     │  └─ do_anonymous_page:映射全局共享零页(只读零页,
                     │     物理上全机共享,写到才分真页)
                     ├─ 匿名 VMA、写访问
                     │  └─ do_anonymous_page:alloc 新物理页(清零)→ set_pte_at
                     ├─ 文件 VMA(如 so text/rw 段)
                     │  └─ do_read_fault/do_write_fault → filemap_fault:
                     │     查 page cache(xarray),miss 则发起实际磁盘/flash 读
                     │     → 建映射(文件页缓存,多进程共享同一物理页)
                     ├─ COW(do_wp_fault):写只读页 → 复制页(zygote 共享页在此分家)
                     └─ swap(do_swap_page,app 域 zram 常见)
                  └─ PTE 写入页表 + TLB 无该项 → 返回用户态
                     └─ ★同一指令重新执行,这次页表命中
```

### 5.2 The mprotect chain

```
frida Memory.protect / 壳改页权限
└─ libc mprotect → svc __NR_mprotect(226)
   └─ sys_mprotect → do_mprotect_pkey
      └─ mprotect_fixup → change_protection
         ├─ 拆/合并 VMA,逐 PTE 改 R/W/X 位
         └─ flush_tlb_range 刷旧映射
```
- frida's `Memory.protect(addr, size, 'rwx')` followed by patchCode is, at the kernel level, exactly this chain - **it necessarily leaves traces**: sys_mprotect events and page-table bit changes.
- Packers keeping code pages RX with periodic CRC checks: the check itself is an ordinary read (no exception-chain involvement), but self-decryption necessarily shows the `mprotect(RW)->write->mprotect(RX)` sequence -> **kprobe do_mprotect_pkey watching prot changes is a low-noise probe for catching self-decryption timing**.
- wxshadow shadow-page stealth breakpoints: redirect at the PTE layer, swapping the normal mapping built by do_page_fault for the shadow page, hidden from both `/proc/mem` and GUP - see the wxshadow chapter of [kernel-hook-stealth.md](../07-kernel/kernel-hook-stealth.md) (area 07).

### 5.3 Chain 5 tying back to the other chains

- Chain 2's mmap only creates the VMA; **the real "load" happens at the first fault** (filemap_fault fetches from the page cache). The complete segments you see when dumping an in-memory so are filled in piece by piece by the fault chain.
- Chain 1's COW split: when a child **writes** a zygote preloaded page, do_wp_fault copies the physical page - every write to heap/bss after app start is a "split".
- Chain 4's Primary regions reserve but don't commit; committing is an anonymous write fault (do_anonymous_page supplies a new page).

### 5.4 Observation points (chain 5)

| Observation point | Layer | What to watch |
|---|---|---|
| kprobe do_page_fault / handle_mm_fault | L5 | fault-storm locations (locating decryption/self-modifying-code hotspots; high-volume, needs filtering) |
| kprobe do_mprotect_pkey | L5 | permission-flip events (packer self-decryption, the precondition of frida patchCode) |
| tracepoint sys_enter_mmap / sys_enter_mprotect | L5 | syscall-parameter level (prot/flags visible verbatim) |
| perf stat page-faults / minflt | L1 | quick magnitude confirmation (doesn't distinguish file/anonymous) |

## 6. The full-chain observation-point matrix (summary)

| Event | L1/L2 (Java/ART) | L3 (libc/linker) | L4 (Stalker/ptrace) | L5 (eBPF/kprobe) |
|---|---|---|---|---|
| Process birth | ActivityThread.main | zygote-side sendmsg | - | kernel_clone / sched_process_fork |
| Application init | attachBaseContext/onCreate hook | - | - | - (a user-space event) |
| so loading | System.loadLibrary hook | android_dlopen_ext, call_constructors | - | sys_enter_openat (.so filtered) |
| Segment mapping | - | - | - | vm_mmap_pgoff (PROT_EXEC filtered) |
| Relocation done | - | (GOT diff, before/after reads) | - | do_mprotect_pkey (relro r--) |
| init_array execution | - | call_constructors onEnter | - | - |
| JNI_OnLoad | - | libart symbol hook | - | - |
| Thread creation | Thread.start hook | pthread_create/clone | Stalker x8==220 | sched_process_fork |
| Heap allocation | - | malloc/free | - | mmap (RW filtered) |
| Faults/physical pages | - | - | - | do_page_fault (needs filtering) |
| Permission changes | around Memory.protect | mprotect | svc 226 | do_mprotect_pkey |
Layer-selection principle carried over from area 09: prefer L3 when possible; go L4 only for direct svc calls; go L5 only when you need "global, direct calls included".

## 7. Version-difference quick reference (whole chain)

| Version | Difference points |
|---|---|
| Android 8.0- | so loading goes through dlopen; 8.0+ through android_dlopen_ext (the origin of the area 02 double-hook idiom) |
| Android 7+ | linker namespace isolation (classloader domains; so visibility restricted by PathClassLoader) |
| Android 10+ | the USAP pre-fork pool (default-on status `[unverified]`) |
| Android 11 | scudo becomes the default allocator; the GKI 5.4 kernel's fork entry named _do_fork |
| Android 12+ (kernel 5.10+) | kernel_clone (verified); scudo tags on MTE devices; 32-bit apps go through the secondary zygote's two-level fork |
| Android 14+ (6.1/6.6) | scudo rolls with LLVM (details `[unverified]`); the fork-path structure unchanged |
| 6.x kernels | arm64 exception entries split into handlers (the el0_da family names shifted); the mm main chain (do_page_fault->handle_mm_fault->do_*_fault) unchanged |

## 8. Verification record (2026-10-15)

- kernel/fork.c: v5.4 (`_do_fork` line 2339) and v5.10 (`kernel_clone` line 2415, `copy_process`, `copy_mm` line 1379, the CLONE_VM branch at 1406, `trace_sched_process_fork` line 2466, `wake_up_new_task` line 2480) both verified line-by-line against googlesource raw.
- scudo: LLVM official docs + source. (default since Android 11; Primary/Secondary/quarantine/chunk-header checks.) Bit fields and thresholds marked `[unverified]`.
- frida spawn mechanics: the frida 17.6 release note (spawn gating withholds the ACK) + community source analysis (spawn starts the process via the system route, ptrace-injects, gating suspends).
- zygote specialize call order, USAP default status, Android 14 scudo specifics, 6.x exception-handler names: marked `[unverified]`.
- Hook code points are not repeated here; they uniformly point to [native-hook-cheatsheet.md](../02-frida/native-hook-cheatsheet.md) (dlopen/call_constructors/pthread/clone/registerNatives) and [hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md) (svc interception/thread cases).

## Related documents

- Ready-made hook-point code: [../02-frida/native-hook-cheatsheet.md](../02-frida/native-hook-cheatsheet.md)
- Fallback routes and the svc compendium: [../09-function-map/hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md)
- binder/eBPF hands-on: [../07-kernel/android-kernel-ebpf.md](../07-kernel/android-kernel-ebpf.md)
- wxshadow/PTE-layer stealth: [../07-kernel/kernel-hook-stealth.md](../07-kernel/kernel-hook-stealth.md)
- Layered detection methods: [../04-evasion/detection-landscape.md](../04-evasion/detection-landscape.md)
- Dumping hands-on: [../03-unpacking/dex-unpacking.md](../03-unpacking/dex-unpacking.md) / [../03-unpacking/so-repair-dump.md](../03-unpacking/so-repair-dump.md)
