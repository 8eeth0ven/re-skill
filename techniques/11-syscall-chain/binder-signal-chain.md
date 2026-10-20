# Binder and Signal Chains (kernel-level, end to end)

> Positioning: expands five confrontation-critical chains end to end down into the kernel - the full Binder IPC sequence (bidirectional), ServiceManager lookup, ptrace anti-debugging, signal delivery (SIGTRAP/SIGPIPE), and process exit. The detection-surface checklist is in 04-evasion/detection-landscape.md; this piece covers "the chains and kernel-side observation"; the concise binder vulnerability attack-surface table is in 07-kernel/android-kernel-ebpf.md sec.2 - this piece writes the full sequences.
> Wording: symmetric offense/defense descriptions; mechanisms described neutrally.

## 0. Panorama

### 0.1 One synchronous Binder call (bidirectional)

```
[Client app 进程]                         [内核 drivers/android/binder.c]        [system_server]
pm.getPackageInfo(...)                       │                                      │
 IPackageManager$Stub$Proxy.transact         │                                      │
  android.os.BinderProxy.transactNative      │                                      │
   (JNI android_util_Binder.cpp)             │                                      │
    BpBinder::transact(handle)               │                                      │
     IPCThreadState::transact                │                                      │
      writeTransactionData(BC_TRANSACTION)   │                                      │
      talkWithDriver                         │                                      │
       ioctl(fd,BINDER_WRITE_READ,&bwr) ─────► binder_ioctl                          │
                                               binder_ioctl_write_read               │
                                               binder_thread_write                   │
                                               binder_transaction ──┐                │
                                                解析 binder_transaction_data          │
                                                handle→binder_ref→binder_node        │
                                                binder_alloc_new_buf:数据拷入目标 mmap│
                                                binder_proc_transaction:             │
                                                 select/enqueue/wakeup ──────────────►│ (阻塞在 ioctl 读侧的
                                                (唤醒目标线程,wake_up_interruptible) │  binder 线程被唤醒)
                                                                                     │ binder_thread_read
                                                                                     │ → BR_TRANSACTION(_SECCTX)
                                                                                     │ IPCThreadState::executeCommand
                                                                                     │ BBinder::transact→JavaBBinder::onTransact
                                                                                     │ Binder.execTransact(JNI)
                                                                                     │ → PackageManagerService.getPackageInfo
                                                                                     │ sendReply → BC_REPLY
                                                binder_transaction(reply=true) ◄─────│
                                                拷回 client mmap + 唤醒 client 线程    │
       ioctl 返回(BR_REPLY) ◄───────────────┘                                      │
      waitForResponse 收 Parcel(直接指向 client mmap 区)                            │
     JNI/Java 反序列化 → PackageInfo
```

### 0.2 Signal and exit chains at a glance

```
发信号: kill/tgkill → sys_tgkill → do_tkill/do_send_sig_info → __send_signal_locked
        → complete_signal → signal_wake_up_state{ set_tsk_thread_flag(TIF_SIGPENDING) }
递送:   返回用户态(ret_to_user 检查 _TIF_SIGPENDING) → do_notify_resume → do_signal
        → get_signal(被 trace 则先 ptrace_signal/ptrace_stop 给 tracer) → handler/默认行为
异常源: BRK 断点 → el0_dbg → do_el0_brk → send_user_sigtrap → SIGTRAP(TRAP_BRKPT)
退出:   exit_group(94) → do_group_exit → do_exit → do_task_dead → schedule(不返回)
```

## 1. Chain 1: the full Binder call sequence (PackageManager.getPackageInfo as the example)

### 1.1 Originating side: Java -> libbinder

| Step | Layer | Function/object | Anchor |
|---|---|---|---|
| 1 | Java API | `PackageManager.getPackageInfo(pkg, flags)` -> `getPackageInfoAsUser` -> `ActivityThread.getPackageManager` returns the cached `IPackageManager` proxy | frameworks/base/core/java/android/app/ApplicationPackageManager.java |
| 2 | AIDL proxy | `IPackageManager$Stub$Proxy.getPackageInfo(...)`: arguments written into `Parcel data`, `mRemote.transact(Stub.TRANSACTION_getPackageInfo, data, reply, 0)` | generated classes (TRANSACTION_ ordinals drift by version, `[unverified]` exact values) |
| 3 | Java->JNI | `android.os.BinderProxy.transact` -> `transactNative` (native method) | frameworks/base/core/java/android/os/Binder.java (BinderProxy inner class) |
| 4 | JNI | `android_os_BinderProxy_transact`: takes the native-side `sp<IBinder>` (i.e. `BpBinder(handle)`) and calls `transact` | frameworks/base/core/jni/android_util_Binder.cpp |
| 5 | libbinder | `BpBinder::transact` -> `IPCThreadState::self->transact(handle, code, data, reply, flags)` | frameworks/native/libs/binder/BpBinder.cpp |
| 6 | Packing | `writeTransactionData(BC_TRANSACTION, handle, code, data)`: the `binder_transaction_data` goes into the write buffer (`data.ptr.buffer` points at the user address of the client's own Parcel mData) | frameworks/native/libs/binder/IPCThreadState.cpp |
| 7 | Driver interaction | `waitForResponse` -> `talkWithDriver` -> `ioctl(mDriverFD, BINDER_WRITE_READ, &bwr)`; sleeps on the driver's read side when idle | IPCThreadState.cpp; fd/mmap come from `ProcessState::open_driver`+`mmap` (about 1MB-2 pages by default, PROT_READ) |
Key point: the binder mmap region is a **read-only user mapping**; the "one copy" happens when the kernel writes the client's data into the server's mmap pages (the server reads `tr.data.ptr.buffer` as its own process address - no second copy).

### 1.2 Into the kernel: binder_ioctl -> binder_transaction

Source anchors:

```
sys_ioctl(arm64 __NR_ioctl=29)
 → binder_ioctl(filp, BINDER_WRITE_READ, arg)        // file_operations
   → binder_ioctl_write_read(...)
     → binder_get_thread()                             // 按 task 找/建 binder_thread
     → binder_thread_write(proc, thread, bwr->write_buffer, ...)   // 消费写侧命令
        → BC_TRANSACTION/BC_REPLY → binder_transaction(proc, thread, &tr, reply, 0)
     → binder_thread_read(...)                         // 生产读侧命令(BR_*)
```

Key steps inside `binder_transaction` (the non-reply, non-zero-handle path):

```c
binder_proc_lock(proc);
ref = binder_get_ref_olocked(proc, tr->target.handle, true);   // handle → binder_ref
...
target_node = binder_get_node_refs_for_txn(ref->node, &target_proc, &return_error);
```

Then: `binder_alloc_new_buf` (drivers/android/binder_alloc.c) allocates a `binder_buffer` in the **target process**'s binder_alloc free region, copying the client user data pointed to by `tr->data.ptr.buffer/offsets` into the target's mmap pages via `binder_alloc_copy_user_to_buffer`; the `flat_binder_object`s indicated by `offsets[]` are rewritten in place by the driver (BINDER_TYPE_BINDER<->HANDLE conversion, fd installation); if `target_node->txn_security_ctx`, `security_secid_to_secctx` attaches the SELinux context. Security-context enums/structs: `struct binder_transaction_data_secctx { struct binder_transaction_data transaction_data; binder_uintptr_t secctx; }`.

### 1.3 Waking the target thread (the server-side wakeup path)

At the end, `binder_transaction` calls `binder_proc_transaction(t, target_proc, target_thread)`:

```c
if (!thread && !pending_async)
        thread = binder_select_thread_ilocked(proc);      // 挑一个可用 binder 线程
binder_enqueue_thread_work_ilocked(thread, &t->work);     // 挂到线程 todo 队列
binder_wakeup_thread_ilocked(proc, thread, !oneway /* sync */);
```

`binder_wakeup_thread_ilocked`: sync (two-way transactions) goes through `wake_up_interruptible_sync(&thread->wait)`, oneway through `wake_up_interruptible(&thread->wait)` - **modern kernels use per-thread wait queues** (old versions hung off `proc->wait`; `[unverified]` which side the target kernel falls on); with `thread==NULL` it degrades to `binder_wakeup_poll_threads_ilocked(proc, sync)`. What gets woken is the binder thread in system_server sleeping on the read side of `ioctl(BINDER_WRITE_READ)` (equivalent to `wait_event_interruptible_*` on `binder_wait_for_work`).

### 1.4 Server-side execution and the BC_REPLY return trip

| Step | Layer | Action | Anchor |
|---|---|---|---|
| 1 | kernel->user | `binder_thread_read` takes `t->work` from the todo queue, emits `BR_TRANSACTION` (or `BR_TRANSACTION_SECCTX` with secctx) into `bwr->read_buffer`, and the `ioctl` returns | binder.c; command definitions include/uapi/linux/android/binder.h |
| 2 | libbinder | `IPCThreadState::joinThreadPool/talkWithDriver` receives the command -> `executeCommand(br)` | IPCThreadState.cpp |
| 3 | native object | `((BBinder*)tr.cookie)->transact(code, &buffer, &reply, flags)` -> `JavaBBinder::onTransact` | android_util_Binder.cpp |
| 4 | JNI->Java | `env->CallBooleanMethod(jobject, mExecTransactMethodCode, ...)` -> `Binder.execTransact` -> `Binder.onTransact` -> `PackageManagerService.getPackageInfo` (checks the PackageParser cache, assembles a PackageInfo into the reply Parcel) | Binder.java / services/core/java/com/android/server/pm/PackageManagerService.java |
| 5 | Return trip | `sendReply` -> `BC_REPLY` -> `binder_transaction(reply=true)`: the target resolves to the client's waiting thread (via `thread->transaction_stack`), likewise copied into the client's mmap + `binder_proc_transaction` wakes the client | binder.c |
| 6 | Client wrap-up | `waitForResponse` receives `BR_REPLY`, `reply->setData(tr.data.ptr.buffer, tr.data_size)` referencing the client mmap region directly; after consumption `BC_FREE_BUFFER` returns it | IPCThreadState.cpp |

### 1.5 Key structure quick reference (uapi: include/uapi/linux/android/binder.h; kernel: drivers/android/binder.h)

| Structure | Key fields | One-sentence role |
|---|---|---|
| binder_write_read | write_size/write_buffer/write_consumed + read_size/read_buffer/read_consumed | the read/write double buffer of one ioctl exchange; the driver backfills consumed |
| binder_transaction_data | target (handle or ptr), cookie, code, flags (TF_ONE_WAY etc.), sender_pid/sender_euid (kernel-backfilled sender identity), data_size/offsets_size, data.ptr (buffer/offsets) | one transaction's metadata + data pointers; code is the AIDL method number |
| binder_proc | tsk/pid, threads (rb_tree), nodes (rb_tree), refs_by_desc/refs_by_node, todo, wait, is_dead, embedded binder_alloc (the mmap region) | the whole state of one process with /dev/binder open, as the driver sees it |
| binder_node | ptr/cookie (the peer's user-space BBinder address), proc (owner), local_strong/weak_refs, has_async_transaction, txn_security_ctx, async_todo | a service object addressable across processes |
| binder_ref | desc (i.e. the user-space handle value), node, proc, strong/weak counts, two rb indexes | one process's reference to one node; the bridge between handle<->node |
| binder_buffer | entry/rb_node, target_node, data_size/offsets_size, data[0] | the transaction data buffer; struct header + data both sit directly in the target process's mmap region |
Command numbers: `BC_TRANSACTION=_IOW('c',0,...)`, `BC_REPLY=_IOW('c',1,...)`, `BR_TRANSACTION=_IOR('r',2,...)`, `BR_REPLY=_IOR('r',3,...)`, `BR_TRANSACTION_SECCTX=_IOR('r',2,struct binder_transaction_data_secctx)` (same nr as BR_TRANSACTION, distinguished by encoded struct size - printing the hex cmd when parsing is most robust). `BINDER_WRITE_READ=_IOWR('b',1,struct binder_write_read)`, typical 64-bit value 0xC0306201 (trust the decode).

### 1.6 Observation point table (the binder call chain, four layers)

| Layer | Observation point | Means | What you get |
|---|---|---|---|
| Java | `IPackageManager$Stub$Proxy.transact` / `BinderProxy.transact(transactNative)` | frida `Java.use("android.os.BinderProxy")`, proxy IPackageManager (see 02-frida/java-layer/storage-and-system.md sec.9.1-9.3) | full objects before/after deserialization; most convenient, and most easily caught by Java-layer integrity checks |
| libbinder | `IPCThreadState::transact` / `writeTransactionData` | uprobe on `/system/lib64/libbinder.so` symbols (mangled names verified per version, `[unverified]`) | handle/code/flags; zero injection into the target process |
| syscall | the `ioctl` entry | frida Interceptor on libc `ioctl`, filter `arg1==BINDER_WRITE_READ` | raw bwr bytes; the read_buffer holds BR_REPLY + parcel |
| kernel | `kprobe:binder_transaction`, `tracepoint:binder:binder_transaction` (also binder_command/binder_return) | bpftrace/BCC, root | code/handle/data_size, `tr->data.ptr.buffer` (the client user address; current==client allows probe_read_user); server-side data is at `t->buffer->data` = the server mmap user address - must be read from an observation point in server context |
**Where in the mmap offsets the data is readable (the answer)**: on the client side look at `binder_transaction_data.data.ptr.buffer` (the client's own Parcel user memory); the data received by the server sits in the server process starting at `binder_alloc.buffer`, in the `binder_buffer->data` sliced out by `binder_alloc_new_buf` - the same pages are written by the kernel and read-only-mapped by the server's user space, so reading that address range from a server-process context (kprobe `binder_thread_read` / uprobe `executeCommand`) gets the zero-copy original.
bpftrace examples:

```bash
# 例1:kprobe binder_transaction,按进程过滤 dump 事务元数据(需 BTF;arg2 = struct binder_transaction_data*)
bpftrace -e 'kprobe:binder_transaction /comm=="com.target.app"/ {
  $tr = (struct binder_transaction_data *)arg2;
  printf("handle=%d code=%d dsz=%d fl=%x\n", $tr->target.handle, $tr->code,
         $tr->data_size, $tr->flags); }'

# 例2:tracepoint 版(字段由 TRACE_EVENT 提供,跨版本更稳)
bpftrace -e 'tracepoint:binder:binder_transaction /args->code==<TRANSACTION_getPackageInfo>/ {
  printf("to_proc=%s code=%d reply=%d\n", comm, args->code, args->reply); }'
```

### 1.7 Practice: forging the getPackageInfo return at the binder layer

Background: RASP often self-checks signatures/package info from the native layer via **raw Binder** (bypassing the Java PackageManager object) (detection-landscape.md sec.7.3 "hook-proof detection channels"), where Java-layer hooks (including the sec.9.3 sPackageManager dynamic proxy) can't intercept. The equivalent confrontation surface drops two notches:
1. **User-space ioctl layer**: hook libc `ioctl` (or uprobe) inside the target process, filtering `BINDER_WRITE_READ`; for calls identified as getPackageInfo (matching `binder_transaction_data.code`, value drifts by version `[unverified]`), parse the BR_REPLY + parcel in the returned read buffer (length-prefixed structure) and do an **equal-length replacement** of the signatures blob (unequal lengths require rebuilding the parcel and syncing data_size - costly). Pros: zero hook traces in the Java layer; cons: you must parse the parcel format and keep BC_FREE_BUFFER semantics faithful.
2. **Kernel layer**: with root, use kprobe/kretprobe to locate the reply moment, and the `bpf_probe_write_user` helper to rewrite this process's (current==client) user-memory read_buffer - zero user-space injection; research-grade, granularity and stability to be self-verified (`[unverified]` helper availability per kernel).
3. Changing the server side (modifying PMS results inside system_server) affects everything globally - not recommended here, only noted as existing.
Division of labor with 02-frida/java-layer/storage-and-system.md sec.9.3: the Java proxy scheme fights "Java-layer validation"; the binder-layer scheme fights "native raw-binder validation"; one level further down (the detector itself parsing parcels directly + svc-izing ioctl) leaves only kernel observation/patching the so.

## 2. Chain 2: the ServiceManager lookup chain

### 2.1 The chain

```
Java ServiceManager.getService("package")                     frameworks/base/core/java/android/os/ServiceManager.java
 → handle 0 的 BinderProxy(Android 11+ 经 ServiceManagerNative/IServiceManager AIDL 包装,底层不变)
 → IPCThreadState::transact(handle=0, GET_SERVICE, name)
 → binder_transaction:target.handle==0 时不走 binder_get_ref_olocked,
   目标定为 binder_context_mgr_node(servicemanager 启动时
   ioctl BINDER_SET_CONTEXT_MGR(_EXT) 注册的 context manager 节点)(EXT 变体用于 features 协商)
 → servicemanager 进程(frameworks/native/cmds/servicemanager)BR_TRANSACTION 醒来查 svcinfo 表
 → BC_REPLY 返回 flat_binder_object(type=BINDER_TYPE_HANDLE)
 → 驱动 binder_translate_binder:在 client 进程 binder_inc_ref_for_node 建 binder_ref、
   分配新 handle desc,回填到 client 读到的对象里(函数名以 binder.c 为准)
 → libbinder 包装成新的 BpBinder(handle N)/Java BinderProxy
 → 之后所有 getPackageInfo 的 BC_TRANSACTION 都用 target.handle=N
```

The essence of a handle: the client's `binder_ref->desc`; the same service has different handle values in different processes - `binder_node` (unique on the server side) is the global anchor.

### 2.2 Observation point table (the ServiceManager chain)

| Layer | Observation point | Means | Notes |
|---|---|---|---|
| Java | `ServiceManager.getService/rawGetService` | frida Java.use | see the service name and the returned BinderProxy's mObject (handle) |
| libbinder | `defaultServiceManager` / `getService` | uprobe libbinder.so | catches every framework-side query |
| syscall | ioctl with `tr.target.handle==0` | bpftrace predicate `$tr->target.handle==0` | all context-manager traffic (addService included) |
| kernel | `kprobe:binder_transaction` filtering handle==0; on the servicemanager side further filter `comm=="servicemanager"` | bpftrace | gets the name string (probe_read_user in client context) |
Common system service entrances (the name argument of getService; additions/removals per version):

| name | Provider | Reversing value |
|---|---|---|
| activity / activity_task | system_server (ATMS/AMS) | startActivity, task-stack info |
| package | system_server (PMS) | install/signature/permission surface |
| window / display | system_server (WMS) | windows and overlays |
| power / alarm / notification | system_server | smaller behavioral surface |
| telephony.registry | the phone process | device/network state |
| media.audio_flinger | audioserver | audio surface |
| SurfaceFlinger | the surfaceflinger process | screenshot/render surface (not system_server) |

## 3. Chain 3: the ptrace anti-debugging chain

### 3.1 Debugger side: the full attach chain (arm64 __NR_ptrace=117)

Source anchor: kernel/ptrace.c.

```
sys_ptrace → arch_ptrace(arm64/kernel/ptrace.c) → ptrace_attach:
  task_lock + cred_guard_mutex 下:
    __ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)   // 权限总闸
    task->ptrace = flags;
    ptrace_link(task, current);                                 // 建立跟踪关系
    ptrace_set_stopped(task, seize);
      非 seize:send_signal_locked(SIGSTOP, SEND_SIG_PRIV, task, PIDTYPE_PID);
      已停止:signal_wake_up_state(task, __TASK_STOPPED);
```

The `__ptrace_may_access` check sequence: same thread group passes directly; otherwise under RCU compare the caller's uid against the target's euid/suid/uid and the gid triple for full equality; unequal -> `ptrace_has_cap` (ns_capable CAP_SYS_PTRACE); then `task_still_dumpable` (the dumpable state - where `prctl(PR_SET_DUMPABLE,0)` acts); finally `security_ptrace_access_check` (the LSM/SELinux hook). Any step failing -> EPERM.
`__ptrace_link(child, new_parent, ptracer_cred)`:

```c
BUG_ON(!list_empty(&child->ptrace_entry));
list_add(&child->ptrace_entry, &new_parent->ptraced);
child->parent = new_parent;                  // 关键:parent 指向 tracer
child->ptracer_cred = get_cred(ptracer_cred);
```

`ptrace_traceme` (for self-attach): `current->ptrace = PT_PTRACED; ptrace_link(current, current->real_parent);`. Re-attaching an already-traced target is refused (conventionally EPERM; the exact return code `[unverified]`).

### 3.2 The TracerPid output chain (verified conclusion: the code is in array.c, not base.c)

- fs/proc/base.c only registers: `ONE("status", S_IRUGO, proc_pid_status)` mounted into the tgid_base_stuff/tid_base_stuff tables, dispatched via proc_single_show.
- The actual output is in `task_state` of **fs/proc/array.c** (`proc_pid_status` prints the name first, then calls it):

```c
rcu_read_lock();
tracer = ptrace_parent(p);
if (tracer)
        tpid = task_pid_nr_ns(tracer, ns);
...
seq_put_decimal_ull(m, "\nTracerPid:\t", tpid);
```

The semantics of `ptrace_parent(p)` (include/linux/ptrace.h): returns `p->parent` (the sec.3.1 reparent effect) when `p->ptrace` is non-zero, else NULL - **TracerPid's data source is exactly the combination of task->ptrace + task->parent**. That is the kernel-level basis for "what to change to erase TracerPid".

### 3.3 Self-attach anti-debugging and the frida spawn timing

- Self-attach: fork a child that `PTRACE_ATTACH`/`TRACEME`-chains to occupy the parent's tracer slot (sec.3.1's non-empty ptrace_entry) -> later arrivals (IDA/gdb/lldb) get EPERM on attach; meanwhile `task->ptrace` stays non-zero -> TracerPid stays non-zero - a double-edged effect: blocks debuggers, but leaves a fingerprint.
- The timing essence of frida spawn bypassing early detection: in spawn mode, injection happens after zygote forks the new process but **before** the Application/so anti-debug initialization runs (gating sits early in the entry); attach mode must instead collide with an already-occupied tracer slot. Right after spawn, hooking `ptrace` (both libc and svc paths) and `sigaction` silences the self-attach child's subsequent moves; if the detection has already run, attach gets EPERM - only a spawn restart or a kernel scheme remains.

### 3.4 Confrontation observation point table (ptrace/TracerPid)

| Layer | Observation/intervention point | Means | Notes |
|---|---|---|---|
| User-space proc-read layer | `open/read/fgets` of /proc/self/status | hook, then rewrite the TracerPid digits in the buffer (equal length) | fails against svc-ized openat+read (detection-landscape.md sec.2.9) |
| User-space proc-read layer (equivalent signals) | the `/proc/self/task/<tid>/stat` state column, wchan, waitpid | same | RASP usually cross-checks multiple files - changing one is not enough |
| Kernel ptrace layer | `kprobe:ptrace_attach` | bpftrace logging tracer pid/comm | observation only; kprobe cannot change return values |
| Kernel decision layer | `bpf_lsm/ptrace_access_check` returning -EPERM | BPF LSM (needs CONFIG_BPF_LSM) | can actively reject unknown tracers (research-flavored) |
| proc output layer | seq_file output (task_state/proc_pid_status) | LKM/KPM inline hook rewriting the tpid output | see the sec.3.5 comparison |

### 3.5 Comparing the "full kernel solutions" for TracerPid

| Scheme | Approach | Pros | Cons |
|---|---|---|---|
| Filter proc output | hook `task_state` (or the seq read layer) zeroing tpid | scheduling semantics untouched; the debugger still works | big leak surface: equivalent signals (stat state=t, wchan, waitpid, other task-reading interfaces) each need patching |
| Modify task_struct | clear `task->ptrace`/unlink `ptrace_entry`/restore `parent` | vanishes at the data source, for every read path | breaks real tracing semantics; event delivery (wait) goes haywire; heavy maintenance |
| Swap the breakpoint mechanism | no ptrace: shadow-page stealth breakpoints (**wxshadow**, 07-kernel/kernel-hook-stealth.md sec.2.3: PTE redirection/BRK #0x7/GUP hiding) | task->ptrace stays 0, TracerPid naturally clean; prologue checks read the original page and miss | needs a root/KPM environment |

## 4. Chain 4: the signal chain (SIGTRAP/SIGPIPE anti-debugging)

### 4.1 The send chain (arm64: kill=129, tkill=130, tgkill=131)

kernel/signal.c (the tgkill/tkill tails were truncated; the inner do_tkill chain is generic fact):

```
kill(2):  sys_kill → kill_something_info
            pid>0 → kill_proc_info → kill_pid_info → kill_pid_info_type(..., PIDTYPE_TGID)
            → group_send_sig_info(check_kill_permission 鉴权)
            → do_send_sig_info(sig, info, p, type)
tgkill:   sys_tgkill → do_tkill → do_send_sig_info(si_code=SI_TKILL)
共同后段: __send_signal_locked → complete_signal(选目标 task/线程)
            → signal_wake_up_state(t, state):
                set_tsk_thread_flag(t, TIF_SIGPENDING);
                wake_up_state(t, state | TASK_INTERRUPTIBLE) / kick_process(t);
```

### 4.2 The delivery chain (return to user space)

The arm64 return path (ret_to_user checks `thread_flags & _TIF_SIGPENDING` -> `do_notify_resume` -> `do_signal(regs)`; function names adjusted across versions; anchors arch/arm64/kernel/entry-common.c and arch/arm64/kernel/signal.c):

```
do_signal → get_signal(&ksig)(kernel/signal.c):
  dequeue_signal 取信号
  → 若 current->ptrace 且非 SIGKILL 且非 SA_IMMUTABLE:
        signr = ptrace_signal(...) → ptrace_stop(signr, CLD_TRAPPED, ...)
        「We're back. Did the debugger cancel the sig?」——tracer 先看:
        tracer 不转发(signr==0)→ 信号被丢弃;改号/被阻塞 → 重排队
  → SIG_DFL 走默认行为 / 否则 handle_signal → setup_rt_frame → 用户态 handler
```

**The kernel mechanism of "the debugger eats the signal" is exactly this stretch**: for a traced task, every non-IMMUTABLE signal first `ptrace_stop`s to the tracer; gdb/IDA don't reinject by default, so the app's handler never fires.

### 4.3 SIGTRAP sources and breakpoint self-check detection

The arm64 BRK exception (arch/arm64/kernel/debug-monitors.c):

```c
do_el0_brk():先试 uprobes(UPROBES_BRK_IMM),否则
send_user_sigtrap(TRAP_BRKPT) → arm64_force_sig_fault(SIGTRAP, TRAP_BRKPT,
                     instruction_pointer(regs), "User debug trap");
32 位:do_bkpt32 → arm64_notify_die("aarch32 BKPT", ..., SIGTRAP, TRAP_BRKPT, ...);
EL1 未处理 BRK → die("Oops - BRK")。旧内核对应 el0_dbg→brk_handler→force_sig_fault 路径。
```
- **Single-step**: PTRACE_SINGLESTEP sets PSTATE.SS (hardware single-step) -> the step exception -> SIGTRAP (TRAP_TRACE). Detection can only sense it via latency/behavioral side channels; user space cannot read mdscr_el1.
- **Breakpoint self-check detection principle**: the app first `sigaction`-registers a SIGTRAP handler, then deliberately executes `brk #0` in its own code (or raise/tgkills itself) - normally the handler runs and sets a flag (sec.4.2 normal delivery); under a ptrace-style debugger it goes `ptrace_signal`->`ptrace_stop`, the tracer swallows it by default, the handler never runs -> the flag is missing -> debugger detected. Counter: have the tracer forward SIGTRAP (the gdb `handle SIGTRAP nostop pass` idea), or switch to a breakpoint mechanism that doesn't depend on ptrace (wxshadow shadow pages - the checked page reads the original instruction, even the prologue CRC misses).

### 4.4 SIGPIPE

Source: writing to a closed pipe/socket has the kernel send SIGPIPE on the write path (net/ipv4/tcp.c tcp_sendmsg_locked, fs/pipe.c; MSG_NOSIGNAL suppresses it). Detection usage: the app registers a SIGPIPE handler and periodically writes to a monitored socket/pipe; if the handler doesn't run as expected (intercepted by a tracer or the process state is off) -> the watchdog logic flags an anomaly/kills itself. Weaker than the SIGTRAP self-check; usually one signal in a combination.

### 4.5 Observation point table (the signal chain)

| Layer | Observation point | Means | Notes |
|---|---|---|---|
| User-space registration layer | `sigaction`/`rt_sigaction` (arm64 __NR_rt_sigaction=134) | frida Interceptor | see which handlers the app registers (= the detection-intent list) |
| User-space send layer | `raise`/`kill`/`tgkill` (libc) | Interceptor | self-test-style anti-debugging reveals itself here |
| Kernel send layer | `kprobe:do_send_sig_info` / `tracepoint:signal:signal_generate` | bpftrace | who sent what signal to whom - even direct svc calls can't escape |
| Kernel delivery layer | `kprobe:get_signal` / `tracepoint:signal:signal_deliver` | bpftrace | whether the handler really ran, or was intercepted by ptrace_stop |

```bash
# 例3:观测 SIGTRAP(5) 的产生与目标
bpftrace -e 'tracepoint:signal:signal_generate /args->sig==5/ {
  printf("sig=%d target_pid=%d target=%s from=%s\n", args->sig, args->pid, args->comm, comm); }'
```

## 5. Chain 5: the abnormal process-exit chain (exit/kill detection and suicide)

### 5.1 The chain (arm64: exit=93, exit_group=94)

```
Java: System.exit(code) → Runtime.getRuntime().exit(code)
      → shutdownHooks → native Exit → libc exit(走 atexit)→ exit_group
native: exit()/quick_exit → exit_group;_exit → exit(93) 单线程
svc 直调: 内联汇编 mov x8,#94; svc #0(不经 libc,用户态 hook 失效)
内核: sys_exit_group → do_group_exit(code) → do_exit:
        exit_signals/exit_mm/exit_files/exit_fs/exit_task_work...
        → do_task_dead() → schedule()   // 不再返回
      父进程收 SIGCHLD(kernel/exit.c)
```

Common anchors of "suicide" detection: after an RASP hit, the descent runs from Java System.exit through native exit to direct svc; once the defense blocks the Java/native layers, the last stage can only be intercepted at the syscall (Stalker instruction rewriting/patching the so/kernel observation). SIGKILL-style termination cannot be intercepted in-process - only by an external watchdog/kernel observation.

### 5.2 Observation point table (the exit chain)

| Layer | Observation point | Means | Notes |
|---|---|---|---|
| Java | `Runtime.exit`/`System.exit` | frida Java.use | topmost; interceptable and redirectable |
| native | libc `exit`/`_exit`/`abort` | Interceptor | interceptable before atexit |
| syscall | `svc #0` (x8=94) | Stalker instruction-level tracing | the only user-space interception for direct svc calls |
| kernel | `kprobe:do_exit` / `tracepoint:sched:sched_process_exit` | bpftrace | reached even by direct svc; kstack gives the kernel path |

```bash
# 例4:exit 时打内核栈(kstack 可行;用户态/Java 栈需在进程内另取,内核侧拿不到)
bpftrace -e 'kprobe:do_exit /comm=="com.target.app"/ { print(kstack); }'
```

The kernel side only sees `do_exit`'s kernel call path (sys_exit_group->do_group_exit->do_exit); "which business line triggered the suicide" needs user-space hooks (frida backtrace) or the uprobe libart/so layer to fill in - the two evidence classes usually must be stitched together (`[unverified]`: bpftrace's ustack support on Android drifts by version/compile options).

## 6. Five-chain quick master table

| Chain | User-space entry | Kernel core functions (anchor files) | First-choice observation points |
|---|---|---|---|
| Binder call | BinderProxy.transactNative / IPCThreadState::transact | binder_ioctl->binder_transaction->binder_proc_transaction (drivers/android/binder.c) | kprobe:binder_transaction / tracepoint:binder:* |
| ServiceManager | ServiceManager.getService | handle==0->binder_context_mgr_node (binder.c) | same, predicate handle==0 |
| ptrace | ptrace(117) | ptrace_attach->__ptrace_may_access->__ptrace_link (kernel/ptrace.c); TracerPid output fs/proc/array.c task_state | kprobe:ptrace_attach; read-layer hooks |
| Signals | kill/tgkill (129/131) | do_send_sig_info->complete_signal->signal_wake_up_state (kernel/signal.c); delivery get_signal | tracepoint:signal:signal_generate/deliver |
| Exit | exit_group(94) | do_group_exit->do_exit->do_task_dead (kernel/exit.c) | tracepoint:sched:sched_process_exit |

## 7. Open items

1. The exact line order of binder_ioctl->binder_ioctl_write_read->binder_thread_write/read (googlesource pages truncated; the textbook path; anchors given).
2. The tail of tgkill->do_tkill->do_send_sig_info (si_code=SI_TKILL) (signal.c page truncated; do_send_sig_info).
3. Which vendor kernels carry the modern per-thread binder wait queue (&thread->wait) (old versions use &proc->wait).
4. The BINDER_SET_CONTEXT_MGR_EXT ioctl number and servicemanager usage details per version.
5. The TRANSACTION_code value of IPackageManager.getPackageInfo (varies with the AIDL version; check against the target's libframework jar/dex).
6. The exact errno of re-attaching an already-traced target (EPERM/EIO by convention).
7. The per-version spelling of libbinder mangled symbols (_ZN7android14IPCThreadState8transactE...); renames of ret_to_user/do_notify_resume in arm64's entry-common.c across versions.
8. The availability of bpf_probe_write_user in the target GKI kernel's helper whitelist (a precondition for the sec.1.7 kernel reply-rewrite scheme).
9. The exact wording of the one-line `ptrace_parent` (p->ptrace? p->parent : NULL) (semantics already confirmed by the task_state quotation).

## 8. Related documents

- 04-evasion/detection-landscape.md: the detection-surface checklist (this piece only adds the chains and kernel observation)
- 07-kernel/android-kernel-ebpf.md sec.2: the binder vulnerability attack surface; the bpftrace-on-Android environment
- 07-kernel/kernel-hook-stealth.md sec.2.3: wxshadow shadow pages (referenced by sec.3.5)
- 02-frida/java-layer/storage-and-system.md sec.9.1-9.3: the getPackageInfo Java hook and the PMS dynamic proxy (referenced by sec.1.7)
