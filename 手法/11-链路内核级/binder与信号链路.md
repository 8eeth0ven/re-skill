# Binder 与信号链路(内核级端到端)

> 定位:把五条对抗必经链路端到端展开到内核——Binder IPC 完整时序(双向)、ServiceManager 查找、ptrace 反调试、信号递送(SIGTRAP/SIGPIPE)、进程退出。检测面清单见 04-对抗攻防/检测原理全景.md,本篇写「链路与内核侧观测」;binder 漏洞攻击面简表见 07-内核级/Android内核与eBPF.md §2,本篇写完整时序。
> 措辞:攻防对称描述,机制中性。

## 0. 全景图

### 0.1 Binder 一次同步调用(双向)

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

### 0.2 信号与退出链一览

```
发信号: kill/tgkill → sys_tgkill → do_tkill/do_send_sig_info → __send_signal_locked
        → complete_signal → signal_wake_up_state{ set_tsk_thread_flag(TIF_SIGPENDING) }
递送:   返回用户态(ret_to_user 检查 _TIF_SIGPENDING) → do_notify_resume → do_signal
        → get_signal(被 trace 则先 ptrace_signal/ptrace_stop 给 tracer) → handler/默认行为
异常源: BRK 断点 → el0_dbg → do_el0_brk → send_user_sigtrap → SIGTRAP(TRAP_BRKPT)
退出:   exit_group(94) → do_group_exit → do_exit → do_task_dead → schedule(不返回)
```

## 1. 链1:Binder 调用完整时序(以 PackageManager.getPackageInfo 为例)

### 1.1 发起端:Java → libbinder

| 步 | 层 | 函数/对象 | 锚点 |
|---|---|---|---|
| 1 | Java API | `PackageManager.getPackageInfo(pkg, flags)` → `getPackageInfoAsUser` → `ActivityThread.getPackageManager` 返回缓存的 `IPackageManager` 代理 | frameworks/base/core/java/android/app/ApplicationPackageManager.java |
| 2 | AIDL 代理 | `IPackageManager$Stub$Proxy.getPackageInfo(...)`:参数写入 `Parcel data`,`mRemote.transact(Stub.TRANSACTION_getPackageInfo, data, reply, 0)` | dl 生成类(TRANSACTION_ 序号随版本变化,[]具体数值) |
| 3 | Java→JNI | `android.os.BinderProxy.transact` → `transactNative`(native 方法) | frameworks/base/core/java/android/os/Binder.java(BinderProxy 内部类) |
| 4 | JNI | `android_os_BinderProxy_transact`:取出 native 侧 `sp<IBinder>`(即 `BpBinder(handle)`)调 `transact` | frameworks/base/core/jni/android_util_Binder.cpp |
| 5 | libbinder | `BpBinder::transact` → `IPCThreadState::self->transact(handle, code, data, reply, flags)` | frameworks/native/libs/binder/BpBinder.cpp |
| 6 | 组包 | `writeTransactionData(BC_TRANSACTION, handle, code, data)`:`binder_transaction_data` 填入 write buffer(`data.ptr.buffer` 指向 client 自己 Parcel 的 mData 用户地址) | frameworks/native/libs/binder/IPCThreadState.cpp |
| 7 | 驱动交互 | `waitForResponse` → `talkWithDriver` → `ioctl(mDriverFD, BINDER_WRITE_READ, &bwr)`,无活则睡在驱动读侧 | IPCThreadState.cpp;fd/mmap 来自 `ProcessState::open_driver`+`mmap`(默认约 1MB-2页,PROT_READ) |
要点:binder mmap 区是 **只读用户映射**,"一次拷贝"发生在内核把 client 数据写进 server 的 mmap 页(server 读 `tr.data.ptr.buffer` 直接是本进程地址,不再拷第二次)。

### 1.2 进入内核:binder_ioctl → binder_transaction

源码锚点:

```
sys_ioctl(arm64 __NR_ioctl=29)
 → binder_ioctl(filp, BINDER_WRITE_READ, arg)        // file_operations
   → binder_ioctl_write_read(...)
     → binder_get_thread()                             // 按 task 找/建 binder_thread
     → binder_thread_write(proc, thread, bwr->write_buffer, ...)   // 消费写侧命令
        → BC_TRANSACTION/BC_REPLY → binder_transaction(proc, thread, &tr, reply, 0)
     → binder_thread_read(...)                         // 生产读侧命令(BR_*)
```

`binder_transaction` 内部关键步骤(非 reply、handle 非零路径):

```c
binder_proc_lock(proc);
ref = binder_get_ref_olocked(proc, tr->target.handle, true);   // handle → binder_ref
...
target_node = binder_get_node_refs_for_txn(ref->node, &target_proc, &return_error);
```

随后:`binder_alloc_new_buf`(drivers/android/binder_alloc.c)在**目标进程** binder_alloc 的空闲区分配 `binder_buffer`,把 `tr->data.ptr.buffer/offsets` 指向的 client 用户数据经 `binder_alloc_copy_user_to_buffer` 拷入目标 mmap 页;`offsets[]` 指示的 `flat_binder_object` 由驱动就地改写类型/引用(BINDER_TYPE_BINDER↔HANDLE 转换、fd 安放);若 `target_node->txn_security_ctx` 则 `security_secid_to_secctx` 附带 SELinux 上下文。安全上下文相关枚举/结构: `struct binder_transaction_data_secctx { struct binder_transaction_data transaction_data; binder_uintptr_t secctx; }`。

### 1.3 唤醒目标线程(server 侧醒来的路径)

`binder_transaction` 末尾调用 `binder_proc_transaction(t, target_proc, target_thread)`:

```c
if (!thread && !pending_async)
        thread = binder_select_thread_ilocked(proc);      // 挑一个可用 binder 线程
binder_enqueue_thread_work_ilocked(thread, &t->work);     // 挂到线程 todo 队列
binder_wakeup_thread_ilocked(proc, thread, !oneway /* sync */);
```

`binder_wakeup_thread_ilocked`:sync(双向事务)走 `wake_up_interruptible_sync(&thread->wait)`,oneway 走 `wake_up_interruptible(&thread->wait)`——**现代内核是每线程独立等待队列**(老版本挂在 `proc->wait`,[]目标内核归属);`thread==NULL` 时退化 `binder_wakeup_poll_threads_ilocked(proc, sync)`。被唤醒的是 system_server 里睡在 `ioctl(BINDER_WRITE_READ)` 读侧的 binder 线程(等价于 `wait_event_interruptible_*` 于 `binder_wait_for_work`)。

### 1.4 服务端执行与 BC_REPLY 回程

| 步 | 层 | 动作 | 锚点 |
|---|---|---|---|
| 1 | 内核→用户 | `binder_thread_read` 从 todo 取 `t->work`,生成 `BR_TRANSACTION`(带 secctx 时 `BR_TRANSACTION_SECCTX`)写入 `bwr->read_buffer`,`ioctl` 返回 | binder.c;命令定义 include/uapi/linux/android/binder.h |
| 2 | libbinder | `IPCThreadState::joinThreadPool/talkWithDriver` 收到命令 → `executeCommand(br)` | IPCThreadState.cpp |
| 3 | native 对象 | `((BBinder*)tr.cookie)->transact(code, &buffer, &reply, flags)` → `JavaBBinder::onTransact` | android_util_Binder.cpp |
| 4 | JNI→Java | `env->CallBooleanMethod(jobject, mExecTransactMethodCode, ...)` → `Binder.execTransact` → `Binder.onTransact` → `PackageManagerService.getPackageInfo`(查 PackageParser 缓存,组装 PackageInfo 写入 reply Parcel) | Binder.java / services/core/java/com/android/server/pm/PackageManagerService.java |
| 5 | 回程 | `sendReply` → `BC_REPLY` → `binder_transaction(reply=true)`:目标定为 client 等待线程(`thread->transaction_stack` 反查),同样拷入 client mmap + `binder_proc_transaction` 唤醒 client | binder.c |
| 6 | client 收尾 | `waitForResponse` 收 `BR_REPLY`,`reply->setData(tr.data.ptr.buffer, tr.data_size)` 直接引用 client mmap 区;消费后 `BC_FREE_BUFFER` 归还 | IPCThreadState.cpp |

### 1.5 关键结构体速查(uapi:include/uapi/linux/android/binder.h;内核:drivers/android/binder.h)

| 结构体 | 关键字段 | 作用一句话 |
|---|---|---|
| binder_write_read | write_size/write_buffer/write_consumed + read_size/read_buffer/read_consumed | ioctl 一次交互的读写双缓冲,驱动回填 consumed |
| binder_transaction_data | target(handle 或 ptr)、cookie、code、flags(TF_ONE_WAY 等)、sender_pid/sender_euid(内核回填发送者身份)、data_size/offsets_size、data.ptr(buffer/offsets) | 一次事务的元数据+数据指针;code 即 AIDL 方法号 |
| binder_proc | tsk/pid、threads(rb_tree)、nodes(rb_tree)、refs_by_desc/refs_by_node、todo、wait、is_dead、内嵌 binder_alloc(mmap 区) | 驱动里一个打开 /dev/binder 的进程全态 |
| binder_node | ptr/cookie(对端用户态 BBinder 地址)、proc(属主)、local_strong/weak_refs、has_async_transaction、txn_security_ctx、async_todo | 一个可被跨进程寻址的服务对象 |
| binder_ref | desc(即用户态 handle 值)、node、proc、strong/weak 计数、两棵 rb 索引 | 某进程持有某 node 的引用,handle↔node 的桥 |
| binder_buffer | entry/rb_node、target_node、data_size/offsets_size、data[0] | 事务数据缓冲;结构头+数据都直接放在目标进程 mmap 区里 |
命令号:`BC_TRANSACTION=_IOW('c',0,...)`、`BC_REPLY=_IOW('c',1,...)`、`BR_TRANSACTION=_IOR('r',2,...)`、`BR_REPLY=_IOR('r',3,...)`、`BR_TRANSACTION_SECCTX=_IOR('r',2,struct binder_transaction_data_secctx)`(与 BR_TRANSACTION 同 nr,靠结构体尺寸编码区分,解析时打印十六进制 cmd 最稳)。`BINDER_WRITE_READ=_IOWR('b',1,struct binder_write_read)`,64 位典型值 0xC0306201(以解码为准)。

### 1.6 观测点表(binder 调用链,四层)

| 层 | 观测点 | 手段 | 能拿到什么 |
|---|---|---|---|
| Java | `IPackageManager$Stub$Proxy.transact` / `BinderProxy.transact(transactNative)` | frida `Java.use("android.os.BinderProxy")`、代理 IPackageManager(见 02-frida/java层/存储与系统.md §9.1-9.3) | 反序列化前后的完整对象,最方便,也最容易被 Java 层完整性检测盯上 |
| libbinder | `IPCThreadState::transact` / `writeTransactionData` | uprobe `/system/lib64/libbinder.so` 符号(mangled 名逐版本核对,[]) | handle/code/flags;对目标进程零注入 |
| syscall | `ioctl` 入口 | frida Interceptor 挂 libc `ioctl`,按 `arg1==BINDER_WRITE_READ` 过滤 | bwr 原始字节;read_buffer 里即 BR_REPLY + parcel |
| 内核 | `kprobe:binder_transaction`、`tracepoint:binder:binder_transaction`(另有 binder_command/binder_return) | bpftrace/BCC,root | code/handle/data_size、`tr->data.ptr.buffer`(client 用户地址,current==client 可 probe_read_user);server 侧数据在 `t->buffer->data` = server mmap 用户地址,须在 server 上下文观测点读 |
**mmap 偏移在哪可读到数据(回答)**:client 侧看 `binder_transaction_data.data.ptr.buffer`(client 自己的 Parcel 用户内存);server 侧收到的数据就在 server 进程 `binder_alloc.buffer` 起、由 `binder_alloc_new_buf` 切出的 `binder_buffer->data` 处——同一份页既被内核写、也被 server 用户态只读映射,故在 server 进程上下文(kprobe `binder_thread_read` / uprobe `executeCommand`)读这段地址即可拿到零拷贝原文。
bpftrace 示例:

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

### 1.7 实战:binder 层伪造 getPackageInfo 返回

背景:RASP 常在 native 层走 **raw Binder**(绕开 Java PackageManager 对象)自查签名/包信息(检测原理全景.md §7.3「检测通道防 hook」),此时 Java 层 hook(含 §9.3 的 sPackageManager 动态代理)拦不到。等价对抗面下沉两档:
1. **用户态 ioctl 层**:在目标进程内 hook libc `ioctl`(或 uprobe),过滤 `BINDER_WRITE_READ`;对识别为 getPackageInfo 的调用(`binder_transaction_data.code` 比对,数值随版本 []),解析返回读缓冲的 `BR_REPLY` + parcel(长度前缀结构),**等长替换** signatures blob(长度不等需重建 parcel 并同步 data_size,代价高)。优点:Java 层无任何 hook 痕迹;缺点:需解析 parcel 格式、BC_FREE_BUFFER 语义要保真。
2. **内核层**:root 后用 kprobe/kretprobe 定位回包时刻,`bpf_probe_write_user` helper 改写本进程(current==client)用户内存里的 read_buffer——用户态零注入;属研究性质,粒度与稳定性需自验([]各内核 helper 可用性)。
3. 服务器侧改(system_server 内改 PMS 结果)影响全局,不在此推荐,仅指出存在性。
与 02-frida/java层/存储与系统.md §9.3 的分工:Java 代理方案对付「Java 层校验」;binder 层方案对付「native raw-binder 校验」;再往下(检测自己也直接解析 parcel + svc 化 ioctl)则只能内核观测/patch so。

## 2. 链2:ServiceManager 查找链

### 2.1 链路

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

handle 的本质:client `binder_ref->desc`;同一个服务在不同进程里 handle 值不同,`binder_node`(server 侧唯一)才是全局锚点。

### 2.2 观测点表(ServiceManager 链)

| 层 | 观测点 | 手段 | 备注 |
|---|---|---|---|
| Java | `ServiceManager.getService/rawGetService` | frida Java.use | 可看服务名与返回 BinderProxy 的 mObject(handle) |
| libbinder | `defaultServiceManager` / `getService` | uprobe libbinder.so | 命中框架侧全部查询 |
| syscall | ioctl 且 `tr.target.handle==0` | bpftrace 谓词 `$tr->target.handle==0` | 所有 context manager 流量(含 addService) |
| 内核 | `kprobe:binder_transaction` 过滤 handle==0;servicemanager 侧再按 `comm=="servicemanager"` 过滤 | bpftrace | 拿到 name 字符串(probe_read_user 于 client 上下文) |
常用系统服务入口(getService 的 name 参数,各版本有增减):

| name | 提供者 | 逆向价值 |
|---|---|---|
| activity / activity_task | system_server(ATMS/AMS) | startActivity、任务栈信息 |
| package | system_server(PMS) | 安装/签名/权限面 |
| window / display | system_server(WMS) | 窗口与叠层 |
| power / alarm / notification | system_server | 行为面较小 |
| telephony.registry | phone 进程 | 设备/网络状态 |
| media.audio_flinger | audioserver | 音频面 |
| SurfaceFlinger | surfaceflinger 进程 | 截屏/渲染面(非 system_server) |

## 3. 链3:ptrace 反调试链

### 3.1 调试器侧:attach 全链(arm64 __NR_ptrace=117)

源码锚点:kernel/ptrace.c。

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

`__ptrace_may_access` 的检查序列:同线程组直接放行;否则 RCU 下比对 caller uid 与目标 euid/suid/uid、gid 三元组全等;不等则 `ptrace_has_cap`(ns_capable CAP_SYS_PTRACE);再 `task_still_dumpable`(dumpable 状态,即 `prctl(PR_SET_DUMPABLE,0)` 的作用点);最后 `security_ptrace_access_check`(LSM/SELinux 钩子)。任何一步不过 → EPERM。
`__ptrace_link(child, new_parent, ptracer_cred)`:

```c
BUG_ON(!list_empty(&child->ptrace_entry));
list_add(&child->ptrace_entry, &new_parent->ptraced);
child->parent = new_parent;                  // 关键:parent 指向 tracer
child->ptracer_cred = get_cred(ptracer_cred);
```

`ptrace_traceme`(自附加用):`current->ptrace = PT_PTRACED; ptrace_link(current, current->real_parent);`。目标已被 trace 时再次 attach 被拒(惯例 EPERM,精确返回码 [])。

### 3.2 TracerPid 输出链(核对结论:代码在 array.c,不在 base.c)

- fs/proc/base.c 只做注册:`ONE("status", S_IRUGO, proc_pid_status)` 挂进 tgid_base_stuff/tid_base_stuff 表,经 proc_single_show 分发。
- 真正输出在 **fs/proc/array.c** 的 `task_state`(`proc_pid_status` 先打名字再调它):

```c
rcu_read_lock();
tracer = ptrace_parent(p);
if (tracer)
        tpid = task_pid_nr_ns(tracer, ns);
...
seq_put_decimal_ull(m, "\nTracerPid:\t", tpid);
```

`ptrace_parent(p)`(include/linux/ptrace.h)语义:`p->ptrace` 非零时返回 `p->parent`(即 §3.1 的 reparent 效果),否则 NULL——**TracerPid 的数据源就是 task->ptrace + task->parent 两个字段的组合**。这就是「改哪里能消 TracerPid」的内核依据。

### 3.3 自附加反调试与 frida spawn 时序

- 自附加:fork 子进程 `PTRACE_ATTACH`/`TRACEME` 链占住父进程 tracer 位(§3.1 的 ptrace_entry 非空)→ 后来者(IDA/gdb/lldb)attach 收 EPERM;同时 `task->ptrace` 恒非零 → TracerPid 恒非零,是双向效应:拦调试器,也留指纹。
- frida spawn 绕过早期检测的时序本质:spawn 模式下注入发生在 zygote fork 出新进程后、Application/so 的反调试初始化**执行之前**(gating 在入口早期);attach 模式则必须撞上已占用的 tracer 位。spawn 后立刻 hook `ptrace`(libc+svc 两条)与 `sigaction`,可把自附加子进程的后续动作静默;若检测已跑完,attach 收 EPERM,只剩 spawn 重启或内核方案。

### 3.4 对抗观测点表(ptrace/TracerPid)

| 层 | 观测/干预点 | 手段 | 说明 |
|---|---|---|---|
| 用户态 proc 读层 | `open/read/fgets` 读 /proc/self/status | hook 后改写缓冲区中 TracerPid 一位(等长) | svc 化 openat+read 时失效(检测原理全景.md §2.9) |
| 用户态 proc 读层(等价信号) | `/proc/self/task/<tid>/stat` state 列、wchan、waitpid | 同上 | RASP 常多文件交叉,只改一处不够 |
| 内核 ptrace 层 | `kprobe:ptrace_attach` | bpftrace 记录 tracer pid/comm | 只观测;kprobe 无法改返回值 |
| 内核决策层 | `bpf_lsm/ptrace_access_check` 返回 -EPERM | BPF LSM(需 CONFIG_BPF_LSM) | 可主动拒绝陌生 tracer(研究向) |
| proc 输出层 | seq_file 输出(task_state/proc_pid_status) | LKM/KPM inline hook 改 tpid 输出 | 见 §3.5 对比 |

### 3.5 TracerPid 的「完全内核解」对比

| 方案 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| 过滤 proc 输出 | hook `task_state`(或 seq 读层)把 tpid 置 0 | 不动调度语义,调试器仍正常工作 | 漏网面大:等价信号(stat state=t、wchan、waitpid、其它读 task 的接口)要逐个补 |
| 改 task_struct | 清 `task->ptrace`/摘 `ptrace_entry`/恢复 `parent` | 数据源层面消失,所有读法一起消失 | 破坏真实跟踪语义,事件交付(wait)紊乱,维护成本高 |
| 换断点机制 | 不用 ptrace:影子页无痕断点(**wxshadow**,07-内核级/内核Hook与无痕对抗.md §2.3:PTE 重定向/BRK #0x7/GUP 隐藏) | task->ptrace 恒 0,TracerPid 天然干净,prologue 校验读原页不命中 | 需要 root/KPM 环境 |

## 4. 链4:信号链(SIGTRAP/SIGPIPE 反调试)

### 4.1 发送链(arm64:kill=129,tkill=130,tgkill=131)

kernel/signal.c(tgkill/tkill 尾部被截断,内层 do_tkill 链为通用事实):

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

### 4.2 递送链(返回用户态)

arm64 返回路径(ret_to_user 检查 `thread_flags & _TIF_SIGPENDING` → `do_notify_resume` → `do_signal(regs)`,函数名随版本有调整,锚点 arch/arm64/kernel/entry-common.c、arch/arm64/kernel/signal.c):

```
do_signal → get_signal(&ksig)(kernel/signal.c):
  dequeue_signal 取信号
  → 若 current->ptrace 且非 SIGKILL 且非 SA_IMMUTABLE:
        signr = ptrace_signal(...) → ptrace_stop(signr, CLD_TRAPPED, ...)
        「We're back. Did the debugger cancel the sig?」——tracer 先看:
        tracer 不转发(signr==0)→ 信号被丢弃;改号/被阻塞 → 重排队
  → SIG_DFL 走默认行为 / 否则 handle_signal → setup_rt_frame → 用户态 handler
```

**「调试器吃掉信号」的内核机制就是这一段**:被 trace 的任务,任何非 IMMUTABLE 信号先 `ptrace_stop` 交给 tracer,gdb/IDA 默认不回注,app 的 handler 永远收不到。

### 4.3 SIGTRAP 来源与断点自检检测

arm64 BRK 异常(arch/arm64/kernel/debug-monitors.c):

```c
do_el0_brk():先试 uprobes(UPROBES_BRK_IMM),否则
send_user_sigtrap(TRAP_BRKPT) → arm64_force_sig_fault(SIGTRAP, TRAP_BRKPT,
                     instruction_pointer(regs), "User debug trap");
32 位:do_bkpt32 → arm64_notify_die("aarch32 BKPT", ..., SIGTRAP, TRAP_BRKPT, ...);
EL1 未处理 BRK → die("Oops - BRK")。旧内核对应 el0_dbg→brk_handler→force_sig_fault 路径。
```
- **单步**:PTRACE_SINGLESTEP 置 PSTATE.SS(硬件单步)→ 步进异常 → SIGTRAP(TRAP_TRACE)。检测侧只能靠时延/行为侧信道感知,用户态读不到 mdscr_el1。
- **断点自检检测原理**:app 先 `sigaction` 注册 SIGTRAP handler,再在自己代码里主动执行 `brk #0`(或 raise/tgkill 自己)——正常时 handler 执行并置标志(§4.2 正常递送);被 ptrace 型调试器跟踪时走 `ptrace_signal`→`ptrace_stop`,tracer 默认吞掉,handler 不执行 → 标志缺失 → 判定被调试。对抗:让 tracer 转发 SIGTRAP(gdb `handle SIGTRAP nostop pass` 思路),或改用不依赖 ptrace 的断点机制(wxshadow 影子页,被校验页读原指令,连 prologue CRC 都不命中)。

### 4.4 SIGPIPE

来源:向已关闭的管道/socket 写,内核在写路径发 SIGPIPE(net/ipv4/tcp.c tcp_sendmsg_locked、fs/pipe.c,MSG_NOSIGNAL 可抑制)。检测用法:app 注册 SIGPIPE handler 并周期向受监控 socket/pipe 写,若 handler 未按预期执行(被 tracer 截胡或进程状态异常)→ 看门逻辑判定异常/自杀。弱于 SIGTRAP 自检,常作组合信号之一。

### 4.5 观测点表(信号链)

| 层 | 观测点 | 手段 | 说明 |
|---|---|---|---|
| 用户态注册层 | `sigaction`/`rt_sigaction`(arm64 __NR_rt_sigaction=134) | frida Interceptor | 看 app 注册了哪些 handler(=检测意图清单) |
| 用户态发送层 | `raise`/`kill`/`tgkill`(libc) | Interceptor | 自测型反调试会在这里现形 |
| 内核发送层 | `kprobe:do_send_sig_info` / `tracepoint:signal:signal_generate` | bpftrace | 看谁给谁发什么信号,svc 直调也逃不掉 |
| 内核递送层 | `kprobe:get_signal` / `tracepoint:signal:signal_deliver` | bpftrace | handler 是否真执行、是否被 ptrace_stop 截胡 |

```bash
# 例3:观测 SIGTRAP(5) 的产生与目标
bpftrace -e 'tracepoint:signal:signal_generate /args->sig==5/ {
  printf("sig=%d target_pid=%d target=%s from=%s\n", args->sig, args->pid, args->comm, comm); }'
```

## 5. 链5:进程异常退出链(exit/kill 检测与自杀)

### 5.1 链路(arm64:exit=93,exit_group=94)

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

「自杀」检测的常见锚位:RASP 命中后从 Java System.exit、native exit 到 svc 直调分层下探;对抗侧拦 Java/native 层后,最后一级只能拦 syscall(Stalker 改指令/patch so/内核观测)。SIGKILL 型终止无法在进程内拦截,只能由外部看门/内核观测。

### 5.2 观测点表(退出链)

| 层 | 观测点 | 手段 | 说明 |
|---|---|---|---|
| Java | `Runtime.exit`/`System.exit` | frida Java.use | 最上层,拦截后可改走 |
| native | libc `exit`/`_exit`/`abort` | Interceptor | atexit 前可拦 |
| syscall | `svc #0`(x8=94) | Stalker 指令级跟踪 | svc 直调唯一用户态拦法 |
| 内核 | `kprobe:do_exit` / `tracepoint:sched:sched_process_exit` | bpftrace | svc 直调也必然到达;kstack 给内核路径 |

```bash
# 例4:exit 时打内核栈(kstack 可行;用户态/Java 栈需在进程内另取,内核侧拿不到)
bpftrace -e 'kprobe:do_exit /comm=="com.target.app"/ { print(kstack); }'
```

内核侧只看得到 `do_exit` 的内核调用路径(sys_exit_group→do_group_exit→do_exit);「哪行业务触发的自杀」要靠用户态 hook(frida backtrace)或 uprobe libart/so 层补齐——两类证据常需拼合([]:bpftrace 在 Android 上 ustack 支持随版本/编译选项浮动)。

## 6. 五链速查总表

| 链 | 用户态入口 | 内核核心函数(锚点文件) | 首选观测点 |
|---|---|---|---|
| Binder 调用 | BinderProxy.transactNative / IPCThreadState::transact | binder_ioctl→binder_transaction→binder_proc_transaction(drivers/android/binder.c) | kprobe:binder_transaction / tracepoint:binder:* |
| ServiceManager | ServiceManager.getService | handle==0→binder_context_mgr_node(binder.c) | 同上,谓词 handle==0 |
| ptrace | ptrace(117) | ptrace_attach→__ptrace_may_access→__ptrace_link(kernel/ptrace.c);TracerPid 输出 fs/proc/array.c task_state | kprobe:ptrace_attach;读层 hook |
| 信号 | kill/tgkill(129/131) | do_send_sig_info→complete_signal→signal_wake_up_state(kernel/signal.c);递送 get_signal | tracepoint:signal:signal_generate/deliver |
| 退出 | exit_group(94) | do_group_exit→do_exit→do_task_dead(kernel/exit.c) | tracepoint:sched:sched_process_exit |

## 7.汇总

1. binder_ioctl→binder_ioctl_write_read→binder_thread_write/read 的精确行序(googlesource 页面截断,教科书路径,锚点已给)。
2. tgkill→do_tkill→do_send_sig_info(si_code=SI_TKILL)尾部(signal.c 页面截断;do_send_sig_info)。
3. 现代内核 binder 每线程等待队列(&thread->wait)在目标厂商内核的落地版本(老版为 &proc->wait)。
4. BINDER_SET_CONTEXT_MGR_EXT 的 ioctl 号与 servicemanager 各版本使用细节。
5. IPackageManager.getPackageInfo 的 TRANSACTION_code 数值(随 AIDL 版本,需在目标机 libframework jar/dex 对)。
6. 已被 trace 的目标再次 attach 的精确 errno(EPERM/EIO 惯例)。
7. libbinder mangled 符号(_ZN7android14IPCThreadState8transactE...)逐版本拼写;arm64 entry-common.c 的 ret_to_user/do_notify_resume 函数名随版本改名。
8. bpf_probe_write_user 在目标 GKI 内核 helper 白名单的可用性(§1.7 内核改回包方案前置条件)。
9. `ptrace_parent` 一行实现(p->ptrace? p->parent : NULL)的确切写法(语义已由 task_state 引文确认)。

## 8. 关联文档

- 04-对抗攻防/检测原理全景.md:检测面清单(本篇只补链路与内核观测)
- 07-内核级/Android内核与eBPF.md §2:binder 漏洞攻击面;bpftrace on Android 环境
- 07-内核级/内核Hook与无痕对抗.md §2.3:wxshadow 影子页(§3.5 引用)
- 02-frida/java层/存储与系统.md §9.1-9.3:getPackageInfo Java hook 与 PMS 动态代理(§1.7 引用)
