# The Full-Chain Observation-Point Matrix and Three Usage Paths (area 11 wrap-up)

> Positioning: gathers the scattered points of area 09 (function layering/hook fallback), area 07 (kernel hooks/eBPF/symbol locating), area 03 (eBPF unpacking), and areas 05/08 (tool matrix/AI ecosystem) into **one lookup-ready master table of observation points** + three end-to-end usage paths + a reverse quick reference. It answers three questions: at which layer a target action is visible (sec.2 matrix), where to fall back to when detected (sec.1 decision tree), and which point to attach first when a task lands (sec.4 quick reference).
> References: "[android-function-layers.md](../09-function-map/android-function-layers.md)", "[hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md)", "[kernel-hook-stealth.md](../07-kernel/kernel-hook-stealth.md)", "[kernel-symbol-locating.md](../07-kernel/kernel-symbol-locating.md)", "[android-kernel-ebpf.md](../07-kernel/android-kernel-ebpf.md)", "[ebpf-unpacking-deep.md](../03-unpacking/ebpf-unpacking-deep.md)", "[ai-re-tools.md](../08-ai-re/ai-re-tools.md)".

## 1. The observation-point layering model (a five-layer tool stack)

The five layers = the **tool-side projection** of area 09's L1-L5 layering. One paragraph per layer: tools / applicable targets / information available / detection exposure / cost.

### L1 frida (Java + libc symbols)

- **Tools**: frida `Java.use` replacement, `Interceptor.attach(Module.findExportByName(...))`.
- **Applicable targets**: public framework APIs and the symbol-bearing system libraries libart/libjavacore/libcrypto etc. (the symbol surfaces of area 09's L1/L2/L3).
- **Information available**: complete - Java objects are deserializable; arguments/return values/call stacks (`Thread.backtrace`) all captured; on the native side x0-x7 are the args.
- **Detection exposure**: the largest. frida-server process/port (27042), the injected agent's maps (rwxp/so), thread names (gum-js-loop/gmain/pool-frida-), TracerPid, Java-layer hook frames. Area 09's "hook-fallback playbook" sec.4 strength table: every typical detection method hits.
- **Cost**: the lowest. Ready-made scripts abound (area 02 quick refs); results within minutes.

### L2 frida (no symbols: signature scanning / Stalker)

- **Tools**: `Memory.scanSync` signature locating (the BoringSSL string `42 6F 72 69 6E 67 53 53 4C`, AESE bytes `?? 48 28 4E`, scanning svc for `01 00 00 D4`) + inline hook by address; `Stalker.follow` to capture svc (x8 distribution) and call chains.
- **Applicable targets**: so files with statically compiled boringssl/libc, self-unpacking loaders, direct svc invocation (area 09 fallback cases 5/1/6).
- **Information available**: register-level (x8=number, x0-x5=args, x0=return), but untyped - structures must be reconstructed by hand; Stalker overhead is heavy, short windows only.
- **Detection exposure**: inline-hook byte changes can be caught by CRC self-checks; Stalker slows execution -> measurable by double-read timing deltas (area 09 sec.4: the L4 row "medium-high").
- **Cost**: medium. Do the five-way layer test first (so dependencies/import table/memory svc scan/strace diff) before acting.

### L3 eBPF uprobe (any user-space address) + kprobe (syscalls / kernel exports)

- **Tools**: bpftrace (NDK cross-compile patch set, area 07's android-kernel-ebpf.md sec.5) / libbpf CO-RE programs; uprobe on so offsets (symbols optional), kprobe on `sys_*`/`__sys_*` kernel functions.
- **Applicable targets**: any behavior that passes through a syscall (including direct svc invocation - the kernel entry is the master gate nothing skips); any user-space function, via uprobe, without injection.
- **Information available**: uprobe: arg0-arg7/retval map automatically; with BTF, bpftrace reads struct fields (`kprobe:binder_transaction` + `struct binder_transaction_data*`). Helpers: `bpf_probe_read_user/_kernel`. **Read-mostly**; return rewriting is restricted by the `bpf_override_return` whitelist (area 09 sec.3.4).
- **Detection exposure**: nearly zero against the app - zero injection, zero threads, zero ptrace (area 03's eBPF unpacking sec.1.2 comparison table); the audit surface lives only in root-side tracefs.
- **Cost**: medium-high. root + CONFIG_UPROBES/BTF; ART-internal offsets are version-sensitive.

### L4 ftrace / fentry + kallsyms (any kernel function)

- **Tools**: tracefs (kprobe/ftrace filter), `BPF_PROG_TYPE_TRACING` fentry/fexit (bpftrace `kfunc:`/`kretfunc:`), LKM/KPM. Prerequisites = the five symbol-locating routes (area 07's kernel-symbol-locating.md sec.2: official GKI vmlinux / vmlinux-to-elf / kprobe lookup / available_filter_functions / string xref) + the KASLR slide (sec.3).
- **Applicable targets**: any kernel function (binder internals, scheduling, page-table paths); fentry is an order of magnitude faster than kprobe and captures entry/exit args and return values (the comparison table in area 07's kernel-hook-stealth.md sec.1).
- **Information available**: the fullest (kernel-mode viewpoint); fentry needs BTF (GKI 5.15+ ships it), otherwise fall back to kprobe.
- **Detection exposure**: invisible to the app (the app has no bpf/tracefs/CAP_SYS_ADMIN privileges); the residue is only timing side channels and another root observer (area 07 sec.6/sec.8).
- **Cost**: high. root + symbols + CFI handling (when changing execution flow).

### L5 wxshadow / KPM (stealth breakpoints / physical pages)

- **Tools**: wxshadow (KPM, W^X shadow-page breakpoints), the mkpms-stealth four-in-one (hide-maps/kload/wxshadow/dbc-rw), KernelPatch inline hook, the android-kernel-hacking-toolkit LKMs, perf_event hardware breakpoints (area 07's kernel-symbol-locating.md sec.6, zero byte modification).
- **Applicable targets**: targets needing argument/return rewriting even under the strongest RASP (CRC self-checks, GUP comparisons, anti-root scans).
- **Information available**: full register capture (x0-x30/sp/pc/pstate) + shadow-page instruction patching + register rewriting (area 07's kernel-hook-stealth.md sec.2.3).
- **Detection exposure**: structurally minimal - the breakpoint lives only on the shadow physical page; read paths (GUP/`/proc/PID/mem`) see the original page; the only universal residue is the timing side channel (area 07 sec.6/sec.8).
- **Cost**: the highest. An APatch/KP environment + kernel-version adaptation (the 6.12 engineering points in area 07 sec.2.3).

### 1.1 Layer-selection decision tree

```
目标动作在哪层可见?(查 §2 矩阵该行,先跑判层五法:so 依赖/导入表/扫 svc/Stalker x8 分布/strace)
│
├─ 三大特例(不落 svc):属性读 / vDSO 时间 / 用户态加密
│    → 属性:改 /dev/__properties__ 共享内存(09 区案例 3)
│    → 时间:patch __vdso_clock_gettime 或时间补偿(09 区案例 4)
│    → 加密:L1 doFinal / 特征码定位静态实现(09 区案例 5);L3/L4/L5 对其 N/A
│
├─ Java/符号层可见(有导出符号)
│    → L1 frida 直接挂 ──被检?──→ 隐蔽化(strongR 改名改端口 / gadget)
│         仍被检(Java 栈扫描)→ 降半层挂 L2 导出(libjavacore/libart,少人防)
│         CRC 校验字节 → L3 eBPF uprobe(同一符号零注入)
│
├─ 无符号 so(静态编译/自实现)
│    → L2 特征码 + 按地址 hook;或 L3 uprobe 偏移(IDA 定位)
│
├─ svc 直调(内核入口前的层全漏)
│    → L2 Stalker 抓 svc(短窗口);或 L3 kprobe sys_*/tracepoint(全局,含直调)
│
└─ 用户态手段全灭(RASP 最强档)
     → L4 fentry/kprobe 观测 + L5 wxshadow/KPM 改写;binder 深挖走内核符号定位五路(07 区)
```

Fallback path chart (read horizontally: left->right is the fallback direction; parentheses hold the failure signal of that step):

```
Java hook ─(栈扫描/CRC)→ L2 导出符号 ─(GOT 校验)→ L3 uprobe ─(需要改写)→ L5 wxshadow
libc hook ─(svc 直调)→ Stalker/ptrace BRK ─(性能/痕迹)→ L3 kprobe ─→ L4 fentry
libc hook ─(字节 CRC)→ L3 uprobe(不改目标字节)或 L5 影子页(读了也看不见)
```

Cross-layer switching notes (one line per layer: when NOT to use it):

| Layer | Scenarios where it's the wrong tool | Switch to |
|---|---|---|
| L1 frida symbols | Target is a native so with no exports; the Java layer is reflection-scanned | L2 signatures / L3 uprobe |
| L2 signatures/Stalker | Long-duration stable observation needed (Stalker is short-window only); need a cross-process global view | L3 kprobe/tracepoint |
| L3 eBPF | Target action never reaches a syscall (property reads/vDSO time/crypto); need to rewrite return values | L1/L2 (user space) or L5 (rewriting) |
| L4 ftrace/fentry | Need in-process argument/return changes (fentry observes only) | L5 wxshadow/KPM |
| L5 wxshadow/KPM | No root / kernel version unadapted (outside 6.12, verify engineering points yourself); just want a quick look | Drop back to L3 |

## 2. The full-chain observation-point master matrix

Column key: **Java hook**=L1 framework; **libc hook**=L2 system-library exports (libart/libjavacore/libbinder...) + L3 libc merged; **svc interception**=L4 Stalker/ptrace breaking on svc; **uprobe point**=eBPF user space (symbol or offset); **kprobe/tracepoint point**=eBPF kernel-mode events; **ftrace point**=kernel functions attachable via tracefs/fentry; **stealth point**=wxshadow/KPM breakpoint addresses. "-" = no anchor for this action at that layer (pass-through between layers or purely user-space), reason attached.

| Chain | Java hook | libc/so hook | svc interception | uprobe point | kprobe/tracepoint point | ftrace point | stealth point |
|---|---|---|---|---|---|---|---|
| 1 File read | `FileInputStream.read` | `Java_libcore_io_Posix_open/read` (libjavacore), `openat/read` (libc) | x8=56/63 (path in x1) | `openat`/`read` (libc symbols) | `kprobe:sys_openat`/`sys_exit_openat`; `tracepoint:syscalls/sys_enter_openat` | `do_sys_openat2`->`do_filp_open`; `ksys_read`->`vfs_read` | wxshadow on libc `openat` or kernel `do_sys_openat2` |
| 2 /proc self-check reads | `File.exists` | same as above; filter maps/status content after `read` | 56+63 (the only solution when direct-invoked) | `openat` (filter path `/proc/self/`) | `kprobe:sys_openat` filtering filename | `pid_maps_open`->`proc_maps_open`; `show_map` (seq_file; on 5.7+ base.c REG files mount a dedicated table directly, bypassing the proc_reg layer - see the file-attr-chain.md sec.2.2 clarification) | wxshadow breakpoint + KPM hide-maps filtering output |
| 3 Directory enumeration | `File.listFiles` | `getdents64` (libc) | x8=61 | `getdents64` | `tracepoint:syscalls/sys_enter_getdents64` | `sys_getdents64` (version-dependent) | wxshadow on `getdents64`, rewrite buffer |
| 4 Property read | `SystemProperties.get` (@hide reflection) | `__system_property_get/__system_property_find/__system_property_read_callback` | **none** (shared-memory direct read, zero syscalls) | `__system_property_get` (covers only libc callers) | `kprobe:sys_mmap` filtering `/dev/__properties__` (intercepts initialization only) | - (the kernel has no property system) | Modify prop_info value directly (area 09 case 3); wxshadow on `__system_property_get` |
| 5 Property write | `SystemProperties.set` | `__system_property_set` (unix socket to init) | connect+write to `/dev/socket/property_service` | `__system_property_set` | kprobe `__sys_connect` filtering netd/init sockets | - | KPM propedit (kernel writes user pages) |
| 6 connect | `Socket.connect` | `Java_libcore_io_Posix_connect` (libjavacore), `connect` (libc) | x8=203 (sockaddr in x1) | `connect` | `kprobe:__sys_connect`; `tracepoint:syscalls/sys_enter_connect` | `__sys_connect`->`inet_stream_connect` (af_inet.c) | wxshadow on libc `connect`, rewrite return |
| 7 send/recv | `OutputStream.write` (socket) | `Java_libcore_io_Posix_sendto/recvfrom`, `sendto/recvfrom/sendmsg/recvmsg` (libc) | x8=206/207/211/212 | `sendto`/`recvfrom` | `tracepoint:net:net_dev_queue` (send side) | `__sys_sendto`->`sock_sendmsg` | wxshadow breakpoint; eBPF response rewriting (the VoidLink route) |
| 8 DNS resolution | `InetAddress.getByName` | `getaddrinfo/gethostbyname` (libc resolver; via the netd socket, path varies by version) | 203+211/212 (netlink/netd traffic) | `getaddrinfo` | `kprobe:__sys_connect` filtering netd; `tracepoint:net:net_dev_queue` | `__sys_connect` (netd destination) | wxshadow on `getaddrinfo` |
| 9 binder client | `IPackageManager$Stub$Proxy`->`BinderProxy.transact` (framework) | `IPCThreadState::transact/talkWithDriver` (libbinder), `ioctl` (libc) | x8=29, fd=/dev/binder, BC_TRANSACTION | `ioctl` (filter by handle+code) | `tracepoint:binder/binder_transaction` (binder_trace.h CONFIG) | `kprobe:binder_ioctl`->`binder_thread_write`->`binder_transaction` | wxshadow/KPM on `binder_transaction` (dump parcel; area 07's kernel-symbol-locating.md sec.4) |
| 10 binder server | `XXX$Stub.onTransact` (AIDL) | `IPCThreadState::joinThreadPool`/`getAndExecuteCommand` (libbinder) | x8=29 (BR_TRANSACTION read-back) | same `ioctl` | same; `kprobe:binder_thread_read` | `binder_ioctl_write_read` (area 07's android-kernel-ebpf.md sec.2 chain) | same |
| 11 ptrace detection | - (no Java API) | `ptrace` (libc) | x8=117 | `ptrace` | `kprobe:sys_ptrace`/`ptrace_attach` | `sys_ptrace`->`__ptrace_may_access` | The detecting side reads status TracerPid -> use row 2 filtering; wxshadow has no ptrace surface |
| 12 Signal self-traps | - | `signal/sigaction`, `kill/tgkill`, `pthread_kill` | x8=134 (rt_sigaction)/129/131 | `sigaction` | `kprobe:sys_rt_sigaction`; `tracepoint:signal:signal_generate` (version-dependent) | `sys_kill`->`kill_something_info` | wxshadow on `rt_sigaction` (direct svc still escapes rewriting the kernel side -> L4 fentry) |
| 13 exit | `System.exit`/`Process.killProcess` | `exit/_exit` (libc) | x8=93 (exit)/94 (exit_group) | `exit_group` | `tracepoint:sched/sched_process_exit`; `kprobe:sys_exit_group` | `do_group_exit`->`do_exit` | wxshadow on `exit_group` to see the scene before exit |
| 14 zygote fork | `ZygoteProcess.start` (framework) | `nativeForkAndSpecialize` (libandroid_runtime, symbol name), `fork` (= a clone wrapper) | x8=220 (clone)/435 (clone3) | `clone` (libc) | **`tracepoint:sched/sched_process_fork`** (observes all process/thread creation, direct calls included) | `sys_clone`->`kernel_clone` (pre-5.9 named `_do_fork`)->`copy_process` | KPM on `kernel_clone`; wxshadow on libc `fork` |
| 15 Thread creation | `Thread.start` | `JVM_StartThread` (libart), `pthread_create` (libc) | x8=220 (apps calling clone directly to bypass pthread hooks, area 09 case 6) | `pthread_create` | `tracepoint:sched/sched_process_fork` | `kernel_clone`->`copy_process` | wxshadow on `pthread_create`; thread-name surface -> prctl (167) |
| 16 so loading | `System.loadLibrary/load` | `Java_java_lang_Runtime_nativeLoad` (libart, symbol), `dlopen/android_dlopen_ext` (libdl/libc) | 56 (openat .so)+222 (mmap) | `android_dlopen_ext`; linker `__dl__ZN6soinfo17call_constructorsEv` (area 02 quick ref 1.15) | `kprobe:sys_openat` filtering .so paths | `do_filp_open`; `vm_mmap_pgoff` | wxshadow on `android_dlopen_ext` (timing earlier than attach - must spawn) |
| 17 init_array | - (linker-internal sequence) | `__dl__ZN6soinfo17call_constructorsEv` (linker export) | - (init_array execution passes no syscall) | linker `call_constructors` or init-function offsets | - | - | wxshadow on the init function's first address (place before load) |
| 18 malloc/free | - (Unsafe limited) | `malloc/free/calloc/realloc` (libc; backend scudo, A11+) | - (small blocks, no syscall; large blocks mmap->222/brk->214) | `malloc` (high-volume; short-window sampling only) | `tracepoint:kmem/mm_page_alloc` (page-level approximation, not malloc-level) | `sys_brk`; `vm_mmap_pgoff` | wxshadow on `malloc` to grab plaintext keys (area 09 sec.5 hint) |
| 19 mmap/mprotect | `ByteBuffer.allocateDirect` | `mmap/munmap/mprotect/madvise` (libc) | x8=222/215/226/233 | `mmap`/`mprotect` | `kprobe:sys_mmap`/`sys_mprotect`; `tracepoint:syscalls/sys_enter_mprotect` | `sys_mmap`->`ksys_mmap_pgoff`->`vm_mmap_pgoff`; `do_mprotect_pkey` | wxshadow on `mprotect` (the signal of a packer unlocking its code section, area 09 sec.5) |
| 20 Page faults | - | `sigaction(SIGSEGV)` custom handler (observes only faults the app already owns) | - (faults trap in the CPU; no user-space svc) | - | perf_event `PERF_COUNT_SW_PAGE_FAULTS`; `tracepoint:exceptions:page_fault_user` (arm64) | `do_page_fault`->`handle_mm_fault` (arm64 entry names vary by version) | KPM on `handle_mm_fault`; the perf_event hardware-breakpoint family (area 07's kernel-symbol-locating.md sec.6) |
| 21 dex loading | DexFile ByteBuffer constructor route (area 03's dex unpacking) | `_ZN3art7DexFileC1/C2` (x1=base), `_ZN3art13DexFileLoader7OpenOne` (A15+ source first param header_offset; x1 shape to re-verify on-device - the dex-load-exec-chain.md sec.1.2 correction) | - (purely user-space; file side goes 56+63) | **`uprobe:libart.so` DexFile::DexFile ctor / DexFileLoader::OpenOne** (area 03 sec.4.1) | `kprobe:sys_mmap` (indirect; no user-space semantics) | - (user-space functions) | wxshadow on ctor offsets (A16/17 symbols stripped -> string-xref locating) |
| 22 DefineClass | - (frida on libart symbols; 5th param=DexFile&, area 03 sec.4) | `_ZN3art11ClassLinker11DefineClass...` (libart) | - | same symbol uprobe | - | - | wxshadow on DefineClass (dump begin_/size_) |
| 23 Nterp execution | - | `ExecuteNterpImpl`/`ExecuteNterpWithClinitImpl`/`nterp_op_invoke_*` (A15+ stripped -> offsets, area 03 sec.4.4) | - | **uprobe offsets** (`--nterp-offset`); x0=ArtMethod* (area 03 sec.4.3) | - | - | wxshadow on offsets; perf_event hardware breakpoints (zero bytes) |
| 24 JNI registration | - | `art::JNI<false>::RegisterNatives` (libart export/offset) | - | **uprobe** (PARM3=JNINativeMethod*, PARM4=count, area 03 sec.3.2) | - | - | wxshadow on RegisterNatives to rewrite the registration table |
| 25 JNI strings | - | `art::JNI::GetStringUTFChars` (libart; mangled `_ZN3art3JNI21GetStringUTFCharsEP7_JNIEnvP8_jstringPh*`, area 07's android-kernel-ebpf.md sec.5) | - | **uprobe+uretprobe pair** (str(retval)=UTF-8 contents) | - | - | wxshadow on the return address; jniq for vtable slots (0x520->GetStringLength) |
| 26 cert loading/validation | `X509TrustManager.checkServerTrusted`, `TrustManagerImpl.checkTrustedRecursive` (conscrypt) | `NativeCrypto_*` (libjavacrypto); in so `SSL_CTX_set_verify/SSL_get_verify_result/X509_verify_cert` (libssl/libcrypto or static) | - (purely user-space; network side via rows 6/7) | `X509_verify_cert`/`SSL_CTX_set_verify` (area 04's ssl-pinning bypass sec.2) | - | - | wxshadow on `X509_verify_cert` forcing X509_V_OK |
| 27 crypto EVP | `Cipher.doFinal/Mac/MessageDigest` | `Java_com_android_org_conscrypt_NativeCrypto_*` (libjavacrypto), `EVP_CipherUpdate/EVP_DigestUpdate` (libcrypto) | **no syscall** (area 09 special case 3) | `EVP_CipherUpdate` (statically compiled -> signature+offset, area 09 case 5) | - | - | wxshadow on update (plaintext is in the input args) |
| 28 getrandom | `SecureRandom.nextBytes` | `RAND_bytes` (libcrypto), `getrandom` (libc) | x8=278 | `getrandom`/`RAND_bytes` | `kprobe:sys_getrandom` | `sys_getrandom`->`__do_sys_getrandom` (6.x name) | Fixed return -> wxshadow rewrites the x0 buffer |
| 29 Time reads | `System.currentTimeMillis/SystemClock.uptimeMillis` | `JVM_CurrentTimeMillis/JVM_NanoTime` (libart), `clock_gettime` (libc, **vDSO preferred**) | x8=113/169 (normally never hits svc! absorbed by vDSO, area 09 special case 2) | `clock_gettime` (covers libc callers only) | `kprobe:sys_clock_gettime` (a hit means direct invocation = anomaly signal) | `sys_clock_gettime` (posix-timers.c) | patch `__vdso_clock_gettime` (area 09 case 4); KPM kernel-time offset |
| 30 Cross-process R/W | - | `process_vm_readv/writev` (libc) | x8=270/271 | `process_vm_readv` | `kprobe:sys_process_vm_readv` | `sys_process_vm_readv` | **wxshadow GUP hiding** (`follow_page_pte` hook; read paths see the original page, area 07 sec.2.3) |
| 31 execve (spawning children) | `Runtime.exec` (ProcessBuilder) | `Java_libcore_io_Posix_forkAndExec`? (libjavacore)->`execve` (libc) | x8=221 | `execve` | `tracepoint:syscalls/sys_enter_execve` | `sys_execve`->`do_execveat_common` (old name `__do_execve_file`, version-dependent) | wxshadow on `execve`; KPM hideproc to hide the child |
| 32 Reaping children | `Process.waitFor` | `waitpid/wait4` (libc) | x8=260 | `wait4` | `tracepoint:sched/sched_process_exit` (object side) | `sys_wait4`->`do_wait` | Observing exit usually suffices; the wait surface is rarely used |
| 33 prctl (thread name/domain) | - (setThreadName goes native) | `prctl` (libc; PR_SET_NAME option; prctl itself=syscall 167, sets the thread name) | x8=167 | `prctl` | `kprobe:sys_prctl` | `sys_prctl` | wxshadow on `prctl`, rewrite the name argument |
| 34 futex (locks/waiting) | - | `pthread_mutex_lock` (libc)->`futex` (libc) | x8=98 | `futex` (high-volume; short windows only) | `kprobe:sys_futex`; the GhostLock surface=PI variants (area 07's android-kernel-ebpf.md sec.3) | `sys_futex`->the `futex_wait` family | wxshadow; for lock-storm analysis, profile with the `sched/sched_switch` tracepoint |
| 35 Trace cleanup | `File.delete` | `unlinkat/remove` (libc), `readlinkat` (self-check of /proc/self/fd) | x8=35/78 | `unlinkat` | `tracepoint:syscalls/sys_enter_unlinkat` | `sys_unlinkat` | wxshadow on `unlinkat` to see which logs/so files get deleted |
**Three iron rules for reading the table**:
1. First check whether the "svc interception" column says "none" - property reads/crypto/time (vDSO)/ART internals are all user-space; the L3/L4/L5 kernel tools are N/A against them, don't force it (area 09 sec.13 cross-domain rule 1).
2. The "uprobe point" column and the "libc/so hook" column are often the same function: the difference is only **whether you enter the target process**. Need rewriting and fear CRC -> uprobe/eBPF; need Java object semantics -> frida.
3. Prefer full tracepoint names (stable ABI): `sched/sched_process_fork`, `sched/sched_process_exit`, `syscalls/sys_enter_*`, `net:net_dev_queue`, `kmem/mm_page_alloc`; kprobe function names (`kernel_clone`/`do_sys_openat2` etc.) drift with the kernel version - verify against available_filter_functions before attaching (area 07's kernel-symbol-locating.md route D).

## 3. Three usage paths (kernel-level extended edition)

### 3.1 Path A: the enterprise-packaged APK analysis chain (seven steps, each with "failure -> alternative")

**Step 1 Identify (device untouched)**
- APKiD one-shot profiling: packer/obfuscator/compiler (area 05's profiling-and-recon sec.1); on a miss, the manual four moves: `unzip -l` so list, manifest Stub Application, `strings lib*.so | grep -iE "jiagu|secneo|ijiami|nesec|tup"`, so-name signatures (area 05's static-analysis tools sec.9).
- Failure -> alternative: packer not identified but behavior says packer (odd dex in assets/undersized classes.dex) -> proceed to step 2 as an "unknown packer" and let the dump results back-derive.
**Step 2 eBPF memory extraction**
- Main route: eBPFDexDumper (-rs) dumping. Observation points = matrix rows 21/23/24: `uprobe` on `art::JNI<false>::RegisterNatives` (PARM3=JNINativeMethod*), the `DexFile::DexFile` ctor (x1=DEX begin; validate magic directly with `looks_like_dex_header`) / `DexFileLoader::OpenOne` (A15+ source first param header_offset, contradicting the tool comment's x1=base - re-verify in IDA before attaching; the dex-load-exec-chain.md sec.1.2 correction), `ExecuteNterpImpl` (x0=ArtMethod*, chained dereference: ArtMethod+0 compressed declaring_class->Class+0x10 dex_cache->DexCache+0x10 DexFile->+0x8 begin, untag the top byte throughout to clear MTE/PAC) (area 03's eBPF unpacking deep dive sec.3-sec.4).
- Failure modes and alternatives:
 - **No symbols** (A16/17 stripped the DexFile ctor/inlined it) -> fall back to `DexFileLoader::OpenOne`; when its dynsym `st_value=0` -> locate offsets by string xref: the AOSP warning strings `"This is slow, consider changing your RegisterNatives calls."` (RegisterNatives), `"Interpreting "` (Execute) -> parse ADRP+ADD/ADR for the address; failing that, scan the ARM64 byte pattern of the `ExecuteNterpImpl` prologue -> supply `--register-natives-offset/--nterp-offset/--execute-offset` manually (area 03 sec.3.3/sec.4.4).
 - **eBPF read misses a page** (`bpf_probe_read_user` doesn't fault in) -> user-space `process_vm_readv` re-reads the missed offsets (the -rs built-in backstop, area 03 sec.5.2).
 - **Kernel unsupported/no root** -> drop to frida: the `ClassLinker::DefineClass` route (5th param=DexFile&, area 03's dex unpacking sec.4) + `enumerateClassLoadersSync` to find the packer's ClassLoader.
**Step 3 Extraction-packers backfill (when method bodies are nop)**
- First choice JDex/JDex2: LSPosed injection -> reflect LoadedApk for the real ClassLoader -> walk the DexPathList's DexFiles -> **actively invoke each class's constructors** to trigger the packer's backfill -> mCookie dump (area 03 sec.7.2).
- The FART approach (modified ART source, actively invoking all methods): **broken on stock A12-16** (ArtMethod layout accessorization/call-chain changes/odex->vdex); reviving it means a serious port (cyrus-studio's 2025-08 account) or MikRom/Youpk (area 03 sec.7.1).
- **Nterp-layer observation alternative** (when active invocation is dead on A12+): don't force execution, just passively collect - multi-site uprobe on `nterp_op_invoke_*` + `read_method_bytecode` to grab method bodies that "naturally executed", backfilled from `dex_..._code.json` (area 03 sec.3.2). Coverage depends on how many screens you walk; pair with monkey UI crawling to raise the hit rate.
- Failure -> alternative: on no-root scenarios BlackDex (A5-12, cookie route + hook route); for Pairip packing use RePairip directly.
**Step 4 dex repair**
- The seven-stage pipeline (-rs sec.5.2): ringbuf chunking (4096) and assembly -> page-miss process_vm_readv re-reads -> dedup by begin -> code_item back-scan (64MB/0x1000 stride) -> method-bytecode backfill -> **SHA-1 recompute of signature (dex[32..]) + Adler-32 recompute of checksum (dex[12..])** -> structural validation, accepted via `repair/fix/final/missed.json`.
- Failure -> alternative: the Go `fix` subcommand; cdex notice -> vdexExtractor (area 03 sec.3.4).
**Step 5 Deobfuscation**
- ROSAL: deterministic mapping for the standard libraries (androidx/support) - platform API references cannot be renamed, making them restoration anchors; feed the tiny mapping back to jadx and business classes stand out from the `a.b.c` noise (area 05's static-analysis tools sec.4). **Boundary: app-owned classes are not mapped**; business-class restoration still relies on manual jadx + DexKit.
- Failure -> alternative: native obfuscation (OLLVM flattening) -> area 10's deobfuscation playbook, four routes (d810/function-level emulation/instruction-stack back-tracing/angr+unicorn).
**Step 6 Dynamic analysis (the fallback chain when frida is detected)**
- `frida detected -> frida-mcp switches to strongR-frida (hzzheyang, auto-patched build; version discipline: matching major versions on both ends, area 05's dynamic-and-hook-frameworks sec.version discipline) -> rename/change port/frida-server -l on a non-loopback -> gadget injected with a so (no TCP listener) -> Zygisk (LSPosed/LSPilot/Renef memfd injection; when Zygisk itself is scanned, KernelSU+SUSUFS+ReZygisk kernel-level hiding) -> uprobe backstop (same symbol, zero injection, matrix column 5)`.
- Triage basis: detection-surface classification (port scan -> changing the port suffices; maps/thread names -> gadget+soinfo unlinking; CRC -> uprobe/wxshadow) - diagnose the cause class first with area 09's "hook-fallback playbook" sec.1 decision tree A/B/C/D, then fall back.
- The uprobe backstop pattern: Java semantics still need frida; so-layer semantics all move to uprobe (`uprobe:libtarget.so:0xoffset { printf("%r", buf(arg1,64)); }`, area 07's android-kernel-ebpf.md Appendix C2).
**Step 7 Entry discovery**
- SnikrFlow (angr+claripy symbolic-execution triage; **project exists**, area 05's static-analysis tools sec.5) -> the equivalent command chain in native angr: `angr.Project("libfoo.so", auto_load_libs=False)` symbolize entry params -> probe functions (explore find=avoid=) -> `ddg/data_ref` to chase taint; or a Ghidra script walking xrefs for `system/execve/open/dlopen` sinks.
- Failure -> alternative: too many entries -> jadx-mcp lets AI read the manifest/launchable-activity to converge first; so without symbols -> transplant the string-xref method of Path A step 2.
**Seven-step acceptance checklist (self-check at each step's end)**:
1. The APKiD conclusion agrees with subsequent observations (packer type <-> the count/structure of dumped dex matches; if not -> back to the manual four moves);
2. The dump directory holds at least 1 non-empty `dex_<pid>_<begin>_<size>.dex` with magic='dex' (0x64); `missed.json` coverage is explainable;
3. Key business-class method bodies are not nop/`return-void` placeholders (spot-check in jadx; still nop -> back to step 3, switch to JDex/Nterp observation);
4. jadx/baksmali report no corrupt file (SHA-1+Adler-32 recomputed); on error -> back to step 4 repair;
5. After ROSAL mapping, business class names/call chains are readable (androidx restored; app classes located via DexKit);
6. The app never crashes during dynamic analysis (the four-phase process-alive->attach->hook->dump checklist, area 04);
7. Every sink in the entry list has reachable evidence (an angr explore path/Ghidra xref); mark unverifiable ones "unverified" to prevent hallucination.

### 3.2 Path B: the system-layer research chain (root + kernel)

**B1 wxshadow (stealth breakpoints)**
- Principle wrap-up (area 07's kernel-hook-stealth.md sec.2.3): the breakpoint is written to the **shadow physical page** (target-page copy + BRK #0x7), the user PTE redirected; the execution flow walks the shadow page and captures registers (x0-x30/sp/pc/pstate), while readers (GUP/`/proc/PID/mem`/`process_vm_readv`) always resolve to the original page -> CRC self-checks are structurally blind. Fork protection hooks `uprobe_dup_mmap`; `exit_mmap` cleanup; `tlbi vaale1is` broadcast invalidation.
- Client: `wxshadow_client -p <pid> -a <addr> [-r x0=<val>] [--patch <hex>]`. Applicable to: every row of the matrix "stealth point" column.
- Deployment chain (OnePlus Android 16 tested path, area 07 sec.9 original): push to /sdcard -> `su cp` to /data/local/tmp (the KernelSU redirection trap) -> `kpatch kpm load wxshadow.kpm` -> `wxshadow_client --release` to wrap up. Failure self-checks: THP targets return -14 (split first); unloading without the 5-stage unhook leaves a dangling hook.
**B2 android-kernel-hacking-toolkit (a textbook-grade LKM)**
- Four modules: filecopy (kernel-mode copy, `filp_open/kernel_read/kernel_write`)/hideproc (hide by PID)/propedit (kernel edits user-page properties)/syscall_hijack (sys_call_table). The four moves: kprobe-resolved `kallsyms_lookup_name` (5.7+ unexport), `no_sanitize("cfi")` wrappers, mmuhack page-table write-unprotection, physical-memory writes (area 07 sec.4).
**B3 bpftrace JNI-boundary ARM64 calling-convention table (memorize before writing handlers)**

| Register | Contents | How to read it |
|---|---|---|
| x0 | `JNIEnv*` | It's a **pointer to a pointer to the function table**: `*(u64*)x0`=JNINativeInterface table base, `((u64*)x0)[index]`=a specific JNI function (RegisterNatives~entry 215, drifting by version - check art_jni_impl.h/jniq) |
| x1 | `jobject/jclass/jstring` | On ART a **32-bit IndirectRef handle**, not a raw pointer - **do not deref directly**; either just watch handle flow, or hook the target JNI function's uretprobe to get contents |
| x2 | instance method=1st parameter / static method=1st parameter after jclass (i.e. x1=clazz, x2=arg1) | Judge by the method signature |
| x3 | 2nd parameter | Same |
| retval (x0) | Return value | `GetStringUTFChars` returns char* -> `str(retval)` gives UTF-8 directly (area 07's android-kernel-ebpf.md sec.5 scenario B) |
Do not mix the three ART-internal ABIs (the corrected version in area 03's eBPF unpacking sec.4.3): the `DexFile::DexFile` ctor is **x1=base**; `DexFileLoader::OpenOne` on A15+ takes header_offset as the source first param (the x1 shape contradicts the tool comment; re-verify in IDA on-device, dex-load-exec-chain.md sec.1.2); `ClassLinker::RegisterDexFile` is **x1=DexFile\*** (dereference again); the `ExecuteNterpImpl` family is **x0=ArtMethod\*** (chained dereference to get the DEX). Plus two hard rules: read compressed references as u32; untag the top byte before dereferencing.
**B4 kprobe -> fentry upgrade**
- Start with kprobe (best compatibility, attaches without BTF); with BTF (`/sys/kernel/btf/vmlinux` exists, GKI 5.15+) -> upgrade to `fentry:`/`kfunc:` (trap-free, an order of magnitude faster, entry/exit args + return values all captured); limits: entry/exit only, no arbitrary offsets, inlined targets cannot be attached (bpftrace #2888, area 07's kernel-symbol-locating.md sec.2 route D).
- To change execution flow, upgrade again: ftrace IP_MODIFY / KernelPatch inline hook (the one-line selection guide in area 07's kernel-hook-stealth.md sec.9).

### 3.3 Path C: the AI-driven chain

- **Orchestration layer**: REA (`npx rea-agents setup`, CLI+MCP dual form, conclusions carry evidence to prevent hallucination)/ MobileRE-Skill (decision-tree brain + 25 frida modules + 22 standalone tools, six-layer drill-down Java->JNI->Native->libc->syscall->SVC)/ LSPilot (on-device LSPosed closed loop, free of every frida tell) (area 08's AI reversing tool ecosystem sec.0-sec.4).
- **Single-point MCP layer**: the jadx-mcp family (Java source)/ GhidraMCP+ghidra-mcp (so)/ ida-pro-mcp (in local use)/ frida-mcp family picked per scenario: dnakov (simplest stdio)/kahlo (autonomous long-control)/frida-c2 (rooted-device C2)/barbatos (zero config)/jniq (JNI-slot verification, the first gate against LLM hallucination).
- **Wiring into this document's matrix**: the Agent gets a "target action" -> checks the sec.4 quick reference to pick the observation point -> frida surfaces go through frida-mcp, kernel surfaces go through the CLI (bpftrace/adb). The decision tree (area 08 sec.8) + this document's sec.1.1 layer-selection tree stack into a two-level router.
- **The possibility and status of MCP-izing kernel-level observation (2026-10 snapshot)**
 - Status: **there is no kernel-level MCP server**. Existing MCPs all wrap user-space tools (frida/jadx/IDA); on the kernel side, only CLI forms are orchestratable - one-line bpftrace commands, bpftool, tracefs cat, invoked by the Agent over shell (area 08 sec.1.5 "CLI form is naturally orchestratable").
 - MobileRE-Skill's `fsmon_run.py` is the closest precedent: a standalone Python tool doing kernel-level file events (an eBPF/tracefs wrapper) invoked by the Agent per the decision tree - proving "kernel observation can enter the Agent workflow without entering the MCP protocol".
 - Engineering points for MCP-izing (if self-building): (1) the tool surface = the three actions "list probes (bpftrace -l) -> attach/detach -> stream ringbuf output"; (2) constraints = bound to a rooted device, degrade to kprobe when BTF is missing, output must be truncated/aggregated (bpftrace output floods would blow the context); (3) safety = whitelist tracefs writes, to keep the Agent from attaching global kprobes and dragging the machine down.
 - Verdict: short term, the dual track "frida-mcp (user space) + bpftrace CLI (kernel)"; mid term it is worth turning the sec.2 matrix's tracepoint column into a read-only MCP tool (lowest risk, direct payoff).

## 4. From task to observation point: the reverse quick reference (20 entries)

"I only want to know X -> attach which first (cheapest first) + alternatives + log-reading essentials." All observation-point names map to sec.2 matrix row numbers.

| # | Intelligence need | First choice (cheapest) | Alternatives | Log-reading essentials |
|---|---|---|---|---|
| 1 | Who reads a given file | frida on libc `openat` (row 1) | `tracepoint:syscalls/sys_enter_openat` (direct svc included) | Filter the target path; `Thread.backtrace` locates the calling so; a direct-invocation delta = libc counts don't add up |
| 2 | When a domain gets resolved | frida `getaddrinfo` (row 8) | kprobe `__sys_connect` filtering netd; `net:net_dev_queue` | DNS goes UDP 53/netd socket; align hit times with the app's lifecycle phase |
| 3 | When a dex gets decrypted | uprobe the `DexFile::DexFile` ctor (row 21) | the frida DefineClass route; `mmap`+`mprotect` combos (row 19) | An mprotect rwx->rx followed closely by mmap/file reads = the unpack window; ctor x1 is the DEX start directly |
| 4 | Who called exit | frida `exit/_exit` (row 13) | `tracepoint:sched/sched_process_exit`; a short Stalker window | The last backtrace before exit = the trigger; distinguish exit_group from suicidal anti-debug (check whether sensitive files were read beforehand) |
| 5 | When a so loads | frida `android_dlopen_ext` (row 16) | `__dl__ZN6soinfo17call_constructorsEv`; kprobe openat filtering .so | If already loaded before attach, the hook never fires -> spawn mode; anti-debug in init_array can precede frida's arrival |
| 6 | Which thread scans memory | frida `pthread_create` (row 15) + thread names | `tracepoint:sched/sched_process_fork` + read comm; `process_vm_readv` (row 30) | Memory-scanner thread signatures: loops of openat /proc/ or process_vm_readv; names (gum-js-loop etc.) are frida's self-exposure |
| 7 | Which IP:ports the app connects to | frida `connect` (row 6) | kprobe `__sys_connect` (global); parse `/proc/net/tcp` | sockaddr_in ports are network order; hits on 27042/27043 = it's scanning for frida |
| 8 | What data is sent | frida `sendto/sendmsg` (row 7) | the uprobe `SSL_write` family; `net:net_dev_queue` (packet-level metadata only) | Plaintext is already ciphertext at the libc send layer (TLS); for plaintext pass rows 26/27 first |
| 9 | What was said over binder | kprobe `binder_transaction` dumping parcels (row 9) | `tracepoint:binder/binder_transaction` | Filter by target.handle+code; x86/arm32 layout differences - match binder.h to the version |
| 10 | Whether being ptraced | Read `/proc/self/status` TracerPid emulation (row 2) | kprobe `sys_ptrace`; under wxshadow there is naturally no ptrace surface | TracerPid!=0 = attached; combine with row 11 |
| 11 | Which properties were read | frida `__system_property_get` (row 4) | Direct read/modify of `/dev/__properties__` (self-parse, full app coverage) | The svc layer can't intercept it (zero syscalls); hits on ro.debuggable/test-keys = environment probing |
| 12 | Where keys/plaintext live | frida `Cipher.doFinal` (row 27) | `EVP_CipherUpdate` uprobe; short-window `malloc` sampling (row 18) | Plaintext is in update's input args; static boringssl -> signature-locate then attach by address |
| 13 | Where randomness comes from | frida `getrandom` (row 28) | `RAND_bytes`; `sys_getrandom` kprobe | A fixed return enables challenge replay; mind the urandom-file fallback path |
| 14 | Whether time is used for detection | frida `clock_gettime` (row 29) | patch `__vdso_clock_gettime`; kprobe sys_clock_gettime (a direct call = anomaly) | The normal path never hits svc! An svc hit means the app cached the pointer and called directly; the double-read delta is the detection principle |
| 15 | Where memory got modified | frida `mprotect` (row 19) | `sys_mprotect` tracepoint; wxshadow `--patch` on the adversarial side | rwx/rx flips = self-unpacking; mind the 16KB-page stride assumption (area 09 sec.14) |
| 16 | Where the faults are | perf_event `PERF_COUNT_SW_PAGE_FAULTS` (row 20) | `exceptions:page_fault_user`; `handle_mm_fault` fentry | High-frequency faults + a SIGSEGV handler = the packer's on-demand decryption (C++-exception-style protection) |
| 17 | The JNI method registration table | uprobe `RegisterNatives` (row 24) | frida on libart symbols | Walk PARM3 at a 24-byte stride (name+0/sig+8/fnPtr+16); record TGID for after-the-fact module attribution |
| 18 | Where Java execution has reached | uprobe Nterp offsets (row 23) | frida Stalker/`art::interpreter::Execute` (A15+ failing to attach is normal) | x0=ArtMethod*, chained to get dex_method_index; covers only executed methods |
| 19 | Who does cross-process R/W | kprobe `sys_process_vm_readv` (row 30) | frida `process_vm_readv`; under wxshadow the read path is hidden | Check the requester pid vs target pid relation; both dump tools and risk-control scans show up here |
| 20 | When children/daemons fork | `tracepoint:sched/sched_process_fork` (row 14) | frida `fork` (libc); KPM on `kernel_clone` | fork followed by execve (221) = spawning a child; pair with row 1 to see what the child reads |
**Three principles for using the quick reference**:
1. **Try the cheapest first, but only once**: know within 30 seconds whether the first-choice layer produces results (Java/libc hooks are instant; uprobe needs BPF up; tracepoint needs root); once the first choice is confirmed dead, switch immediately - don't grind parameters at the wrong layer (area 09's "hook-fallback playbook" sec.5 closing checklist 1: confirm the layer you dropped to is the one actually in use).
2. **Choose observation and rewriting separately**: for the same chain, "just want to know" -> tracepoint/uprobe (read-only, zero risk); "need to intervene" -> frida/wxshadow (rewriting, introduces an adversarial surface). The table's first-choice column defaults to read-only.
3. **Read two chains together**: a single observation point rarely answers everything - "who reads files" paired with "when forks happen" (rows 1+14) separates main process from child; "when dex decrypts" paired with "mprotect flips" (rows 21+19) nails the unpack window shut.

## 5. Checklist (verify first when refreshing)

- [ ] The full libandroid_runtime export symbol name of `nativeForkAndSpecialize` (row 14).
- [ ] Availability of the arm64 `exceptions:page_fault_user` tracepoint across GKI versions (row 20; the perf_event software event is the safe substitute).
- [ ] Current status of the `signal:signal_generate` tracepoint (row 12).
- [ ] CONFIG dependencies and field layout of the `binder/binder_transaction` tracepoint (rows 9/10).
- [ ] Refactor churn of internal function names `sys_getdents64`/`sys_getrandom` across kernel versions (same origin as area 09 sec.15).
- [ ] Community progress on a kernel-level observation MCP server (sec.3.3: none implemented yet; on re-check search bpftrace-mcp/tracefs-mcp keywords).

## 6. Relationship to the rest of the library

- Every syscall number in the matrix's "svc interception" column defers to area 09's android-function-layers sec.0.1 (errata absorbed: sendto=206, not 211).
- The feasibility argument for the "stealth point" column is entirely in area 07's kernel-hook-stealth.md sec.2.3/sec.6; the symbol-locating prerequisites are area 07's kernel-symbol-locating.md routes A-E.
- The offset-identification chain and repair pipeline of Path A steps 2-4 are in area 03's eBPF unpacking deep dive; step 6 fallback details are in area 04's frida anti-detection playbook four-phase checklist.
- Path C tool shoot-out: see area 08's AI reversing tool ecosystem (the mobile-security-mcp four-piece set is an unverified lead).
