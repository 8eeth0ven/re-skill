# Process Timeline and Memory Chains (zygote fork -> linker -> init_array -> JNI_OnLoad -> the full memory/fault chains)

> Positioning: expands the complete timeline of "an app from birth to its first line of native code", together with the user-space allocation chain and the page-fault chain, down to the kernel side.
> Uses: (1) deciding "which layer, which beat, the thing I want to intercept actually happens on"; (2) the essential analysis of detection/injection races; (3) back-deriving attack surfaces from observation points.
> Baseline: kernel/fork.c v5.4 / v5.10, the LLVM Scudo official docs, bionic fork/pthread/scudo, the linker (dlfcn/linker.cpp) source structure. Uncertain items marked `[unverified]`.
> All syscall numbers are arm64: x8=call number, x0-x5=args. Register conventions in [hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md) sec.3.1.

## 0. The global picture: how the five chains string together

```
Chain 1: process creation    Chain 2: SO loading             Chain 4: memory allocation
AMS → zygote fork  →   System.loadLibrary     ←   malloc/new
  (kernel_clone)         → dlopen → mmap         → scudo → mmap (chain 5: demand paging)
       │                     │ relocate            │
       ▼                     ▼ init_array          ▼
Application.onCreate     JNI_OnLoad ←──────── first-access page fault (chain 5)
  │ Thread.start(chain 3)   │
  ▼                         ▼
Activity.onCreate      RegisterNatives / self-decryption / integrity checks
```

One-sentence version: fork builds the shell (the address space inherits zygote via COW), dlopen lays the road (segment mapping + relocation), init_array/JNI_OnLoad starts the race (the packer's self-checks and decryption usually live here), malloc/faults feed the runtime (all dynamic behavior ultimately lands on the two kernel entrances vm_mmap_pgoff / do_page_fault).

## Chain 1: the full timeline of app process birth (AMS -> zygote fork -> Application -> JNI_OnLoad -> Activity)

### 1.1 Timeline diagram (indentation = call depth)

```
system_server(AMS)
└─ ActivityManagerService.startProcessLocked
   └─ Process.start() → ZygoteProcess.start
      └─ Write /dev/socket/zygote (local socket, not binder; binder coverage: area 07 eBPF article)
         Request body: uid/gid/gids, seinfo, niceName, ABI, rlimit, seccomp policy, mountMode…
zygote (64-bit primary zygote; 32-bit apps use secondary zygote)
└─ ZygoteServer.runSelectLoop (epoll waits for socket)
   └─ ZygoteConnection.runOnce
      ├─ Read argument list and validate uid
      └─ forkAndSpecialize
         └─ nativeForkAndSpecialize(com_android_internal_os_Zygote.cpp)
            └─ bionic fork() (libc/bionic/fork.cpp: pthread_atfork prepare chain runs first)
               └─ svc __NR_clone(220), flags only SIGCHLD   ←★ not CLONE_VM!
                  └─ sys_clone → kernel_clone(kernel/fork.c v5.10:2415, checked against the tested source)
                     ├─ copy_process(line 2456)
                     │  ├─ dup_task_struct(slab allocates task_struct; copy parent fields)
                     │  ├─ copy_creds: fork without CLONE_THREAD → new cred (still matching zygote)
                     │  ├─ copy_files: no CLONE_FILES → copy fd table
                     │  ├─ copy_mm(line 1379): no CLONE_VM → dup_mm → dup_mmap
                     │  │  └─ copy_page_range(line 593): copy PTEs per VMA, make writable pages read-only = COW
                     │  │     (Parent and child share zygote-preloaded class/resource pages; this speeds app startup)
                     │  ├─ copy_thread: set child return context (fork returns 0 in child)
                     │  ├─ sched_fork: initialize scheduling entity (CFS/EEVDF)
                     │  └─ Allocate pid/tid
                     ├─ trace_sched_process_fork(line 2466)   ←★ eBPF tracepoint
                     └─ wake_up_new_task(line 2480)→ enqueue runnable task
   ───────────── Return from kernel; parent and child diverge ─────────────
Child process (still has all zygote privileges)
└─ ZygoteConnection.handleChildProc / specializeAppProcess
   ├─ SpecializeCommon(native):
   │  ├─ setgroups / setresgid / setresuid(drop to target uid)
   │  ├─ setrlimit(ASLR bit fields, memory limits)
   │  ├─ capset drops surplus capabilities
   │  ├─ Install seccomp filter according to policy (the app domain blocks io_uring here)
   │  ├─ prctl(PR_SET_PDEATHSIG, SIGKILL)(child dies if zygote dies)
   │  ├─ SELinux setcon(switch to untrusted_app domain; call order is version-dependent, verify)
   │  └─ According to mountMode: unshare(CLONE_NEWNS) + storage remount (verify details)
   ├─ ZygoteInit.childZygoteInit / RuntimeInit.commonInit
   └─ findStaticMain(ActivityThread.main)→ MethodAndArgsCaller.run()
      └─ ActivityThread.main
         ├─ Looper.prepareMainLooper
         └─ attach → binder calls AMS.attachApplication(IActivityManager)
            (AMS attachApplicationLocked sends the bindApplication/activity queue back)
App main thread (handleBindApplication)
└─ ActivityThread.handleBindApplication
   ├─ Construct LoadedApk / ContextImpl
   ├─ createAppClassLoader → PathClassLoader(BaseDexClassLoader)  ← determines SO visibility
   ├─ makeApplication → new Application → app.attach(context)
   │  └─ Application.attachBaseContext   ←★ earliest detection-SDK initialization point (before onCreate)
   ├─ installContentProviders → ContentProvider.onCreate  ←★ also before Application.onCreate
   │    (Many security SDKs start detection threads in providers; do not inspect only Application)
   └─ Instrumentation.callApplicationOnCreate
      └─ Application.onCreate
         └─ static { System.loadLibrary("xxx") } or first loadLibrary in onCreate
            └─ → chain 2: dlopen → init_array → JNI_OnLoad (see §2)
AMS scheduleTransaction → app main thread
└─ Activity.onCreate(after Application.onCreate; JNI_OnLoad usually occurs earlier)
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
Java layer
└─ System.loadLibrary("native-lib")
   └─ Runtime.loadLibrary0 → ClassLoader.findLibrary(SO name → full path)
      └─ Runtime.nativeLoad → libart JavaVMExt::LoadNativeLibrary
         └─ android_dlopen_ext(path, RTLD_NOW, &extinfo)(libdl.so is only a forwarding wrapper)
libdl → linker64(bionic's own linker, distinct from glibc ld.so)
└─ __loader_android_dlopen_ext → do_dlopen
   ├─ Resolve caller's linker namespace (classloader namespace; isolation since Android 7+)
   └─ find_library_internal
      ├─ Already in solist(global SO list)→ cache hit returns handle directly
      └─ load_library
         ├─ openat(svc 56)opens SO file → read ELF header / phdr
         ├─ mmap(svc 222)reserves total span with PROT_NONE
         ├─ phdr_table_load_segments: mmap each PT_LOAD, separating PF_R/W/X:
         │    r--(rodata/relro), r-x(text), rw-(data/bss); page-align file offset;
         │    anonymous zero-fill mapping at bss tail)   ←★ segment permissions are established here
         ├─ Allocate soinfo, record soname/base/size, link into namespace solist
         └─ Recursively process DT_NEEDED (same process for dependencies; zygote-preloaded SOs use cache)
   ──────────── Relocation (relocate, soinfo::relocate)────────────
   ├─ Iterate .rela.dyn / .rela.plt (RELR/RELA depends on version)
   ├─ For each symbol, soinfo_do_lookup searches this SO + dependency-chain dynsym/dynstr
   ├─ Patch GOT entries / directly relocate target address ←★ runtime counterpart of the "patchelf process"
   └─ phdr_table_protect_gnu_relro: mprotect(svc 226)changes RELRO to r--
   ──────────── Constructors (call_constructors)────────────
   └─ soinfo::call_constructors(libc++ demangled symbol: __dl__ZN6soinfo17call_constructorsEv)
      ├─ Run all dependency constructors first (dependencies before the main SO)
      ├─ Execute DT_INIT (legacy init function)
      └─ Execute DT_INIT_ARRAY: invoke entries in ascending address order
         └─ ★Packer self-checks/decryption/anti-debug threads often start here; an important early-injection window
   ──────────── Return to Java layer ────────────
└─ dlopen returns handle (libart side)
   └─ dlsym(handle, "JNI_OnLoad")
      └─ Call JNI_OnLoad(JavaVM*, void*)   ←★ after all init_array entries
         └─ Dynamic registration: RegisterNatives (hook point in area 02, §1.14)
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
Early ←───────────────────────────────────────────→ Late
zygisk (immediately after zygote fork; agent is already in address space before fork)
 > frida spawn (process exists, app code has not run; gating suspends for injection)
 > gadget (loaded as a dependency before target SO; its init_array runs first)
 > hook android_dlopen_ext onEnter (target SO has not entered load_library)
 > hook call_constructors onEnter (segments mapped, relocation incomplete; area 02, §1.15)
 > hook init function entry (first instruction of packer self-check)
 > attach (after onCreate; early initialization has already finished)
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
Java layer
└─ Thread.start()
   └─ ART JVM_StartThread → Thread::CreateNativeThread
      └─ pthread_create(libc/bionic/pthread_create.cpp)
         ├─ mmap(svc 222, RW, ANON|STACK)allocates thread stack + TLS block
         ├─ guard page: mprotect one page PROT_NONE (stack-overflow protection)
         └─ clone(__pthread_start, child_stack, flags, …)
            flags = CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND
                  | CLONE_THREAD|CLONE_SYSVSEM
                  | CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
            └─ svc __NR_clone(220)
               └─ sys_clone → kernel_clone → copy_process
                  ├─ CLONE_VM → shared copy_mm branch (get_mm, reference count, no page-table copy)
                  ├─ CLONE_FILES → copy_files shares fd table
                  ├─ CLONE_THREAD → join parent's thread group: same tgid, newly allocated tid
                  ├─ copy_creds: CLONE_THREAD → share cred directly (no new cred)
                  ├─ copy_thread: CLONE_SETTLS → set tpidr_el0 (TLS register)
                  ├─ Record ctid (CLONE_CHILD_CLEARTID: kernel clears *ctid on thread exit
                  │   and futex-wakes waiters; underlying mechanism of pthread_join)
                  └─ wake_up_new_task + tracepoint sched_process_fork
                     └─ ret_from_fork → return to user-space __pthread_start
                        └─ Run start_routine(routine(arg))→ finish with pthread_exit → exit
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
Java objects
└─ new → ART heap's own space (region space / bump-pointer TLAB;
   │     card-table write barrier records cross-generation references + concurrent-copying GC; bypasses malloc)
   └─(Only off-heap/direct buffer/Bitmap pixel data, etc.)→ native allocation
native
└─ malloc / new / operator new(libc/bionic)
   └─ scudo(bionic default allocator since Android 11; jemalloc on A10 and earlier)
      ├─ CombinedAllocator::allocate
      │  ├─ Small allocation(config-dependent threshold, approximately ≤64KiB; verify)→ Primary
      │  │   SizeClassAllocator64:
      │  │   - Regions by size class (reserve large VA once at startup through mmap,
      │  │     reserve only; commit as used → physical pages on demand faults, chain 5)
      │  │   - Header before each chunk: checksum(cookie)+class id+state+offset
      │  │     (Packed into about 8 bytes; bit fields depend on version, verify)
      │  └─ Large allocation → Secondary(LargeMmapAllocator):
      │      Separate mmap for each allocation(svc 222 → sys_mmap → vm_mmap_pgoff → mmap_region),
      │      metadata before the page; free = munmap
      │      ※ Android heaps rarely use brk(svc 214); observe mmap for heap activity
      ├─ Apply tags on allocation on MTE devices (Android 12+)
      └─ Return user pointer
free(ptr)
└─ scudo Deallocate
   ├─ Validate header (part of corruption/UAF protection)
   └─ Enter quarantine(delayed reuse against UAF: hold freed chunks temporarily,
      │  return batches by randomized countdown/capacity cap; contents may be poisoned meanwhile)
      └─ At expiry, return to matching Primary region / directly munmap Secondary
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
User space EL0
└─ First load/store/instruction fetch at a newly mmap'ed address(e.g. new SO text)
   └─ MMU page-table walk: PTE absent (or permission mismatch)
      └─ Trigger Data Abort / Instruction Abort; trap to EL1
         └─ Exception vector el0t_64_sync → el0_da(entry-common.c; handlers split in 6.x; verify version-specific names)
            └─ do_mem_abort(dispatch by ESR.EC: 0x24=data abort from lower EL)
               └─ do_page_fault(mm/memory.c family)
                  ├─ Read fault address from far_el, access/instruction information from ESR
                  ├─ Find VMA(lock_mm_and_find_vma); no VMA → SIGSEGV
                  └─ handle_mm_fault → handle_pte_fault; dispatch by PTE/VMA state:
                     ├─ Anonymous VMA, empty PTE, read-only access
                     │  └─ do_anonymous_page: map global shared zero page (read-only,
                     │     physically shared system-wide; allocate a real page only on write)
                     ├─ Anonymous VMA, write access
                     │  └─ do_anonymous_page: allocate new zeroed physical page → set_pte_at
                     ├─ File VMA(e.g. SO text/rw segment)
                     │  └─ do_read_fault/do_write_fault → filemap_fault:
                     │     Look up page cache(xarray); on miss issue actual disk/flash read
                     │     → Establish mapping(file page cache; processes share the physical page)
                     ├─ COW(do_wp_fault): write read-only page → copy page(zygote-shared pages separate here)
                     └─ swap(do_swap_page; zram common in app domain)
                  └─ Write PTE to page table + no TLB entry → return to user space
                     └─ ★Re-execute the same instruction; page-table lookup now succeeds
```

### 5.2 The mprotect chain

```
frida Memory.protect / packer page-permission changes
└─ libc mprotect → svc __NR_mprotect(226)
   └─ sys_mprotect → do_mprotect_pkey
      └─ mprotect_fixup → change_protection
         ├─ Split/merge VMAs; change R/W/X bits in each PTE
         └─ flush_tlb_range invalidates old mappings
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
