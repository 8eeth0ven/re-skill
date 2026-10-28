# File and Property Chains: Java API -> Deep into the Kernel (kernel-level deep dive)

> Positioning: **expands five chains end to end** - "file read-write / /proc pseudo-files / the property system / IO transparent decryption / mmap" - with per-step call sequences and observation points at every layer.
> The five-layer function-name quick table is in area 09's "[android-function-layers.md](../09-function-map/android-function-layers.md)"; concrete kernel-hook recipes are in area 07's kernel-hook-stealth.md and android-kernel-ebpf.md; dex landing is in area 03's dex-unpacking.md.
> Baseline: kernel = master + the common Android kernels (5.15/6.1/6.6, naming differences flagged separately); AOSP = aosp-mirror (bionic/libcore/system_core, main branch). Each item annotated [checked: file@branch]; items whose source could not be obtained are marked `[unverified]`.
> Version alert: torvalds master renamed and refactored the open/mmap paths in recent years (`do_filp_open`->`do_file_open`, `call_mmap`->`vfs_mmap`+`.mmap_prepare`/`vm_area_desc`) - **the 5.15~6.6 kernels on Android devices still use the old names**. This document's body follows the common Android kernels; the new names are given in full in the version notes.
> Wording convention: neutral technical-document style, uniformly "observe / extract / filter / modify surface".

## 0. Three-minute overview (the one-sentence version of each chain)

| Chain | Java entry | Final kernel landing | syscall surface | Special property |
|---|---|---|---|---|
| 1 Plain file read | FileInputStream.read | read_iter -> filemap_read -> pagecache | openat(56)+read(63) | /sdcard goes through FUSE (user space) |
| 2 /proc read | same as above | seq_file show callbacks generate on the fly | same as above | **Content is generated at read time**; no static inode data |
| 3 Properties | SystemProperties.get | **no kernel involvement**: shared-memory trie | reads are zero-syscall; set goes over a unix socket | The L4/L5 hole in the five-layer model |
| 4 Transparent decryption | (packer native code) | only openat/read reach the kernel | openat+read+mmap | decryption happens in user space; the kernel only sees ciphertext |
| 5 mmap | ByteBuffer/DexFile | mmap_region -> filemap_fault | mmap(222) | plaintext loaded on demand at first access |

## Chain 1: the plain file-read chain

### 1.1 Full sequence diagram (indentation = call depth)

```
new FileInputStream("/sdcard/a.dat")                      ← L1 libcore(Java)
  └─ open0(path, O_RDONLY)                                ← L1 FileInputStream.open0(native declaration)
      └─ Java_java_io_FileInputStream_open0               ← L2 libjavacore.so(JNI registered in libcore Register.cpp)
          └─ libcore IoBridge open wrapper(eventually calls libc open)
              └─ open(path, flags)                        ← L3 libc.so export
                  └─ bionic open implementation: forwards to __openat(AT_FDCWD,...) [source: bionic libc/bionic/open.cpp; verify file-level details]
                      └─ svc #0, x8=56(__NR_openat)       ← L4 instruction level(arm64)
                          └─ sys_openat(SYSCALL_DEFINE4)  ← L5 kernel entry
                              └─ do_sys_open              [source: fs/open.c@master]
                                  └─ do_sys_openat2
                                      ├─ build_open_flags(parse flags/O_CREAT, etc.)
                                      └─ do_filp_open(old name; renamed do_file_open on master)
                                          └─ path_openat(fs/namei.c)
                                              ├─ path_init → link_path_walk → walk_component
                                              │   └─ lookup_fast(dcache)/lookup_slow(actual lookup)
                                              ├─ may_open(permission/type checks)
                                              └─ do_open
                                                  └─ vfs_open(path, file)
                                                      └─ do_dentry_open           [source: fs/open.c@master]
                                                          ├─ f->f_op = fops_get(inode->i_fop)  ★ f_op assigned here
                                                          └─ f_op->open(e.g. ext4_file_open/f2fs_file_open)
                          → Install fd in fdtable; return to user space

fis.read(buf)                                             ← L1
  └─ readBytes(byte[],off,len)                            ← L1 FileInputStream private native
      └─ Java_java_io_FileInputStream_readBytes           ← L2 libjavacore.so
          └─ read(fd, buf, count)                         ← L3 libc.so
              └─ svc #0, x8=63(__NR_read)                 ← L4
                  └─ sys_read(SYSCALL_DEFINE3) → ksys_read        [source: fs/read_write.c@master]
                      └─ vfs_read(file, buf, count, pos)
                          ├─ Check FMODE_READ/FMODE_CAN_READ
                          ├─ rw_verify_area → security_file_permission(LSM/SELinux hook)
                          ├─ access_ok(user buffer)
                          └─ Dispatch:
                              ├─ f_op->read(legacy drivers; absent for regular files)
                              └─ new_sync_read
                                  ├─ init_sync_kiocb + iov_iter_ubuf(wrap synchronous kiocb)
                                  └─ f_op->read_iter          ★ actual filesystem entry
                                      ├─ ext4_file_read_iter   [source: fs/ext4/file.c@master]
                                      │   └─ generic_file_read_iter → filemap_read(mm/filemap.c)
                                      ├─ f2fs_file_read_iter   [source: fs/f2fs/file.c; search result, main file was truncated]
                                      │   ├─ fscrypt/compression inline branches
                                      │   └─ filemap_read / generic_file_read_iter
                                      └─ erofs_file_read_iter [source: fs/erofs/data.c@master]
                                          └─ filemap_read(except DAX/DIO branches)
                              filemap_read loop:
                                ├─ filemap_get_folio(look up address_space->i_pages/XArray)
                                │   ├─ Hit and uptodate → copy_folio_to_iter → copy_to_user ★ data returns to user space
                                │   └─ Miss → page_cache_sync_ra(readahead)
                                │       └─ a_ops->read_folio / submit block IO → page becomes uptodate
                                └─ folio_unlock; return copied byte count
```

**The /sdcard special case** [version-dependent]: on Android 11+ external storage (`/storage/emulated/0`) is mounted via kernel FUSE, so read_iter lands on `fuse_file_read_iter` with data supplied by the **user-space MediaProvider daemon** - the observation point must move up to the FUSE daemon; `/data/app` is a direct partition (f2fs/ext4) without this layer. EROFS (read-only system partitions) has no write path; reads are isomorphic to the above.

### 1.2 Key structures

| Structure | Location | Key members | Why it matters for observation |
|---|---|---|---|
| `struct file` | include/linux/fs.h | f_op, f_mode, private_data, f_pos | f_op drives all later dispatch; swapping f_op at the filp layer swaps the implementation |
| `struct file_operations` | same | read_iter/open/mmap/release | the hook target table; one per fs |
| `struct inode` | same | i_fop, i_op, i_sb | the f_op source in do_dentry_open |
| `struct address_space` (mapping) | fs.h | i_pages (XArray page-cache tree), a_ops | the cache layer for ciphertext/plaintext pages; the readahead unit |
| `struct folio/page` | mm | PG_uptodate | pagecache hit decision |

### 1.3 Observation point table (chain 1)

| Layer | Tool | Recipe essentials |
|---|---|---|
| L1 Java | frida `Java.use` | hook `FileInputStream.read`/`<init>`; easiest, but Java-layer stack scans can detect it |
| L2 JNI | frida Interceptor / breakpoints | `Module.findExportByName("libjavacore.so","Java_java_io_FileInputStream_readBytes")`; nobody validates it - great value |
| L3 libc | Interceptor.attach | on `openat`/`read`/`pread64`; three caveats: (1) `fopen/fgets` has stdio buffering - one read fills BUFSIZ, so filter at the read layer (2) dead against direct svc calls (3) function-prologue CRC checks are a common detection surface |
| L4 svc | Stalker/inline breakpoints | short-window `Stalker.follow` counting `01 00 00 D4` (svc #0) and the x8 distribution; after locating direct-call sites, set breakpoints with CodeWriter |
| L5 kernel | eBPF tracepoint / kprobe / ftrace | `syscalls/sys_enter_openat`+`sys_enter_read` captures everything (direct calls included); kprobe `vfs_read` for paths that bypass fd-layer filtering; rewriting needs bpf_override_return (root) |

### 1.4 Practical tips

- Capturing ciphertext to disk: openat records the (fd,path) mapping -> read stores raw bytes by fd (pairs with chain 4).
- Changing file contents as seen by the app: don't touch disk; swap the wrapper at the vfs_read exit or at f_op->read_iter (kernel module); in user space, filter libc reads (mind fopen buffering and direct calls).
- ART-side addendum: `ClassLoader.getResourceAsStream`/`AssetManager.open` ultimately land on openat too - assets live inside the APK (zip); reading the APK is read + user-space unzip, so the observation point is post-unzip memory, not the file layer.

## Chain 2: the /proc pseudo-file read chain (a detection disaster zone)

### 2.1 The full /proc/self/status sequence

```
open("/proc/self/status")                        ← L3(app's own read; usually direct native read)
  └─ svc #0, x8=56
      └─ sys_openat → do_filp_open → path_openat
          └─ procfs path resolution(proc_super_block mounted at /proc)
              └─ proc_get_inode(fs/proc/inode.c)          [source: fs/proc/inode.c@master]
                  └─ status registered by ONE("status", S_IRUGO, proc_pid_status) in base.c
                      → inode->i_fop = proc_single_file_operations
          └─ do_dentry_open: f_op established
              └─ f_op->open = proc_single_open            [source: fs/proc/base.c@master]
                  └─ single_open(filp, proc_single_show, ...)  ← fs/seq_file.c
read(fd, buf, n)
  └─ svc #0, x8=63
      └─ sys_read → ksys_read → vfs_read
          └─ f_op->read = seq_read                         [source: fs/seq_file.c@master]
              └─ seq_read_iter                             ★ main loop
                  ├─ m->op->start(single_start)
                  ├─ m->op->show = proc_single_show        [source: fs/proc/base.c@master]
                  │   └─ PROC_I(inode)->op.proc_show(m, ns, pid, task)
                  │       └─ proc_pid_status(fs/proc/array.c)   [source: fs/proc/array.c@master]
                  │           ├─ proc_task_name("Name:")
                  │           ├─ task_state("Tgid:/Pid:/PPid:/TracerPid:/Uid:")
                  │           │   ★ TracerPid uses ptrace_parent(task) to obtain tracer pid
                  │           │     (seq_put_decimal_ull(m, "\nTracerPid:\t", tpid))
                  │           ├─ task_mem(VmRSS, etc.; traverse mm_struct)
                  │           ├─ task_sig(SigPnd/ShdPnd/Blocked)
                  │           └─ task_seccomp / task_cap / ...
                  ├─ m->op->next/stop
                  └─ copy_to_iter(m->buf, m->count) ← ★ actual copy from kernel to user buffer
```

### 2.2 The full /proc/self/maps sequence

```
open("/proc/self/maps")
  └─ sys_openat → ... → proc_get_inode
      └─ maps registered by task_mmu.c: proc_pid_maps_operations [source: fs/proc/task_mmu.c@master]
          (.open=pid_maps_open, .read=seq_read, .release=proc_map_release,
           newer kernels also expose .ioctl=procfs_procmap_ioctl for PROCMAP_QUERY, avoiding whole-table parsing)
          └─ pid_maps_open → proc_maps_open(no intermediate do_maps_open; only these two levels in task_mmu.c)
              ├─ __seq_open_private(allocate proc_maps_private)
              └─ proc_mem_open(inode, PTRACE_MODE_READ)→ mm reference(obtain mm_struct)
read(fd, buf, n)
  └─ sys_read → vfs_read → seq_read → seq_read_iter
      └─ seq_operations = proc_pid_maps_op{.start=m_start,.next=m_next,.stop=m_stop,.show=show_map}
          ├─ m_start: vma_iter_init(create VMA iterator over mm maple tree)→ proc_get_vma
          └─ show_map → show_map_vma                          [source: fs/proc/task_mmu.c@master]
              ├─ show_vma_header_prefix(start,end,flags,pgoff,dev,ino)
              │   ★ Permission string "rwxp" derived from vma->vm_flags(VM_READ/VM_WRITE/VM_EXEC/VM_SHARED)
              └─ get_vma_name: file path seq_path / "[heap]" "[stack]" "[vdso]" "[anon:...]"
```

**The proc_reg layer clarified** (a common confusion): `proc_reg_open/proc_reg_read` (fs/proc/inode.c) serves only legacy nodes registered via `proc_create` + `struct proc_ops`; **status goes through proc_single_*, maps through proc_pid_maps_operations - neither passes through the proc_reg layer**. [checked: fs/proc/inode.c@master - proc_reg_file_ops and pde->proc_ops dispatch]

### 2.3 The key conclusion (this chain's most valuable sentence)

**/proc content is generated at read time by the show callback; it does not exist on disk, and what sits in the page cache is not file data either.**
Corollaries:
1. A user-space hook on read/fgets can only modify text "after generation", and only for readers that go through libc - code that reads natively via direct svc still sees the truth (that's why "hooked libc fgets, yet their native direct read still found TracerPid": not a failed hook, incomplete coverage).
2. The data source is task_struct/the maps VMA: the most robust place to change content is **the kernel's show callback or task_struct itself**, not the read exit.
3. Detector and hider meet at the same point: `task_state` reads `ptrace_parent`; `show_map_vma` reads `vma->vm_flags`.

### 2.4 Observation/filtering point table (chain 2)

| Layer | Tool | Recipe essentials |
|---|---|---|
| L3 libc | Interceptor | hook openat filtering path prefixes `/proc/self/`, `/proc/<pid>/`; rewrite text at the read exit (drop frida/gum/rwxp lines, zero TracerPid); only defends libc readers |
| L4 svc | Stalker | capture direct calls; pattern-alert on openat+read combos against maps/status (for studying detection behavior) |
| L5 seq layer | kprobe/fprobe/function hook (kernel module) | rewrite the output of `proc_pid_status` (i.e. PROC_I(inode)->op.proc_show) or `show_map_vma`; covers all readers at once (direct svc included) |
| L5 data source | kernel module/eBPF (rewriting needs root+module) | (1) compare paths at `do_sys_openat2` and return -ENOENT (make the file "not exist") (2) change `ptrace_parent` semantics/`task->ptrace` bits (3) walk the target mm and change `vm_flags` for a given vma's display (note this affects real fault behavior - intercepting the show translation is safer) |
| L5 off-the-shelf | wxshadow-class /proc masquerade modules (material lead; specific project) | the idea = kernel-side openat path filtering + show-callback rewriting; implementation details in area 07's kernel-hook-stealth.md |

### 2.5 Practical tips

- Determining whether the app reads /proc through libc: hook, then reconcile with strace/root-side eBPF - syscall count > hook count means direct calls exist.
- Making one process "unable to see" another: beyond `kill -9`, intercept at the kernel side at the PTRACE_MODE_READ check in `pid_maps_open`/`proc_mem_open` - more elegant than editing every read.
- The maps line format `addr-addr perms offset dev inode pathname` is generated at `show_vma_header_prefix` - the only authoritative translation point for faking maps; user-space-forged maps text is easily exposed by re-parsing (misaligned fields).

## Chain 3: the property-system chain

### 3.1 The read chain (zero syscalls)

```
System.getProperty(key)                    ← Java system properties(System table; distinct from Android properties)
SystemProperties.get("ro.build.tags")      ← framework @hide; reflection call(L1)
  └─ native_get                            ← L2 JNI(libandroid_runtime, android_os_SystemProperties.cpp; verify file)
      └─ __system_property_get(name, value)   ← L3 libc.so export[source: bionic libc/bionic/system_property_api.cpp@main]
          └─ SystemProperties::Get(name,value)  [source: bionic libc/system_properties/system_properties.cpp@main]
              └─ Find(name)
                  └─ contexts_->GetPropAreaForName(name)
                      └─ ContextsSerialized: use /dev/__properties__/property_info
                        (serialized contexts + SELinux rules)to locate target prop_area
                          └─ prop_area::find(name)
                              └─ find_property               [source: bionic libc/system_properties/prop_area.cpp@main]
                                  ├─ Split name at '.' ("ro.build.tags" → ro→build→tags)
                                  ├─ find_prop_trie_node: binary search siblings by left/right
                                  └─ Descend children segment by segment → match prop_info
                              └─ Read(pi):
                                  ├─ Read serial with acquire semantics → copy value(use backup area if dirty bit set)
                                  ├─ Read serial again and compare; retry on change(lock-free consistency)
                                  └─ "ro." prefix short-circuits(read-only properties bypass retry loop)
                          → Return value; no svc anywhere in the read path ★
```

Initialization (once per process): `__libc_init_common -> __system_properties_init -> SystemProperties::Init -> InitContexts -> ContextsSerialized::Initialize -> map_fd_ro`: fstat validation (uid0/gid0/non-group-writable/size sane) -> `mmap(PROT_READ)` `/dev/__properties__/*` -> validate `PROP_AREA_MAGIC/VERSION`. From then on a property read = a pure shared-memory access. [checked: prop_area.cpp@main - map_fd_ro; map_prop_area_rw (init side, O_RDWR|O_CREAT|O_EXCL + fsetxattr SELinux label, ftruncate to PA_SIZE)]

### 3.2 The write chain (over a unix socket, never entering a kernel property subsystem - the kernel has no property system at all)

```
__system_property_set(key, value)          ← L3 libc[source: bionic libc/bionic/system_property_set.cpp@main]
  └─ PropertyServiceConnection
      ├─ socket(AF_LOCAL, SOCK_STREAM|SOCK_CLOEXEC)     ← blocking
      ├─ connect("/dev/socket/property_service")         ← __NR_connect(203); sys.powerctl uses a separate privileged path
      ├─ Detect protocol version: read ro.property_service.version
      └─ v2:SocketWriter.writev { uint32 PROP_MSG_SETPROP2 | len+key | len+value }
          └─ RecvInt32 blocks for acknowledgment(v1: fixed-size prop_msg; assumes success after 250ms poll)

init process side:
StartPropertyService → StartThread(two listeners: /dev/socket/property_service + for_system)
  └─ PropertyServiceThread(epoll)                          [source: system_core init/property_service.cpp@main]
      └─ handle_property_set_fd
          ├─ accept4 + SO_PEERCRED(obtain caller uid/pid)
          └─ PROP_MSG_SETPROP2 → HandlePropertySet
              ├─ CheckPermissions:CheckMacPerms(getpeercon + selinux_check_access)
              ├─ "ctl.*" → SendControlMessage(forward to init main loop for service control)
              ├─ "persist.*"/"next_boot.*" → WritePersistentProperty(/data/property)
              └─ Other keys → PropertySet
                  ├─ __system_property_find
                  │   ├─ Existing → __system_property_update(rewriting ro.* rejected)
                  │   └─ Absent → __system_property_add
                  └─ Increment serial(release semantics)+ __futex_wake(INT32_MAX)

No broadcast: all processes share the same mmap area. When serial changes:
  SystemProperties::Wait(__futex_wait)waiters wake; ordinary readers see the new value on their next read.
fork inheritance: zygote/app mappings come from the parent; init's memory update becomes visible to all immediately ★
```

The `getprop` command: toybox -> `__system_property_foreach` -> `prop_area::foreach_property` (recursive in-order: left->prop->children->right over the trie) -> print. Likewise zero syscalls.

### 3.3 Key structures

| Structure | Defined in | Key members | Notes |
|---|---|---|---|
| prop_area | bionic prop_area.h | magic/version/serial/data | the whole region is PA_SIZE=128KiB (1MiB with LARGE_SYSTEM_PROPERTY_NODE) |
| prop_trie_node (old name/alias prop_bt) | prop_area.cpp | namelen, name, children, left, right | **all 32-bit offsets, not pointers** (shared memory across processes); the old literature's prop_bt is this |
| prop_info | prop_info.h | name, serial, value[PROP_VALUE_MAX=92], long_value_offset | serial encoding: bit0=dirty, bits24+=value length (`SERIAL_VALUE_LEN(serial) = serial>>24`) |
| contexts | contexts_serialized | /dev/__properties__/property_info | the three-level mapping name-prefix -> sub-area file -> SELinux context |

### 3.4 Observation point table (chain 3)

| Layer | Tool | Recipe essentials |
|---|---|---|
| L1 Java | frida Java.use | hook SystemProperties.get/native_get; first scene for faking emulator tells like ro.build.tags/test-keys; Build fields are boot-time snapshots - change them in tandem |
| L3 libc | Interceptor | on `__system_property_get/find/read_callback`; detectors often CRC these function heads |
| Shared-memory layer | mmap it directly (independent of any libc function) | `open("/dev/__properties__/...")+fstat+mmap(PROT_READ)`, walk the trie offsets by hand (the 3.3 structures); **the modification surface is here too**: borrow libc `__system_property_find` to get the prop_info pointer, then **overwrite value in place with equal length** (leave serial untouched - readers never notice; ro. properties, due to the ReadCallback short-circuit, take effect immediately for every read path after the overwrite) |
| Socket layer (user space) | Interceptor on connect/writev | filter sun_path==/dev/socket/property_service to observe all set requests (plaintext key/value) |
| Socket layer (kernel) | kprobe __sys_connect / eBPF | filter by sockaddr_un path; observe the cross-process set surface (needs root). the init-side user-space function handle_property_set_fd can be observed with an **uprobe** (/system/bin/init) - kprobe only reaches the kernel, don't confuse them |

### 3.5 Practical tips

- "Hooked __system_property_get but they still noticed": they bypassed libc and walked the trie themselves via mmap (the same fallback shape as /proc direct reads). The correct answer is to go back to the shared-memory layer and change the value directly - catches everything at once.
- Device-spoofing consistency: after changing in-memory properties, `getprop` (toybox traversal), app reads, and the Build snapshot must all agree, or cross-checks blow the cover (area 09 sec.12).
- Property **reads** have no kernel landing at all - eBPF/kprobe are useless; to observe property reads you must go user-space (instrument libc/so) or modify shared memory plus hardware breakpoints (research environments).
- Tracing "who set a property": the socket layer is one of exactly two entrances (the other is init itself loading build.prop at boot); the observation surface is tiny - ideal for behavioral profiling.

## Chain 4: the IO transparent-decryption chain (reading fortified files)

### 4.1 Chain sequence (file-level encryption by packers/fortifiers)

```
Packer loader(commonly in JNI_OnLoad / .init_array / Application.attachBaseContext)
  └─ Locate encrypted resource(APK assets/SO or separate .dat)
      └─ openat(ciphertext path)                    ← svc 56(packers often call directly to bypass libc hooks)
          └─ sys_openat → ...(same as chain 1)
      └─ read / pread64(ciphertext)                 ← svc 63/67
          └─ Ciphertext enters user-space buffer
      └─ Decryption function(user space only: RC4/XOR stream/AES-ECB·CBC; key often hardcoded or derived from path/package)
          └─ Plaintext(malloc buffer or anonymous mmap area)
              ├─ dlopen in-memory SO(shadow load)/ InMemoryDexClassLoader
              └─ Or write a temporary file, then follow chain 1
ART DexFile consumes plaintext(see chain 5 mmap)
```

The kernel sees only ciphertext the whole way - **encryption/decryption has no syscall** (area 09 special case 3), so kernel-side observation can only get "ciphertext + behavior"; plaintext must be harvested in user space.

### 4.2 Observation strategy (syscall-level paired collection)

1. **Pairing**: openat records (fd->path) -> read/pread64 stores ciphertext by fd -> harvest plaintext at the decryption-function exit -> `ciphertext XOR plaintext` recovers the keystream directly (XOR); for RC4, known plaintext recovers the PRGA output and back-derives the KSA (the key).
2. **Locating the decryption function**:
 - Static: walk the cross-references of libc `read` and inspect each buffer's aftermath (a function where high entropy enters and low entropy leaves is the suspect);
 - Signatures: RC4's 256-byte sbox init loop (0..255 ascending assignment + swap); for AES see the S-box constant `63 7C 77 7B...` in area 09 sec.6;
 - Dynamic: hook malloc/memcpy then entropy-scan; the point where entropy plummets is the decryption exit.
3. **Instruction signatures of arm32 direct svc calls** (a favorite packer trick for bypassing libc; trust the disassembly):
 - `svc #0` = `0xEF000000` (arm32); arm64 is `0xD4000001`, little-endian bytes `01 00 00 D4` (what area 09's memory scan looks for);
 - Loading the syscall number: `mov r7,#imm8` = `0xE3A070xx` (e.g. `mov r7,#56` = 0xE3A07038); numbers >255 (e.g. arm32 openat=322) cannot be encoded as imm8, so the compiler picks `movw` or `ldr r7,[pc,#off]` literal pools - **scan all three signatures together**;
 - Erratum: the material lead's `0xE1A0C007` decodes (verified) to `mov r12,r7` (a register move), **not** a syscall-number load; the correct load family is the `0xE3A07xxx`/movw/ldr above;
 - arm64: `movz x8,#nr` = `0xD2800008 | nr<<5` (mov x8,#64 -> 0xD2800808).
4. **Saving the original function in a trampoline** (when hand-rolling inline hooks): back up the first N entry bytes + an absolute jump; mind arm64 PAC (pointer auth, newer devices) + CFI; frida's Interceptor already builds this layer - use frida when you can (the material lead's native scheme is for when frida is unavailable).
5. **The cheapest path**: frida hooks the decryption-exit function directly for plaintext; if the function cannot be found, settle for the fault/mmap layer of chain 5 (plaintext must eventually be mapped or copied into memory).

### 4.3 Observation point table (chain 4)

| Layer | Tool | Recipe essentials |
|---|---|---|
| L4 syscall (ciphertext side) | Stalker / ptrace / eBPF (root) | capture openat+read combos, store ciphertext by fd; eBPF `sys_enter_read` gets limited content from the ciphertext pointer (needs bpf_probe_read_user) - user-space Stalker is more practical |
| User-space decryption exit | frida Interceptor | collect plaintext directly; locating per 4.2-2 |
| L3 backstop | hook mmap2/mmap + post-scan | if decryption surfaces via mmap, scan the returned region in onLeave for entropy analysis |
| Full memory scan | frida Memory.scan | full-process scan for plaintext headers (ELF magic/dex magic `dex\n035`); dump directions in area 03 |

## Chain 5: the mmap memory-mapping chain (dex-dump relevant)

### 5.1 Mapping-creation sequence

```
mmap(NULL, len, PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, off)    ← L3 libc(thin wrapper)
  └─ svc #0, x8=222(__NR_mmap; arm32 uses mmap2=192 with page-granular off)
      └─ SYSCALL_DEFINE6(mmap_pgoff) → ksys_mmap_pgoff(fget(fd) obtains file)[source: mm/mmap.c@master]
          └─ vm_mmap_pgoff(acquire mmap_lock write lock)
              └─ do_mmap
                  ├─ calc_mmap_flags(prot/flags → vm_flags:VM_READ/VM_WRITE/VM_EXEC/VM_SHARED)
                  ├─ __get_unmapped_area(find gap; security_mmap_addr at end)
                  ├─ security_mmap_file(LSM/SELinux: file label × process label × prot)
                  └─ mmap_region
                      ├─ vm_area_alloc + insert into maple tree(new VMA)
                      ├─ vfs_mmap(file, vma)   ← name on master; call_mmap on Android 5.15~6.6
                      │   └─ file->f_op->mmap:
                      │       ├─ ext4_file_mmap(old name; master uses .mmap_prepare=ext4_file_mmap_prepare,
                      │       │    argument now struct vm_area_desc*)→ vma->vm_ops = ext4_file_vm_ops
                      │       │    (.fault=filemap_fault, .map_pages=filemap_map_pages)
                      │       ├─ f2fs_file_mmap → f2fs_file_vm_ops(.fault=f2fs_filemap_fault[formerly filemap_fault],
                      │       │    .map_pages=filemap_map_pages, .page_mkwrite=f2fs_vm_page_mkwrite)
                      │       └─ EROFS:generic_file_readonly_mmap_prepare(read-only mapping)[source: fs/erofs/data.c@master]
                      ├─ Anonymous mapping(fd==-1): f_op and vm_ops are null → do_anonymous_page on fault
                      └─ vma_set_page_prot(vm_flags→vm_page_prot)→ return addr
```

### 5.2 On-demand loading at first access (page fault)

```
Access mapped page(load/exec instruction; no PTE for data yet)
  └─ EL0 Data/Instruction Abort(hardware exception)
      └─ do_mem_abort → esr_to_fault_info dispatches by ESR FSC [source: arch/arm64/mm/fault.c@master]
          └─ do_translation_fault(user address is_ttbr0_addr)
              └─ do_page_fault
                  ├─ Fast path: lock_vma_under_rcu(per-VMA lock; lock-free VMA lookup)
                  │   └─ handle_mm_fault(FAULT_FLAG_VMA_LOCK); fall back on failure
                  └─ Slow path: lock_mm_and_find_vma → handle_mm_fault
                      └─ __handle_mm_fault → handle_pte_fault
                          └─ do_read_fault(read fault)
                              └─ __do_fault → vma->vm_ops->fault = filemap_fault
                                  ├─ filemap_get_folio(RCU lookup in i_pages)
                                  │   ├─ Page-cache hit:
                                  │   │   filemap_map_pages(around-fault: batch PTEs for adjacent cached pages)
                                  │   │   → alloc_set_pte ★ establish PTE; subsequent access has no fault overhead
                                  │   └─ Miss: do_sync_mmap_readahead → page_cache_sync_ra
                                  │       → Block IO loads page → read_folio → establish PTE
```

ART-side tie-in: DexFile opens .dex/.vdex with `mmap(PROT_READ, MAP_PRIVATE)` and faults on demand (art dex_file_loader, exact function name) - **the "landing moment" of a dex dump = after first execution/fault completion**, matching area 03's active ClassLoader-walk fault-triggering strategy.

### 5.3 The rwxp detection view

- Detector logic: read /proc/self/maps (chain 2) looking for lines whose perms contain `rwxp` - typical targets are the frida agent (gum's code pages) and the self-unpacking packer's executable heap.
- Kernel truth: the maps permission string = `show_map_vma -> show_vma_header_prefix` translating `vma->vm_flags`; `mprotect` goes through `sys_mprotect -> do_mprotect_pkey` and changes both vm_flags and the page tables. **Directly editing vm_flags affects real fault behavior** (removing executability breaks the process); the proper kernel-side masquerade is **intercepting the show translation** (changing `show_map_vma`/`show_vma_header_prefix` output); the user-space masquerade is chain 2's read filtering.
- Newer frida versions use rx/rw split mappings + write toggling for agent pages (exact behavior varies by version), so maps no longer show explicit rwxp - detection and hiding keep dueling here; conclusions drift by version.

### 5.4 Observation point table (chain 5)

| Layer | Tool | Which registers/params to grab |
|---|---|---|
| L3 user space | frida Interceptor on libc `mmap` | onEnter args[0..5] = addr,len,prot,flags,fd,off (arm64: x0~x5); prot contains PROT_EXEC and fd>0 -> packer-load signal |
| L4 | Stalker | svc x8=222 (arm64)/mmap2 (arm32 192), read x0~x5 |
| L5 kprobe | kprobe `vm_mmap_pgoff` | params per the kernel ABI: x0=file*, x1=addr, x2=len, x3=prot, x4=flags (exact positions per your kernel version's ABI) |
| L5 tracepoint | eBPF `syscalls/sys_enter_mmap` | structured fields arg1..arg5, no register reads; pair with `sched_process_mmap` for a full-process mapping profile |
| fault layer | kprobe `filemap_fault`/tracepoint exceptions:page_fault_user | observe on-demand-load timing; when dumping, use it to judge whether a dex page is decrypted and ready |

## 6. Rules common to the five chains

1. **First decide "does it reach a syscall"**: chains 1/2/5 hit svc; chain 3 reads don't; chain 4's decryption math doesn't (only its file/mapping surfaces do). This decides whether eBPF/kprobe have any observation surface.
2. **Where content is generated decides where to modify it**: static files (chain 1) can be changed at the disk/page-cache/user-space layers; pseudo-files (chain 2) must be changed at the show callback or data source; shared memory (chain 3) - change the memory and it takes effect globally.
3. **Direct svc invocation is the natural enemy of every user-space hook**; it exists in three chains (1/2/4); the detection methods (memory scan `01 00 00 D4`/Stalker counting/strace reconciliation) are in area 09 sec.0.
4. **fd is the handle running through chains 1/2/4/5**: openat creates the mapping -> subsequent read/mmap/mprotect all hang off the fd; stand up an fd->path/region table first on the observation side, then filter - the signal-to-noise ratio jumps immediately.
5. Kernel-rewrite techniques (bpf_override_return, show-callback replacement, vm_flags display interception) all need root + the corresponding kernel symbols; for the symbol-renaming drift between common Android kernels and master see the sec.0 version alert - verify names against `/proc/kallsyms` before dropping hooks.

## 7. Version notes (2026-10 snapshot)

- master: `do_filp_open`->`do_file_open`, the `FD_ADD` wrapper, `call_mmap`->`vfs_mmap`, `.mmap`->`.mmap_prepare`+`struct vm_area_desc` (ext4/f2fs/erofs all switched), maps gained the `PROCMAP_QUERY` ioctl. Android device kernels (5.15/6.1/6.6) still use the old names - in the field, /proc/kallsyms is authoritative.
- bionic: `prop_bt` renamed `prop_trie_node` (structurally equivalent); property protocol v2 (PROP_MSG_SETPROP2) default; persist writes can be asynchronous (`ro.property_service.async_persist_writes`).
- Android 11+: /sdcard goes through FUSE/MediaProvider; file observation points move up.

## 8. Checklist

- [ ] libcore's `java_io_FileInputStream.cpp` unreachable on aosp-mirror (404); the internal wrapper function names of readBytes (IoBridge::read?) not verified line-by-line - the JNI names agree with area 09.
- [ ] The JNI registration location of `android_os_SystemProperties.cpp` (frameworks/base/core/jni).
- [ ] The exact ART DexFile mmap function chain (dex_file_).
- [ ] The parameter positions of kprobe `vm_mmap_pgoff` (kernel ABI).
- [ ] The version boundary of frida agent rx/rw split mappings.
- [ ] The specific open-source project behind wxshadow.
- [ ] The internal branches of f2fs_file_read_iter (master file truncated; only search-result evidence -> filemap_read/generic_file_read_iter).
- [ ] bionic fopen/stdio buffer size (affects fgets filtering granularity).

## 9. Verification sources (2026-10-15)

- kernel master: fs/open.c, fs/read_write.c, fs/namei.c (truncated), fs/seq_file.c, fs/proc/base.c, fs/proc/array.c, fs/proc/task_mmu.c, fs/proc/inode.c, fs/ext4/file.c, fs/erofs/data.c, fs/f2fs/file.c (truncated + search corroboration), mm/mmap.c, mm/memory.c (truncated), mm/filemap.c, arch/arm64/mm/fault.c, include/linux/fs.h.
- AOSP (aosp-mirror@main): bionic libc/bionic/system_property_api.cpp, system_property_set.cpp, libc/system_properties/system_properties.cpp, prop_area.cpp; system_core init/property_service.cpp.
- Cross-references: this library's area 09 android-function-layers.md (syscall numbers, five-layer model), area 07 (kernel-hook recipes), area 03 (dex dump).
