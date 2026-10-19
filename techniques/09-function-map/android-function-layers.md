# Android Function Layer Panorama (Five-Layer Model)

> Positioning: in reverse engineering, hooks often get detected/killed (inline hooks caught by integrity checks, the Java layer swept by reflection scans).
> This table answers: **what the function names for the same feature are at each layer — when the upper layer gets killed, drop to a deeper one**.
> Companion playbook: 《[hook-fallback-playbook.md](hook-fallback-playbook.md)》.
> Syscall numbers follow **arm64**, checked against kernel `include/uapi/asm-generic/unistd.h` (arm64 uses this table directly);
> arm32 differences are annotated separately. Facts verified against AOSP source (cs. / android.) and kernel source; uncertain spots are marked.
> Erratum notice: a common misremembering is `__NR_sendto=211` — 211 is **sendmsg**; sendto is **206** (recvfrom=207, recvmsg=212).

## 0. Five-Layer Model and Three Big Exceptions

| Layer | Definition | Typical form | Detection difficulty (attacker's view) |
|---|---|---|---|
| L1 | Java API | Public classes in framework.jar / android.jar | Easiest to detect (Xposed/reflection sweeps) |
| L2 | JNI/ART internals | JNI-registered functions and JVM_* exports inside libart.so / libjavacore.so / libandroid_runtime.so | Medium |
| L3 | bionic/libc + system-library exports | Exported symbols of libc.so / libcrypto.so / libbinder.so (the main battleground of inline/GOT hooks) | Medium-high (instruction CRC/GOT verification can find them) |
| L4 | syscall | `__NR_xxx` → `svc #0` (x8=call number, x0-x5=args) | High stealth (stalker/ptrace breakpoints) |
| L5 | Kernel functions | sys_* → do_* / filp_open / binder_ioctl | Highest (almost no user-mode detection surface; needs root+kernel means) |
**Three big exceptions (they violate the "deeper means closer to syscall" intuition — memorize these before reading the table):**
1. **Property reads make no syscall**: bionic `__system_property_get` reads the mmap'd `/dev/__properties__` shared memory directly — **zero syscalls** after initialization (§3).
2. **Time functions usually never land on svc**: bionic `clock_gettime/gettimeofday/clock_getres` prefer the vDSO function pointer (from `AT_SYSINFO_EHDR`); only when the vDSO is missing does a real syscall happen (§9).
3. **Symmetric crypto has no syscall**: Cipher/EVP/AES all compute in user mode; L4/L5 are empty; the only syscall surface is the randomness source getrandom (§6/§7).
**Five quick ways to identify the layer** (to judge which layer the target app calls at):
1. Inspect so dependencies: linking against libc.so exports only → L3 is hookable; ships its own static libc / hand-written syscalls → L4+ only.
2. IDA import table: no `openat` import yet openat behavior exists → the code issues direct `svc` calls.
3. Memory-scan `01 00 00 D4` (svc #0) to count direct-call sites (details in the fallback doc §3).
4. frida Stalker short-window statistics of the x8 distribution for svc; a mismatch against libc call counts means direct calls exist.
5. Under root, strace the target process and compare the syscall sequence against the libc calls you hooked.

## 0.1 arm64 Syscall Quick Reference (those involved in this library)

| syscall | # | syscall | # | syscall | # |
|---|---|---|---|---|---|
| ioctl | 29 | openat | 56 | close | 57 |
| pipe2 | 59 | getdents64 | 61 | read | 63 |
| write | 64 | pread64 | 67 | readlinkat | 78 |
| newfstatat | 79 | fstat | 80 | unlinkat | 35 |
| faccessat | 48 | fcntl | 25 | dup/dup3 | 23/24 |
| socket | 198 | socketpair | 199 | bind | 200 |
| listen | 201 | accept / accept4 | 202/242 | connect | 203 |
| getsockname | 204 | getpeername | 205 | sendto | 206 |
| recvfrom | 207 | setsockopt | 208 | getsockopt | 209 |
| shutdown | 210 | sendmsg | 211 | recvmsg | 212 |
| clock_gettime | 113 | gettimeofday | 169 | clock_nanosleep | 115 |
| nanosleep | 101 | getpid / getppid | 172/173 | gettid | 178 |
| getuid / geteuid | 174/175 | getgid | 176 | kill / tgkill | 129/131 |
| exit / exit_group | 93/94 | clone / clone3 | 220/435 | execve | 221 |
| wait4 | 260 | rt_sigaction | 134 | set_tid_address | 96 |
| brk | 214 | mmap / munmap | 222/215 | mprotect | 226 |
| madvise | 233 | futex | 98 | prctl | 167 |
| getrandom | 278 | statx | 291 | uname | 160 |
| seccomp | 277 | bpf | 280 | ptrace | 117 |
| process_vm_readv/writev | 270/271 | epoll_create1/ctl/pwait | 20/21/22 | pselect6 / ppoll | 72/73 |
arm32 differences (32-bit ARM, EABI): the socket family has **independent numbering** (socket=281, bind=282, connect=283, listen=284, accept=285, getsockname=286, getpeername=287, socketpair=288, sendto=290, recvfrom=292, shutdown=293, setsockopt=294, getsockopt=295, sendmsg=296, recvmsg=297, from `arch/arm/tools/syscall.tbl`); **socketcall(102) is only the multiplexed entry of old architectures like x86-32 — neither arm32 EABI nor arm64 has it**. openat=322, mmap2=192, clock_gettime=263 (time64 variant 403), getrandom=384, clone=120, ioctl=54.

## 0.2 L2 System-Library Map (which so carries which JNI functions)

| so | What it carries | Typical symbol prefixes |
|---|---|---|
| libart.so | ART runtime, java.lang core natives, JVM_* bridges | `JVM_`, `Java_java_lang_`, `art::` (mangled) |
| libjavacore.so | JNI for java.io / java.net / libcore.io | `Java_java_io_`, `Java_java_net_`, `Java_libcore_io_` |
| libjavacrypto.so | Conscrypt (javax.crypto/java.security) | `Java_com_android_org_conscrypt_` |
| libandroid_runtime.so | android.* framework-class natives | `Java_android_` (e.g., `Java_android_os_Process_`) |
| libbinder.so | binder IPC transport layer (C++) | `IPCThreadState::`, `android_util_Binder` |
| libandroid.so | Public NDK C API | `AAssetManager_`, `ASensorManager_` |
Memory mnemonic: java.lang→libart, crypto→libjavacrypto, android.*→libandroid_runtime.

## 0.3 Full Penetration Example: What one Java file read actually passes through

```
new FileInputStream("/sdcard/a.dat").read(buf)
  → L1  FileInputStream.read(byte[])                    [libcore Java]
  → L2  Java_java_io_FileInputStream_readBytes          [libjavacore.so 导出]
  → L3  openat() / read()                               [libc.so 导出]
  → L4  svc #0,x8=56(openat)/ x8=63(read)              [指令级]
  → L5  sys_openat → do_sys_openat2 → do_filp_open;
        ksys_read → vfs_read → 文件系统 read_iter       [kernel]
```

Read it alongside the fallback doc: hook L1 detected → L2 exported symbols → L3 libc (mind byte verification) → L4 svc (mind app direct calls) → L5 (needs root).
For the "how it gets killed" judgment and the code at each layer, see 《hook-fallback-playbook.md》 case by case.

## 1. File I/O

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `File.exists/canRead`, `FileInputStream.read`, `FileOutputStream.write`, `RandomAccessFile` | framework (built on libcore) | File attribute queries go through the `UnixFileSystem` native | `Java.use` replacement is easiest, but leaves the heaviest Xposed/frida traces |
| L2 | `Java_java_io_FileInputStream_open0/readBytes`, `Java_libcore_io_Posix_open/read/close` | **libjavacore.so** (all JNI for java.io/java.net/libcore.io is registered here; see libcore `Register.cpp`) | open0 internally goes IoBridge→Posix native | Just hook the exported symbol; no need to touch ART |
| L3 | `open/open64`, `openat`, `fopen`, `read`, `write`, `pread`, `close`, `fstat`, `faccessat` | libc.so | bionic's `open` is actually an openat wrapper; fopen wraps openat again | Interceptor's main battleground; note that apps CRC-verify function-head bytes |
| L4 | `__NR_openat`(56), `__NR_read`(63), `__NR_write`(64), `__NR_close`(57), `__NR_pread64`(67), `__NR_fstat`(80), `__NR_faccessat`(48) | svc instruction | `svc #0`, x8=number | When hooking libc isn't enough: stalker catch svc / inline breakpoints |
| L5 | `sys_openat` → `do_sys_openat2` (old name do_sys_open) → `do_filp_open` → `path_openat`; `filp_open` (the kernel-internal open entry); `ksys_read` → `vfs_read` | kernel | fs/open.c, fs/namei.c | rootkit/kprobe territory; eBPF tracepoint `syscalls/sys_enter_openat` |
**/proc/self/maps and /proc/self/status read chains (the core anti-detection paths):**

| Layer | Path |
|---|---|
| L1-L2 | Same as above (File + libjavacore); no dedicated API |
| L3 | `openat("/proc/self/maps")` + `read` loop; status likewise (it is the app itself that parses the text to grab the TracerPid field) |
| L4 | openat(56)+read(63); hard-confrontation apps read via direct svc — libc hooks are all dead |
| L5 | `sys_openat` → `proc_reg_open` → `proc_maps_open`, content produced by seq_file (`show_map`/`show_proc`); hooking the kernel can rewrite the output — highest difficulty |
**Domain practice tips**
- Apps most often strike L3: CRC/hash self-verification of the first 16 bytes of libc `open/read`, or comparison of GOT entry targets.
- The key to hiding frida = hook L3 `openat`+`read`: **return-content filtering** for the maps/status/task directories (delete frida/gum lines) — more thorough than renaming.
- The stealthiest is L4 direct svc (hand-written assembly reading maps); then only Stalker-following or the kernel layer can catch it — see fallback doc case 1.

## 2. Networking

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `.Socket`, `HttpURLConnection`, OkHttp (third-party; ultimately also goes through Socket), `NetworkInterface.getNetworkInterfaces` | framework/libcore | For capture, the first pick is modifying SSLContext/OkHttp interceptors | The Java layer is easily detected by RASP (hook frames in the stack) |
| L2 | `Java_libcore_io_Posix_connect/sendto/recvfrom/socket` | libjavacore.so | NioSocketImpl/PlainSocketImpl all converge into the Posix natives | Equivalent to the old hooking of PlainSocketImpl, more stable |
| L3 | `socket/connect/bind/listen/accept/send/sendto/recv/recvfrom/write/read` (fd operations), `getaddrinfo/gethostbyname` (DNS, via netd or direct UDP), `getifaddrs`, `if_nametoindex` | libc.so | bionic DNS goes from the resolver over a netd socket (the exact path varies by version) | connect captures target addresses; send/recv captures traffic |
| L4 | `__NR_socket`(198), `__NR_connect`(203), `__NR_sendto`(**206**), `__NR_recvfrom`(207), `__NR_sendmsg`(211), `__NR_recvmsg`(212), `__NR_getsockname`(204), `__NR_shutdown`(210) | svc instruction | Note 211 is sendmsg; x86-32's socketcall multiplexed entry does not exist on arm | Apps issuing direct svc calls need stalker |
| L5 | `sys_socket` → `__sys_socket` → `sock_create`; `sys_connect` → `__sys_connect` → `inet_stream_connect` (net/ipv4/af_inet.c); `__sys_sendto` → `sock_sendmsg` | kernel | The endpoint of TCP connection establishment | kprobe `__sys_connect` sees every connection (direct calls included) |
**VPN/NIC detection surface (frequently used by risk control):**
- `getifaddrs` (libc): enumerates NIC names (tun0/wg0/rs***[] to flag VPN/proxy); bionic implements it via a **netlink socket** (AF_NETLINK + RTM_GETLINK, i.e., sendmsg/recvmsg syscalls), not ioctl;
- `if_nametoindex` (libc): `ioctl(SIOCGIFINDEX)`;
- Reading `/proc/net/route` (openat+read) to see the default route;
- `ConnectivityManager.hasTransport(TRANSPORT_VPN)`: goes over binder to system_server connectivity (same chain as §8).
**Domain practice tips**
- Port-scan detection of frida (connecting to 127.0.0.1:27042 and checking the D-Bus banner) happens in this domain; when the app issues direct svc connects, hooking libc is useless → fallback doc case 2.
- For capturing keyed traffic, prefer L1 (OkHttp interceptor/SSLContext); only heavy confrontation needs L4.
- MAC-address risk control: `NetworkInterface.getHardwareAddress` → libjavacore → getifaddrs (netlink); hooking getifaddrs can change it uniformly.

## 3. Property System (SystemProperties)

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `System.getProperty` (Java system properties — **a different system from Android properties, don't confuse them**), `SystemProperties.get` (@hide, called via app reflection) | framework | Reflectively calling @hide trips the hidden-API restrictions | Hook SystemProperties.get to change ro.build.tags etc. — ground zero of emulator/root-detection confrontation |
| L2 | No JNI layer — framework calls the libc export directly (reflection→native) | — | Direct pass-through between layers | None |
| L3 | `__system_property_get`, `__system_property_find`, `__system_property_read_callback`, `__system_property_serial` (libc.so exports) | libc.so | **Read = a pure shared-memory operation, zero syscalls** (bionic `system_property_api.cpp` delegates to SystemProperties::Get) | Hook get to change the return value; but an app can self-mmap to bypass (see tips) |
| L4 | Read: **no syscall**. set: `__system_property_set` → connects to `/dev/socket/property_service` (unix socket) to send the request → involves connect/write | libc + init | The property area is initialized by libc via `__system_properties_init` → mmap `/dev/__properties__`; zygote descendants can also reload via `__system_properties_zygote_reload` | There is no syscall to intercept for "reading properties"; you can only intercept mmap or modify memory |
| L5 | **No property system on the kernel side** (no sys_prop); property writes are ultimately persisted/broadcast by the init process | kernel (nonexistent) | A typical case of L4/L5 being empty in the five-layer model | — |
**Domain practice tips**
- Hard-confrontation apps skip the libc functions: they mmap `/dev/__properties__` themselves and parse the prop trie (including SELinux property contexts) — hooking `__system_property_get` is then completely useless.
- The correct answer is to **modify the shared memory directly**: locate the /dev/__properties__ mapping from maps → borrow libc `__system_property_find` to get the prop_info pointer → overwrite the value bytes with same-length data; every read path is covered in one strike (fallback doc case 3).
- ro. being read-only applies to set; in-memory modification is unrestricted.

## 4. Process/Thread

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `Process.myPid/myUid/myTid`, `Process.killProcess`, `Thread.start`, `Runtime.exec` (ProcessBuilder) | framework | exec chain: ProcessBuilder→libcore Posix natives (fork+exec) | The starting point of thread-count/thread-name risk control |
| L2 | `JVM_StartThread` (a C symbol exported by libart), `art::Thread::Create` (C++ mangled) | libart.so | Thread.start ultimately enters ART thread creation | Hooking JVM_StartThread intercepts ART-level thread creation |
| L3 | `pthread_create/pthread_exit` (libc), `clone`, `fork` (a wrapper over clone), `getpid/gettid/getppid`, `kill/tgkill`, `exit/_exit`, `waitpid`, `pthread_setname_np` | libc.so | bionic pthread_create goes through clone internally; thread names go via prctl(PR_SET_NAME) | Hook pthread_create to catch thread creation; thread names are a frida detection surface (gum-js-loop etc.) |
| L4 | `__NR_clone`(220), `__NR_clone3`(435), `__NR_getpid`(172), `__NR_gettid`(178), `__NR_getppid`(173), `__NR_kill`(129), `__NR_tgkill`(131), `__NR_exit_group`(94), `__NR_execve`(221), `__NR_wait4`(260), `__NR_rt_sigaction`(134), `__NR_set_tid_address`(96) | svc instruction | arm64 has no separate fork syscall; fork=clone(SIGCHLD,0) | Hand-written direct clone calls bypass the pthread hook → fallback doc case 6 |
| L5 | `sys_clone` → `kernel_clone` (named `_do_fork` before 5.9) → `copy_process`; `sys_getpid` (reads current->tgid); `do_group_exit`; `sys_kill` → `kill_something_info` | kernel | kernel/fork.c, kernel/exit.c, kernel/signal.c | eBPF tracepoint `sched/sched_process_fork` observes all thread creation (direct calls included) |
**Domain practice tips**
- Anti-debugging signal self-traps (the app installing a handler for SIGTRAP) happen at rt_sigaction (134) and tgkill (131); hooking the signal family lets you observe them.
- frida's thread names (gum-js-loop/gmain/pool-frida-*) get exposed via /proc/self/task enumeration + reading comm; the countermeasure lives in the file domain (getdents64/read filtering), not this domain.
- Thread-count risk control (a sudden 3-5 extra threads) can only be met by injecting fewer threads or altering getdents64 results.

## 5. Memory

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `ByteBuffer.allocateDirect`, `Unsafe.allocateMemory` (restricted) | libcore | The Java entry to direct memory | Rarely used |
| L2 | `Unsafe_AllocateMemory` (art/runtime/native/sun_misc_), `NewDirectByteBuffer` | libart.so | JNI-level allocation | Useful for locating direct-memory blocks when dumping/unpacking |
| L3 | `malloc/free/calloc/realloc` (libc; the backend is **scudo** — the default allocator since Android 11, jemalloc before that), `mmap/munmap/mprotect/madvise` | libc.so | scudo mmaps large blocks directly; small bins go through caches | Hook malloc to grab plaintext keys/passwords; watch mprotect to observe self-unpacking |
| L4 | `__NR_mmap`(222), `__NR_munmap`(215), `__NR_mprotect`(226), `__NR_madvise`(233), `__NR_brk`(214, basically unused by scudo — detail), cross-process: `__NR_process_vm_readv`(270)/`writev`(271) | svc instruction | Dumping another process = process_vm_readv | Packer loaders often issue direct svc mprotect calls to unlock code sections |
| L5 | `sys_mmap` → `ksys_mmap_pgoff` → `vm_mmap_pgoff`; `sys_mprotect` → `do_mprotect_pkey` | kernel | mm/mmap.c, mm/mprotect.c | Kernel-mode hooks can observe mapping changes globally |
**Domain practice tips**
- The essence of inline hooks being caught by CRC is that L3 code-section bytes were altered; the counter is to switch to L4 breakpoints or KernelPatch/kprobe — see the fallback doc.
- The unpacking trio all lands in this domain: mprotect (section unlocking), mmap (mapping the dex), process_vm_readv (pulling the dex).
- scudo's free quarantine/delay makes "reading freed memory" behave differently from the jemalloc era (mind this when mining wild-pointer data).

## 6. Crypto

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `javax.crypto.Cipher` (init/doFinal), `Mac`, `MessageDigest`, `SecretKeySpec` | framework (Conscrypt provider) | Hooking doFinal at L1 grabs plaintext/ciphertext directly — cheapest | Fails when obfuscation/RASP inspects the call stack |
| L2 | `Java_com_android_org_conscrypt_NativeCrypto_*` (EVP_CIPHER_CTX / evp_aead family natives) | libjavacrypto.so (Conscrypt) | The JNI implementation of Cipher/Mac/MessageDigest | Steadier than reflection; exported symbols attachable |
| L3 | `EVP_EncryptInit_ex/EVP_CipherUpdate/EVP_EncryptFinal_ex`, `EVP_DigestInit/Update/Final`, `HMAC_Init_ex`, `AES_set_encrypt_key`, `RAND_bytes` | libcrypto.so (BoringSSL) | Plaintext/keys are most complete in the update arguments | The optimal hook layer for the system path; if the app's so statically links boringssl there are no exports (fallback doc case 5) |
| L4 | **No syscall (pure user-mode computation)**; sole exception: the randomness source `__NR_getrandom`(278), reading `/dev/urandom` (openat 56+read 63) | — | AES/RSA/HMAC all complete in user space | Grabbing key randomness = hook getrandom |
| L5 | None (no kernel-accelerated path) | — | — | — |
**Identification points (finding statically linked crypto implementations):**
- arm64 crypto extension instructions: `AESE/AESD/AESMC` (AESE=0x4E2848xx, AESD=0x4E2858xx, AESMC=0x4E2868xx encoding families; the exact bit patterns per the disassembly);
- AES S-box / Te0 constant bytes (`63 7C 77 7B F2 6B 6F C5...`) appearing in .rodata;
- The string "BoringSSL"/version tags often survive in statically linked artifacts — locate first, then walk cross-references backward.
**Domain practice tips**
- The system path (HTTPS/TLS, default provider) goes through libcrypto.so — straight to L3; when the app ships a so with static boringssl, L3 fails; retreat to L1 for plaintext or signature-based locating (case 5).
- Hooking `RAND_bytes`/getrandom is the low-cost surface for catching "key generation" — it often hits before the decryption function.

## 7. Randomness

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `SecureRandom.nextBytes/nextInt`, `UUID.randomUUID` (internally goes through SecureRandom) | libcore | Entry point of challenge codes/nonces/key seeds | — |
| L2 | `NativeCrypto.RAND_BYTES` | libjavacrypto.so | SecureRandom's native path (OpenSSL provider) | Attach the exported symbol |
| L3 | `RAND_bytes` (libcrypto.so), `getrandom` (libc.so), `open("/dev/urandom")` | libcrypto.so / libc.so | BoringSSL prefers getrandom, falling back to the urandom file (order varies by version) | The most practical layer for grabbing nonces/key seeds |
| L4 | `__NR_getrandom`(278), `__NR_openat`(56, /dev/urandom)+`__NR_read`(63) | svc instruction | — | For direct svc calls, stalker catches x8=278 |
| L5 | `sys_getrandom` → `__do_sys_getrandom` → CRNG read (function names change across kernel versions; 6.x uses get_random_bytes_user) | kernel | drivers/char/random.c | Audit-grade; rewriting is hard |
**Domain practice tips**
- Risk-control device fingerprints often use SecureRandom to generate challenges; pinning the getrandom return makes replay possible.
- Old sos that open urandom directly as a file still exist (compat code); file-domain hooks cover them in passing.

## 8. Package Info/Signatures (structurally identical to every binder service)

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `PackageManager.getPackageInfo(GET_SIGNATURES)`, `getInstalledPackages`, `checkSelfPermission` | framework | The data source of emulator/root/re-signing detection | Replacing return values (changing signatures/Installer/PACKAGE_USAGE_STATS) is standard for device spoofing |
| L2 | `IPackageManager$Stub$Proxy` → `BinderProxy.transact` → `android_util_Binder` | framework.jar + libandroid_runtime.so | The proxy object assembles the parcel inside the app process | Hooking transact is too broad; filter by transaction code |
| L3 | `IPCThreadState::transact/talkWithDriver` (libbinder.so), `ioctl` (libc) | libbinder.so | All binder converges into the ioctl on /dev/binder | Hook ioctl + parse binder_write_read to grab traffic without the Java layer |
| L4 | `__NR_ioctl`(29), fd pointing at /dev/binder | svc instruction | BC_TRANSACTION/BINDER_WRITE_READ command words | High volume; must filter by target ptr/handle |
| L5 | `sys_ioctl` → `binder_ioctl` → `binder_ioctl_write_read` → `binder_thread_write` → `binder_transaction` (drivers/android/binder.c) | kernel | The actual cross-process execution point | Kernel hooks can audit binder globally (needs root) |
Supplement: obtaining a service proxy first passes **servicemanager** (a user-mode daemon that is itself a binder client); hooking `svcmgr_*`/`getService` lets you observe service queries.
**Domain practice tips**
- App-side signature checks are mostly L1 re-wrappers (locally digesting the signatures from getPackageInfo results); changing the L1 return fools them; if the so parses the base.apk ZIP to pull the CN=RSA certificate, go through the file domain instead.
- binder is the "universal L4": every system service at the Java layer (settings/phone/accounts) converges into ioctl 29 — learning to filter by handle+code amounts to holding the full system-call surface.

## 9. Time

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `System.currentTimeMillis/nanoTime`, `SystemClock.uptimeMillis/elapsedRealtime`, `Date/Calendar` | framework | Risk-control double-read delta detection launches from this layer | Java hooks leave heavy traces |
| L2 | `JVM_CurrentTimeMillis`, `JVM_NanoTime` (libart exports) | libart.so | ART internally calls libc clock_gettime directly | Hooking these two exports covers all Java time reads (native direct calls excluded) |
| L3 | `clock_gettime`, `gettimeofday`, `clock_getres` (libc.so) | libc.so | **bionic prefers the vDSO function pointer** (`__libc_globals->vdso[]`, initialized from `getauxval(AT_SYSINFO_EHDR)`); when non-null, no syscall happens; only when null does `__clock_gettime` do a real syscall | Hooking only libc clock_gettime **works for calls that go through libc**; if the app cached the vDSO pointer and calls directly, they leak through |
| L4 | `__NR_clock_gettime`(113), `__NR_gettimeofday`(169), `__NR_clock_nanosleep`(115), `__NR_nanosleep`(101) | svc instruction | The normal path **produces no svc** (the vDSO absorbs it) — counter to intuition | Syscall breakpoints cannot catch vDSO calls! |
| L5 | vDSO implementation: reads the arm64 system register CNTVCT_EL0 + vvar page data; syscall path `sys_clock_gettime` (kernel/time/posix-timers.c) | kernel / vDSO | The vDSO shows as `[vdso]` in maps, vvar as `[vvar]` | Modify vDSO code (mprotect first) or kernel time offsets |
**Domain practice tips**
- The first suspect when "hooking libc clock_gettime catches nothing" = the vDSO; the second = the app took AT_SYSINFO_EHDR and parsed/called it itself (fallback doc case 4 gives the vDSO patch).
- Time-based risk control is essentially a double-read delta (one read before and after the operation; a large delta flags hook/debugging): the counter is not to intercept the read but to **compensate the return value** (maintain small monotonic increments).
- On x86/x86_64 time also lives in the vDSO; on arm64 the vDSO time functions are only clock_gettime/clock_getres/gettimeofday (bionic vdso.cpp hooks exactly these three; the vDSO segment also contains an rt_sigreturn stub, unrelated to time reads).

## 10. UID/Process Info

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `android.os.Process.myUid/myPid/myTid`, `Build` (fields come from boot properties, cross-ref §3) | framework | — | — |
| L2 | `android_os_Process_*` (libandroid_runtime.so) | libandroid_runtime.so | Natives of myUid etc. | Rarely used |
| L3 | `getuid/geteuid/getgid/egid`, `getpid/getppid/gettid` (libc.so) | libc.so | — | Hook getuid to fool uid checks; group list via getgroups |
| L4 | `__NR_getuid`(174), `__NR_geteuid`(175), `__NR_getgid`(176), `__NR_getpid`(172), `__NR_gettid`(178) | svc instruction | For direct calls, again only L4 means work | svc breakpoints/stalker |
| L5 | `sys_getuid` → `from_kuid_munged(current_user_ns, current_uid)`; `sys_getpid` reads current->tgid | kernel | kernel/sys.c | — |
**Domain practice tips**
- Shared-uid/multi-process apps (an app process group sharing one uid) commonly judge package ownership via myUid+packagename mapping — verified at the binder end (system_server); changing the local getuid cannot fool the server.
- The whole `Build` family is actually a snapshot of the property domain (§3); device spoofing must change both domains together, otherwise the mismatch between properties and getters gets caught.

## 11. Input/Sensors (for offline spoofing)

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `SensorManager.getSensorList/registerListener`, the `onSensorChanged` callback, `MotionEvent.obtain` | framework | Offline spoofing changes gravity/gyro/step-count sources | Changing onSensorChanged's values is cheapest |
| L2 | `android_hardware_SensorManager_*` (libandroid_runtime.so), InputChannel event dispatch (system_server→app over a socketpair) | libandroid_runtime.so | Input events are delivered via InputChannel (unix socket) | — |
| L3 | NDK: `ASensorManager_getInstanceForPackage`, `ASensorEventQueue_getEvents` (libandroid.so→libsensor.so); the event channel BitTube = `recvmsg/sendmsg` over a socketpair; the collection end EventHub (system_server) reads `/dev/input/eventX` | libandroid.so / libsensor.so | The native sensor client goes over binder to the sensorservice daemon | Hook recvmsg filtered by pipe fd; injection via /dev/uinput needs root |
| L4 | `__NR_ioctl`(29, binder), `__NR_recvmsg`(212)/`__NR_sendmsg`(211) (events), `__NR_openat`(56, /dev/input/eventX)+`__NR_read`(63), injection writes `__NR_write`(64)/uinput | svc instruction | — | The event stream is fully observable at the svc layer |
| L5 | `sys_ioctl` → binder_ioctl; sensorservice→HAL; `evdev_read/evdev_write` (drivers/input/evdev.c), uinput (device injection) | kernel | — | Changing events in the kernel is the ultimate form |
**Domain practice tips**
- The most practical offline spoof = L1 changing onSensorChanged + time-domain compensation (sensor-event timestamps cross-verified against the system clock is the most common tell).
- Synthetic data lacks physical continuity (abrupt acceleration changes/constant gravity); risk control sees through it at the sensor-feature layer — hooking is only a necessary condition.
- Root injection uses sendevent/uinput; without root you can only dispatchTouchEvent at the Activity layer, which the app's built-in checks can notice by origin.

## 12. Device Identifiers

| Layer | Function/symbol | Module | Notes | Hook key points |
|---|---|---|---|---|
| L1 | `Settings.Secure.getString(ANDROID_ID)`, `TelephonyManager.getDeviceId/getImei/getSubscriberId`, `Build.getSerial`, OAID (vendor SDK) | framework | IMEI consistency is verified on the modem side — the hardest to forge | The main battleground of device spoofing: hook L1 + property-domain linkage |
| L2 | ContentResolver→ActivityThread→`IContentProvider$Stub$Proxy` (SettingsProvider lives in system_server); `ITelephony$Stub$Proxy`→phone process (com.android.phone)→RIL | framework.jar | ANDROID_ID lives in SettingsProvider; IMEI leaves via the phone process to the modem | Hooking proxy transact requires filtering by URI/code |
| L3 | The binder chain (libbinder transact→ioctl); `__system_property_get` (ro.serialno etc.); `/sys` node reads (openat, e.g., serialno/boards — paths differ per vendor) | libbinder.so / libc.so | — | Property changes as in §3 |
| L4 | `__NR_ioctl`(29, binder), `__NR_openat`(56, /sys files) | svc instruction | — | The binder full-filtering method as in §8 |
| L5 | `sys_ioctl` → binder_ioctl; `sys_openat` → sysfs nodes | kernel | — | — |
**Domain practice tips**
- Each vendor's OAID chain is proprietary (HMS/MSA etc., mostly their own binder services or content providers — details omitted); the generic approach is hooking the vendor SDK's Java entry.
- The most common device-spoofing tells: ANDROID_ID mismatched against the SettingsProvider database, serial mismatched against properties — when changing in-memory return values, remember to sync the system-side visible values.
- IMEI/modem-side consistency checks cannot be bypassed by local hooks; only the protocol layer can handle them.

## 13. Cross-Domain Patterns (how to read this table)

1. **First ask "does this feature land on a syscall"**: property reads, crypto computation, and vDSO time are the three big "no-svc" exceptions — L4 means are inherently ineffective against them.
2. **binder unifies everything**: every system service (package management/settings/phone/sensors/connectivity) converges into `ioctl(/dev/binder)` → `binder_ioctl`; filtering by handle+code at L4 is the universal capture method.
3. **User-mode library split**: libjavacore, libjavacrypto (Conscrypt), libart (JVM_*/art::), libandroid_runtime (android_*) — before an L2 hook, confirm which so the function hangs on.
4. **The standard action sequence when an upper layer gets killed**: switch hook style (inline↔GOT↔exported symbol) → switch layer (L3→L2 or L1) → L4 break on svc → L5 kernel. Step by step in 《hook-fallback-playbook.md》.
5. **Direct svc calls are the natural enemy of L3 hooks** — first establish their existence via memory scanning/strace, then pick your means.
6. **L2 is the cost-effectiveness depression**: exported symbols of libjavacore/libjavacrypto go undefended for years (CRC checks all stare at libc); when the Java layer gets swept, drop half a layer to L2 rather than charging straight at L4.
7. **Return-value rewrites must change the system side too**: values fooled by local hooks, if cross-verifiable on the system_server side (signatures/settings/accounts), must be synced (e.g., changing the SettingsProvider database/property shared memory directly) — otherwise a tell is guaranteed (§12).

## 14. Version Notes (2026-10 snapshot)

- Android 11+: the default native allocator is scudo (§5); jemalloc before that.
- Android 8+: the property area is a serialized trie (`/dev/__properties__` multiple files + SELinux contexts); the prop_info layout differs from old versions (§3).
- kernel 5.9+: `_do_fork` renamed `kernel_clone` (§4); the naming of `do_sys_openat2` on the openat path should likewise be verified per version.
- 16KB-page kernels (A15+ pilots) do not affect syscall numbers, but do affect mmap alignment and the stride assumptions of scanning scripts.

## 15. Checklist (verify first when refreshing)

- [ ] Whether bionic DNS resolution uniformly goes through the netd socket (changes across Android versions).
- [ ] Whether scudo entirely skips brk (214), or keeps a low-probability path.
- [ ] The getrandom/urandom fallback order of BoringSSL RAND_bytes on the current AOSP branch.
- [ ] The internal function name of `sys_getrandom` (random.c refactors frequently across 6.x minor versions).
- [ ] The arm64 AESE/AESMC instruction-encoding constants (for precise masks in signature scanning).
- [ ] The exact binder service names of each vendor's OAID chain (HMS/MSA/Xiaomi/OPPO).
- [ ] The precise binder interface of Build.getSerial (suspected ITelephony/IPhoneSubInfo family — to be verified).

## 16. Source Anchors

- arm64 syscall numbers: kernel `include/uapi/asm-generic/unistd.h` (torvalds master).
- arm32 syscall numbers: kernel `arch/arm/tools/syscall.tbl`.
- Property shared-memory mechanism: bionic `libc/bionic/system_property_api.cpp`.
- vDSO-preference policy: bionic `libc/bionic/vdso.cpp`.
- libjavacore carrying the JNI: libcore `luni/src/main/native/Register.cpp` (the JNI registration table).
- Binder kernel chain: kernel `drivers/android/binder.c`.
- Allocator: scudo default since Android 11 (jemalloc before), per the AOSP release notes.
