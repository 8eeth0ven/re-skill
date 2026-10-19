# Cross-Platform Kernel Quick Reference (iOS / macOS / Windows / Generic)

> Positioning: **kernel-level extended knowledge beyond the main Android battlefield**, for cross-reference and as an upgrade path.
> Three-tier information organization: **attack surface -> data structures/key functions -> tool entry points**.
> Entries marked `[verified]` have been checked against official sources; entries marked `[]` come from user materials with no public source found - re-verify before use.

## 0. Fact-verification table

| Item | Verification result | Source |
|---|---|---|
| CVE-2026-46242 "Bad Epoll" | Confirmed: Linux eventpoll `ep_remove` keeps using `@file` after clearing `file->f_ep`, racing `__fput`'s `eventpoll_release` fast path -> struct eventpoll / struct file **UAF** | cvelistV5 official JSON `[verified]` |
| RTCore64 CVE-2024-1460 | Confirmed but **the type is a kernel memory leak** (MSI Afterburner v4.6.5.16370, RTCore64.sys IOCTL 0x80002040, handle requires a high-integrity process); its classic **arbitrary read/write** is CVE-2019-16098 | cvelistV5 `[verified]` |
| WinRing0 CVE-2020-14979 | Confirmed: WinRing0.sys/WinRing0x64.sys 1.2.0 (bundled with EVGA Precision X1 <=1.0.6), arbitrary physical memory read/write, mapping `\Device\PhysicalMemory` -> SYSTEM | cvelistV5 `[verified]` |
| BdApiUtil CVE-2024-51324 | **Correction: it is Baidu Antivirus v5.2.3.116083**, not Bitdefender; BYOVD terminating arbitrary processes (AV-vs-AV / anti-EDR use) | cvelistV5 `[verified]` |
| MTE vs KASAN/KFENCE | KASAN's three modes (Generic / SW_TAGS / HW_TAGS) are **mutually exclusive, pick one**; HW_TAGS builds on arm64 MTE. **KFENCE complements KASAN and is not mutually exclusive** (official wording "complementary") - the claim in the source material that "kasan and kfence are mutually exclusive" does not hold | kernel Documentation/dev-tools/kasan.rst + kfence.rst `[verified]` |
| KTRW | Confirmed: a Google Project Zero (Brandon Azad) iOS kernel debugger that uses A11 external debug registers to bypass KTRR and remap the kernel writable | `[verified]` |
| iOS 26.5 removes most of kdp_core | **No public source found**; the claim that only the remote-debugging portion remains does not conflict with the official Kernel Debug Kit docs | `[]` |
| DeepZero (AI screening kernel drivers for exploitability) | No kernel-fuzzing paper of this name found on arXiv/Crossref (the identically named paper is in zeroth-order optimization) | `[]` |
| XM Cyber privileged XPC disabling enterprise security tools | Not verified verbatim; widely reported in the industry (macOS privileged XPC services abused to disable EDR) | `[]` |

## 1. Generic kernel capabilities (cross-architecture)

### 1.1 Kernel-mode assembly / exception-context constraints

Three iron rules of kernel code: **never trust user pointers, never fault, never sleep** (in atomic contexts). Point by point:
- **Never trust user pointers**: kernel access to user memory must go through exception-guarded paths like `copy_from_user/copy_to_user` (Linux) / `ProbeForRead + __try` (Windows); dereferencing a user pointer directly = user space can control the page-table contents (fault, swap mapping, unmap) -> an arbitrary kernel read/write primitive.
- **Never fault**: kernel memory must be resident; faulting/sleeping while holding a spinlock = deadlock/BSOD. When reversing race bugs, look first for "allocate/copy under a lock".
- **Never sleep**: inside atomic contexts (spinlock/rcu/softirq) `kmalloc(GFP_KERNEL)`/waiting is forbidden; wrong allocation flags are a steady source of kernel bugs.
**x86-64**

| Mechanism | Essentials | Relation to vulnerabilities |
|---|---|---|
| swapgs | syscall/interrupt entry switches GS base (user GS <-> kernel GS) | Missing swapgs on an error path -> kernel pointer used as user pointer; a classic local privilege-escalation surface |
| sysret vs iretq | sysret is the fast return that doesn't reload all state; iretq does full restore | sysret to a non-canonical address raises #GP handled in kernel mode (the historical CVE-2012-0217 pattern); iretq restoring SS raises #SS (mitigated by espfix64) |
| CR3 | page-table physical base register | KPTI (Meltdown mitigation): user/kernel dual page tables, the user table keeps only a trampoline entry - important background for KASLR bypass and privilege-escalation ROP |
| SMAP/SMEP | SMAP blocks kernel access to user pages (AC flag + stac/clac toggles); SMEP blocks kernel execution of user-page code | Kernel ROP cannot jump straight to shellcode; ret2dir/physical-map aliasing was once the bypass |
**ARM64**

| Mechanism | Essentials | Relation to vulnerabilities |
|---|---|---|
| VBAR_EL1 | exception vector base, 16 entries (SP_EL0/SP_ELx x current/lower EL x 4 exception classes) | The fixed starting point of kernel-entry code audits |
| ELR_EL1 / SPSR_EL1 | exception return address / saved PSTATE | Tampering = control-flow hijack (given an arbitrary write) |
| TTBR0_EL1 / TTBR1_EL1 | user lower half / kernel upper half page-table bases | ARM64 KPTI is likewise dual page tables; same as the main Android battlefield |
| MTE (ARMv8.5) | memory tagging + hardware ldst checks; production-grade low overhead | The carrier of HW_TAGS KASAN `[verified]`; complements KFENCE, not exclusive `[verified]` |
| PAC (ARMv8.3) | PACIA/AUTIA sign function pointers and return addresses; the ARM64e kernel enables them too | Bypasses: PAC gadgets (trusted code signs/validates a controlled value for you), signature-cache reuse, finding unsigned indirect jumps to relay JOP |

### 1.2 Kernel data-structure attack surfaces (comparison table)

| Platform | Structure | Key fields/pointers | Vulnerability pattern |
|---|---|---|---|
| Linux | `task_struct` | `cred*` (real_cred/cred) | After an arbitrary write, `commit_creds(prepare_kernel_cred(0))` - the classic privilege-escalation finish |
| Linux | `mm_struct` / `vm_area_struct` | VMA list, PTEs | COW-breaking class (the Dirty COW pattern), VMA races |
| Windows | `_EPROCESS` | `Token` (offset varies by version - **verify dynamically, don't memorize**), `UniqueProcessId`, `ActiveProcessLinks` | Token Stealing (copy the SYSTEM process Token); unlinking the list to hide processes |
| Windows | `_KTHREAD` | `PreviousMode` | After switching to KernelMode, `NtReadVirtualMemory` reads/writes kernel memory - an arbitrary-read/write amplifier |
| Windows | `_KPROCESS` | `DirectoryTableBase` (CR3) | Escape/forensics localization |
| XNU | `task` / `ipc_port` | port rights bits, kobject pointer | retained send right + free-then-realloc (UAF primitive) |

### 1.3 IPC attack surfaces

| Platform | IPC | Key entries | Vulnerability pattern |
|---|---|---|---|
| Linux | futex | futex_wait/requeue, PI futex | pi races (the CVE-2014-3151 pattern: hash bucket lock window) |
| Linux | epoll | `ep_remove` / `eventpoll_release` | CVE-2026-46242: file vs eventpoll double-free race `[verified]` |
| Linux | io_uring | many subsystem opcodes | A UAF/race hotspot; Google server-side disabled outright since 2023 (widely reported) |
| Windows | ALPC | `ntdll` RPC underlayer, `_KALPC_MESSAGE` | UAF (the CVE-2018-8440 in-the-wild pattern: ALPC+Win32k) |
| XNU | Mach IPC | `mach_msg_trap` (~100 trap-table entries), the mach_port rights matrix | mis-granted port rights, send-once races |
| XNU/user space | XPC | `xpc_connection` + listener callbacks | missing validation in privileged services (detailed in the macOS section) |

### 1.4 LKM / driver development entry points

| Platform | Model | Essentials |
|---|---|---|
| Linux | LKM | `module_init`/`file_operations`; `kallsyms_lookup_name` no longer exported since 5.7 (commit 0bd476e6c671); the customary bypass: `register_kprobe` on a known function name, take `kp.addr`, then resolve everything via `kallsyms` (a publicly known trick, widely documented); ftrace: `register_ftrace_function` to attach callbacks, or ftrace direct |
| Windows | WDM/KMDF | `DriverEntry` fills the `MajorFunction[]` dispatch; IRP flow; memory via `ExAllocatePoolWithTag` (pool tags, visible to PoolMon); inf + test-signing mode loading |
| XNU | kext (being phased out) -> DriverKit | kext requires SIP downgrade; DriverKit is user-space + Swift runtime (TypeMetadata/VWT, see the iOS section) |
The customary kprobe-resolves-kallsyms snippet (the first step when doing kernel hooks/research):

```c
static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
register_kprobe(&kp);
kallsyms_lookup_name_t lk = (kallsyms_lookup_name_t)kp.addr;
unsigned long addr = lk("commit_creds");
```

### 1.5 Kernel crypto identification

- Identification routine: find a **256-byte permutation table** in `.rodata`/driver constant areas and compare against the standard AES S-box / SM4 S-box; Rcon tables and GF(2^8) multiplication (the xor-folding pattern of `xtime`) are also strong signatures.
- Crypto APIs per platform (locate via import tables when reversing):

| Platform | API | Entry functions |
|---|---|---|
| Linux | Kernel Crypto API | `crypto_alloc_skcipher` / the `scatterlist` family |
| Windows | CNG (BCrypt) | `BCryptEncrypt` / `BCryptGenerateSymmetricKey` |
| XNU | corecrypto | `cccbc` / `ccgcm` prefixed symbols |

## 2. iOS (XNU)

### 2.1 Attack surface table

| Component | Key structures/functions | Vulnerability pattern | Tool entry |
|---|---|---|---|
| Mach IPC | `mach_msg_trap`, `ipc_port`, `ipc_entry`, port rights (SEND/SEND_ONCE/RECEIVE) | mis-granted port rights; UAF then realloc impersonating a kobject | LLDB + kernel symbols; panic logs |
| BSD syscalls | the `sysent[]` dispatch table (~540 entries on iOS 17+, count drifts by version - the source material says 540+; the current syscalls.master is authoritative) | missing argument validation, semantic gaps vs user-space libSystem | source at opensource.apple.com / XNU mirrors |
| IOKit | `IOUserClient::externalMethod`, `getTargetAndMethodForIndex`, `clientClose`/`clientDied` (cleanup paths) | external-method array OOB (unbounded Index), cleanup-path UAF - **a historical hotspot** | `iokitd`; class-dump doesn't work, kernel-extension symbols needed |

### 2.2 Signing/protection systems

| Mechanism | Essentials | Breakthrough |
|---|---|---|
| AMFI | AMFI.kext + user-space amfid; `cs_blob` validation, entitlement grants, the `get-task-allow` debug switch | IPA injection idea: after bypassing amfid, modify cs_blob flag bits (CS_HARD/CS_KILLED etc.), then `task_for_pid(0)` to grab the kernel task and inject |
| KTRR (A11+) | hardware-locks the kernel code section (page-table RO guaranteed by hardware, software cannot change it) | the KTRW debugger: borrows A11 external debug registers to bypass and remap writable `[verified]` (googleprojectzero/ktrw) |
| KDP | UDP protocol, LLDB `kdp-remote udp://[ip]:port`, paired with KDK (Kernel Debug Kit) symbols | "iOS 26.5 removed most of kdp_core but remote debugging remains" `[]` - test on the target version before use |
| SIP | `csr_get_active_config` reads the NVRAM bitflag; `csrutil` changes require recovery mode | On jailbroken/research devices, read the config bits directly to see which protections are off |
| DriverKit/Swift kernel components | user-space drivers + Swift runtime; TypeMetadata/VWT (value witness table) structure reversing | Few symbols; identify by Swift runtime constant patterns |

### 2.3 Typical exploit-chain skeletons (iOS-side finishes)

| Primitive | Finishing move | Notes |
|---|---|---|
| UAF arbitrary read/write | locate own task's `cs_blob` -> clear CS_HARD/CS_KILLED/CS_RESTRICT etc. | Equivalent of Linux's cred rewrite: one flag-bit change buys a whole-process escape |
| Arbitrary read/write + task_for_pid(0) | `mach_vm_write` on the target process + `thread_create_running` | The orthodox route for injecting execution flow (paired with the amfid bypass) |
| Info leak only | kernel pointer -> compute the KASLR slide -> pave the way for a write primitive | In the PAC era a leak is not enough; a signing surface is still needed |

### 2.4 What to look at first when migrating from Android reversing

1. **Binder <-> Mach IPC**: both are torrential IPC surfaces; the "rights matrix + handle lifetime" instincts you learned on Android map directly onto mach_port rights; Binder bug-nose transfers to `ipc_port` UAFs.
2. **Set up the ipsw toolchain first** (blacktop/ipsw): unpack kernelcache, recover symbols - the equivalent of grabbing the GKI vmlinux/symbol table first on Android; without symbols nothing else matters.
3. Shift the attack focus from **Binder/Futex** to **vm_map races + IOKit cleanup paths + XPC**.
4. Mitigation cross-reference: Android PAC/MTE experience ports directly (the same ARM64 hardware features); the new learning cost is KTRR/PAC signing chains.

## 3. macOS

### 3.1 Attack surface table

| Component | Key structures/functions | Vulnerability pattern | Tool entry |
|---|---|---|---|
| Mach IPC | freeing an `ipc_port` while **retaining send rights**, then `mach_msg` | Primitive-izing the UAF: free -> spray/realloc -> mach_msg walks into a fake kobject | LLDB (KDK or LLDBagility `[verified]` quarkslab) |
| IOKit | `clientClose`/`clientDied` cleanup paths | double free / race UAF (same origin as iOS; easier to reproduce on desktop) | io registry probing (`ioreg`) |
| XPC | listener `shouldAcceptNewConnection` | privileged daemon not validating Entitlement/Audit Token -> any process connects and escalates; XM Cyber's "privileged XPC disabling enterprise security tools" is this pattern `[]` | `launchctl` service enumeration + process auditing |
| SIP | Migraine-style research: environment-variable-style primitives injected via entitled daemons `[]` | Bypassing the root/SIP line of defense | verify with `csr_get_active_config` |
| TCC | the database `/Library/Application Support/com.apple.TCC/TCC.db`, daemon `tccd` | bypassing privacy grants (SIP-unprotected paths / timing windows) | read the database directly and diff grants |
| Persistence | launchd (LaunchDaemon/LaunchAgent) | legitimate mechanism abused; rootkit landing spot | `launchctl print` |
| PAC | ARM64e fully enabled on desktop | bypasses: PAC gadgets, signature caches, unsigned indirect jumps for JOP | see the generic section 1.1 |

### 3.2 TCC bypass notes (a desktop-only bonus)

| Pattern | Idea |
|---|---|
| Direct database read | The SIP-protected TCC.db cannot be written directly, but many versions historically had bypass windows (path-permission change timing) |
| Client spoofing | A privileged service trusts "the identity the connector claims" instead of measuring the Audit Token |
| Environment injection | Same idea as Migraine: an entitled daemon hijacked via environment variables/arguments `[]` |

### 3.3 What to look at first when migrating from Android reversing

1. **macOS is the "debuggable, scaled-up version" of the iOS attack surface**: the same XNU + IOKit + XPC, but with KDK two-machine debugging installable and SIP disable-able - practice the iOS surface on macOS first, then drop back to the iPhone.
2. Android's **app permission-model instincts -> TCC**: tccd is macOS's "sensitive permission gateway"; the ideas for bypassing TCC (path races, daemons trusting clients) parallel bypassing Android Runtime Permissions.
3. The full Frida kit runs against macOS processes directly (the injection target becomes a Mach task), one notch lower than the iOS research-device barrier.
4. Persistence cross-reference: LaunchDaemon <-> Android's device_admin/accessibility abuse - the same "legitimate mechanism misused" playbook.

## 4. Windows

### 4.1 Driver PE and IRP flow

| Component | Key structures/functions | Essentials |
|---|---|---|
| Driver PE | `DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)` | `DRIVER_OBJECT->MajorFunction[]` is the whole IRP dispatch table; a `.sys` is a PE - the import table shows ntoskrnl dependencies |
| Device chain | `DEVICE_OBJECT` AttachDevice | filter drivers (minifilter/network) insert into the chain; attacker view: someone else's filter driver is an attack surface |
| IRP flow | `DeviceIoControl` -> ntdll -> `NtDeviceIoControlFile(device handle,...,IOCTL,input buffer,length,output buffer,length)` -> I/O Manager builds the IRP -> driver dispatch routine | The last user-space parameter chain is the kernel-side bug's entry parameters |

### 4.2 IOCTL methods and bug hotspots

| METHOD | Buffering | Risk |
|---|---|---|
| METHOD_BUFFERED | `SystemBuffer` double copy | Length-validation error -> overflow |
| METHOD_IN/OUT_DIRECT | MDL mapping | Wrong mapping range |
| METHOD_NEITHER | `Type3InputBuffer` **hands the raw user pointer into the kernel** | **Arbitrary R/W hotspot**: no probe/exception guard and dereference directly = BSOD + privilege escalation in one |
The `CTL_CODE(DeviceType, Function, Method, Access)` macro - when reversing, decode the quadruple first, then judge the method.

### 4.3 The BYOVD live-fire arsenal (verified this round)

| Driver | CVE | Effect | Verification |
|---|---|---|---|
| RTCore64.sys (MSI Afterburner) | CVE-2019-16098 | Arbitrary kernel read/write (the BYOVD textbook case, a member of Microsoft's driver blocklist) | Public knowledge, widely documented |
| RTCore64.sys | CVE-2024-1460 | IOCTL 0x80002040 kernel **memory leak** (requires a high-integrity handle) | `[verified]` cvelistV5 |
| WinRing0.sys/WinRing0x64.sys 1.2.0 | CVE-2020-14979 | Arbitrary physical memory read/write (bundled with EVGA Precision X1 <=1.0.6), mapping `\Device\PhysicalMemory` -> SYSTEM | `[verified]` cvelistV5 |
| BdApiUtil.sys (**Baidu Antivirus** v5.2.3.116083) | CVE-2024-51324 | BYOVD terminating arbitrary processes (anti-EDR / AV-vs-AV scenarios) | `[verified]` cvelistV5 (note: not Bitdefender) |
Other weaponization material (from user materials, not item-verified): BTR Reforged - abusing Defender's own BTR.sys to knock out EDR `[]`; .NET NativeAOT kernel components (`RhpNewFast` and other runtime entries) `[]`.

### 4.4 Privilege-escalation finishing primitives

- **Token Stealing**: walk the `_EPROCESS` list for SYSTEM, copy its `Token` pointer into the current process (offset varies by build; verify dynamically).
- **PreviousMode rewrite**: current thread's `_KTHREAD->PreviousMode = KernelMode`; afterwards `NtReadVirtualMemory/NtWriteVirtualMemory` read/write kernel memory directly - more elegant than hunting for shellcode.
- Process hiding: unlink from `ActiveProcessLinks` (note the PID hash table still exists; forensics will notice).
Typical Token Stealing flow (once you have arbitrary read):

```
1. NtQuerySystemInformation(SystemProcessorInformation 无关,用
   SystemProcessInformation 或注册表/句柄) → 拿 SYSTEM 进程 PID
2. PsInitialSystemProcess(内核导出) → SYSTEM _EPROCESS 基址
3. 读 SYSTEM 进程 EPROCESS + Token 偏移 → Token 指针
4. 定位自身 _EPROCESS(_KPROCESS/ApcState 或遍历 ActiveProcessLinks)
5. 写 SYSTEM Token 指针到自身 EPROCESS.Token → 完成
（WinDbg 验证：!process 0 0 对比 Token 值）
```

### 4.5 What to look at first when migrating from Android reversing

1. **Mental-model switch**: Android/Linux is "kernel objects + cred"; Windows is "object manager + Token" - first eyeball EPROCESS in WinDbg with `!process 0 0`, the equivalent of looking at task_struct on Linux.
2. The **Frida injection + confrontation** you practiced on Android carries over; the kernel side becomes KMDF driver loading (test-signing mode `bcdedit /set testsigning on`).
3. Attack-surface entry cross-reference: `/dev/*` <-> `\\Device\\*`; ioctl interface reversing <-> Binder onTranscode - both are the triple "dispatch function + command code + buffer"; your fuzzing nose ports directly.
4. BYOVD is a Windows-only bonus: Android has no "bring-your-own-vulnerable-driver" surface; prioritize filling this gap.

## 5. Kernel debugging shoot-out

| Platform | Solution | Setup | Key details |
|---|---|---|---|
| Linux | KGDB/kdb | `kgdboc` serial or kgdboe network; `nokaslr` boot parameter | kdb on-machine / kgdb two-machine; disable KASLR before setting breakpoints |
| Windows | WinDbg KD two-machine | target `bcdedit /debug on` + `bcdedit /dbgsettings serial debugport:1 baudrate:115200` (or network debugging /dbgsettings net, or a Hyper-V VM KD channel); host `_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols` | Two-machine is the standard posture for kernel driver dev/vuln reproduction |
| iOS/macOS | LLDB + KDP | `kdp-remote udp://[host]:port`; macOS installs the KDK (Kernel Debug Kit) symbols; LLDBagility offers a route beyond KDP `[verified]` | See the iOS-side KDP status in sec.2.2 `[]` |
| Cross-platform | HyperDbg | VT-x/EPT (SLAT) implements kernel breakpoints without touching kernel code (no int3 writes) | Selling point: undetectable by anti-debugging that scans for int3; MBEC+SLAT |
Debugger cheat commands:

```
Linux   : target: kgdboc=ttyS0,115200 nokaslr    host: gdb vmlinux → target remote /dev/ttyS0
Windows : target: bcdedit /debug on; bcdedit /dbgsettings serial debugport:1 baudrate:115200
          host: windbg -k com:port=\\.\pipe\com_1,baud=115200,pipe （Hyper-V/VMware 管道）
          符号: set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
macOS/iOS: lldb → kdp-remote udp://192.168.x.x:41139 （目标 boot-args 含 debug=0x144/kdpi=1）
```

## 6. Kernel toolchain panorama

| Category | Tool | Use | Existence |
|---|---|---|---|
| Fuzz | syzkaller (syzlang syntax + syzbot continuously fuzzing KASAN kernels) | The de-facto standard for Linux kernel syscall-level fuzzing | `[verified]` public repo |
| Fuzz | DeepZero (AI screening kernel drivers for exploitability) | Source-material lead | `[]`, see sec.0 |
| Fuzz | kAFL / Hypervisor fuzzing | Hypervisor-level coverage feedback, cross-OS | Public projects (nyx) |
| Dynamic | ftrace / kprobe / eBPF / KernelPatch | Linux tracing and inline hooking; KernelPatch-style frameworks do hot-patch-style kernel hooks | Public knowledge |
| Debug | KGDB / WinDbg / HyperDbg / LLDB+KDP / KTRW | See the sec.5 shoot-out | KTRW `[verified]` |
| Rootkit | Diamorphine (LKM, signal-triggered escalation/hiding), Reptile (full kernel rootkit suite), VoidLink | Learning kernel hook/hiding techniques (for authorized testing) | Diamorphine/Reptile public repos `[verified]`; VoidLink `[]` |
| Forensics | Volatility 3 (cross Win/Linux/Mac profiles), LiME (Linux memory dump), WinPmem (Windows physical memory acquisition) | Memory forensics <-> rootkit detection sharpen each other | Public projects |
| XNU | ipsw (blacktop/ipsw) | kernelcache unpacking, symbol recovery, firmware analysis - the first stop of iOS kernel research | Public repo |
| Protocol reversing | Linux: netfilter hooks / `struct proto` recvmsg; Windows: WFP `classifyFn` callouts; XNU: `proto_input` (mbuf) | Network-stack mount points per platform; entry points for protocol fuzzing/MITM injection | Framework knowledge |

## 7. Kernel-level growth path (four platforms, in order)

Main line: **build the foundation on Linux first (the reference frame for every kernel concept), then return to the main Android battlefield, then extend to iOS / Windows as targets require**.

```
Linux                Android              iOS                  Windows
syzkaller+KASAN  →   GKI 符号 +       →   IPSW 提取 +      →   WinDbg 双机 +
找 crash/复现        Binder/Futex         ipsw 符号恢复        EPROCESS 结构
    ↓                适配已公开 CVE        vm_map/IOKit/XPC     Token Stealing
slab/UAF 原语                             PAC/KTRR 对抗        BYOVD + IOCTL
    ↓                主战场：逆向          (Mach IPC 嗅觉       METHOD_NEITHER
futex/io_uring 竞态  对抗 + 提权          来自 Binder)         任意读写
    ↓
任意读写 → cred
(commit_creds)
```
- **First stop, Linux**: syzkaller + KASAN grinds out crashes -> stable reproduction -> understand slab and UAF primitives via -> futex/io_uring races -> arbitrary read/write -> finish with `commit_creds`. This route walks the full concept chain of "memory error -> privilege escalation".
- **Back to Android**: GKI's unified kernel comes with symbols; load the Linux primitive capabilities onto the Binder/Futex surfaces and adapt already-published CVE reproductions (a required course before 0days).
- **iOS**: start with the ipsw toolchain -> vm_map races / IOKit cleanup paths / XPC surfaces -> fight the PAC/KTRR hardware mitigations (research-device costs jump sharply after A11).
- **Windows**: WinDbg two-machine environment -> hands-on EPROCESS/Token structures -> Token Stealing -> BYOVD + METHOD_NEITHER IOCTL arbitrary read/write, a surface still in its bonus period.
