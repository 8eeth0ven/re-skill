# Kernel Function Locating: the Last Piece of Deep Hooking

> Positioning: targets that frida/user-space hooks cannot touch (binder detection, direct syscall invocation, kernel-mode validation) force you into kernel hooking; and the first line of any hook is always "what is the target function's runtime address". This piece covers **locating only**: five symbol-acquisition routes for the four hard cases (GKI without symbols, KASLR, not exported, statically stripped) + KASLR bypass + a binder walkthrough + two special frameworks, svc_hook/perf_event. The hook mechanisms themselves are in kernel-hook-stealth.md in the same directory; the eBPF ecosystem is in android-kernel-ebpf.md.

## 1. Why kernel function locating is hard

Hooking a so function in user space: open it in IDA, offset + module base, done. Kernel functions add four layers of obstacles:
1. **Image without symbols**: the kernel in a production device's boot.img is a stripped Image (not a vmlinux ELF with symtab), and vendors never ship vmlinux; in the GKI era the kernel body is unified, but what you get is pure binary. Load it into IDA and the screen fills with sub_FFFFFF8008010200.
2. **/proc/kallsyms masquerade**: without root, at `kptr_restrict=2` every symbol shows as `0000000000000000` (at `=1` root/CAP_SYSLOG sees the truth, `=0` fully open). A shell user gets no real address at all.
3. **KASLR**: the kernel text base is randomized at every boot; addresses from static analysis still need the slide added (sec.3).
4. **Vendor forks/compiler variance**: on pre-GKI legacy devices (4.x/non-GKI 5.4) every vendor has its own kernel and offsets do not port across devices; compiler inlining/LTO/CFI make "function" boundaries themselves drift (bpftrace issue #2888: a kprobe cannot attach to nf_nat because it got inlined away - the probe point simply does not exist).
**Locating is a prerequisite for hooking**: all four mechanisms in kernel-hook-stealth.md (kprobe/ftrace/fentry/LSM) require a "symbol name or address" up front; KernelPatch inline hook demands a raw address. Choose among this piece's five routes with the table:

| Hard case | Recommended route (sec.2) |
|---|---|
| Have root, know the function name | Route D (runtime discovery) |
| No root, have boot.img | Route A (official GKI) / Route B (image recovery) |
| Target not exported, `extern` in an LKM fails | Route C (two methods) |
| Don't even know the name (only behavior/error strings) | Route E (static signatures) |

## 2. Five routes to symbol acquisition

### Route A official symbols: GKI official downloads / /proc/kallsyms

**Applicable when**: the target is a GKI device (the vast majority of Android 12+), the boot.img was not recompiled by the vendor (vendor-side features live in .ko; the kernel body = Google's original); or you already have root.
**Procedure**:
1. Confirm kernel version and KMI: `adb shell uname -r` (e.g. `5.15.104-android13-4-00257-g...`).
2. Download the `boot.img`, `vmlinux`, `symbols` triple directly from the official release builds page (GKI publishes all three for every build; `vmlinux` is officially described as "the statically linked kernel ELF with symbols"):
 - Branch examples android14-6.1 / android14-5.15, plus the all-branches index and download flow, are all on ci.android.com (search the branch name; tick boot.img/vmlinux/symbols under artifacts).
3. Look up offsets directly in the official vmlinux's System.map/symbol table. Verify consistency with the target device: `adb shell sha256sum` against the boot.img dd'd from the boot partition (magiskboot unpack flow in Appendix A of android-kernel-ebpf.md).
4. With root there is another official route: `echo 0 > /proc/sys/kernel/kptr_restrict`, then `grep binder_transaction /proc/kallsyms` for runtime truths (slide included - you don't even need to solve KASLR).
**Pitfalls**:
- If the vendor recompiled the kernel (boot-time patching, GKI exception list), the official vmlinux offsets are unusable -> fall back to Route B;
- The boot.img in an OTA delta package may not match the device's current slot - always trust the one you dd'd yourself;
- `/proc/kallsyms` still shows zeros as root: check kptr_restrict and SELinux (some ROMs block reads with selinux); if still failing, take Route C method one.

### Route B recovery from the image: vmlinux-to-elf / kallsyms-finder / KernelPatch

**Applicable when**: any scenario where you hold the kernel image (vendor fork, GKI check failed, no root). The command-line walkthrough is already in Appendix A of android-kernel-ebpf.md; this piece explains the principle and troubleshooting.
**Principle: nearly all kernels ship an embedded kallsyms symbol table** (CONFIG_KALLSYMS on by default since 2.6.10; even with the ELF header stripped, the compressed symbol table still sits in the data section). kallsyms-finder's parse chain (principle from the README):

```
kallsyms_token_table   ← 256 个 null 结尾字符串片段(压缩字典,先启发式找它)
kallsyms_token_index   ← 256 个偏移,指向 token_table 各片段
kallsyms_markers       ← 每 256 个符号一个偏移的二级索引
kallsyms_names         ← 压缩符号名(每字节是 token 索引)
kallsyms_num_syms      ← 符号总数(用来反向校验解码正确)
kallsyms_offsets + kallsyms_relative_base   ← 相对地址表 + 基址(新版)
kallsyms_addresses     ← 绝对地址表(老版)
```

The tool starts from token_table and back-derives every field level by level (trial-and-error on alignment/length), then emits an ELF with full symbols -> use directly in IDA/Ghidra. KernelPatch's symbol extraction follows the same idea and additionally handles GKI layouts on arm64; `tools/extra_symbol` can import extra symbols.
**Troubleshooting**:
- Error `No embedded symbol table found`: the target really turned off CONFIG_KALLSYMS (rare, some custom kernels) -> only Route E remains;
- 6.2+ uses `kallsyms_seqs_of_names` (3-byte packed indexes), 6.4+ reorders the arrays - vmlinux-to-elf officially claims support up to 6.4; when a newer kernel fails, upgrade the tool first;
- Compressed kernels (gz/lz4/xz/zstd) are auto-decompressed; magiskboot unpack then decompress is more reliable;
- If locating fails, force parameters: `--e-machine` (ARM64=183/0xB7), `--bit-size 64`, `--base-address`, `--use-absolute`.

### Route C locating non-exported functions: two methods

**Applicable when**: you are writing an LKM/KPM and `extern` cannot get the target (not EXPORT_SYMBOL'd). The LKM linker only resolves against the exported symbol table; non-exported != nonexistent - the name is still in `/proc/kallsyms`, it just refuses to link for you. Both methods cross-verified.
**Method one: register a kprobe and let the kernel resolve it (name -> address, and the whole family for free)**
The kprobes subsystem can still resolve by symbol name internally; `register_kprobe` writes the resolved result into `kp.addr`:

```c
// 5.7 起 kallsyms_lookup_name 被 unexport(commit cf240d59,背景 https://lwn.net/Articles/813350 )
// 标准恢复法:用 kprobe 挂它自己,取 kp.addr 拿到函数指针
static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
typedef unsigned long (*kln_t)(const char *name);
kln_t kallsyms_lookup_name;

register_kprobe(&kp);
kallsyms_lookup_name = (kln_t)kp.addr;
unregister_kprobe(&kp);

// 之后任意未导出符号(含 sys_call_table)一个名字一个地址:
unsigned long addr = kallsyms_lookup_name("binder_transaction");
```

- Requires `CONFIG_KPROBES=y` + `CONFIG_KALLSYMS=y` (add `CONFIG_KALLSYMS_ALL=y` for non-function symbols);
- One registration, one lookup: if you temporarily need a symbol, just register `{.symbol_name="target"}`, read addr, and unregister - no need to detour through lookup_name;
- Adversarial environments (kprobes blocked/CONFIG off): the HITCON 2025 talk "A kernel rootkit works without kallsyms" discusses alternatives without kprobe;
- Variant: `kallsyms_on_each_symbol` was unexported in the same batch and can be recovered the same way (iterate to get all symbols - good for an in-memory System.map).
**Method two: compute a relative offset from an exported anchor (compile-time offset + runtime anchor)**
`extern` an **exported** symbol in the LKM; the linker resolves its address automatically (runtime truth); add the `target - anchor` offset obtained from static analysis (the official vmlinux, or the symbol table recovered via Route B) and you get the target's runtime address:

```c
extern unsigned long *_stext;            // 已导出锚点(或 printk、init_task 等)
// 静态:在 vmlinux/System.map 里查 target_addr - anchor_addr = OFFSET(编译期常量)
unsigned long target = (unsigned long)_stext + OFFSET;
```

Where the offset comes from (three derivations, from solid to wild):
1. **Same-struct member**: the target function pointer hangs in some ops table; locate the struct first, then read at the member offset. Example: `binder_ioctl` is a member of `static struct file_operations binder_fops` - `binder_fops` is not exported, but `binder_ioctl`'s first argument is it, no mistake there; back-derive the struct address from the `binder_init` -> `misc_register(&binder_miscdev)` call chain, then `*(void**)((char*)&binder_fops + offsetof(struct file_operations, ioctl))`;
2. **Call-chain derivation**: disassemble a known locatable function A and find the `BL target` target offset - in IDA, xref/callees of A gives it directly;
3. **container_of style**: obtain a pointer to an embedded substruct (global table/list head), walk member offsets back to the parent object, where function pointers or data live (the classic: walk the `tasks` list from `init_task` to enumerate all processes).
**Pitfalls**:
- The offset must come from a build identical in source and config to the target kernel - under GKI the official vmlinux is trustworthy; on vendor forks you must recover the target's own symbols via Route B;
- `container_of`/member offsets must be checked against **the target version's** headers (android-mainline struct layouts move across versions);
- A "function" inlined by the compiler has no standalone address (the bpftrace issue #2888 case) -> hook an outer real function instead;
- With CFI on (CONFIG_CFI_CLANG, commonly enabled on Android 12+ GKI), an address you obtain may not be directly callable as a function pointer - wrap it with `__attribute__((no_sanitize("cfi")))` (one of the android-kernel-hacking-toolkit moves in kernel-hook-stealth.md sec.5).
Reference frame: multiple Stack Overflow questions concentrate on this problem; for a systematic treatment see the Kernel Play Guide's "Accessing the Non-Exported in Modules".

### Route D runtime discovery: ftrace / kallsyms / kfunc

**Applicable when**: root is in hand and the question is "what attachable points does this machine have right now".
1. **ftrace available_filter_functions** (= the full set of attachable functions, kallsyms minus notrace/blacklist):

```bash
cat /sys/kernel/tracing/available_filter_functions | grep binder
# 或老路径 /sys/kernel/debug/tracing/available_filter_functions
grep -w binder_ioctl /sys/kernel/tracing/available_filter_functions   # 在=可挂 fentry/kprobe
cat /sys/kernel/debug/kprobes/blacklist     # kprobe 禁挂清单(entry 函数等)
```

2. **Build your own lookup after recovering kallsyms_lookup_name**: the Route C method-one code, done at LKM/KPM init; afterwards resolve everything by name;
3. **BPF kfunc (fentry/fexit)**: bpftrace's `kfunc:`/`kretfunc:` probes are aliases of fentry/fexit; function argument types come from BTF (GKI 5.15+ `CONFIG_DEBUG_INFO_BTF=y`); limits: entry/exit only, no arbitrary offsets, and inlined targets cannot be attached. The BTF file itself: `/sys/kernel/btf/vmlinux` - it doubles as a free struct-layout dictionary (pahole reads it directly), so locating struct member offsets needs no source digging.

```bash
ls -la /sys/kernel/btf/vmlinux          # root 第一眼(另一篇 §9 同结论)
bpftrace -l 'kfunc:*binder*'            # 列可挂 kfunc
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h   # 全量结构体
```

**Pitfalls**: targets missing from available_filter_functions (notrace/inline) do not mean nonexistent - fall back to Route E static search; debugfs/tracefs mount points vary by ROM (check with `mount -t tracefs`).

### Route E static signatures: string xrefs / struct cross-referencing / official image diffing

**Applicable when**: the function name is unknown and you only have behavior (error strings, logs, specific constants); or symbol recovery failed entirely.
1. **printk format-string locating (the number-one weapon)**: a kernel function's `pr_err/pr_info` strings get compiled into .rodata; in IDA, `Shift+F12` on the kernel image, search the string -> xref to the referencing function = the target. The binder walkthrough is in sec.4;
2. **Signature constants**: driver magic numbers, the jump tables of command-code switches, crypto tables (e.g. the AES S-box `63 7C 77 7B`), struct-size immediates (`SUB SP, SP, #0x2A0` matching sizeof);
3. **Struct cross-referencing**: ops tables of misc/platform drivers (`file_operations`/`miscdevice`) have fixed member order; the first real function in `.open` is usually the entry; back-look from the major number in `/proc/misc`;
4. **Official image diffing (the GKI privilege)**: the target mangled the symbols but the code is largely upstream -> run BinDiff (difference/function similarity) between the official vmlinux and the target image and "identify relatives" of unknown functions directly - in the GKI era vendor mangle rates are low and this route hits extremely often;
5. **Entry anchoring**: in boot.img the `ANDROID!` magic locates the kernel payload (hands-on records on CSDN [lead]:); the ARM64 Image header `MZ` - skip the 64-byte header, text base read from the Image header's text_offset field.

## 3. KASLR bypass

A static address (Routes A/B/E) is a "link-time address"; the runtime truth = static + slide. Ways to solve the slide:
**A. Rooted scenario (the reverse-engineering norm) - no "bypass" needed, just take the truth**:
- After `kptr_restrict=0`, read `/proc/kallsyms` (any symbol's truth - static value = slide, applicable kernel-wide);
- If any kprobe attach point is known, the difference between its runtime address and the static one is the slide (same conclusion as Scenario C in android-kernel-ebpf.md sec.5);
- On the BPF side, read ARM64 globals like `kimage_voffset` via kprobe (Appendix C of the same piece);
**B. Un-rooted leak points (the kasld taxonomy)**:
- kernel pointers in dmesg/logs (panic, warning backtraces with addresses);
- accidental sysfs/procfs leaks (`/sys/module/*/sections/.text` on old kernels, kstkeip in old `/proc/*/stat`, etc.);
- EntryBleed: a prefetch/TLB timing side channel that yields the text base in seconds (MIT CSAIL paper + ~100-line PoC); same-family CVE-2022-4543 prefetch side channel;
- Project Zero 2025, "Defeating KASLR by Doing Nothing at All": under specific configurations, non-executable mappings of .text allow inference without any active leak;
- memory-corruption primitives: a binder UAF (CVE-2022-20421) style arbitrary kernel read kills KASLR outright [lead : community discussion].
**C. Android realities and entropy**:
- The Android app domain seals dmesg/kallsyms with SELinux+seccomp; the un-rooted leak surface is far narrower than desktop Linux - in real projects it is almost always "root first (APatch/KP), then kallsyms truth"; KASLR is a real obstacle only for **exploitation (bug-hunting without root)**;
- Order of magnitude of the entropy (when judging the feasibility of brute-guessing addresses during troubleshooting): x86_64 text has only ~5-6 bits of slot entropy, direct map ~14.6 bits (measured/computed by u1f383); on ARM64 slot size/count depends on `kaslr-region` and the memory layout, the random seed comes from DTB `rng-seed`/EFIVAR, and some devices run low-entropy;
- On a self-built target just use `nokaslr` (android-kernel-ebpf.md sec.6/sec.12) and skip this whole section.

## 4. Binder function-locating in practice (when user-space hooks lose to binder detection)

**Scenario**: the RASP/app goes straight to syscalls or detects user-space hooks (see the "direct svc call" row of the comparison table in kernel-hook-stealth.md sec.6), forcing the fight to the kernel's `binder_ioctl`/`binder_transaction` layer. Call chains and structs are detailed in android-kernel-ebpf.md sec.2; only locating is covered here.
**Steps (no root, fully static)**:
1. **Extract the image**: `dd` the boot partition -> magiskboot unpack/decompress to get the Image (commands per Appendix A of android-kernel-ebpf.md); on a GKI device try Route A's official vmlinux first; if it matches, jump straight to step 4;
2. **Recover symbols**: vmlinux-to-elf (Route B) -> an ELF with symbols; hit rates are high since binder.c ships in android-common and, under `CONFIG_KALLSYMS`, is always present;
3. **Load into IDA**; if symbols are still missing or need manual cross-check, use string anchors (real prints from kernel source drivers/android/binder.c):
 - `"binder: %d:%d transaction failed %d, size %zd-%zd"` / `"binder_alloc: %d: binder_alloc_buf size %zd failed..."` -> the xref'd function is `binder_transaction` (the error paths all live in the transaction main function);
 - `"binder_ioctl: %d:%d cmd %x arg %p\n"` (debug-macro path) or the BINDER_WRITE_READ branch structure -> `binder_ioctl`;
 - `binder_devices` (the string array of device names "binder/hwbinder/vndbinder") -> xref to `binder_init` -> `binder_miscdev` -> the `.fops` member is `binder_fops` -> read out `.open/.ioctl` at the member offsets;
 [string anchors: kernel source binder.c (see android-kernel-ebpf.md sec.2) + Synacktiv's binder kernel analysis; exact strings drift by version - the target kernel source is authoritative]
4. **Struct cross-check**: `binder_ioctl` signatures - a very long switch (BINDER_WRITE_READ/SET_MAX_THREADS/ENABLE_ONEWAY_SPAM_DETECTION...), first two params `struct file*`/`flags`; `binder_transaction` signatures - calls `binder_alloc_new_buf`, many parameters (7-9), contains a `binder_fixup_parent` call;
5. **KASLR finish**: Route C method one (kprobe on `binder_ioctl` for kp.addr) or sec.3A for the slide;
6. **Landing verification**: after attaching kprobe/fentry, filter `comm=="target app"` and dump parcels (ready-made script: Appendix C C1 of android-kernel-ebpf.md); for observation tools see binder-trace (LKM implementation) and btrace (eBPF).
**Pitfalls**:
- Mixing a 32-bit binder uapi with a 64-bit kernel (the binder32 compat layer - `binder_transaction` splits into `binder_transaction`/`binder_transaction_buffer_fixup`? - actually the `compat` path has separate ioctl entries); hook the wrong layer and your dumps are all zeros;
- `binder_transaction`'s parameter order varies by version (early on arg2=dest_node; newer versions differ) - trust the target source, don't copy argN from scripts;
- High throughput: tracing all binder traffic drags the system down; always filter by comm/handle.

## 5. The svc_hook framework (user-space syscall hooking, no kernel required)

**Anchor**: the original project retrage/svc-hook (Apache-2.0).
**Principle (counter-intuitive: the kernel is untouched)**:

```
LD_PRELOAD 注入 libsvchook.so
  → 扫描目标进程代码段,记录每条 svc #0 指令地址
  → 为每条 svc 生成定制 trampoline(嵌入原地址)
  → 把 svc 指令改写为 b trampoline(±128MB 范围内直接 b)
运行时:执行到原 svc 处 → b 进 trampoline → 保存全部 CPU 上下文
  → 调用 LIBSVCHOOK 指定的 hook 函数(可看/改 x8 nr 与 x0-x5 参数)
  → 恢复上下文 → 执行真实 svc(或改写后语义)→ 返回原流程
```

Performance: the README claims ~1000x faster than ptrace; other accounts say ~2000x vs ptrace and ~140x vs seccomp BPF. Supports ARM64 Linux/Android/FreeBSD/NetBSD.
**Compared with kernel-side options (choosing among three syscall-hook approaches)**:

| Option | Layer | What changes | Prerequisites | Weakness |
|---|---|---|---|---|
| **sys_call_table replacement** | Kernel | Table entry pointers | root + write-protection lifted (STRICT_RWX, mmuhack) + symbol locating (Route C) | **CFI** (CONFIG_CFI_CLANG) type-checks indirect calls; a raw jump/replacement easily panics; page-table manipulation traces; old technique with mature detection |
| **svc_hook (user-space rewrite)** | User space | The svc instructions in the process's own code section | LD_PRELOAD must work (dynamically linked executable) | Statically linked/self-unpacking targets cannot be PRELOADed; code-section CRC self-checks will see it (the svc bytes changed) |
| **eBPF/kprobe (kernel entry attach)** | Kernel | No code changes; traps/trampolines | root + BPF privileges | Observation/limited argument tweaks only; average performance (kprobe), fentry is fast but needs BTF |
Selection: **to change syscall semantics against a conventionally dynamically linked app -> svc_hook is lightest; for stealth observation -> eBPF; for total control -> sys_call_table + CFI bypass (the moves in kernel-hook-stealth.md sec.5) or KernelPatch syscall hook (sec.2.1)**. From a CFI perspective, svc_hook's value: it moves the battlefield from "the indirect-call surface the kernel's CFI guards" back to "direct instruction rewriting in user space" - a sidestep against the CFI kernels of Android 12+.
Related reading: "SVC的TraceHook沙箱的实现 & 无痕Hook实现思路", the Frida-Seccomp approach.

## 6. perf_event hardware breakpoints: breakpoints that change not a single byte

**Principle**: ARM64 ships a self-hosted debug architecture - hardware breakpoint registers DBGBVR/DBGBCR (instruction breakpoints) and DBGWVR/DBGWCR (data watchpoints); when the CPU's fetch or memory access hits the VA, a debug exception fires **without modifying any instruction byte**. Linux wraps these registers behind the perf_event interface:
- perf_event_open(2) `PERF_TYPE_BREAKPOINT`;
- ARM64 implementation arch/arm64/kernel/hw_breakpoint.c ("a unified kernel/user-space hardware breakpoint mechanism implemented with CPU debug registers");
- ARM architecture doc: AArch64 self-hosted debug (the BRK software exception and hardware breakpoint exceptions have different EC encodings).

```c
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
struct perf_event_attr attr = {};
attr.type          = PERF_TYPE_BREAKPOINT;
attr.size          = sizeof(attr);
attr.config        = HW_BREAKPOINT_X;        // 执行断点(R/W/RW 为 watchpoint)
attr.bp_addr       = (uint64_t)target_addr;  // 路A-E 定位出的运行时地址
attr.bp_len        = 4;                      // ARM64 执行断点长度 4(或 8,实现对齐要求)
attr.sample_period = 1;                      // 每次命中出事件
attr.disabled      = 0;

int fd = sys_perf_event_open(&attr, target_pid, -1, -1, 0);
// 命中通知三选:read() 计数 / mmap ring buffer / fasync+SIGIO(signal_handler 里 siginfo->si_addr 等)
```

The kernel-module-side equivalent interface: `register_wide_hw_breakpoint` (exported by hw_breakpoint.c) - an LKM attaching kernel-address breakpoints on any CPU goes through it too. A reference walkthrough: Martin Uy, "Hardware breakpoints in the Linux kernel through perf_events"; the ptrace-side equivalent is `PTRACE_GETREGSET(NT_ARM_HW_BREAK)`.
**Why it is stealthier than INT3/BRK software breakpoints**:
1. **Zero byte modification**: software breakpoints (kprobe BRK/wxshadow shadow pages) ultimately must "let the fetch stream see a breakpoint instruction"; a hardware breakpoint has the CPU compare DBGBVR in the fetch pipeline - not one bit of target memory moves -> every code-section CRC/hash self-check, every `/proc/self/mem` comparison stays green;
2. No page-table tricks needed (contrast wxshadow's shadow PTE), the mmap/TLB surface untouched;
3. The only residual detection surfaces are perf_event counter occupancy (setting a bp on yourself returning ENOSPC/EOPNOTSUPP reveals the register slots are taken) and hit timing (debug-exception latency) - consistent with kernel-hook-stealth.md sec.8's "the timing side channel is the only universal residue".
**Limitations**:
- Hard slot cap: AArch64 commonly 4-6 breakpoints + 2-4 watchpoints (IMPLEMENTATION DEFINED; read the `SYS_DBG...ID` registers to know; only a few addresses watchable at once);
- Permissions: `perf_event_paranoid` and seccomp - the Android untrusted app domain basically cannot perf_event_open; this technique belongs to root/kernel-side scenarios (rooted reversing);
- Kernel-address breakpoints must avoid hitting in non-reentrant contexts (nested exceptions); handlers must be extremely short;
- Contends with kgdb/kprobe for slots; coexistence needs coordination.

## 7. The locate -> hook closed loop (prose flowchart)

```
[目标函数确认] 名字?行为/字符串?在哪个子系统(binder/syscall/futex…)?
   │
   ├─ 知道名字、有 root ──────────► 路D:available_filter_functions/kallsyms(先 kptr_restrict=0)
   │                                 └─ 名字在 kallsyms 但 LKM 链接不到 → 路C 方法一(kprobe 代查)
   ├─ 知道名字、无 root ──────────► GKI? ─是─► 路A:ci.android.com 官方 vmlinux 直接查偏移
   │                                 └─否─► 路B:vmlinux-to-elf 恢复目标机镜像符号
   ├─ 不知道名字 ────────────────► 路E:printk 串 xref / ops 表成员 / 常量特征 / BinDiff 官方镜像
   │
   ├─ [拿到静态地址] ──► 解 KASLR(§3):root 直接 kallsyms 真值 / 单符号反推 slide / 泄漏点
   │                      └─ 无 root exploit 场景:EntryBleed/prefetch/内存读原语
   │
   ▼
[hook 机制选择] ── 见《kernel-hook-stealth.md》§1/§9,摘:
   ├─ 只看参数/返回值、零侵入 ──► kprobe(兼容最好)/ fentry·kfunc(有 BTF,快+带类型)
   ├─ 改执行流/改参 ──────────► ftrace IP_MODIFY / KernelPatch inline hook / svc_hook(纯用户态 syscall 面)
   ├─ 用户态目标函数且怕注入痕迹 ► uprobe(零注入)或 perf_event 硬断点(§6,零字节修改)
   └─ 要对 app 无痕断点 ────────► wxshadow(KPM 影子页,《kernel-hook-stealth.md》§2.3)
   │
   ▼
[验证] tracefs 输出或 bpftrace printf 实测命中 / 行为 diff(改参后目标逻辑变化)
       / dmesg 无 WARN / 性能无异常(时序侧信道自查,同篇 §8)
       └─ 失败回滚检查:符号版本对不对(路A 坑)、inline(路C 坑)、CFI、槽位冲突(§6)
```

For an engineering reference of this closed loop within the APatch ecosystem: the APatch source covers KP's symbol extraction (extra_symbol) and KPM loading; capability mapping in kernel-hook-stealth.md sec.2.1.

## 8. Quick reference: target type x locating route x hook

| Target type | Recommended locating route | Recommended hook (see the other piece) | Notes |
|---|---|---|---|
| Exported functions (printk etc.) | Route D (root) / Route A (static) | kprobe/fentry directly | LKM can extern-link directly |
| Not exported, name known | Route C method one (kprobe lookup) -> get the kallsyms_lookup_name family | kprobe by name; KP inline for flow changes | The 5.7+ standard opening move |
| Not exported, no root, no image | Route A (official GKI) -> Route B on mismatch | Static patch (KP) / runtime attach after flashing | dd-verify consistency first |
| Not exported, vendor-forked kernel | Route B (vmlinux-to-elf) + Route E cross-check | Same as above | Mind tool versions on 6.4+ |
| Inlined/static functions | Route E (hook the outer real function, or BinDiff "relatives") | Hook the caller; kprobe cannot attach to an inlined target | Proven by bpftrace #2888 |
| Only behavior/error strings | Route E (printk string xref -> the sec.4 binder flow) | Pick from the rows above after locating | Strings per the target kernel source |
| Syscall entries | Route C (sys_call_table by name) or svc_hook with no locating needed | KP syscall hook / svc_hook (user space) | Be careful with raw table jumps on CFI kernels |
| User-space so functions | uprobe offset (IDA) | uprobe/uretprobe, perf_event hardware breakpoints (sec.6) | See android-kernel-ebpf.md sec.5 |
| Struct offsets (no specific function) | /sys/kernel/btf/vmlinux (bpftool dump) | Use BTF/CO-RE directly | Free on GKI 5.15+ |
| KASLR slide | sec.3: root kallsyms / single-symbol delta / EntryBleed | - | nokaslr on self-built machines |
**The tool pipeline**: magiskboot (unpack) -> vmlinux-to-elf (symbols) -> IDA/Ghidra (static) -> bpftool/pahole (BTF structs) -> bpftrace (kfunc/kprobe verification) -> kpatch/KPM (landing the hook). Full-chain commands in the sections of this piece + Appendix A of android-kernel-ebpf.md.

## 9. Open items

- No authoritative figure for ARM64 KASLR entropy bits (the x86_64 conclusions do not port directly);
- The svc_hook performance numbers (1000x vs 2000x) come from two inconsistent sources; take the order of magnitude.
