# Kernel Hooking and Stealth Confrontation

> Positioning: every frida tell (maps/rwxp/threads/gadget) lives in user space where the strongest RASP can see it all; move the hook into the kernel (patching entry instructions/page tables/shadow pages) and nothing exists within the app's field of view. This piece: a comparison of four kernel hook mechanisms, the KernelPatch family in detail (KPM/wxshadow stealth breakpoints), VoidLink, android-kernel-hacking-toolkit, the ANDROID-MRI idea, and a principled wrap-up of "why it cannot be detected".

## 1. The four kernel hook mechanisms compared

| Mechanism | Principle | Entry | Performance | Detection surface (visible to the app?) | Dependencies |
|---|---|---|---|---|---|
| **ftrace** | The compiler inserts `__fentry__` at every kernel function entry (on ARM64 a `BL` to ftrace_caller); when tracing is on, the call slot is rewritten to a jump | `tracefs` (debugfs/tracefs); `ftrace_set_filter` to filter target functions | Low overhead, reusable at livepatch scale | Visible only to whoever can read tracefs; the app has no read access -> **invisible** | CONFIG_FUNCTION_TRACER |
| **kprobe** | The instruction at the target address is replaced with a breakpoint instruction (x86 `int3`, ARM64 `BRK #0x1`); on hit, an exception handler single-steps the original instruction | `register_kprobe`; post-5.7 commonly used to resolve `kallsyms_lookup_name` | Trap + single-step, fairly slow | Same as above, **invisible**; but `/sys/kernel/debug/kprobes` can list them (root-only readable) | CONFIG_KPROBES |
| **eBPF fentry/fexit** | BPF trampoline: JITs the fentry call slot directly into a jump to the trampoline, capturing args and return value on both entry and exit, **trap-free** | `BPF_PROG_TYPE_TRACING` + `attach_fentry` (bpftrace `fentry:func`) | An order of magnitude faster than kprobe | **Invisible** (the app has no bpf privileges); the audit surface is on the root side | CONFIG_BPF+BTF (mandatory for fentry) |
| **LSM hook (bpf_lsm)** | Fixed hook points on kernel security paths (`file_open`/`task_alloc`/`bprm_check_security`...) | `BPF_PROG_TYPE_LSM`; or classic LSM registration | Path-level | **Invisible**; a legitimate framework capability | CONFIG_BPF_LSM |
**Key points**:
- Resolving `kallsyms_lookup_name` with a kprobe: no longer exported since 5.7 -> register a kprobe on the same-named symbol and take `kp.addr` (the standard opening move of android-kernel-hacking-toolkit and countless LKMs, see sec.5);
- fentry needs BTF: new GKI kernels have it; on old kernels/no-BTF setups fall back to kprobe;
- All four are **completely invisible to the app process** - the app has no CAP_SYS_ADMIN, no debugfs/bpf access; the "detection surface" exists only from the viewpoint of another root observer (adversarial root scanning).

## 2. The KernelPatch family: from the boot image to stealth breakpoints

### 2.1 KernelPatch / KPM

**Repo**: bmax121/KernelPatch (GPL-2.0, ~1.6k stars)
- Capabilities, from a stripped kernel image alone (no source/symbols needed): full symbol extraction (based on the vmlinux-to-elf approach), static patching of the kernel image, runtime injection of arbitrary code into the kernel, **inline hook + syscall table hook**, "Additional SU for Android" (i.e. APatch's root);
- Platforms: arm64 only, kernels 3.18-6.6 (in theory), requires CONFIG_KALLSYMS=y; thanks to android-inline-hook (arm64 instruction fixup);
- **SuperKey**: the APatch-world passphrase - calls to hooked syscalls carry the super key to trigger root authorization, ordinary calls run the original logic;
- **KPM (KernelPatch Module)**: kernel modules loaded at runtime (independent of the KMI .ko system), with its own SDK; APatch is its official Android front end.
**Inline Hook vs Inline Wrap** (user-material terminology; corresponds to KP README's inline hook/syscall hook):
- Inline Hook: directly rewrites the first N instructions at the target kernel function's entry into a jump (ARM64 commonly the 16-byte `LDR X16,#8; BR X16; addr` scheme); the original instructions are relocated into a trampoline with PC-relative addressing fixed up before execution - the kernel version of frida Interceptor attach;
- Inline Wrap: does not modify the target directly; wraps it in a layer (the trampoline runs user logic first, then jumps to the original function) - onEnter/onLeave semantics.

### 2.2 The "KernelHook" framework

Lead: "KernelHook: an Android ARM64/GKI kernel LKM hook framework derived from KernelPatch" -> verification result:
- GitHub searches for "KernelHook" only hit **Windows** kernel hook frameworks (adrianyy/kernelhook 312 stars, smallzhong/KernelHook 190 stars); no public repo of an Android/GKI LKM framework by that name was found;
- Verdict: the name most likely refers to the KernelPatch ecosystem's hook capability or a private project name. **Understand it as a capability, do not cite it as a standalone project**.

### 2.3 wxshadow: W^X shadow-page stealth breakpoints

**Repo**: wxshadow (a KPM module; also an 18-star PoC repo and a merged distribution)
**Technical origin**: the community post "shadow-memory hook".
**Capability facts** (README test matrix, closed loop on OnePlus Android 16 / Linux 6.12.23 / 4KiB pages / va_bits=39):
Mechanism (the full life cycle of a stealth breakpoint):

```
设断点: 分配影子物理页 = 目标页副本,在目标地址写入 BRK #0x7
        把用户 PTE 重定向到影子页(BBM 原子 PTE 写)
执行取指: CPU 走影子页 → 命中 BRK #0x7 → 异常进 handler
        → 寄存器全捕获(x0–x30/sp/pc/pstate)
        → PTE 翻回原始页 → 单步原指令 → 重装影子 PTE → 继续跑
读取者: 始终解析到原始页 → 永远看到原始字节,BRK 不可见
```

Two "read hiding" evidence chains (from the README test matrix):
- **/proc/PID/mem read hiding**: reading the target address returns the original instruction (`ff0301d1`), not the BRK;
- **GUP hiding**: hooks `follow_page_pte`, so `process_vm_readv`/`ptrace` (which go through get_user_pages->follow_page) also get the original page.
Other capabilities: multiple breakpoints, arbitrary shadow-page patching (instruction rewriting), register rewriting (x0 injection), cross-process hooking (client `wxshadow_client -p <pid> -a <addr>`, dispatched via prctl), fork protection (hooks `uprobe_dup_mmap`, children do not inherit the shadow), `exit_mmap` hook cleanup, `tlbi vaale1is` broadcast TLB invalidation, 100/100 stability.
**Key engineering points of the Linux 6.12 adaptation** (extremely valuable for building similar tools, all from the README):
- 6.12's `find_vma` carries `WARN_ON_ONCE(rwsem_is_locked(&mm->mmap_lock))` and `mmap_read_lock` is static inline -> the runtime path **abandons find_vma entirely**, switching to lockless page-table walking with `get_user_pte` + PFN validation;
- `page->mm` (captured from `get_task_mm` at set_bp time) is the authoritative owner; do not trust `vma_mm(vma)`;
- THP (2MiB block) targets return `-14` and are refused (a reliable probe of the `mm->mmap_lock` offset would be needed to split);
- if `wxshadow_exit` skips the 5-stage unhook, a dangling hook points into unloaded module code -> the next syscall reboots.
**Why it is stealthy (the principled wrap-up)**: the breakpoint exists only on the **shadow physical page**; every read path (page-table walkers, the hooked GUP, /proc/mem) sees the original PFN; the only difference is that the execution flow transiently walks the shadow page, and within that window the PTE is flipped back again. Any user-space self-check of the form "read my own code section and compare hashes" always hits the original bytes. **This is a structural checkmate against "inline-patch self-check" RASP.**

### 2.4 mkpms-stealth: the four-in-one combat module

 - `stealth.kpm`, four capabilities in one load:
- **hide-maps**: filters `/proc/<pid>/maps|smaps|map_files`, hiding injected so files by keyword/address range (explicitly "cannot do" memory scanning/dl_iterate_phdr/solist - the so must unhook itself);
- **kload**: kernel dlopen hijack, injects a so **without ptrace** (prctl 0x4B4C);
- **wxshadow**: sec.2.3;
- **dbc-rw**: kernel cross-process read/write (syscall 41 instrumentation).
-> The combination is a complete stack of "invisible injection + invisible breakpoints + reads/writes that never touch user space", targeting APatch/KP.

## 3. The VoidLink rootkit

**Entity**: VoidLink kernel rootkit hiding-module POC (repo has no README; code details need firsthand review).
**User-lead portion** (LKM ftrace syscall hook + eBPF rewriting Netlink response buffers to hide network connections): the concrete implementation is unverified. But the technique itself is a community-known generic approach:
- ftrace syscall hooking: see sec.1; the standard approach has ftrace directly flip the syscall entry via ops (kernel side), invisible to user-space readers of `ss`/`netstat`;
- eBPF response rewriting: `BPF_PROG_TYPE_TRACEPOINT`/kprobe on the `inet_diag`/sock_diag path, using `bpf_probe_write_user` to rewrite the port/address entries in the netlink response buffer, erasing listening ports from `ss`/`netstat` output - a classic application of eBPF writing user-space buffers (same shape as Cilium's early hide-port demo);
- Verdict: **project existence confirmed, technique feasibility confirmed, this repo's concrete implementation unconfirmed**.

## 4. android-kernel-hacking-toolkit

**Repo**: (bilingual Chinese-English README)
Four LKM modules (interacting via ioctl on a /dev device), all targeting modern Android aarch64 5.4+ mitigations:

| Module | Function | Key implementation |
|---|---|---|
| filecopy | Copies files in kernel mode (bypassing SELinux constraints on user-space IO) | Resolves `filp_open/kernel_read/kernel_write` from kallsyms, CFI-bypass wrappers |
| hideproc | Hides a process by PID + kill protection | Hooks `openat` (blocking /proc/<pid>/*) and other syscalls |
| propedit | Modifies Android system properties | Kernel-mode physical-memory writes to user pages |
| syscall_hijack | Fakes `sysinfo` return | sys_call_table hijack |
**The four moves against modern mitigations (README originals; mandatory for LKM work)**:
1. `kprobe` obtains the address of `kallsyms_lookup_name` (the solution for it being unexported >=5.7, sec.1);
2. `__attribute__((no_sanitize("cfi")))` wrappers around function pointers bypass CFI indirect-call checks;
3. **mmuhack**: direct page-table manipulation to temporarily lift write protection on kernel memory (sys_call_table) - bypasses rodata RO/CONFIG_STRICT_KERNEL_RWX;
4. Physical-memory writes to user pages (the propedit case).

## 5. ANDROID-MRI: the OS-level instrumentation idea

**Verification**: no public paper or project matching "50 apps with >=1M installs each, bypassing 97.6% of RASP (frida comparison: 52.4%), with trace runtime / ROM loader / root interface modules" was found; treat it as an idea to borrow:
- Core claim: don't inject into user space (that's the RASP radar zone); instead do **OS-level instrumentation on a vendor-signed production ROM** - the system layer looks completely normal, signature, integrity, and properties all pass;
- The three modules as imagined: `trace runtime` (ROM-built-in tracing, equivalent to a system-wide frida but with none of frida's tells), `ROM loader` (flashes/loads the instrumented ROM), `root interface` (a controlled root outlet such as /system/bin/sh);
- A realistic landing path (assembled from the components above): APatch/KernelPatch (KPM = the kernel side of the trace runtime) + wxshadow (stealth breakpoints) + your own ROM build or a magisk boot patch (loader) + the KPM-provided su (root interface) - equivalent in capability, just without a quantified "97.6%" endorsement.

## 6. Why kernel-level hooks cannot be detected (summary of the principle)

Every information source available to user-space detection, item by item:

| RASP detection method | Under frida | Under kernel hooks |
|---|---|---|
| Read /proc/self/maps looking for rwxp/so | Hits | None (no injection; hide-maps as backstop) |
| Scan code-section prologue hashes/comparisons | Patch hits | **wxshadow: read paths see the original page, no hit** |
| Check thread names (gum-js-loop)/thread counts | Hits | No new threads (kprobe/BRK run in exception context) |
| Check files (magisk/frida-server/properties) | Hits | APatch/KPM has none of these surfaces |
| ptrace self-check of TracerPid | frida attach hits | No ptrace used (wxshadow explicitly hides from GUP) |
| Inline svc direct-call comparison of returns | May hit (the libc layer is what's modified) | The hook is in the kernel; direct svc calls are hooked too |
| perf_event/timing side channels | Theoretically measurable | Still measurable (trap overhead) - **the only residual detection surface** |
One sentence: **detection is fundamentally "reading state you cannot see", and kernel hooks move the state to a layer the app can never read (page-table shadow pages, kernel entry instructions); the residual risks are only performance side channels and another root observer (anti-root scanning) - which is already root-vs-root, not app-vs-app.** Pair with root-and-environment-hiding.md (area 04) and KPM hide capabilities for a closed loop.

## 7. Mechanism deep dive (the foundations of stealth)

### 7.1 ARM64 breakpoint instructions and exception decoding (why wxshadow chose `BRK #0x7`)

- ARM64 has no x86 `int3`; the generic software breakpoint is `BRK #imm16`: on AArch64 `BRK` raises EC=0x3C (BRK exception, ESR_EL1.EC=111100);
- imm16 is an immediate space; kernel kprobes habitually use `BRK #0x1`/`#0x2` (kprobe/kgdb each hold one); **`#0x7` is chosen to avoid the kernel's own number range**, and the exception handler dispatches by imm to the KPM's handler;
- Single-step: `PSTATE.SS` (Software Step, enabled via MDSCR_EL1.SS) - after flipping back to the original page, wxshadow relies on hardware single-step to execute the original instruction, then reinstalls the shadow PTE;
- TLB coherence: after a PTE change you must invalidate; wxshadow broadcasts `tlbi vaale1is` (inner-shareable, all ASIDs, with VA) - stale TLB entries on other cores are the most common way this class of tools crashes.

### 7.2 LKM hooking by rewriting IP directly via ftrace (generic, no KP dependency)

The classic x86 idiom (community ftrace-hook template): register `ftrace_ops` on the target function address, declare `IP_MODIFY`, and in the callback rewrite `regs->ip` to point at a wrapper (equivalent to changing the return address; the target function is hijacked before it ever runs); ARM64 has no `regs->ip` equivalent, so the community approach is a **fentry trampoline** or straight-up KernelPatch inline hook (sec.2.1). Detection surface: a root observer reading tracefs can see it - still invisible to the app.

### 7.3 Minimal KPM skeleton (understanding how a KPM differs from a .ko)

```
KPM:KernelPatch Module,由 KP 的 kpatch 工具加载(kpm load),不走内核 module_load,
     因此不依赖 KMI 版本、不落 /proc/modules 常规路径、无 module 签名校验环节。
接口形态(概念):hook 原语 + 符号解析(extra_symbol)+ 事件回调;
wxshadow 的 KPM 化 = 模块 init 时装好 BRK handler/页表工具,prctl 留用户态控制通道。
```

Compared with insmod of a .ko: a `.ko` goes through the official loader (module signature/lockdown checks; on Android GKI, loading outside the vendor_dlkm domain is restricted); a KPM is installed by KP's own patch engine - which is why APatch works on devices with a locked boot chain (provided the bootloader is unlocked or a bug allows writing the boot partition).

### 7.4 APatch vs KernelSU vs Magisk (root-hiding surface comparison)

| | Magisk | KernelSU | APatch (KP) |
|---|---|---|---|
| Principle | ramdisk patching + su client | Kernel-mode su (GKI module/integrated kernel) | KernelPatch kernel-image patch + SuperKey |
| Detection exposure | Frequently scanned (magisk properties/files) | Less | Least + stackable KPM hide stack |
| Module ecosystem | Largest | Zygisk compatibility layer | KPM (kernel mode, this piece's protagonist) |
| Companion pieces | Zygisk+Shamiko | Built-in | stealth.kpm (hide-maps+kload+wxshadow+dbc-rw) |
Positioning: APatch/KP is the foundation of the "kernel hook stack"; Magisk/KSU are conventional root; the three are mutually exclusive installs - selection details in 04-evasion/root-env-hiding.md.

## 8. The reverse view: how another root observer finds these (red-team self-audit)

- **kprobe/ftrace detection**: `/sys/kernel/debug/kprobes`, tracefs enabled lists, resident ftrace trampoline symbols in `/proc/kallsyms`;
- **wxshadow residual surfaces**: shadow pages are extra physical pages -> anomalies in total memory/buddy-system stats; page-table PFNs inconsistent with `page->mapping` expectations (requires kernel-side walking); dmesg may retain pr_info (good implementations are silent); per-process exception: single-step exceptions inside the BRK window are visible in perf_event (PERF_COUNT_HW_INSTRUCTIONS spikes) - **the timing side channel is the only universal residual detection surface**;
- **KPM detection**: after kpm load, the boot partition hash disagrees with the running state (another layer of compromise is needed to check); diffing sys_call_table/entry instructions against static vmlinux (root holds a static image and diffs live memory) is the ultimate self-audit;
- Verdict: **no solution at the app layer; root-vs-root is the current confrontation frontier**. When writing tools, converge traces against this checklist.

## 9. Selection decisions

**wxshadow client quick reference** (commands from the README):

```
wxshadow_client -p <pid> -a <addr>                 # 设断点(寄存器全捕获)
wxshadow_client -p <pid> -a <addr> -r x0=<val>     # 断点 + 改寄存器
wxshadow_client -p <pid> -a <addr> --patch <hex>   # 影子页改指令
wxshadow_client -p <pid> --release                 # 全部释放
```

Deployment chain (OnePlus Android 16 tested path, README original): push to /sdcard -> su cp to /data/local/tmp (the KernelSU redirection trap) -> `kpatch kpm load wxshadow.kpm`.
**One-line selection guide**:
- To hook kernel functions/syscalls with a controllable environment: start with kprobe (best compatibility) -> fentry (when BTF is present);
- For stealth breakpoints/argument rewriting against **the target app process**: wxshadow (KPM) or mkpms-stealth;
- To hide the network surface: the VoidLink route (ftrace + eBPF writing netlink responses; principle confirmed);
- For a full root+hiding stack: APatch (KP) + the KPM module stack;
- Just to understand the mechanics: android-kernel-hacking-toolkit's four modules are small enough to be the best textbook.
