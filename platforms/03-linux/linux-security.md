# Linux Security (knowledge base · Linux platform 1001248)

> Corresponding tree: Linux platform [1001248], 16 nodes (9 second-level). This file is organized as "principles → tools → field work → representative posts".

## §1 ELF Format in Depth [1001020]

### 1.1 Overall layout

ELF (Executable and Linkable Format) is the foundation of all reversing on the Linux platform. Two views: the linking view looks at Sections, the execution view looks at Segments.

```
+-----------------------------+ 0x0
| ELF Header (64B/52B)       |  e_ident/e_type/e_machine/e_entry/e_phoff/e_shoff
+-----------------------------+
| Program Header Table        |  执行视角:内核 loader 只认这里(PT_LOAD/PT_DYNAMIC...)
+-----------------------------+
| .text / .rodata / .data    |  ← 节(Section)按功能切分
| .bss(仅占位)/.got/.plt    |
+-----------------------------+
| Section Header Table        |  链接视角:ld/readelf -S 消费(可被 strip 删掉)
+-----------------------------+
```
(self-drawn ASCII)

Key difference: **virus and injection samples often delete the Section Header Table or forge section names** — because kernel loading depends only on the Program Header, static-analysis tools get "inertially" misled. Used in reverse: `readelf -h` showing zero sections while the program still runs = a classic packed/infected trait.

- 64-bit ELF Header: `e_phoff` (program header offset), `e_shoff` (section header offset), `e_entry` (entry virtual address, OEP-related).
- Common sections: `.text` (code), `.rodata` (constants), `.data` (initialized data), `.bss` (uninitialized data), `.got`/`.got.plt` (global offset table), `.plt` (procedure linkage table), `.rela.plt`/`.rela.dyn` (relocation tables), `.dynamic` (dynamic segment info), `.init_array`/`.fini_array` (constructor/destructor callbacks), `.interp` the dynamic-linker path (`/lib64/ld-linux-x86-64.so.2`).
- Common segments: `PT_LOAD` (loadable), `PT_DYNAMIC` (dynamic-linking info), `PT_INTERP` (interpreter), `PT_NOTE` (not needed at runtime — **the classic infection/injection point**), `PT_GNU_STACK` (where the NX flag lives).

Representative posts:
- ELF Format (2020; section structure and the runtime view)
- Analysis notes on Linux executables — ELF files with a C implementation (hand parsing ELF; the text specifically discusses why PT_NOTE is so easily abused by virus infections)

### 1.2 Dynamic linking and relocation

Looking at a shared library's "symbol references" statically, the core is two pointer groups in the `.dynamic` segment: `DT_SYMTAB` (symbol table `.dynsym`) + `DT_STRTAB` (symbol-name string table `.dynstr`), plus `DT_JMPREL` (pointing to `.rela.plt`) + `DT_PLTGOT` (pointing to `.got.plt`).

Key x86-64 relocation types:

| Type | Table | Meaning |
|---|---|---|
| `R_X86_64_JUMP_SLOT` | `.rela.plt` | **function symbols** through the PLT's GOT entries, the lazy-binding protagonist |
| `R_X86_64_GLOB_DAT` | `.rela.dyn` | data/function addresses already resolved at startup |
| `R_X86_64_RELATIVE` | `.rela.dyn` | base relocation (load bias + addend), for PIE |
| `R_X86_64_64` | `.rela.dyn` | absolute 64-bit embedding |
| `R_X86_64_COPY` | `.rela.dyn` | (32-bit tradition) libc variables copied into .bss, basically extinct on 64-bit |

RE significance: to find "which libc functions a program calls", dump `.rela.plt` (`objdump -R` / `readelf -r`); the offense-defense of GOT hooking (changing function pointers) and GOT protection (RELRO: Full makes `.got` read-only) all plays out on this table.

Representative posts: Understanding the dynamic-linking lifecycle of Linux systems through ELF function hijacking (2024; the full dynamic-linking flow starting from an ELF infection algorithm), Summary and code implementation of ELF hooks (hands-on `.rela.plt`/`.rela.dyn` modification).

### 1.3 GOT/PLT lazy binding (hand-traced once)

```
call printf@plt
  └─ printf@plt:  jmp *GOT[n]        ← 第一次:GOT[n] 指向 plt[0]push 序列
       ┌─(首次)──────────────────────┐
       │ push reloc_index           │ plt 尾巴
       │ jmp  plt[0]                │
       │   push link_map            │
       │   jmp  _dl_runtime_resolve │ ← ld.so:查 .dynsym+.dynstr
       └────────────────────────────┘
  解析后 GOT[n] = 真实 printf 地址
  第二次起:jmp *GOT[n] 直达 libc
```
(self-drawn ASCII)

Essentials:
1. Lazy binding = deferring symbol-resolution cost to the first call; `LD_BIND_NOW=1` forces full resolution at startup (paired with Full RELRO).
2. RE timing trick: break after `_dl_runtime_resolve`, or let the function be called once, then dump the GOT for real addresses — escaping the static-analysis plight of seeing only stubs.
3. Malicious surface: GOT overwrite (old-style infection), forging reloc_index for **ret2dl_resolve** (resolving arbitrary symbols without a libc base; exploitation belongs to area 06).

### 1.4 Inside dlopen/dlsym

- `dlopen(path, flag)`: in glibc goes `__dlopen` → `_dl_open` (inside dlfcn/ld.so); core steps: mmap-map the load → `_dl_map_object` finds/maps the so → walks the `DT_NEEDED` dependency tree → `_dl_relocate_object` relocates (here `R_X86_64_JUMP_SLOT` is resolved immediately or deferred per BIND_NOW) → runs `.init_array`.
- `dlsym(handle, name)`: `_dl_sym` → `do_dlsym`; first searches the handle's symbol tables (incl. the dependency chain, affected by `RTLD_LOCAL/GLOBAL` scopes), then falls back to the default scope; the return value is the real function address — **effectively a built-in "symbol brute-force interface"**; use it during RE to read any exported symbol.
- Field hooks: LD_PRELOAD/LD_DEBUG=all are three free RE weapons (with dlopen): the first changes behavior, the second logs the whole ld.so symbol-lookup and binding process.
- Android-side variant: `/system/bin/linker` (bionic) does the same job; flow post: A brief talk on the startup flow of ELF executables.

### 1.5 The loading view (execution chain)

`execve` → kernel `load_elf_binary`: read the ELF Header → mmap each `PT_LOAD` segment (load bias = randomized base, PIE) → `PT_INTERP` finds ld.so and maps it too → switch to the ld.so entry `_start`→`_dl_start`→`_dl_start_user`: relocate, initialize, run `.init_array`, finally jump to `e_entry`. **When reversing packed samples, the real OEP is the target of that final jump.**

### 1.6 Hand-writing a Linker (the top thread under the software-development node [1001347])

The classic community route: the best way to understand ELF is to hand-write a loader/linker. Representative posts:
- Hand-writing an ARM64 custom linker from scratch: parse ELF yourself, map segments, process relocations, run init_array — turning §1.1~§1.5 into code.
- Turning .o into .ko (part 3): what you only learn by writing your own loader: ELF format conversion + a self-written loader; the seam between the linking view and the kernel-loading view.
- Tool-grade: elfspirit: a static-analysis and injection framework for Linux (2021; supports adding/removing sections, static so injection — itself "replicating linker behavior with a tool").

## §2 Linux RE Tools [1001459/1001460/1001480/1001481]

### 2.1 The GDB family (GDB [1001481])

| Tier | Contents |
|---|---|
| Native | `break/watch/catch` (catch syscall/load), `info proc mappings`, `disas`, `x/`, `generate-core-file`, `set follow-fork-mode`, `checkpoint` (fork snapshot rollback), `gdb --args`, remote `target remote :1234` (gdbserver/qemu -g) |
| GEF | The largest one-screen install: context panels, `heap`/`pattern`, integrated checksec, ROP gadget search |
| pwndbg | Strongest for CTF pwn: pwntools affinity, `vmmap`/`telescope`/`find_fake_fast`, heap debugging's `vis_heap_chunks` |
| Choice | GEF for analyzing malware/large programs; pwndbg for pwn; install only one (both hook the prompt; mixing conflicts) |

### 2.2 GDB Python automation

The built-in interpreter imports `gdb` directly, no modules needed. Core APIs:

```python
class ScanBP(gdb.Breakpoint):          # 类断点:停了自动做事
    def stop(self):
        v = gdb.parse_and_eval("$rdi") # 取寄存器/表达式
        s = gdb.selected_inferior().read_memory(int(v), 64).tobytes()
        open("dump.bin","ab").write(s)
        return False                   # 不真正停,继续跑 → 无感批量 dump

gdb.execute("set pagination off")      # 跑任意 gdb 命令
gdb.events.stop.connect(on_stop)       # 事件回调:断点/信号/退出
gdb.write(gdb.execute("info functions", to_string=True))  # 捕获输出
```
Three usages: command line `-ex "source sc.py"`; `source` inside gdb; permanent in `~/.gdbinit`. Typical scenarios: looping memory reads/writes, batched breakpoints, "loop dump + compare until memory stops changing" during unpacking (the embryo of automated OEP finding).
Representative post: gdb — automated debugging with python (2024-01).

### 2.3 DynamoRIO [1001461] and static tools

- **DynamoRIO**: a runtime-instrumentation framework (DBI) with good native Linux support. Write a client (callback `dr_register_bb_event`) to act on every basic block: coverage counting, instruction tracing, syscall monitoring — the full recorder for malware behavior analysis, complementing Frida (same DBI class, finer hook granularity). Same class: Intel Pin, Valgrind.
- **radare2**: the command-line open-source RE suite: `r2 -A` analyze, `aaa`/`pdf`/`axt` (xref)/`izz` (strings)/`/r` (gadget search). Scripting via r2pipe (Python); GUI front end Cutter. Good for fast triage on GUI-less servers, complementing IDA/Ghidra. Broad architecture support (incl. MIPS/ARM — a first pick for IoT samples). (Special-topic posts: nYale's translated trilogy "radare2 primer"/"radare2 intermediate"/"radare2 advanced" — translated from the megabeets.net series (1=primer, 2=intermediate writing exploits, 3=analyzing ROMs); also "Debugging with radare2", "RADARE2+FRIDA setup", "Radare2 documentation")
- **Static helpers**: `readelf -a/-r/-S`, `objdump -d/-R`, `nm -D`, `strings -a`, `file`, checksec (NX/Canary/PIE/RELRO — the first shot before analysis), 010 Editor (with ELF templates).

### 2.4 Analysis environments (basic operations [1001353])

Minimal set: `file/readelf/objdump/strings/ltrace/strace/gdb/python3`; advanced: qemu-user (running MIPS/ARM ELF cross-architecture, attach gdb with -g), the binutils toolchain, angr (symbolic execution, see the fundamentals area [1001369]). Containerized analysis environments have been mainstream these past two years (see [other-platforms.md](other-platforms.md) §3).

## §3 Linux Anti-Debug and Tracing

### 3.1 The ptrace system (the heart of anti-debug)

ptrace is Linux's only "native debug protocol"; strace/gdb/ldb are all built on it:
- `PTRACE_TRACEME`: the child self-declares "traced by the parent" → commonly used by fork self-check anti-debug.
- `PTRACE_ATTACH/SEIZE`: attach to the target; `PTRACE_PEEKTEXT/POKETEXT`: read/write memory (a breakpoint is just 0xCC + POKETEXT); `PTRACE_GETREGS/SETREGS`; `PTRACE_CONT/STEP`; `PTRACE_SYSCALL`: syscall-level interception (how strace is implemented).
- The four anti-debug classics (sample side):
  1. **Occupying the seat**: at startup the process forks a child, the child does `PTRACE_TRACEME` and the parent ptraces itself — one process can be traced by only one tracer at a time, so a later gdb attach gets EPERM.
  2. **Self-check**: read the `TracerPid:` field of `/proc/self/status`; non-zero means debugged.
  3. **Timing difference**: rdtsc/`clock_gettime` sampled on both sides; breakpoint pauses amplify the delta.
  4. **int3 self-verification**: CRC over its own .text; 0xCC contamination reveals hardware/software breakpoints.
- Defeats: understand the check from kernel-source perspective then patch/bypass; or "fight ptrace with ptrace".

Representative posts:
- Analysis of Bangcle anti-debugging in a connected-car app (2023; ptrace seat-occupying principle and implementation)
- Analysis of a CTF reversing challenge with ptrace anti-debug (the intro exemplar of practical Linux anti-debugging)
- [Beating anti-debug from source] 2: beating PTRACE_TRACEME (principle and bypass analyzed from kernel source)
- Using ptrace to beat ptrace anti-debug (fighting poison with poison)

### 3.2 strace / ltrace / perf

| Tool | Hook point | RE use |
|---|---|---|
| strace | ptrace(PTRACE_SYSCALL) | see which files/network/processes a sample touched — the first shot of behavior profiling; `-f` follows children, `-e trace=file,network` filters |
| ltrace | breakpoints at the PLT | library-function-level tracing (the principle is the §1.2 PLT interception, so it fails on statically-linked or hand-written-syscall samples) |
| perf | perf_event (not ptrace) | sampling hotspots: locate encryption functions/check loops, `perf record -g` + flame graphs |

Complements: `/proc/<pid>/maps` for segment mappings (spotting so injection, picking dump ranges), `/proc/<pid>/fd` for open files. Samples can detect strace (attaching is exposed via TracerPid) → high-stealth needs go to §3.3 emulation.

### 3.3 Signals and multi-process

On Linux, "exceptions" = signals (SIGTRAP/SIGSEGV/SIGILL). Debuggers take back control via SIGTRAP; anti-debug forges the signal flow (self `raise(SIGTRAP)` + a pre-armed handler deciding whether a real debugger exists). Multi-process samples: daemonize (fork two generations) + parent-child mutual ptrace is the mainstream self-defense combo of Linux packers; the gdb answer is `set follow-fork-mode child` + `detach-on-fork off`.

## §4 UPX and Linux Packers

### 4.1 UPX structure (Linux ELF edition)

```
原文件: [ELF头|原段们|........]  --压缩-->
UPX文件:[ELF头|PT_LOAD×2|UPX stub|压缩数据(LZ/NRV)]
              │         └── 解压后 mmap RWX 区,自恢复 section
              └── 入口指向 stub;特征串 "UPX!" / "$Info: This file is packed..."
```
(self-drawn ASCII)

- Stub logic: mmap the decompression target → NRV/LZMA-decompress the original segments → rebuild the original entry and jump → (erase packer traces). Signatures: `readelf` shows only 2 PT_LOADs, the entry sits in the packer's code segment, the trailing `UPX!` magic.
- `upx -d` restores directly (provided the magic wasn't changed/traits weren't wiped; samples often change `UPX!` to junk bytes so -d refuses — hand-edit back and it works).
- Variant confrontation: UPX with scrambling, modified l_info/p_info structures, double UPX (two layers).

### 4.2 The Linux commercial/malicious packer ecosystem

The Linux counterparts of Windows' VMProtect/Themida: modified UPX packers (a favorite of miner samples, magic wiped), self-built compression packers (IoT samples often carry MIPS/ARM UPX), encrypt/decrypt stubs (ransomware decrypting payloads at runtime). See §6 for unpacking.

## §5 Linux Malware [1001394]

### 5.1 ELF viruses (infectious)

Unlike trojans (standalone processes), viruses parasitize host files. The four classic infection algorithms:
1. **Data-segment injection (into padding/cavities)**: stuff the virus body into alignment cavities after `.text` or into the data segment, patch `e_entry` to point there, and jump back to the original entry after running — **no file-size growth**, the stealthiest. Community exemplar: Analysis of an ELF data-segment injection virus (2024-09: at host runtime the virus code maps into the process space together with host code; the virus runs first, finds the next host, then returns control).
2. **PT_NOTE overwrite**: turn the runtime-useless PT_NOTE segment into PT_LOAD and inject code (mentioned in §1.1, with principles).
3. **Appending a new section**: add a section/segment; the file grows but the structure is most stable (elfspirit's add/remove section support is exactly this).
4. **Function hijacking**: change GOT/symbol pointers, e.g. understanding the dynamic-linking lifecycle through ELF function hijacking.
Early discussion: understanding a small ELF file-infection snippet from the web.

### 5.2 IoT/botnet samples (the Mirai lineage)

- **Mirai** (2016): telnet dictionary brute-force infection, then scanning to spread + DDoS. Structural traits: multi-architecture cross-compilation (x86/ARM/MIPS), table-driven string obfuscation (index table XOR decryption), watchdog disabled, random self-deletion. The first pick for analysis onboarding; the many variants (RapperBot, Sora, Gafgyt/Bashlite) only swap the string table and C2 protocol.
- **RapperBot**: brute-forces SSH instead of telnet; exemplar post: RapperBot, what are you brewing?.
- Macro-trend post: SSH brute-force trends: migrating from cloud platforms to IoT devices (over 50% of dropped malicious files are ELF, x86 at 63%).
- Systematic text: ELF malware analysis 101: Linux threat defense no longer lags (2020 translated long read, Mirai as the typical case).

### 5.3 Miners / ransomware / rootkits

- Miners: the largest sample class, UPX packing + `kworker` disguise + crontab persistence; exemplar post: dual-system mining, analysis of a new AutoUpdate mining virus.
- Ransomware: RaaS ported to the Linux side, e.g. the Sodinokibi (REvil) ransomware attacking Linux platforms (focus on key generation and the file-walk encryption path).
- Rootkits: user-mode (LD_PRELOAD hijacking) and kernel-mode (LKM, eBPF-flavored new variants); case: server compromised, a Linux rootkit trojan installed. Detection confrontation and kernel mechanisms in §7.

## §6 Linux Unpacking [1001376/1001377]

### 6.1 The generic flow (Linux four steps)

1. **Find the OEP**: the packer finishes decompressing and jumps back to the original entry. Techniques: `catch` (break at `mprotect`/`brk`/write returns), entry breakpoint + single-step the jump chain, or gdb-python automation "periodically dump the .text segment; stable content = OEP" (reuse the §2.2 code idea directly).
2. **Dump**: pull each PT_LOAD segment from process memory back into a file (`gdb dump binary memory` / a self-written /proc/pid/mem reader; Linux needs no Windows-style ImpREC).
3. **Repair**: rebuild section headers (or go headerless — Linux still runs), fix `e_entry`=OEP, restore the dynamic segment's `DT_JMPREL` entries to their pre-binding PLT values (or just run once with LD_BIND_NOW then dump — the GOT is then complete).
4. **Verify**: executable + `strace` behavior matches the original sample.

The root reason Linux unpacking is more comfortable than Windows: **dynamic-linking info lives in .dynamic/GOT and is self-consistent at runtime**; the dumped image natively carries resolved symbols — no "rebuild the import table" step.

### 6.2 A UPX example [1001378]

- Fast lane: `upx -d sample -o unpacked` (hex-restore a wiped `UPX!` magic first).
- Manual lane (teaching value): run in gdb until the stub finishes decompressing → break at the jmp to OEP → dump the three segments → fix the ELF header. The corpus has multiple UPX unpacking example posts (tree node 1001378 dedicated; Windows side: "upx unpacking and appended-data handling", "A UPX-packed DLL", "Reversing the unUPX.dll plugin" — Linux-side dedicated posts searchable on site).
- Combined with SMC patching: patch memory directly without unpacking (gdb `set {char}addr=0x90`), suited to crack scenarios changing only a jump or two — the mainstream Linux cracking practice, no file rebuild.

## §7 System & Kernel Entry [1001348] (mechanisms and RE; exploitation goes to 06)

### 7.1 RE entry points

- **vmlinux extraction**: `/boot/vmlinuz` is compressed → the `extract-vmlinux` script decompresses a symbol-carrying vmlinux; distros offer `dbgsym` packages. No-symbols scenario: `vmlinux-to-elf` (rebuilds symbols from the kallsyms table) is the standard weapon.
- **kallsyms**: `/proc/kallsyms` exposes kernel symbol addresses (restricted by `kptr_restrict`; root or setting it to 0 shows real values); extraction scripts/module development all depend on it.
- **Source**: `/usr/src` or elixir.bootlin.com online. Reversing so means reading ld.so; reversing the kernel means reading exactly these entries.

### 7.2 Interfaces to user-mode RE

- Syscalls: the syscall table (sys_*) is the "final destination" of user-mode sample behavior; `strace` is its user-mode mirror (§3.2).
- LKM (loadable kernel modules): a `.ko` is itself an ELF (ET_REL); reversing it = reversing a linking-view ELF + kernel symbols. The `turning .o into .ko` series is exactly this chain at play.
- `/proc`, `/sys`, netfilter, eBPF: the rootkit mounting surfaces; the detection side (forensics) likewise starts from the "tampering traces" of these mechanisms.

### 7.3 Boundary statement

EoP chains, kernel heap exploitation, module-loading exploit usage → all in the **06-binary-vuln area** (Linux kernel exploit study [1001433], practice [1001442], CTF Linux kernel-mode exploitation [1001691]).

## §8 VMs and Emulation [1001266]: Qiling / Unicorn on Linux ELF

### 8.1 The two-layer stack

- **Unicorn**: pure CPU emulation (the engine carved out of QEMU TCG), instruction layer only — no syscalls, no memory layout. RE uses: single-function emulation (brute-forcing registration codes, emulating decryption routines), forging a stack to feed arguments. The knowledge base's Android area has a Unicorn special topic [1001648]; the methods transfer directly.
- **Qiling**: fills in the "OS layer" on top of Unicorn — ELF loader, rootfs path redirection, syscall emulation, dynamic-library loading. So you can: run MIPS/ARM Linux ELF malware directly on an x86 machine, never touching a real device.

### 8.2 The Qiling RE workflow

```python
from qiling import Qiling
ql = Qiling(["/samples/arm_bin"], "/rootfs/armhf")  # rootfs 提供 libc 等
ql.hook_address(oep_cb, 0xADDR)      # 地址钩子:到 OEP dump
def sys_hook(ql, syscall_id, params):  # syscall 钩子:行为画像
    log(params)
ql.os.set_syscall(0x1000, sys_hook)
ql.run()
```
Value: ① cross-architecture sample analysis; ② **naturally anti-anti-debug** (no ptrace, TracerPid always 0, timing adjustable via the clock); ③ unpacking inside the emulator (wait for decompression to finish then dump, fully controlled environment). Limits: rootfs dependency matching; some syscalls unimplemented and self-supplied.

Representative items:
- First look at the Qiling framework (2024-11)
- Using the Qiling framework to emulate firmware with IDA dynamic debugging (Qiling + IDA together)
- Smart-hardware board digest compilation (the master index of Qiling/firmware analysis)

## §9 Reference quick table

| Topic | Item | Link |
|---|---|---|
| ELF format | ELF Format |  |
| ELF format | ELF file analysis notes and a C implementation |  |
| Dynamic linking | Understanding the dynamic-linking lifecycle via ELF function hijacking |  |
| ELF hooks | ELF hook summary and code implementation |  |
| Startup flow | A brief talk on the startup flow of ELF executables |  |
| Hand-written linker | Hand-writing an ARM64 custom linker from scratch |  |
| Loader | Turning .o into .ko (part 3): writing your own loader |  |
| ELF tools | elfspirit static-analysis and injection framework |  |
| gdb python | gdb — automated debugging with python |  |
| Anti-debug | Analysis of Bangcle anti-debugging in a connected-car app |  |
| Anti-debug | A CTF reversing challenge with ptrace anti-debug |  |
| Anti-debug | Beating anti-debug from source: PTRACE_TRACEME |  |
| Anti-debug | Using ptrace to beat ptrace anti-debug |  |
| ELF viruses | Analysis of an ELF data-segment injection virus |  |
| ELF viruses | Discussion of a small ELF file-infection snippet |  |
| Malware | ELF malware analysis 101 |  |
| Malware | RapperBot analysis |  |
| Malware | SSH brute-force trends (ELF share) |  |
| Malware | Linux rootkit trojan case |  |
| Malware | Sodinokibi ransomware hits Linux |  |
| Malware | AutoUpdate miner analysis |  |
| Emulation | First look at the Qiling framework |  |
| Emulation | Qiling emulating firmware + IDA dynamic debugging |  |
| Index | Smart-hardware board digest compilation |  |
