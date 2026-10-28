# Trace in Practice (all-layer tracing tools: from function level to instruction level to time-travel replay)

> Topic: when to use which layer of trace, how to actually run it, how to control volume, how to post-process.
> Division of labor: Stalker's assembly-level principles and transform recipes are in [02-frida/advanced/stalker.md](../02-frida/advanced/stalker.md); this piece covers only **runnable practice + the full selection panorama + post-processing**.
> Environment: macOS arm64 (darwin 25.6.0, SIP on), frida 17.23.3 (`tools-env/.venv/bin/`), radare2 6.2.4. Everything marked "verified locally" is real output from 2026-10-16.

**Bundled driver scope:** `scripts/stalker_trace.py` defaults to starting a
host-local executable with `subprocess.Popen` and local `frida.attach`. Its optional
Android attach mode requires an exact `--device-serial` and an existing `--pid`;
it never chooses a device automatically or starts/kills that device process.
Use only the task-owned test APK allowed by [device-testing.md](../../device-testing.md).
`--thread-id` selects a verified enumerated TID; without it, Android/Linux mode
requires the requested PID to match `Process.id` and verifies that the matching
process-leader TID exists. The macOS `threads[0]` observation is confined to the
default host mode. Device mode has offline mock coverage and **has not been
verified on physical Android hardware**. `scripts/syscall_sim.py` remains a
host-local macOS observer; `scripts/calltree.py` only post-processes JSONL.

## 0. The one-sentence creed

Trace is fundamentally **buying information by layer**: at the syscall layer you buy "what resources were touched"; at the function layer "who called whom"; at the block/instruction layer "the true face of the control flow"; at the record/replay layer "time travel". The deeper the layer, the bigger the data volume and the slowdown - **locate at function level first, then drop layers for evidence**; never open Stalker wide from the start.

---

## 1. The trace panorama comparison table (selection core)

| Tool | Tracing layer | Platform | Overhead | Invasiveness | Output form | Best scenario | Shortest command |
|------|---------|------|------|--------|---------|---------|---------|
| frida-trace | Function level (libc/any export+JNI/OC) | All platforms | Low (only hooked functions) | Injects an agent | One line per call: ms+args | Quick answers to "who called X, with what args" | `frida-trace -p PID -i open` |
| frida Stalker | Basic-block/instruction level (DBI recompilation) | All platforms | High (1.5~N x slowdown verified locally) | Injection + code bloat | call/ret/block/exec event streams | Full control flow, unpacking dumps, coverage | See the sec.3 driver script |
| QBDI | Instruction level (standalone DBI, can share a frida session) | x64/AArch64 (0.10.0+) | High, but pure instruction tracing beats Stalker (community-tested) | Injection (via the frida-qbdi binding) | Instruction callbacks/basic-block events | The alternative engine when you don't want Stalker bloat | `pip install qbdi`, then Python callbacks |
| strace | syscall level | Linux | Medium (ptrace stop-and-go) | ptrace (detectable) | One line per syscall | Watching IOCs: file/network/execve surfaces | `strace -f -e trace=openat,connect ./bin` |
| ltrace | Library-function level | Linux | High | ptrace | Library-call lines | Watching the libc call surface | `ltrace -e malloc+free ./bin` |
| dtruss/dtrace | syscall level (DTrace probes) | macOS | Low (kernel probes) | No injection but **SIP limits** | One line per syscall | The macOS strace equivalent; needs SIP off + root | `sudo dtruss -t open ./bin` (refused with SIP on, verified locally) |
| `log stream` | System log/unified log | macOS | Very low | Zero | Structured log stream | Blue-team view of process behavior, SIP-free | `log stream --predicate 'process == "x"'` |
| DynamoRIO | Instruction level (DBI, started out-of-process) | Win/Linux (no mac) | Medium-high | No injection; swaps the code cache | Coverage/custom callbacks | The WinAFL coverage-guided base | `drrun -c winafl.dll -- target.exe` (see the win-vuln toolchain piece) |
| Triton | Instruction level + symbolic execution | All platforms (Python) | Very high | Emulated execution | Instruction streams+constraints+taint | Auto-solving inputs, algorithm restoration | `python -c 'from triton import *; ...'` (feeding instructions via ASTContext) |
| rr | Full syscall record + time-travel replay | Linux | 2~20x slower | gdb remote | Deterministic replay of a gdb session | "Crashes only once" race/non-deterministic bugs | `rr record ./bin && rr replay` |
| WinDbg TTD | Full instruction-level record/replay | Windows | High | Debugger | .trace files, bidirectional single-step | Malware-sample forensics, after-the-fact `!analyze` | `windbgx -TTD.exe`, see platforms 01 debugging |
| eBPF tracepoint/uprobe | Kernel functions/syscalls/user-space functions | Linux 4.x+ | Very low (kernel aggregation) | Zero injection, root | Aggregated stats/events | Global multi-process observation, blue-team monitoring, unpacking | `bpftrace -e 'uprobe:...:func { @[ubpfarg0] = count(); }'` (details in the area 07 eBPF piece) |
| r2 dts/ESIL | Debug trace sessions/offline emulation | All platforms | Emulation speed | Zero (never touches the real process) | Trace-session snapshots | Static execution flow when you'd rather not run the sample | `r2 -q -c 'dts+; 10 aes; dts' -d bin` (ESIL: `aei; aes`) |

Two notes (locally verified corrections):
- r2's `aht` is **not** a trace command - in 6.2.4 it is a type hint that "marks an immediate as a struct offset"; r2's trace surfaces are `dts` (debug trace session), `aes` (single-step), and ESIL `ae*` (emulated execution).
- QBDI and frida Stalker have **no inheritance relationship**: QBDI is a standalone DBI engine (stable 0.12.1); via the frida-qbdi binding, QBDI's JS API can be loaded into a frida session (its JS `QBDI` class corresponds to the C++ `VM` class) - the combo of "frida manages injection, QBDI manages tracing"; for pure instruction-level tracing the community reports it faster than Stalker.

---

## 2. Function level: frida-trace in practice (verified locally)

### 2.1 Three environment traps (macOS)

| Trap | Symptom | Fix |
|----|------|-----|
| No permission on the cache dir | `error creating directory ~/.cache/frida/...: Permission denied` | `export XDG_CACHE_HOME=/tmp/xdgcache` |
| SIP platform binaries | spawning `/bin/ls` fails with `unable to access process with pid ... from the current user account` | Use a non-platform binary (self-compiled/venv python); everything under `/bin/*`, `/usr/bin/*` is SIP-shielded |
| No log lines in spawn mode | See sec.2.3 | Switch to attach mode |

### 2.2 Attach mode (the standard posture, clean output)

Start a loop-that-opens-files process yourself, then attach:

```bash
python3 -c "
import time,os
print('READY', flush=True)
while True:
    open('/etc/hosts').read(); os.stat('/tmp'); time.sleep(0.5)
" &
frida-trace -p <pid> -i open -i stat64
```

Locally verified output (essentials):

```
Instrumenting...
open: Loaded handler at "/private/tmp/ft-ls/__handlers__/libsystem_kernel.dylib/open.js"
stat64: Loaded handler at ...
           /* TID 0x103 */
   137 ms  open(path="/etc/hosts", oflag=0x1000000, ...)
   138 ms  stat64(path="/tmp", buf=0x16d4e2050)
   643 ms  open(path="/etc/hosts", oflag=0x1000000, ...)
   ...
```

What to read: relative milliseconds (timing), TID (thread attribution), auto-decoded arguments (path read straight out as a string). One js file per function in the handlers directory; the template:

```js
defineHandler({
  onEnter(log, args, state) {
    log(`open(path="${args[0].readUtf8String()}", oflag=${args[1]}, ...)`);
  },
  onLeave(log, retval, state) {}
});
```

Add `onLeave(log, retval){ log('ret=' + retval) }` to the handler to backfill return values - **hot edits take effect**, which is frida-trace's edge over strace: you define the argument semantics yourself.

### 2.3 The spawn-mode trap (verified locally, important)

On macOS, frida 17.23.3's spawn mode (`frida-trace -f`) spawns/injects/auto-generates handlers correctly and the process runs to completion, but **not a single call-log line appears** (tried with both the v8/qjs runtimes; zero lines even with the process running 4 seconds while continuously opening). Attach mode works flawlessly. Verdict: **on macOS, do function-level tracing as "self-started process + attach"; don't gamble on spawn**.

### 2.4 Wildcards and module scoping

- `-i open`: exact/wildcard name match across any module's exports (`-i 'stat*'` verifiably hits stat64/statfs64/statvfs/statx_np/stat_with_subsystem and 7 others).
- `-I libsystem_kernel.dylib`: **every function of the whole module** - locally this generated 100+ handlers and drowned the log in Auto-generated floods; use sparingly when triaging; the correct posture is precise `-i` names, or the combination `-I module -i name`.
- For Android targets, function-level tracing has three more layers: `-j javaMethodName` (the Java layer), `-I libnative-*.so -i Java_exportName` (the JNI layer), and the OC layer's `-i "*[Cls method:]"` wildcard; Java/JNI/OC hook details live in the area 02 pieces and are not repeated here.

### 2.5 The three questions for reading function-level traces

1. **Timing** (the ms column): intervals between two calls ~ polling periods; bursts within the same ms ~ a loop body/initialization.
2. **Threads** (the TID column): cross-thread alternation means worker/handler threads exist; split by TID before digging deeper.
3. **Argument semantics**: the default template decodes only the first argument; socket fds/struct pointers need hand-edited handlers (read `args[1]`, `hexdump(args[0], 32)`) - frida-trace's core increment over strace: strace only knows the fd, you can follow the fd pointer down to the object.

---

## 3. Block level: Stalker in practice (verified locally)

### 3.1 The three big macOS traps (the order you hit them is the triage order)

1. **Everything is dead during the spawn suspension**: scripts loaded during the suspension never fire `recv()` callbacks after resume, and following produces no events; switching to "Popen starts the process -> sleep 0.4s -> attach -> load (do the follow at load time)" makes everything work.
2. **Thread selection**: on macOS `Process.enumerateThreads()` returns only the main thread, and tid != pid (locally always small numbers like 259); `[0].id` is the main thread; but **don't follow the agent's own thread** - following the wrong thread shows up as 0 events + all JS timers dead.
3. **exclude fails for shared-cache modules**: after `Stalker.exclude({base,size})`-ing 348 dylibs, libsystem_kernel events still arrive (the dyld shared-cache address range doesn't match). **JS-side `findModuleByAddress` filtering is the final backstop**.

One more event-parsing detail: `Stalker.parse(blob, {annotate:true})` must be run with annotate, or e[0] is an address instead of the `'call'/'block'` type name.

### 3.2 The reusable driver (scripts/stalker_trace.py)

```bash
# Collect call+block events, keep the main module only, cap at 3,000 events, and write JSONL
python3 scripts/stalker_trace.py --target $(which python3) --args workload.py \
    --events call,block --limit 3000 --exclude-all-but-main --filter-main --out ev.jsonl
```

For the already-running self-installed test APK on the explicitly selected
phone (run from the skill root, with the recorded serial and PID):

```bash
tools-env/.venv/bin/python techniques/13-trace/scripts/stalker_trace.py --device-serial "$RE_DEVICE_SERIAL" --pid "$RE_TEST_PID" --events block --limit 3000 --wait 8 --out android-blocks.jsonl
```

Exercise the test APK's selected workload during capture; the device mode attaches
to the recorded PID and does not launch the application.

Add `--thread-id <verified-tid>` when tracing a specific worker. The driver checks
that the selected TID belongs to the attached process and refuses the agent's own
thread. With `--events block --limit N`, **N caps received block events before
module filtering**, not guaranteed JSONL rows or unique blocks; filters, timeout,
and an early process exit may yield fewer rows. Mixed `call,block` mode counts both
event types toward the same cap. Cleanup stops only this script's selected trace,
unloads its script, and detaches its session; the attached APK remains running.
These are implemented transport/thread checks, not a claim of real-device success.

The script's three volume-control switches (the 3 key parameters of the task):

| Parameter | Where | Effect | Measured result |
|------|------|------|---------|
| Module exclusion | `Stalker.exclude({base,size})` xN | Don't recompile these ranges; prevents event explosion | 348 dylibs excluded; partially ineffective for shared-cache modules -> add the JS filterMain on top |
| Event switches | `events:{call,ret,block,exec,compile}` | Each granularity step differs by an order of magnitude | call/block mixed, 3000 events filled in 16ms; exec has the same delivery rate but bloats the target worse |
| Queue buffering | `queueCapacity`/`queueDrainInterval` | Event buffer size and flush interval | The delivery pipeline tops out at ~65k events/second measured, see sec.5.1 |

Locally verified capture output:

```
[cfg] {"excluded": 348, "keep": "Python"}
[cfg] {"tid": 259, "module": "Python", "base": "0x102260000", "events": ["call","block"], "limit": 3000}
[done] seen=3000 elapsed=16ms
    2747  block
     309  Python!0x187eb4      ← 块热点 top1
     253  call
     104  Python!0x187ee4
     ...
{"type": "block", "at": "Python!0x245cfc"}
{"type": "call", "from": "Python!0x245d04", "to": "Python!0x1c9a10", "depth": -2}
{"type": "block", "at": "Python!0x245d08"}
```

### 3.3 The symbolization loop (atos)

`Mod!off` is just an offset; on macOS, batch-resolve with atos (verified locally, hot addresses -> nearest exported symbols):

```bash
atos -o /path/Python -l 0x0 0x3e9d4 0x256b64 0x25263c
# PyMapping_GetOptionalItem / _io_TextIOWrapper_read / textiowrapper_dealloc ...
```

The loop's hotspot chain reads at a glance: `the read call chain -> TextIOWrapper_read -> the object dealloc crowd` - exactly the CPython machinery of `open().read()`. Tracing without symbolizing = tracing for nothing.

---

## 4. Call-chain extraction: call events -> tree (verified locally)

`scripts/calltree.py` reads stalker_trace.py's JSONL, maintains the call stack via relative depth values, and aggregates into a tree + hotspots + dedup rate:

```bash
python3 scripts/calltree.py ev.jsonl --top 8 --children 2
```

Output essentials for 100k call events (verified locally):

```
== 调用树 ==
|- Python!0xc39a8 x99988            ← PyObject_GenericGetAttr
|  |- Python!0x256b64 x99981        ← _io_TextIOWrapper_read
|  |  `- Python!0x25263c x99980
|  |     `- Python!0x120650 x99979
|  |        |- Python!0x7fcc0 x99971
|  |        |  |- Python!0x241f74 x99967
== 热点目标 ==
   31244  Python!0x3e9d4            ← PyMapping_GetOptionalItem
== 去重统计 ==
  call 事件总数: 100000
  唯一 from->to 边: 31 (去重率 100.0%)
  唯一目标符号: 27
```

**Key reading: a loop-shaped workload produces only 31 unique edges from 100k events** - trace data explodes along the "time-dimension repetition" axis; the first cut of post-processing is always `(from,to) dedup + frequency`: no information lost, volume collapses to zero.

---

## 5. syscall level: what to do on macOS (verified locally)

### 5.1 The native macOS routes

| Route | Status (verified locally) | Verdict |
|------|----------------|------|
| dtruss | `dtrace: system integrity protection is on` + `DTrace requires additional privileges` | No chance with SIP on; needs recovery-mode `csrutil disable` + root, at system-wide cost |
| dtrace scripts | Same as above; only unsigned processes + root partially usable | Don't gamble on a production machine |
| `log stream` | Works; filter with `--predicate 'process=="x"'` | The zero-cost backstop; watch the system-log surface |
| strace/ltrace | Don't exist | Linux-only |

### 5.2 Simulating syscall tracing with frida Interceptor (the usable equivalent)

macOS syscalls are forwarded through libsystem_kernel.dylib's exported functions (user space has almost no bare `svc` to hook - the syscall instruction lives in the shared cache where it can't be hooked), so **Interceptor on that export family = user-space strace**. `scripts/syscall_sim.py` (verified locally, 32 functions hooked):

```
[ready] hooked 32 functions in libsystem_kernel
open           "/etc/hosts"                    ret=3
read           fd=3                            ret=213     ← 字节数
close          fd=3                            ret=0
stat64         "/tmp"                          ret=0
getcwd         ""                              ret=1757872128
access         "/etc/hosts"                   ret=0
write          fd=1                            ret=8       ← 正是 "W2_DONE\n" 8 字节
```

Extend coverage by adding to the `fam` table as needed (openat/fstatat64/posix_spawn/mmap/connect...); fd-type and path-type argument decoding are already split in the script (mind that fstat*'s first arg is an fd - don't let the stat regex swallow it). Equivalence with strace: you see the same layer of information (paths, return values, timing); the difference is you only see libsystem's forwarding surface, not the kernel-side failure details (errno-grade semantics need you to read retval yourself).
API reminder: frida 17 dropped the two-argument `Module.findExportByName(mod, name)`; use `Module.findGlobalExportByName(name)`.

### 5.3 Measured volume-control numbers (burn these in)

| Experiment (the same 8-second busy-loop workload) | Number |
|------|------|
| No-attach baseline | 475687 opens |
| Stalker call+block following throughout | 320607 opens -> **1.48x slowdown**; 458747 events written (~57k events/second) |
| Time to fill 100k events (A no filter/B exclude+filter/C block-only) | 1524/1522/1521ms - **the host-side delivery pipeline hard-tops at ~65k events/second**; filtering saves disk, not time |
| exec events (full instruction level) | Same delivery rate; the target-side bloat is worse; 380k lines flushed in 6 seconds |

Corollaries: (1) to go fast, cut **event production** (exclude/filter/event switches) - don't count on the backend; (2) for long runs, always `--limit` + JSONL to disk; accumulating in memory will blow up; (3) keep your eyes on exactly two metrics, "events/second" and "target slowdown ratio".

### 5.4 The strace family cheat sheet (Linux, memorize by contrast)

| Posture | Command | Use |
|------|------|------|
| Surface only | `strace -f -e trace=openat,connect,execve ./bin` | The IOC triple: files/network/execution |
| Statistical summary | `strace -c ./bin` | Per-syscall counts + time ranking; see the distribution before tracing in detail |
| fd -> path restoration | `strace -yy ./bin` | fd=3 displays as `/etc/hosts</etc/hosts>` |
| Following children | `-f` (follows fork/vfork/clone) | The standard posture when a sample drops a loader |
| String decoding | `-s 4096` | The default truncates at 32 bytes; read payloads need more |
| Network payloads | `-e trace=network -xx` | Hex dumps of send/recv buffers (for judging the ciphertext surface) |

The macOS equivalent of each row: surface = syscall_sim.py's fam table; statistics = post-hoc defaultdict; fd restoration = read the `/dev/fd/N` link in onLeave or keep your own fd table (a 20-line addition to the script).

---

## 6. Post-processing methodology

1. **Filtering** (do it at the source):
   - By module: when exclude fails, use the JS filterMain (sec.3.1 trap 3);
   - By thread: follow only the main thread; run business threads in another round;
   - By depth/frequency: truncate tree display with `--depth-max`, `--children` (built into calltree.py).
2. **Aggregation**:
   - Dedup: the `(from,to)` edge set - loop workloads reach a 100% dedup rate (sec.4, measured);
   - Hotspots: top-N block/target-address frequencies (stalker_trace.py's done packet spits out the top 15 directly);
   - Symbolization: offline atos / addr2line in batches; never inside event callbacks.
3. **Offline analysis**: once the event JSONL is on disk it's ordinary data - `grep '"type": "call"'`, python defaultdict aggregation, import into a spreadsheet for distributions; for big files, grepping the `Mod!off` prefix is the coarse filter.
4. **The three volume-control axes** (by payoff): event switches (call over block over exec) > a limit cap + early unfollow > module filtering.
5. **Coverage mode** (no replay; just the deduped block set): `events:{compile:true}` records only the blocks Stalker **compiled** (each block arrives once - naturally deduped), an order of magnitude below block events; ideal for fuzz coverage guidance / the execution-surface inventory after unpacking; step up to exec only when you need instruction-level coverage.

---

## 6.5 The trace tools' own detection surface (adversarial scenarios)

When the traced target carries anti-debugging, pick the layer by first asking "who gets seen" (the full detection-surface matrix is in [../04-evasion/detection-landscape.md](../04-evasion/detection-landscape.md); bypasses once your hook gets killed go through [../12-bypass/bypass-playbook.md](../12-bypass/bypass-playbook.md)):

| Tool | Detectable tells | Stealth ranking |
|------|-----------|-----------|
| The ptrace family (strace/ltrace/gdb) | Target's own `ptrace(PTRACE_TRACEME)` failing, `/proc/self/status` TracerPid | Worst; any anti-debugging sample detonates |
| frida injection (trace/Stalker) | Scans for thread names/mapping names frida-agent, gum memory segments, task thread counts | Medium; mitigable with a renamed gadget (the area 04 confrontation piece) |
| QBDI (via frida) | Same as the frida injection surface | Medium |
| DynamoRIO | Code-cache segments (no frida tells, but non-image executable segments exist) | Medium |
| dtrace/eBPF | Kernel-side observation, zero in-process traces; but needs root/kernel privileges | Best (that's why the eBPF unpacking piece chose it) |
| rr/TTD | Debugger semantics, same family as ptrace but configurable against detection | Poor~medium |

One sentence: **the harder the target hits, the deeper into the kernel layer trace goes**; in-process DBI (frida/QBDI/DR) is for the forensics phase after "the target can't touch you" or "the confrontation is already won".

---

## 7. Scenario decision tree

```
Who calls X, or what are X's arguments? --------> function level: frida-trace attach / Interceptor (Section 2)
Full execution flow, coverage, or flow changes? -> start with Stalker call+block (Section 3) and its three volume limits
Instruction level, with less overhead than Stalker? -> QBDI, a parallel engine within a Frida session (Section 1 table)
Syscall/resource-access surface or IOCs? -------> Linux: strace/eBPF; macOS: syscall_sim.py (Section 5)
System-wide multiprocess observation, no injection? -> eBPF tracepoint/uprobe, ../07-kernel/android-kernel-ebpf.md
Record/replay or a bug that crashes only once? --> Linux: rr; Windows: WinDbg TTD in ../../platforms/01-windows/
Recover flow without running the sample? ------> r2 ESIL emulation / Triton symbolic execution (Section 1 table)
Explore inputs automatically with fuzzing? ----> DBI engine: DynamoRIO + WinAFL, Windows vulnerability toolchain
```

Layer-drop discipline: every address/path/call-site obtained at one layer becomes the **anchor** for the next layer's finer trace (frida-trace locates the function first, then Stalker that single function); whole-process full-instruction Stalker is the last resort.

A layer-drop walkthrough (the locally tested path): frida-trace spots high-frequency opens -> Stalker call events aggregate 100k calls down to 31 unique edges -> the hotspot `_io_TextIOWrapper_read` -> atos symbolization -> the next round, an `Interceptor.attach` conditional breakpoint on that one function (args/return/call stack). **Each layer's output is the next layer's filter** - that is the engineering essence of trace.

---

## 8. Cross-links to the existing pieces

| To go deeper | Open which piece |
|--------|--------|
| Stalker assembly-level principles/transform/putCallout/hang triage | [02-frida/advanced/stalker.md](../02-frida/advanced/stalker.md) |
| The full-chain observation-point matrix (what to attach at each of L1-L5) | [observation-matrix.md](../11-syscall-chain/observation-matrix.md) and [process-memory-chain.md](../11-syscall-chain/process-memory-chain.md) sec.6 |
| eBPF tracepoint/uprobe/bpftrace hands-on | [android-kernel-ebpf.md](../07-kernel/android-kernel-ebpf.md) |
| eBPF unpacking (Stalker's injection-free stand-in) | [ebpf-unpacking-deep.md](../03-unpacking/ebpf-unpacking-deep.md) |
| WinDbg TTD/the Windows debugging system | [../../platforms/01-windows/debugging.md](../../platforms/01-windows/debugging.md) sec.5 |
| DynamoRIO/WinAFL coverage-guided fuzzing | [../../platforms/01-windows/win-vuln/toolchain-setup.md](../../platforms/01-windows/win-vuln/toolchain-setup.md) sec.3.1 |
| Emulated execution (unidbg environment-filling) | [../05-toolbox/emulation-frameworks.md](../05-toolbox/emulation-frameworks.md) |
| Linux platform details (the rr/strace ecosystem) | [../../platforms/03-linux/linux-security.md](../../platforms/03-linux/linux-security.md) |

## This piece's script inventory (scripts/)

| Script | Use | Test status |
|------|------|---------|
| stalker_trace.py | The Stalker capture driver: spawn-trap avoidance + the three volume-control parameters + hotspot stats | Verified locally |
| calltree.py | call events -> call tree/hotspots/dedup rate | Verified locally |
| syscall_sim.py | Interceptor on libsystem_kernel simulating strace | Verified locally (32 functions) |

## 9. Boundaries and errata

- "Verified locally" = 2026-10-16, macOS arm64 (darwin 25.6.0, SIP on) + frida 17.23.3. Spawn mode producing no log lines and Stalker being dead during the spawn suspension are **version behaviors, not protocol** - after changing frida version/OS, re-run the minimal cases of sec.2.3 and sec.3.1 first.
- rr, DynamoRIO, Triton, WinDbg TTD, strace are not installed/not applicable on macOS locally; their table behavior is generic knowledge - defer to their official docs; rr needs Linux + specific CPU features (ring-buffer recording); TTD is Windows-only.
- QBDI status: standalone DBI, stable 0.12.1, AArch64 since 0.10.0, loaded into a frida session via the frida-qbdi binding; "faster than Stalker" is community tracers' report - workloads vary widely; self-test on your critical paths.
- r2's `aht` is a type-hint command, not trace (6.2.4 help text verified); r2's trace surfaces are `dts`/`aes`/ESIL `ae*`.
- dtruss is hopeless with SIP on - don't touch csrutil on a production machine; for the syscall surface use the sec.5.2 user-space equivalent.
