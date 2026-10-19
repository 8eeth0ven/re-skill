# Multi-Approach Race Example: Five Equivalent Ways to Hook the Target Process's open (All Field-Tested)

> Methodology demo: **for the same target, first propose multiple equivalent approaches -> actually run them all under the same harness -> pick the winner by measured results**.
> The core of never entering a dead end is not "always choosing right", but "having a next lane when wrong, and switching lanes on data, not feelings".
> Test date: 2026-10-16. All probe values follow `../../test-values.md`: `[RE]` prefix / `/tmp/re_probe_*.txt` / magic value `0x52455052` ("REPR") / `REPROBE-20261016-NNN`.

## 0. Environment Snapshot and Task Definition

| Item | Value |
|----|----|
| OS | macOS 26.6.2 (25G83), arm64 |
| frida | 17.23.3 (Python side at `~/re-skill/tools-env/.venv/bin/`) |
| Target | `/opt/homebrew/opt/python@3.13/bin/python3` (the real Mach-O that pyenv's `which python3` resolves to; the `/usr/bin/python3` bundle build hangs - dropped) |
| Target behavior | Loops 14 times: `os.open("/tmp/re_probe_target.txt")` -> write `REPROBE-20261016-NNN`+`0x52455052` -> sleep 1s |
| Task | Observe/take over/block the target's open of the probe file - five equivalent techniques in a race |

Target script (`/tmp/re_race_20261016/re_target.py`, shared by all five approaches):

```python
import os, time
PROBE = "/tmp/re_probe_target.txt"
MAGIC = 0x52455052  # "REPR"
for n in range(1, 15):
    try:
        fd = os.open(PROBE, os.O_RDWR | os.O_CREAT, 0o644)
        os.pwrite(fd, ("REPROBE-20261016-%03d" % n).encode() + MAGIC.to_bytes(4, "big"), 0)
        os.close(fd)
        print("[TARGET] iter %02d ok fd=%d" % (n, fd), flush=True)
    except OSError as e:
        print("[TARGET] iter %02d open FAILED errno=%s" % (n, e), flush=True)  # after S5's patch, it lands here
    time.sleep(1)
```

## 1. Groundwork Before the Race: The Attribution Triple (each step saved the five approaches later)

A race is not five shots fired blind. First spend three cheap attributions to get the ground-truth data:

### 1.1 API-drift pitfall: frida 17 removed `Module.findExportByName`

The old form `Module.findExportByName(null, "open")` throws `TypeError: not a function` outright on 17.23.3.
Measured new name: **`Module.findGlobalExportByName("open")`** -> `0x18f6438b0` (libsystem_kernel.dylib).

### 1.2 Channel pitfall: spawn+resume kills the agent on this machine; attach-to-running is fully stable

Conventional wisdom says "macOS attach to someone else's process is denied -> spawn your own child". Measured on this machine, **it's reversed**:

| Channel | Measured |
|------|------|
| `device.spawn()` -> attach -> load -> `device.resume()` | The agent **dies silently** after resume: timers stop, hook callbacks send nothing, RPC reports `script has been destroyed`, session `process-terminated` (crash=None); occasionally the target dies too |
| `subprocess.Popen` starts the target -> sleep 1.2s -> `device.attach(pid)` | **5/5 stable**: timers tick normally, hook messages all flow |

> Lesson: known-pitfall lists are a "starting hypothesis", not "local fact". The channel itself must first be verified cheaply - this is the race mindset's first application, at the harness layer.
> Side effect: attaching 1.2s late misses the first 2~3 open rounds; each approach records this honestly (no impact on conclusions - the target runs 14 rounds).

### 1.3 Traffic groundwork: which layer does the probe's open actually go through (don't guess - hook and count)

Hook all four layers - `open` / `openat` / `fopen` / `open_nocancel` - run 10s and count:

```
[RE] DIAG 已挂 open @ 0x18f6438b0
[RE] DIAG open_nocancel -> 无此导出符号
[RE] DIAG 已挂 openat @ 0x18f6541bc
[RE] DIAG 已挂 fopen @ 0x18f5196e0
[RE] DIAG 计数 open(total=10, probe=10) | openat(total=0, probe=0) | fopen(total=0, probe=0)
```

**Conclusion: CPython's `os.open` traffic goes 100% through the `open` symbol; `openat`/`fopen` are empty lanes.** This one data point decided S3's fate and S1's win.

## 2. The Race Comparison Table (overview)

| Approach | One line | Result | Invasiveness | Overhead | Fitting scenarios | This round's rank |
|------|--------|------|--------|------|----------|----------|
| **S1 Interceptor.attach** | Insert callbacks at entry/exit, watch without changing | (PASS) 10/10 hits, call sites symbolized to `Python!os_open` | Low (trampoline, ~5-instruction level) | Very low (one callback per open) | Default first choice: observing args/return values/call stacks | **1** |
| **S2 Interceptor.replace** | Swap the whole implementation, manually forward to the original | (PASS) 10/10 takeovers, target fully unaware after forwarding | High (every caller passes through my NativeCallback) | Low (one JS boundary + one forwarding call) | When you must change args/return values/short-circuit logic | **2** |
| **S3 Equivalent-function substitution** | open awkward to hook -> switch to the openat/fopen equivalent layer | (FAIL) Empty lanes for this target: openat/fopen traffic=0 (`open_nocancel` has no symbol) | Low | Low (but hooked in vain) | Only meaningful when the target uses stdio (fopen) or statically links openat; **verify traffic before switching lanes (Section 1.3)** | 4 (methodological value above the score) |
| **S4 Stalker call-site interception** | Don't touch the function; trace the instruction stream and filter for open's address | (PASS) 6/6 precise hits (must use the exec-entry method; the call-target method misses everything due to stub trampolining) | **Zero** (zero modification of the target function, no trampoline) | High: 96101 exec events in a 6s window, fully parsed | Function under anti-hook watch / reconstructing the full call chain / one-shot forensics | 3 |
| **S5 Entry patch (ret rework)** | Edit machine code directly: `mov x0,#-1; ret` - permanent failure | (PASS) The patch window's 7 FAILED rounds map precisely; triple verification via byte read-back + behavior + filesystem; recoverable | **Highest** (process-global effect - even frida's own opens break) | Very low (2 instructions) | When behavior must change "physically" (circuit-breaking/whitelisting); must keep a backup and stay rollback-able | 5 (this task was observation, not blocking - hence last; if the task were "make open fail forever" it would be first outright) |

> The ranking is **task-bound**: this problem wanted "observe the probe file being opened" - S1 wins outright. Change the task to "block" and S5 is first; change it to "evade anti-hook detection" and S4 is first. The race table re-ranks every round; there is no permanent champion.

## 3. Per-Approach Field Records (commands + real output + pitfalls)

The common runner (`/tmp/re_race_20261016/run.py`, the Popen+attach route, Section 1.2):

```python
import datetime, subprocess, sys, time, frida

REALPY = "/opt/homebrew/opt/python@3.13/bin/python3"

def ts(): return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

agent_src = open(sys.argv[1]).read()
t0 = time.time()
proc = subprocess.Popen([REALPY, "/tmp/re_race_20261016/re_target.py"],
                        stdout=sys.stdout, stderr=sys.stderr)
time.sleep(1.2)                       # wait for the target to enter its loop, dodging python's startup phase
session = frida.get_local_device().attach(proc.pid)
script = session.create_script(agent_src)
script.on("message", lambda m, d: print("[%s] %s" % (ts(), m.get("payload") or m), flush=True))
script.load()
proc.wait(timeout=60)
```

### S1 Interceptor.attach - This Round's Champion

```javascript
const openAddr = Module.findGlobalExportByName("open");   // frida 17's new name!
let hits = 0, others = 0;
Interceptor.attach(openAddr, {
  onEnter(args) {
    const p = args[0].readCString();
    if (p && p.indexOf("/tmp/re_probe_") === 0) {
      hits++;
      if (hits <= 3) send('[RE] S1 命中#' + hits + ' open("' + p + '", flags=0x' +
        (args[1].toInt32() >>> 0).toString(16) + ") 调用点=" +
        DebugSymbol.fromAddress(this.returnAddress).toString());
    } else others++;
  }
});
setInterval(() => send("[RE] S1 累计: 探针命中=" + hits + " 非探针 open=" + others), 5000);
```

Measured output (excerpt):

```
[RE] S1 open @ 0x18f6438b0 (libsystem_kernel.dylib)
[RE] S1 命中#1 open("/tmp/re_probe_target.txt", flags=0x1000202) 调用点=0x1017f57d8 Python!os_open
[RE] S1 命中#2 ... 调用点=0x1017f57d8 Python!os_open
[RE] S1 累计: 探针命中=10 非探针 open=0
=== S1 finished, target rc=0, total 14.1s ===
```

- Every success criterion met: path read out, flags=`0x1000202` (O_RDWR|O_CREAT|O_CLOEXEC), **the return address symbolizes directly to `Python!os_open`** (caller attribution for free).
- Pitfalls: (1) `findExportByName` is gone (Section 1.1); (2) filter high-frequency functions by prefix or you drown in output.

### S2 Interceptor.replace - Semantic-Takeover Verification

```javascript
const openAddr = Module.findGlobalExportByName("open");
const origOpen = new NativeFunction(openAddr, "int", ["pointer", "int", "int"]);
let seen = 0;
Interceptor.replace(openAddr, new NativeCallback(function (path, flags, mode) {
  const p = path.readCString();
  const isProbe = p && p.indexOf("/tmp/re_probe_") === 0;
  const fd = origOpen(path, flags, mode);      // manual forward to the original implementation
  if (isProbe && ++seen <= 3) send('[RE] S2 接管 open("' + p + '") 转发原实现 -> fd=' + fd);
  return fd;
}, "int", ["pointer", "int", "int"]));
```

Measured output (excerpt):

```
[RE] S2 已整体替换 open,语义=原样转发;靶子应无感知地继续写探针文件
[RE] S2 接管 open("/tmp/re_probe_target.txt") 转发原实现 -> fd=3 (第1次)
[TARGET] iter 03 ok fd=3 ...        ← target fully unaware throughout, 14/14 rounds normal
[RE] S2 累计接管探针 open 次数=10
```

- Verification point: after replacement, **all** opens pass through our hands; forwarding to the original leaves behavior unchanged (target rc=0, probe file written as usual).
- Pitfalls: for variadic functions (`open(path, oflag, ...)`), the NativeCallback signature must be declared with the **maximum argument count** (3) - omitting `mode` plants a mine for O_CREAT scenarios; forgetting to forward wrecks the target entirely - the invasiveness is on you.

### S3 Equivalent-Function Substitution - An Empty Lane Is Also a Result

Scenario assumption: open's entry is under anti-debug watch / the symbol is unavailable - switch to equivalent functions for observation. All three equivalent lanes hooked (`openat`/`fopen`/`open_nocancel`), open itself untouched:

```
[RE] S3 已挂等价道 openat @ 0x18f6541bc
[RE] S3 已挂等价道 fopen @ 0x18f5196e0
[RE] S3 open_nocancel 无导出符号,跳过
[RE] S3 等价道计数 openat(total=0, probe=0) | fopen(total=0, probe=0)
[TARGET] iter 03~14 全 ok(探针照开,等价道全程没看见)
```

- **The defeat is data, not posture**: CPython's `os.open` lands directly on the `open` symbol (Section 1.3); the equivalent lanes physically carry no traffic.
- The highest methodological value of the lot: **"equivalent function" != "equivalent traffic"**. Before switching lanes, hook and count for 10 seconds (Section 1.3) - don't bet traffic on posture.
- When S3 would be the right lane: the target uses C stdio (traffic only at the `fopen` layer - many C/C++ clients), Linux static musl (go/rust static binaries largely go through `openat`), or upper-layer wrappers (ObjC `NSFileHandle`, Swift `FileHandle`).

### S4 Stalker Call-Site Interception - Zero Invasiveness, but Two Deep Pits

The v1 call-target filter **missed everything** (the target made 6 opens, 0 hits). Attribution (T4/T5):

```
[RE] T4 call总数=1230 ... open精确地址 0x18f6438b0 计数=0   ← the open address simply isn't among the call events
[RE] T5 exec总数=48055 | open 内指令执行=42 样例@0x18f6438b0,0x18f6438b4   ← open is clearly executing
[RE] T5 call总数=1097 | target==open 的 call=0
```

**Root cause: between os_open and open sits a stub (BL stub -> `br x16` -> open); the call event's target is the stub's address, not open itself.** The correct posture is the **exec-entry method**: open's first instruction being executed == one call to open, and the "location of the most recent call event" correlates out the effective call site:

```javascript
const openAddr = Module.findGlobalExportByName("open");
const tid = Process.enumerateThreads()[0].id;          // the main thread runs the loop
let openEntryHits = 0, execTotal = 0, lastCallLoc = null;
Stalker.follow(tid, {
  events: { call: true, exec: true },
  onReceive(events) {
    const parsed = Stalker.parse(events, { stringify: false });  // pitfall: annotate:false strips the type tags!
    for (const ev of parsed) {
      if (ev[0] === "call") lastCallLoc = ev[1];
      else if (ev[0] === "exec") {
        const loc = ev[1];
        if (loc.compare(openAddr) >= 0 && loc.compare(openAddr.add(4)) < 0) {
          openEntryHits++;   // an entry-instruction hit == one open call
          ...
        }
      }
    }
  },
});
setTimeout(() => { Stalker.unfollow(tid); Stalker.flush(); /* report */ }, 6000);
```

Measured output (v2):

```
[RE] S4 结果: 6 秒窗口 exec 事件=96101, call 事件=2203
[RE] S4 open 入口指令执行次数=6 (每次==一次 open 调用)     ← exactly 6 probe opens in the window, precise correspondence
[RE] S4 调用点关联采样: 入口#1 前序call点=0x104ee97d4 Python!os_open
[RE] S4 结论: 未碰 open 一个字节(无 trampoline),纯旁路指令流 trace 确认探针 open
```

- Pitfall 1: `Stalker.parse(..., {annotate:false})` strips the event-type tags, `ev[0]` becomes a pointer, and `ev[0]==='call'` is forever false -> a silent 0 hits (the nastiest bug class: no error, just nothing).
- Pitfall 2: stub trampolining defeats call-target filtering (above).
- Pitfall 3: unfollowing mid-run and immediately re-following the same thread once drove the target to `rc=-4` (SIGILL); for re-windowing, prefer one follow with staged statistics.
- Overhead: 6s collected 96101 exec + 2203 call events, all parsed on the JS side - three orders of magnitude heavier than S1, but it buys "zero modification of the target function".

### S5 Entry Patch (ret Rework) - Byte-Level Ground Truth

Goal: write `mov x0,#-1; ret` (`0x92800000` + `0xd65f03c0`) at open's entry - permanent failure; restore after 9.5s. All three API pitfalls stepped on: v1's `Arm64Writer.putBytes` doesn't exist, v2's `putInstruction` doesn't either - **in frida 17, `Memory.patchCode`'s callback argument is a "writable code pointer" (NativePointer-family methods), so just `writeU32`**:

```javascript
const openAddr = Module.findGlobalExportByName("open");
const hex8 = p => Array.from(new Uint8Array(p.readByteArray(8)))
  .map(b => ("0" + b.toString(16)).slice(-2)).join(" ");
send("[RE] S5 原始 8 字节: " + hex8(openAddr) + " (首指令 pacibsp)");

setTimeout(() => {
  Memory.patchCode(openAddr, 8, function (code) {      // code is a writable code pointer, not a writer
    code.writeU32(0x92800000);                         // mov x0, #-1
    code.add(4).writeU32(0xd65f03c0);                  // ret
  });
  send("[RE] S5 patch 后字节回读: " + hex8(openAddr));  // ground-truth verification
}, 2500);

setTimeout(() => {                                     // restore at 9.5s
  Memory.patchCode(openAddr, 8, function (code) {
    code.writeU32(0xd503237f);                         // pacibsp (the original first instruction)
    code.add(4).writeU32(0xd10103ff);                  // sub sp,sp,#0x40 (the original second instruction)
  });
  send("[RE] S5 恢复后字节回读: " + hex8(openAddr));
}, 9500);
```

Measured output (v3, full success):

```
[RE] S5 原始 8 字节: 7f 23 03 d5 ff 03 01 d1 (首指令 pacibsp)
[RE] S5 patch 前全新探针 -> fd=3 errno=0 (期望 fd>=0)
[RE] S5 patch 后字节回读: 00 00 80 92 c0 03 5f d6     ← shared-cache page COW write succeeded, bytes match exactly
[RE] S5 patch 后全新探针 -> fd=-1 errno=0 (期望 fd=-1)
[TARGET] iter 06 open FAILED errno=[Errno 60] Operation timed out: '/tmp/re_probe_target.txt'
[TARGET] iter 07~12 同上 FAILED                        ← patch window 2.5~9.5s, exactly 7 rounds, seam-perfect
[RE] S5 恢复后字节回读: 7f 23 03 d5 ff 03 01 d1        ← original bytes restored
[RE] S5 恢复后全新探针 -> fd=4 errno=0 (期望 fd>=0)
[TARGET] iter 13 ok fd=5 / iter 14 ok                  ← behavior restored
```

- Forensic detail: three probe calls produced only two files - `re_probe_s5_1.txt` and `re_probe_s5_3.txt` - **`re_probe_s5_2.txt` does not exist**; the open inside the patch window never actually created a file. Independent filesystem-level corroboration that the patch took effect.
- Pitfall 1 (behavioral): after patching to "always -1 + ret", **errno stops updating**; python reported the stale errno 60 (ETIMEDOUT) - the caller seeing "file open timed out" is pure misdirection. For cleanliness, patch an errno-setting sequence like `mov x0,#-1; mov w20,#ENOENT...`, or accept the noise.
- Pitfall 2 (local sandbox): the agent re-opening an **already existing** probe file with `O_RDWR|O_CREAT` gets EACCES (errno=13), while fresh files are fine - always verify with brand-new filenames, lest sandbox noise get misread as patch effect (v1 was nearly fooled by exactly this: the patch had failed yet fd=-1).
- Pitfall 3 (verification discipline): **a patch must be verified by byte read-back**. In v1/v2 the patchCode callbacks threw and the patch never landed; judging by return values/behavior alone would have concluded the opposite.
- Aside: open's original first instruction is `pacibsp` (arm64e PAC) - the shared cache is arm64e; Interceptor can tame PAC, but a manual patch replaces the whole thing and restores the original bytes verbatim - don't dream of "partial preservation".

## 4. Cross-Comparison and the Verdict

**For this task (observe who/how the probe file gets opened), the winner: S1 Interceptor.attach.**

Reasoning chain: the traffic is on the `open` symbol (Section 1.3) -> the symbol is hookable with no detection resistance -> S1 grabs every observation field (path/flags/fd/symbolized call site) at the lowest invasiveness and overhead. S2 in an "observe-only" scenario is a sledgehammer on a nut; S3 is an empty lane; S4/S5 observe fine but their cost/invasiveness is disproportionate.

**Which lane to switch to when (the dead-end switch table, embryonic):**

| Dead-end signal | Switch action | This round's measured basis |
|------------|----------|--------------|
| Attaching to someone else's process denied | Switch to spawning your own child; **spawn+resume also dies (agent silent) -> degrade again to Popen+attach** | Section 1.2: spawn channel agent dies; Popen+attach 5/5 |
| `Module.findExportByName` reports not a function | Switch to `Module.findGlobalExportByName` (frida 17+) | Section 1.1 measured |
| Hook attached but zero hits | First hook and count traffic (multiple equivalent layers hooked together, 10s) before touching posture; if the traffic isn't there, switch layers (S3's lesson) | openat/fopen=0, open=10/10 |
| Function under anti-hook watch (trampoline scanned) | attach->replace->**equivalent-function layer->Stalker (zero trampoline)**->patch | S4: zero target-function modification, still got 6/6 |
| Only want behavior change, observation itself optional | Patch the entry directly (permanent-fail/whitelist trampoline), keep the original bytes + rollback | S5: 7 FAILED rounds mapping precisely to the window |
| Behavior "unchanged" or "changed" after a patch | **Always byte read-back**, trust no single signal; use brand-new probe filenames to dodge sandbox EACCES noise | v1's false-positive near-miss; Section S5 pitfalls 2/3 |
| Stalker call-target filter all zeros | A stub/tail call sits in between; switch to the exec-entry method (entry-instruction execution == one call) | T4/T5 attribution data |
| Filtering stays false after `Stalker.parse` | `annotate:false` stripped the type tags - drop that option | S4 pitfall 1 |
| `__error` reads errno as garbage | It's a function `int*(void)`; wrap it in a `NativeFunction`, call, then dereference | T6 |

## 5. Retrospective: The Structural Value of This Race Itself

1. **All five approaches shared the same target and the same runner** - the only variable is the technique, so the results are comparable. If the harness has pitfalls, fix the harness first (Section 1.2); don't let channel noise pollute the scoring.
2. **Two approaches "failed/degraded" yet both produced**: S3's empty lane contributed the "equivalent != equal traffic" ground data; S4's v1 failure forced out the stub-trampolining attribution - worth more than a smooth pass.
3. **Every "success" carries at least two independent pieces of evidence**: S5 has byte read-back + behavior + file-absence; S4 has exact window-count correspondence + call-site symbolization. A single signal (especially a return value) will lie to you (v1's fd=-1).
4. Rankings are bound to task semantics; a new task re-ranks: observation->S1; changing args/returns->S2; evading detection->S4; hard blocking->S5.

## 6. Cleanup (test-value spec Section III)

```
$ ls /tmp/re_probe_* → (probe files all cleared)
$ ps aux | grep re_target → (no leftover processes)
```

Scripts and full logs archived at: `/tmp/re_race_20261016/` (s1~s5.log + the attribution _t series + diag.log). Re-run:
`cd /tmp/re_race_20261016 && XDG_CACHE_HOME=./cache ../../../../../../.zcode/skills/re/tools-env/.venv/bin/python run.py s1_attach.js S1`
(Note: the XDG_CACHE_HOME redirect exists because the default `~/.cache/frida` is unwritable inside the sandbox.)
