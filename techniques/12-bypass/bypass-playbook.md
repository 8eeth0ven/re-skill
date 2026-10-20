# Bypass Playbook: One Detection Point → Which Routes Remain → Which Route When

> Positioning: **the decision-convergence piece for confrontation work**. Areas 04 (detection principles / evasion), 09 (fallbacks), 07 (kernel), and 11 (observation points) cover "what it is and how to do it"; this piece answers exactly one question — **when a function gets detected during testing and one approach fails, which routes remain and which one matters most right now**.
> How to use: on failure, open the two decision trees in §1 first to set the overall direction, then look up the bypass matrix in the matching detection-point subsection of §2; see §3 when resource-constrained, §4 for priority calls, and §5 to work backward from symptoms.
> References (all real paths; details not repeated here):
> [detection-landscape.md](../04-evasion/detection-landscape.md), [frida-anti-detection.md](../04-evasion/frida-anti-detection.md), [root-env-hiding.md](../04-evasion/root-env-hiding.md), [rasp-bypass.md](../04-evasion/rasp-bypass.md), [hook-fallback-playbook.md](../09-function-map/hook-fallback-playbook.md), [kernel-hook-stealth.md](../07-kernel/kernel-hook-stealth.md), [observation-matrix.md](../11-syscall-chain/observation-matrix.md)
> The 2025–2026 community-popular route of "blocking detection-so loading / thread creation" (libmsaoaidsec class) is tagged [idea · community-popular].

## 1. Opening: Two Iron-Law Decision Trees

In any confrontation failure, first split into two cases: **"my hook never took effect" vs. "a detection hit"**. The former goes to Tree 1, the latter to Tree 2. Symptoms often blur together (a crash can be either the hook being killed or a detection hit), so first separate the two with the three steps in §1.0, then enter the trees.

### 1.0 Spend Three Minutes on Triage First

1. **Did any `console.log` from the frida script ever appear**: if yes → the hook did work at some point, check Tree 2 (detection hit); if no → the hook never executed, check Tree 1 (hook killed).
2. **Strip all hooks and keep only attach**: if the app survives → the hook behavior/signature is what gets detected; if it still dies → the mere existence of frida is detected (port/maps/thread names), go straight to §2.1/§2.2.
3. **Watch the timing of death**: dies the instant you attach = early svc detection + suicide (rasp-bypass.md symptom C); dies after a few seconds = periodic watchdog; only garbles data after running full business flows = key-grade self-destruction (rasp-bypass.md §2.3, go offline).

### Tree 1: Hook Killed (function never reached / crash right after hooking)

```
hook has no effect, or dies as soon as it lands
│
├─ Cause of death D "timing": detection code runs before the hook (init_array/JNI_OnLoad wins the race)
│    Evidence: spawn passes but attach does not; or the hooked function never appears in call logs
│    → Way out: switch startup mode to grab the timing first (zygisk > spawn > gadget > attach;
│      timing-line evidence in area 11 process-memory-chain.md, injection-timing section);
│      detections inside init_array must be intercepted before load (observation-matrix row 17)
│
├─ Cause of death A "hook detected": inline-hook byte changes caught by CRC, frida runtime signatures scanned
│    Evidence: still dies even when hooking your own so/libc exports; logs show reads of maps/own code sections
│    → Way out 1: go stealth (change port / strongR / soinfo unlink, see the matching §2 subsection)
│    → Way out 2: switch to a layer that modifies no bytes — Stalker / hardware breakpoints / wxshadow shadow pages
│      (area 09 hook-fallback-playbook.md §4 strength table rows L4/L5)
│    → Way out 3: give up hooking this function and patch the so to physically remove it (§2.12)
│
├─ Cause of death B "function copied / statically compiled": the target so bundles its own libc/boringssl,
│    hooking system libc exports does nothing (the executing body is not the one you hooked at all)
│    Evidence: findExportByName finds no symbol; or the symbol exists but post-hook argument logs never match the business
│    → Way out: locate the real executing body inside the so and hook by address — signature scanning
│      (BoringSSL strings / AESE byte patterns, area 09 case 5) / string-xref locating
│      (rasp-bypass.md §2.1 five-step backtrace method)
│
└─ Cause of death C "direct syscall": the target goes through inline svc assembly; no user-mode function boundary to intercept
     Evidence: memory-scanning the so shows the 01 00 00 D4 + movz x8 prologue
     (area 09 hook-fallback-playbook.md §3.3 scan script); strace sees it, frida hook does not
     → Way out 1: Stalker catches svc and rewrites registers (short window, area 09 §3.2)
     → Way out 2: intercept sys_openat etc. from kernel mode (KPM/eBPF, area 07)
     → Way out 3: patch the so to NOP the detection function (once the detection function is physically gone, svc no longer matters)
```

**Tree 1 iron law: determine the cause of death before acting**. The ways out for the four causes are not interchangeable — for a timing problem, switching to a stealthier hook is useless (it is still too late); for static compilation, switching to Stalker is useless (the function is perfectly fine in user mode, it just is not the one you thought); for direct syscalls, switching hook targets is even more useless. Five methods for layer determination (area 09 hook-fallback-playbook.md §1).

### Tree 2: Detection Hit (app popup / silent flagging / crash)

```
detection hit
│
├─ Step 1: locate the detection layer (decides the minimum viable bypass)
│    Written in Java (PackageManager/System.getProperty/isDebuggerConnected)
│      → Java layer; frida Java.use passes in seconds
│    Calls libc from a so (fopen/strstr/opendir)
│      → Native layer; Interceptor on libc exports can pass
│    Inline svc + hand-assembled syscall number (x8=56 openat etc.)
│      → all user-mode hooks fail; only three roads remain: Stalker / patch so / kernel mode
│    Kernel layer (another root observer / cloud-real-device side)
│      → device-level problem; swap devices or fight in the kernel
│    Full table of layer-determination criteria: detection-landscape.md §0
│
├─ Step 2: pick the play based on the feedback style
│    Crash / popup = hard detection: locatable (backtrace the kill/exit call chain); blocking it wins
│    Silent flagging / data corruption = soft detection: black-box diffing (same request on two devices),
│      run rasp-bypass.md §0 symptom triage A/B/C/D first
│
└─ Step 3: when multiple detections stack, order by "survive first → work next → stay stealthy last" (§4.3)
```

**Tree 2 iron law: the bypass layer must be ≥ the detection layer, otherwise everything is void**. When detection sits at the svc layer, no matter how beautifully you hook libc open/strstr it scores zero hits — the detection code never passes through the functions you hooked. This is the most expensive mistake in confrontation work: endlessly tuning a bypass that sits below the detection layer. Before every bypass switch, ask one question: "does the detection code actually pass through the path I am intercepting, or not?"

### 1.1 One-Screen Recap (the whole playbook)

```
hook killed   → Tree 1, determine cause of death: timing A (pre-empt) / detection A (switch to a traceless layer) / copy B (locate the real body) / direct-call C (Stalker|patch|kernel)
detection hit → Tree 2, determine layer: Java < JNI < libc < svc < kernel < key binding
                 bypass layer must be ≥ detection layer; symptoms unchanged no matter the tuning = layer misjudged
resource ceiling: no root (gadget/patch) < root (Shamiko/Stalker/feed-original-apk) < kernel (KPM/wxshadow) < offline (derivation/unidbg)
stacking order:  keep the process alive first → keep functionality next → stay stealthy last
stop-loss line:  same method unchanged twice / all green but garbled / user mode all dead without kernel → switch route (§4.4)
```

## 2. Detection-Point Bypass Matrix (main body)

Uniform template: 3 lines of detection principle | bypass-matrix table | recommended order and why. In the tables, "cost": ★ = minutes, ★★ = hours, ★★★ = days, ★★★★ = research grade.

### 2.1 frida-server Port Scanning

**Detection principle**: `connect` probes 127.0.0.1:27042/27043, or scans 27000-27100; the nastier variant sends no packets at all and reads `/proc/net/tcp` (the kernel socket table) directly, searching for `HEX:69A2`. At the protocol layer there is also the D-Bus handshake signature whose reply carries the string `frida`. Full principle in detection-landscape.md §2.1.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Change port `-l 0.0.0.0:random` | port scan comes up empty | detection only connect()s known ports | detection switches to reading the full /proc/net/tcp table or scanning all ports | ★ |
| Rename frida-server + change port | ps/cmdline walks also come up empty | stacked with process-name detection | maps/thread-name detection remains | ★ |
| strongR-frida prebuilt | signature strings fully replaced | quickly obtain a de-signatured build | version lags; deep in-memory signatures not necessarily all clean | ★ |
| gadget mode (embedded in APK) | no TCP listener, no server process | port/process-name scans always come up empty | requires repackaging; the gadget signature still shows in maps (pair with §2.2) | ★★ |
| Zygisk-Frida | injection at zygote fork time, no standalone server | rooted environment + the server form factor is targeted | memory/thread signatures remain | ★★★ |
| eBPF rewrites /proc/net/tcp reads | kernel-side laundering of the socket-table output | root+GKI, detection goes through the net/tcp table | heavy engineering; usually not worth it for this single point | ★★★★ |

**Recommended order**: change port + rename → strongR → gadget/Zygisk. Why: port/process-name is the outermost detection; spend one minute ruling it out first so you can confirm whether the cause of death sits in a deeper layer — "changing the port is an entry ticket, not a get-out-of-jail card" (frida-anti-detection.md §1.1). If it still dies after the change, jump to §2.2/§2.3 immediately; do not keep grinding on the port.

### 2.2 /proc/maps Scanning for frida-agent

**Detection principle**: fopen/fgets walks line by line with strstr for `frida-agent`/`re.frida.server`/`gadget`; the advanced version does not search the file name but "anonymous executable mappings that are rwxp with offset=0" — name-independent, so renaming cannot fool it. The Java-layer equivalent is a BufferedReader over maps. Full principle in detection-landscape.md §2.2.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| hook read/fgets to launder the buffer | what the detection reads is laundered maps | detection goes through libc (evidence: detection goes silent after the hook) | zero hits when svc directly calls openat+read (area 09 case 1) | ★★ |
| Redirect openat to a forged file | swap the fd whenever the path matches maps | detection cross-reads multiple /proc files; packaged as one framework | caught when fstat's inode/size do not match | ★★ |
| soinfo unlinking | dlsym/dl_iterate_phdr no longer emit frida | detection works the symbol layer, not the file layer | offsets change per Android version; timing must land right after attach completes | ★★ |
| gadget renamed and embedded | the line in maps is a normal so name | detection searches file-name strings | the rwxp-anonymous-segment detection still kills it (name-independent) | ★★ |
| Injection that never lands in maps (Zygisk/kload) | injection method changes, no mapping left behind | maps scans always come up empty (no frida mapping) | in-memory content signatures remain (§2.4) | ★★★ |
| KPM hide-maps | kernel filters /proc/<pid>/maps output | root+APatch, mkv-steam-tier adversaries | memory scanning / dl_iterate_phdr / solist still need the so to hide itself | ★★★★ |

**Recommended order**: hook read to launder the buffer (runnable code in area 09 case 1) → if svc defeats that, Stalker catches svc → if still unstable, switch to the gadget/Zygisk form factor. Why: laundering the buffer leaves the injection form untouched with the fewest side effects; "changing the loading method" is the structural fix — once and for all, but one cost tier higher. Criterion: if memory-scanning the so shows the svc prologue (01 00 00 D4), skip libc hooks outright.

### 2.3 Thread-Name Enumeration (gmain/gum-js-loop/gdbus/pool-frida)

**Detection principle**: opendir walks `/proc/self/task/<tid>/comm` reading each, or pthread_getname_np; a frida injection necessarily carries these four fixed comm names. Detection code in detection-landscape.md §2.4.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| hook getdents64 to erase directory entries | no frida threads in the enumeration results | detection goes through libc opendir/getdents64 (runnable code in area 09 case 6) | zero hits when svc directly calls getdents64 (x8=61) | ★★ |
| hook prctl(PR_SET_NAME) to rename | new threads' names never leak | only guards newly created threads | frida's own threads already exist; existing ones cannot be intercepted | ★ |
| strongR / self-build with renamed threads | change prgname at the source | when memory-string detection must also be passed | version lags; needs a controllable self-build | ★★ |
| [idea · community-popular] hook dlopen/pthread_create to block detection-module loading or watchdog-thread creation | the detection thread never comes up at all | shells of the libmsaoaidsec class where "detection runs in a thread" | not applicable when detection runs synchronously in init_array; blocking loads may take business sos down with it | ★★ |
| Kernel task hiding (KPM hideproc idea) | filtering at the /proc/<pid>/task output layer | root + kernel grade; even direct svc cannot escape | kernel-version adaptation | ★★★★ |

**Recommended order**: getdents64 entry-erasing + prctl renaming in tandem → block the detection thread if blockable → go kernel. Why: thread names are a "legacy stock" problem (changing prctl only covers new ones), so the main attack is filtering on the enumeration side; blocking the detection thread (acting at load time) is the cost-effective route the community validated in 2025-2026 — a detection thread that does not exist is more thorough than a detection thread that cannot read.

### 2.4 rwxp Anonymous-Segment Scanning (memory signatures)

**Detection principle**: parse maps to find "anonymous mappings with rwxp + offset=0" (frida-agent/gadget and most injection frameworks land via mmap RWX), then pread/dereference the suspicious segments to scan memory strings: `frida:rpc`, `LIBFRIDA`, `linjector-`, `FridaScriptEngine`, etc. (detection-landscape.md §2.2/§2.3). This detection is file-name independent; it only recognizes memory shape and content.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Self-build / strongR with all signature strings replaced | known strings unfindable in memory | memory-string scanning detection | the string list must be complete (miss one and you die); GType class names hide deep | ★★ |
| lief equal-length binary string patching | modify so/frida-server directly without compiling | no build environment available | length must be strictly equal, otherwise all addresses go wrong | ★★ |
| frida memory-layout adjustment (split RX/RW sections) | no monolithic rwxp block appears | detections that only check the permission shape, not the content | custom-agent engineering effort; requires frida internals knowledge | ★★★ |
| Switch injection form so the memory shape changes | embedded gadget / slim homegrown agent | detections sensitive to the rwxp shape | a homegrown agent must control its own signatures | ★★★ |
| wxshadow shadow pages (W^X) | execution flows through the shadow page; readers see the original page | the structural fix for "even reading sees nothing" | needs a KPM environment; if the detection scans for anonymous-segment existence rather than content, it may still hit | ★★★★ |
| Simply do not stay resident: patch so / offline emulation | nothing injected inside the process | the strongest memory scanning (page-by-page comparison) | gives up dynamic hooking capability | ★★★ |

**Recommended order**: strongR / self-build string replacement (detection searches content) → adjust memory layout (detection searches shape) → wxshadow / offline (the strongest tier). Why: first distinguish whether the detection searches "content strings" or "the rwxp shape" — for content, replacing strings is enough; for shape, the loading method must change. Discriminator: all signature strings changed yet it still dies with clean maps → shape detection; otherwise content detection.

### 2.5 strstr/strcmp Signature-String Comparison (the comparison functions the detection itself uses)

**Detection principle**: the detection code compares sensitive strings (frida/gum/su/xposed) with libc strstr/strcmp/memmem. Hooking these functions so the match always fails is the most common bypass, but **this road is completely dead when the detection side calls libc directly (statically compiled) or svc-izes it** (Tree 1 causes of death B/C).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Interceptor.replace strstr/strcmp/memmem | the match always fails | detection calls libc exports (ready-made code in frida-anti-detection.md §2.2) | the so is statically compiled with its own strstr; the comparison is inlined into instructions | ★ |
| Hook the verdict function instead of the comparison function | change the return value where the result is computed | comparison inlined but the verdict centralized (locate via the rasp-bypass.md §2.1 backtrace method) | when the verdict is scattered across many sites, patch each | ★★ |
| Stalker intercepts svc and post-processes | even direct calls are intercepted | svc-ized detection (area 09 §3.2) | heavy performance cost; open only in a short window on the detection thread | ★★★ |
| patch so to NOP the comparison logic | the comparison code is physically gone | string detection of any form | requires unpacking to locate + repackaging; may trigger signature verification (§2.9) | ★★★ |

**Recommended order**: replace strstr → unify the verdict function's return value → Stalker/patch. Why: replace takes one minute to verify "whether the detection goes through libc" — it is simultaneously a bypass and a probe; the failure information tells you directly whether the cause of death is B or C, faster than blind guessing. Unifying the verdict function's return value (one change covers the whole chain) beats hooking comparison functions one by one.

### 2.6 TracerPid (/proc/self/status)

**Detection principle**: native reads the `TracerPid:` line of `/proc/self/status`; anything non-zero means debugged (gdb/lldb/frida-IDA remote all count). The libc layer fopen/fgets can be intercepted; the advanced version reads directly via svc. Equivalent signals include `/proc/self/wchan`, a lowercase t in the state of column 3 of task/<tid>/stat, and waitpid error codes. RASP often cross-checks multiple files (detection-landscape.md §7.1).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| hook read/fgets to rewrite the buffer | the TracerPid read is always 0 | detection goes through libc (frida-anti-detection.md §2.3) | direct svc reads; cross-reads of wchan/stat missed | ★★ |
| openat redirected to a forged status | the whole file is fed fake data | multi-file cross-checking detection; packaged by one redirection framework | inode/size must be consistent across the board | ★★ |
| Self-attach pre-emption (ptrace yourself to hold the slot) | the tracer slot is already held; frida in turn cannot attach | the reverse use, for scenarios defending against IDA/gdb attaching | conflicts with frida; this is the detection side's own trick | ★ |
| spawn mode avoids attach traces | frida spawn injects in a non-ptrace form | first choice when using frida itself | gadget/zygisk likewise have no TracerPid surface | ★ |
| Kernel modifies the task structure / output layer | filtering at the source where status is generated | even direct svc reads cannot escape | KPM environment | ★★★★ |

**Recommended order**: first confirm your own injection form (spawn/gadget never produces TracerPid in the first place) → launder the buffer → at the svc layer switch to Stalker/kernel. Why: many "TracerPid detection" deaths are actually caused by something else (maps detection mixed in); under spawn mode TracerPid is 0 anyway — rule out the cheapest possibility first, "you were never traced at all".

### 2.7 Timing Detection (rdtsc/clock_gettime double-read delta)

**Detection principle**: take the time once before and once after a key computation; an abnormal delta indicates debugging/hooking. bionic clock_gettime prefers the vDSO function pointer; when the app/ART caches the pointer and calls it directly, hooking the libc export cannot intercept everything (area 09 case 4). Stalker itself slows execution and is also caught by this method.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Time compensation (forge the clock) | the return value's increment is always small; the double-read delta stays constant | delta exposure caused by hook/debugging overhead | detection cross-checks multiple clock sources (CLOCK_MONOTONIC vs REALTIME) | ★★ |
| Patch the __vdso_clock_gettime body | everything calling vDSO directly passes through here | detection calls vDSO directly (the scenario libc hooks cannot intercept) | the vDSO code page must be mprotect'ed open first | ★★ |
| Shrink the Stalker scope + exclude | lower overhead so the delta falls back within threshold | caught by timing detection because Stalker slowed things down | insufficient when the detection threshold is extremely sensitive | ★★ |
| Switch to zero-overhead observation (uprobe/perf_event) | the observation itself does not slow execution | when you only need to watch, not modify | unusable when return values must be changed | ★★★ |
| Kernel time skew (KPM) | shift time globally from the kernel side | the last resort when user mode is completely dead | affects everything; research grade | ★★★★ |

**Recommended order**: time compensation + vDSO patch in tandem → switch to uprobe observation → kernel. Why: what timing detection detects is "the overhead your presence causes"; merely intercepting the read is useless (intercepting makes the delta even weirder) — the return value itself must look un-debugged; compensation fixes the root. Criterion: kprobe hits on sys_clock_gettime mean the app is calling directly (the normal path never lands in svc; observation-matrix row 29).

### 2.8 ptrace Detection (self-attach slot-holding / PR_SET_DUMPABLE)

**Detection principle**: the detection side forks a child that calls `ptrace(PTRACE_TRACEME)` and attaches to itself to hold the tracer slot, making your attach fail (Operation not permitted); or prctl(PR_SET_DUMPABLE,0) blocks non-same-uid debugging. Principle in detection-landscape.md §1.1.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| hook ptrace to fail TRACEME/ATTACH | the self-attach pre-emption fails; the tracer slot stays free | detection calls ptrace at the libc layer (code in frida-anti-detection.md §2.3) | svc calls ptrace directly (x8=117) | ★ |
| hook fork and kill the guard child process | the slot-holder no longer exists | child-process slot-holding type | the detection side has multiple watchdogs taking turns holding the slot | ★★ |
| root and SIGKILL the guard process outright | same as above, handled at the system layer | root available and the guard is identifiable | new watchdogs respawn | ★ |
| gadget/Zygisk injection (no ptrace used) | the injection form never goes through ptrace at all | the form-factor fix when attach is slot-blocked | other detection surfaces remain | ★★★ |
| Kernel ptrace hiding | interception at the sys_ptrace layer | direct svc + heavy confrontation | KPM environment | ★★★★ |

**Recommended order**: hook ptrace → kill the guard → switch injection form. Why: hooking ptrace doubles as a probe (logs show who calls it and how often); "switching the injection form" appears again — it is the structural fix for ptrace-class detection: if ptrace is never used, ptrace cannot be detected. This is also why the area 11 timing chain ranks zygisk ahead of attach.

### 2.9 Signature Verification (APK repackaging detection)

**Detection principle**: the Java layer uses PackageManager.GET_SIGNATURES to compare against a hardcoded signature hash; the native layer reads the base.apk mapping from `/proc/self/maps` and computes the hash itself, bypassing Java hooks; RASP-grade uses the signature as an input to key derivation (detection-landscape.md §3.6, rasp-bypass.md §2.3).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| PMS proxy hook on getPackageInfo | the Java layer returns the original signature | detection sits in the Java layer (ready-made code in the signature-forgery section of 02-frida/java-layer/storage-and-system.md) | native computes the hash itself, bypassing Java | ★ |
| [freeRASP method] openat/read/fstat feeding the original package | what native reads is always the untampered APK | native computes the hash itself | libc hooks fail once svc-ized; mapping range/ino/mtime must all match | ★★★ |
| Repackage + V2 signing | sign with your own key if the detection only verifies "a signature exists" | detection only checks signature presence, not the hash | dies against hardcoded-hash comparison | ★★ |
| Dynamic patching without touching disk | no repackaging at all; the signature is unchanged | any patching need should be done dynamically first | see the CRC risk in §2.12 | ★★ |
| Offline key derivation | crack the encrypted artifacts directly without running the app | RASP with signature-bound keys (DexProtector type, rasp-bypass.md §2.3) | high algorithm-analysis cost; but one derivation covers the whole version | ★★★★ |

**Recommended order**: dynamic patching first (triggers no signature problem) → feed the original package when repackaging is unavoidable → go offline for signature-bound keys. Why: the essence of fighting signature verification is "never let it read the evidence of tampering" — dynamically modifying memory leaves no file evidence, the cheapest structural evasion; feeding the original package is the universal fallback framework — one openat/read/fstat redirection set solves several file-class detections (maps/status/net/tcp) at once.

### 2.10 root Detection (su files / mounts / props / package names)

**Detection principle**: four stacked layers — access walking su paths, /proc/mounts scanned for magisk/overlay, __system_property_get querying ro.debuggable/test-keys, PackageManager enumerating magisk/xposed package names. Once svc-ized, all user-mode hooks fail. Principle in detection-landscape.md §3.

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Shamiko (blacklist/whitelist mode) | unmount + trace-wiping at the instant of zygote fork; the app sees an unrooted world | most finance/risk-control apps (root-env-hiding.md §1.4) | mounts-topology statistical detection (a 2025 dedicated topic already exists); residual props surface | ★ |
| HideMyApplist (HMA) | hooks PackageManager to filter package names | Java-layer package-name enumeration | cannot block the pm command path (Runtime.exec); cannot block native directory scans | ★ |
| resetprop / MHPC | change props in the memory view + full fingerprint replacement | props-blacklist-type detection | ro.boot.* comes from cmdline; resetprop cannot change the real thing | ★ |
| KernelSU + ZygiskNext | no su binary in user mode / no magiskd / no overlay | stubborn cases where Magisk has been "sentenced to death" | kernel adaptation cost | ★★ |
| APatch + KPM (kernel grade) | root in kernel mode; smallest detection surface + a hide stack can be layered on | finance-grade detection stacks, svc-ized root detection | research-to-engineering-grade threshold | ★★★★ |
| Environment cleanup: switch to an unrooted test device + gadget | no root at all; injection goes through repackaging | no kernel resources and the detection is too brutal | must be redone for every target app | ★★ |

**Recommended order** (same source as root-env-hiding.md §5.2): clean the environment layer first (Magisk + Shamiko whitelist + HMA + resetprop; KSU is even better if available) → reduce injection-layer signatures → then beat the packer and pinning. Why: **with a dirty environment, no matter how fancy your injection tools are, they will not survive the first screen** — root detection is usually the first detection to run; once it hits, you never even get the chance to locate the other detection points. This is the primary landing spot of the "keep the process alive first" principle.

### 2.11 VPN / Proxy Detection

**Detection principle**: the Java layer uses System.getProperty("http.proxyHost") + ProxySelector; VPN via NetworkCapabilities containing TRANSPORT_VPN or NetworkInterface showing tun0/ppp0; native can ioctl(SIOCGIFCONF) to ask the kernel directly. tun0 detection is harder to bypass than proxy detection — forging the whole network-interface enumeration chain is heavy engineering (detection-landscape.md §5.1).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| hook System.getProperty / ProxySelector | the Java layer reports no proxy | the scenario of a capture tool setting a system proxy | native reads environment variables / ioctl | ★ |
| iptables transparent proxy (REDIRECT) | no system proxy variables set; traffic silently redirected | both tun0 and proxy are detected | iptables rules must pair with certificate deployment (capture-all-scenarios.md proxy-detection section) | ★★ |
| Physical NIC relay (router / MITM AP) | forwarding at the device level; zero traces on the phone | the strongest VPN/proxy detection (interface enumeration comes up clean however you check) | extra hardware needed; the certificate problem must be solved separately | ★★ |
| Offline protocol restoration | if you cannot capture, stop decrypting; restore the algorithm and replay offline | when capturing is only the means and the algorithm is the goal | gives up the convenience of live capture | ★★★ |
| [idea · kernel] eBPF rewrites interface-enumeration output | launder tun0 at the ioctl/getifaddrs layer | root + kernel, native detection | heavy engineering | ★★★★ |

**Recommended order**: hook the Java layer → iptables transparent proxy → physical NIC / offline. Why: the decision variable on this line is "what do you actually want" — if it is plaintext traffic, iptables is enough; for long-running unattended analysis, the physical NIC is the only traceless option; when the real goal is the algorithm, stop grinding on capture and take the area 10 offline route directly.

### 2.12 Integrity Checking (prologue CRC / inline-hook detection)

**Detection principle**: at startup, hash/CRC the first N bytes of key function prologues and store them, then recompute periodically; a mismatch = inline hooked. Or judge the instruction pattern directly (arm64 `ldr x17` signature 0x58000051, x86 0xE9). RASP-grade is not limited to its own so nor to the PLT — libc functions, the linker's rtld_db_dlactivity, and libart entry points are all checked; some even feed the machine code into key derivation (detection-landscape.md §2.6/§7.2).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Stalker in place of Interceptor | original instructions untouched; execution is translated and run | CRC detection confirmed (frida-anti-detection.md §4.1) | slows execution → exposed by timing detection (§2.7); scope must be narrowed with exclude | ★★★ |
| Hardware breakpoints (perf_event/BRP) | breaks at an address without changing a single byte | dual CRC + timing detection | frida has no direct API; you must write your own; ptrace dependency | ★★★ |
| wxshadow shadow pages | breakpoints live only in the shadow physical page; read paths (GUP / /proc/mem) see the original page | the strongest CRC + GUP comparison (area 07 §2.3, verified on OnePlus A16) | KPM environment; residual timing side channel | ★★★★ |
| Patch the "expected verification value" (X23=X0 identity method) | the comparison is always true; the verified function is untouched | verification centralized in a "compute-value BL→CMP→B.NE" structure (rasp-bypass.md §2.1) | verification scattered; patching CMP but not B.NE (the else path leaks) | ★★ |
| Change the hook point: hook the GOT instead of the function head | the verified function body stays untouched | verification only checks function prologues, not the GOT table | fails when GOT entries themselves are compared | ★★ |
| Key-bound type: offline derivation | never executing it means it cannot corrode the keys | DexProtector type (key derivation includes code content) | gives up runtime hooking | ★★★★ |

**Recommended order**: patch the expected verification value → Stalker / hardware breakpoints → wxshadow; for the key-bound type go offline directly. Why: the essence of fighting CRC detection is "let the verification read the expected value" or "never modify bytes at all" — the former is a cheap one-site patch, the latter a structural solution. **Warning**: in the key-bound type (DexProtector), every place you patch may be a key input; the more you bypass, the worse it gets, with the symptom "all bypass points green but business data garbled" — rasp-bypass.md §4.1 line one; the moment you see it, stop runtime confrontation and go offline.

### 2.13 SELinux / props Detection

**Detection principle**: security_getenforce or reading /sys/fs/selinux/enforce (Permissive = weak signal); __system_property_get querying ro.debuggable/ro.secure/test-keys/verifiedbootstate; **when properties are read straight from shared memory (/dev/__properties__) there are zero syscalls**, and hooking the libc property functions is not even noticed (the special case in area 09 case 3).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| resetprop changes the runtime view | system properties live in a memory region; change the values directly | props-blacklist detection | detections that read ro.boot.* from /proc/cmdline (cannot change the real thing) | ★ |
| Stay Enforcing + magiskpolicy fine-grained allowances | SELinux state is normal; no Permissive signal triggered | your root scheme itself should never set SELinux permissive | none (this is proper posture, not a bypass) | ★ |
| Modify the prop_info shared memory directly | every read path (including self-parsing) sees the same memory | when the app self-parses the trie and hooking __system_property_get does not work (area 09 case 3 code) | layout offsets vary by version; dump and verify first; equal-length writes to avoid breaking the trie | ★★ |
| MHPC full fingerprint replacement | swap in a certified build fingerprint per device model | Play Integrity device-integrity blacklists | the fingerprint library needs maintenance | ★★ |
| KPM propedit (kernel writes user pages) | change properties from kernel mode | when user-mode changes will not stick | KPM environment | ★★★★ |

**Recommended order**: resetprop + Enforcing → direct shared-memory modification → kernel. Why: properties are one of the "big three never-landing-in-svc exceptions" (property reads / vDSO time / user-mode crypto) — L4/L5 kernel measures are N/A against it, so do not force the kernel at it (observation-matrix table-reading iron law 1); the correct fix for self-parsing detection is to change the data source (memory), not to intercept the read.

### 2.14 Self-Destruction / Crash Functions (exit/kill/key poisoning)

**Detection principle**: the "execution means" after a detection hit — System.exit/kill(getpid)/abort dies outright; RASP-grade is key poisoning (decrypts to garbage) or delayed reaction (recorded now, breaks only at a key operation). Intercepting exit/kill only treats the symptom: the detection has already decided, and killing the process is merely the execution (pitfall note in frida-anti-detection.md §2.2).

| Bypass | Principle | When applicable | Failure signature | Cost |
|---|---|---|---|---|
| Hook the verdict function and change its return value | make the detection rule "normal" at the source | centralized verdict (the case of unifying return values across 14 detection functions, rasp-bypass.md §2.1) | scattered verdicts; worse if changed in the key-bound type | ★★ |
| hook kill/exit/abort + backtrace | not a bypass but **locating**: backtrace who killed it | the first step of the diagnosis phase (frida-anti-detection.md phase 1) | even after blocking, normal business is not restored (data may already be flagged) | ★ |
| [community-popular] timing-pre-empting NOP: front-load your own patch before init_array | the detection code is neutralized before it runs | detection concentrated in init_array/JNI_OnLoad | requires static locating first; cannot out-pre-empt timings beyond zygisk | ★★★ |
| patch the so to eliminate the self-destruct/detection function | the function is physically gone | detection function already located; dynamic solutions unstable | repackaging triggers signature verification (handle together with §2.9) | ★★★ |
| Intercept the reporting channel + forge responses | detection results cannot go out / fake ones are sent | silent-flagging type (the freeRASP events domain, last line of rasp-bypass.md §4.1) | useless if the server already has a historical flag | ★★ |
| Key-poisoning type: switch to offline derivation | never executing it means no corrosion | symptom B (garbled / corrupted data) | see the warning in §2.12 | ★★★★ |

**Recommended order**: use the hook on kill/exit **as a probe** to backtrace and locate the verdict layer → change the verdict layer's return value → if still unstable, patch the so; for the key-poisoning type go offline immediately. Why: the core insight of this section is "the crash is the result, not the cause" — grinding on exit is the most common waste; a backtrace drags out the real culprit (the verdict function) in three minutes. Also note the distinction: crash = locatable hard detection (actually easier to handle); silent flagging = soft detection discoverable only by black-box diffing (§4.2).

## 3. Resource-Dimension Decisions (the optimal route for the same detection at different resource levels)

For the same detection point, the resources in hand decide which route is "currently feasible". Find your row first, then check the cost-tagged rows in the §2 matrices.

| Resource form | Ceiling of usable bypasses | Optimal per detection point at this resource level | Hard ceiling |
|---|---|---|---|
| **No root (bare device / cloud real device)** | Java hook / libc hook / repackaging | detection in the Java/libc layer: frida spawn passes directly; svc layer: patch so + repackage (gadget embedded); root detection: switch to a real device or an unrooted environment + gadget | svc + kernel-grade detection is basically unsolvable (except patch so); when ptrace-class is slot-blocked, only a form-factor switch remains |
| **Root, no kernel (plain Magisk)** | the above + environment hiding + Stalker + feeding the original package | root detection: Shamiko whitelist + HMA + resetprop; frida detection: strongR + laundering maps; svc detection: Stalker short window; signature: openat feeding the original package | key-bound RASP, page-by-page memory comparison; extremely timing-sensitive scenarios |
| **Root + kernel (APatch/KPM/KSU+LKM)** | the above + kernel-mode interception + traceless breakpoints | svc detection: KPM hook on the sys_openat return layer; CRC+GUP: wxshadow shadow pages; residual root surface: KSU naturally small surface + hideproc; strongest stack: the mkpms-stealth four-in-one (hide-maps + kload + wxshadow + dbc-rw) | timing side channel (the only universal residual surface); another root observer |
| **Pure static (never run the app)** | unpacking + decompile + patch | detection logic statically neutralized wholesale (patch CMP to identity); algorithms read directly (with area 10 pure-algorithm restoration); key derivation (DexProtector solved offline) | anti-dump packers must be unpacked first; VMP/white-box is a separate matter |
| **Offline emulation (unidbg etc.)** | emulate so execution; supply the environment yourself | detection functions inside the so: call the target function directly, bypassing every detection layer; risk-control algorithms restored offline (area 05 emulation-frameworks.md) | environment-stubbing cost; JNI/UI-heavy logic cannot be emulated |

Three resource decision laws:
1. **The fallback chain is one-way**: prefer user mode over kernel, dynamic over static, online over offline — each step down doubles the engineering cost while generality shrinks (an offline solution only works for this one app at this one version).
2. **Resources decide "which detection point to rule out first"**: without root, first confirm it is not root detection (30 seconds to verify by switching to an unrooted device); with kernel access, touch kernel measures last instead (save them for a true svc-grade adversary).
3. **Resources change which way out applies, not the cause of death**: Tree 1 cause of death C (direct syscall) leaves only "patch so" without root; with KPM it becomes a three-way choice. The cause of death does not change; the way out changes with resources — determine the cause of death first (Tree 1), then pick the way out by resources (this section).

## 4. The "What Matters Most When" Special

### 4.1 Three Criteria: Detection Layer / Trigger Timing / Feedback Style

**Criterion 1: detection layer** (Tree 2 iron law). The lower the detection layer (svc/kernel), the fewer usable bypasses and the higher each one's cost — so **lower-layer detection is always handled first**. When a confrontation has both a Java-layer root detection and an svc-layer maps detection, solve the svc one first: the Java layer is a one-minute job you can patch up anytime; the svc layer is the question of whether you get into the game at all.

**Criterion 2: trigger timing (startup vs. runtime)**.
- Startup detection (init_array/JNI_OnLoad/Application.onCreate): **you must get ahead of it** — timing is the line between life and death; if spawn is not enough, go gadget; if gadget is not enough, go zygisk (kernel evidence of timing ranking: area 11 process-memory-chain.md, injection-timing section). Startup detection that "passes once, passes forever" is even a bargain: one hook of the return value is valid for life.
- Runtime detection (periodic watchdog / re-checks before key operations): **must be continuously stable** — the focus shifts to "the hook must not be caught by timing detection" and "laundered data must be consistent"; heavy tools like Stalker need narrowed windows; when the detection thread is blockable (the §2.3 community route), physically blocking it takes priority.

**Criterion 3: feedback style (crash = locatable, silence = needs diffing)**.
- Crash / popup = hard detection: logs capture it and the call chain can be backtraced — **good news**. hook kill + backtrace locates it in three minutes.
- Silent flagging / key poisoning = soft detection: **black-box diffing is mandatory** — same request on two devices (one clean, one with tools) and compare response differences; run complete business flows instead of only the home screen (delayed-reaction types strike only at payment/decryption, rasp-bypass.md §7.3); retest after restart (to distinguish one-shot vs. periodic detection). Verification of a soft-detection bypass can only rely on behavioral diffing, never on "no popup".

### 4.2 The Detection Layer Decides the Minimum Viable Bypass (core-law quick table)

| Where the detection code lives | Minimum viable bypass | All effort below this layer is void |
|---|---|---|
| Java API | Java hook (`Java.use`) | — |
| JNI wrappers (RegisterNatives layer) | libart symbol hook / RegisterNatives observation | a Java hook may suffice (depends on the entry) but native is often needed |
| libc wrappers (fopen/strstr…) | Interceptor on libc exports | Java-layer hooks cannot intercept native calls |
| Direct svc (inline assembly) | Stalker rewrites instructions / patch so / kernel mode | **all user-mode function hooks (even libc)** |
| Kernel layer (another observer) | swap devices / kernel confrontation | everything user-mode |
| Key binding (top RASP tier) | offline derivation | **all runtime bypasses (the more you bypass, the worse)** |

The last two rows are money pits: tuning libc-hook parameters against svc-layer detection, or continuing to bypass detection in the key-bound case, are both "effort below the detection layer"; their signature is **symptoms unchanged no matter how you tune** — the moment this appears, go back to Tree 1/Tree 2 and re-determine the layer.

### 4.3 Stacked Detections: Keep the Process Alive → Then Keep Functionality → Then Stay Stealthy

Finance-app detection stacks are layered (packer shell + environment sweep + pinning + risk-control reporting, root-env-hiding.md §5.1). The processing order under stacking is not "bypass whichever is easiest first"; it is:
1. **Keep the process alive first** (phase 1, first block of the area 04 four-phase checklist): root environment + injection form pass, the app does not crash — otherwise nothing after matters. The main battlegrounds of this step are §2.10 root and §2.1/§2.2 frida form.
2. **Then keep functionality** (phases 2-3): attach succeeds, hooks land, both Java and native work, dumps come out — main battlegrounds are §2.8 ptrace, §2.12 CRC, and class-loader handling.
3. **Stay stealthy last** (phase 4 + residual risk-control surface): reporting channel intercepted, timing/behavior signatures narrowed, scripts minimized — main battlegrounds are §2.7 timing, §2.14 reporting, and the risk-control restraint of "passing ≠ traceless".

Why this order: failures of the three layers mask each other — when the process cannot even stay alive you observe nothing at the functionality layer; when functionality does not work, the best stealth has nothing left to hide. Doing it in reverse (polishing stealth first) is the most common spinning-in-place in confrontation work.

### 4.4 When to Cut Losses and Switch Routes

- The same bypass tuned twice with unchanged symptoms → the cause of death was misjudged; go back to §1.0 triage and re-judge (fallback-practice closing checklist item 1: confirm that what you fell back to is the layer actually in use).
- All bypass points green but business data garbled → key poisoning; stop runtime confrontation and go offline (§2.12 warning).
- All user-mode means dead (svc + CRC + page-by-page memory) with no kernel resources → downgrade expectations: static patch or unidbg; stop chasing "traceless dynamic".
- Cost inversion: engineering effort to bypass one detection point > switching devices/versions/offline emulation → switch paths. "Abandoning a path is also part of the expert's workflow."

## 5. Failure-Signal Quick Table

Symptom → most likely cause → next action. The first three columns cover 90% of scenarios; parentheses in the "action" column give the matching subsection.

| # | Symptom | Most likely cause | Next action |
|---|---|---|---|
| 1 | Process vanishes the instant you attach, no logs | early svc detection + immediate suicide | enter with spawn suspended / patch early init; confirm the detection layer (§1.0, rasp-bypass.md symptom C) |
| 2 | Still crashes after port + rename changes | not port/process-name detection; death is in a deeper layer | move to §2.2 maps / §2.3 thread names; hook kill and backtrace to locate |
| 3 | Hook works for a few seconds then gets killed | periodic watchdog rescanning (CRC/memory) | locate the detection thread (pthread_create logs); block the thread or use Stalker (§2.3/§2.12) |
| 4 | Hooked a libc function but zero hit logs | cause of death B (static compilation) or C (direct svc) | five layer-determination methods; memory-scan for the svc prologue (area 09 §3.3); switch to Stalker/signature scanning (§2.5) |
| 5 | Dies the moment Interceptor lands, lives without it | prologue-CRC detection caught the inline hook | switch to Stalker / hardware breakpoints / patch-the-expected-value (§2.12) |
| 6 | findExportByName returns null | custom dlsym trampoline / stripped symbols | search method-name strings in IDA; parse the trampoline table by hand (rasp-bypass.md §4.1) |
| 7 | All bypass points green but the app white-screens / garbles | key-grade self-destruction already triggered | stop runtime confrontation; derive keys offline (§2.12/§2.14) |
| 8 | Crashes after patch-and-repackage | APK signature verification (another integrity layer) | feed the original package (freeRASP method) or switch to dynamic patching off-disk (§2.9) |
| 9 | Java.perform cannot find the class | the detection class lives in the packer's ClassLoader | enumerateClassLoaders and switch to the shell's loader (frida-anti-detection.md §2.5) |
| 10 | Shamiko configured but root still detected | Enforce DenyList conflict / residual mounts surface | toggle off and watch the smiley; resetprop + MHPC; if still failing, KSU (§2.10, troubleshooting table in root-env-hiding.md §6) |
| 11 | App drops the moment the capture tool opens | proxy/VPN detection (tun0) | iptables transparent proxy / physical NIC (§2.11) |
| 12 | Time-related functions misbehave / kicked out | double-read delta timing detection | time compensation + vDSO patch (§2.7) |
| 13 | TracerPid patched but still killed | cross-reads of wchan/stat missed | a full /proc-file redirection framework (§2.6) |
| 14 | Behavioral diff between two devices (no popup) | silent flagging: the reporting channel is alive | intercept the reporting domain + forge responses (§2.14); check device-fingerprint consistency |
| 15 | SEGV_MAPERR while dumping DEX | anti-dump unmap (region cleared after decryption) | change the timing (the decryption instant); dump from the eBPF side (area 03) |
| 16 | App freezes with Stalker on / caught by timing detection | translation-execution overhead too large | narrow with exclude + short window + unfollow (area 09 §3.2 three performance laws) |
| 17 | Spawn passes but attach does not | timing cause of death D: detection runs before the hook | switch to spawn/gadget/zygisk to grab the timing (Tree 1 cause of death D) |
| 18 | frida itself crashes after the soinfo unlink | unlinked too early; lazy symbol resolution still needs the chain | do it immediately after attach completes (frida-anti-detection.md §2.4) |
| 19 | Kernel solution deployed but the app still senses | residual surface: timing side channel or root exposure (not the hook surface) | area 07 §8 red-team self-check list; tighten the environment layer further (§2.10) |
| 20 | Everything normal but the server blacklists | historical flags / behavioral fingerprint | change device fingerprint; restrain the testing rhythm (§4.3 third layer) |
| 21 | App functionality breaks after hooking pthread_create | business threads / the shell's worker threads intercepted by mistake | add a whitelist (allow by the start routine's owning module); intercept only the detection so's (§2.3) |
| 22 | strongR frida cannot connect / script errors | client and server versions mismatched | align major versions on both ends (version discipline in area 05 dynamic-hook-frameworks.md) |
| 23 | System misbehaves after changing props in shared memory | variable-length writes broke the trie layout | equal-length writes; dump and verify offsets before changing (§2.13, area 09 case 3) |
| 24 | Stalker catches svc but shows no hits | the target never called directly at all (cause misjudged) or it runs on another thread | re-verify with the five layer-determination methods; follow only the detection thread; confirm the scanned so scope is right (area 09 §3.3) |

**How to use the table**: find the row by symptom → execute the "next action" → the subsection the action points to holds the full matrix. If the symptom is absent from the table, go back to the §1.0 three-step triage and reclassify.

## 6. Relation to the Rest of the Library

- This piece is the decision convergence: detection-principle details are in area 04 detection-landscape.md, frida confrontation details in frida-anti-detection.md, fallback code in area 09 hook-fallback-playbook.md, kernel solutions in area 07 kernel-hook-stealth.md, and observation-point selection in area 11 observation-matrix.md.
- When revising this piece, cross-check in sync: whether the "recommended order" in each §2 matrix still matches the latest conclusions of areas 04/09/07; add rows to the §5 quick table as new pitfalls are hit.
- The two [idea · community-popular] tags (blocking detection-so loading / thread creation, and the init_array pre-emptive patch) come from 2025-2026 public hands-on post directions; app-specific offsets do not belong in this piece — verify them yourself when using.
