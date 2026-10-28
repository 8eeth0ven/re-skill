# Hook Fallback Playbook: Where to Go When the Upper Layer Gets Killed

> Companion to 《[android-function-layers.md](android-function-layers.md)》. Premise: first determine why the hook failed, then pick the fallback action — never fall back blindly.
> Code is primarily frida (JavaScript API), with eBPF/CLI as support; register conventions per arm64.
> All syscall numbers are arm64: x8 = call number, x0-x5 = arguments, return value in x0 (the kernel returns -errno; the libc wrapper converts it to errno).

## 1. Fallback Decision Tree: Diagnose First, Then Act

Four causes of hook failure, mapping to four classes of action:

```
Hook has no effect / gets countered
│
├─ A. The hook itself is detected (inline hook byte changes caught by CRC, GOT entries verified,
│     frida runtime fingerprints: port 27042 / gum thread names / re.frida.server in maps)
│     → Actions: go stealth (rename frida-server / change the port / inject via gadget)
│            + trace cleanup (read filtering for maps/status/task directories, see cases 1/6)
│            + if still caught by byte verification → change layer: give up on L3 inline,
│              switch to L2 exported-function hooks or L4 breakpoints
│
├─ B. The function was duplicated / carries its own implementation (the so statically links
│     libc/boringssl; Java wraps it in another shell method)
│     → Action: locate the real execution body (signatures/strings/call chains), hook the body (case 5)
│
├─ C. The target behavior never passes through your hooked layer (direct svc calls bypassing libc,
│     vDSO bypassing the syscall, property reads straight from shared memory bypassing libc functions)
│     → Action: pick the layer per special case —
│            direct svc → L4: Stalker catch svc / ptrace breakpoint / eBPF (cases 1/2/6)
│            vDSO time → patch the vDSO code or compensate the return value (case 4)
│            self-parsed properties → modify the shared memory directly (case 3)
│
└─ D. The hook works but its side effects give it away (time double-read delta, errno style mismatch,
      sudden thread/memory changes, return values inconsistent with system-side cross-checks)
      → Action: don't change layer; fix the side effects (compensate time, sync system-side state,
        remove the extra threads)
```

**Five ways to identify the layer** (quoted from the layers doc §0): inspect so dependencies / import tables / memory-scan for svc / Stalker statistics of the x8 distribution / root strace comparison. Run through them before falling back, to avoid wasting effort on a layer that isn't even being used.

## 2. Six Complete Fallback Cases

### Case 1: File detection — hooking Java File gets caught → libc openat → Stalker catch svc → eBPF

**Scenario**: the app detects root/debugging: reads `/proc/self/maps` to find frida, reads `/proc/self/status` for TracerPid, enumerates `/proc/self/task`.
**Upper-layer approach (L1, the most easily detected)**:

```js
Java.perform(() => {
  const File = Java.use("java.io.File");
  File.exists.implementation = function () { /* Filter sensitive paths */ };
});
```

**Why it gets killed**: Xposed/frida Java-layer traces (loaded hooks, anomalous call stacks, `exists` returning suspiciously slowly).
**Fallback 1 (L3: libc openat + read, content filtering)** — don't intercept "the open", intercept "what gets read":

```js
const openat = Module.findExportByName("libc.so", "openat");
const readf  = Module.findExportByName("libc.so", "read");
const hotFds = new Set();

Interceptor.attach(openat, {
  onEnter(args) { this.p = args[1].readCString(); },
  onLeave(retval) {
    if (this.p && /^\/proc\/(self|\d+)\/(maps|status|task)/.test(this.p))
      hotFds.add(retval.toInt32());
  }
});

Interceptor.attach(readf, {
  onEnter(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
  onLeave(retval) {
    const n = retval.toInt32();
    if (!hotFds.has(this.fd) || n <= 0) return;
    const s = this.buf.readUtf8String(n);
    const cleaned = s.split("\n")
      .filter(l => !/frida|gum|re\.frida|linjector|TracerPid:\s*[1-9]/.test(l))
      .join("\n");
    if (cleaned.length !== s.length) {
      this.buf.writeUtf8String(cleaned);   // Overwrite the original buffer
      retval.replace(cleaned.length);
    }
  }
});
```

Key points: track fds with a Set to avoid poisoning every read; only let TracerPid `0` through.
**Killed again**: the app's so is **statically linked + issues direct svc calls** to read maps (L3 sees nothing at all).
**Fallback 2 (L4: Stalker follows svc)**:

```js
function traceSyscalls(tid) {
  Stalker.follow(tid, {
    transform(iterator) {
      let insn;
      while ((insn = iterator.next()) !== null) {
        if (insn.mnemonic === "svc") iterator.putCallout(onSvc);
        iterator.keep();
      }
    }
  });
}
function onSvc(ctx) {
  const nr = ctx.x8.toInt32() & 0xffffffff;
  if (nr === 56) {                    // __NR_openat
    const path = ctx.x1.readCString(); // openat(dirfd, pathname, ...)
    if (/\/proc\/(self|\d+)\/(maps|status)/.test(path)) {
      console.log("[svc openat]", path, "from",
        Thread.backtrace(ctx).map(DebugSymbol.fromAddress).join("\n  "));
    }
  }
}
```

Stalker is expensive: use `Stalker.exclude` to shrink the followed range by excluding libc/system libraries, and only enable it on key threads/short windows.
**Fallback 3 (L5: eBPF, root)** — even direct calls cannot escape the audit:

```
# bpftrace: generally available on GKI kernels; verify the specific device
tracepoint:syscalls:sys_enter_openat /str(args->filename) =~ /proc/ {
  printf("%s(%d) %s\n", comm, pid, str(args->filename));
}
```

eBPF is read-only; after locating the direct-call site, return to user mode (e.g., frida attach at that address) to do the rewriting.

### Case 2: Port-scan detection of frida — connect gets called directly

**Scenario**: the app's native thread fires `connect` at 127.0.0.1:27042/27043; once connected it `read`s for the D-Bus `REJECTED` banner; or it parses `/proc/net/tcp` (27042=0x69A2).
**Do the no-fallback fix first** (cheapest): `frida-server -l 127.0.0.1:1337` to change the port, rename the binary, or switch to **gadget mode injected with the so** (no TCP listener).
**L3 approach** (effective while the app goes through libc):

```js
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
  onEnter(args) {
    const sa = args[1];
    if (sa.readU16() === 2 /*AF_INET*/) {          // sockaddr_in.sin_port uses network byte order
      const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      if (port === 27042 || port === 27043) {
        this.block = true;
      }
    }
  },
  onLeave(retval) { if (this.block) retval.replace(-1); }
});
```

**Why it's killed, cause C**: the app issues direct `svc` calls (x8=203) to scan ports, so hooking libc sees nothing; and frida always listens on a port regardless, so `/proc/net/tcp` parsing still exposes it.
**Fallback**: ① L4 Stalker catching `x8==203` (the same `onSvc` as case 1, watching connect targets); ② read-filter `/proc/net/tcp` (the same read filtering as case 1, deleting the frida listener line); ③ L5 eBPF `kprobe:__sys_connect` for global auditing (direct calls included):

```
kprobe:__sys_connect { @[comm, pid] = count(); }
```

**Radical fix**: gadget/`frida-server -l` on a non-loopback address + SELinux domain, or straight kernel-level injection — leave no trace on the TCP surface.

### Case 3: Property detection — __system_property_get hooked, the app self-parses the shared memory

**Scenario**: you changed `ro.build.tags` (test-keys) and `ro.debuggable` to fool root/emulator detection; the app doesn't call libc — it mmaps `/dev/__properties__` itself and walks the trie.
**Upper-layer approach (L3; gets bypassed wholesale by "self-parsing")**:

```js
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
  onEnter(args) { this.name = args[0].readCString(); this.value = args[1]; },
  onLeave(retval) {
    if (this.name === "ro.build.tags") {
      this.value.writeUtf8String("release-keys");
      retval.replace(1);
    }
  }
});
```

**Fallback (the correct answer: modify the shared memory directly; one strike covers every read path)** — whether the reader goes through libc or self-parses, it looks at the same memory:

```js
const find = new NativeFunction(
  Module.findExportByName("libc.so", "__system_property_find"),
  "pointer", ["pointer"]);          // (address, returnType, argTypes): const prop_info* (const char*)

function patchProp(name, newval) {
  const pi = find(Memory.allocUtf8String(name));
  if (pi.isNull()) throw new Error("prop not found: " + name);
  // Android P+ serialized layout: serial (4 bytes), followed by the value slot (PROP_VALUE_SIZE = 92 bytes)
  // Offsets have varied across versions; dump and verify before writing (unverified for this target)
  const val = pi.add(4);
  Memory.protect(val, 96, "rw-");
  const old = val.readCString();
  val.writeUtf8String(newval.substr(0, 91));
  console.log(`[prop] ${name}: ${old} -> ${newval}`);
}
patchProp("ro.build.tags", "release-keys");
```

Key points:
- Using libc's `__system_property_find` is merely **borrowing it to parse the trie and locate the prop_info** (not hooking it); an app that self-parses still reads this very memory;
- The property area is a shared read-only mapping; writing same-length values is safest — variable-length writes may break the trie layout;
- More thorough still: hook `mmap` to intercept the app's mapping of `/dev/__properties__` (high fallback cost, rarely used).

### Case 4: Time-based risk control — vDSO clock_gettime, hooking libc is not enough

**Scenario**: risk-control "double-read delta": it takes the time once before and once after a stretch of pure computation; an anomalous delta indicates hook/debugging; the Java layer's `System.currentTimeMillis` really lands in libc every time.
**Pitfall**: bionic `clock_gettime` prefers the **vDSO function pointer** (`__libc_globals->vdso[]`); if the app/ART cached the pointer and calls it directly, hooking the libc exported function won't intercept everything.
**Fallback 1 (patch the vDSO body)** — everyone who calls the vDSO directly passes through here:

```js
const vdso = Process.enumerateModules().find(m => m.name.includes("vdso"));
// Frida usually lists [vdso] as a module; otherwise locate the mapping in /proc/self/maps
const sym = Module.enumerateSymbols(vdso.name)
  .find(s => s.name === "__vdso_clock_gettime");
Memory.protect(sym.address, 0x1000, "rwx");   // The vDSO code page is read-only; make it writable first
Interceptor.attach(sym.address, {
  onLeave(retval) { /* Apply time compensation here as described in fallback 2 below */ }
});
```

**Fallback 2 (time compensation, attacking the essence of the double-read delta)** — don't intercept the read; make the returned value "look like no debugging happened":

```js
let lastReal = null, fakeElapsed = 0;   // Accumulated synthetic clock value in milliseconds
Interceptor.attach(getTimeFn, {           // clock_gettime from libc or the vDSO
  onEnter() { this.ts = this.context.x1; },
  onLeave() {
    // tv_sec=*ts, tv_nsec=*(ts+8); convert to milliseconds for this demo, and update both fields as needed in a complete implementation
    const now = this.ts.readU64().toNumber() * 1e3
              + this.ts.add(8).readU64().toNumber() / 1e6;
    if (lastReal !== null) {
      const realDelta = now - lastReal;   // Actual elapsed time, including hook/debugging overhead
      fakeElapsed += realDelta / 10;      // Compress elapsed time to simulate execution without debugging
      this.ts.writeU64(Math.floor(fakeElapsed / 1e3)); // Write synthetic tv_sec; increments remain small and monotonic
    }
    lastReal = now;
  }
});
```

Idea: maintain a "fake clock" that always returns a forged accumulated value (constant, small increments), so the double-read delta stays constant. The L5 approach (kernel time skew/KernelPatch) is the last resort when rootless options fail.

### Case 5: Crypto — the so statically links boringssl, no EVP_* exports

**Scenario**: the app's so ships its own full BoringSSL; `Module.findExportByName("libcrypto.so","EVP_CipherUpdate")` finds no symbol; the entire L3 layer is dead.
**Fallback 0 (conditional low-cost Java probe)** — use this when the observed
caller or provider actually uses `javax.crypto.Cipher`. Native code may generate
and consume plaintext without calling Java Cipher, so this is not a guaranteed
observation point for a statically linked BoringSSL routine:

```js
Java.perform(() => {
  const Cipher = Java.use("javax.crypto.Cipher");
  Cipher.doFinal.overload("[B").implementation = function (input) {
    const out = this.doFinal(input);
    console.log(`[Cipher] algo=${this.getAlgorithm()}\n in=${hex(input)}\nout=${hex(out)}`);
    return out;
  }
});
```

If the Java probe has no hits, first establish whether that provider is on the
executed path. No hits alone do not establish obfuscation, reflection, or hook
blocking. For a wholly native path, inspect the actual JNI argument/result
boundary or locate the native implementation directly:
**Fallback 1 (signature scanning)**:

```js
const mod = Process.getModuleByName("libtarget.so");
// 1. Version strings: statically linked BoringSSL often retains identifying strings
Memory.scanSync(mod.base, mod.size, "42 6F 72 69 6E 67 53 53 4C")  // "BoringSSL"
  .forEach(h => console.log("[str]", h.address));
// 2. ARM64 crypto instructions: AESE = 0x4E2848xx, little-endian bytes ?? 48 28 4E
mod.enumerateRanges("r-x").forEach(r => {
  Memory.scanSync(r.base, r.size, "?? 48 28 4E").forEach(h => {
    console.log("[AESE] @", h.address,
      DebugSymbol.fromAddress(h.address));   // Without symbols, locate the function start manually
  });
});
```

Once you have an address inside the function, walk upward to find the function prologue (`stp x29, x30, [sp, #-...]`) to pin the entry, then `Interceptor.attach` hooks it by address (a statically linked function can still be inline-hooked — it merely lacks a symbol, not hookability).
**Fallback 2 (Stalker follows the data flow)**: start from a demonstrated entry
on the actual path (`SecretKeySpec` only when used, an observed JNI native method,
or a located native caller). Record a bounded call chain with `Stalker.follow`,
then correlate buffer addresses and argument observations to locate the
update-type function. A call trace alone does not prove how key bytes flow.
**Domain reminder**: crypto has no syscall (layers doc §6); L4/L5 have nothing to intercept — the endgame against statically linked boringssl is signature scanning + in-memory hooks.

### Case 6: Thread detection — pthread_create hook bypassed by direct clone calls

**Scenario**: the app detects abnormal thread counts / frida thread names (gum-js-loop, gmain, pool-frida-*): enumerates `/proc/self/task` (getdents64) and reads each `<tid>/comm`.
**Upper-layer approach (only guards new additions; can't guard what already exists)**:

```js
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
  onEnter(args) { console.log("[pthread_create] fn=", args[2]); }
});
```

**Why it's killed, cause C**: the app (or packer) builds threads with direct `syscall(__NR_clone)` calls, so the pthread hook sees nothing; and frida's own threads have long existed.
**Fallback 1 (L3: getdents64 filtering — wipe frida threads out of the directory)**:

```js
Interceptor.attach(Module.findExportByName("libc.so", "getdents64"), {
  onEnter(args) { this.buf = args[1]; },
  onLeave(retval) {
    let len = retval.toInt32(); if (len <= 0) return;
    let off = 0;
    while (off < len) {
      // struct linux_dirent64: d_ino(8) d_off(8) d_reclen(2,+16) d_type(1,+18) d_name(+19)
      const reclen = this.buf.add(off + 16).readU16();
      const name   = this.buf.add(off + 19).readCString();
      if (/^(gum-js-loop|gmain|pool-frida-|linjector)/.test(name)) {
        Memory.move(this.buf.add(off), this.buf.add(off + reclen), len - off - reclen);
        len -= reclen; retval.replace(len);   // Remove this directory entry
        continue;                              // Keep off unchanged and read the current position again
      }
      off += reclen;
    }
  }
});
```

**Fallback 2 (L4/L5: audit direct clone calls)**: Stalker catches `x8==220` (clone); under root, the eBPF tracepoint `sched/sched_process_fork` observes all newly created threads (direct calls included). To block the app from spawning "detection threads", pair with a ptrace breakpoint at the svc return point to change the return value to -1.
**Follow-up action**: thread names can also be changed at the source — `pthread_setname_np` ends in `prctl(PR_SET_NAME)` (PR_SET_NAME=15, svc number 167); hooking prctl to filter the name argument only works for newly created threads; frida's own threads are backstopped by file-domain filtering (getdents64/read).

## 3. svc Instruction Interception Compendium (the L4 general toolbox)

### 3.1 arm64 conventions

| Item | Value |
|---|---|
| Instruction | `svc #0`, encoding `0xD4000001`, little-endian bytes `01 00 00 D4` |
| Syscall number | `x8` (32-bit) |
| Arguments | `x0`-`x5` (mapping to C-prototype args 1-6) |
| Return | `x0`; the kernel returns `-errno`, the bionic wrapper converts it to `errno` and returns -1 |
| Special | High numbers such as `svc #0x8xxxx` are kernel tagged variants (common on MTE/PAC-enabled kernels; exact semantics to be verified) |

### 3.2 Stalker catching svc (the standard posture)

```js
Stalker.follow(Process.getCurrentThreadId(), {
  transform(iterator) {
    let insn;
    while ((insn = iterator.next()) !== null) {
      if (insn.mnemonic === "svc") iterator.putCallout(onSvc);
      iterator.keep();
    }
  }
});
```
- In the callout, `context.x8/x0..x5` are the live registers;
- Three performance rules: ① `Stalker.exclude(Process.getModuleByName("libc.so"))` to exclude high-frequency libraries; ② follow only the target thread; ③ collect in a short window (a few seconds) then `Stalker.unfollow`.
- Typical filters: `x8==56` (openat, `x1`=path), `x8==203` (connect, `x1`=sockaddr), `x8==220` (clone), `x8==113/169` (time — a direct call is itself anomalous: the normal path goes through vDSO!), `x8==278` (getrandom).

### 3.3 Memory-scan for svc: proving that "direct syscall calls" exist

```js
const mod = Process.getModuleByName("libtarget.so");
mod.enumerateRanges("r-x").forEach(r => {
  Memory.scanSync(r.base, r.size, "01 00 00 D4").forEach(h => {
    // Inspect preceding movz x8, #imm16: encoding 0xD2800008 | (imm<<5)
    let nr = -1;
    for (let back = 4; back <= 24; back += 4) {
      const w = h.address.sub(back).readU32();
      if ((w & 0xffe0001f) === 0xd2800008) { nr = (w >>> 5) & 0xffff; break; }
    }
    console.log(`[svc] ${h.address} nr=${nr}`);
  });
});
```

The set of syscall numbers counted = the so's direct-call surface; if it contains 56/63 (file reads) or 203 (connect), then L3 hooks necessarily leak — go straight to 3.2. Note the caveat of dynamically generated code (not scannable).

### 3.4 Other svc-Level Means

| Means | How | Fit |
|---|---|---|
| ptrace breakpoints | Insert `BRK #0` (0xD4200000) at the svc address; in SIGTRAP use PTRACE_GETREGS to alter args/returns, single-step over | Offline/no-frida, precise single-point edits |
| eBPF tracepoints | `syscalls/sys_enter_xxx` (carries its own args struct), `sys_exit_xxx` (see ret) | root + GKI kernel, global auditing |
| eBPF kprobes | L5 functions such as `__sys_connect`/`kernel_clone`; `bpf_override_return` is limited to a kernel whitelist of functions | Return-modification restricted; mostly observation |
| KernelPatch/kernel modules | Alter sys_* behavior in kernel space | root + unlocked bootloader/kernel; the ultimate means |

### 3.5 Why seccomp cannot serve as a hook

- seccomp BPF's verdict actions are only: `KILL_PROCESS / KILL_THREAD / TRAP(ERR SIGSYS) / ERRNO / LOG / ALLOW`, plus `TRACE` (handing over to a ptrace tracer) and `USER_NOTIF` (user-mode notification) — **there is no "modify registers then continue traceless" action**, so it is inherently a filter/auditor, not a hook.
- `SECCOMP_RET_TRACE + ptrace` can `PTRACE_SETREGS` in the tracer to alter arguments and continue — but it requires a tracer process and traps on every syscall: slow and heavy on traces;
- `USER_NOTIF` (SECCOMP_RET_USER_NOTIF) + `SECCOMP_IOCTL_NOTIF_ADDFD` can only insert an fd on behalf of the app; changing ordinary arguments requires a detour through `process_vm_writev` to modify its memory — high latency;
- And the filter must be **installed by the target process itself** (or injected at creation time); an attacker cannot impose it externally.
- Conclusion: to "modify", use Stalker/ptrace in user mode and kprobe/KP in kernel mode; leave seccomp for **denial** (e.g., anti-sandbox uses it to cut off debuggers).

## 4. Per-Layer Anti-Detection Strength Reference Table

| Layer | Hook form | Typical detection means | Confrontation cost (attacker) | Notes |
|---|---|---|---|---|
| L1 | Xposed/LSPosed, frida Java.use | Scan for XposedBridge/loaded dex, call-stack walks, `isDebuggerConnected`, hidden-API-call alerts | Low (mature tooling but the most traces) | Device spoofing/return-value replacement remains the first pick — fast |
| L2 | Hooking exported symbols of libart/libjavacore | CRC of exported functions (rare), extra native frames in the Java stack | Low-medium | `JVM_*`/`Java_libcore_io_*` work well and few defend them |
| L3 | Interceptor inline / GOT / PLT | CRC of libc function-head bytes, GOT-entry comparison, anomalous register state, `dl_iterate_phdr` segment-hash verification | Medium | The most-used layer, and the most heavily defended |
| L4 | Stalker catching svc, ptrace BRK, inline at svc addresses | Time double-read delta (Stalker slows execution), anomalous voluntary_ctxt_switches in `/proc/self/status`, per-CPU counter discrepancies | Medium-high | The only user-mode answer to direct svc calls |
| L5 | eBPF kprobe/tracepoint, kernel modules, KernelPatch | Nearly no user-mode detection surface; only root detection (Magisk traces) can indirectly expose it | High (root + kernel threshold) | Strong observation, restricted rewriting (override whitelist) |
**Combination advice**: weak targets fall to L1/L3 in one pass; moderate confrontation gets maps/status filtering (L3) + device-spoofing linkage; heavy confrontation (direct svc + CRC + double-read time) calls for L4 Stalker/ptrace; consider L5 only with root.

## 5. Wrap-Up Checklist (self-check after every fallback)

1. Confirm the layer you fell back to is **the one actually being used** (the five layer-identification methods), not a guess;
2. Don't force the three "no-svc" special cases (property reads / vDSO time / crypto) into L4;
3. Hook working ≠ zero tells: check time deltas, errno style, thread count, consistency of return values with the system side;
4. After Stalker, `unfollow` + `garbageCollect`; long-running scripts must configure exclude properly;
5. Persist the output: backfill the "hook key points" column of the matching domain in android-function-layers.md for the functions/layers you hit.
