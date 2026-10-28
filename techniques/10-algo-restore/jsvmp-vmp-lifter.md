# JSVMP and VMP Lifter in Practice: Turning the Five-Step Method into a Pipeline

> Positioning: `deobfuscation-practice.md` §6 gives the VMP restoration five-step method (the methodology layer); this doc is its **lifter practice layer** — your hand is already on the VM, so how do you actually build the handler semantic table, the translator, and the replay verification.
> Cross-references: `deobfuscation-practice.md` (VM identification and the five-step method), `algo-restoration-methodology.md` (L1/L2/L3 layering and the §1.3 restoration boundary), `protocol-offline-rpc.md` (the not-restoring three-stage rocket via RPC), `../13-trace/trace-practice.md` + `../02-frida/advanced/stalker.md` (native/dex-side tracing), `../04-evasion/device-fingerprint-risk.md` (the environment-collection surface).

## 0. Pipeline Overview and Acceptance Gates

```
①Identify & dissect → ②semantic extraction (static + dynamic) → ③semantic table → ④lifter duo → ⑤verification loop → ⑥delivery
 JSVMP          babel classification + trace inference    op→semantics    translator + replayer    output diff + trace diff    pseudocode/runnable JS
 dex/native     IDA annotation + stalker trace            same           same (borrow unidbg)     per-opcode comparison       method-level restoration
```

Two iron laws (prior judgments that come even before the five-step method):
1. **The lifter has exactly one acceptance gate: the replay loop** — rerun the original bytecode with your restored semantic table; under the same input, byte-for-byte identical to the original VM's output, with the trace aligned entry by entry. However beautiful the translator, a failed replay diff scores zero;
2. **Decide first whether you even want a lifter**: if the input contains strong device fingerprints / dynamic challenges (`algo-restoration-methodology.md` §1.3), or you only need low-frequency outputs → don't write a lifter; go straight to the three-stage rocket of `protocol-offline-rpc.md`. Lifter investment is counted in "weeks"; RPC in "hours".

---

## 1. JSVMP Identification and Structural Dissection (the Main Force of Web Risk Control)

### 1.1 Identification signatures (three layers)

| Layer | Signature | Notes |
|---|---|---|
| File level | a single js of hundreds of KB to several MB; filename/content changes on every refresh (anti-archiving); an inline bootstrap js precedes the external link | typical of the Ruisu family: inline js generates the meta/external link; the external body is the actual VM |
| Code level | a giant self-decrypting IIFE; super-long strings or big arrays (the bytecode carrier); a `switch` with hundreds of cases or "function array + index calls"; `eval`/`Function` chains | case count ≈ handler count, from dozens to a thousand+ |
| Behavioral level | `charCodeAt`/`at`/`fromCharCode` call counts explode (fetch + decode); extremely high in-loop call frequency within one function; opening console triggers a `debugger` statement or a `toString` check | the fetch hotspot = inside the dispatcher |

The ten-minute test: run one signing in Chrome DevTools Performance; in the flame chart a single function with 80%+ self time and tens of thousands of calls → almost certainly the dispatcher/handler; in Sources after pretty-printing, search `charCodeAt(` — the dense-hit zone is the bytecode reading region.

### 1.2 Generic structural dissection (five pieces)

```
Entry stub (the exported sign/frontier function)
   │  assembles ctx, decrypts the bytecode
   ▼
bytecode carrier ── long string / charCode array / Uint8Array / base64 segment (may self-decrypt and rewrite at runtime)
   │
   ▼
dispatcher ── while(1){ op=fetch(pc); pc+=stride; dispatch(op) }
   │            form A: switch(op){case 0x23:...}    form B: tbl[op](ctx), table-driven
   ▼
handler table ── N small functions, each mapping to one virtual opcode (or one family)
   │
   ▼
ctx (context object) ── fields are the registers: pc / st (stack array) or sp / regs (array or r0..rn) / cp (constant pool) / scope (chain) / ret
```

### 1.3 Locating the parts, hands-on

1. **dispatcher**: after pretty-printing, find the "super-long switch" or the loop body where "`arr[op]` (or `arr[op&0xff]`, `arr[map[op]]`) is immediately followed by a function call"; confirmation criterion: the loop body contains a `pc`/`ip`-style counter incrementing itself;
2. **bytecode**: backtrack the fetch expression inside the dispatcher — the `s` of `s.charCodeAt(pc++)`, the `a` of `a[pc++]`; for encrypted forms, first find the one-shot decryption loop in the entry IIFE (XOR/base64 variants), hook it, and dump+archive the decrypted result (**do all subsequent analysis against the decrypted bytecode**);
3. **handler table**: in form B it's directly an array/object; in form A the handlers are the switch's case bodies (§2.2 gives the "manual tabling" rewrite);
4. **ctx registers**: the dispatcher's first argument is almost always ctx; listing ctx's field names yields the VM's register inventory — this pins the architecture in 30 seconds (stack machine vs register machine: a `st` array means stack machine; dense `r[]` indexed reads/writes means register machine);
5. **opcode variants**: `op` doesn't necessarily index the table directly — common are `tbl[(op^k)&255]`, `tbl[op%len]`, two-level mapping. Copy the mapping formula down first; the lifter's fetch step must replicate the very same formula.

### 1.4 Environment-confrontation checklist (defuse before touching anything)

- `debugger` statements + time-delta detection (`Function('debugger')` stall detection): always use "conditional breakpoint Never pause here" or delete via AST;
- `Function.prototype.toString` integrity detection: before hooking/wrapping any function, pass through toString first (skeleton in §2.2);
- console/DevTools detection (`console.log` triggering a getter, window-size delta): replaying in CLI Node has no such surface — prefer stripping down to Node (§3.2).

---

## 2. Handler Semantic Extraction, Hands-On (the lifter's core cost)

### 2.1 Method A: static classification (babel-assisted)

Read through each handler once and label it into eight classes:

| Semantic class | Looks like (inside the case body) | Label |
|---|---|---|
| Stack ops | `st.push(x)` / `st.pop()` / two consecutive pops then a push | PUSH/POP/DUP/SWAP |
| Constant load | `st.push(imm)` / `st.push(cp[k])` | LDC_IMM / LDC_CP |
| Arithmetic/logic | two pops and one push, with `+ - * ^ << >> &` in between | ADD/SUB/XOR/SHL... |
| Compare/jump | pop-compare + `pc = imm` (or `pc += imm`) | CMP+JCC / JMP |
| Variables/scope | `regs[i]=` / `scope[n][m]` reads/writes | LOAD/STORE |
| Property access | `.length` / `[k]` / `Object.keys` | GETPROP/SETPROP |
| Calls | `f.apply` / `new f`, argument count popped or imm | CALL/CALL_M/NEW |
| Environment/host | reads `window/navigator/document/screen` | ENV (the risk-control collection surface lives here; cross-reference `../04-evasion/device-fingerprint-risk.md`) |

The efficiency tool for static reading is babel: extract the dispatcher function's source → `@babel/parser` to AST → collect each handler body per case → generate a "case number ↔ source" table to paste into notes and label one by one (with a hundred-plus handlers, skipping this step gets labels crossed):

```javascript
// extract_handlers.mjs: Node + @babel/parser; extract a handler table from formatted vmp.js
// After npm i @babel/parser, run: node extract_handlers.mjs vmp.js <dispatcher-line-number> > handlers.txt
import { readFileSync } from "fs";
import { parse } from "@babel/parser";
import generate from "@babel/generator";

const src = readFileSync(process.argv[2], "utf8");
const ast = parse(src);
let out = [];
// Locate a long switch: a SwitchStatement with more than 50 cases is a dispatcher candidate
(function walk(n) {
  if (!n || typeof n.type !== "string") return;
  if (n.type === "SwitchStatement" && n.cases.length > 50) {
    for (const c of n.cases) {
      const code = c.test ? generate(c.test).code : "default";
      const body = c.consequent.map(st2 => generate(st2).code).join("; ");
      out.push(`${code}\t${body.slice(0, 200)}`);   // Inspect the first 200 characters of each handler for initial classification
    }
  }
  for (const k in n) Array.isArray(n[k]) ? n[k].forEach(walk) : walk(n[k]);
})(ast);
console.log(out.join("\n"));
```

Statically-assisted hooks (to cover static reading's blind spots): temporarily replace `console.log`/`Object.defineProperty`, hook `Function.prototype.call` to print call sequences, and observe which handlers triggered native methods — confirm ENV/CALL-class handlers with this first.

### 2.2 Method B: dynamic trace inference (the recommended main line)

Statically reading a hundred-plus handlers is slow and error-prone; the recommendation is **dynamic first, static second**: get structural features from traces; use statics only to verify the doubtful ones.

Probe design (one move per dispatcher form):

- **Form B (table-driven)**: wrap the handler array, recording per dispatch `(handlerIdx, entry snapshot, post-return snapshot)` — the snapshot delta = the stack effect, no need to understand the handler's internals;
- **Form A (switch-style)**: first "manually table it" — babel extracts each case body into a function `h0x23(ctx){...}` stored in a table, the switch becomes `tbl[op](ctx)`, then treat as form B. The rewrite is purely mechanical and doesn't touch semantics; after rewriting, first cross-check the output against the original VM to confirm the rewrite is lossless.

```javascript
// Skeleton 1: dispatcher hook injected through the browser console to collect traces
// Prerequisites: locate vmCtx and the handlers table, then paste into the browser DevTools console
(function () {
  var H = vmCtx.handlers, seq = 0, traces = [];
  var snap = function (c) {                      // Context snapshot: copy arrays and scalars only, and mark objects
    var o = {};
    for (var k in c) {
      var v = c[k];
      if (typeof v === "number" || typeof v === "string" || typeof v === "boolean") o[k] = v;
      else if (Array.isArray(v)) o[k] = v.slice(0, 64).map(function (x) {   // Keep the top 64 stack slots
        return (typeof x === "object" && x !== null) ? "[obj:" + Object.prototype.toString.call(x).slice(8, -1) + "]" : x;
      });
      else o[k] = "[obj:" + Object.prototype.toString.call(v).slice(8, -1) + "]";
    }
    return o;
  };
  var passthrough = function (f) {               // Preserve the original toString representation for integrity checks (Section 1.4)
    var g = function () { return f.apply(this, arguments); };
    g.toString = function () { return f.toString(); };
    return g;
  };
  for (var i = 0; i < H.length; i++) (function (idx, orig) {
    H[idx] = passthrough(function () {
      var a0 = snap(vmCtx), r = orig.apply(this, arguments), a1 = snap(vmCtx);
      traces.push({ seq: seq++, op: idx, s0: a0, s1: a1, ret: (r === undefined ? null : String(r).slice(0, 128)) });
      return r;
    });
  })(i, H[i]);
  window.__dumpTrace = function () {             // After triggering one signature calculation, persist copy(window.__dumpTrace())
    return JSON.stringify(traces);
  };
})();
```

frida edition (the app-embedded H5 scenario): inject the same snippet via `WebView.evaluateJavascript` (hook points in `../02-frida/java-layer/network-webview.md`), or hook `String.prototype.charCodeAt` directly to record the fetch sequence (when the bytecode is a string, fetching must pass through here — more general than wrapping the table, but yields only (pc,op) without stack snapshots; use as auxiliary).

### 2.3 Differential probes: inferring semantics from traces

The key move is **repeat-invocation with controllable inputs**: find the page-global entry (`window.sign` / the exported frontier function), invoke with probe sets, one trace per set:

| Probe set | Inference target |
|---|---|
| `f(1,1)` vs `f(1,2)` vs `f(2,3)` | ops whose ret/stack-top equals 2/3/5 = ADD candidates; equals 2/3/6 = MUL candidates |
| `f("a","b")` vs `f("ab","c")` | ops yielding "ab"/"abc" = CONCAT/string handling |
| `f(x)` vs `f(x')` (change one field only) | **the common prefix of the two traces = environment opcodes independent of that input; the first diverging op = that field's consumption point** — concatenation structure and field→ciphertext-segment mapping read straight off this (same idea as `algo-restoration-methodology.md` §7.2 differential testing) |

Statistical surface: an op frequency table + the stack-effect distribution per op (a stable `|st|` delta = pops-N-pushes-M). Aggregation script:

```python
# Skeleton 2: Python semantic statistics; consume multiple trace_json files from skeleton 1 and emit sem_table.json
import json, sys, collections

def load(path): return json.load(open(path))

def stack_len(snap):                      # Adapt the stack field name to the sample: st/stack/_
    return len(snap.get("st", []))

def main(traces):                         # Accept several trace paths, for example trace_11.json trace_12.json ...
    freq = collections.Counter(); effect = collections.defaultdict(collections.Counter)
    for p in traces:
        for e in load(p):
            op = e["op"]; freq[op] += 1
            effect[op][stack_len(e["s1"]) - stack_len(e["s0"])] += 1
    sem = {}
    for op, eff in effect.items():
        stable = eff.most_common(1)[0]            # Most common stack effect; for polymorphic handlers also inspect less frequent effects
        sem[op] = {"count": freq[op], "delta_stack": stable[0], "guess": None}
    # Fill guess by comparing probe traces; confirm through diff_trace in skeleton 3 before marking the semantics verified
    json.dump(sem, open("sem_table.json", "w"), indent=1, ensure_ascii=False)
    for op, s in sorted(sem.items(), key=lambda kv: -kv[1]["count"]):
        print(f"op 0x{op:x}: n={s['count']:6d}  dStack={s['delta_stack']:+d}  {s['guess']}")

if __name__ == "__main__":
    main(sys.argv[1:])
```

The output is the **semantic table** (`sem_table.json`: op → {stack effect, guessed semantics, confidence}); op is the handler index; if an opcode mapping formula exists (§1.3 item 5), store a `raw_op → handler_idx` layer in the table too. The semantic table is the sole shared input of §3's translator and replayer — **the three scripts interlock through it**.

---

## 3. Building the Lifter, Hands-On

### 3.1 Translator: bytecode → pseudocode (a python recursive-descent template)

Translating stack-style bytecode goes in two passes: first a linear scan collecting jump targets (label the target pcs); then per-instruction translation into stack-machine IR, followed by **stack resolution** (folding push/pop sequences into expression trees):

```python
# Lifter template: bytecode + semantic table -> pseudocode
import json

OPS = json.load(open("sem_table.json"))          # op -> {"guess": "ADD", ...}

def disasm(bc):                                   # First pass: collect branch targets
    pc, labels = 0, set()
    while pc < len(bc):
        op = bc[pc]; info = OPS.get(op)
        if not info: raise SystemExit(f"Unknown op 0x{op:x} @ {pc}; missing semantics, complete section 2.3 first")
        name = info["guess"]; pc += 1             # Adapt instruction length to the sample; variable-width instructions follow operandWidth in the semantic table
        if name in ("JMP", "JCC"): labels.add(read_imm(bc, pc)); pc += imm_w
        elif name in ("LDC_IMM",): pc += imm_w
    return labels

def lift(bc):
    labels = disasm(bc); pc = 0; out = []; stack = []      # Keep expression strings on stack for stack elimination
    while pc < len(bc):
        if pc in labels: out.append(f"L{pc}:")
        op = bc[pc]; name = OPS[op]["guess"]; pc += 1
        if name == "LDC_IMM": stack.append(str(read_imm(bc, pc))); pc += imm_w
        elif name == "ADD":   b, a = stack.pop(), stack.pop(); stack.append(f"({a}+{b})")
        elif name == "STORE": out.append(f"v{bc[pc]} = {stack.pop()}"); pc += 1
        elif name == "JMP":   out.append(f"goto L{read_imm(bc, pc)}"); pc += imm_w
        elif name == "JCC":   out.append(f"if {stack.pop()} goto L{read_imm(bc, pc)}"); pc += imm_w
        # Expand the other semantic classes in the same way; CALL pops the function and argument count
        else: raise SystemExit(f"Unfolded semantics {name} @ {pc}")
    return "\n".join(out)
```

The output is assembly-like pseudocode (labels + goto + folded expressions); good enough for a human to read the algorithm — **no need to chase restorable, compilable JS** — if you need a runnable version, go to the §3.2 replayer, not the translator.

### 3.2 Custom-interpreter replay (the acceptance gate)

With the semantic table, directly implement a mini interpreter that reruns the **original bytecode** (bypassing the translator, ruling out second-order error introduction):

```python
# Skeleton 3: Python replay comparison; execute the semantic table and bytecode, then compare output/trace against the original VM
import json

OPS = {0x23: ("LDC_IMM", 1), 0x35: ("ADD", 0)}   # op -> (semantics, immediate width), populated from skeleton 2
BC  = open("bc.bin", "rb").read()                 # Decrypted bytecode dumped through a hook (Section 1.3)

def replay(inp):
    pc, st, regs, out = 0, [], {}, None
    trace = []                                    # Replay's own trace, aligned in Section 3.3
    while pc < len(BC):
        op = BC[pc]; name, iw = OPS.get(op, (None, None)); pc += 1
        imm = int.from_bytes(BC[pc:pc+iw], "little") if iw else None; pc += iw
        trace.append((pc, name, tuple(st[-4:])))
        if   name == "LDC_IMM": st.append(imm)
        elif name == "ADD":     b, a = st.pop(), st.pop(); st.append(a + b)
        elif name == "ENV":     st.append(env_shim(imm))    # Environment-dependent behavior; see the shim discussion below
        elif name == "EXIT":    return st.pop(), trace
        else: raise SystemExit(f"Missing semantics {name} @ {pc}; extend section 2.3 table")
    return st[-1], trace

out, trace = replay({"ts": 1760000000, "input": "..."})
orig = open("orig_out.txt").read()                # Original VM output for identical input with time frozen
print("Outputs match" if out == orig else f"FAIL: replay={out} orig={orig}")
json.dump([{"pc": p, "op": n, "st": list(s)} for p, n, s in trace], open("replay_trace.json", "w"))
```

Two hands-on essentials:
1. **Progressive replay**: fill the OPS table only with confirmed semantics; run until a "semantic gap" error → go back to §2.3 and fill that one op → run again. "Fix as you go" beats writing it all at once — every round's diff converges;
2. **ENV-class ops are the watershed of replay success**: the arithmetic side almost never errs; the environment side (navigator/screen/document values) needs fake-data shims in python — first copy the ENV ops' actual return values from the original VM trace into the shim table ("environment snapshot transplant"), get outputs matching, then swap in fake values item by item for sensitivity testing to confirm which environment items really enter the input.

### 3.3 The trace-diff method (locating the divergence point)

The output diff only tells you "it's wrong"; the trace diff tells you "which instruction is wrong":

```python
# Align original VM traces from skeleton 1 with replay traces from skeleton 3 to find the first divergence
orig  = json.load(open("orig_trace.json"))        # Normalize [{seq,op,s1...}] to (opcode, stack-top tuple) first
repl  = json.load(open("replay_trace.json"))
for i, (a, b) in enumerate(zip(orig, repl)):
    if a["op"] != b["op"]:
        print(f"#{i} Control-flow divergence: orig op={a['op']} vs replay op={b['op']} —— previous op semantics (especially JCC/comparison) are wrong"); break
    if list(a["st"]) != list(b["st"]):
        print(f"#{i} Data divergence @ op={a['op']}: {a['st']} vs {b['st']} —— op semantics or ENV shim value is wrong"); break
else:
    print("Traces fully aligned" if len(orig) == len(repl) else "Prefix aligned but lengths differ: EXIT/jump semantics error")
```

The divergence bisection: for a control-flow divergence, look at the previous entry (a jump condition computed wrong); for a data divergence, look at the current one (this op's semantics are wrong, or an ENV return value is wrong — distinguish per §3.2 item 2). **The verification loop = output diff passing + trace fully aligned**; only when both pass is the lifter delivered.

---

## 4. dex VMP Lifter Supplement (connecting with the §6/§6.3 methodology)

`deobfuscation-practice.md` §6.3 gives only the mantra; here it becomes a four-step engineering effort (the approach inherits the dex VMP restoration series' engineering practice).

### 4.1 VM handler extraction (IDA-script mode)

1. jadx-side locating: methods turned `native` + RegisterNatives registration inside the so (hook to grab the registration table, `../02-frida/native-hook-cheatsheet.md`);
2. IDA-side dispatch-loop recognition: high-frequency `BR Xn` + a pool of short functions called only indirectly (§6.1 signatures); mind the countermeasure of **the fetch block being copied into every handler's tail** — cluster by "repeatedly appearing fetch sequences" rather than hunting a unique dispatcher;
3. IDAPython bulk annotation: from the jump-table base scan out the handler address set; create each as a function named `vm_op_XX`, writing `XX` (the index) into the comment too — this is the native-version semantic table in embryo:

```python
# IDAPython: extract and name jump-table handlers in bulk; ARM64 table at jump_tbl_ea with N entries
import ida_bytes, idc
BASE = 0x7A0000                                   # Shared-object jump table address; identify X19 in LDR X9,[X19,X9] statically
for i in range(256):
    ea = ida_bytes.get_qword(BASE + i * 8)
    if ea and idc.get_func(ea) or True:
        idc.add_func(ea); idc.set_name(ea, f"vm_op_{i:02x}", idc.SN_NOWARN)
        idc.set_cmt(ea, f"handler idx={i} entry@{BASE + i*8:X}", 0)
```

### 4.2 Dispatch-loop tracing

Run the target method on a real device; stalker follows only the dispatch address range, `putCallout` recording `(pc, key registers)` per hit — the fetch-point register values are the (pc_vm, op) sequence. The writing, hang troubleshooting (the mutex_lock switch method), and volume-controlled post-processing all adapt the ready-made scripts of `../13-trace/trace-practice.md` and `../02-frida/advanced/stalker.md`: follow only a small address window, persist output before offline statistics (op frequency/stack effect as in §2.3 skeleton ②, register snapshots replacing ctx snapshots).

### 4.3 Building the opcode mapping table (the white-box contrast method)

The JSVMP side relies on probe-input differentials; the dex side's cheaper path is the **white-box contrast**: write demo Java methods containing each instruction type yourself (iadd/if_icmple/aget/invokevirtual/stringbuilder chains); if you can obtain the same hardener, harden them and contrast traces; if not, do "behavioral contrast" on the target method — the handler dense with JNIEnv calls in the trace is the invoke-semantics handler (the §6.3 mantra), and the JNI function name directly gives that invoke's target. Fill the table class by class: handler address ↔ dex instruction semantics ↔ operand encoding.

### 4.4 Tooling the method restoration (per-opcode comparison via frida active invocation)

Once the mapping table is roughly complete, do **single-opcode verification**: actively invoke the target native method with frida (the ArtMethod/fromJni active-invocation in `../02-frida/frida-api-reference.md`), construct minimal bytecode containing just one virtual instruction (or replay the trace's captured state for that op), and compare the execution result against the semantic table's expectation — batch through every op once, and you have the native-version "replay diff". After all ops pass, restore whole methods: bytecode segment → dex instruction stream → smali/pseudocode, cross-checking against real-device output to close (same acceptance gate as §3.3).

---

## 5. Big-Vendor Risk-Control Scenario Positioning Table (which VM is behind which parameter)

| Scenario | Protection form | Identification anchor | Lifter restoration cost | Non-restoring alternative (decision point) |
|---|---|---|---|---|
| Web risk-control parameters (a_bogus web side / Ruisu / Tongdun / Shumei class) | **JSVMP** | §1.1 three-layer signatures; flame-chart single-function hotspot | Medium: handlers in the hundreds; probe differentials surface the core ops in 1-3 days | Browser RPC (playwright resident) is cheapest; only scale up to a lifter when you need scale |
| Risk-control parameters of an app-embedded H5 | JSVMP (same as web, inside a WebView) | js signatures inside the WebView, same as left | Medium (same as left) | Go straight to R1 frida RPC (`protocol-offline-rpc.md` §2) — an order of magnitude cheaper than restoring |
| Method protection of shield-class hardening (Bangcle/360/Ijiami commercial VMP) | **dex VMP** | methods nativized + dense JNI in the so | High: all four steps of §4, week-scale | Whole-package restoration usually not worth it — restore only the few methods carrying the signature; the rest goes R1/R2 |
| ByteDance/Meituan/Pinduoduo native-layer signing (mtgsig class / anti_content class) | **native VM + OLLVM** | `deobfuscation-practice.md` §6 signatures | Extreme (weeks to months) | Default R2 unidbg black-box recomputation (`algo-restoration-methodology.md` §6); full VM restoration only when unidbg can't complete the environment |

Decision criteria (reusing the existing docs, no new standard): inputs constructible offline + the business needs scale → only then consider a lifter (L1); inputs contain strong device fingerprints / server-side challenges → stop at R1/R2, a lifter is meaningless (the `algo-restoration-methodology.md` §1.3 criterion). **The lifter's applicable band is narrow: it pays back only for high-value, multi-version long-term maintenance targets whose semantic table can be rebuilt by script (a version change swaps only the bytecode)**.

## 6. Toolbox

The dataflow contract of the three skeletons (a self-consistency checklist):

```
Skeleton 1 (browser/Frida injection) --JSON: [{seq,op,s0,s1,ret}]--> multiple probe traces
        │
Skeleton 2 (semantic statistics) <-- trace_*.json; output sem_table.json(op->{delta_stack,guess})
        │
Skeleton 3 (replay comparison) <-- sem_table.json + bc.bin + orig_out/orig_trace
                              output: output diff + trace-alignment report (Section 3.3)
```

Interlock points: ①'s `op` = the handler index (not the raw opcode; the mapping formula gets its own layer); ②'s `delta_stack` and `guess` are ③'s only inputs; ③'s "semantic gap" exception flows back into ② to keep filling the table — **a closed-loop trio, each independently runnable, each artifact archivable and reusable**.

Other tools:

| Tool | Use | Notes |
|---|---|---|
| babel (parser/traverse/generator) | handler extraction (§2.1), switch tabling (§2.2), string-decryption and constant-folding preprocessing | the first stop for web VMP analysis; pair with the ast explorer web UI to try transforms fast |
| Node `vm` module + jsdom/hand-built window | JSVMP browser-less replay (the host of §3.2's ENV shim) | "environment snapshot transplant" first, then item-by-item replacement; more controllable than debugging in a browser |
| Chrome DevTools Performance | dispatcher hotspot locating (§1.1's ten-minute test) | paired with Sources pretty-printing |
| frida + WebView injection | JSVMP tracing of app-embedded H5 | the same script as §2.2 |
| IDAPython / stalker / unidbg | dex and native VMP (§4) | references `../13-trace/trace-practice.md`, `../05-toolbox/emulation-frameworks.md` |

One final discipline: the lifter is "the weapon of last resort". Before starting, pass the decision gate of §0 iron law 2; after starting, keep investing only while every step shows converging diff evidence (the semantic table filling up, the replay gaps shrinking) — two consecutive days without convergence, immediately downgrade to RPC (`protocol-offline-rpc.md`).
