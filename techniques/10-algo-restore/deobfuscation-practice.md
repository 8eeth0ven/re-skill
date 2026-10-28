# Deobfuscation in Practice: From Junk Code to VMP

> Cross-references: `algo-restoration-methodology.md` (deobfuscation is the preceding stage of pure computation), `../05-toolbox/emulation-frameworks.md`.

## 0. Master Principles

The only goal of deobfuscation is **to make IDA F5 readable / to make traces interpretable** — not "to restore source code". Three iron laws:
1. **Patch when you can, don't restore**: when you only need the algorithm to run (the L2 route), patching out the interference is enough;
2. **Emulate rather than go static**: running it once under unidbg/unicorn to get an execution trace beats statically reasoning through three layers of jumps;
3. **Trace rather than brute-reverse**: for VMP-grade obfuscation, hooking input/output as a black box always takes priority over restoring the instruction set. When hard deobfuscation meets multiple dispatchers, decisively switch to pure dynamics.

## 1. Master Classification Table of Obfuscation (what it looks like in IDA)

| Obfuscation type | Principle | IDA signature | Effect on F5 | Restoration cost |
|---|---|---|---|---|
| Junk code | Insert never-reachable/always-false bytes and jumps that break linear disassembly | Disassembly derails wholesale from some byte; lots of `DCB` data mixed into the code section | F5 fails or the function gets truncated | Low (patch bytes) |
| Control-flow flattening (fla) | Real blocks get scattered, strung together by dispatcher + switch(state) | One big loop: `while(1){ switch(var){ case 0x1a2b: ... } }`, var gets a new value at each block end | F5 emits a giant switch; logic unreadable | Medium-high |
| Bogus control flow (bcf) | Insert always-false predicate branches (opaque predicates) | Many paired if/else with a junk block on one side; always-false forms like `x*(x-1)%2==1` | F5 balloons several-fold but stays readable | Low-medium (NOP after identification) |
| Instruction substitution (sub) | Equivalent instruction transforms (a+b → a-(-b)) | Arithmetic takes the scenic route | Readable but verbose | Low (ignore as equivalent) |
| Indirect jumps (BR obfuscation) | Target address computed via table/arithmetic then `BR Xn` | IDA stops analyzing at `BR X9`; F5 jumpout | F5 fails outright | Medium |
| String encryption | Strings stored as ciphertext, decrypted on use | The strings window is all garbage; many XOR-loop functions cross-referenced | Doesn't affect F5; affects locating | Low (write a decryptor script) |
| VMP/VM protection | Code compiled to custom bytecode with a built-in interpreter | One giant dispatch loop + dozens/hundreds of handlers; the original function is down to vmEnter | No F5 to speak of | Extreme |
| Java2C/dex VMP | Java methods made native, or bytecode virtualized | In the dex, methods turn native; in the so, dense JNI calls | Unreadable at the jadx layer | High |
Spend 10 minutes classifying first, then follow the matching section. **The price of misclassification is a wholly wrong methodology** (attacking VMP with flattening ideas is all wasted effort).

## 2. Junk Code

### 2.1 Common patterns

1. **Junk byte + short jump**: `jmp +2; db E8/E9 ...` — E8/E9 are deliberately placed fake call/jmp first bytes, making the linear scanner mis-slice subsequent instructions;
2. **Always-false jumps**: `cmp r0, r0; b.ne next` (never equal) or opaque predicates; junk bytes stuffed into the false path;
3. **Unreachable blocks**: a junk block that "looks like an entry" right after an unconditional jump;
4. **EFLAGS games**: exploit the deterministic flag values after `adds` to construct constant branches.

### 2.2 Static patching (IDA script)

The standard flow: at the derailing instruction press D/U to redefine as data, re-Code from the correct bytes; for bulk cases, write IDAPython to scan past-jmp junk bytes and NOP them directly:

```python
# IDAPython: scan short-branch-over-junk patterns and replace junk with NOPs
import ida_bytes, ida_ua, idc

def deflower(start, end):
    ea = start
    while ea < end:
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz <= 0:                       # A disassembly failure may indicate junk bytes
            ida_bytes.patch_bytes(ea, b"\x1f\x20\x03\xd5")  # NOP (arm64)
            ea += 4
            continue
        # Replace an always-false Bxx, for example after comparing a register with itself, with NOP so execution falls through
        if is_opaque_branch(insn):
            ida_bytes.patch_bytes(ea, b"\x1f\x20\x03\xd5")
        ea += sz
```

### 2.3 Dynamic confirmation (stalker)

When statics can't tell "which branch is always false", run one real input under frida stalker and compare against the set of actually executed basic blocks — **blocks absent from the trace are junk**; back in IDA, NOP them all. Stalker usage and hang troubleshooting are in `../02-frida/advanced/stalker.md`.

## 3. Control-Flow Deflattening

### 3.1 Principle (the flattened structure)

```
entry: state = INIT
loop: while(1) {
    switch(state) {
        case A: ...; state = C; continue;    // Real block; its tail writes the next state
        case B: ...; state = A; continue;
        ...
        dispatcher update: state variable = case value
    }
}
```

Common arm64 shape: the master dispatcher is a `CMP W8, #imm / B.EQ block` chain or a jump table + `BR X9`. The restoration goal = delete the dispatcher and directly chain the real blocks by their `state` succession (straight jumps).

### 3.2 Four routes (by degree of automation)

1. **Symbolic execution (angr/unicorn traversal)**: treat the state variable as symbolic; symbolic execution collects the real block and successor for each case value; rebuild the CFG and patch. Classic paper: Tencent Security's "Removing Control-Flow Flattening via Symbolic Execution". Suits standard OLLVM with a single dispatcher.
2. **Emulated execution (a self-written interpreter)**: "A Simple Self-Written Arm64 Emulator to Remove Control-Flow Flattening" (2024.12): **function-level** emulation — process only the target function, no need to complete the whole so environment; identify blocks from IDA's CFG info; the key thesis: "no matter the situation, block-to-block links have only 2 outcomes: real block or dispatch block" — satisfying that condition lets you enumerate the result, and it auto-patches all real blocks (source included). Positioned for **complex cases** (multiple dispatchers/nesting).
3. **unidbg trace backtracking**: CodeHook stores register state per instruction into an "instruction stack"; on `BR X9`, look back up to match the four-instruction `ADD→LDR→CSEL→CMP` pattern, and with the saved register state directly compute both true/false targets, then equivalently replace with a conditional jump + direct jump. Suits samples with **indirect-jump arithmetic** layered onto the obfuscation.
4. **Decompiler-stage optimization (d810)**: eshard's D-810 IDA plugin performs deobfuscating optimization at the Hex-Rays microcode layer; the original repo is eshard/d810, and the community-maintained fork d810-ng is still updated. Zero patching, F5 yields clean code directly — but non-standard customized OLLVM needs a self-written optimization pass (the plugin author provides the pass framework).

### 3.3 unicorn deflattening skeleton (a runnable frame)

```python
# Unicorn approach: walk the flattened CFG, build block-to-successor mappings, then patch from those mappings
# pip install unicorn capstone keystone-engine
from unicorn import *
from unicorn.arm64_const import *
import capstone

BASE   = 0x10000                    # Shared-object mapping base; align with IDA's relative base to simplify writing patches back
FUNC   = BASE + 0x8A40              # Target function
FUNC_END = BASE + 0x9F00
STATE_REG = UC_ARM64_REG_W8         # Dispatcher state register, identified statically first

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(BASE, 0x100000)
mu.mem_write(BASE, open("libtarget.so","rb").read())
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

blocks, succ = {}, {}               # state value -> (block start, set of successor states)

def trace_block(state_init, entry_pc):
    """One run: force state=state_init, then execute until the next dispatcher."""
    mu.reg_write(UC_ARM64_REG_X0, 0x1111)     # Restore input arguments from hook observations
    mu.reg_write(STATE_REG, state_init)
    last, cur = None, entry_pc
    hits = []
    while cur < FUNC_END:
        code = mu.mem_read(cur, 4)
        (ins,) = md.disasm(bytes(code), cur)
        hits.append(ins)
        if ins.mnemonic in ("b", "br") or ins.mnemonic.startswith("b."):
            # At a block tail, stop before the branch returns to the dispatcher
            end_state = mu.reg_read(STATE_REG)  # New state written by the block tail
            return entry_pc, end_state, hits
        mu.emu_start(cur, cur + 4, count=1)     # Single-step while preserving the evolving register state
        cur = mu.reg_read(UC_ARM64_REG_PC)
    return entry_pc, None, hits

# 1. BFS over all reachable states from the entry state
from collections import deque
q = deque([INIT_STATE]); seen = set()
while q:
    s = q.popleft()
    if s in seen: continue
    seen.add(s)
    entry, nxt, hits = trace_block(s, DISPATCH_ADDR)
    succ[s] = nxt
    if nxt is not None: q.append(nxt)

# 2. Patch from succ: rewrite each real block's dispatcher-update tail
# Assemble b #target with Keystone, write the bytes into a copy of the shared object, then verify F5 in IDA
import keystone
ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
for s, (blk_end, patch_addr, nxt_entry) in patch_plan(succ).items():
    mc, _ = ks.asm(f"b #{nxt_entry - patch_addr}", patch_addr)
    # write back to so copy at file offset(patch_addr - BASE)
```

Skeleton essentials: single-step with `count=1` + read-PC advance, so you can stop at the dispatcher to read state; walk each state once only; for uncovered branches, modify registers/NZCV and rerun to fill in (one emulation walks only one path).

### 3.4 deflat tooling status (2026-10 snapshot)

- The old angr deflat scripts (the deflat.py family of the cscout/angr ecosystem) circulate scattered online with no unified maintained repo — adapt the dispatcher-identification conditions to your sample before use;
- quarkslab QSynth (deflattening via program synthesis, the academic line) keeps seeing follow-ups;
- In engineering practice, **the steadiest duo remains d810 (pre-F5 cleanup) + unidbg/self-written emulation (pattern patching)**;
- On the jadx side a CFF plugin has appeared, jadx-deflatten (handles Java-layer hashCode-switch flattening) — don't force native-style thinking onto Java-layer obfuscation.

## 4. Indirect Jumps / BR Obfuscation

### 4.1 Shape

OLLVM often layers one more on top of fla: the real target addresses live in an offset table, fetched at runtime as `LDR X9,[X19,X9]; ADD X9,X9,X24; BR X9` (X19=table base, X24=fixed base). IDA statically doesn't understand `BR X9`; F5 jumpout.

### 4.2 Two moves

1. **unicorn single-step to solve the target**: load the so, emulate up to just before the BR instruction, read X9 directly — that's the real target; batch-run all input paths collecting (BR address → target) pairs, then back in IDA `idc.add_cref(ea, target, fl_JF)` to revive the cross-references;
2. **Instruction-stack backtracking, equivalent replacement**: see §3.2 route 3 — after identifying the CMP/CSEL/LDR/ADD four-instruction combo, use the live register state to compute both true/false targets, then replace the BR segment with "one conditional jump + one direct jump", NOPing the CSEL/LDR.

## 5. Understanding the OLLVM Source

### 5.1 The Pass mechanism

OLLVM = LLVM plus three obfuscation passes (Obfuscation passes run at the IR layer):
- **Flattening (fla)**: `Split basic blocks → strung into a dispatcher loop`; the state variable is `alloca+switch`;
- **BogusControlFlow (bcf)**: clones basic blocks and inserts always-false predicates (by default globally-provable odd/even opaque predicates of the `x*(x-1)%2` family);
- **Substitution (sub)**: equivalent rewrites of arithmetic/boolean operations, layered over multiple rounds.
Source-reading entry points: the same-named cpp files under the `Obfuscation/` directory (the structure is public LLVM knowledge).

### 5.2 Active branches (GitHub, 2026-10)

After the original obfuscator-llvm (unmaintained since 2017, based on LLVM 4), community forks are all active:
- **Hikari** (HikariObfuscator/Hikari, 2103 stars): rewrote fla/bcf, added StringEncryption and anti-class-dump;
- **goron** (amimo/goron, 717 stars): focuses on indirect-branch obfuscation (IBR) — exactly the source of the §4-style BR obfuscation;
- **Pluto** (bluesadi/Pluto, 914 stars): Upx-style fla variants and MBA obfuscation;
- **ollvm17** (DreamSoule/ollvm17, 670 stars) / wwh1004/ollvm-16 (271 stars): ports to newer LLVM versions.
The reversing-side value: **understanding the obfuscator's source = knowing the generation rules of the patterns** — write deobfuscation detectors per the generation rules; steadier than blind pattern guessing.

### 5.3 Self-implemented passes and customization directions

Typical customization directions (the generator side's escalation of the arms race; infer them in reverse):
- **Composition timing**: fla runs multiple rounds with different parameters each; bcf predicates picked randomly from a template library; sub depth randomized — hence patterns differ across functions within one so, and scripts must adapt per function;
- **state encoding**: state values are encoded via XOR/addition before comparison — decode one layer first when identifying;
- **dispatcher duplication**: the dispatch block gets copied into every handler's tail (the same move on the VM side against the static idea of "find the unique dispatcher", see §6).

## 6. VMP / Virtual Machine Restoration

### 6.1 VM structure and identification

A native VM = `vmEnter → bytecode pointer → dispatch loop (fetch/decode/jump to handler) → N handlers → vmExit`. Identification signatures: the loop function accounting for 90%+ of traced instructions is the dispatch; high-frequency `BR X8` plus a batch of short functions called only indirectly is the handler pool.

### 6.2 Methodology (five steps)

1. **Handler identification**: classify first — pure arithmetic (add/xor/mov semantics), memory read/write, stack ops, environment calls (JNI/syscalls); tag each handler with a semantic label;
2. **Dispatch-loop dissection**: is the opcode one byte or variable-length instructions (operand encoding, register-slot encoding)? The Meituan-family case restored the full VM architecture, instruction set, and decoding process, and noted that **the fetch basic block of the dispatch gets duplicated as every handler's terminator** — countering the routine of "find the unique dispatch location in the trace"; when identifying, cluster by "repeatedly appearing fetch sequences" rather than by address;
3. **Building the opcode mapping table**: construct known inputs yourself (white-box method: write a demo function containing each instruction type, harden it, compare traces), progressively filling the opcode→handler→semantics table;
4. **Trace comparison**: write a plaintext implementation of the same feature, trace both sides simultaneously, align by data flow — the VM's handler sequence ≈ the plaintext instruction sequence;
5. **Bytecode back to high-level language**: once the mapping table is complete, write a lifter (opcode stream → pseudo-IR → human reading / compile back to C). A certain short-video app's libEncryptor.so contains three independent VMs, with instruction encoding borrowing arm64 rules.
6. **Material roundup**: GitHub airen3339/awesome-vmp collects the VM-protection series.

### 6.3 dex VMP (the Java layer)

The trio: opcode permutation + JNIEnv reshuffling + bytecode decryption; trace comparisons and repair order are not expanded here. Core mantra: **having the trace means half the success; the handler dense with JNI calls is the invoke instruction's handler.**

## 7. Toolchain

| Tool | Positioning | Status (2026-10) | Notes |
|---|---|---|---|
| IDA + d810/d810-ng | Decompile-stage deobfuscation | Usable | Microcode-layer optimization; needs IDA 7.7+/8.x |
| IDA + self-written IDAPython | pattern patch | Always available | §2/§4 cref repair, NOP batch processing |
| unidbg | so-level emulation + CodeHook tracing | Active | JNI environment ready out of the box; first choice (`05-toolbox`) |
| unicorn | pure instruction emulation | Active 2.x | the base for self-built deobfuscation engines (§3.3 skeleton) |
| angr | symbolic execution | Usable | deflat/constraint solving |
| BinaryNinja | HLIL-layer scripted analysis | Active | IL steadier than F5; good for writing automated recognition |
| Ghidra | free decompilation | Active | budget-sensitive alternative; decompiler scripting ecosystem weaker than IDA |
| Keystone | assembly backfill | Active | the last step of patching to disk |
| frida stalker | real-device instruction tracing | Active | the mutex_lock hang switch method (see `../02-frida/advanced/stalker.md`) |

### 7.1 angr symbolic-execution skeleton (flattening state traversal)

```python
# angr approach: symbolize the state variable and solve each case's real successors
import angr, claripy

proj = angr.Project("libtarget.so", auto_load_libs=False)
FUNC = 0x8A40                       # Relative base aligned with IDA
cfg = proj.analyses.CFGFast(normalize=True)   # Build the CFG and recover basic blocks first

state = proj.factory.blank_state(addr=FUNC)
state_var = claripy.BVS("st", 32)   # Dispatcher state variable; locate its SSA representation in the actual sample
# Hook the dispatcher, bind W8 or its stack slot to a symbolic value, then solve in a loop
sm = proj.factory.simulation_manager(state)

real_succ = {}                      # state value -> successor state value
while sm.active:
    for s in sm.active:
        if s.addr in DISPATCH_BLOCKS:
            v = s.solver.eval(state_var)      # Current case value
            nxts = s.solver.eval_upto(state_var_next, 8)  # Solve the successors
            real_succ.setdefault(v, set()).update(nxts)
    sm.step()                                # Advance symbolic execution through all branches

# Recover the pre-flattening graph: DFS over real_succ to produce block order, then a patch plan
# ARM64 shared objects require correct address and PLT handling; angr loader semantics may be unreliable for a given library
# A practical fallback is a three-stage pipeline: angr solves successors, Unicorn verifies, Keystone patches
```

### 7.2 unicorn single-step to solve BR targets (with §4)

```python
# Collect the actual target table for BR X9
targets = {}
def br_hook(u, addr, size, ud):
    if addr in BR_SITES:                      # Locate all BR instruction addresses through static analysis or single stepping first
        targets[addr] = u.reg_read(UC_ARM64_REG_X9)
mu.hook_add(UC_HOOK_CODE, br_hook)            # Instruction callback: read X9 at BR to obtain the target
# After multiple inputs, write targets back to IDA with idc.add_cref(ea, t, idc.fl_JF)
```

## 8. Decision Tree (how to pick the route once you have an obfuscated so)

```
Q1 Is F5 readable?
 ├─ Yes → no deobfuscation needed; go straight to algo-restoration-methodology.md §2 algorithm identification
 └─ No ↓
Q2 Is the disassembly itself derailed (pseudo-instructions/garbage bytes)?
 ├─ Yes → junk code: §2 static NOP / stalker to confirm junk blocks → back to Q1
 └─ No ↓
Q3 Is F5 a giant switch(state) or a jumpout (BR)?
 ├─ Standard OLLVM fla → try d810 first (zero cost) → if it fails, §3 emulated execution
 ├─ BR indirect jumps → §4 unicorn to solve targets + add_cref to rescue the CFG → back to Q1
 └─ Neither ↓
Q4 Is the function body one dispatch loop + a sea of handlers?
 ├─ Yes → VMP: first ask "do you want the algorithm or the logic"
 │    ├─ Only input/output → stop; L2: unidbg environment completion, black-box recomputation (pure-computation methodology §6)
 │    └─ Full logic wanted → §6 five-step methodology (handler classification → decoder → mapping table → lifter)
 └─ No ↓
Q5 Obfuscation multiply nested / multiple dispatchers, still messy after three patch rounds?
 └─ Admit there is no universal kill → go pure dynamic: stalker trace + input/output cross-check (§0 iron law 3)
```

Cost ordering (cheap to expensive): d810 one-click → IDAPython pattern patch → unicorn/unidbg emulated traversal → self-written lifter → manual reversing. **Before dropping one tier, ask why the tier above failed**; skipping tiers straight to manual reversing is the novice's biggest time sink.
