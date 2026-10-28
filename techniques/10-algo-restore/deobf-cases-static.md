# Deobfuscation Case Collection (Static): Copyable OLLVM/Junk-Code Workflows

> Positioning: `deobfuscation-practice.md` is the methodology overview; this file is the copyable workflow from 8 hands-on case posts — steps/scripts/disassembly signatures. Six sections: junk-code identification & removal / IDA+Hex-Rays / Binary Ninja / ARM64 special topics / string-obfuscation repair / IDA&FRIDA joint debugging. The cases are mostly ARM/ARM64/Thumb mobile native; the x86 junk-code identification signatures are universal.

## 1. Junk-Code Identification and Removal

### Identifying and Avoiding Junk Code in Disassembly
Author: skeep

Core premise: x86 instructions are densely encoded — 98% of 16KB of random data disassembles into valid instructions — **disassembling successfully ≠ real code**. The feature checklist for judging "is this region garbage" (Ring0 instructions are legitimate only when analyzing bootloaders/kernels/drivers):
```
Ring-0 privileged/junk-code candidates in userspace: IN/INS/INSB/INSW/INSD  OUT/OUTS/OUTSB/OUTSW/OUTSD  IRET/IRETD  ARPL  ICEBP/INT 1  CLI/STI  HLT
Unusual convenience instructions: generally hand-written rather than compiler-generated; nearly 1% of opcode space and frequent in junk sequences
  ENTER/LEAVE (compilers often use PUSH/MOV/SUB)  LOOP/LOOPE/LOOPZ/LOOPNE/LOOPNZ  PUSHA/POPA (also saves SP)
Unlikely arithmetic instructions:
  F*/WAIT/FWAIT (floating point; exceptions include FPU-based shellcode self-location and legitimate 3D code)  SAHF/LAHF (unusual compiler output)  AAA/AAS/AAM/AAD (legacy one-byte BCD)
  SBB (roughly 3.5%, similar to SUB; legitimate for 64-bit math in 32-bit code)  XLAT (one-byte table lookup)  CLC/STC/CLD/STD (legitimate near REP string operations)
Far-pointer instruction candidates, associated with 16-bit code; inspect carefully in 32-bit code: LDS/LSS/LES/LFS/LGS
```
**Instruction-prefix signals**: 32-bit code full of 16-bit registers (AX instead of EAX — the prefix bytes land in the ASCII letter range, frequent in disassembly text); frequent `LOCK/BOUND/WAIT` before mnemonics; segment prefixes `FS:/GS:/SS:/ES:` on instructions that **don't address memory**, `POP SS`, writes to segr7 → junk code (legitimate 32-bit code uses FS/GS only in specific scenarios). Usage: the above features appearing frequently and in swaths → judge the whole segment garbage; don't read it as code.

### Android Notes: Removing Junk Code and Restoring the Algorithm
Author: neilwu

**Sample**: Qiangwang Cup flower.apk (ARM32 Thumb), JNI `MainActivity.check` → `sub_F34` (input validation), inside which `sub_F8E`/`sub_FD0` won't F5. **Flow 1: JUMPOUT repair (Thumb)** — F5 emitting `JUMPOUT(...)` = the function got shredded into fragment functions; follow IDA's hint to find the real landing (e.g., `sub_F8E` should jump to `0xFA4 = 0xF98+0xC`), patch an unconditional B at 0xF98:
```python
def put_unconditional_branch(source, destination):
    offset = (destination - source - 4) >> 1
    if not (-2097152 <= offset <= 2097151): raise RuntimeError("Invalid offset")
    if offset > 1023 or offset < -1024:    # Outside the 11-bit conditional-branch range; patch a 4-byte B.W using the 0xF000/0xB800 prefix/suffix pair
        PatchWord(source, 0xf000 | ((offset >> 11) & 0x7ff)); PatchWord(source+2, 0xb800 | (offset & 0x7ff))
    else: PatchWord(source, 0xe000 | (offset & 0x7ff))
```
After patching, U-undefine the function region then P-recreate — F5 works; `sub_FD0` same method.

**Flow 2: junk-code byte-pattern removal** — the shape (disassembling into `MOV R3, PC`-style: writes PC into a register to cause misalignment, garbage data right after gets sliced into instructions), 26 bytes:
```
8F 46 [r] 46 00 DF 8F BD BF 46 70 47 [n] BC 8E BC 08 46 11 46 1A 46 3B 46 80 BC  → 00 × 26
```
Signatures: the first two bytes `8F 46` fixed; the 3rd byte (register number) varies; the skeleton `00 DF`/`8F BD` etc. fixed; after `70 47` comes a varying `xx BC`; multiple groups in one function differ only in the register byte and small constants. After dynamically confirming non-execution (non-executable junk) or no effect (executable junk), wholesale-replace with 0, P-recreate the function, F5.

**Flow 3: algorithm restoration** (post-deflowering pseudocode still obfuscated: lots of `(&dword_0+3)` junk arithmetic + mixed JUMPOUT, verified by dynamic debugging):
1. CRC16 (polynomial 0x1021) computes the input's check value `v5`;
2. `v12=v5&0xF`, `v13=(v5>>8)&0x3F` decide the padding parameters; first-char padding + plaintext + trailing-char padding out to 128 bytes;
3. 16 rounds × 8-byte block encryption: each round XORs with key1 `{0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88}` and key2 `{0x77,0x23,0x9D,0xAC,0x13,0x27,0xCF,0xFE}`, then 28×(v5&0xF+16) rounds of 4-bit nibble rotation (high/low nibble swap combos), finally a whole-buffer XOR with 0x88;
4. Compare against the 128-byte target ciphertext.
Key point: **junk code only blocks statics — the algorithm itself is usually symmetric lightweight custom block crypto**; after deflowering, split it into the four segments "check → padding → round function → compare" (keys and intermediates fetched dynamically with breakpoints at `loc_11B0`/`loc_10AA`).

## 2. The IDA+Hex-Rays Route

### Hex-Rays: Ten Steps to Kill One Man, Two Steps to Shred OLLVM-BCF
Author: 葫芦娃

BCF principle: constructs opaque predicates from **global variables that are initialized but never written**; the result is constant → only the real branch ever executes. Typical F5: `while(1){ do{ ...a pile of constant tests like if(dword_XXX & 1)... }while(v10^1); }`, the predicate variables living in the .data segment (`dword_B004 DCD 0xD14E403C` heading a contiguous dword table).
**Two-step removal**: Hex-Rays' built-in DCE could already eliminate always-false branches; it doesn't because the global-variable segment the predicates use is **writable** (the optimizer can't assume constancy). Operation: `Edit Segment` → select `.data` → **uncheck Write** → re-F5; the predicates fold as constants and the bogus branches all vanish. Boundaries: cleanest when .data holds only BCF predicate variables; effective since IDA 6.9; changes only the analysis view, not the file.

## 3. The Binary Ninja Route

### Using Binary Ninja to Remove OLLVM Control-Flow Flattening
Author: krash

**Samples**: libvdog.so (Nagapt) + a self-compiled cff (both ARM64 fla). Toolchain: Binary Ninja (HLIL) analysis + Keystone assembly + an IDA new segment holding the patch. **The analysis stage** extracts three things: each case's entry block, exit block, and the exit jump's target case (for conditional exits, also the true/false branches and their cases):
- **Case-entry identification**: when LLVM generates switch code that can't use a jump table, it degrades to **binary search** — the search must end with one exact test on the case number: `bool cond = x9.w9 != 0x76579ace; if (cond) then 0x704f0 else 47@0x70688` → the false branch 0x70688 is the case entry; `if (x8 == 0xdcf244e1) then 439@0x71080` → the true branch is the entry;
- **Case-exit identification**: basic blocks containing "an assignment to the state variable": `aop_init(); uint64_t x8_1 = 0xc88d21cd; goto 0x704f0` (writes the new state back to the dispatcher);
- **Conditional true/false correspondence**: the two state-assignment blocks at a case's tail; check the target block's incoming-edge type:
```python
def resolve_branch_condition(state):
    il_bb = state.il_basic_block
    assert len(il_bb.incoming_edges) <= 1
    return il_bb.incoming_edges[0].type == BranchType.TrueBranch if len(il_bb.incoming_edges) == 1 else True
```
Boundaries (may also be conservatively skipped): a block that is **simultaneously a case entry, an exit, and part of the dispatcher**; variable-vs-variable comparisons inside the dispatcher need backtracking; anything unhandled goes unpatched, keeping the original dispatcher — **conservative repair** affects only restoration completeness, not correctness.

**The repair stage**: the hard parts are finding patch caves and compiler-optimized code motion. Strategy: **don't squeeze space at the original addresses — create a new IDA segment (0x4000000) holding all patch code, intentionally keeping the original dispatcher** — cases whose successors went unrecognized still route through the original dispatcher; once all state successors are patched, the dispatcher becomes unreachable and is optimized away automatically.

**Pitfall: compiler block merging** (no other article covers it): the common head/tail of two cases gets merged by the compiler into one block:
```c
case 1: case 2: {
  puts("enter case 1 or 2");          // Shared entry block, belonging to neither individual case
  if (state_var == 1) { puts("case 1"); state_var = 2; }
  else               { puts("case 2"); state_var = 3; }
  puts("exit case 1 or 2");           // Shared exit block
}
```
The fix = **code copying**: copy every instruction on the paths "dispatcher entry → case entry" and "case exit → dispatcher entry" into the patch region; after patching, the executed sequence = the original case's instructions + the copied instructions — semantically equivalent, split back into independent cases; unrecognized cases fall back into the dispatcher and still work out right.

**Multi-exit cases**: one case can have multiple exits (TBNZ/CBZ/CSEL+B coexisting) — **every exit must be patched individually**. Single-exit template (exit 1 patched to jump to the patch, exit 2 kept):
```
b    patch_code                      ; Redirect exit 1 to the patch; original: tbnz w8,#0,to_dispatcher
cont: ...                           ; Preserve exit 2: cbz w0,to_dispatcher
patch_code:
tbnz w8, #0, to_case_entry          ; Reproduce the original exit semantics
b cont
to_case_entry:
  [instructions overwritten by the patch]
  [all instructions from this block to the dispatcher entry]     ; copied code
  [all instructions from dispatcher entry to target case entry]   ; copied code
  b target_case
```
Dual exit (CSEL-style) — **you cannot jump away right after CSET; the following MOV is a live instruction**:
```
cset w7, eq                   ; Preserve this; do not branch early. Original: csel w7,w15,w14,eq
mov  w20, w0
b    patch_code
patch_code:
cbnz w7, true_branch
cbz  w7, false_branch
true_branch:  [overwritten instructions][to dispatcher][dispatcher to true branch]   b true_target
false_branch: [overwritten instructions][to dispatcher][dispatcher to false branch] b false_target
```
Concrete instance (vdog 0x704dc; the predecessor loc_704CC's `LDR W9,[X19,#0x18]` would be overwritten): the patch region first re-emits `LDR W9,[X19,#0x18]`, then the original block's `STR W9,[X19,#0x1C]`, then copies the whole dispatcher binary-search CMP chain, ending with `B loc_70778` (the successor of 0x6fa40fc9). Engineering numbers: the vdog JNI_OnLoad repair ran 21KB of patches/15 minutes; copied instructions must be **dead-code-filtered** or the function grows too big for IDA to decompile; copying PC-relative instructions (calls/global references) requires **relocation repair**; the vdog JNI_OnLoad has **6 dispatchers** (customized ollvm or inline) — state-variable and dispatcher auto-recognition remains a to-do; verification: after restoring a four-branch fla function, F5 matched the source semantics, and JNI_OnLoad's anti-debug/signature checks/package-name checks all became readable.

## 4. ARM64 Special Topics

### ARM64 OLLVM Deobfuscation
Author: 无名侠

Pure Unicorn+Capstone emulated execution (no angr/miasm — their arm64 support is poor). Block bisection: **bogus blocks contain only flow-control instructions; real blocks contain any real instruction**; the crux is finding the ordering/branch (csel) relations between real blocks, then Keystone-patching direct jumps.

**Step 1: Capstone disassembly into blocks + reference counting** (`md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True`):
```python
# Walk md.disasm(bin1[offset:end], offset); a branch/ret with nonempty i.groups ends a block; save saddress/eaddress/ins
# Record immediate operands as naddress; self-jumps belong in dead_loop; count references with processors[imm] += 1
for dead in dead_loop: processors.pop(dead, None)   # This Naga sample contains dead-loop paths; exclude them
```
**Step 2: identify real blocks** — first pass: a target referenced by >1 block is the dispatcher; blocks referencing the dispatcher are candidates (`naddress in processors and processors[n]>1`); second pass (signatures): bogus blocks may also reference the dispatcher, so match by an "instruction mnemonic + operand types" signature (independent of registers/constants):
```python
def get_code_sign(block):      # Concatenate mnemonic and operand-type signatures, for example 'movz' + '12' for immediate and register
    sign = ''
    for i in block['capstone']:
        sign += i.mnemonic
        for op in i.operands: sign += str(op.type)
    return sign
# OLLVM bogus-block signatures, accumulated per sample:
ssign = {'b2','cmp11b.ne2','cmp11mov11b.ne2','movz12movk12b2','movz12movk12cmp11b.ne2',
         'movz12movk12cmp11mov11b.ne2','movz12movk12movz12movk12b2','movz12movk12cmp11movz12movk12b.eq2',
         'movz12movk12cmp11movz12movk12b.ne2','ldr13b2','...'}
def is_real_block(item):
    sign = get_code_sign(item)
    if sign in ssign or sign.endswith('movk12movz12movk12b.ne2'): return False
    return any(insn.mnemonic not in ['movz','movk','cmp','b.eq','b.ne'] for insn in item['capstone'])
# Any non-control-flow instruction identifies a real block; after filtering fake blocks, add unreferenced ret blocks to real_blocks separately
```
**Step 3: Unicorn emulated execution to find successors**:
```python
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(0x80000000, 0x10000*8); mu.reg_write(UC_ARM64_REG_SP, 0x80000000+0x10000*6)   # Stack
mu.mem_map(0, 4*1024*1024); mu.mem_write(0, bin1)       # Code region; map the shared object at base 0
mu.hook_add(UC_HOOK_CODE, hook_code); mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_access)
```
hook_code's five core tricks (all inside the per-instruction callback):
- ① Skip an instruction (disable bl/non-stack memory access, masking real-code side effects): `mu.reg_write(UC_ARM64_REG_PC, address+4)`;
- ② Memory-access whitelist: an operand contains `[` and the target is outside the stack region 0x80000000~+0x80000 → skip that instruction; bl/blx always skipped (we want only the ollvm path, not real execution results);
- ③ Hit the next real block: `isSucess=True; distAddr=address; mu.emu_stop()`;
- ④ Manual csel branch control (ollvm's conditional dispatch picks the state via csel): read v1/v2, write `regs[0]=v1/v2` per `branch_control`, then PC+size;
- ⑤ Mini breakpoint debugger: a hit address enters single-step; '>' + Enter steps over / 's' stops / 'r' quits / '!x0' prints a register.

Register-name conversion + context save/restore + path search:
```python
def reg_ctou(regname):   # Capstone name to Unicorn constant: w0-w28 -> W0+index; x29 -> 1; x30 -> 2; other x registers -> X0+index; sp -> 4
def get_context():  return [mu.reg_read(UC_ARM64_REG_X0+i) for i in range(31)] + [mu.reg_read(UC_ARM64_REG_SP)]
def set_context(regs):
    for i in range(31): mu.reg_write(UC_ARM64_REG_X0+i, regs[i])
    mu.reg_write(UC_ARM64_REG_SP, regs[31])
def find_path(start_addr, branch=None):
    # emu_start(start_addr, 0x10000); on UcError with pc!=0, continue through find_path(pc+4, branch); return distAddr or None
queue, flow = [(offset, None)], {}          # BFS items are (block address, register context), so each block searches successors under a consistent context
while queue:
    pc, ctx = queue.pop(); set_context(ctx)
    if pc in flow: continue
    flow[pc] = []
    # csel block: p1=find_path(pc,0); restore saved state, then p2=find_path(pc,1); append each resolved (p, get_context()) to the queue
    # Sequential block: p=find_path(pc); append the resolved (p, get_context()) to the queue
```
Result: draw the flow graph with graphviz; write back per flow with Keystone — sequential block tails `ks.asm("b #%x" % dist)`; csel blocks `ks.asm("b%s #%x;b #%x" % (cond, d1, d2))` (cond taken from the csel condition code).
Takeaway summary: reference counting finds the dispatcher → signature filtering drops bogus blocks → Unicorn one-way search of each real block's successor (csel both ways) → the flow dict → Keystone write-back; instructions inside real blocks aren't emulated for side effects (bl/memory access all skipped) — only the state flows.

### ARM64 OLLVM Deobfuscation (Continued)
Author: FraMeQ

Patches on the previous piece (the master idea unchanged: identify real blocks/prologues/retn/garbage blocks → determine before/after relations by emulation or symbolic execution → repair):

**Pitfall 1: tutorial CFGs don't match reality** — tutorial samples are Debug builds that keep a "pre-dispatcher" (locatable with the classic method from "Removing Control-Flow Flattening via Symbolic Execution"); real-world Release builds optimize the pre-dispatcher away, the CFG shape differs completely, and the classic method fails. **Confirm the target so's optimization level before choosing a locating method**.
**Pitfall 2: two flaws of reference counting** — when sub-dispatchers follow the dispatcher, they too get misjudged as real blocks (the original scheme patched this with signatures); and it **misses** some real blocks.

**Finding real blocks, three iterations** (on angr's CFG supergraph):
- Idea 1 (failed): the most-referenced block = the master dispatcher; blocks referencing it = real blocks — under Release, some real blocks reference **sub-dispatchers**, producing misses (not mis-hits);
- Idea 2 (filling the misses): DFS from the master dispatcher over successors recording the visit list; when the current block's successor is already in the list (a cycle back to the dispatcher) → the previously visited block is a real block:
```python
def get_relevant_nodes(supergraph, node, founded_node):
    founded_node.append(node)
    for i in supergraph.successors(node):
        if i not in founded_node: get_relevant_nodes(supergraph, i, founded_node)
```
- Idea 3 (handling merged blocks): Release merges adjacent real blocks' common code (two puts optimized into one) → a real block's predecessors are still real blocks. Rule: **if a node's sole successor is an already-identified real block, the node is also a real block** (add a single-successor check in the function above, appending `supergraph.predecessors(node)` into relevant_nodes).
Still unsolved (manual backstop): with -bcf stacked, dead-loop blocks appear and real blocks get split in two — the first half unidentifiable → hand-add to the list; individual patched conditional jumps have completely inverted conditions (true/false targets swapped) and need manual verification. Reference: GitHub cq674350529/deflat (angr-based symbolic-execution deflattening; the supergraph-based block-classification idea).

## 5. String-Obfuscation Repair

### OLLVM String-Obfuscation Repair
Author: einsteinzl

Scenario: Armariris (SJTU GoSSIP, based on ollvm) string encryption. Traits: **the decryption functions live in initArray; equal-length encryption, decrypted in place back to the original .data position** — once the so finishes loading, the strings are already restored in memory; you can dump once and backfill the static file. Steps:
1. In IDA look at initArray: a batch of `.datadiv_decodexxx`-named functions — those are the Armariris decryption functions (each covering a batch of encrypted strings);
2. `readelf -S libxxxxx.so` to find the encrypted-string-table section's file offset and size (measured 0x7f0000/0x1ca8, the tail area of .data);
3. gdb attach to the running process (so loaded, initArray executed) and dump that memory range — the decrypted plaintext table;
4. Backfill the 0x1ca8 bytes **directly into the so file's .data at the same offset**; reload in IDA: all strings readable, cross-references resolve normally;
5. Directly above the table sits an **offset table** (initialized at load time to actual virtual addresses, not ciphertext) — after backfilling, correct it with a beyond-compare-style tool;
6. For the repaired so to run normally, **remove the decryption-function registrations from initArray** (the strings are already plaintext; re-decrypting would corrupt the data).
Essence: leveraging "equal-length + in-place decryption" to snapshot the runtime state into statics once. Applicability test: the body of `.datadiv_decode` is a loop XOR/table lookup over a fixed range, and the write target coincides with the ciphertext range.

## 6. IDA&FRIDA Joint Debugging

### A First Try at Joint IDA&FRIDA Debugging of the Source of an Encrypted Function Protected by Simple OLLVM
Author: 无造

Scenario: an encryption function with light fla obfuscation; IDA Trace yields logs but locating the computation points is hard → "IDA reads structure statically + Frida hooks cross-check the data flow" to restore the full C source. With light obfuscation F5 stays readable — an order of magnitude faster than chewing through trace assembly.
1. **Entry locating**: inside function e, a direct call to `sub_1500C(v42, v41)` (v42=input bytes, v41=output key); hook to verify args and return:
```javascript
Interceptor.attach(base_native.add(0x1500C), {
  onEnter: function (args) {
    this.args0 = args[0];   console.log("args0:", hexdump(this.args0));
    var args1addr = ptr(args[1]).add(Process.pointerSize*2).readPointer();   // Second-level args[1] structure: the string data is referenced at offset 2*8
    console.log("args1:", args1addr.readCString());
  },
  onLeave: function (retval) {   // The output is not retval: it is in the buffer referenced at args0+5*8; probe nested return structures to locate the result
    console.log("onLeave:", hexdump(ptr(this.args0).add(Process.pointerSize*5).readPointer()));
  }
});
```
2. **Layer-by-layer drill-down** (IDA static) + register conventions: `sub_1500C` computes the total post-encryption length (lenStr+6 header+padding), imports the hardwired string `"www.pediy.com&kanxue"`, and tail-calls `sub_13CE4` (x0=input string/x1=length/x2=fixed string/x3=fixed-string length/x4=output buff); `sub_13CE4` core: a 6-byte header (fixed `79 79` (yy)+`03`+lenPadding+`00 01`) → copies the plaintext → table lookups via `byte_42108` (0x63,0x7C,0x77,0x7B… i.e., the AES S-box) replacing byte by byte → `sub_13808` generates a 0x10-byte round key from the fixed string (the fixed string first passes the S-box, then bswap32 per 4-byte group) → `sub_172D0` does 3 modes of byte rotation (AABBCCDD→BBCCDDAA style) → the rotated result XORs with the round key `key[i%4]`, including `part>>(32-i%4*8) ^ part<<(i%4*8)` shift mixing;
3. **Restoration verification**: write a C replica (myenc) per the structure; same input with identical output hex = success.
Reusable takeaways: when hook args are nested objects, probe slot by slot with `ptr(args[n]).add(k*8).readPointer()`; when the return value hides in an argument buffer structure, read it back in onLeave from `this.args0+k*8`; under light obfuscation, "static layering for structure + dynamic verification of data flow only" is an order of magnitude faster than pure dynamic tracing; recognition accelerators: a 256-byte table starting 0x63,0x7C,0x77,0x7B is the AES S-box, and bswap32 + grouped shift-XOR is the usual look of round-key scheduling.
