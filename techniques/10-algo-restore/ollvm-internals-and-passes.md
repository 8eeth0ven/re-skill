# OLLVM Internals and Pass Source Code

> Positioning: a source-level teardown on the **generator** side of the obfuscator — how the fla/split/bcf/jump-encryption/string-encryption passes are written at the LLVM IR layer, plus the complete playbook for writing your own obfuscation pass; complements `deobfuscation-practice.md` (the reverse/restoration side): understand the data structures and key instruction sequences, and deobfuscation detectors can be derived from the generation rules.

## 1. Obfuscator Overview and Build

### OLLVM Quick Start
Author: 七少月

llvm-4.0.1 official source vs ollvm (llvm-4.0 branch), compared with BeyondCompare (ignore timestamps, file-only mode); the diffs concentrate in: `include/llvm/Transforms/obfuscation/` — 6 headers, 5 corresponding to the compile flags `fla` (control-flow flattening) / `sub` (instruction substitution) / `bcf` / `split` / `aesSeed`, with `Utils.h` as the utility box; `lib/Transforms/obfuscation/` holds the cpp implementations; registration goes through `lib/Transforms/CMakeLists.txt` + `LLVMBuild.txt` additions to the build, completed by `IPO/LLVMBuild.txt` + `PassManagerBuilder.cpp`.

**The pass registration chain** (paving the way for self-written passes): `PassManagerBuilder.cpp` imports headers → adds cl::opt flags → global `aesSeed` initialization (`cryptoutils->prng_seed()`) → `createSplit/createFlattening/createBogus/createSubstitution` get stuffed into the pipeline → factory functions declared in the same-named .h. **The bcf call chain**: `struct BogusControlFlow : public Pass` (ModulePass) → `runOnModule` → `bogus(f)` → `addBogusFlow(BB1, BB2)` is the core; `CryptoUtils` provides the `get_bytes/scramble32` random primitives.

**phi elimination**: real assembly has no phi; before processing, `reg2mem` lowers it to load/store: `b=phi(a1,a2)` → each of the two predecessors does `store value->slot`, and the use site becomes `b=load slot`. **Industry view**: ollvm needs source (binary hardening requires a self-built disassembly engine to lift instructions into virtual instructions); **when only LLVM IR is available there is no virtualization, only obfuscation**.

### Installing and Using ollvm 8.0 on Windows 10 + Android Studio 3.6.1 (condensed into a command section)
Author: 天河霜雪

Source at GitHub `heroims/obfuscator`, llvm-8.0 branch; CMake generates a VS2019 project and compiles for 20-40 minutes; the artifacts in `Release/bin/` (clang.exe etc.) replace the same-named files under the NDK's `toolchains/llvm/prebuilt/windows-x86_64/bin/` (NDK 20.1); for missing headers, copy `__stddef_max_align_t.h/float.h/stdarg.h/stddef.h` from the NDK `sysroot/usr/include`; enable obfuscation in `build.gradle` with: `cppFlags "-mllvm -sub -mllvm -bcf -mllvm -fla"`.

## 2. The Control-Flow Flattening Pass Source (Flattening)

### OLLVM Source Analysis — The Flattening Pass
Author: freakish

Function-granularity `FunctionPass`; `toObfuscate(flag, tmp, "fla")` checks `__attribute__((annotate(("fla"))))` or `-mllvm -fla`; on pass, `flatten()`:

**① Seed + ② eliminate the source switch / first-block handling**:
```cpp
char scrambling_key[16];
llvm::cryptoutils->get_bytes(scrambling_key, 16);
createLowerSwitchPass()->runOnFunction(*f);   // Lower existing switches to if/else so all blocks follow the dispatcher transformation
// Collect all basic blocks in origBB and remove the entry block; splitBasicBlock(i,"first") if its terminator is conditional or it has multiple successors
```

**③ Build the skeleton** (CFG: first block writes the state initial value → loopEntry (load+switch) → each case block ↔ loopEnd ← swDefault):
```cpp
switchVar = new AllocaInst(Int32Ty, 0, "switchVar", insert);
new StoreInst(ConstantInt::get(Int32Ty, cryptoutils->scramble32(0, key)), switchVar, insert);  // Initial state value
load = new LoadInst(switchVar, "switchVar", loopEntry);    // Load state inside loopEntry
insert->moveBefore(loopEntry);  BranchInst::Create(loopEntry, insert);   // Entry block -> loopEntry
BranchInst::Create(loopEntry, loopEnd);  BranchInst::Create(loopEnd, swDefault);
switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, loopEntry);  switchI->setCondition(load);
```

**④ Fill the blocks into the switch** (all case values pass through `scramble32` — the reason case values look patternless across functions of the same so; `i->moveBefore(loopEnd)` is a purely visual move with no logic):
```cpp
for (each block in origBB) {   // numCase = ConstantInt::get(condTy, scramble32(getNumCases(), key))
  switchI->addCase(numCase, i);
}
```

**⑤ Rewrite block tails** (three cases by successor count): 0 successors (return blocks) untouched; 1 successor — delete the terminator, look up the successor's case value, `new StoreInst(numCase, load->getPointerOperand(), i)` + `br loopEnd` (write the new state back, loopEnd re-dispatches); 2 successors (conditional branch) folded into a state selection with `SelectInst`:
```cpp
ConstantInt *numCaseTrue  = switchI->findCaseDest(term->getSuccessor(0));
ConstantInt *numCaseFalse = switchI->findCaseDest(term->getSuccessor(1));
// If a successor has no case and falls through to default, use scramble32(getNumCases()-1)
SelectInst *sel = SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "", term);
new StoreInst(sel, load->getPointerOperand(), i);  BranchInst::Create(loopEnd, i);
```
`findCaseDest(succ)` looks back in the switch for the successor block's case value; the true/false two ways → `sel = cond ? caseTrue : caseFalse`, written in one shot.

**The final IDA F5 shape**:
```c
int state = 0x123456;
while (true) switch (state) {
  case 0x654321: /* real logic B */ state=0x...; continue;   case 0x123456: /* real logic A */ state=0x...; continue; }
```

## 3. Basic-Block Splitting (SplitBasicBlocks)

### OLLVM Source Analysis — The SplitBasicBlocks Pass
Author: freakish

Function-granularity `FunctionPass`; `runOnFunction` validates the `-mllvm -split_num=x` range **(1,10]**, then `toObfuscate(..., "split")` → `split()`:
```cpp
void SplitBasicBlock::split(Function *f) {
  std::vector<BasicBlock *> origBB;               // Collect all basic blocks; validity checks omitted
  for (each block in origBB) {
    std::vector<int> test;
    for (unsigned i = 1; i < curr->size(); ++i) test.push_back(i);  // Generate indices 1..n-1
    if (test.size() != 1) { shuffle(test); std::sort(test.begin(), test.begin()+splitN); }
    BasicBlock::iterator it = curr->begin();  BasicBlock *toSplit = curr;  int last = 0;
    for (int i = 0; i < splitN; ++i) {
      for (int j = 0; j < test[i]-last; ++j) ++it;   last = test[i];       // Advance to the next split point
      if (toSplit->size() >= 2) toSplit = toSplit->splitBasicBlock(it, name + ".split");  // Split successively
    }
  }
}
```
**The cut-point algorithm**: n instructions generate `[1,n)` → shuffle → sort only the first splitN → those are the cut positions (e.g., `[2,4,5]` cuts into 4 segments).

**The iterator trap**: the `it` reused in the loop never invalidates — `splitBasicBlock` internally updates it to **the begin() of the new block (the latter half)**; the next round's `++it` proceeds from the new block's base.

`BasicBlock::splitBasicBlock` semantics (official): instructions before the cut point stay in the original block, the remainder including the terminator gets spliced into the new block (inserted after the original), and an unconditional jump is appended to the original block's tail; the incoming block of PHI nodes in successor blocks is fixed from this→New, else semantics break. PHI = the product of SSA constraints: `a=1; if(v<10) a=2; b=a` → under SSA, `b=PHI(a1,a2)`, taking a version according to the control-flow arrival path.

**Effect**: each block is cut into x+1 blocks chained by unconditional jumps `entry→entry.split→...`; **the point of split is to feed fla** — the finer the blocks, the more numerous and more random the cases after flattening.

## 4. Instruction Bloat and Junk Code (Self-Written Packer / the x86 Generator Side)

### Notes on Writing a Protection Packer — Instruction Bloat and Junk-Code Insertion
Author: Wszzy

A self-written protection packer = PE handling/obfuscation virtualization/protection; the obfuscation engine's three pieces:
1. **Code-block splitting**: split code blocks at jump instructions, tagging attributes (`JCC`/`NULL`/`End`);
2. **A global address manager**: during obfuscation the size of the next block after bloating is unknown, so the manager must dynamically allocate block addresses and chain them (deduplicated, chunked against the load base 0x401000), with a simple relocation;
3. **The obfuscation process = splitting + address management + instruction bloat + junk code**.

**Instruction bloat (equivalent replacement)**, `push 0x123456` → precompute `imm=(0x123456+0x111111)^0x22222` offline, restore at runtime:
```asm
push eax;  mov eax, imm;  xor eax, 0x22222;  sub eax, 0x111111   ; Invert the arithmetic to recover 0x123456
push eax;  mov eax, dword ptr [esp+0x4]
```

**Junk-code insertion** (`_flower_code` global switch gated at %100 probability, asmjit-implemented, three random modes):
```cpp
void CodeObfuscationEngine::_insert_flower_code(asmjit::X86Assembler *&_a) {
  if (_insert_junk_code_number % 100 > _flower_code) return;
  switch (rand() % 3) {  // Cases 0/1: jump over one fake E8/E9 byte using Label l=newLabel; jmp(l); db(0xE8/0xE9); bind(l)
  case 2: Label l = _a->newLabel(); int addr = rand()%0x66+0x5;    // Call over 0x74+rand bytes, then rebalance the stack
          _a->call(l); _a->db(0x74); _a->db(addr); _a->bind(l); _a->add(esp, 4); break;
  }
}
```
Modes 0/1's "jmp over a single E8/E9 byte" are precisely the generation source of the reverse side's most common "short jump over junk bytes" junk pattern; mode 2 fakes a call with call+add esp,4.

## 5. Logical-Operation Equivalence Derivations (VMP Universal Gate / OLLVM sub)

### Memorandum: Formula Derivations for Some Logical Operations (VMP, OLLVM)
Author: 天水姜伯约

The original text's "nand" is actually **nor**: `Nor(a,b)=~a&~b` (kept per the original's formula shape).

**The VMP universal gate** (one gate assembles all logic):
```
Not(a)   = Nor(a, a)
Or(a,b)  = Nor(Nor(a,b), Nor(a,b))
And(a,b) = Nor(Nor(a,a), Nor(b,b))
Xor(a,b) = ~(a&b) | ~(~a&~b) = Nor(And(a,b), Nor(a,b)) = Nor(Nor(Nor(a,a),Nor(b,b)), Nor(a,b))
```
Reverse-engineering value: when a VMP handler stream shows only one kind of binary operation repeatedly self-composing, expand it backward per the universal-gate formulas to get the real logic. **Arithmetic identities** (EFLAGS derivations not rigorously proven; for reference): `-a = ~a+1`; `a-b = ~(~a+b)`.

**OLLVM sub — three groups of equivalences**:
```
a = b & c  ->  a = (b ^ ~c) & b     [b^~c=(~b&~c)|(b&c); AND with b still yields b&c]
a = b | c  →  a = (b & c) | (b ^ c)
a = a ^ b  ->  a = (~a & b) | (a & ~b)   [definition]
```
Recognition: on meeting the three IR/assembly shapes `(x^~y)&x`, `(x&y)|(x^y)`, `(~x&y)|(x&~y)`, fold them straight back to and/or/xor (d810 ships the same rules).

## 6. Jump Encryption (indirect branch)

### Study Notes on the Jump-Encryption Obfuscation of Current Open-Source OLLVM
Author: wx_tuancc

**Hikari indirectBr**: conditional BR generates a `[2 x i8*]` BrTable storing 2 target label symbols, replaced by `gep(BrTable, zext(cmp result))` to fetch the label then `indirectbr`; unconditional BR uses a GlobalTable storing all target labels, `gep(GlobalTable, index)` + `indirectbr`. x86 shape: unconditional `mov eax,[TableN]; jmp eax`; conditional `mov eax,[TableX+ecx*8]; jmp eax`. **Weakness**: labels sit in the table in plaintext — read the table and you know both the true and false targets.

**Goron indirectBr** (two reinforcements in the same framework): the BrTable stores `gep(label)+random` offsets, decrypted at runtime with a Key on read — no plaintext addresses in the table; the decryption key is **split in half** (one half stored into a function-local variable, the other half participates as a constant in a sub, merging just before the jump):
```asm
mov  [esp+n], key1
mov  ebx, [esp+n]
...FunctionCode
mov  eax, [TableX+ecx*8]
mov  edx, key2
sub  edx, ebx          ; key2-key1 = actual decryption offset
add  eax, edx
jmp  eax
```
Reverse-side technique: before the BR, backtrack key1's store slot and the key2 constant; one subtraction yields the jump table's true values in bulk (see `deobfuscation-practice.md` §4 instruction-stack backtracking).

## 7. String Encryption (three posts merged into one section)

### Study Notes on the String-Encryption Obfuscation of Current Open-Source OLLVM
Author: wx_tuancc

**IR prerequisites**: string constants/char arrays are all `ConstantDataSequential(CDS)`; anonymous literals are `@.str = private unnamed_addr constant`, named ones `@name = global/internal constant`, empty string `[1 x i8] zeroinitializer`. **Constant-expression demotion**: lift gep/bitcast embedded in load/store/call into standalone instructions (`getAsInstruction+setOperand` / `replaceUsesOfWith`); afterwards references to a GV remain only as "an instruction directly referencing the global CDS" or "indirectly via CA/CS/i8*".

**Armariris**: iterate CDS GVs, judge by the name prefix `.str`/`.str.` (filtering `llvm.metadata`/`__objc_methname`); `getRawDataValues().data()` fetches the original data, encrypts it into a new GV, `replaceAllUsesWith` swaps references; `appendToGlobalCtors` builds a ctor that decrypts everything uniformly, then deletes the original GV. Can encrypt all ANSI/UNICODE constants; **cannot encrypt string arrays** (array symbol names don't start with .str).

**Yag00**: `isString` (i8 array)/`isCString` (i8+null) filter and fetch data, encrypt into a new `.encstr` GV; then iterate instructions to rewrite references — `CallInst/InvokeInst`: for arguments, `dyn_cast<ConstantExpr>` filters CE and GEP forms; if `getPointerOperand()->getName()` hits an encrypted GV, `setArgOperand` swaps in the new Alloc; `LoadInst`: `getPointerOperand()`→GV→CE→GEP name filtering, `replaceAllUsesWith`. Decryption generation: `AllocaInst` buffer + `GEP(alloc,idx)`/`GEP(array,idx)` to fetch ciphertext + Load + `CreateXor` + Store. Can encrypt const arrays; **cannot**: non-const arrays, UNICODE (isString only accepts i8), char local-variable references (the IR is a store GEP), strings inside structs, string-array read references (load(GEP) rather than load(GV)).

**Hikari** (the most complex): iterate Functions generating a decryption-status GV (encstatus); BB→Inst→Operand, `dyn_cast<GlobalVariable>` entries go into Globals/Usrs tables (`dyn_cast<User>` recursively expands indirect references). Globals filter `llvm.metadata`/objc; `NSConstantString_tag` (OC strings) takes its 2nd member into rawStrings; CDS goes into rawStrings; `ConstantArray` iterates Operands putting GVs back into Globals. rawStrings generates key tables and ciphertext tables per getInt8/16/32/64Ty (GV2Keys, old2new); objCStrings build encrypted ConstantStructs via `ConstantExpr::getInBoundsGetElementPtr` into old2new; `replaceUsesOfWith` swaps wholesale + delete old GVs. **Decryption-block insertion** (the three-piece at function entry): EntryBlock (A) is split to carve out PrecedingBlock (C), with StringDecryptionBB (B) wedged between: a Load(GEP)→Xor→Store decryption loop + `CreateBr(C)`; in A, `CreateLoad` atomically reads encstatus + `CreateICmpEQ` conditional branch "already decrypted→C / not yet→B"; in C, `CreateStore` atomically writes the status (reentrancy guard). Can encrypt const and non-const arrays; **cannot**: constants referenced by global char/wchar variables, strings inside struct variables.

| Scheme | Location method | Decryption timing | Arrays | UNICODE | Inside structs |
|---|---|---|---|---|---|
| Armariris | .str name prefix | ctor | × | ✓ | × |
| Yag00 | isString/isCString | before the use site | const only | × | × |
| Hikari | Operand walk + type filtering | function entry + status flag | ✓ (incl. non-const) | partial | × |

### Summary of the String-Encryption Obfuscation of Current Open-Source OLLVM
Author: wx_tuancc

The design space has three axes: **encryption scope × decryption timing × decrypted storage location**; scope = instructions directly referencing CDS or indirectly via CA/CS/i8*. Timing: ① **ctor** has the best compatibility and covers nearly all CDS, but after startup everything is plaintext — a DUMP gets it all, lowest strength; ② **function entry** handles only the current function's references regardless of repeated-reference order — the flaw is everything turns plaintext the moment you enter the function; ③ **before the instruction** decrypts only when execution arrives — best performance, smallest scope, but you must handle repeated references to the same CDS within a function.

Storage: ① **on the section**: a DUMP of process memory at any moment yields the plaintext already executed; entry/instruction-preceding decryption onto the section additionally has decryption-status and multithreaded reentrancy issues (locking needed — none of the open-source schemes handle it); ② **on the stack**: overwritten as soon as used — even dumping the whole process may not get the plaintext; naturally immune to multithreading, **the best overall**; the price: decrypted strings can't be used as constants (can't be returned/assigned to globals or heap variables), the encryptable scope is limited, and high-load repeated decryption costs performance.

Conclusion: section-based decryption and ctor timing are practically meaningless; "re-encrypt after use" has severe reentrancy + performance problems — inferior to the stack; viable schemes converge to **function-entry or instruction-preceding decryption + stack storage, giving up indirect CDS references**. **The VMProtect reference**: `VMProtectDecryptString(str)` wrapping constants covers only instructions directly referencing CDS (you can't call a function at the definition site) = instruction-preceding decryption; in practice the decrypted strings are stored on the **heap** (each string is allocated and decrypted only once, subsequent calls just return the pointer) — maximum protection without performance loss, but heap allocation is awkward to implement in IR.

### Using OLLVM to Customize a Simple String Encryption
Author: misskings

**Four steps to a self-written pass**: ① implement and verify the encryption algorithm in C++ first; ② `clang -emit-llvm -S main.cpp -o main.ll` to produce reference IR; ③ the pass builds instructions with the C++ API per the reference IR; ④ build the decryption function per the reference IR.

**The algorithm** (iterative XOR, with the final round flipped-not then XORed; kstr_size controls the rounds):
```cpp
int randkey = 11;                 // Fixed for this demo; use cryptoutils->get_uint8_t() per byte in the real pass
int enclen = randkey + kstr_size;
for (i in len) for (y = randkey; y < enclen; y++)
    enc[i] = (y==randkey) ? str[i]^y : (y==enclen-1) ? enc[i]^(~y) : enc[i]^y;
// Decrypt by decreasing y from enclen-1 to randkey; XOR with ~y first when y==enclen-1, otherwise XOR with y
```

**Pass skeleton** (kstr name registered; toObfuscate goes through the annotate/kstr flag):
```cpp
struct KStringEncode : public FunctionPass {
  static char ID;  bool flag;
  bool runOnFunction(Function &F) {
    if (!(KStringSize > 0 && KStringSize <= 0x20)) { /* Report the error and return */ }
    if (toObfuscate(flag, &F, "kstr")) { kstr(F); return true; }
    return false; }   void kstr(Function *func);
};
// Omitted: ID initialization, RegisterPass registration, and createKStringEncode factory, following the built-in OLLVM pass pattern
```

**String locating**: a string is an instruction operand in IR (`@.str = private unnamed_addr constant [15 x i8] c"hello world!!!\00"`); triple-iterate Function→BasicBlock→Instruction→operands(), `stripPointerCasts()` then `contains(".str")` filtering; fetch the content:
```cpp
std::string ConvertOpToString(Value* op) {
  GlobalVariable* gv = dyn_cast<GlobalVariable>(op);   if (!gv) return "";
  ConstantDataSequential* cds = dyn_cast<ConstantDataSequential>(gv->getInitializer());
  if (!cds) return "";   return cds->getRawDataValues();
}
```

**Decryption-IR generation** (build instructions one by one at the located spots; `insertBefore/insertAfter` controls order; buffer = `[N x i8]` alloca + bitcast i8* + a result alloca):
```cpp
for (i in strdata) {
  element = GetElementPtrInst::CreateInBounds(bitInst, i_const);          // &buf[i]
  for (y = enclen-1; y >= randkey; y--) {  // Store the constant y with alloca+store, then load it again
    // y==enclen-1: CreateNot(~y)→CreateXor(enc_const,notOp)→store eor_res
    // Otherwise load the previous eor_res, CreateXor(prev,eor_load), and store it; remember the final anchor when y==randkey
  }
  new StoreInst(load(eor_res), element);   // Write the final plaintext into buf[i]
}  // Finally redirect uses to the decryption buffer with val->replaceAllUsesWith(bitInst), then remove the plaintext global with eraseFromParent()
```

**The scope pitfall**: the same literal string used twice (two `printf("hello")`) merges into one string at the assembly layer; when decrypting at the use sites, the other branch may not be able to access the bitcast (not in the same scope). **Fix: record the function's first instruction `begin_ins` and insert all decryption instructions uniformly at the very top of the function**; when modifying the instruction stream during iteration, cache `begin_ins` before touching the IR.

## 8. fla's ARM Landing Artifacts and the Real-Block/Control-Block Criteria

### A Detailed Walk-through of ARM OLLVM-Style Obfuscation — Basic Ideas
Author: my1988

thumb+fla hands-on; the runtime model: `[real block] → [control block(s) (0..n)] → [next real block] → ...`. After the real block finishes the original logic, `MOV R0,#imm` writes the dispatch register; the control block only chain-compares against R0 via `CMP+B.EQ/B.NE` (possibly through several relay blocks) before landing on the next real block — exactly the ARM-lowered form of §2 Flattening's `store state→loopEnd→switch` (state lands in R0/a local; the switch lowers to a CMP chain).

**The key criteria (statically identifiable)**:
1. **Control-block traits**: extremely short, register-only operations, no memory operations, tail `cmp+jump`; vendors differ in the details — isolate them in the deobfuscator with polymorphism/adapters; identified control blocks can simply be zeroed (they no longer execute after repair, sparing IDA the noise);
2. **Real-block traits**: input **dataflow-disjoint** from the dispatch control blocks (a real block's inputs are local variables like var_20, with no intersection with the dispatch registers like R0 that control blocks read/write) — the hard criterion for telling real from control blocks;
3. Control blocks only serve dispatch, "deciding the next real block": once you know the before/after relations of real blocks, connecting them directly with B/BNE and skipping all control blocks keeps the program correct.

**Determining before/after relations** (statics too slow — go by trace): ① IDA dynamic: put a breakpoint on every instruction and change its attribute to `BPT_TRACE` (doesn't stop, just fires the callback); the callback records the address + register state, producing a per-instruction trace (in the shape `0x0001CA34: ADD R5,SP,#0X208 ;(SP=0x100FF248)`); ② emulated execution, unidbg/AndroidNativeEmu style (complete syscalls+JNI), ignoring anti-debug. Extract successors from the trace: locate real block A at trace position n; from n+1 skip control blocks; the first instruction of real block B is A's successor; dual-successor blocks are covered by tracing multiple inputs down both paths. **Limitation**: uncovered branches are lost (what gets restored is the executed logic, not 100%) — but it naturally filters out bcf bogus blocks; **generality**: not limited to ollvm — applies to all "real block + dispatch control block" fla-style obfuscation (tested on several video apps and hardened sos); only the control-block recognition needs slight tuning. **Patching note**: never blindly patch a real block's tail — logic-bearing tail instructions like `BL` must not be overwritten; analyze overwrite-ability class by class.
