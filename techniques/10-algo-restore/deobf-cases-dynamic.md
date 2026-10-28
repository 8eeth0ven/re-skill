# Deobfuscation Case Collection, Dynamic: OLLVM Trace/Emulation/Active-Invocation Practice

> Positioning: **complete dynamic-restoration case workflows for OLLVM obfuscation** (sample traits → locating → tracing → algorithm-restoration results). Complements `deobfuscation-practice.md`: that one holds the generic unicorn/angr skeletons; this one holds seven hands-on posts' **case parameters, hook points, reasoning chains, and pitfalls** — adapt and use directly.

## 0. Seven-Case Quick Index

| Case | Means | Arch | Sample traits | Key output |
|---|---|---|---|---|
| Unicorn deflattening with bb | unicorn+keystone patch | arm32 | TBB/TBH dispatch + obfuscated logging/decryption functions | F5-readable after deflattening |
| unicorn tracing of a non-standard algorithm | unicorn full-instruction trace | arm64 | UUIDCheckSum custom transform | full C replica of the algorithm |
| Notes on restoring a function with Trace | IDA trace + frida active invocation | arm64 | S-box lookups + rotations + XOR | round-function reasoning chain |
| An ollvm algorithm-restoration case shared | frida hook chain + trace | arm64 | AES S-box lookups + transforms | full C replica of the keygen |
| Another algorithm-restoration case after ollvm, shared | hook chain + trace + MBA simplification | arm64 | MD5(salt+input) + dual password tables | full replica of the encryption flow |
| ollvm CrackMe algorithm analysis | trace contrast + negation simplification | arm64 | heavy MBA negation mixing | simplification playbook |
| Xposed flag brute-force | Xposed+sandhook active invocation | arm64 | test(3 chars) enumerable | brute-forced without restoring the algorithm |

## 1. Unicorn Deflattening (arm32 TBB/TBH)

### Unicorn Against OLLVM Control-Flow Flattening: bb
Author: 欧阳峰峰

**Sample**: an arm32 so; after fla, F5 shows a big while+switch; the target functions picked are the app's logging-output function (hijack `__android_log_write`/`__android_log_buf_write`) and the string-decryption function — in an obfuscated so these two kinds are natural restoration targets.
**fla's IR generation rules** (the basis for writing recognizers): ① first block does AllocaInst(switchVar)+StoreInst(random initial value)+br loopEntry; ② loopEntry: LoadInst+SwitchInst table-dispatch jump; ③ loopEnd: br back to loopEntry; ④ real blocks: unconditional branch → remove the original br, add StoreInst(successor's switchNum)+br loopEnd; conditional branch → SelectInst picks the switchNum then stores; ⑤ switchDefault: br back to loopEnd. During debugging, `Function.viewCFG()` dumps before/after `runOnFunction` for contrast. **Note: the IR layer is a switch, but the final arm32 machine code has no switch instruction** — it lands as a multi-block cmp comparison chain; identify statically by the assembly shape, not the IR shape.

**The four unicorn restoration steps** (TBB/TBH dispatch):
1. **Find the dispatch instruction**: Capstone walks the function matching `TBB`/`TBH`, taking a cmp group: the first cmp's operand = the function's `pop`-block entry number; the second cmp's operand + 1 = the switch table's entry count;
2. **Compute case addresses**: `case_addr = pc+4+4*table[i]` (TBB 1 byte per entry, TBH 2 bytes) → the **switchVar ↔ real-block-entry mapping**;
3. **Emulate all paths**: from the tbb/tbh, unicorn emulates; exit timing = execution reaches `pop` (function exit) or returns to the dispatch block; on exit read **R3** (the register holding switchVar) and look up the mapping → next real-block address + patch location;
4. **keystone patch**: per the mapping, change the dispatch-block tail jumps into direct jumps to the real blocks.

**Pitfalls** (not fully automatable; adapt per function): the switch feature may be a `cmp/bhi/tbb` combo; case chains nest switch tables (nested flattening); switchVar isn't a mov immediate but register arithmetic; one real block jumps to different successors per its internal result, assigning R3 via conditional execution through `ITE/MOVELT/MOVEGE` — one emulation walks one path only; uncovered branches need re-runs after changing conditions/NZCV to fill in.

## 2. Unicorn Tracing for Algorithm Restoration (arm64)

### Using Unicorn to Trace and Restore an OLLVM-Obfuscated Non-Standard Algorithm
Author: misskings

**Applicability criterion**: the algorithm is pure (no JNI/syscall-context dependency), F5 branch explosion but simple input/output → unicorn whole-segment emulation + full-instruction trace. **Sample**: ollvm9.apk's `UUIDCheckSum(input,len,output)`; IDA pins the boundary `start=0xfcb4 end=0xff2c`.
**Iron rule: don't use the so unpacked from the apk — you must dump it from a real device's runtime memory** (frida_dump `dump_so`); the dump carries full relocations and executes directly; the base address in the filename (e.g., `0x7eae047000`) is the emulation base.

**Setting up the unicorn environment** (fully runnable):
```python
uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
code_addr = 0x7eae047000                    # Actual shared-object base at dump time; matches the filename
uc.mem_map(code_addr, 8*0x1000*0x1000)      # Allocate a large code region to avoid undersizing the mapping
stack_addr = code_addr + code_size          # Place the stack immediately after the code; stack_top = stack_addr+0x1000-0x8, with 8-byte alignment for this 64-bit case
uc.mem_map(stack_addr, 0x1000)
args_addr = stack_addr + 0x1000; uc.mem_map(args_addr, 0x1000)   # Allocate a separate argument region
uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)                      # Instruction-level callback
uc.mem_write(code_addr, open(dump_path,'rb').read())
uc.mem_write(args_addr, input_str.encode()) # Use distinctive input to distinguish constants from input-dependent values
uc.reg_write(UC_ARM64_REG_X0, args_addr); uc.reg_write(UC_ARM64_REG_X1, len(input_str))
uc.reg_write(UC_ARM64_REG_SP, stack_top)
uc.emu_start(code_addr+0xFCB4, code_addr+0xFF2C)   # IDA offset plus base; output is written into the input buffer and read back through mem_read(args_addr)
```

**A customized trace callback** (three things that beat raw assembly dumps by an order of magnitude): ① after each assembly line, print the current values of all registers that line uses; ② **print the destination register's new value one line late** — in the next instruction's hook, read the previous instruction's first register = the post-execution value (`pre_codestr`/`pre_regname` held in globals); ③ **memory watching**: hex-snapshot the watch-listed addresses every 0x10 bytes; print on change:
```python
cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM); cs.detail = True
reg_names = {"X0": UC_ARM64_REG_X0, ..., "W28": UC_ARM64_REG_W28, "SP": UC_ARM64_REG_SP}  # Complete register constants are in unicorn.arm64_const
def hook_code(uc, address, size, user_data):
    for inst in cs.disasm(uc.mem_read(address, size), size):
        # 1. Add the previous instruction's post-execution register values to pre_codestr, then print that line
        # 2. Snapshot each watch_addrs entry through b2a_hex; print and update when it changes
        # 3. Extract register names with re.findall(r'[^0]([wx][0-9]+)', op_str, re.I|re.M); save the first written register in pre_regname
        # Assemble the line in pre_codestr and set has_pre=True
```
Output shape (pre-execution value first; after `//` is the post-execution value):
```
0x7eae056cc8: ldrb w22,[x0,#0x18] ------x0=0x7eb6048000 w22=0x0 //w22=0x46
0x7eae056f0c: sub w9,w10,w9       ------w9=0x9d0 w10=0x9db //w9=0xb
```
**The backward dataflow reasoning chain** (UUID's last two bytes, example): ① search for the output-parameter address, `strb w8,[x0,#0x22]` → where does w8 come from; ② backtrack `ldrb w8,[x11,w9,uxtw]`; the x11 watch printed the table's content `30313233343536373839616263646566` = **"0123456789abcdef"** (hex-to-ascii lookup table); ③ w9=0xb is the index; backtrack `sub w9,w10,w9` (w10=0x9db, w9=0x9d0), further back `and w9,w9,#0xfffffff0`; ④ 0x9db backtracks to `add w20,w23,w20` — grepping the same instruction by address shows 29 executions, each round w20 = one input byte → **0x9db = the accumulated sum of some input bytes** (boundaries read off the trace).
Key technique: **the same address recurring (loop body) — grep all its occurrences and string the register changes together = that loop's semantics**.

**Restoration result** (C replica cross-checked identical):
```c
char getAscii(int num) { char tmp[3]; snprintf(tmp,3,"%x",num); return tmp[0]; }  // Convert a hexadecimal nibble to ASCII
int sum = 0, eorsum = 0xff;
for (int i = 0; i < strlen(input); i++) {
    output[i] = input[i] ^ 0x1;                                             // Main transformation: XOR every input byte with 1
    if (i==0x8||i==0xd||i==0x12||i==0x18) { output[i]=0x2d; continue; }    // UUID separator positions use '-'
    // Special positions: i==0xe -> 0x34; i==0x23 -> input[0x22]; i==0x22 -> input[0x9]; i==0x17 -> input[0x18]^0x1
    if (i < 0x22) { int v = input[i]; if (i==0x17) v = input[0x18];        // The checksum accumulates only the first 0x22 bytes
                    sum += v; eorsum ^= v; }
}
output[0x22] = getAscii(sum - (sum & 0xfffffff0));   // Convert the low four bits of the sum to ASCII
output[0x23] = getAscii(eorsum & 0xf);               // Convert the low four bits of the XOR sum to ASCII
```

## 3. Trace + frida Hook-Chain Restoration

### Notes on Restoring an OLLVM-Obfuscated Function with Trace
Author: neilwu

**IDA trace's three modes**: Instruction tracing (stores modified registers per instruction; the workhorse) / Basic block tracing (reached block addresses) / Function tracing (calls/returns). After tracing, back to the CFG view — **instructions turned yellow = the really executed path** — peeling off bcf's always-false branches at a glance.
**frida active invocation to construct known inputs** (get the black-box baseline first, then trace):
```javascript
var sub_13CE4 = new NativeFunction(Module.findBaseAddress("libnative-lib.so").add(0x13CE4),
    "void", ["pointer","int","pointer","int","pointer"]);
sub_13CE4(Memory.allocUtf8String("pediy_imyang_lXcaTALmow"), 23,
          Memory.allocUtf8String("www.pediy.com&kanxue"), 20, Memory.alloc(0x26));
// Output: 79 79 03 09 00 01 a4 b8 b6 c8 9e b4 7f 4f 29 b4 ...
```
**The round-function reasoning chain**:
1. Argument 1 (23 bytes) is table-transformed byte by byte (0x70→0x51) yielding `514d43f9 b6cff93c b6ef9f85 cf506afb ef208329 3ca8f563 63636363 63636363` (the last two dwords are fixed padding values);
2. Only the **first 16 bytes** of argument 3 participate downstream (see the trace for the tail truncation, not F5);
3. The two byte groups loop 8 times pairwise, with **argument 1 rotating per loop count**: `0 rounds 514d43f9→514d43f9; 1 round b6cff93c→cff93cb6; 2 rounds b6ef9f85→9f85b6ef; 3 rounds cf506afb→fbcf506a` (byte-wise rotation per round, done by the separate function sub_172D0);
4. **On rounds 1/5, argument 1 only rotates and doesn't participate in the encryption — argument 3 operates with the constant `0x68DE32AA`** — "skipping one input every other round" is invisible statically; only trace comparison reveals it;
5. Round-function core (read straight from trace registers): `X8=0xf5f5f531(argument-3 transform) X9=0x514d43f9(argument-1 transform); W11=X8&(X8^X9); W8=X9&(X9^X8)→0xa4b8b6c8` — the MBA expansion of `(a&~b)|(b&~a)=a^b`;
6. The 6 header bytes `797903090001` are fixed: dynamically watch the first 6 bytes of the memory pointed by x4 (confirmed repeatedly) or search the trace for the assignment.
**Pitfall**: aligning consecutive memory assignments in a trace strains the eyes — trace backward "first search who writes the output address → then see which instruction the written value came from"; don't read 150,000 lines forward.

### An ollvm Algorithm-Restoration Case Shared
Author: 咸鱼炒白菜

**The locating chain (pure frida)**: ① jadx shows `MainActivity.e(byte[])` is the native result function; ② hook `RandomStringUtils.randomAlphabetic` to **pin the random suffix "lXcaTALmow"** → the black-box input/output becomes reproducible; ③ hook the Java-layer `e` printing in/out-arg hex for a baseline pair; ④ hook `sub_184EC` (called three times; the third call's arg1 is the result) → reference backtracking to `sub_13CE4(input, inputlen, tb, tblen, output)`, the key algorithm.
**The hook combo**:
```javascript
RandomStringUtils.randomAlphabetic.overload('int').implementation = function (a) { return "lXcaTALmow"; };  // Fix the random string
Java.choose("com.kanxue.ollvm5.MainActivity", { onMatch: function (inst) {    // Invoke the native method through Java
    console.log(ByteString.of(inst.e(Java.array('byte',[0x70,0x65,0x64,...]))).hex()); }, onComplete: function () {} });
Interceptor.attach(base.add(0x13CE4), {   // Confirm the signature at the native layer; read output only in onLeave
  onEnter: function (args) { console.log(hexdump(args[0]), args[1]); arg4 = args[4]; },
  onLeave: function (r) { console.log(hexdump(arg4)); } });
```
**Byte-transform confirmation** (one hook pass): `172D0 onEnter 0xb6cff93c → onLeave 0xcff93cb6; 0xb6ef9f85→0x9f85b6ef` cross-checked → `sub_172D0(v) = v rotate-right by 8×round-count bits`.
**Recognizing the AES S-box**: the lookup table `byte_42108` starts `63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76` = the standard S-box. **Why IDA statically finds no MD5/S-box signatures: OLLVM instruction substitution scatters the constants into the arithmetic** — you must confirm table contents dynamically via hook/trace.
**The restored algorithm** (cross-check passed):
```c
static char keytb[] = "www.pediy.com&kanxue";                 // Argument 3
static char keytbde[] = {0x31,0xf5,0xf5,0xf5, 0xf9,0x43,0x4d,0x51, 0xa8,0xfb,0x31,0xb6, ...};  // sub_13808 derives this from keytb
int REV(int v) { return ((v<<24)&0xFF000000)|((v<<8)&0xFF0000)|((v>>8)&0xFF00)|((v>>24)&0xFF); }
int keygen_13CE4(input, inputlen, tb, tblen, output) {
    sub_13808(tb, tblen, o13808);    // Derived key table; first six bytes are 79 79 03 [length expression (-len^0xFFFFFFF0)&-len] 00 01
    for (int i=6; i<=0x25; i++)                               // Transform input bytes through the S-box, padding out-of-range positions with 0x63
        output[i] = (i-6 >= inputlen) ? 0x63 : byte_42108[input[i-6]];
    for (int i=0; i<tblen; i++) tb[i] = byte_42108[(uchar)tb[i]];   // The key also passes through the S-box
    for (int i=0; i<=(0x25-0x6)/4; i++) {                     // Eight rounds, one dword per round
        uint tmp1; memcpy(&tmp1, keytbde+4*(i%4), 4);         // Key stream cycles over four dwords
        uint tmp2; memcpy(&tmp2, output+i*4+6, 4);
        tmp2 = REV((tmp2 >> 8*(i%4)) | (tmp2 << 32-8*(i%4))); // Rotate according to the round index, then reverse byte order
        int out = REV(tmp1 & ~tmp2 | tmp2 & ~tmp1);           // MBA expression equivalent to XOR
        memcpy(output+(6+i*4), &out, 4);
    }
}
```
The playbook: **version header (fixed value) + length-obfuscation byte + S-box lookups + key stream cycling dwords + shift transforms + MBA XOR** — heavily reused across risk-control sos; match the mold first, then carve the details.

### Another Algorithm-Restoration Case After ollvm, Shared
Author: 咸鱼炒白菜

**The hook chain from the JNI entry down to MD5** (correcting the signature once per hooked function, pure black box):
1. `RegisterNatives` hook grabs `sign1→0x10BE8` (dynamic registration; not in the export table);
2. F5 shows `sprintf` fired 16 times in a row (the classic binary-to-hex shape) → the `sub_1494C4(&in,16,&out)` above it is the key algorithm; hook confirms `(input,inputlen,output)`;
3. Hook `sub_14141C(input,len,output)` → a 16-byte digest; hook `sub_1390B8(ctx,data,len)` — called 4 times, the call pattern is exactly an **MD5Update sequence**: `(ctx,"421d38d9...",0x20)` salt (32 chars) / `(ctx,input,0x10)` / `(ctx,bits,8)` internal length padding / the 4th inside Final;
5. **CyberChef cross-check of `MD5(salt+input)` matching confirms it**; IDA can't find the MD5 constants (the IV `01234567 89abcdef fedcba98 76543210` shows up in the hooked ctx instead) — **"hook the ctx and read the IV at 0x30" beats searching IDA for constants**;
6. The salt's origin: among the three `.init_array` functions, the **second** completes the string decryption (when static ciphertext disagrees with runtime, check init_array first).
**Trace setup** (IDA's dynamic debugger): `idc.SetReg(ea,"T",0)` (on ARM64 you must switch T to 0 or breakpoints won't land) + `MakeCode`+`add_bpt`; break at the function head and end; the trace runs ~150,000 entries; **combine with F5 to bound the basic-block ranges** (trace-hit addresses ↔ F5 blocks cross-checked) and read in segments.
**Dynamically locating the two password tables**: table 1: 153F24 suspected → hook 153F28 reading `this.context.x11`, cross-check → `v2015={0x3a,0x33,0x9b,0x79,0x61,0xf3,0x27,0x96,0xbe,0x5b,0x84,0xd2,0x6c,0xf5,0xb9,0x15}`; table 2: `LDUR W16,[X29,#var_80]` felt like a table → follow the writes to find `ADRL X10, xmmword_1FF160`, frida `print_string` dump → `"151caed3cfc7e999ebf6b66d3e8e96cc"` (taken with `i%8`).
**Algorithm skeleton** (two big-layer loops with MBA):
```c
for (int i = 0; i < 16; i++) {          // Round 1 maps the MD5 result into v2020[16]; round 2 mixes v2020 with two tables to produce another 16 bytes
    int v1433 = md5_out[i];             // = MD5(salt + input)
    int v1434 = v2015[i];               // First password table
    int v47   = v2018[i % 8];           // Second password table, indexed modulo its string length
    // Dozens of MBA layers shaped like (~a & c | a & d) ^ e; the only inputs are v1433/v1434/v47
    v2020[i] = result & 0xFF;
}
```
**MBA simplification playbook** (OLLVM's flourishes all sit on identities): `(~x&c | x&d)` = a bitwise selector (x's bits choose c/d); with c/d complementary it's just `x^c`; `(~0xa3&A|0xa3&B) ^ (~0x33&A|0x33&B)` = `A^B` (two selectors XORed, the masks cancel); `x&~x=0`, `x|~x=0xFF..`, `x^x=0` are all dead operations. For multi-layer negation mixing, **fold layer by layer with the selector identities first, then read**.

### ollvm CrackMe Algorithm Analysis
Author: ddsf

One core move: **negation-obfuscation equivalence simplification**:
```c
v = (~0xa3 & 0x5E58FB3C | 0xa3 & 0xA1A704C3) ^ (~0x33 & 0x5E58FB3C | 0x33 & 0xA1A704C3);
// Simplifies to v = 0x5E58FB3C ^ 0xA1A704C3: masks cancel, leaving a constant
```
Method: locate the key encryption segment → segment it → pair up each segment's inputs and results → verify the simplification against traced register values. In traces, the abundant "negation + fixed constants" combos almost always fold back into one XOR/AND-OR via the selector identities.

## 4. Xposed Active-Invocation Brute Force (No Algorithm Restoration)

### Using Xposed to Brute-Force the Flag in a Post-ollvm so
Author: PTRer

**Criterion**: you can't be bothered to restore the algorithm but the **answer space is enumerable** (test(str), 3 chars upper+lower case, 52^3=140K) → batch active invocation on a real device. Three steps:
1. **Find the key function**: jadx shows `jnitest`; nested while+state machine inside the so = fla; **analyze back-to-front** (from sprintf/return-value handling backward) locks `test` (0xF9A0) faster; `test(sub_103C0(s))!=0` is the hit;
2. **Inject only after the so finishes loading**: hook `Runtime.loadLibrary0` (on Android 8.1 System.loadLibrary ultimately goes through it; **function names/parameter order differ across Android versions — read the matching version's source first**); on a package-name hit, load the homegrown hookso inside JNI_OnLoad:
```java
XposedHelpers.findAndHookMethod(Runtime.class, "loadLibrary0",
    Class.class, ClassLoader.class, String.class, new XC_MethodHook() {
  @Override protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    if (param.args[1].toString().contains("com.kanxue.test2"))
        System.load("/data/data/com.kanxue.test2/files/hookso.so"); } });
```
3. **sandhook active-invocation brute force**: sandhook chosen because it can take a so-internal function address and call it directly (arm32/64 both); **init must complete before hooking; the wrapped call function fires from JNI_OnLoad**; push the so to `/data/data/<pkg>/files/`, disable SELinux, enumerate the 3-letter combinations calling test — a nonzero return is the flag.
**The trade-off**: want the flag, not the algorithm, and the space is small → brute force is orders of magnitude faster; a space of hundreds of millions (long tokens) doesn't work — go back to §2/§3 restoration.

## 5. Cross-Case Experience Summary

**The fixed playbook for locating key functions**: ① hook `RegisterNatives` to grab dynamically-registered JNI addresses (when the export table search fails); ② in F5, find `sprintf`×N / `__android_log_*` / return-value assembly points and work **back to front**; ③ hook function by function correcting signatures to `(input,len,output)` — save pointers in onEnter, read in onLeave = a black-box input/output pair; ④ pin the randomness sources (hook RandomStringUtils returning a fixed value) to make samples reproducible — the precondition for cross-checking.
**Dynamic tool selection**: pure algorithm, no JNI → **unicorn + the memory-dumped so** (offline, fast, controllable); context-dependent or environment-build-averse → **IDA instruction trace** (real-device accurate, on the 150,000-entry scale); only black-box recomputation/enumeration needed → **frida NativeFunction / Xposed+sandhook** (zero restoration cost).
**High-frequency pitfalls**: feeding the so straight from the apk into unicorn makes it run off the rails — you must frida-dump the memory state (with relocations); under ARM64, IDA breakpoints need `SetReg(ea,"T",0)`; failing to find algorithm constants statically (MD5 IV/AES S-box) ≠ a non-standard algorithm — instruction substitution scatters constants, trust the memory you hooked; salts/keys are often decrypted in `.init_array` — when static ciphertext disagrees with runtime, check it first; details like string tables participating with `i%8` modulo — pull the table contents at runtime with frida print_string; the way to read a trace is always **backward** (first search which str wrote the output → trace where the written value came from → grep loop bodies by address to aggregate semantics); fold `(a&~b)|(b&~a)` and `(~x&c|x&d)^e` with MBA identities before reading — ninety percent of "complex algorithms" collapse to a single XOR after folding.
