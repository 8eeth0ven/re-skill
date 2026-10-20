# Western corpus · Windows RE tutorial collections (mytechnotalent / Yurichev / crackmes.de)

> Positioning: distinctive lessons from the big free English books & the crackmes.de solution archive.
> Deduped against `../../platforms/01-windows/fundamentals.md` (crypto-ID, PE, calling conventions, vtable/if-else patterns),
> `../../platforms/06-binary-vuln/arm64-rop-practice.md` (ARM register/PC/Thumb basics) and
> `../06-crypto/keygen-algorithm-cases.md` (keygen-writing techniques). Only novel angles kept.

## I. Methodology: the Program → Debug → Hack pedagogy (mytechnotalent RE4E)

### The Code/Debug/Hack triple (src: mytechnotalent RE4E)
Author: mytechnotalent (Kevin Thomas)
- Every single primitive (ADD, MOV, char, float, ++/--, pointers, branches) is drilled as a fixed three-beat loop: **write it → debug it in GDB → hack it**.
- "Debug" = load in GDB, `b _start`, `r`, `disas`, step with `si`, inspect `i r`; the "Hack" beat then hijacks one live value: `si; i r; set $eax = 0x66` — change 0x64→0x66 in flight and watch behavior change.
- Pedagogical payload: the analyst's muscle memory is *register-window-driven patching*, not reading. When you hit unknown code, your instinct becomes "break earlier, watch the register that holds the decision value, mutate it live" instead of statically decoding everything.
- The books deliberately author every sample twice (assembly and C/C++) so the reader sees the same binary shape from both sides — a cheap way to learn compiler-vs-handwritten fingerprints.
> Same approach: every per-architecture volume (x86 Course, ARM-32 Course 1/2, x64, ARM-64, Pico, Embedded) repeats the triple; language variants (Go Hacking, Hacking Rust) do it per language runtime.

### ARM-64 Hacking Hello World (src: mytechnotalent RE4E ARM-64)
Author: mytechnotalent
- Minimal radare2 patch loop for a static ELF: `radare2 -w ./bin` → `aaa` → `s main` → `v` (or `p` twice for debugger view) → find the string at a fixed `.rodata` VA with `ps @0xb48` → overwrite with `w Hacked World @0xb48` → verify `ps` again → run.
- Point of the drill: on-disk addresses vs runtime addresses (no PIE run shown), and the habit of *verify the patch in-tool before executing* — two `ps` checks bracket every `w`.
- The file is patched in write mode (`-w`), not memory-patched — the change survives re-runs; contrast with the GDB register hijack from the x86 course which never touches the file.
> Same approach: Pico course patches then re-flashes via elf2uf2; Hacking Windows patches MessageBox captions the same way.

### Pico/embedded patch loop (src: mytechnotalent RE4E Pico Course Part 4)
Author: mytechnotalent
- Embedded variant of the same loop, with the two traps that only bite on MCU ELF→UF2 flows:
  - `iz~` shows strings with **paddr and vaddr columns** — patching the pointer cell vs patching the string bytes are different addresses; `psz @ [0x00000338]` dereferences the pointer cell, `psz @ 0x00004cf8` reads `.rodata` directly. Both must agree after the patch.
  - Instruction patch of a Thumb shift: `sleep_ms(1000)` compiles to `lsls r0, r0, 2` (250<<2); hack via `wa lsls r0, r0, 1 @ 0x00000330` → half-second blink. Recognizing *multiply-by-shift* encodings is what makes the patch a one-instruction edit.
- Then `elf2uf2` + copy to `/Volumes/RPI-RP2` (BOOTSEL) + `screen /dev/tty.usbmodem...` to watch the hacked firmware stream.
> Same approach: all Pico datatype hacks (char/int/float/double) follow; Embedded Hacking Course repeats on bare-metal Cortex-M.

### Hacking Windows: pure-asm Win32API ladder (src: mytechnotalent Hacking-Windows)
Author: mytechnotalent
- A free book structured as one Win32API family per chapter: MessageBox (Hello World) → CreateDirectoryW/RemoveDirectoryW → CopyFileW → MoveFileW → CreateFileW → WriteFile. Each API appears 5×: C version, debug x86, hack x86, debug x64, hack x64.
- The pedagogical trick: the reader *writes the same API call in pure MASM/NASM first*, so when they later meet an unknown binary calling CreateFileW they already know the register/stack shape of all 3-5 arguments in both ABIs — no guessing which slot is dwCreationDisposition.
- Unicode APIs (W variants) are used throughout, so `LEA RCX, [wide_string]` patterns and UTF-16 string blobs in .rdata become familiar before they are ever "reverse engineered".
> Same approach: his Windows Process Lifecycle / Windows Kernel Debugging / wis (Windows Indirect Syscall) repos extend the same ladder into process internals and syscalls.

### AArch64-Bytes: bite-size AArch64 articles (src: mytechnotalent AArch64-Bytes)
Author: mytechnotalent
- Part 1 "Reversing Exit": decode a 4-byte AArch64 `exit` syscall instruction by hand — bit-field surgery on the raw encoding as the fastest way to internalize `svc #0` + x8=syscall-number.
- Part 2 "64-bit Immediate Values": AArch64 cannot `mov` a full 64-bit immediate; compilers emit `MOVZ X0, #imm16, LSL #32` + `MOVK` pairs. Seeing a MOVZ/MOVK pair = a 64-bit constant being assembled — count the shifts to rebuild it.
- Part 3 "Yet Another Upper": lowercase→uppercase as a timeless parsing algorithm case (the `c^0x20` idiom, see Yurichev §3.16).
> Same approach: the ARM-32 Course 1/2 do the same per-instruction (ADD/ADDS/ADC/SUB with flags commentary).

## II. Compiler pattern recognition beyond the basics (Yurichev RE4B)

### switch(): two emission shapes (src: Yurichev RE4B §1.15)
Author: Dennis Yurichev
- Few cases (0..4): MSVC emits a **subtraction/DEC chain**, not a table — `sub eax,0 / je case0; sub eax,1 / je case1; sub eax,1 / je case2; ... default`. The "subtract 0" looks absurd until you read it as "cmp with 0, free because SUB sets ZF".
- Many dense cases: bounds check first (`cmp [arg],4 / ja default`), then `mov eax,[arg]; shl eax,2; mov eax, ds:jpt[eax]; jmp eax`. OllyDbg draws the jump table and underlines its cells because they are **FIXUPs/relocations** — a free tell that a blob of dwords is a jump table, not data.
- Each case body ends in `jmp _printf` instead of `call` — tail-call reuse of the caller-pushed return address; a switch whose branches all JMP away is a compiler, a human, or a dispatcher.
- Diagnostic habit: count cases and their value density before assuming a table exists; sparse values (e.g. 1,100,1000) fall back to compare-chains even from optimizing compilers.
> Same approach: GCC 4.4.1 non-optimizing output shown side-by-side; ARM switch via `ldrpc` tables in §1.15 ARM parts.

### Division using multiplication (src: Yurichev RE4B §3.9)
Author: Dennis Yurichev
- `int f(int a){return a/9;}` compiled /Ox becomes `mov eax,954437177 (0x38E38E39); imul ecx; sar edx,1; mov eax,edx; shr eax,31; add eax,edx` — **no division instruction at all**.
- How to read it: the low 32 bits of the product are *dropped* — a hidden division by 2^32; the code multiplies by 0x38E38E39/(2^32+1) ≈ 1/9. `shr eax,31` extracts the sign bit and `add` applies sign correction (rounding toward zero). Reconstruct the real divisor with `modinv32`-style computation: divide 2^32+1 by the magic constant; if it prints ~8.999 you found `/9`.
- Common misconceptions the author flags: it is *not* modular inverse, and people routinely miss the implicit 2^32/2^64 division when only the high half of IMUL/MUL is used. Diophantine limitation: for some divisors no magic constant exists ( compilers then use shift-subtract sequences).
- Cross-arch tells: ARM (pre-v7) has no DIV — `__aeabi_idiv`/`__aeabi_idivmod` library calls, or SMULL magic-constant tricks; Keil calls `__aeabi_idivmod` always; MIPS emits real `div` + `break 0x1C00` on zero-divisor with result in LO/remainder in HI (`mflo`/`mfhi`).
> Same approach: Cointerra case (§8.8) reads `SMULL` with `0x51EB851F` as `/3.125` then `/50` — a divisibility check `x-((x/50)*50)==0` in the wild.

### Branchless abs() (src: Yurichev RE4B §3.13)
Author: Dennis Yurichev
- Optimizing GCC x64: `mov edx,edi; mov eax,edi; sar edx,31; xor eax,edx; sub eax,edx; ret`.
- Reading: `sar 31` = all-ones mask if negative else 0; XOR with mask = conditional bit-flip; SUB mask = conditional +1 — together exactly two's-complement negation, applied only when the sign bit was set. No branch, no flag-dependent path.
- ARM64 folds it into operand2: `eor x1, x0, x0, asr 63` / `sub x0, x1, x0, asr 63` — the mask is *recomputed inline* per instruction because shifted-register operands are free. Two instructions where x86 needs four: a strong compiler fingerprint.
- Generic lesson: any `X ^ (X>>31) - (X>>31)` shaped code is a conditional-negate/min/max/select idiom (Hacker's Delight ch.2-4), not obfuscation.
> Same approach: min/max/clamp idioms with CMP+CMOVcc / ARM `csinc/csel` in the same chapter family.

### Multiplication by two LEAs + negative ADD (src: Yurichev RE4B §3.10 atoi)
Author: Dennis Yurichev
- Hand-written atoi loop, optimized MSVC x64: `lea edx,[rax+rax*4]` (×5) then `lea eax,[rax+rdx*2]` (×10) — **×10 done with two LEAs**, never `imul`. First char is loaded before the loop and next char pre-fetched at loop end ("loop regrouping").
- `add eax,-48` instead of `sub eax,48`: MSVC habitually encodes SUB of a constant as ADD of the negative — cosmetic, but throws off naive pattern matching that greps for `sub`.
- Keil ARM does the same regrouping with the barrel shifter: `ADD r0,r0,r0,LSL #2` (×5) `ADD r0,r2,r0,LSL #1` (×10); ARM64 adds pre-increment load `ldrb w1,[x2,1]!` — the fused addressing-mode version of "advance pointer while loading".
- Takeaway table: constant ×5+×2=×10, ×3=lea[rax+rax*2], ×10 on ARM=ADD with LSL — when you see these, it's *scaled arithmetic*, not pointer math.
> Same approach: §3.22 loop optimizations (MSVC memcpy keeps only ONE pointer: `sub esi,eax` (src-dst) then `mov cl,[esi+eax]`/`mov [eax+1],cl` — indexing everything off dst).

### Variadic functions on x64: shadow-space as an array (src: Yurichev RE4B §3.14)
Author: Dennis Yurichev
- MSVC's `arith_mean(int v, ...)` first **spills the 4 register arguments into the shadow space** (`mov [rsp+8],ecx; mov [rsp+16],rdx; mov [rsp+24],r8; mov [rsp+32],r9`), then takes `lea rcx,[rsp+8]` and walks shadow space + stack as **one contiguous array of 4-byte ints** until the -1 sentinel.
- GCC's version is split in two: save the register args into the **red zone** below RSP, process that block first, then switch to the stack block — the function visibly branches on "argument number <= 6?" mid-loop.
- Reversing value: a prologue that stores RCX/RDX/R8/R9 to [rsp+8..0x20] *before any call* is the variadic/`va_list` prologue; the spill area is the x64 analog of the 32-bit "arguments start at [ebp+8]" trick.
- The same shadow-space reuse appears in his §6.1.8 (calling conventions) — two independent witnesses that this is the canonical idiom, not a compiler quirk.
> Same approach: §3.26.1 shows the dirty 32-bit counterpart — a callee walking `&its_own_arg` upward reads the *caller's* arguments and return address (stack-dump loop printing RA into main, 0x64, 0xc8, pointer — "X-Ray of the call frame").

### C++ classes: thiscall and why mangling exists (src: Yurichev RE4B §3.18.1)
Author: Dennis Yurichev
- A class with 2 ints compiles to a plain 8-byte struct; `main` does `lea ecx,[c1]; call ??0c@@QAE@XZ` / `push 6; push 5; lea ecx,[c2]; call ??0c@@QAE@HH@Z` / `lea ecx,[..]; call ?dump@c@@QAEXXZ` — **this travels in ECX (MSVC thiscall)**, other compilers pass it as the first stack argument (GCC): same binary, different convention, always identify the compiler first.
- The mangling rationale worth internalizing: neither the linker nor the PE loader knows C++ exists, so class+method+all-argument-types are *encoded into the ASCII symbol* (`??0` prefix = constructor, `?dump@c@@QAEXXZ` = method dump of class c taking nothing returning void). Demangling is therefore not decoration-recovery but signature recovery — exports of C++ DLLs carry full prototypes for free.
- Constructor fingerprint: prologue stores ECX to `[ebp-4]` as `_this$`, fills fields at offsets 0/4, and **returns this in EAX** (required so `new` chains). A function that saves its first ECX to a local, writes through it, and returns that same pointer = ctor.
- Destructor follows the same shape with the `??1` prefix; spotting `??0/??1/??4` (scalar deleting dtor) trios reconstructs object lifecycle without running the binary.
> Same approach: §3.18.2 ostream (operator<< chains), §3.18.3 References (compile to plain pointers), §3.18.5 Memory (new/delete loops).

### std::string internals: SSO layout dump recipe (src: Yurichev RE4B §3.18.4)
Author: Dennis Yurichev
- MSVC `std::string` (basic_string) is 24 bytes on x86 / 32 on x64:
```c
struct std_string {
    union { char buf[16]; char* ptr; } u;  // SSO: <=15 chars live inline
    size_t size;      // 'Mysize' in MSVC
    size_t capacity;  // 'Myres'  in MSVC
};
```
- Read any string in a dump with one ternary: `p->size>16 ? p->u.ptr : p->u.buf` — do not assume the first qword is a pointer; short strings are the bytes themselves (that is why so many "pointer-looking" fields in MSVC binaries contain ASCII).
- The standard does not mandate the layout — this recipe is MSVC-only; GCC libstdc++ uses ptr/size/union-with-15-byte-buffer + reordering. Version-peg the runtime before scripting struct walks.
- Practical fallout he names: the buffer stays zero-terminated so `printf("%s", &s1)` works directly on the object — seeing code take the *address of the object* as a char* is itself an SSO tell.
> Same approach: same subsection family covers std::vector (three pointers: begin/end/capacity) and container iteration inlining under -O2.

### Duff's device: unrolled tail via fall-through switch (src: Yurichev RE4B §3.8)
Author: Dennis Yurichev
- The memset-style example splits a byte count into `count>>3` 8-byte blocks plus a `count&7` tail; the tail is `switch(count & 7){ case 7: *dst++=0; case 6: ... case 0: ; }` — **no breaks**: every case falls through, and the switch *jumps into the middle of the run*.
- Recognition: a jump table whose targets are successive instruction addresses inside a straight-line store run = Duff's device (or its memset cousin), not obfuscation. The compiler emits `jmp table[count&7]` where table[k] points at the (7-k)-th store.
- Why the bit tricks work: 8 = 2^3, so division/modulo collapse to shift/mask; the "is there any full block" test is `count & ~7 == 0`. The same shape appears wherever block-plus-tail processing shows up (crypto buffers, memset/memcpy clones) — when the modulus is *not* a power of two, you are back to magic-number division (§3.9).
- Performance footnote from the author: unrolling won on old CPUs; modern ones often do *better* on short loops that fit the µop cache — so a modern binary with Duff-style code is either inherited or deliberately weird.
> Same approach: §3.8.1 discusses when unrolling helps (loop body fits L1/µop cache).

### Negative array indices & address-from-the-end (src: Yurichev RE4B §3.19)
Author: Dennis Yurichev
- ARM64 month-table access compiles to `ldr x0, [x1, w0, sxtw 3]` — the index is **sign-extended (`sxtw`) and scaled (<<3)** *inside the addressing mode*; a negative month correctly picks an element *before* the table base. Seeing sxtw in an addressing operand = the source indexes with a signed (possibly negative) int.
- The classic source pattern is `table_end[-n]` / addressing a block from its end; on x64 it shows up as `movsxd` + `[base + idx*8]`. Misreading the sign-extension as noise breaks every offset calculation for that table.
- Companion trick in the same chapter: string indexing via `"string"[i]` works because the literal decays to a pointer — binaries sometimes *read string constants backwards* (serial checks comparing from the last char) which looks like out-of-bounds reads unless you expect negative indexing.
> Same approach: §1.20 arrays chapter shows the same Keil DCD offset-table idiom (`DCD ||.conststring||+0x11` per month).

### Zobrist-style incremental XOR hash (src: Yurichev RE4B §2.6/§2.7)
Author: Dennis Yurichev
- Chess-position hashing: `uint64_t table[12][8][8]` of random values; `hash ^= table[piece][row][col]` per occupied square. The property that matters: moving one piece updates the hash with **two XORs** (`^= old_cell; ^= new_cell`) instead of a full recompute.
- Recognition: a big const array of random 64-bit values XOR-accumulated by multi-dimensional index = Zobrist hashing (game AI, board state caches, dedup). It is *not* encryption despite looking like it.
- Reversing consequence: such hashes are trivially forgeable — flip the two cells you want and the "checksum" still matches; never treat them as integrity protection.
- Adjacent idiom in §2.7: POPCNT (Hamming weight) as a compact per-value signature; compilers emit `popcnt` only with the right -march flags, so its presence pegs the build target fairly tightly.
> Same approach: population-count puzzles in challenges.re bit-field exercises (##67-70).

### setjmp/longjmp as stack time travel (src: Yurichev RE4B §3.25)
Author: Dennis Yurichev
- longjmp restores (almost) all registers, takes RA from the jmp_buf and jumps — "as if setjmp() returned non-zero". Everything pushed between the two calls is simply *abandoned*: no destructors, no frees — dangerous in C++, still used in production (Oracle RDBMS named as a live user).
- The author's security observation: if a buffer inside a function overflowed (remotely) and the error path longjmps out, the overwritten stack region is skipped rather than crashed on — longjmp can *mask* corruption that a return would have tripped over. In crash-free-but-weird targets, look for setjmp frames.
- Exercise he leaves (worth actually answering once): why are XMM0-XMM5 and friends *not* saved? (ABI: caller-saved, nobody expects them to survive a call boundary — jmp_buf only keeps what setjmp's caller could legally rely on.)
> Same approach: §3.26 "weird stack hacks" — walking `&first_arg` upward to read the caller's frame (see variadic entry above).

### Linear congruential generator recognition (src: Yurichev RE4B §1.23)
Author: Dennis Yurichev
- `state = state*1664525 + 1013904223; return state & 0x7fff` — Numerical Recipes constants. Seeing the pair **1664525 / 1013904223** (0x41C64E6D / 0x6073) in a multiply-add chain = home-rolled LCG (glibc-style `rand()` uses the same family; Java uses 0x5DEECE66D+0xB).
- Reversing consequence: LCG output is fully predictable from one observed value — seed recovery by modular inverse, then predict/forge every subsequent "random" token, session id or key material.
- Thread-safe variant compiles the state update into one instruction region with a CAS/retry loop around it — the retry loop is the fingerprint that the LCG state is a global.
> Same approach: §2.6.8 documents `XOR reg,reg`=MOV 0, `OR reg,-1`=MOV -1 (shorter encoding) — why zeroing XORs are everywhere and not suspicious by themselves.

## III. Obfuscation & protection catalog (Yurichev RE4B §3.17 + cases)

### String hiding: byte-per-byte build & compare (src: Yurichev RE4B §3.17.1)
Author: Dennis Yurichev
- The simplest professional-grade anti-strings trick: build the string on the stack with `mov byte ptr [ebx],'h'; mov [ebx+1],'e'; ...` — invisible to `strings`, IDA string window and hex-editor grep.
- Its compare twin is even more common in license checks: `cmp byte ptr [ebx],'j'; jnz fail; cmp [ebx+1],'o'; jnz fail; ...` — the serial "joh n" never exists as a contiguous byte sequence anywhere in the file.
- Piecewise construction via `sprintf(buf,"%s%c%s%c%s","hel",'l',"o w",'o',"rld")` looks deranged in C but defeats plain string search cheaply.
- Legitimate use worth knowing: PIC and shellcode cannot put strings in .data, so byte-stacks there are *not* obfuscation. Discriminator: surrounding code is position-independent (no absolute relocs) → shellcode; reloc-rich binary with byte-stacks → deliberate hiding.
> Same approach: §8.5.2 (SCO OpenServer dongle) decrypts every string right before use — each usage site is preceded by a small decrypt stub.

### Garbage instructions, bloated equivalents, opaque predicates (src: Yurichev RE4B §3.17.2)
Author: Dennis Yurichev
- Garbage insertion uses *dead registers* (ESI/EDX untouched by real code) interleaved between real instructions; junk may still consume real intermediate values "for extra mess".
- Instruction bloating table (memorize — it is the vocabulary of every packer stub):
```
MOV op1,op2      -> PUSH op2 / POP op1
JMP label        -> PUSH label / RET          ; IDA loses the xref
CALL label       -> PUSH ret_addr / PUSH label / RET
PUSH op          -> SUB ESP,4 / MOV [ESP],op
```
- Opaque predicate: `mov esi,1 ... dec esi ... cmp esi,0 / jz real_code` with ESI provably always 0 — the jz is always taken, `fake_luggage` between is dead bytes. Or `add eax,esi` with esi==0 folded into real arithmetic.
- Spaghetti: rewrite `insn1;insn2;insn3` as `jmp ins1; ins2: insn2; jmp ins3; ...` — every real instruction behind its own jump. Indirect-pointer variant: reference `dummy_data+0x100` so IDA shows xrefs to the dummy blob, never to the string that lives inside it.
- Case-flip footnote: `c^0x20` inside a-zA-Z flips case — old keyboards toggled Shift by flipping bit 5, so ASCII case pairs (and digit/symbol pairs) are structurally regular (Eric S. Raymond's "things every hacker once knew"). Case-insensitive compares compile to xor-normalize loops; serial alphabets transforming via ±0x20 are case maps, not crypto.
> Same approach: §3.17.3 VM/pseudo-code — translate to custom bytecode + interpreter, the manual ancestor of VMProtect.

### Dongle emulation: string → xref → invert one branch (src: Yurichev RE4B §8.5)
Author: Dennis Yurichev
- Workflow on an unknown arch (MacOS Classic PEF/PowerPC, unfamiliar to the analyst): find "Invalid Security Device" string → xref lands at `li r3,1; bl check1; clrlwi r0,r3,24; bne OK; lwz r3, aInvalidSecurityDevice` → the single BNE decides everything. Emulation = force the check to pass.
- On x86 DOS extender code the same case is bypassed by **rewriting the check function's head**: `mov ax,0 / retf` — a three-byte "always no-dongle" replacement; `retf` because the check was far-called in the segmented memory model.
- Bonus fingerprint from the same case: DOS far-pointers — `strcpy` is called with **four** pushes (`push ds; push offset src; push ds; push offset dst`) because one C pointer = segment:offset pair. Seeing 2 pushes per "pointer argument" = 16-bit segmented model, adjust every stack-offset calculation accordingly.
- The author's meta-lesson: dongle checks are guarded by *one* data-dependent branch 90% of the time; the work is finding which one, not defeating crypto.
> Same approach: §8.5.2/§8.5.3 (SCO OpenServer, MS-DOS) — encrypted strings + many scattered checks survive the single-branch pattern.

## IV. Locating code & data in unknown binaries (Yurichev RE4B ch.5)

### XOR-scan of a whole listing (src: Yurichev RE4B §5.8)
Author: Dennis Yurichev
- `XOR reg,reg` (same operands) = zeroing, totally innocent. `XOR a,b` with **different, large** operands is rare in normal code and "widespread in cryptography, including amateur one" — flag every such site as candidate decrypt/checksum routine.
- Ready-to-run AWK filter over an IDA `.lst` dump (adapt the column logic to your disassembler):
```awk
$2=="xor" { tmp=substr($3,0,length($3)-1);
            if (tmp!=$4) if($4!="esp") if($4!="ebp") { print $1,$2,tmp,",",$4 } }
```
- Documented exceptions that will otherwise pollute results: stack canary generation/checking uses XOR (1.20.3); misdisassembled data regions also emit pseudo-XORs — cross-check with a second disassembler before believing a hit.
- Companion heuristic §5.8.2: modern compilers never emit `LOOP` or `RCL` — spotting them = hand-written assembly (license checks, shellcode stubs, compiler-avoiding authors) and worth a manual read.
> Same approach: §5.10 — any file/buffer-processing task implies a decrypt/process LOOP; grep trace logs for the loop body iterating file-size times.

### Magic numbers as contrast agent while tracing (src: Yurichev RE4B §5.9)
Author: Dennis Yurichev
- To learn how a program consumes a file/packet field: **overwrite 4 bytes of the input with a unique value** (0x0badf00d, a birthdate 0x11101979), run under a tracing tool in code-coverage mode that logs every executed instruction with register/memory values, then `grep` the trace for the value.
- Every hit is one hop of the data-flow graph: loaded here, added there, compared there — a poor man's taint analysis that needs no tooling beyond a tracer (his `tracer`, DosBox `heavydebug` for DOS targets, x64dbg trace+`TraceLog` equivalents).
- Constraints: the number must be unique in the binary's own code/data (else false positives); technique is not 100% reliable (value may be transformed before reuse) — grep for the raw value, byte-swapped halves, and XOR-with-common-constants variants.
- The medical metaphor is the mnemonic: inject contrast agent → X-ray the flow. Works identically for network packets.
> Same approach: §5.10 loops (find the loop that runs exactly filesize iterations); his Excel FDIV practical joke uses the same tracer `bpx=...,set(st0,666)` to prove which instruction renders a cell.

### Minesweeper: auto-locate the grid via sentinels (src: Yurichev RE4B §8.3)
Author: Dennis Yurichev
- The 9x9 board lives in one flat array wrapped by a **border of 0x10 bytes with 0x0F filler rows** — sentinels the UI never shows. ReadProcessMemory the whole region, then `memcmp` scan for the 32-byte pattern `\x10×11 \x0F×20 \x10` — the match address *is* the grid, no hard-coded offsets, version-independent.
- Generalizable: game/app state arrays almost always carry sentinel borders (simplify bounds checks in the original code); scanning for the sentinel frame locates the structure across versions and ASLR.
- Chapter exercises point at the underlying question — why sentinels exist and what other cell values appear (opened, flagged) — i.e. read the enum by dumping states after in-game actions.
> Same approach: his Windows clock hack (precalculated coordinate table + MulDiv rescale) — recognize data tables by their use pattern, not by symbols.

## V. Crackme solution patterns (crackmes.de archive → crackmes.one)

### Easy-tier ladder: strings → ltrace → break-before-compare (src: crackmes.one Wheredakey / thefirsttest)
Author: Glitch_Baby / JoeJoeJoe (+ community writeups)
- Wheredakey (x86-64 ELF, strcmp): the community's 10 writeups converge on a 3-step ladder — (1) `strings` (or Ghidra pseudo-C) for a hardcoded password; (2) `ltrace` to watch the strcmp arguments live; (3) GDB breakpoint *before* the compare, read the register/stack slot holding the expected string.
- thefirsttest adds the classic gotcha: input is parsed by `scanf("%d")` and compared against hex constant `0x72abb3c9` — the "password" is the **decimal rendering** of the immediate. When a string password fails, always check whether the comparison target is an integer and the input was atoi'd.
- Writeup taxonomy worth copying: each solution names one tool and one observation — the diversity (strings/ltrace/gdb/Ghidra/registers) is the lesson: pick the cheapest window that shows the expected value, don't ritualistically decompile.
> Same approach: the whole 1.x difficulty band on crackmes.one; imported crackmes.de archives solve the same way with OllyDbg.

### Orrery 2: living VM — daily opcode permutation (src: crackmes.one Orrery 2)
Author: SVz
- Design: serial validation runs on a **stack VM whose bytecode is regenerated, opcode-permuted and re-encrypted every day** — valid serials are day-dependent and name-keyed; success prints `ORRERY2{fingerprint}`.
- The intended solve path stated by the author: (1) devirtualize the VM (recover the opcode map for *today's* build), (2) model the probe-survey logic over the hidden 12x12 grid (11 planets, 6 rings), (3) write a keygen for the `XXXXX-XXXXX-XXXXX` format.
- Distinctive lesson for VM targets: when the bytecode is *derived from the date*, the dump you took yesterday maps to different opcodes today — keygen must re-derive the permutation, not replay a trace. Solvers who merely found one serial (the three comment "solves") produced day-expiring answers; only devirtualization generalizes.
> Same approach: CERBERE stage 1 (VM) — same devirtualize-then-algebra pipeline.

### CERBERE: chained VM + lattice reduction + discrete log (src: crackmes.one CERBERE)
Author: TrynaToBe6for6Def
- Hardest-tier crackme (5.7): three chained stages, solved in comments as **VM reversing → lattice reduction (LLL) → discrete logarithm**. The crypto tail is the differentiator: the final check is an algebraic relation (hence LLL for approximate/bounded solutions and dlog for exponent recovery), not a byte compare.
- Protection set (site labels): IsDebuggerPresent + PEB checks + INT3 scanning + hardware-breakpoint detection, XOR/table string encryption, self-modifying code, SHA-256, code virtualization, anti-tamper.
- Pattern to remember: when a crackme's final compare is over *transformed* values (hashes, modular exponentials), patching the branch proves nothing and keygenning requires solving the underlying number theory — budget your time on the math, not the anti-debug layer (bypass once, symbolically execute past it).
> Same approach: VSEC Challenger #3's unresolved dispute is exactly this fork — is the password stored (extract from VM state) or only hashed (preimage problem)?

### TotalALL | The Last Gate: packer + self-debugging + decoys (src: crackmes.one TotalALL)
Author: CrackNotMe
- Architecture: custom packer/loader, **parent-child process pair where the parent debugs the child**, multiple VM stages, and decoy paths that *never* produce a fake success message — failure looks identical whether you fell for a decoy or not.
- Rules of engagement (author-enforced): keygen/reproducible solver accepted, patching rejected; "a memory dump may help, but it will not explain the password-checking logic" — i.e. dump-and-static-analysis is deliberately insufficient, the VM must be understood.
- Reversing lessons: (1) self-debugging parent-child defeats single-process debuggers — attach to the child *as the parent does*, or break the DebugEvent loop; (2) no-fake-success decoys kill the classic "patch the failure jump" shortcut because you cannot distinguish success-shaped code from decoys without semantics; (3) multi-stage VMs = devirtualize stage by stage, persisting intermediate state.
> Same approach: matryoshka9 (9 nested self-modifying layers, "well-written solver runs in ~30 ms"); Tetris DRM below.

### Tetris DRM: reconstruct a dead license server (src: crackmes.one Zydak's Tetris DRM)
Author: Zydak (game by Xusheng)
- A retro Tetris whose DRM phoned home to a **shut-down server**; offline it enters a corrupted state. Solve: patch the `exit(1)` out of the failed handshake, then **reconstruct what the server was supposed to send** (it only ever talked to localhost — emulatable fully offline) and beat 5 levels to surface the flag.
- Distinctive pattern: "network DRM" reversing is not just branch-patching — you must infer the server's protocol/response format from the client's parsing code (miniaudio/termbox2 dependencies noted for orientation) and answer it correctly.
- Generic takeaway: any client that parses structured server data embeds a *specification of that data* in its parsing routines; read the parser as the protocol definition and write the fake server to match.
> Same approach: Yurichev's SAP traffic-compression case (read the decompressor as the wire-format spec).

### VSEC Challenger #3 label taxonomy (src: crackmes.one VSEC #3)
Author: VSEC
- The challenge itself is unremarkable (24-char password, C++ x64), but its **label set** is the best one-line checklist of modern protection combos seen in the wild on crackmes.one: UPX packing → string encryption → code virtualization → control-flow flattening → spaghetti/junk branches → indirect & computed calls → stack/return-address-based dispatch → anti-disassembly → junk bytes → opaque predicates → overlapping/misaligned instructions → jump-based desync.
- Use it as a triage rubric: each label maps to a known counter (unpack first; string-decrypt stub scan; devirtualize dispatcher; deflattening; realign from a clean indirect-jump; trace to recover computed targets...). Count how many labels fire before choosing tooling — ≥5 labels means scripted/trace-driven analysis beats manual.
- The attached dispute is itself instructive: a solver patched the final compare claiming "password only exists as a hash vs a 64-bit constant"; the author insists the key is extractable by analyzing the VM. Both positions define the extract-vs-preimage fork every keygen target presents.
> Same approach: matryoshka9 asks solvers to report agent time/token usage — the archive is now also an AI-agent benchmark (see below).

### crackmes.de legacy archive mechanics (src: crackmes.one imported solutions)
Author: crackmes.one maintainers
- crackmes.de is gone; crackmes.one absorbed the full archive. Imported writeups show "This writeup is only available for download" — the zip is password-protected with **crackmes.de** (newer ones with `crackmes.one`). Plan for this when batch-mining old solutions: fetch `/static/solution/<id>.zip`, unzip with the archive password, expect mixed OllyDbg-era formats.
- Site mechanics that matter for mining: difficulty 1-6 *user-voted*, quality 1-5 separately; writeups are counted per crackme; comments often contain spoiler-flagged serials — solving an unlisted crackme's approach from comment spoilers is possible without downloading the binary.
- challenges.re (Yurichev's exercise site) is the book's companion: 87 numbered exercises, no solutions published on purpose; tagged classes — "black boxes" (level 3), obfuscation, unknown cryptoalgorithm, simple copy-protection, 4-byte XOR mask, LOOP-instruction, bit fields, crackme/keygenme, broken compression algorithm. Numbering is chaotic and permanent: cite by number.
> Same approach: the site's auto-validated crackmes (submit key, server checks) — same loop as keygen verification in `../06-crypto/keygen-algorithm-cases.md`, different packaging.

## VI. File-format & entropy craft (Yurichev RE4B ch.9)

### Entropy as compressibility + trigram language recovery (src: Yurichev RE4B §9.2)
Author: Dennis Yurichev
- Working definition he teaches: entropy = how tightly data can be compressed; 1 MiB of zeros compresses to nothing (low entropy), an already-compressed archive won't compress further (high). Compute over sliding windows to *segment* a file into plaintext/packed/encrypted regions.
- When you gradually decrypt a ciphertext (rolling key, partial recovery): score candidate plaintext with **trigram frequency** — test 3 adjacent decrypted characters against English "the"/"tha" rates (cites the N-Gram-Based Text Categorization recipe). Cheaper and more robust per-byte than dictionary matching.
- UTF-8 tell: Cyrillic text interleaves every second byte with 0xD0/0xD1 (Unicode block 4) — a structural fingerprint for identifying *language* (and thus plaintext-ness) even before full decryption; other scripts carry their own block bytes.
- §9.2.9 "Making lower level of entropy": attackers deliberately re-encode high-entropy payloads (e.g. Base64-ish expansions) so naive entropy scans miss them — always pair entropy with alphabet analysis.
> Same approach: §8.7 encrypted-database case walks Base64 detection → compressed? → encrypted? → CryptoPP identification → CFB mode → IV brute-force, the full classification ladder in one case.

### Position-additive cryptor break (src: Yurichev RE4B §8.9)
Author: Dennis Yurichev
- Simplest possible executable cryptor: every byte of the section is `(byte + position) % 256` — encoded in two lines of Python. Recognition cue: decryption stub is a loop doing `sub`/`add` with the loop counter on the same register used as index.
- Break: replicate the transform offline, or dump after the stub ran. The chapter's point is the *decision tree*, not the cipher: try constant XOR → position-dependent add/xor → rolling key derived from previous byte, in that order of simplicity.
- His Cointerra companion case (§8.8) shows the same reading skill on constants: `MOV R3,#0x51EB851F; SMULL ...; ASR#4` decodes (via modinv32 → 3.125, plus shifts → /50) to a divisibility check `x - (x/50)*50 == 0` rejecting frequencies not multiple of 50. Magic constant + high-half multiply = division by something; always invert before assuming crypto.
> Same approach: QR9 below for the amateur-crypto extreme.

### QR9: Rubik's-cube cipher (src: Yurichev RE4B §8.6)
Author: Dennis Yurichev
- An amateur encryption utility whose lost-source algorithm had to be recovered from IDA listings of `set_bit`/`rotate1`/`rotate2` primitives — the cipher is bit-permutation surgery conceptually close to rotating cube faces.
- Distinctive mining value: the *method* for amateur crypto — list the primitives (bit set/clear/test, rotate direction pairs), count state size (how many bits carried), infer the round structure from call multiplicities, then re-implement in C and verify against known plaintext/ciphertext pairs.
- Amateur-crypto markers he catalogues: fixed S-box-ish permutation tables, symmetric encrypt/decrypt (same routine reversed), byte↔bit unpacking loops, and constants that are round counts rather than algorithm magic numbers.
> Same approach: challenges.re exercises tagged "unknown cryptoalgorithm" and "amateur cryptography" (##25, 33, 34, 42, 44, 50) are drills for exactly this method.

## Sources

- mytechnotalent Reverse Engineering hub (RE4E) — https://github.com/mytechnotalent/Reverse-Engineering
- mytechnotalent Hacking Windows — https://github.com/mytechnotalent/Hacking-Windows
- mytechnotalent AArch64-Bytes — https://github.com/mytechnotalent/AArch64-Bytes
- RE4E assembled ebook (0xInfection GitBook mirror of mytechnotalent's series) — https://0xinfection.github.io/reversing/
- Dennis Yurichev, Reverse Engineering for Beginners (free book landing) — https://beginners.re/
- RE4B-EN.pdf mirror used for mining (July 9 2018 text version) — http://ebook.pldworld.com/_eBook/Reverse%20Engineering%20for%20Beginners/beginners.re/RE4B-EN.pdf
- Yurichev challenges.re exercise index (87 exercises) — https://challenges.re/
- crackmes.one (successor host of the crackmes.de archive) — https://crackmes.one/
- CERBERE crackme page — https://crackmes.one/crackme/6ac27efc0885f990699dc0fa
- TotalALL | The Last Gate — https://crackmes.one/crackme/6ab8ef470885f990699dbfee
- Orrery 2 — https://crackmes.one/crackme/6ac2301aca34abba98f82e95
- VSEC Challenger Num #3 — https://crackmes.one/crackme/6acd5d2d6349e4b2540c70d8
- Zydak's Tetris DRM — https://crackmes.one/crackme/6ac989246349e4b2540c6fe9
- matryoshka9 — https://crackmes.one/crackme/6ad44c6c5fa39ab0d4ac1c16
- thefirsttest — https://crackmes.one/crackme/6abc48c1ace07d1c3fbc4816
- Wheredakey — https://crackmes.one/crackme/6ab4ce5195b976f8f1300b54
- Imported crackmes.de solution example (keygenme3, archive password crackmes.de) — https://crackmes.one/solution/5ab950a233c5d422feed7ef7
