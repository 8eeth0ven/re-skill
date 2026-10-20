# CTF Writeup Methodology (knowledge base · CTF writeup 1001414)

> Corresponding directory tree: CTF writeup [1001414], 23 nodes in total. Per-category playbooks are distilled following ExploitMe → Pwn (user mode / kernel mode / environment) → Web → Reverse → Crypto → misc → CrackMe; the signature contest format (KCTF attack-defense) and the historical events (the KCTF [1001027] tree) are folded in as well.

> Boundary: detailed **vulnerability-principle explanations** for Pwn (per-challenge heap/GOT/sandbox-escape detail) overlap with the binary-vulnerability area and live in 06-binary-vuln; this article provides only **methodology and indexing**.

---

## §1 General CTF Solving Mindset

1. **Classify before you act**: file/checksec/pack detection → route into the five major categories (Pwn/Reverse/Web/Crypto/misc).
2. **For reverse challenges, run before you read**: observe behavior first (input/output, anti-debug popups), then open IDA; strings and constant tables are ready-made leads.
3. **For pwn challenges, check protections first**: `checksec` (NX/PIE/Canary/RELRO) directly decides the exploitation route (§3).
4. **Post-contest retrospectives beat flag counts**: the corpus forum culture treats "the writeup itself as study material"; the digest section carries many post-contest retrospective threads (Xihu Lunjian / CTF retrospectives; see the sister IoT articles).

Official entry points:
- KCTF platform ctf.kanxue.com (attack-defense season pages include the official writeups)
- Historical challenge collections: Evil0ctal/Kanxue-CTF-Challenge

---

## §2 ExploitMe (a community institution) [1001011]

The forerunner of community-run CTFs: **the organizer posts a vulnerable program, and whoever writes a working exploit first wins**. The 2007/2008 Exploit Me challenge contests (problems plus full solution analyses, collected in full) were the textbook of the Windows-overflow era:
- Playbook = stack overflow/heap overflow → rescue SEH/VEH → bypass SafeSEH/DEP (back then the main weapon was proto-ROP ret2libc).
- Value today: **reading the old writeups teaches the complete reasoning chain of "manual exploitation without metasploit"**, in direct lineage with modern Windows user-mode exploitation (§3.2).

## §3 Pwn [1001012]

### 3.0 Environment and Prerequisites [1001765]

- OS: one Docker container per challenge, pinned to each Ubuntu release (the glibc version decides heap behavior; 2.23/2.27/2.31/2.35 are must-haves).
- Tools: pwntools (scriptable IO) + gdb (gef/pwndbg) + one_gadget + ROPgadget/Ropper + LibcSearcher/glibc-all-in-one; IDA/Ghidra for static work.
- Command shorthand: `checksec ./pwn; file ./pwn; seccomp-tools dump ./pwn` (sandbox detection; orw/seccomp rules directly change the plan of attack).

### 3.1 Linux User-Mode Exploitation [1001687]

Master index entry: the categorized index of curated threads in the CTF "Pwn" section (stack overflow/ret2libc/ret2csu/retdlresolve/SROP/heap/format string, all covered; **the source of this article's methodological skeleton**). Starter read: "CTF-PWN from Scratch (Part 2): Stack Overflow".

#### 3.1.1 Stack Overflow [1001695]

```
checksec → 无NX:ret2shellcode;有NX:ret2libc
         → 有Canary:泄露canary(格式化串/输出函数)再回填
         → PIE:先泄露返回地址低12位同页性质或放弃栈上定址
         → partial overwrite 是 PIE/ASLR 万金油(改低1-2字节)
```
(hand-drawn ASCII decision tree)
Beyond the basics, the index thread collects: ret2csu (64-bit gadget shortage), retdlresolve (forge an Elf64_Rel to resolve system when no libc is available), SROP (forge the sigreturn frame for clock-interrupt-grade context restoration).

#### 3.1.2 Heap Exploitation [1001696]

The main line = a history of glibc heap attacks:
- **unlink** (the pre-2.23 classic): forge fd/bk so that `FD->bk==P && BK->fd==P`.
- **fastbin attack**: overwrite fd → arbitrary allocation; fastbin dup uses 0x7f to fool the size check.
- **The House of series** (Orange/Force/Lore/Atum...): top-chunk overwrite / house of orange triggering `_IO_list_all` → FSOP.
- **tcache** (2.27+): tcache poisoning turns a single write into arbitrary-address allocation; 2.29+ adds the key double-free check — the bypass is to alter the key before performing the double free.
- **Newer glibc**: 2.34+ removed `__free_hook/__malloc_hook` → pivot to exit_funcs/_IO_FILE vtable/ld-chain attacks on `_rtld_global`.
- Landmark writeups: **house of kiwi** (early glibc 2.34; overwrites the `_IO_file_jumps` vtable pointer to trigger; killed off by vtable validation in later versions, but the methodology remains the prerequisite for Emma) and **house of emma** (an FSOP variant: hijack stderr and offset the vtable into the legitimate `_IO_cookie_jumps` region to pass the `__libc_IO_vtables` range check, overwrite `__pointer_chk_guard` to confuse the pointer-mangling key, then trigger the cookie callback through a Kiwi-style `__malloc_assert` to reach system); same-family spin-offs include house of apple 1/2, house of cat, and house of bnana. External canonical references: evilpan's IO_FILE techniques, roderickchan's House-of compendium, how2heap.

#### 3.1.3 Format String [1001699]

- Three steps: probe the offset with `%p` → write with `%n` (`%hhn` for byte-granular segmented writes) → for large values, combine `$` positional access with width padding.
- When there is no binary to leak from, `fmt` is the universal read: `%12$p` lands right on the key; for multi-round interaction use one_gadget or write a ROP chain onto the stack.
- Related tree: format-string principle deep-dives belong to 06-binary-vuln `1000985`.

#### 3.1.4 Practice-Platform Write Ups [1001700]

- **pwnable.kr** [1001697]: "Sharing my approach to the ascii challenge on pwnable.kr" (idea-driven problems beyond fd/collision/asm); full-level external reference: veritas501's writeup.
- **WarGame XCTF** [1001698]: the pwn zone of XCTF's attack-defense world (a dedicated node in the knowledge-base tree); the local digest corpus confirms in-site writeups: XCTF attack-defense world level2, the classic integer-overflow challenge XCTF int_overflow, the XCTF app3 challenge, and XCTF mobile newbie-zone solving notes (mobile side); the 2017 WiFi Master Key CTF challenges 4/5 writeup cluster likewise counts as in-site contest original material.
- Other practice ranges: DVRF (router pwn, cross-linked from [iot/firmware-emulation.md](iot/firmware-emulation.md)) and BUUCTF reproduction environments.

### 3.2 Windows User-Mode Exploitation [1001689]

- The progression: SEH exploitation → SafeSEH/SEHOP bypass → DEP (ROP) + ASLR (info leak first) → the CFG/VirtualAlloc protection surface.
- Dedicated threads are thin in this tree (the digest-section mainstream lives in 06-binary-vuln's "Exploit Writing Series" [1000990] and "Windows Vulnerability Exploitation Development" [1001435]); the boundary recorded here: methodology = the stack/heap/shellcode trio does not change, what changes is the protection-mechanism checklist.
- Browser/kernel routing: Edge/Chrome renderer vulnerabilities belong to the browser-vulnerability node of the 06 area [1001439].

### 3.3 Linux Kernel-Mode Exploitation [1001691]

- Prerequisites: a self-built kernel debugging environment with QEMU + busybox (`-s -S` + gdb vmlinux); pull symbols from `/proc/kallsyms` (needs kptr_restrict=0).
- Playbook checklist: integer overflow/UAF/slub double-fetch → `commit_creds(prepare_kernel_cred(0))` → under KPTI, return via `swapgs_restore_regs_and_return_to_usermode`; overwriting modprobe_path is the low-effort route on 5.x and later; msg_msg/pipe_buffer are the workhorse primitives on 5.9-6.x (external body of work; the in-tree deep-dives belong to the 06 area's "Linux Kernel Exploit Learning" [1001433]).
- Container-escape scenarios (cgroup/overlayfs CVE-2021-3493 etc.) cross-link to 03-linux `../03-linux/other-platforms.md` §3 (containers).

---

## §4 Web [1001262]

- Two problem shapes: source-audit (code provided) and black-box (site only).
- Playbook priority: **weak logic (broken access control/password reset/race conditions) → injection (SQL/NoSQL/SSTI) → deserialization (Java/PHP chains) → SSRF/file upload** — a one-to-one mapping onto the vulnerability matrix of the 05-web area [1000965]; details cross-linked from 05-web (not repeated here).
- The Web child nodes in the knowledge-base tree are leaves (no thread-cluster expansion underneath); the methodology here rests mainly on KCTF Web challenges over the years plus the "CTF Training Camp — Web" online course.

## §5 Reverse [1001415]

- Playbook chain: identify the packer (IDA/PEiD/exeinfo) → unpack (the packer catalog belongs to the 01-windows unpacking articles) → recover the algorithm (usually a tweaked TEA/AES/RC4: **compare against the standard constant tables first** — TEA's delta 0x9E3779B9 and the AES S-box are instant tells) → write a keygen or a patch.
- VM / custom-instruction-set challenges: map bytecode → opcode-dispatch switch/jump table to recover instruction semantics; speed things up with unicorn emulation.
- Community flavor: Reverse overlaps heavily with CrackMe (§8), the staple category of the KCTF attack-defense contests.

## §6 Crypto [1001417]

- Real-challenge distribution: classical (classical ciphers + encodings) → symmetric (AES/DES mode misuse: ECB concatenation, CBC bit-flipping, Padding Oracle) → asymmetric (RSA small exponent/common modulus/Wiener/related message, weak-curve ECDLP) → LLL lattices (knapsack/known high bits).
- Tools: SageMath (a must for lattices/elliptic curves), yafu/factordb (factorization), RsaCtfTool.
- Algorithm-theory deep-dives cross-link to the 01-windows Decryption Chapter's Encryption Algorithms node [1000486] (the MD5/SHA/RSA/ElGamal/ECC/DES/AES/TEA theory threads all live there).

## §7 misc [1001419]

- The standard progression: file types (put 010 Editor templates to work) → steganography (stegsolve/steghide/zsteg/frequency domain) → traffic (wireshark/USB keyboard-and-mouse traffic recovery writeups) → forensics (volatility memory) → odd tricks (zero-width characters; the Kanxue-CTF-Challenge collection includes a zero-width stego challenge).
- Hardware-flavored misc (BLECTF/RF) cross-links to [wireless-hw/ble-zigbee.md](wireless-hw/ble-zigbee.md) / [wireless-hw/sdr-wireless.md](wireless-hw/sdr-wireless.md).

## §8 CrackMe and KCTF [1001499]

### 8.1 The CrackMe Tradition

The community's founding culture: crack-me practice applets (serial/keyfile/time limits). The in-tree, book-length tutorials belong to the 01-windows Decryption Chapter (case analyses collected year by year from 2000 to 2024) — **the CrackMe node of the CTF writeup tree is that chapter's CTF-flavored extension**.

### 8.2 The KCTF Attack-Defense Format (unique to this community)

```
防守方(出题):提交题目+漏洞程序     攻击方(解题):限时攻破拿 flag
        └────────── 同一赛季双向计分,题目即攻击面 ──────────┘
```
(ASCII contest diagram drawn by the author, aligned with the official page's description)
- History: CrackMe attack-defense contest → KCTF (challenge categories span Windows/Android/iOS/Pwn/**smart devices** — which makes KCTF the meeting point of every facet of this area's sister articles).
- Historical season tree (KCTF [1001027]): Kingsoft Cup 2007, ExploitMe 2007/2008, Tencent 2008/2010, Qihoo 2008, 2011 ExploitMe, 2015MSC, the 2017 TSRC autumn contest (nine challenges), and the 2017 WiFi Master Key mid-year contest (fifteen challenges).
- Representative recent writeup: "2024 KCTF contest, challenge 10 — a probing writeup" (shellcode + a Huarongdao sliding-block search); the official writeups for each challenge live on the season pages (§1 entry points).
- IoT-flavored contest retrospectives: "Xihu Lunjian 2024 IoT post-contest retrospective, with MQTT RCE in detail", "A general approach to emulating second-development OpenWrt firmware (NepCTF2024)", "Getting started with MQTT protocol pwn (ciscn2025 final)" — **CTF has become the debut venue for new IoT attack surfaces**, which is why this methodology and the articles under [iot/](iot/) are two sides of the same coin.

## §9 One-Page Summary

| Category | First move | Decisive tools |
|------|--------|-----------|
| Pwn | checksec+seccomp | pwntools/gdb |
| Reverse | packer check + constant-table comparison | IDA/unicorn |
| Web | audit the logic, not the features | burp |
| Crypto | identify the math structure | sage |
| misc | file/strings/binwalk | stegsolve/010 |
| CrackMe/KCTF | run it and observe | x64dbg |
