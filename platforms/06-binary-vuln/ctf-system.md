# The CTF System (KCTF rules + annual challenge tech points + CTF reversing/PWN methodology)

> Local article citation format: `[精华N-<tid>] title`
> Cross-links: heap/stack exploitation principles -> `heap-exploitation.md`; vulnerability types -> `vuln-types-exploitation.md`; CTF reversing tools -> `../01-windows/`; Android challenge reversing -> `../02-android/`

## 1. The KCTF rules

### 1.1 The two-phase attack-defense format (official rule essentials)

- **Phase 1, defense**: the defenders build challenges per the rules and put them on the range; **ranked by "time until cracked"** — the longer you hold out, the higher the rank; never cracked puts you at the top
- **Phase 2, offense**: the attacking teams crack all the challenges, **ranked by number of cracks and total time** (the official pages show the scoreboards of pizzatql/Nu1L/tekkens and other teams)
- Platform: the KCTF online range (past challenges replayable year-round)
- Challenge formats: PWN (Linux userland/kernel/VM), reversing (CrackMe/VM protection/deobfuscation), Android, algorithm challenges; in recent years 8-10 challenges per season, spring and autumn seasons plus the annual final
- History: KCTF's predecessor was the 2017 TSRC autumn CTF (challenges 2 and 3 drew dozens of writeups; back then it was pure CrackMe reversing), which later evolved into the KCTF attack-defense format (the PWN share rose from about the third edition, 2019)

### 1.2 Style evolution

- 2017: CrackMe-heavy (anti-debug/multiple solutions/VM packers); single challenges crowdsourced many posts
- 2020: Android reversing enters (disguised class names/init_array decryption/JNI dynamic registration)
- 2021-2022: PWN becomes the mainstay — BROP, format-string GOT, heap IO_FILE, tcache; novel surfaces appear such as VM/LLVM PASS/lua (LLVM PASS PWN, lua pwn)
- From the setter's seat: "The DAS September Monthly PWN Challenge: a Setter's Journey", "DAS October PWN setting && CVE-2023-40930" (the paradigm of turning a self-found CVE straight into a challenge)

## 2. Annual challenge tech-point tables

### 2.1 Per-challenge distillation of the local writeups (2017-2022)

| Edition/Challenge | Name | Type | Core technique | Key solution |
|---|---|---|---|---|
| 2017 autumn Q2 | Flowers Revealed by Fpc | Reversing | A CrackMe with PWN shadows | 10+ posts of crowdsourced dissection, and more |
| 2017 autumn Q3 | crackMe | Reversing | Anti-debug/multiple solutions | "Hands-On Anti-Debugging" |
| KCTF (classic) | Past and Present | PWN | Format string on the heap | An isatty-independent bug; stack-resident libc leaked with %21$p; a **stack springboard chain** (0x...dec0->def0->df20) with two-stage %n for arbitrary write; one_gadget `execve("/bin/sh",rsp+0x70,environ)` |
| KCTF (classic) | KCTF challenge (Android) | Reversing | Class-name disguise + the native layer | The MainActivity check is fake; the real logic lives in `AppCompiatActivity` (a confusingly similar class name); the so has no eq symbol -> **init_array string decryption** -> JNI_OnLoad dynamic registration -> RC4 (subtract/modify/add steps) + **table-swapped Base64** (a custom 64-character alphabet); a UUID-shaped key |
| 2022 spring Q5 | GetPwn3 | PWN | Format string + GOT | A username +1 check ("rxraclhm"); an ftp semantics challenge: put_file stores name/content, get_file `printf(content)` is the format-string bug, dir -> show_dir calls puts(name); the block name `;/bin/sh;` combined with **overwriting puts@GOT with system** -> dir triggers system("/bin/sh"); no libc file -> compare several function offsets to pin the version |
| 2022 spring Q6 | BROP | PWN | Blind ROP | See `heap-exploitation.md` §8.3: low-byte brute force -> a stop gadget -> a pop chain -> dump the ELF -> SROP shell; the author's two lessons: don't guess gadgets blindly, and once you have leaked something, use what is certain |
| NKCTF 2023 | babyHeap | PWN | off-by-one + tcache | See `heap-exploitation.md` §2.2 |

### 2.2 The companion local challenge bank (contemporary contests; the tech points transfer to KCTF)

| Contest/Challenge | Type | Core technique |
|---|---|---|
| 0ctf2018 heapstorm2 | PWN | unsorted + chunk shrink |
| LCTF2017 2ez4u | PWN | largebin attack |
| Seccon2016 Tinypad | PWN | House of Einherjar |
| ACTF2019 message | PWN | fastbin double free -> __free_hook |
| LCTF2016 pwn200 | PWN | House of Spirit |
| BCTF2018 Atum | PWN | fighting the tcache mechanism |
| 2020 Xiangyun Cup garden | PWN | botcake (glibc 2.31) |
| 2022 Qiangwang Cup House of cat | PWN | High-version IO (the cat technique) |
| ciscn2022 semifinal | Kernel | msg_msg OOB read + pipe_buffer arbitrary write (1 solve) |
| BlackHat2023 Houseofminho | PWN | A 0-solve new IO technique |
| 0ctf2020 chromium_rce | Browser | V8 + sandbox |
| GoogleCTF2018 justintime | Browser | A V8 introduction |
| starctf2019 oob | Browser | The V8 oob.diff template |
| 2023 CISCN Southwest/Central | PWN | Contest practice |
| pwnable.tw/kr | PWN | The grinding platforms for beginners |

### 2.3 2023/2024 KCTF overview

- 2023, 7th edition: the annual final kept the attack-defense format; the challenges spanned PWN (post-glibc-2.35 techniques for the IO/hook-removal era), VM reversing, Android; the writeups shipped as the "Challenge N" post series on the CTF board
- 2024: the defender-rules post; the online range supports replays

### 2.4 The 2017 TSRC autumn CTF: the writeup-crowdsourcing phenomenon

The early days preserved the spectacle of 10-40 writeups on a single challenge (challenge 2, Fpc; challenge 3, crackMe):
- Multiple solutions per challenge were the norm: "Hands-On Anti-Debugging and Multi-Solution Analysis", "True Fans Never Need a Debugger" (a pure static flow)
- **The value for learners**: reading three to five writeups with different ideas on one challenge opens more horizons than grinding ten challenges — still true in the KCTF era (the officials aggregate the offense-side WPs after each challenge)
- Defender style: already "CrackMes with PWN shadows" back then, foreshadowing the later PWN dominance

## 3. CTF methodology

### 3.0 The universal solving flow (an experience digest)

```
Obtain challenge → file/checksec (or APK/SO inspection) → run once and record behavior → locate entries statically in IDA/Ghidra
  ├─ PWN: map menus/input surfaces → flaw (overflow/format string/UAF) → leak → primitive → shell (consider seccomp→ORW)
  └─ RE: locate verification function → handle anti-debugging/obfuscation → restore algorithm (often rc4/base64 variants/custom VMs) → write a keygen
```

- When unsure, start with `checksec` + the libc version to pin the era (the 2.23/2.27/2.31/2.35 technique tiers, see `heap-exploitation.md`)
- Don't mistake remote-vs-local behavioral differences (isatty/buffering) for protections

### 3.1 The reversing track

- **Junk instructions (anti-disassembly filler)**: "A Complete Walkthrough of Junk Instructions in CTF, from Easy to Hard" (Dua0g) — the principle = **disrupting the decompiler's linear sweep** (IDA's linear scan is fooled by garbage bytes embedded after a jmp); it covers the simple/advanced classes (custom junk); **stack-pointer balance** is the construction essential; it also covers writing automated junk-stripping scripts (unicorn/patch)
- **Algorithm restoration**: "The Hacker Spirit: Algorithm Restoration": "Nep CTF password (rc4 + table-swapped base64)" (the same pattern as the §2.1 Android challenge), "enbase64": `LitCTF enbase64`
- **Deobfuscation**: "The 3W-Class Exercise: AntiOllvm Deobfuscation" (OLLVM control-flow-flattening restoration)
- **Mobile challenges**: "Savoring the sec2023 Android Challenges": "smali Editing + log Dynamic Instrumentation": "The MobileCTF easy Series": the AliCrackme series; the toolchain unidbg/frida -> `../02-android/`
- **Forensics**: "A Guide to CTF Forensics Challenges"; cryptography: "A Guide to the CTF Cryptography Track"
- **Debugging environments**: ret-Sync (x64dbg+IDA co-debugging); GDA on mobile; docker ranges

### 3.2 The PWN track

- **The systematic-learning mainline** (the accepted path): the 蒸米 ROP series -> ctf-wiki -> pwnable.kr/tw -> the contest challenges. Local companions: "CTF-PWN from 0 (IV): ROP Bypassing Stack Protection and GOT Hijacking", "Getting into PWN via a Freshman Contest"
- **The heap track**: "Deeply Understanding Pwn_Heap and Related Examples" — **organized by the mainstream glibc tiers 2.23/2.27/2.31/2.35/2.37**, techniques and examples per tier, with IO_FILE as a standalone topic; tools pwncli/PwnGdb
- **Kernel**: "Basic ROP Privilege Escalation" as the entry -> msg_msg/pipe_buffer -> CVE reproduction (`vuln-types-exploitation.md` §3)
- **Heterogeneous ISAs**: "Pwn under the ARM & AArch64 Architectures" (winmt) — the cross-compilation toolchain, handling a symbol-less libc, ARM gadget/stack-layout differences
- **New surfaces**: LLVM PASS, lua, ptrace injection, angr symbolic execution, VDSO
- **Version pinning**: with no libc file, leak the low 12 bits of several functions and compare; replicate the target machine's environment
- **The setter's seat** (the best feedback loop for playing): a setter's journey = designing the test points + preventing unintended solutions; DAS EASYBOX fused the router trio (directory-traversal canary read/command injection/stack overflow) into one challenge
- **AWD**: "A pwntools+seccomp Universal-Defense Tool": "AWD_pwn_patch Notes"
- **Scripting/the team flow**: environment replication, pwndbg+tmux, angr; challenge-bank training: the CTFHub series (ret2dl_resolve, FastBin, UnsortedBin, LargeBin|Storm, ret2VDSO — five articles that together form an advanced heap+stack roadmap)

### 3.3 Training resources

- Platforms: the KCTF range, pwnable.kr/tw, CTFHub, BUUCTF
- The highest writeup-density contests: ciscn/DASCTF/NKCTF/Qiangwang Cup/0ctf/LCTF/HITCON (see the §2.2 table)

## 4. Cross-links

- Heap/tcache/house-of/FSOP/ROP principles -> `heap-exploitation.md`
- V8/kernel/document-type/fuzzing -> `vuln-types-exploitation.md`
- Android CTF challenges (sample counterplay/frida/unidbg) -> `../02-android/`
- Reversing tools (IDA/x64dbg/GDA) -> `../01-windows/`
- Algorithm challenges (cryptography/base64 variants) -> §3.1 of this article
