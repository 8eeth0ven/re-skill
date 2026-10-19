# Knowledge Base · Windows Security · Part 3: Unpacking

> The main line derives from Part 3 of *Encryption & Decryption*, the community's founding "signature skill": software protection analysis, serials/keygens, unpacking and packer confrontation, and cryptography reverse engineering.
> Prerequisites: [basics.md](basics.md) (PE/IAT/relocations), [debugging.md](debugging.md) (breakpoints/exceptions/tools).

## 1. Demo-Version Protection Techniques Overview (Tree Node 1000183)

### 1.1 The Unpacking Knowledge View (1000184)

"Getting started with unpacking" began with the Shang-era cracking tutorials (1000186, an enlightenment post from the 2000s). The methodological core: **protection is "delay", not "prevention"** — every protection must ultimately complete its validation on the user's machine; the reverse engineer's task is to find that "compare/jump" logic and understand or bypass it. The canonical flow:

```
Locate the target (feature/prompt) → locate the code (string/window/message/breakpoint backtrace)
 → understand the validation (algorithm/flag bits/state machine) → pick one of three:
   A. Patch (patch the jump)     B. Write a keygen (invert the algorithm)     C. Forge the environment (keyfile/registry/network packet)
```

### 1.2 Quick Survey of Protection Forms (All Nodes)

| Node | Mechanism | Typical defeat |
|---|---|---|
| Warning window NAG (1000228) | startup delay dialog | find the DialogBox/MessageBox call, NOP it or change the return |
| Time limits (1000231) | GetLocalTime/GetTickCount/SetTimer expiry | make the comparison always false; or freeze system time |
| key file (1000234) | read a file and validate contents | bp CreateFileA/W to catch the filename, forge a valid file |
| Feature limits (1000237) | grayed menus/disabled-feature flags | change the flag's memory value → hardware write breakpoint to find the decision point |
| CD-check (1000240) | GetDriveType/read volume label/hidden track | fake CD drive/change the check |
| Watermarks (1000243) | registration info embedded in output | locate the assembly code, blank it |
| Self-checks (1000244) | CRC/Hash over its own code sections | bypass with hardware breakpoints (Debugging §3.4) |
| Network validation (1000245) | server-returned challenge-response | capture and forge the response/protocol analysis (§7) |
| Ad removal (1000246) | ad windows/popups | locate the destroy call by window class name |
| Menu feature limits (1000247) | EnableMenuItem etc. | change the call arguments |
| Web encryption (1000248) | JS obfuscation/encryption | deobfuscate (Languages, JS) |
| Floppy encryption (1000249) | special sector/bad-track fingerprint | historical: duplicators/emulators |

Self-checks merging with anti-debugging is exactly the modern in-packer environment (see the Protection chapter; not expanded here).

## 2. Serial Protection and Keygens (Tree Node 1000189, Case Studies Spanning 2000~2024)

### 2.1 Plaintext Comparison vs. Opaque Comparison

```
Plaintext comparison: input string == built-in string (or compared after a simple transform)
  Locating: bp GetDlgItemTextA/W / GetWindowTextA, single-step a few times and the cmp appears
Opaque comparison: f(input) == g(machine code/built-in value) — validation and generation are separated
  Key: find the "input → intermediate value" transform f (often a homegrown algorithm)
```

### 2.2 The Three Cracking Routes (Corresponding to Tree Child Nodes)

1. **Memory keygen** (1000192, principles 1000193/KeyMake 1000194/CrackCode 1000197): trace to "the instant the comparison passes", grab the **real registration code** in memory at that moment (the expected value computed by the program) and pop it up in a dialog — no need to understand the algorithm, just steal the result. KeyMake (the "button machine") packages "breakpoint location + value-extraction rule" as a distributable configuration.
2. **The WinHex method** (1000200): search-and-replace signature bytes directly in the file/memory (the primitive form of patching).
3. **Writing a keygen** (1000202, tutorial series 1000203~1000206): fully understand the algorithm, then re-implement it forward.
   - Assembly-extraction method: lift the validation function's assembly verbatim, wrap it in C `__asm`/load a standalone .bin and execute — most reliable when the algorithm is obfuscated or depends on a random seed.
   - **Algorithm inversion** (1000209): if f is injective, deduce the input backwards. Invertible transforms (per-byte xor/table lookup/shifts) invert directly; non-invertible ones (md5) allow only collisions or a different route (forge the comparison result).

### 2.3 Registry Comparison/Self-Registration (1000201/1000208)

`RegQueryValueExA` reads a key and validates: forge the key value; self-registration = the program writes the key on first run, so crack by changing the written value or bypassing the expiry check. For deadline-style key values mind the timestamp arithmetic (those computing a delta against system time); the focus is the delta comparison point.

### 2.4 Practical Essentials

1. Prefer "stealing the result from the opaque comparison": flip ZF at the `cmp/jz` deciding point or grab the expected value directly — ten times faster than inversion.
2. Validation-function signatures: jump table on string length (switch len) + table-lookup arithmetic + accumulator loop — once recognized, lift the whole thing out.
3. Multi-layer validation (input format/registration state/re-validation inside features) must all be found; breaking only one layer yields "registered successfully but features don't work".
4. Modern commercial software uses RSA/ECDSA (server public-key signature verification) — forward inversion is infeasible; you can only patch the verification jump or forge the public key (§6.3).

### 2.5 Representative Posts

- The "Cracking from Zero with OllyDbg" series (knowledge tree 1001216, complete collection), chapters 51/52 on ASProtect — thread-11794
- Hex Comparison registration analysis
- Qixi Festival gift: the GrindEQ formula suite registration algorithm
- Source Insight4 keygen
- Allok Video Splitter analysis with keygen
- Cracking Yitian II account passwords (a very old sample)
- Navicat Premium 11.0.5 x86 crack (the public-key forgery idea)
- "Teaching Rookies to Write Keygens" (2004, W32Dasm static + full algorithm-inversion flow, oriented to NAME/SERIAL); also "Keygen Writing Tutorial" (2001, TRW2000 dynamic tracing with an HMEMCPY breakpoint, with VB/VC/ASM keygen sources in all three flavors).

## 3. The Full Unpacking Workflow (Tree Node 1000288)

### 3.1 The Packer's Execution Model

```
Packed PE:  [packer section (new EP)] [compressed/encrypted original code]
At runtime: the shell decrypts/decompresses → rebuilds the import table → restores relocations → completes stolen code
        → jmp to the original entry point OEP ──→ the program executes normally (the shell may still be resident afterwards: monitoring/re-encryption)
Unpacking = at the instant "decompression done, OEP not yet polluted", dump the memory image + repair the PE (IAT/section table/relocations)
```

### 3.2 Finding the OEP (Tree Node 1000291)

| Method | Operation | Applicability |
|---|---|---|
| **The ESP trick** | at the packer entry `pushad`, set a hardware access breakpoint on the address ESP points to; after `popad` restores the scene, one step lands near the OEP | generic compression packers (UPX/ASPack) |
| Memory breakpoint (execute) | set an "execute" breakpoint on the code section; the first hit is the OEP direction | generic |
| Single-step tracing | F8 step over; a big cross-section jump (jmp to a far address/ret) means the OEP | simple packers; not for VM packers |
| API-breakpoint method | bp GetCommandLineA/GetModuleHandleA etc. — "the program's first cry" — then return to user code | packers that call a system API then hand over |
| Trace conditions | x64dbg trace condition "address ∈ code section", bulk record, then analyze offline | reordered/obfuscated packers |
| The holy grail: stolen code | the few instructions before the OEP were stolen and rebuilt by the shell; the original logic must be restored by hand | ASProtect/EncryptPE etc. (§5.2) |

### 3.3 Capturing the Memory Image Dump (Tree Node 1000292, "A Brief Talk on Dump Techniques in Unpacking" 1000293)

- At the OEP (the unpolluted instant), use LordPE/x64dbg dump/`Scylla dump` to grab the full section image.
- Repair the section table: per the in-memory SectionAlignment rewrite each section's `SizeOfRawData=VirtualSize(aligned)`, and re-lay `PointerToRawData` in file order (Basics §2.10).
- Truncate oversized/hollow sections (huge uncommitted VirtualSize) as needed; decide whether to keep the Overlay (tree node 1000299, appended data).

### 3.4 Rebuilding the Import Table IAT (Tree Node 1000295, the Core Difficulty)

```
How packers destroy the IAT:
  ① Redirection: call [IAT] becomes a call to an in-shell trampoline → the trampoline jmps to the real function (with decryption/counting)
  ② Encryption: IAT entries decrypted at runtime; ③ obfuscated API names (renaming/self-computed hash resolution)
Rebuild flow (ImpREC/Scylla automate the same principle):
  1. At the OEP, scan the code for all call [mem] / jmp [mem] targets → the IAT extent
  2. Read each resolved real function address from memory → GetModuleName+GetProcName to look up the name
  3. Create a new .idata: IMAGE_IMPORT_DESCRIPTOR (grouped by DLL) + INT/IAT arrays
  4. Fix DataDirectory[1] (IMPORT) to point at the new table; keep Size in sync with the IAT directory
Tools: ImpREC (classic, the OD era), Scylla (x64dbg standard, x64 support)★
  Scripted x64dbg repair example: thread-18042 "Repairing the IAT via x64dbg Scripting"
Pitfalls: indirect-call tables are discontinuous (manual chunking needed)/stolen pointers/foreign non-API data mixed into the IAT → fix block by block
```

### 3.5 Relocations/Export Table/Reordering/Optimization (1000296~1000298/1000302)

- Relocation table: after the dump, if ImageBase changed, rebuild `.reloc` (scan all "old-base references" at the new base and regenerate entries); PE-Armor-style packers already redirect relocations at their own table during execution, which must be recomputed after stripping.
- Export table (1000297): after unpacking a DLL, the export directory must be rebuilt from memory (ASProtect encrypts the export table).
- Reordering restoration (1000298): the shell scatters code blocks and rearranges them (connected by jumps); trace + graph algorithms are needed to restore linearity; modern VM packers go straight into the territory of virtual-machine restoration (Protection chapter).
- PE file optimization (1000302): alignment/merging sections/removing residual shell sections, reducing signatures.

### 3.6 Practical Essentials

1. The golden rule of unpacking: **stop at the exact instant of the OEP** — one step later the program self-destructs/re-encrypts, and the dump is ruined.
2. The full verification chain: the dumped PE parses statically (the Basics toolchain) → IAT complete → runs standalone → features work; only after passing all four is the unpacking clean.
3. Double-packers/multi-stage packers: outer compression + inner encryption; strip layer by layer, don't try to do it in one step.
4. Under x64, mind the `.pdata` exception table: if you patch code you must maintain unwind info in sync, or the first exception crashes.

### 3.7 Representative Posts

- Process Dump & PE unpacking & IAT repair — the Windows edition
- Repairing the IAT via x64dbg scripting
- Unpacking an unknown encryption packer
- Unpacking log of the Nine-Story Demon Tower
- An investigation of an unusual UPX packer from a CTF challenge
- [A rookie's first attempt] Challenging the simplest unpack-and-kill of Denuvo DRM encryption
- x64dbg — Scylla (toolchain)
- A collection of anti-(debugging/tracing/unpacking) techniques

## 4. Unpackers (Tree Nodes 1000303~1000309)

```
Static unpackers (1000305): pure algorithmic inversion of the compression stream, never runs the target — fast, safe (no anti-debugging triggered)
  Representatives: UPX (built-in -d), AsPackDie, NsPack, PEArmor-specific (tree 1000306~1000309)
  Conditions: the packer has no polymorphism/no key derivation (same version, same algorithm); locate the compressed data by signature and expand directly
Dynamic unpackers (1000304): a driver/debugger emulates the shell's execution to the OEP, auto dump+fix
  Implementation is exactly "debugger development" (Debugging §4) + a scripted unpacking flow
  Confrontation: the shell detects debug objects/timing deltas/single-step traps → tracelessness required (virtualization/hypervisor grade)
Generic automation: modern trace + emulation (Unicorn) reconstruction, see the virtual-machine node in the Protection chapter
```

Essentials: static first (reproducible and batchable); a dynamic unpacker is essentially an anti-debugging confrontation engineering effort, not a workflow engineering one.

## 5. The Packer Instance Matrix (Tree Node 1000310, 150+ packers)

### 5.1 The Four-Tier Classification (by Confrontation Strength)

```
┌ Compression packers (smaller size, weak protection) ────────────────────────┐
│ UPX (1000461/UPXPR 1000463), ASPack (1000333), PECompact (1000419)            │
│ FSG (1000386), NsPack (1000403), petite (1000430), RLPack, aPLib family      │
│ Traits: pushad/popad + LZ-family algorithms; the ESP trick usually kills them│
├ Crypter packers (compression + encryption + anti-debugging) ────────────────┤
│ ASProtect (1000335: 0.9x→1.0→1.1x→1.2x→1.23→1.3x→1.4x→2.x→SKE)               │
│ ACProtect (1000311: 1.0x~2.x/UltraProtect), PE-Armor (1000415)               │
│ EncryptPE (1000371), PELock, PESpin (1000429), tElock (1000456)              │
│ SDProtector, Obsidium (1000406), Xprotector, yoda's Crypter                  │
│ Domestic: Beidou (1000475), Huanying (1000477), Xifeng (1000483), Xianjian (1000484) │
│   Iron Armor JDPE (1000392), Jufeng (1000478), Waiguai Kexing (1000482)      │
│ Traits: IAT redirection/encryption, stolen code, CRC, multi-threaded anti-debugging, SEH traps │
├ Commercial licensing packers (license + anti-tamper) ──────────────────────┤
│ Armadillo (1000326: 1.xx→6.x, dual process/DNA/nano-encryption)              │
│ WinLicense (1000469) = Themida + licensing, SafeDisc (1000439)/SecuROM (1000444) │
│ StarForce (1000452, optical disc fingerprint), Flexlm (see Protection 1000648)│
│ CopyMinder, Elicense, SoftWrap, VBox                                          │
└ Virtualizing packers (code → bytecode, strongest) ─────────────────────────┐
│ VMProtect (detailed in Protection 1000716~1000719), Themida (1000458/VM analysis) │
│ Safengine (1000441), Code Virtualizer, EXECryptor (1000378)                  │
│ Enigma protector (1000372), ZProtect (1000474), TTProtect (1000460)          │
│ Domestic: VProtect (1000468)                                                  │
│ Confrontation: trace recording → handler distillation → bytecode decompilation (deep dives in the Protection chapter) │
└────────────────────────────────────────────┘
```

### 5.2 The ASProtect Special Topic (the Tree's Most Detailed: 12 Child Nodes)

Version evolution 0.9x→2.x, known confrontation points: SEH anti-debugging/multi-threaded decoding/fully encrypted redirected IAT/stolen code (entry instructions stolen, rebuilt and executed inside the shell; unpacking requires manually restoring the stolen instructions)/SDK embedding (advanced protection encrypting user functions). SKE-version child nodes (1000344~1000350): SDK, unpacking tutorials, Stolen Code, SDK repair, Advanced Import protection, registration algorithm. Knowledge-base post: "Cracking from Zero with OllyDbg, Chapters 51/52: Unpacking ASProtect v2.3.04.26, Part 1/2".

### 5.3 The VMProtect Special Topic (Packer Instance + Virtual-Machine Twin Nodes)

- Composition: VM entry (vm_begin/vm_end markers) → bytecode compilation → dispatcher loop (handler chain).
- Restoration route: full-instruction trace stream → recognize handler semantics (register/stack reads-writes/push imm) → merge and restore equivalent x86 → decompile.
- Knowledge-base posts: "VMProtect2 — A Detailed Analysis of the Virtual Machine Architecture" (a translation); "Sharing vmp2 Code Restoration"; "An Approach to Restoring VMP from the Compilation Perspective"; the 2025~2026 new series "Tearing Apart the 64-bit vmp3.5 Shell from 0, Parts I/II" (tools + deobfuscation/stack analysis); "VMProtect 3.8.1 Obfuscation Strategies Unveiled".
- The knowledge tree also has a dedicated virtual-machine chapter (1000711~1000731, filed under the Protection chapter).

### 5.4 Quick Notes on Other Key Packers

- **Armadillo** (1000326~1000332): dual processes debugging each other (mem diffs via the debug API), checksum-encoded Nanomites (conditional jumps replaced with int3, handled by the debugger) — counters: forge the child process/restore the Nanomites; the experience-notes node (1000327).
- **UPX** (1000461): an LZ77+NRV2B variant, `-d` unpacks; modified builds (changed magic "UPX!") need signature patches.
- **Enigma** (1000372/1000457): high versions include VM + keygen confrontation; new post "The Enigma Protector VM Restoration Plugin" (2026).
- **Beidou/Huanying** and other domestic packers: mainstream around 2010, resource encryption + polymorphic entry; the knowledge base holds complete strategy post groups.

### 5.5 Practical Essentials

1. Identify first (§1 packer detection), then pick the route: compression packers at the 10-minute level; crypter packers by version — look up predecessors' write-ups (the knowledge base's packer-instance nodes cover nearly all); for VM packers assess "whether it's worth it" (tracing starts at hours).
2. Packer versions matter: the same packer differs hugely across versions in confrontation surface; include the exact version number when searching.
3. Old packers on modern systems: use a VM + compatibility mode; many 9x-era packers naturally crash on new systems — don't misjudge that as your own unpacking error.

## 6. Encryption Algorithms (Tree Nodes 1000486~1000545)

### 6.1 The Algorithm Matrix (Full Node Coverage)

| Class | Node | Reverse-identification signatures |
|---|---|---|
| Hash: CRC (1000492)/MD5 (1000495)/SHA (1000498) | 1000490 | MD5 init constants `67452301 EFCDAB89 98BADCFE 10325476` + 64-round shift table; CRC32 table 0xEDB88320 |
| Public key: RSA (1000501)/ElGamal/ECC (1000506)/SM2 (1000270) | 1000500 | big-number modular arithmetic/modular inverse; `FFFFFFFF...` modulus; Openssl/RSA Tool (1000503) assistance |
| Symmetric: AES (1000512)/DES (1000522)/Blowfish (1000519)/TEA (1000528)/IDEA/RC family (1000532)/XOR (1000533)/Base64 (1000515) | 1000510 | AES S-box `63 7C 77 7B...`; DES initial permutation table; TEA's `delta=0x9E3779B9` golden ratio; Base64 alphabet `ABC...+/` |
| Classical: Enigma/substitution/Vigenere/magic-square stream cipher | 1000534 | CTF-oriented |
| Libraries: Crypto API (1000541, CAPI/CNG) | 1000540 | a breakpoint on advapi32 CryptAcquireContext breaks it |
| Applications: known-plaintext attack (1000544, deriving the keystream from known plaintext)/miscellany (1000545)/certificates (1001224) | | |

### 6.2 Algorithm Inversion in Keygens

```
Homegrown transforms (invertible): xor/shift/table-lookup mixes → work backwards from the output to the input (mind the round-function order when inverting)
Standard hashes (non-invertible): only "blow up the comparison point" or "steal the expected value from memory" (§2.2)
RSA signature verification: no forward solution; replace the built-in public key (n,e) with your own generated pair → self-sign as "legitimate" (the thread-12934 idea)
```

### 6.3 Practical Essentials

1. First scan constants to locate the algorithm (the signature column in 6.1), then judge "modifications" (swapped S-boxes/changed round counts/inserted private transforms).
2. Big-number arithmetic: lift out the asm segment and reuse it directly (the assembly-extraction method in §2.2); don't hand-translate to C.
3. The known-plaintext idea also works for custom stream ciphers: XOR the known plaintext with the ciphertext to get the keystream, then verify its period.
4. Crypto API programs: bp CryptDeriveKey/CryptEncrypt to grab the context and key handles, then peel it layer by layer with `CryptGetKeyParam` — faster than reversing the algorithm.

### 6.4 Representative Posts

- Allok Video Splitter analysis with keygen — (a model of algorithm inversion)
- Navicat Premium 11.0.5 x86 crack — (RSA public-key forgery)
- Source Insight4 keygen
- "Teaching Rookies to Write Keygens"; the "Cryptography Getting-Started Series" (1000489)
- Knowledge-base "known-plaintext attack" node 1000544 + CRC algorithm theory 1000493 (zip password/file-checksum scenarios)

## 7. Debugging Application Branches (Tree Node 1000250, 18-Child Overview)

Beyond unpacking/cracking, the generalized scenarios of "using a debugger as a scalpel" (one page each is enough to get started; dig deeper as needed):

- **Localization technology** (1000252/game localization 1000254/reverse engineering in Galgame localization 1001486): resource extraction (PE resources/packaged formats) → translation → repacking; string pointer-table repair (fixed-length → variable-length).
- **Multi-instance launching** (1000255): Mutex/Event/shared-memory detection via handle walking; remove or rename (paired with handle knowledge, Basics §3.5).
- **Data analysis** (1000256~1000260/documents 1001367/databases 1001368): string/image/network packet/save-file format reversing; **protocol analysis** (1000270): WSA hook to capture → restore structs → replay.
- **Password encryption** (1000262~1000269): office/winrar/winzip/FoxMail/access/QQ password storage formats and decryption — a historical series; the modern equivalents are browser passwords/DPAPI.
- **Forensics** (1000271)/memory leaks (1000273)/bug fixing (1000274): dump analysis, residual-password mining.
- **Game analysis** (1000275~1000284): game assistants/trainers (memory search and pinning)/the Minesweeper classic tutorial (1000279)/U3D analysis (1001710)/game security testing (1001291). ⚠️ Historical knowledge-base content, in the context of competitive confrontation/single-player research.
- **Digital signatures** (1000272), **DRM protection** (1001456, Denuvo see the §3.7 post), **browser hijacking** (1001285), **data recovery** (1001477), **development debugging** (1000285), **principle analysis** (1000286), **hard-disk topics** (1000287), **feature enhancement** (1000261, linking to the Reconstruction chapter).

## Appendix: Related Chapters

> Related chapters: [01-windows/basics.md](basics.md) (PE/data structures), [01-windows/debugging.md](debugging.md) (breakpoints/exceptions/tools).
> Extensions: packer writing/anti-tracing/virtual-machine protection belong to [Part 5: Protection] (tree 1000616~1000731); patching/secondary development belongs to [Part 6: Reconstruction] (tree 1000732+); this library files them as separate chapters.
