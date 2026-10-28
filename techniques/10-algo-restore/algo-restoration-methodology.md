# Pure-Algorithm Restoration Methodology: From Hook to Pure Computation

> Cross-references: `../05-toolbox/emulation-frameworks.md` (unidbg basics), `deobfuscation-practice.md` (so preprocessing).

## 0. Whole-Doc Map

```
Hook to learn the inputs/outputs (frida)
   │
   ├─ Algorithm identifiable (signature constant-table hit) ──→ extract constants/customizations ──→ recompute locally ──→ cross-check ──→ pure computation ✅
   │
   ├─ White-box AES (huge lookup tables) ──→ DFA / DCA attack to recover the key ──→ standard algorithm + key, offline recomputation ✅
   │
   ├─ Algorithm unreadable (VMP/deep obfuscation) ──→ unidbg environment completion, black-box recomputation (semi-pure, RPC-ized as a service)
   │
   └─ None of the above works ──→ real-device frida-RPC (the last retreat; device-dependent)
```

The three levels of "pure computation" (unified terminology in this doc):
1. **L1 offline recomputation**: the algorithm is fully restored as python/JS code; input and output are detached from the app (highest cost, highest value);
2. **L2 offline execution**: the algorithm wasn't understood, but the so runs inside unidbg and produces outputs locally in bulk (medium cost; the de-facto mainstream endpoint);
3. **L3 real-device RPC**: frida attaches to a real device and forwards calls (lowest cost; depends on device availability).
This doc's main line pushes the target from L3 toward L1; when it won't move, stop at L2.

## 1. Why Pure Computation

### 1.1 The three sins of RPC

- **Device dependency**: frida-RPC requires a resident real device/emulator, a live app, and a frida-server that doesn't get killed. Risk-control apps generally carry anti-debug/anti-frida (see `04-evasion`); the maintenance cost of RPC rises linearly with version iterations.
- **Throughput bottleneck**: single-device RPC QPS is capped by the app's main thread, internal locks in the signature function, and device sensor refresh; bulk business (scraping, load testing, automation) needs server-grade concurrency — only pure computation/unidbg scales horizontally.
- **Fingerprint exposure**: long-term RPC through one device — once that device's fingerprint gets flagged by risk control, the whole pool is scrapped; pure computation produces no real device behavior and doesn't pollute the fingerprint pool (but by the same token it can't pass interfaces with strong device-fingerprint verification — see 1.3).

### 1.2 The shelf life of risk-control parameters

The lifetime of a signature parameter = the survival period of the key/algorithm version. Big-vendor risk-control sos usually rotate keys and obfuscation shapes per version. This means:
- The restored **method** is worth more than the restored **result** — keys rotate, methodology doesn't;
- The investment in restoring once should be depreciated by "how many versions it survives": with white-box AES, if the key is hard-baked into the tables, a version change only swaps the tables, and the DFA workflow can be replayed by script (see §3.6);
- Conversely, pure computation may stop at the "key is extractable" level and store the key as configuration (the endpoint of the x-zse-96 series is DFA-extract key + IV, then standard AES offline; see the §5 table).

### 1.3 The boundary of pure computation (when to give up on L1)

- The algorithm input contains a **strong device fingerprint** (sensors, TEE/attestation, dynamically delivered challenges that must be answered truthfully) → the input itself cannot be constructed offline; L1 is meaningless;
- The algorithm completes on a **secure chip/server side**, with the device merely relaying → nothing to restore;
- The signature involves a **time-window check + server-side nonce** that cannot be known locally → only real-time forwarding works; pure computation degenerates into L2 RPC.
The criterion in one sentence: **pure computation only makes sense when all inputs can be constructed offline; if you can't even collect the inputs, go straight to L2.**

## 2. Algorithm Identification Workflow

### 2.1 Step one: locate the parameter-generation point (frida search craft)

1. **Java-layer scanning**: jadx full-text search of the parameter name (`"x-zse-96"`, `"mtgsig"`, `"sign"`) to find addHeader/put call sites; parameter names are often string-encrypted — search the decryption function's return value, or hook `String.valueOf`/HashMap.put with frida to observe.
2. **HashMap.put locating method** (proven in the Luckin post): hook `java.util.HashMap.put`, filter by key, and get both the parameter-assembly location and the upstream call stack in one shot.
3. **Native entry capture**:
 - Static registration: just search `Java_com_xxx`;
 - Dynamic registration: hook libart's `RegisterNatives` to grab the method table (so name + offset in one grab, `../05-toolbox/emulation-frameworks.md` §3.2);
 - When even the so is unknown: hook `android_dlopen_ext` to print the load sequence + hook `strstr/strcmp` to observe who compares the parameter-name string.
4. **Generic backstop**: hook `JNI_OnLoad` to watch initialization; for libc-layer encryption, further hook `memcpy`/`malloc` to watch data flow (heavy artillery — use last).

### 2.2 Step two: identify the algorithm type (signature fingerprints)

After entering the so, run "algorithm fingerprint matching" first, then choose the restoration route. Static signatures (search constants/sequences in IDA):

| Signature | Algorithm hit | Identification notes |
|---|---|---|
| `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476` | MD5/SHA1 initial vector | Customized versions most often change these four IVs or the T table in the round function |
| `0x6A09E667 0xBB67AE85 ...` | SHA256-family IV | same as above |
| `0x9E3779B9` | TEA/XTEA/XXTEA | the delta constant; a modified delta is the most common variant |
| `63 7C 77 7B F2 6B 6F C5...` (S-box) | AES | A standard S-box means AES; a "per-row or whole-table shuffled but same value range" table means customized or T-box |
| `62 63 64 ... 2B 2F 30` (`"ABCDEFGH...+/"`) | base64 | Changing alphabet/index table/_padding means customized base64 |
| 256-byte state array + two pointers i/j swapping | RC4 | KSA/PRGA structure; customization points are usually the KSA churn count and the j update formula |
| Giant table masses (tens to hundreds of KB of contiguous rodata) | **white-box AES** | see §3; high frequency |
| dispatch loop + opcode switch | **VMP** | see `deobfuscation-practice.md` §6 |
Dynamic signatures (statistics after frida/unidbg tracing):
- **Block length**: input changing in 16-byte groups → block cipher (AES family); byte-by-byte streaming → RC4/XOR stream;
- **Output length**: fixed 16/20/32 → MD5/SHA/AES single block; growing linearly with input + padding → block encryption/encoding;
- **Avalanche test**: flip 1 input byte and count changed output bits — all change (block cipher/hash) vs partial change (stream cipher/segmented encoding/concatenation).

### 2.3 Static table-scanning script (the first shot after locating the so)

Flipping through tables manually in IDA is inefficient; scan rodata for constant fingerprints directly:

```python
# IDAPython: scan the current shared object for algorithm fingerprint constants
import idautils, idc, ida_bytes

SIGS = {
    "MD5/SHA1 IV":  [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
    "SHA256 IV":    [0x6A09E667, 0xBB67AE85],
    "TEA delta":    [0x9E3779B9],
    "AES S-box 头": [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5],
}
def scan_sigs():
    for seg_ea in idautils.Segments():
        seg_end = idc.get_segm_end(seg_ea)
        if idc.get_segm_attr(seg_ea, idc.SEGPROP_TYPE) != 0x3:  # Scan data segments only
            continue
        ea = seg_ea
        while ea < seg_end:
            hit = False
            for name, sig in SIGS.items():
                if all(ida_bytes.get_dword(ea + i*4) == v if v > 0xFF
                       else ida_bytes.get_byte(ea + i) == v
                       for i, v in enumerate(sig)):
                    print(f"[{name}] 0x{ea:X}")
                    hit = True
                    break
            ea += 4 if not hit else 16
```

No standard-fingerprint hit ≠ these algorithms aren't used: custom versions swap the IVs/tables wholesale — then scan for "statistical features of a table" instead: a 256-element byte segment whose value range covers exactly 0..255 (S-box/permutation table), a contiguous output charset segment (base64 table). On a hit, jump straight to the function using the table via cross-references (the `X` key) — that is the crypto core.

### 2.4 Step three: extract or restore (routing)

- Standard algorithm, unmodified → copy the standard implementation + extract key/IV;
- Customized (§4 three-step method) → locate the diff, restore only the diff;
- White-box → §3 DFA/DCA;
- Unreadable (VMP/obfuscation) → `deobfuscation-practice.md`, or straight to unidbg L2.

## 3. White-Box AES Special Topic

### 3.1 White-box principle: why you can't see the key

White-box cryptography (the Chow 2002 scheme) precomputes "key participation" into lookup tables: each AES round's AddRoundKey+SubBytes+MixColumns gets encoded into several **T-boxes** (input-to-output table lookups); the key melts into the code as tables, and running in a ciphertext environment still doesn't expose it. Engineering shape:
- A series of 16 rounds × 16-byte tables, total constants starting at tens of KB (identification signature: swaths of "complete value range, no discernible order" byte tables in rodata);
- Input/output often carry an **external encoding** layered on top — even after recovering an equivalent key, the ciphertext must pass through a custom mapping before it is standard AES output.

### 3.2 Recognizing white-box traits (what it looks like in IDA)

1. rodata shows table clusters sized 0x100/0x1000/0x10000 with cross-references concentrated in a few functions;
2. Function bodies full of `LDRB W8, [X9, X0]`-style table lookups (base is the table, index is data) rather than arithmetic;
3. 16/13/14-round structural loops (AES-128/192/256 round counts), 16 lookups per round;
4. Usually accompanied by post-transform tables (output encoding) and pre-inverse tables (input decoding).
Yang Ruhua's x-zse-96 series (Zhihu) is exactly the complete path of "locate the white-box AES function → DFA attack to recover the key → pin the IV → pure computation in python".

### 3.3 Choosing the attack surface: DFA primary, DCA auxiliary

The two classic white-box attacks (tooled implementations at SideChannelMarvels/Deadpool):
- **DCA (Differential Computation Analysis)**: run N times with fixed input, trace bits of memory/intermediate variables, do correlation analysis per bit to recover the key — analogous to power-analysis DPA. Suits scenarios where you can instrument traces (frida stalker / unidbg CodeHook).
- **DFA (Differential Fault Analysis)**: inject a fault at the AES **second-to-last round** (flip one intermediate-state byte), compare correct/faulty ciphertext pairs; one set of fault pairs recovers the last two round keys, then walk back to the original key. **The standard play against white-box**: no need to understand the tables — you only need to make a mess between rounds 9 and 10.
The Deadpool repo provides complete attack exemplars for both classes against historical challenge samples (including the SECCON 2016 Android ARM/ARM64 so white-box AES).

### 3.4 DFA principle (one-sentence version)

The last AES round has no MixColumns. If some byte b of the second-to-last-round state is faulted to b', only the **4 bytes of the final ciphertext in the same column diffused through the last round** differ. For one (c, c') differential, enumerate candidate round-key bytes k: the differential `SInv(c_i ^ k) ^ SInv(c_i' ^ k)` must equal the second-to-last-round fault differential mapped through ShiftRows/MixColumns — any k that fails is eliminated. After several fault pairs cross-eliminate, each byte retains a unique candidate → K10 → invert the key schedule to get K0 (the original key).

### 3.5 Landing on Android: where to inject the fault

Deadpool's `deadpool_dfa.py` takes faulty outputs by "statically patching data/the executable then running"; in Android practice, **runtime injection** is more common:
- **unidbg route** (proven in the Luckin post): a CodeHook single-steps at the round-9/10 lookup point to rewrite one register/memory byte; with the same input, run "once correct + N times faulty" and collect (c, c') pairs (Aliyun developer. has full reproduction steps);
- **frida route**: hook internal offsets of the white-box function and modify the intermediate buffer before onLeave; the plus is a real on-device context, the minus is that internal offsets change across versions.
- Note: white-boxes with **integrity self-checks** (table CRC/code hash verification) defeat static patching — runtime injection is mandatory (the Deadpool README states this limitation explicitly).

### 3.6 DFA pseudocode sketch (a runnable skeleton)

```python
# White-box AES DFA skeleton: unidbg/Frida produces (c, c') pairs; this script recovers the key offline
# Use phoenixAES / JeanGrey (SideChannelMarvels), or implement the solver directly
import phoenixAES

# 1. Collect one correct ciphertext c and several faulted ciphertexts c' for the same plaintext
# Fault injection point: flip one byte of the penultimate-round state, after round 9 MixColumns
# unidbg: when CodeHook reaches the round-9 table-lookup sequence, mem_write(state_addr, fault_byte)
fault_pairs = [
    (bytes.fromhex(c_hex),  bytes.fromhex(cp_hex))
    for c_hex, cp_hex in collect_from_tracer()
]

# 2. Default single-byte fault model: phoenixAES standard last-round DFA
# crack_bytes(faults, ref): ref is the correct ciphertext; faults is a list of faulted ciphertext bytes
# Returns the last-round key as uppercase hexadecimal, or None; '..' marks unresolved groups
for c, faulty in fault_pairs:
    r = phoenixAES.crack_bytes([fp for _, fp in fault_pairs], c)
    if r and ".." not in r:
        k10 = bytes.fromhex(r)
        break

# 3. Reverse the AES-128 key schedule from K10 to recover the original or equivalent key
def inv_key_expand(k10):
    w = [k10[i*4:i*4+4] for i in range(4)]
    for i in range(9, -1, -1):
        prev_g = sbox_rot(w[3])           # RotWord+SubWord+Rcon
        w = [bytes(a ^ b for a, b in zip(w_prev, w_next)) for ...]
    return b"".join(w)[:16]

# 4. Verify by encrypting fixed plaintext with the recovered key and comparing against the white-box output
# White boxes may use external encodings; for a fixed extra mapping, collect 256 single-byte differences and reconstruct the permutation table
assert aes_ecb(key, pt) == c  # Or compare against ext_encode(aes_ecb(key, decode(pt)))
```

Key point: after recovering K10 you **must do an equivalence verification** — when an external encoding exists, the equivalent-key encryption differs from the white-box output by one fixed permutation; sweep 256 values with a fixed plaintext to extract the permutation table too (the x-zse-96 series' final step, "DFA recovers the key but the result is wrong; add the determined IV/external encoding", hit exactly this pit — see §3.2/§5).

### 3.7 Table restoration (the hard graft beyond DFA)

No fault injection — treat the white-box as a black-box table machine and restore it directly:
- Control the input byte by byte, observe each table's input-to-output mapping, rebuild T-box equivalent logic;
- For "tables wrapping tables" structures (T-box → affine transform → next round), use known plaintext/ciphertext pairs for constraint propagation.

## 4. Customized Standard Algorithms

### 4.1 Customization checklist (by algorithm)

| Algorithm | Common customization points | Detection method |
|---|---|---|
| base64 | alphabet reshuffle/custom charset; index-table reshuffle; padding swapped/removed; leading XOR/salting | Output charset statistics vs `A-Za-z0-9+/`; encode 0..255 to see the mapping table |
| MD5 | the four IV constants; the K table (T table); shift amounts; output truncation/byte order | Cross-check against standard MD5; divergence in the first round → hook the intermediate state before round 1 |
| SHA family | IV; message-expansion function; round-function constants | same as above |
| RC4 | KSA churn rounds; the j update formula; S initialization; output rounding/post-XOR | Read the 256-byte S-box init code; diff the PRGA loop body |
| AES | S-box reshuffle; round count changed; white-boxed | Cross-check the S-box against the standard table |
| XOR chain | multi-round rolling key; input segments offset-XORed | Byte-wise differential (flip 1 byte, watch the diffusion window) |

### 4.2 The three-step identification method (a generic workflow for locating customizations)

1. **Run the standard algorithm once**: compute a reference locally with the standard implementation (same key/same input);
2. **Locate the divergence**: the app's output differs from the reference → in the so, hook the algorithm's **round-function entry** (or lookup point), dump the intermediate state round by round, find the first diverging round/byte;
3. **Restore only the divergence**: logic before the divergence point (key schedule, IV loading) is trustworthy; reverse just the few instructions at the divergence (swapped table/swapped constant/swapped shift), backfill into the local implementation, cross-check again.
The value of the three-step method: it compresses "reversing the whole algorithm" into "reversing one diff". The recruitment-app sig/sp parameter, Moutai MK-V, and a certain e-commerce's sign body all follow this playbook.

### 4.3 Customized base64 identification skeleton (the generic play for sig/sp parameters)

```python
# Detect modified Base64 by examining the output character set and recovering the alphabet
import string, collections

def probe_b64(samples: list[bytes]):
    charset = set().union(*[set(s) for s in samples])
    std = set(string.ascii_letters + string.digits + "+/=")
    print("非标准字符:", charset - std)          # Characters such as '*-&_#' indicate a custom alphabet
    # Length features: len % 4 distribution, padding presence, and a fixed-length trailing salt
    print("长度 mod 4 分布:", collections.Counter(len(s) % 4 for s in samples))
    # Known-plaintext approach: supply a field with known content, such as device_id, and compare outputs
    # Misaligned 6-bit boundaries suggest an earlier XOR/shift; aligned groups with changed characters suggest an alphabet permutation

ALPHA_CUSTOM = "nopqrstuvwxyzabcdefghijklmABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
# Python base64.b64encode(data, altchars=...) only replaces two characters
# A full alphabet permutation requires a custom mapping of the reconstructed 6-bit groups through ALPHA_CUSTOM.index
```

The recruitment-app sig/sp parameter follows exactly the three steps "scan the alphabet → back-derive the index table → restore the concatenation".

### 4.4 Locating the concatenation of salts/ciphertext ids/timestamps

Risk-control parameters are generally the three stages "plaintext-field concatenation → encryption → encoding". Concatenation order and salt position are business logic — read them directly by hooking the crypto function's **input buffer** (frida `readByteArray`); don't push it out of the so by force. Demo numbers and hidden routes found in JS/pages are likewise evidenced from the input side (see the global rules' JS-inventory entry).

## 5. Parameter Case Index Table (qualitative conclusions, not a tutorial)

> "Algorithm type" in the table is a qualitative conclusion; "systematic analysis" means whether systematic write-ups exist — no implementation details attached.

| Parameter | Owner | Algorithm type (qualitative/inferred) | Difficulty | Systematic analysis | Lead |
|---|---|---|---|---|---|
| x-zse-96 | Zhihu | white-box AES (table implementation) + external encoding | High | Yes | Part 1 locates the white box; part 2 DFA-extracts key+IV, then pure computation in python |
| A certain coffee's sign/q | Luckin | white-box AES + OLLVM | High | Yes | unidbg + DFA to extract the key |
| mtgsig 2.4 | Meituan | libmtguard.so, OLLVM-grade obfuscation | Extreme | Partial | 2025 already has full analyses restoring its VM architecture/instruction set |
| jdgs | JD | so-layer signing, heavily obfuscated | High | Partial | the b1~b7 structure has been restored (see the big-vendor capture-confrontation dossier §7.2) |
| a_bogus | Douyin | JSVMP (web-side JS virtual machine); native on the app side | High | Many | plenty of web-side pure-computation write-ups |
| X-Bogus | Douyin | RC4 variant + customized base64 combo | Medium | Many | analyzed after AST deobfuscation; RPC/environment-completion/instrumentation — three routes |
| sig3 | A certain short-video app | - | - | Yes | systematic analysis exists |
| shield | A certain e-commerce risk control | - | High | Yes | pure-computation analysis exists |
| MK-V | the Moutai app | custom signature | Medium | Yes | restored |
| Simplesign | a certain auto app | white-box AES | High | Yes | restored |
| anti_content | a certain e-commerce | so-layer risk control | High | Partial | scattered here and there |
| Shumei slider | Shumei | slider-trajectory encryption | Medium | Many | belongs to the captcha track |
| F5 Shape | F5 | fingerprint + machine code | Extreme | Yes | encryption/decryption and environment-completion analyses exist |
Usage: when taking a new target, check this table first for a structurally identical case; for the same owner (e.g., the Meituan family), reuse the existing toolchain first (unidbg project, DFA scripts).

## 6. unidbg Environment-Completion Methodology (the L2 level in detail)

### 6.1 What environment completion is

unidbg emulates the CPU (Unicorn) and the JNI shell, but the app's so calls back into the Android runtime heavily: reflection to fetch device info, reading /proc, getting the APK signature, spawning threads. **Environment completion = answering each of these callbacks with a fake implementation one by one, until the target function produces output identical to the real device**. The detailed skeleton is in `../05-toolbox/emulation-frameworks.md` §3; only differences and pitfalls are listed here.

### 6.2 Common pitfall list (by frequency)

1. `unsupported: xxx` AbstractJni exception: an environment-completion gap; the `FindClass/GetStaticFieldID` in the log is the gap list;
2. **Context mismatch**: the so reads `Context.getPackageName/getFilesDir`; unidbg's DVM object needs an overridden `callObjectMethodV` branch to return it;
3. **Threads and TLS**: `pthread_key_create/pthread_specific` are half-emulated; when stuck, enable `traceCode` to see the spin point (mostly waiting on an un-answered lock);
4. **signals**: the so registers SIGSEGV/SIGTRAP for anti-tracing; unidbg swallows them by default, but when the custom handler runs verification logic, confirm the backend's signal semantics;
5. **Signature verification**: `GET_SIGNATURES` reads back the APK signature for key derivation — you must build the ApkEnvironment with the **original package** (a repackaged package computes a wrong key outright, `05-toolbox` §3.3 item 3);
6. **JNI_OnLoad returns -1**: must be handled after changing branches; if unidbg throws, patch BaseVM source to log instead;
7. **Missing libc functions**: copy libc/libm/libdl from a real device's `/system/lib64/` and let unidbg load them.

### 6.3 Take the real frida call sequence as the outline

The master principle of environment completion: the real call order you hooked = the reproduction script; "treat every call before computing the parameter as initialization" and complete them in order — don't guess statically. The iteration loop = run → read the error → complete → run again; dozens of rounds are normal.

### 6.4 frida hook vs unidbg selection

| Dimension | Active frida invocation | unidbg |
|---|---|---|
| Upfront cost | Just pass anti-debugging | Environment completion (grows with so weight) |
| Concurrency | Limited per device | Open as many as you like on servers |
| Controllability | Subject to device state | Registers/memory mutable at will (DFA injection relies on it) |
| Fit | Locating the algorithm + collecting parameters (step one) | Recomputation + scale (the endpoint) |
The rule of thumb stands: **first frida to understand, then unidbg to consolidate** (`05-toolbox` §4).

## 7. Verification Methodology (the quality gate of pure computation)

### 7.1 Local recomputation cross-check

Fix one set of inputs (when timestamps are involved, freeze time: frida hooks `gettimeofday/clock`, unidbg changes it directly at the backend layer); compare the local implementation's output vs the app's output byte by byte. **Cross-check before refactoring**: every rewrite step needs a cross-check baseline, otherwise you can't tell which step introduced the deviation.

### 7.2 Differential testing (finding the input-dependency domain)

Systematically vary inputs, observe the output's change domain, and infer the algorithm's structure:
- Flip 1 plaintext byte → number/position of changed ciphertext bytes (block boundary, chaining mode CBC/ECB/CTR);
- Flip 1 key byte → all change (key participates in every round) vs partial change (key participates only partially);
- Shift the timestamp 1ms/1s → does the output change (does time enter the input; at what granularity);
- Change User-Agent/device fields → locate the change in which ciphertext segment (field→ciphertext-segment mapping; concatenation-structure restoration).
Emit an "input field × output segment" influence matrix; for concatenation-style parameters, read the structure straight off the matrix.

### 7.3 Version regression

Rerun the collection scripts on a new app version: outputs still agree → the key didn't rotate; they diverge → locate the key/algorithm change point to which cell of the differential-test matrix, and restore incrementally. Archiving the trio "collection script + cross-check script + DFA script" is the entire cost of the next upgrade.

## 8. Tools and Reference Cases

- SideChannelMarvels/Deadpool (white-box attack collection: DCA+DFA, with Android so samples)
- SideChannelMarvels/JeanGrey (DFA solver, 372 stars)
- eshard d810 and community forks (d810-ng 325 stars, still updated as of 2026-10)
- x-zse-96 parts 1/2 (white-box locating + DFA key extraction case)
- A certain coffee's DFA AES + ollvm case
- X-Bogus pure-computation + environment-completion three-route case
- Meituan libmtguard VM restoration case —
- IIImmmyyy's self-written Arm64 emulation deflattening — (details in `deobfuscation-practice.md`)
