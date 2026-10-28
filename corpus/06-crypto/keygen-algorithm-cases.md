# Keygens & Algorithm Cases (Cryptography)

> Positioning: the concrete case library for the "keygen writing + registration/crypto-algorithm restoration" topic from the Kanxue 24-volume corpus.
> The generic methodology (algorithm-fingerprint identification / white-box AES / DFA / the three-step modification method / unidbg) lives in `../../techniques/10-algo-restore/algo-restoration-methodology.md`; this file collects only **concrete algorithm-restoration cases**: input/output traits, the back-derivation chain, coding detail, modification points.
> One main case per method; same-approach sources are listed at each entry's end.

## Subtopic Overview

- I Keygen-writing techniques (plaintext/ciphertext/memory-keygen/borrowed-code/borrowed-DLL) | II Generic registration-algorithm patterns and attack surfaces | III Concrete software registration-algorithm restoration cases | IV RSA/ECC/bignum confrontation | V Standard-cipher identification and modification | VI Communication-packet/database/password-class algorithms | VII Mobile signature-algorithm cases | VIII The old-software-era registration forms | IX Anti-crack design (the vendor's view)

## I. Keygen-Writing Techniques

### Teaching Newbies to Write Keygens (Beginner/Intermediate/Advanced) (orig: 教菜鸟写注册机(入门/中级/高级))
- Beginner: W32Dasm string-reference finds the failure message → walk up to the key jump (jne into the failure branch) → read from the `push ebp/mov ebp,esp` function head; the typical CrackMe algorithm `for i: EAX=name[i]^(i+1); EBX+=EAX; result=EAX*6+(EBX<<7)` then `%lX` formatting and lstrcmpA compare — the keygen copies the assembly line by line in C (RoBa). Intermediate: several locals computed separately then assembled into 8 segments per `"%lX%lu-%lu%lX-%lu%lu-%lX%lX"`; lowercase-to-uppercase (`cmp 'a'/sub 0x20`), adjacent-character rolling products `(EBX+name[i])*name[i-1]`, the closer `rol eax,1 ^ 0x1E240`; the EDI constant 0x64F4F0 (a version constant) participates in several segments. Advanced: the code-length constraint hides in the arithmetic (`(len*3)<<2 + 0xCD == 0x1A5` back-solves len=18), per-character must be ≥'0', the core three stages: table lookup for a character → LCG iteration (`x=(x<<3)*0x12345+0x12345` style) → XOR against the input character by character then compare — you can only construct position by position or brute-force. Tricks: F8 past a CALL first to see whether the return value is suspicious (e.g. returning the username length = 4) before following in; `[ebp+ecx-B8]` addressing = the loop trait of fetching the username's ecx-th character; wsprintf format strings (`%lX`/`%lu`) betray the code's assembly format outright.
> Same approach: the LL[CCG] keygen-writing tutorials (VB/VC/ASM, three languages), "A Newbie Makes a Keygen Too (1)-(4)", the beginner's keygen-writing edition, the Win32 ASM keygen template, "Program Reversing: Learning to Write a Simple Keygen", "Perfectly Learning to Write Assembly Keygens", "Making a Keygen in Delphi", "The Delphi Keygen Template", the FCG keygen SDK, "A Few Tricks for Writing Keygens in C++", "delphi keygen code implementation", "Getting a Program's Registration Code"
### How Registration Codes Are Forged (Plaintext and Non-Plaintext) (orig: 注册码是怎样炼成的(明码与非明码))
- Plaintext comparison: the d command shows the real code directly; non-plaintext: compared digit by digit, one wrong character jumps away — you must reverse the algorithm and write a keygen. The analysis cadence: F8 past the CALLs once watching registers change color; a value that's an address gets d, a number gets compared against the input length/digit count; eliminate the useless "string-loading / length-computing / ASCII-fetching" CALLs first, then focus on the CALLs that transform characters participating in arithmetic (商朝子). Case (China Compress 7.0): inside the key CALL, `esi = esi + charASCII*6 + 0xA8` accumulated per character; the CALL at 004f5003 filters characters for legality (only valid ones set al nonzero and store the character at 00D3B3C4); esi's result converted to decimal = the code's second half, concatenated with the first.
> Same approach: "Finding a Program's Registration Code (Chapter 7)"
### How Memory Keygens Work, with masm Source (orig: 内存注册机的工作原理及masm源码)
- The essence is a micro-debugger: CreateProcess launches the target DEBUG-style → write INT3 at the address where the real code is computed → WaitForDebugEvent suspends → ReadProcessMemory/GetThreadContext fetches the real code for display; works on packed targets too (the shell unpacks and the code lands at its address, then you break). Skeleton:
```asm
; Omitted: CreateProcess(..., DEBUG_PROCESS, ...) startup and the outer .while TRUE loop
.if DBEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && dword ptr [DBEvent.u.Exception.ExceptionRecord.ExceptionAddress] == 断点地址
    invoke ReadProcessMemory, pi.hProcess, 真码地址, addr buffer, len, NULL  ; Restore the original byte / set EIP-1 first
.endif
invoke ContinueDebugEvent, DBEvent.dwProcessId, DBEvent.dwThreadId, DBG_CONTINUE
```
> Same approach: the non-plaintext memory keygen, the VB-program memory keygen, memory-keygen source, "A Newbie Tries a Memory Keygen Too", "memory keygen → algorithm keygen, the plaintext edition", "Making a Memory Keygen for Enterprise Architect 15.2"
### From Memory Keygen to Algorithm Keygen (Plaintext/Non-Plaintext Editions) (orig: 内存注册机变算法注册机(明码篇/暗码篇))
- Plaintext edition: the LOADER creates the target process and inserts INT3s at both the "machine-code write point" and the "real-code compute point"; pausing at the machine-code point, write a new machine code and let the original program's own algorithm compute the corresponding code, then read it out — borrowing the original algorithm module as a calculator. Non-plaintext edition: the code = a hidden code further transformed by `+FFF379A6 ^04ECAEDD -0A98AC7`-style ops; once you hold the hidden code, inverting that transform back-solves the code.
> Same approach: a typical DIY keygen based on plaintext (directly turning the source program into a keygen)
### Making a Keygen with IDA (orig: 用IDA做注册机)
- Applicability: when MD5/SHA has modifications (no need to pin down the modification — copy the whole stretch), and Blowfish/DES-class algorithms with big pbox/sbox data (the tables travel with the code). Essentials: (1) variable names identical to IDA's; (2) variable declaration order identical to IDA's — else data misaligns; (3) copy IDA's disassembly into a VC inline-assembly project and compile directly (lnn1123[BCG/FCG]).
> Same approach: extracting code from IDA to build an assembly keygen, VB/C/C++ editions; extracting a program's key code from IDA to build a Keygen; extracting core code to build an assembly keygen
### Writing a Keygen with the Program's Own Code (orig: 利用程序原来的代码写注册机)
- Use OD's Asm2Clipboard plugin to copy the key CALL's assembly wholesale into a high-level-language project; less fuss than the IDA way but more tedious to port (stack/register initialization hand-patched); the case algorithm: each username ASCII XOR 5678 then accumulated, compared against the code side's computation (laomms).
### Writing a keygen with the Software's Own DLL Functions (orig: 用软件本身的DLL函数写keygen)
- Applicability: the verification function sits in a standalone DLL, its inputs clean (no junk-global dependencies), and the main program's shell is too hard to patch. Steps: PEID identifies the shell (Molebox etc. — even after a straight dump, c32asm still disassembles fine) → strings locate the verification function inside the DLL → LoadLibrary that DLL + GetProcAddress for the function pointer and call it directly (feed the fake code in first, read the real code out of the returned structure) (readyu).
> Same approach: the algorithm analysis of the IMToo series (the exported function ImRegUserInfo::IsValidRegInfo_private of UILib8_M.dll)
### On Keygen Failure and Remedies (orig: 谈注册机的失效及解决方案)
- Three failure causes: (1) the algorithm changed (basically rewrite); (2) a constant changed (usually a version number — edit the keygen's constant and it revives; case: HWiNFO32 v1.7); (3) targeted banning — the keygen left a signature inside the code and got recognized, or the vendor blacklisted a set of valid keys (change the signature / find another valid key set to swap in) (啊CR/FTSTT).
### Encrypting Software with the Disk Serial Number (orig: 用磁盘的序列号进行软件加密)
- The machine-code source: the Win32 API GetVolumeInformation fetches the volume serial (hex; theoretically hundreds of millions of combinations) → computed with user info into a code — the classic shareware anti-install scheme; on the reversing side: volume serials are forgeable (serial-changing tools / driver forgery); physical serials (GetDriveLayout or SMART) are harder but still interceptable at the API layer (uino).
> Same approach: intercepting a program's physical-disk-serial fetch system-wide; reading hardware serials via WMI; the driver-forged volume serial; a homemade disk-partition serial modifier; partition serials

## II. Generic Registration-Algorithm Patterns and Attack Surfaces

### The F(UserName)==G(SN) Registration Algorithm (orig: F(UserName)==G(SN) 注册算法)
- The pattern: the program computes an intermediate code F(Name) from the username and G(SN) from the entered code, comparing the two intermediates — **it never compares SN against a computed code; both sides compute, then compare**; the attack surface: no need to reverse F — just construct an SN whose G(SN) lands on F(Name)'s value; if G is invertible, back-solve the SN from the intermediate directly. Recognition traits: the verification function holds two symmetric "computing CALLs" + one comparing CALL (prince). Case (a Delphi 6 commercial program, ASPack-packed): inside G(SN) at 6056C3, floating-point days since 2000-01-01 also participate (36526.0); the code format `98765432101234567890a`-like; the second step then compares against the current time's float to judge expiry.
### Learning Keygen Writing: MD5 (orig: 学注册机编写之 MD5)
- The chain: code lowercased → username uppercased → WideCharToMultiByte wide-to-narrow → **strip the digits from the username** (keep only a-z/A-Z) → concatenate the fixed salt `f4hguNAg` → MD5; coding detail: the salt is a hardcoded string findable by searching wide bytes near the decrypt function; the digit-stripping filter's signature is the four-way `cmp 'a'/'z'/'A'/'Z'` checks before writing into the target buffer (我是小三).
> Same approach: MD5 registration-algorithm research; the QQ 2005 New-Year edition's login-password encryption algorithm
### Learning Keygen Writing: Table Lookup (orig: 学注册机编写之查表)
- The ahead_dv case: inside the key CALL 004158D0, the username and the code are **first compared separately against the same fixed table (the string at 00433560)** — i.e. the username/code prefixes must hit table entries — before entering the 00415690 algorithm function; recognizing table-lookup types: the verification-function entry shows paired double-loop comparisons of "input string vs fixed-address string"; the keygen = enumerate legal prefixes + implement the tail algorithm (我是小三).
### China Search King 2003c Registration Algorithm Analysis (orig: 中华搜索宝2003c注册算法分析)
- Three inputs: machine code + email + password (length must be 20; lowercase→uppercase first); the machine-code string read as decimal and converted to hex (`870889 → 0x000D49E9`), entering the key CALL with the constant 137: `00492A45 call 00408B58` (machine code to hex) → `00492A4C mov ecx,137` → `00492A54 call 00492010` (password string eax × machine-code hex edx × 137 ecx); the key CALL's 1/0 return is written to [eax+5C] as the registration flag; the password side upper-cases then StrToInt; anti-tracing included (lordor).
> Same approach: WinImage 7.0.7000 registration-algorithm analysis, the Smart Power On/Off 3.20 registration algorithm, FinalData 1.0 serial analysis, the PCWorker crack (algorithm) analysis, the A Speeder registration algorithm, the Voila registration-algorithm analysis, a simple analysis of the "Modern Chinese Dictionary" registration algorithm, the ZhuanTuJing algorithm analysis, the keyboard-instrument algorithm analysis, the ActArp algorithm analysis

## III. Concrete Software Registration-Algorithm Restoration Cases

### 010Editor Registration-Code Algorithm Reversing and Keygen (v8.0.1) (orig: 010Editor 注册码算法逆向与注册机(8.0.1 版))
- Locating: IDA searches "thank you"/"please enter a name" → the verification function sub_DD55C0; a breakpoint on `[ecx+4]` confirms the username structure (ktkitty). Algorithm skeleton: the password (16/18 hex chars), every 2 chars → 1 byte forming code[8]: `code[3]==0x9C` (the key-type marker); `hash = HashCalc(username,1,0,0x3E8)` → `code[4..7]=hash[0..3]` (the username-bound segment); `v8=(code[5]^code[2])+((code[7]^code[1])<<8)` must yield 0x3E8 through sub_13BD020 → **brute-force code[1] and code[2]**; `v10=sub_13BD0B0(code[6]^code[0])>=9` → **brute-force code[0]**; assembled as 4 groups of 4 chars `-`-separated; the length difference (16 vs 18) is told by the Qt QLineEdit::setInputMask mask (`####-##9C`-style). Online-check confrontation: the server returns "invalid" on failure; IDA searches invalid → edit the first letter of that global string in rdata (invalid→hnvalid) — a one-byte patch that doesn't break the digital signature.
> Same approach: 010Editor algorithm analysis (de-dup then locate then analyze); the 010Edit10.0 hard-patch (walking the 0xDB/0x2D return-value chain up level by level: mov eax,0x2D/ret 8); the 010Editor crack, 0xac edition (v12.0.1: r[3]∈{0x9c test key, 0xfc version key, 0xac time key}; for the 0xac edition the use count `v23=((((r[5]^r[2])+((r[7]^r[1])<<8))^0x7892)+19760)^0x3421` must be divisible by 0xB, and the expiry `v2=((((0x5b8c27)^a1^0x22C078)-180597)^0xFFE53167)&0xFFFFFF` must be divisible by 0x11 with `v29*86400>0x49C7`; generate r[4..7] from the username first, then back-solve the rest of r[])
### The Source Insight 4 Keygen (orig: Source Insight4 注册机)
- A 19-digit serial `S4XX-XXXX-XXXX-XXXX`; the checker sub_514BA0 pins digits: Serial[0]='S', [1]='4', [2]∈{T,B,S,U} (the product-type map), [3]='G', [6]∈{R,G,D,F}; the last 4 digits are a check code iterated with a 256-byte table pTable, the alphabet `KV96GMJYH7QF5TCW43XZPRS DN` hardcoded in the data segment — the keygen replicates it directly (耿念); the online check: HttpSendRequestW+HttpQueryInfo reading the status code 200 (actually 460) — patchable to skip, or take the signature-file offline route:
```c
for (i = 0; i < 4; *(i + pLastFour - 1) = g_szAlphabetTable[v5 % 26]) {
    v5 = pTable[(i + *szSerial)];
    for (j = 1; j < 15; ++j) v5 = pTable[v5 ^ szSerial[j]];
}
```
> Same approach: the EditPlus registration-code verification flow (stack-backtrace locating the two-layer loop checker); the editplus-5.0 reversing flow
### PhotoZoom Pro 5 Registration-Code Algorithm Analysis (orig: PhotoZoom Pro 5注册码算法分析)
- A 25-digit unlock code; the first 6 digits set the code type, the first 8 are key; whether the registration page's other two fields are required depends on the code type; the locating chain: MessageBoxW breakpoint → walk back 00453B64 call [esi+220] (a vtable call) → 00447EEE → 00447ABA; the mid-way "allocate memory"-type CALLs can be skipped outright (VIDEN).
> Same approach: the Galaxy 3D screensaver algorithm analysis, the Lucky66 software algorithm analysis, the COM Explorer 2.0 algorithm analysis, 1-Click PC Tuneup, Ultra Video Joiner/Splitter, Inpaint 5.2 (Delphi keygen source attached), Allok Video Splitter, the Talisman Desktop series, Flash Desktop 2003, 3D GIF Designer, the Ashampoo series, A4desk, the Nidesoft series, Active Desktop Album/Calendar, AutoRun Design Specialty, ascii picture designer, UltraEdit (translated edition)
### The GrindEQ Formula Suite Registration Algorithm (orig: GrindEQ 公式套装注册算法)
- The deactivation trap: the plugin's ghashmap pre-seeds 0x100 legal MD5s (generated from "an 8-byte variable salt derived from the registration info's MD5 first byte (a Y/N string) + a 15-byte version-number plaintext salt"); the subscript operator's insertion property means **a forged registration produces a 257th entry**, ghashmap.size() becomes 0x101 — right and wrong users call different function pointers, the wrong side hitting a popup + a self-clearing counter (曾半仙). The bypass: loop-collide the 4-byte "launch count" field in the registration info — a first-byte hit of AE averages 26.23us/attempt (2^32 runs hit in 7m20s covering 16.77M tries); collide out a hash landing inside the table and you pass; serial storage: a Base64 variant with a swapped mapping table, 315 bytes of registration info → 420 bits, five time fields interleaved to spread the bits; the confusers: the trial counter increments arithmetically `*2+1` instead of being set to 1, the first call passes a negative argument to suppress the popup, and a registry write suppresses the second popup.
### The Vxworks 6.9 Install-Password Generation Algorithm (orig: Vxworks 6.9安装密码生成算法)
- A 50-char serial, `-`-separated every 5, encoded over the custom 64-char table `F9CgKpUzb8DhM@qVBEeiN$rWd6ajP%sX75GkQ&tYf4HmR*uZA3InS+vxc2JoT#wy`; 50 6-bit bit-planes; key1~key4 are scattered bit-index tables — Customer 20bit, Cdid (product ID) 17bit, Vendor 9bit, check 11bit, each on its own bit-plane; the check `ck = (v6%511 + v1)` then per byte `ck ^= xorkey[(v6%511+dst[i])%64]` (a 64-entry xorkey table); keygen: decode → fillval fills the fields → getck computes the check → fillval writes back → encode; the install password takes no part in decrypting the installer — bypassable outright (wmsuper).
### Restoring the IdaPro 6.6 Installer Key Algorithm (orig: IdaPro6.6安装程序密钥算法还原)
- The installer is multiprocess: the main process drops a child into the temp dir passing its own address on the command line; the key check runs in the child (proven by CreateFile+CreateProcess breakpoints) (zhuhelin1997); the algorithm = an SHA1 variant: after F5 you can see `rotate-left + (b^c&d) + 0x5A827999` (SHA1's first-segment K constant) and the 80-round message expansion `(w[t-13]^w[t-11]^w[t-5]^w[t]) rotl1` — the recognition signature is the K-table's segment constants; the bit ops IDA's F5 can't restore get patched in via dynamic debugging.
> Same approach: the ida81 input-password verification algorithm analysis; the ida 6.8 install-password hard-patch (the other route: patching)
### Hands-on keygen: Winlicense 1.8.5.5 (orig: 动手keygen Winlicense 1.8.5.5)
- The License Unique Key is a long ASCII string with structured segments: 0-7 arbitrary; from 0x8, 4 bytes = dword at +0 of the realkey decrypt, concatenated (0x35555A48+0x49324839=0x7E87A281); +0x10 and +0x18 likewise take the +16-bit dword / +33-bit word; after +0x1C, 8 dwords are constants the key's runtime decrypt needs; 1.8.5.5's RSA check is window dressing — holding the three data parts suffices for a keygen; higher versions hide the data inside the VM (KeyKernel).
> Same approach: writing a keygen with the Asprotect SDK; the Asprotect registration algorithm; the RSALock top-level processing analysis; the preliminary analysis of ASProtect's encryption algorithm; a PEBundle v2.3 keygen for a certain algorithm
### A Certain Shield's Correct Playback Password + Machine Code for Playback on Any PC (orig: 某盾正确播放密码+机器码任意电脑播放)
- The machine-code graft without reversing the algorithm: OD breaks where the machine code is fetched (00497B0E) and binary-edits the machine-code string in the data window into a playable one, repeatedly (break once each at fetch/check/splash); precondition: pass the VM detection (search the Chinese string and flip the jmp); applicability: you have one valid "password + machine code" pair and the algorithm is too heavy to reverse (eacpjls).
### The LC4 Registration Algorithm Analysis (orig: LC4注册算法分析)
- A VC6 program with a self-displayed machine number (15859a29d-style hex) + serial input; after ignoring all exceptions, strings locate "You have entered an invalid code" (冲天剑).
> Same approach: the reams of "machine code + serial"-type domestic/foreign shareware
### Offline Research on the FeiQ Registration Code (orig: 飞秋注册码脱机研究)
- The GetMyCode function computes the correct code then strcmp — a pure plaintext single-function form; ~2000 lines to restore, located by stack backtrace then reversed straight (张新琪).
### Chasing Snooper v1.40.1's Registration Code (orig: 追Snooper v1.40.1的注册码)
- The trial days ride on the system-time delta (-1 day = expired); the cursor changing the instant the registration box opens hints at timing logic (易木马).
> Same approach: the Returnil restore-software password; the RVS2008 settings password
### Trying to Crack the Malachite SDR's Serial Protection (orig: 试着破解孔雀石SDR的序列号保护)
- STM32H7 firmware; the serial protection is based on the chip's 96-bit unique ID (from address 0x1FF1E800; get the register address from the reference manual); hardware-free, purely static: load the hex firmware in IDA → searching the ID address directly fails → search the LCD's English "THE" to locate the display function → xrefs find the caller → the 0x1ff1e8xx accesses mean the UID participates in the arithmetic; the embedded universal: the UID/Flash-size/uniqID trio is the machine-code source (yjmwxwx).

## IV. RSA/ECC/Bignum Confrontation

### Using RSA to Prevent Illegal Keygens (orig: 浅谈利用RSA算法防止非法注册机的制作)
- The forward design: the program embeds the public key (n,e); the vendor computes `SN = m^d mod n` with the private key (n,d) and issues it; the program verifies `c = SN^e mod n`, comparing c against the registration name — **it compares the registration name, not the serial** — forging an SN can't produce a signature over an arbitrary username, hence no universal keygen; Name length ≤ Keysize/8 guarantees m<n; the software side symmetrically does `powmod(m,e,n,c); big_to_bytes(...)` then compares against the Name; the cracking preconditions: n too short (128-bit demo grade) is factorable (RSATool/toolchains); n≥512 bits → switch to the public-key-replacement route (next entry) (Vegeta). The keygen side's four core Miracl functions:
```c
mip->IOBASE = 16; bytes_to_big(namelen, Name, c);   // Hexadecimal mode; convert the username to a bignum
cinstr(n,"963251DC5A9C90D9F203A03C363BA411");       // Modulus n
cinstr(d,"56157D29A89D77BF2F669A8F0B123CC9");       // Private key d
powmod(c,d,n,m); cotstr(m,SN);                      // m = c^d mod n → SN
```
> Same approach: preventing software Keygen with the RSA1024 algorithm (jackozoo); the Arila Sound Recorder (RSA) analysis
### RSA-Protected Programs: Registration-Making Ideas Summarized (orig: RSA保护的程序 注册机制作思路总结)
- Five routes: (1) n<512 bits, factor directly (get p,q → φ(N) → d); (2) small-e attack: given n,d, brute-force e (`temp=m^d%n; c=temp*c%n` looping until c==m — i is the brute-forced small e); (3) patch n and d: fabricate a full n1,e1,d1 set and swap everything; (4) **patch n only**: keep the original d, fabricate a factorable n1, and back-solve e1 from φ(n1) and d (`e1=d^{-1} mod φ(n1)`, BigInteger Calculator "Y/X MOD Z"); (5) **micro-adjust n**: alter n in very few bits to get n1 (e.g. last digit -1) and trial-factor the altered n1 with RSA-Tool 2 (factorability odds rise after the tweak), then solve e1 per (4) — minimizing the patch payload; note: strip the self-check first (FishSeeWater).
> Same approach: breaking RSA-1024; how to crack RSA-1024; rsa512 in practice (Registry Winner); the rsatools solve-for-D analysis; RSA512 bignum factoring speed with GGNFS (msieve/GGNFS tested); some RSA attack ideas in CTF (the gmpy2/sage toolbox + common-modulus/small-exponent/low-decryption-exponent attacks); the RSA weak-public-key common-factor bug; posting code on RSA collisions; Crypto-RSA big-integer factorization; common RSA tools and python libraries in Crypto; the math and examples of RSA; RSA-related math basics and algorithm notes; implementing RSA encryption/decryption; an optimized analysis of the public-key RSA algorithm
### RSA and Bignum Arithmetic (orig: RSA与大数运算)
- A self-contained bignum as a 2^32-base unsigned long array (BI_MAXLEN=40 → 1280-bit ceiling), longhand add/sub/mul/div / Euclid Euc for modular inverse / Montgomery Mon for modular exponentiation — the self-contained math layer for RSA keygens, no Miracl dependency; a 1024-bit bignum = a 32-element array, loop scale under 32 (afanty). The class interface:
```cpp
#define BI_MAXLEN 40
class CBigInt {   // Base-2^32 bignum: m_nSign sign + m_nLength digit count (0–40) + m_ulvalue[BI_MAXLEN]
public:
    // Omitted: Mov/Cmp/Add/Sub/Mul/Div/Mod and decimal/hexadecimal string conversion InPutFromStr/OutPutToStr
    CBigInt Euc(CBigInt& A);    // Euclidean inverse: Y=X.Euc(A), YX mod A=1
    CBigInt Mon(CBigInt& A, CBigInt& B); // Montgomery exponentiation: Y=X.Mon(A,B), X^A mod B=Y
};
```
> Same approach: the RSA algorithm (pediy50349), the RSA computing tool, the theory and application of the DSA algorithm, learning the DSA algorithm, implementing an rsa-based digital-signature scheme
### Sublime Text 4 RSA Public-Key Replacement Analysis (orig: Sublime Text 4 RSA 公钥替换分析)
- The complete public-key-replacement paradigm: (1) search "Unlimited" to locate the pseudo-license construction; non-empty line count × 0x32 must equal 0x1A0 or 0x160 (13 or 11 lines); (2) the public key hides in the data section, decoded at runtime byte-by-byte XOR 0x7F (the XOR value drifts per version); the decoded result is a **DER-format RSA-1024 public key** (recognize the header 30819D300D06092A864886F70D0101); (3) the verification library is tomcrypt: rsa_verify_hash_ex, SHA1 (the license's first three lines) + PKCS#1 v1.5 padding (0xFF-padded to length) + the 1024-bit signature = the hex of a string of 0-serial-lines; (4) keygen: openssl genrsa -3 1024 generates a new key → tomcrypt rsa_sign_hash_ex signs, rsa_export exports DER → XOR 0x7F → binary-edit over the original public-key segment → sign the license file with the new private key and assemble it (Mr.zhong); universality: every "embedded DER public key + standard signature verification" program works the same — to find the key, search for the 30819D/3082010A headers or the XOR loop first.
### A First Look at 58 Zhaocaimao's Modified RSA and Modified BASE64 (orig: 浅析58招财猫变形RSA与变形BASE64)
- libcom_wuba_uc_rsa.so's Java_com_wuba_uc_RsaCryptService_encrypt: JByte2CChar → encrypt_default (first decrypts the embedded RSA public-key file) → encrypt_d (RSA encrypt + ch_crypt transform) → modified Base64 output; structural weaknesses: the RSA mode is simple (CBC suggested), no anti-debug, the modification layers are independent and peelable (无名侠).
> Same approach: the RC4/Base64-modification app-side cases (see section VII's Transformers entry)
### keygen of TMG Official Keygenme #3 (orig: keygen of TMG Official Keygenme #3)
- An MD5+ElGamal64 combo: the ElGamal's DLP (discrete log) was **deliberately weakened at generation** — miracl's bundled index.c routine, lightly adapted, solves it; weakened-parameter ElGamal is an old keygenme regular; the coding: miracl (ms32.lib) + an md5 library, FormatHash converting the 16-byte digest into 32 hex chars (arbiter).
> Same approach: KeyGen of KeyGenMeRSA (the freelip bignum library, lip.h); the signature-based KeygenMe; TMG keygenmersa; KEYGENNING4NEWBIES #7 (the MD5-type keygenme tutorial series)
### The ECC Elliptic-Curve Family (orig: ECC 椭圆曲线系)
- An introduction to ECC encryption (pediy6014): curve equations/point operations/keypair-generation framework; ECC elliptic-curve arithmetic and a C implementation of the national SM2 (217742): full SM2 in C — point add/double/key derivation; ECC elliptic-curve encryption study notes (253672), elliptic-curve crypto and the NSA-backdoor archaeology (259565, the Curve25519/DUAL_EC_DRBG history); reverse-side significance: ECC registration protection is rare, but SM2 is growing in domestic-license software; the point-multiplication constant tables / prime-field parameters p, a, b are the identification fingerprints.

## V. Standard-Cipher Identification and Modification

### Modified Md5 (Constants + Padding + Transform) (orig: 变形Md5(常数+填充+变换))
- cnbragon's three factors of MD5 modification: **change the four initial constants, change the padding characters, change the hash processing** — this case hits all three: the IV written as `1234567/89ABCDEF/FEDCBA98/76543210` (the originals' byte order swapped, A↔B exchanged); padding modified: the first byte 0x01 instead of 0x80 (3 spots), the length field a `len>>0x1D` and `len<<3` bit-displaced combo; restoration: diff against the standard MD5 to find the first-round divergence, reverse only the differences (baby2008).
> Same approach: the modified MD5 (pediy8-7); brute-forcing the QQ local-password file; MD5 assembly-code optimization (performance); MD5 optimization; WinMD5 for ASM
### The DES (Weakkey, X)=X Analysis (orig: DES(Weakkey,X)=X 的分析)
- A weak key makes the subkey sequence K1=K2=...=K16 (or K16=K1 symmetric), so encrypt and decrypt coincide → a fixed-point plaintext X exists with DES(K,X)=X; reverse-side significance: meet DES weak keys (the four: 01…1F/FE…E0/E0…01/1F…FE) and you can mount a cycling-encryption attack directly; recognize weak keys by the subkey generator's C/D registers all-0 or all-1 (winndy).
> Same approach: a brief analysis of a bug in a DES source; the standard DES algorithm analysis; DES recognition; the DES encryption algorithm illustrated; the DES official-document translation; DES encryption/decryption and avalanche-effect verification; the DES64 encryption algorithm; the DES(Weakkey) follow-up discussion
### A Combat DES Keygen (orig: 实战DES算法注册机)
- The Delphi three-stage locating method: PEID identifies Delphi → **DeDe finds the TForm_Reg.btn_ConfirmClick event address** (W32dasm can't search the garbled Chinese failure string; eXeScope neither) → breakpoint in OD; the algorithm is standard DES: the four CALLs read-fake-code/read-machine-code/SubStr-take-segment/compare, and inside the key CALL are the standard IP/FP permutation tables + S-boxes (Esperancer).
> Same approach: the DES test tool (with source); the SDK install password
### Algorithm Identification in Android Reversing (aes, tea, md5) (orig: Android逆向中记算法识别(aes、tea、md5))
- A signature-constant cheat sheet: AES = a 256-byte S-box (or dynamically generated); the TEA family = 0x9e3779b9/0x61c88647; MD5 = 0x67452301/0xefcdab89/0x98badcfe/0x10325476 (neulwu); the parameter-observation method: log each sub_'s inputs/buffer changes (who encrypted what, how long) → xxtea's n argument negated means decrypt (change 0x8 to -0x8 and the original function decrypts) → the AES layer cross-checked with pycryptodome using the same key → the final MD5 layer compared against the target bytes; in one sentence: symmetric layers reuse the original function with flipped parameters, hash layers cross-check against standard libraries.
### RC4 and Base64 Modifications (Kanxue CTF — Transformers) (orig: RC4、Base64魔改(看雪CTF-变形金刚))
- JNI_OnLoad dynamically registers the eq function (hook art's RegisterNatives, or read the off_4010 registration table in IDA); the data initializes in .init_array/.fini_array's datadiv_decode (younghare); modified RC4: the S-box's initial values aren't 0..255 in order but a built-in 256-byte shuffled table (unk_23E8); KSA/PRGA structure preserved; the key derived from a GUID string minus `-` through a custom algorithm-03 transform; modified Base64: a custom 64-char alphabet (`!:#$%&()+-*/…`) + the output side `i%4==0 XOR 0x07, i%4==2 XOR 0xF`; the java-layer sleight of hand: OnCreate registers a fake OnClick, onStart overwrites it with the real callback.
> Same approach: the Nep CTF password (rc4 + alphabet-swapped base64; the java layer compares an rc4 ciphertext table + the so layer verifies)
### Common ShellCode Hash Algorithms (orig: 常用ShellCode Hash算法)
- ror13 plus add per character (`ror hash,13; add hash,c` — the standard for shellcode API-name resolution), the CRC32b variant; when identifying function-name hashes in so/loaders, try ror13 first.
> Same approach: the asm implementation of the common ShellCode hash algorithms; the Hash algorithm tool
### The CRC32 Algorithm, Analyzed and Reversed (orig: CRC32 算法分析、逆向)
- Table generation (the 0xEDB88320 reflected polynomial) and the per-byte table iteration `crc=(crc>>8)^table[(crc^byte)&0xFF]`; reverse-side uses: file-checksum diffing, signature camouflage (瞧红尘).
> Same approach: a clever use of CRC32 (check digits in registration algorithms); brute-forcing CRC32 passwords; a few words on CRC-32; a shallow analysis of the PE-file checksum algorithm; simple signature-search algorithms
### A Deep Understanding of the MD4/MD5/SHA Hash-Password Algorithms and Cracking (orig: 深入了解MD4/MD5/SHA哈希密码算法与破解技术)
- The password-storage side: the hash-storage differences between Linux shadow (SHA512+salt) and Windows (LM/NTLM); three cracking roads = dictionary / brute force / rainbow tables (space-for-time precomputed chains), with John the Ripper (multi-algorithm dictionary + brute) and RainbowCrack (MD5 precompute); reverse-side value: the decision framework for choosing an attack route once you hold database password hashes (salted or not decides rainbow-table feasibility) (linso, translation).
> Same approach: brute-forcing the QQ local-password file; the birthday-dictionary password generator; building a portable password-cracking rig; MD5 enumeration cracking in ASM; accelerating password cracking with ordered Markov chains and user info
### BlowFish/TEA/Twofish/Classical Miscellany (orig: BlowFish/TEA/Twofish/古典杂系)
- Trying BlowFish (HugeFox/5-50259): extract the pbox/sbox verbatim into the keygen, paired with the "make a keygen with IDA" technique; notes on learning BlowFish (7-376), the Blowfish Cipher introduced (256209); the TEA/XTEA/XXTEA encrypt/decrypt process (266933): the three brothers' round functions and delta differences — regulars in android so's; the Twofish encryption algorithm explained (7-29); the Enigma/Vigenere/Hill/affine/shift classical-cipher sextet (vol.10, CTF-oriented), 2ROT13, a real classical-cipher crack, two centuries cracking the presidential cipher (the Zimmermann telegram story); the MYF4 hardware encryption algorithm (216454).
> Positioning: mostly pure tutorials — algorithm-fingerprint reserves; on a reverse hit, check the standard implementation first, then hunt the modifications.

## VI. Communication-Packet / Database / Password-Class Algorithms

### A Game's Packet Encrypt/Decrypt Algorithm and the Algorithm Behind Its KEY (orig: 某游戏封包加解密算法及其算法KEY的算法)
- Structure: at connection the server delivers a key packet holding SendKey/RecvKey; packet[0][1] is the unencrypted length; the KEY derivation (RecvKey isomorphic, copyable into C++):
```cpp
DWORD __stdcall GetRecvKey(DWORD k) {
    return (((~((k ^ 0x006D23CF) - 0x006D2399)) & 0x0FFFF00)
          | ((~((k ^ 0x2E6D23CF) - 0x2E6D2399)) >> 0x18)
          | ((~((k ^ 0xFFFFFFCF) + 0x67)) << 0x18));
}
```
- Locating method: a **memory access breakpoint** on a ciphertext signature byte, walking back the data's origins, chasing level by level up to the encryption CALL (amwmqj).
> Same approach: reversing a game's password-encryption algorithm; a game's script-decryption algorithm reversed; the "chaos;head" resource decryption; the Wulin Waizhuan login-packet encryption analysis; the DNF second-password packet parsing; the Qiqi live-stream algorithm decrypted and restored; the log-file encryption algorithm; APICloud decrypting local resources into reverse-engineering the APP's algorithm
### Cracking a Kingsoft Game's Packet Encryption Algorithm (orig: 破解金山某游戏封包加密算法)
- A send breakpoint → back into the game's own space; the ciphertext buffer's last 2 bytes are **the unencrypted packet length** (strip them when decrypting) (callwhl); the encryption function = table lookup + add-constant-xor: **div + table lookup + a fixed big constant** = the table-driven stream-cipher signature — `xor edx,edx; div dword_91E9B4` takes the modulus for the table index (esi counting down in a loop) → `mov ecx, dword_9190F8[edx*4]` the table lookup → `add ecx, 0x2E6D23C1` the big constant → `xor [edi-4], ecx` XOR back to plaintext; the anti-debug passed with StrongOD.
### The WeChat Database Decryption Algorithm (orig: 微信数据库解密算法)
- sqlcipher's parameters in full: the file's first 16 bytes = salt; the PC edition PBKDF2-HMAC-SHA1 iterates 64000/page 4096, the Android edition 4000/1024 and **no HMAC**; mac_key = salt XOR 0x3a then derived (2 iterations); reserve = IV(16)+HMAC(20) aligned to 16; each page is independent AES-256-CBC with the IV in the page-tail reserve and the page number entering the HMAC; after decrypting the first page, restore the "SQLite format 3" header; the common reason sqlcipher fails is wrong iteration/page-size parameters (tongzeyu). The core calls (straight OpenSSL, no sqlcipher hunting):
```c
memcpy(salt, pDbBuffer, 16); for (i=0;i<16;i++) mac_salt[i] = salt[i] ^ 0x3a;
PKCS5_PBKDF2_HMAC_SHA1(pass, 32, salt, 16, 64000, 32, key);    // Android uses 4000
PKCS5_PBKDF2_HMAC_SHA1(key, 32, mac_salt, 16, 2, 32, mac_key);
// Per page: EVP aes-256-cbc; iv is the 16-byte page-tail reserve; compare HMAC(mac_key,page data+page number) against the final 20 bytes
```
> Same approach: the AliWangwang database decryption algorithm; the DingTalk PC-edition database decryption algorithm; a certain "360" browser's database algorithm reversed (Plus)
### Chatting About mysql's Password Algorithm (orig: 唠一唠mysql的口令算法)
- 4.1+: `password(p) = '*'+hex(SHA1(SHA1(p)))` (the emperor's-new-clothes double SHA1, the leading * as marker); the old 323 algorithm (pulled straight from the source; the brute-forcers were self-written from it) (humourkyo):
```c
long nr=1345345333L, add=7, nr2=0x12345671L;
for (; password < password_end; password++) {
    if (*password == ' ' || *password == '\t') continue;
    nr ^= (((nr & 63)+add)*(long)(char)*password) + (nr << 8);
    nr2 += (nr2 << 8) ^ nr;
    add += (long)(char)*password;
}
result[0]=nr&0x7FFFFFFF; result[1]=nr2&0x7FFFFFFF;   // Concatenate two output segments formatted as "%08lx%08lx"
```
> Same approach: the QQ password-encryption principle / brute-forcing the QQ local-password file; getting QQ's HASH password; the QQ remember-password MD5 reader
### The QQ 2005 New-Year Edition's Login Password Encryption Algorithm (orig: QQ 2005贺岁版登录口令加密算法)
- The ewh.db file (a "QD"-headed QQ Data structure): at offset 0x0B, 2 bytes = the AST loop count (N); the encrypted string and the UIN (QQ number) stored in segments; the algorithm: MD5 looped N times plus XOR then inverted, compared against the ewh.db ciphertext — the complete basis for local password brute-forcing (Binny).
### The Chinese Paladin (PAL) File Encryption/Decryption Algorithm (orig: 仙劍奇俠傳文件加密解密算法)
- The CPK/RST packed files: header 0x1A545352 ("RST") + index area/data-area pointers; the decrypt class's full C++ source included (DBDecEnc), a reference for writing resource extractors (menting).
> Same approach: the Huatu encryption software - clipboard algorithm; a folder-encryption software's algorithm bug; parsing and cracking the .pbb encrypted-file algorithm (attacking the shell-less encryptor side, avoiding the reader's strong shell)
### The Encryption Algorithm of Shared Xunlei P2P Communication (orig: 共享迅雷P2P通信的加密算法)
- The python protocol-decryption algorithm posted verbatim; the packet header's 4-byte length + command word is the plaintext-structure starting point for protocol analysis (xee).
> Same approach: the Shanxun client's local-password algorithm; the Xingji Jisu account capture; notes on reversing fb to find passwords
### The gsa Login Algorithm, an Improved SRP6a (orig: gsa 登陆算法 SRP6a 改良版)
- Apple's GSA = standard SRP-6a improved: N takes the RFC5054-2048 prime (multiple big-endian copies, some stored reversed), g=2, H=SHA256, k=H(N,g); the p entering the computation isn't the plaintext password (it's mapped); M1/M2 verification, the shared key K, the spd login result AES-CBC encrypted; the reverse path: iTunes has no plaintext functions — record the key data points and assemble the parameters; the iOS/macOS sides have plaintext functions to cross-check (ppbb).
> Same approach: the Apple gsa server login algorithm (221012)
### The Steam Token Algorithm Analysis (orig: steam令牌算法分析)
- A local TOTP variant `generateSteamGuardCodeForTime(time)`: `t=time/30` to an 8-byte big-endian → HMAC with mSecret → dynamic truncation taking 4 bytes → modulo over the character set generating a 5-char code; locating: the APK is unobfuscated; uiautomatorviewer takes the component ID twofactorcode_code → jadx searches the ID → getTwoFactorToken().generateSteamGuardCode() (kzzll).
> Same approach: the STEAM pseudo-activation-code principle; bypassing the Steam token for a certain license

## VII. Mobile Signature-Algorithm Cases

### Locating the Douyin Short-Video x-gorgon Algorithm Entry (orig: 抖音短视频x-gorgon算法入口定位)
- The flow: charles captures and pins the endpoint (aweme/v2/feed, protobuf responses) → python builds same-parameter requests verifying "change the URL parameters while the header stands still → no data" → locate the x-gorgon generation point; x-gorgon is coupled to the URL parameters — the entry-locating method is replicable (kzzll).
> Same approach: implementing the Douyin X-Gorgon algorithm with AndServer and the device-id generation endpoint; the Zuiyou sign-v2 signature-algorithm tracing and reverse restoration; the __NS_sig3 48-bit algorithm analysis and restoration (the hand-910 edition's sig3); the Kuaishou sig3 series; a fresh-grocery e-commerce's sign/mfsig; a novel app's sign; a news-reading app's token; a car app's signature; a Moutai-grabbing APP's reservationToken; a supermarket mini-program's encryption; reverse-analysis of the sign algorithm ×2; a certain app's sign-signature restoration; a certain fire APP's encryption + signature restoration; a certain dog-music login algorithm (so layer); a companion-gaming app's protocol encryption (so layer)
### Analyzing and Restoring a Certain Book App's shield (orig: 某书shield分析及算法还原)
- The string "/api/sns/v4/user/login/code" locates the endpoint class → retrofit traits ("Base URL required.") locate the build init → **when frida crashes at startup, switch to an xposed hook** to dump stacks (岁月。).
> Same approach: a Xiaomi APP's login-endpoint env, envkey, sign, hash (locate by searching the serviceLoginAuth2 endpoint name; all four parameters restored one by one)
### Analyzing an APP + Unidbg Algorithm Emulation (JD jdgs) (orig: 某APP逆向分析+Unidbg算法模拟(京东jdgs))
- A 32-bit sign suspected hash → hook `java.lang.String.getBytes` filtered by keyword (functionId) → the stack points straight at JDGuardHelper.genSign → hook again to verify inputs/outputs → the so layer emulated with unidbg patching the environment to produce the output; the getBytes-filter locating method is the generic first shot for hash-class parameters (KKKKKKEM).
> Same approach: bypassing obfuscation with the Unicorn Engine to call an algorithm (cross-platform so invocation, libmcto_media_player.so+0x249BC8); restoring a shell-app's login algorithm and implementing packet-sending; finding an APP's U3D-game http-interface sign and rewriting it in Java; a shallow analysis and algorithm restoration of an APP's new anti-Bot ATT scheme; a simple analysis of a certain ttEncrypt algorithm; the ollvm-series algorithm restorations ×7 (see the ledger)

## VIII. The Old-Software-Era Registration Forms (Vols 1-5 Survey)

- **The plaintext/signature-string era**: winhex 9.x "find the signature string, done in minutes" — 751E→EB22, a one-byte patch to register; codes could be begged for directly on BBSes; **algorithms begin appearing**: UNFOXALL looks up an 18-byte GBK table XOR; Pinyin Jiajia's registry BookID looks up a subtraction table; China Compress accumulates per character `esi+=c*6+0xA8`; Mahjong Puzzle assembles multiple segments with wsprintf.
- **Systematized teaching**: the KEYGENNING4NEWBIES #1-#7 foreign keygenme course (MD5 beginner through ElGamal); the TMG Official Keygenme series for practicing miracl/freelip bignum; the organized CCG/BCG/FCG crack-essay pipelines; **the toolchain**: the TRW2000→OD transition, W32Dasm string references, DeDe (Delphi), MASM32 fully hand-written keygens (the IT-education assessment and the security guard both shipped whole sources).
- **Machine-code binding debuts**: the GetVolumeInformation volume-serial scheme formalized; disk-serial encryption is the origin of hardware fingerprinting; the later evolution: memory keygens (the KeyMake idea) → carving code out of IDA → borrowing DLLs → RSA public-key replacement → database/protocol encryption → APP signatures (see the previous seven sections).

## IX. Anti-Crack Design (the Vendor's View; Know Thy Adversary)

### Designing a Registration-Verification Algorithm Model (orig: 设计一种注册验证算法模型)
- Anti-patch structural design: registration flags scattered across many sites, key comparisons nested inside business logic, constant tables + rotating random salts.
> Same approach: anti-crack tricks — random passwords; hiding the software's registration mechanism inside APIs (verification logic hidden in rarely-used API call sequences); adding cryptographic algorithms to SMC; the quick application of SMC + algorithms
### RSA Against Illegal Keygens + RSA1024 Against Keygen (orig: 用RSA防止非法注册机 + RSA1024防Keygen)
- The design points revisited: n long enough (≥1024), p/q symmetric in size, both e and d avoiding small values, the signature bound to machine code + username + version, and the verification result participating in decrypting real functional data (flipping only a jump inevitably gets patched); the known weakness: public-key replacement is always possible (unless the public key participates in self-verification / is white-boxed) — see section IV's Sublime entry.
## Appendix: Skip-Cluster Ledger (hit the list but off-topic / no body; not distilled)
| Cluster | Post inventory | Why not collected |
|---|---|---|
| ollvm/trace algorithm restoration | vols 21/22, 10+ posts (ollvm algorithm-restoration case shares ×3, ida trace, unicorn trace, junk removal etc.) | obfuscation-restoration topic, belongs to the deobfuscation corpus; the case layer's method names already covered by the 21_258581 series |
| Side channels | first steps into side-channel attacks (power/clock glitching), 2 posts | hardware-attack topic |
| SSDT/Shadow SSDT | 30+ posts hitting the word "algorithm" | system hacking, not cryptography |
| Sorting/data structures/graph algorithms | QuickSort, Trie, pathfinding, handle allocation, DDA lines, FIRST/FOLLOW, factorial performance, radix conversion | non-crypto false hits |
| Wireshark/traffic | traffic-analysis notes, RDP decryption, passive https | network-analysis topic |
| Password-stealing tools | the asterisk-password viewer, QQ password logging/capture series, keyloggers, the mimikatz master password, lock-screen hot attacks, ATM inference | credential theft is outside algorithm restoration (storage-class items like Alipay's password-storage mechanism were merged into section VI's same-approach lines) |
| Vulnerability class | wireshark bugs, DedeCMS password changes, Telegram hijacking, bootkit password bypass | vulnerability topic |
| Pure tutorials | the cryptography-basics quartet (AES/DES/Base64), simple-principle summaries of the ciphers, the MD-family, block-cipher intros, the SHA1 standard doc, the DES official-document translation, php cryptography, "(Chapter 6) encryption algorithms", the CTF cryptography-direction guide | textbook content, no reversing detail; the fingerprints already live in the methodology baseline |
| Ransomware | the RSA-4096 ransom, ransomware encryption-algorithm reverse identification | malicious-sample topic |
| Body in attachments | the aida64 serial analysis, the UltraEdit algorithm analysis (translation), the LeNA tutorial chapters 13-18 (hardcoded serial hunting / serial-generation algorithms), the full BlowFish attempt, parts of the TMG series | attachments only, no body; the method names are in the corresponding same-approach lines |
| Password storage/cracking misc | the birthday-dictionary generator, winrar passwords, ZIP passwords, Markov-chain-accelerated cracking, SMB capture cracking, the portable cracking rig, MD5 enumeration ASM, MD5 collisions, the SHA1 collision BitErrant | brute-force/collision-theory topics, weakly related to keygens |
| VM protection | the ARM VMProtector KeyGenMe, the MyVM KeygenMe, quickly locating VM-protected algorithms | VM topic |
| Game logic | FreeCell reversed, Lianliakan match detection, guess-the-number | not cryptography |
## LEGACY ARCHIVE

The following 2 entries have been moved to [../90-legacy/kernel-mobile-algo-proto-legacy.md](../90-legacy/kernel-mobile-algo-proto-legacy.md): The UNFOXALL 2.1 Keygen (out-of-print software; the table-XOR form is already covered by the generic patterns); The Security Guard Keygen (masm6.0) (the 2000 whole-source era; the standard BlowFish/LCG combo has no unique form). For the era survey see §VIII of this file.
