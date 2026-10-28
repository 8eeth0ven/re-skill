# Quick Reference for Common Techniques

This booklet collects the "simplest and most-used" layer: locate a target function in 30 seconds, land a patch in 1 minute, recognize simple vulnerability patterns at a glance. Deeper confrontation, fallbacks, and in-packer operations are not here; once you have located the function and then get detected or killed, open `../12-bypass/bypass-playbook.md`; when the hook layer is not enough, see `techniques/09-function-map/`.

## I. Quick-Locating Table for Common Functionalities

| Target functionality | Fastest anchor (jadx/strings search terms) | Code anchor (common APIs/classes/methods) | Locating commands (copy-paste ready) |
|---|---|---|---|
| Login/auth check | `isLogin`, `autoLogin`, `token`, `checkLogin` | `SharedPreferences.getBoolean("isLogin")`, custom `UserManager`/`Session`/`Account` classes | Global jadx search for `isLogin`; `rg -a -i -e isLogin -e autoLogin classes.dex` |
| Request signing algorithm | `sign`, `signature`, `appkey`, `nonce` | `TreeMap` sorts params → `StringBuilder` concatenates the secret → `MD5/HmacSHA1/HmacSHA256` finale | jadx search `sign(`; at the so layer after `r2 -A libx.so` run `izz~sign`; hook `javax.crypto.Mac`/`java.security.MessageDigest.digest` first to see the plaintext |
| Encryption key/IV (AES/DES/RSA) | `AES`, `CBC`, `PBKDF2`, `SecretKey`; in the so, search for the AES S-box constant `63 7c 77 7b` | `Cipher.getInstance`, `SecretKeySpec`, `IvParameterSpec`, `KeyPairGenerator` (RSA) | `rg -a -e "AES/CBC" -e "AES/ECB" -e DESede .`; `izz~AES`; hook SecretKeySpec to grab the key (see frida quick-check ③ in this section) |
| root detection | `su`, `magisk`, `Superuser`, `test-keys`, `RootBeer` | existence checks one by one for `File("/system/bin/su")`, `/system/xbin/su`, `/sbin/su`; `which su`; `Build.TAGS` containing `test-keys` | `rg -a -e system/bin/su -e magisk lib/*.so`; r2 `izz~su`, `afl~root` |
| debug/ptrace detection | `TracerPid`, `isDebuggerConnected`, `FLAG_DEBUGGABLE` | `android.os.Debug.isDebuggerConnected()`, native `ptrace(PTRACE_TRACEME,0,0,0)`, reading `/proc/self/status` | `rg -a -e TracerPid -e ptrace lib/*.so`; r2 `izz~TracerPid` |
| frida detection | `frida`, `gum-js-loop`, `gmain`, `linjector`, `27042` | walking thread names, scanning `/proc/self/maps` for `frida-agent`, reading `/proc/net/tcp` for port 27042 | `rg -a -e frida -e gum-js -e linjector -e 27042 lib/*.so`; r2 `afl~anti`, `izz~frida` |
| Emulator detection | `goldfish`, `ranchu`, `qemu_pipe`, `genymotion` | `Build.FINGERPRINT` containing `generic`, `ro.kernel.qemu`, `/dev/qemu_pipe` existence, all-zero IMSI | `rg -a -e qemu -e goldfish -e ranchu lib/*.so` |
| SSL pinning | `pin`, `sha256/`, `checkServerTrusted` | `okhttp3.CertificatePinner`, custom `X509TrustManager`, native `SSL_CTX_set_verify` (BoringSSL/OpenSSL) or `ssl_set_verify` (mbedtls) | jadx search `CertificatePinner`; `rg -a -e ssl_set_verify -e SSL_CTX lib/*.so` |
| Capture-proxy/VPN detection | `proxyHost`, `tun0`, `isProxy`, `vpn` | `System.getProperty("http.proxyHost")`, `NetworkInterface.getName()` matching `tun0/ppp0`, `Proxy.NO_PROXY` | jadx search `proxyHost`; `rg -a -e tun0 -e ppp0 lib/*.so` |
| Update/download verification | `checkUpdate`, `versionName`, `\.apk` | `getPackageInfo` version comparison, `DownloadManager`, MD5/signature verification of the downloaded file | jadx search `versionCode`; `rg -a -i -e checkupdate -e "update.*apk" .` |
| Device-fingerprint collection points | `ANDROID_ID`, `getDeviceId`, `SERIAL`, `getMacAddress` | `Settings.Secure`, `TelephonyManager`, the `Build.` family, sensor lists, `getInstalledPackages` | jadx search `ANDROID_ID`; hook `android.provider.Settings$Secure.getString` and print key/value |
| Protocol fields and serialization | `@SerializedName`, `parseObject`, `parseFrom` | `Gson.fromJson`, fastjson `JSONObject.parseObject`, protobuf `XXX.parseFrom`/field numbers | jadx search `@SerializedName`; `rg -a 'syntax = "proto' .` to find embedded proto definitions |
| so entry and JNI registration | `JNI_OnLoad`, `RegisterNatives`, `Java_` | `System.loadLibrary`, static registration `Java_package_Class_method`, dynamic registration via the `JNINativeMethod` array (when no `Java_` prefix is found, look inside `JNI_OnLoad`) | after `r2 -A libx.so`: `afl~Java`, `is~JNI_OnLoad`; `rg -a RegisterNatives libx.so` |
| Packer-shell signatures | `libjiagu`, `libSecShell`, `libDexHelper`, `libexecmain`, `libmobisec` | the Application entry swapped for a shell class, encrypted dex under assets, an unusually tiny original `classes.dex` | `unzip -l base.apk` to inspect lib/ and assets; `rg -a -e jiagu -e SecShell -e DexHelper -e mobisec .`; on a hit, move to `techniques/03-unpacking/` |
| Hardcoded passwords/key strings | `password`, `secret`, `jdbc`, `admin`, `123456` | literal comparisons, `SharedPreferences.putString`, constant-config classes | `rg -a -i -e passw -e secret -e "key=" libx.so`; global jadx search for `password =` |

The frida quick-check trio (adjust keywords as needed):

```js
// 1. Enumerate loaded classes and filter by keywords to locate detection or business classes
Java.perform(function () {
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (/root|check|secure|anti|frida|emul/i.test(name)) console.log('[RE] ' + name);
    },
    onComplete: function () {}
  });
});
```

```js
// 2. Enumerate loaded shared objects to locate detection or protection libraries
Process.enumerateModules().filter(function (m) {
  return /sec|shield|guard|protect|jiagu/i.test(m.name);
}).forEach(function (m) { console.log('[RE] ' + m.name + ' @ ' + m.base); });
```

```js
// 3. Capture AES key/IV by hooking SecretKeySpec and IvParameterSpec constructors
function hex(buf) {
  return Array.from(buf).map(function (b) {
    return ('0' + (b & 0xff).toString(16)).slice(-2);
  }).join('');
}
Java.perform(function () {
  var KS = Java.use('javax.crypto.spec.SecretKeySpec');
  KS.$init.overload('[B', 'java.lang.String').implementation = function (key, alg) {
    console.log('[RE] key alg=' + alg + ' hex=' + hex(key));
    return this.$init(key, alg);
  };
  var IV = Java.use('javax.crypto.spec.IvParameterSpec');
  IV.$init.overload('[B').implementation = function (iv) {
    console.log('[RE] iv hex=' + hex(iv));
    return this.$init(iv);
  };
});
```

Opening commands (get attached before anything else):

```bash
frida -U -f com.target.app -l quick.js     # Spawn mode; use when detection executes early
frida -U -n com.target.app -l quick.js     # Attach to an already-running process
```

What the one-line r2 commands mean (use with this section's tables):

```bash
r2 -A libcheck.so          # Open and fully analyze, equivalent to aaa
izz~frida                  # Search all strings, including resource sections, for frida
iz~su                      # Search current-section strings for su
afl~check                  # Filter function names for check
axt @ sym.check_root       # Find callers of this function to trace the call chain backward
pdf @ sym.check_root       # Disassemble the complete function
s 0x1A2B0; pd 10           # Seek to an offset and inspect instructions
```

Next step after locating the function: run `axt` first to see the call chain (confirm whether the entry sits in the Java or native layer), then decide which layer is cheapest to hook. For function layering and fallback paths see `../09-function-map/android-function-layers.md`.

## II. NOP and Patch Quick Reference

Always write byte streams little-endian as they appear in the file: r2 `wx`, a hex editor, or `printf` pasting the byte string directly — never reverse the instruction word into big-endian.

### 1. NOP Bytes per Architecture

| Architecture/mode | In-file byte stream | Mnemonic | Notes |
|---|---|---|---|
| arm64 | `1f 20 03 d5` | `nop` | instruction word 0xD503201F, stored little-endian as 1f 20 03 d5; writing it reversed as d5 03 20 1f is an invalid encoding |
| arm (32-bit ARM state) | `00 00 a0 e1` | `mov r0, r0` | the classic nop; instruction word 0xE1A00000 |
| thumb | `00 bf` | `nop` | thumb addresses carry bit0 (symbol value +1); compute patch offsets from the actual alignment |
| x86 | `90` | `nop` | 1 byte; two 90 90 covers a short jump |
| x86_64 | `90`; multi-byte for covering long instructions | `nop` / `nopl` | 5-byte nop = `0f 1f 44 00 00`; pad to the needed length |

arm64 branch-instruction table (branch offset imm = (target − current) / 4; encoding = base word + imm26):

| Instruction | Instruction word | Notes |
|---|---|---|
| `b +n` | `0x14000000` base | unconditional jump; at offset 0 the byte stream is `00 00 00 14` |
| `b.eq +n` | `0x54000000` base | cond=0000; the condition code occupies the low 4 bits of the instruction word |
| `b.ne +n` | `0x54000001` base | differs from b.eq only in the lowest bit; flip bit0 of the first byte in the little-endian stream |

x86 variable-length caution: check the original instruction's total length before NOPing — an under-cover leaves half an instruction behind and the disassembly misaligns outright. Covering instructions "whose jump target address stays unchanged" is safest; glance back with `pd` after covering.

### 2. Forced-Return-Value Patches

| Architecture | Return 1/true | Return 0/false | Notes |
|---|---|---|---|
| arm64 | `mov w0, #1; ret` = `20 00 80 52` + `c0 03 5f d6` | `mov w0, #0; ret` = `00 00 80 52` + `c0 03 5f d6` | 32-bit return values use w0; jlong/pointer returns use x0: `mov x0, #1` = `20 00 80 d2` |
| arm | `mov r0, #1; bx lr` = `01 00 a0 e3` + `1e ff 2f e1` | `mov r0, #0; bx lr` = `00 00 a0 e3` + `1e ff 2f e1` | `mov r0,#1` is 0xE3A00001 — do not write the register form 0xE1A00001 |
| thumb | `movs r0, #1; bx lr` = `01 20` + `70 47` | `movs r0, #0; bx lr` = `00 20` + `70 47` | 4 bytes total; the minimal patch |
| x86 | `mov eax, 1; ret` = `b8 01 00 00 00` + `c3` | `xor eax, eax; ret` = `31 c0` + `c3` | Ignore the function prologue; cover the function head directly |
| x86_64 | same as x86: `b8 01 00 00 00` + `c3` | `31 c0` + `c3` | writing eax auto-zeroes the high 32 bits — good enough |

Write the patch at the function head's first instruction; a jboolean return only looks at the low 8 bits of w0, so returning 1 for true is enough. Leaving the prologue (the stack-frame setup) untouched keeps the caller convention intact.

### 3. Branch/Comparison Patches

- **Conditional jump to NOP**: change the `b.cond` jumping to the failure block (4 bytes on arm64) to `1f 20 03 d5`; change the x86 short jump `74/75 xx` to `90 90`. Fits single-point branches of the "jump only on check failure" kind.
- **eq/ne swap**: on arm64 the condition code sits in the low 4 bits of the instruction word — the lowest bit of the first byte in the little-endian stream; b.eq(0)↔b.ne(1) just flips that bit. The sturdy way is reassembling in r2 with `wa b.ne 0x<target>`.
- **Always-true jump**: swap the conditional branch for an unconditional `b`: instruction word = `0x14000000 | ((target-current)/4 & 0x3ffffff)`; offset 0 is `00 00 00 14`. Note: never replace `cmp` with `mov` — `mov` does not touch flags, and the following branch would test stale flags; this is a common mistake.
- **Smali layer**:
  - Insert `const/4 v0, 0x1` after `invoke-*/move-result v0` (reuse an existing register; do not change `.registers`); for a returned verdict, change the value just before the later `return v0`.
  - Change `if-eqz v0, :fail` to `if-nez`, or retarget the jump to the normal-branch label.
  - In void methods, delete the `throw` of a check and swap in `return-void`; with a return value, `const` + `return`.

Before/after comparison:

```smali
invoke-static {}, Lcom/x/Check;->isVip()Z
move-result v0
const/4 v0, 0x1          # Insert this line to override the check result, reusing v0 without changing .registers
if-eqz v0, :cond_fail    # Alternative: change this if-eqz to if-nez
```
- **The repackaging one-stop pipeline**:

```bash
apktool d target.apk -o out/          # Edit out/smali*/
apktool b out/ -o patched.apk
zipalign -p -f 4 patched.apk aligned.apk
apksigner sign --ks debug.keystore --ks-pass pass:android --out signed.apk aligned.apk
adb install -r signed.apk
# Or align and sign in one step: java -jar uber-apk-signer.jar -a patched.apk
```

Branch-patch practice in r2 (reassembling beats hand-computing bytes, especially for offset-carrying jumps):

```bash
r2 -w libcheck.so
s 0x1A2B4
wa b.ne 0x1A2C0       # Change b.eq to b.ne, keeping the original branch target address
pd 2
q
```

### 4. The so-Patching Workflow

```bash
r2 -w libcheck.so
iS~.text          # ELF file offsets differ from runtime addresses; compare addr/vaddr with paddr in the iS table
# Program-header conversion: readelf -l libcheck.so | grep -A1 LOAD
# File offset = vaddr - segment VirtAddr + segment Offset
afl~check         # Locate the target function; seek with s sym.check_root or s <file-offset>
wx 20008052c0035fd6   # Write the hexadecimal bytes directly: mov w0,#1; ret
# Or assemble directly: wa mov w0, #1; ret
pd 5              # Disassemble again to verify
q
```

If you would rather not open r2, writing straight to the file offset from the command line also works (the seek must be the file offset, and `conv=notrunc` must not be dropped, or the file gets truncated):

```bash
printf '\x20\x00\x80\x52\xc0\x03\x5f\xd6' | dd of=libcheck.so bs=1 seek=$((0x1A2B0)) conv=notrunc
```

Two thumb pitfalls: function symbol addresses carry bit0 (shown as +1) — compute the actual patch offset on even numbers; thumb instructions are 2-byte aligned — when covering with a 4-byte patch, do not split a neighboring instruction in half.

Three post-edit self-checks:

```bash
# 1. Disassemble and compare against the expected instructions
r2 -q -c 's 0x1A2B0; pd 2' libcheck.so
# 2. Confirm the bytes were actually written by comparing before and after
md5 -q libcheck.so          # Use md5sum on Linux
# 3. Verify the signature after repackaging
apksigner verify -v signed.apk
```

When file patches are blocked by signature/integrity checks, do the patch in memory with frida (the in-so offset likewise comes from `iS`/the symbol table):

```js
var base = Module.findBaseAddress('libcheck.so');
var addr = base.add(0x1A2B0);              // Function offset within the shared object
Memory.protect(addr, 8, 'rwx');
addr.writeByteArray([0x20,0x00,0x80,0x52, 0xC0,0x03,0x5F,0xD6]); // mov w0,#1; ret
```

### 5. Which One When

| Scenario | Use |
|---|---|
| The conditional logic is too complex to read and you only want the result | Forced-return-value patch (table 2) |
| The branch merely adds one more check | Conditional-jump NOP (table 3, first item) |
| The dex is unreachable inside the packer, or signature verification pops after repackaging | so file patch / frida memory patch; for going further up see `techniques/02-frida/` and `../12-bypass/bypass-playbook.md` |
| You want it permanent and do not want frida always attached | File patch + repackage-and-sign (table 3, last item) |

## III. Simple Vulnerability-Pattern Quick Reference (locate + one-sentence verification)

Probe-value conventions in `../../test-values.md`: log prefix `[RE]`, constructed values `REPROBE-<date>-<seq>`, memory magic `0x52455052`; high-collision values like deadbeef/0x42 are banned.

| Pattern | Locating anchor | Quick verification |
|---|---|---|
| Hardcoded key | jadx/strings search `AES`, `secret`, `key`; long-base64 regex `[A-Za-z0-9+/]{20,}={0,2}` | Use §I quick-check ③ to hook out the key/iv, then locally decrypt a captured ciphertext once to verify (commands below) |
| Default password / backdoor account | Search the literals `admin`, `test`, `guest`, `123456`; demo accounts inside login shells | Hit the login endpoint directly with `admin/admin`, `test/123456`; a success business code in the reply means hit |
| Weak randomness | jadx search `new Random(`, `Math.random`; classes holding reset-code/SMS-code/lottery logic | Check whether the seed is `System.currentTimeMillis()`; hook `java.util.Random.nextInt` with `[RE]` logs — the same seed reproducing the same sequence locally means weak randomness |
| ECB mode | Search `AES/ECB`, `DES/ECB`, `Cipher.getInstance("AES")` (the default is ECB) | Hook `Cipher.getInstance` and log the transformation string; or compare two requests — identical ciphertext blocks for identical plaintext segments means ECB |
| Single-layer md5/sha1 password storage | Search `MessageDigest.getInstance("MD5")`, login-parameter construction sites | Capture the login request and check whether the password field is 32-hex; compare against common weak-password hashes (commands below) |
| Client-side check bypassable | Local `if (isVip)`, `isPay()`, license/in-app-purchase return-value branches | One-shot verification: `Check.isVip.implementation = function(){ console.log('[RE] bypass'); return true; };`; to make it permanent, switch to the §II forced-return-value patch |
| IDOR-style id parameters | Numeric `id`/`userId`/`orderId` in object endpoints | Change `id=9100000001` → `id=9100000002` (fake-range values, see `../../test-values.md`) and see whether someone else's data comes back; an identical response structure means horizontal privilege escalation |
| Predictable token | Token is a bare timestamp, auto-increment, or timestamp+md5 | Compare two logins: token delta ≈ the request interval in seconds; compute the next one with `date +%s` and replay it |
| Empty certificate-trust implementation | jadx search `checkServerTrusted`, `TrustManager`; check whether the method bodies are empty | A custom TrustManager with both verification methods empty = trusts all certificates; any proxy certificate decrypts the plaintext |
| Sensitive-info log leakage | Search `Log.d(`, `Log.i(` carrying token/password/phone numbers | Clear logcat, run one normal round of app usage, filter keywords and see what was spat out (commands below) |

Verification command blocks (matching the three "commands below" markers above):

```bash
# Hardcoded-key verification: capture key/IV, decrypt one captured ciphertext, and confirm readable plaintext
echo '<base64-ciphertext>' | base64 -d | openssl enc -d -aes-128-cbc -K <keyhex> -iv <ivhex>

# Single-layer MD5 password: compare the captured password field against hashes of common weak passwords
echo -n admin123 | md5sum

# Log leakage: clear logs, then exercise one application workflow
adb logcat -c && adb logcat | grep -i -e token -e password
```

Corroborating hooks for ECB/weak randomness (the transformation string reveals the mode at a glance; Random calls are obvious):

```js
Java.perform(function () {
  var C = Java.use('javax.crypto.Cipher');
  C.getInstance.overload('java.lang.String').implementation = function (t) {
    console.log('[RE] Cipher.getInstance: ' + t);
    return this.getInstance(t);
  };
  var R = Java.use('java.util.Random');
  R.nextInt.overload().implementation = function () {
    var v = this.nextInt();
    console.log('[RE] Random.nextInt = ' + v);
    return v;
  };
});
```

Do a closing pass per `../../test-values.md`: `grep -r "\[RE\]" <artifact-dir>`, and on the device `ls /data/local/tmp/re_*`, confirming zero residue.

## IV. Self-Verification

The sibling `verify_patch.py` in this directory is this booklet's self-check script: capstone disassembles to verify that this booklet's bytes ↔ mnemonics match, and unicorn emulates to demonstrate "original function returns 0, patched function returns 1".

```bash
cd techniques/16-quick-ref && ../../tools-env/.venv/bin/python verify_patch.py
```

Measured results (local capstone 5.0.7 + unicorn 2.x):

```text
[PASS] arm64 NOP: 1f2003d5 -> nop
[PASS] arm64 return1: 20008052c0035fd6 -> mov w0, #1; ret
[PASS] arm64 return0: 00008052c0035fd6 -> mov w0, #0; ret
[PASS] arm NOP(mov r0,r0): 0000a0e1 -> mov r0, r0
[PASS] arm return1: 0100a0e31eff2fe1 -> mov r0, #1; bx lr
[PASS] thumb NOP: 00bf -> nop
[PASS] thumb return1: 01207047 -> movs r0, #1; bx lr
[PASS] x86 NOP: 90 -> nop
[PASS] x86 return1: b801000000c3 -> mov eax, 1; ret
[PASS] x86 return0(xor+ret): 31c0c3 -> xor eax, eax; ret
[PASS] x86_64 NOP: 90 -> nop
[PASS] x86_64 return1: b801000000c3 -> mov eax, 1; ret
[unicorn/arm64] original x0=0, patched x0=1
[unicorn/x86]   original eax=0, patched eax=1
Result: disassembly 12/12 PASS;arm64/x86 emulation before/after behavior changed correctly
```

Two pitfalls you only hit by actually running it (the script already avoids both):
1. The arm `mov r0,#1` instruction word is 0xE3A00001 (the immediate form); slipping into the register form 0xE1A00001 turns it into `mov r0,r1`;
2. Running `ret/bx lr` in unicorn requires **setting a return address first** (set LR on arm64, push on the stack on x86), otherwise it jumps to address 0 and FETCH_UNMAPPED fires immediately.

---

After the patch lands / after locating the function you get detected or killed → open `../12-bypass/bypass-playbook.md`; when you need deeper layers (libc/svc/kernel) → `../09-function-map/hook-fallback-playbook.md`.
