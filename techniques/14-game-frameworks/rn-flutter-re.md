# React Native and Flutter Reverse Engineering

> Positioning: **a command-flow tutorial** — complete reverse engineering of the two hybrid framework families, React Native and Flutter (beyond mere capture): bytecode/snapshot → symbol/source level → frida-hooking business functions.
> Division of labor: **the capture chain** (TLS/certificates/proxies) is not this piece's business — it belongs to `../04-evasion/capture-all-scenarios.md` §2.7 and `../04-evasion/ssl-pinning-bypass.md` §3.3; this piece handles "understand the code, hook the functions, locate the encryption parameters".
> Tool-row index: `../05-toolbox/tool-master-table.md` (the three rows dae / FlutterTap / Reqable).

## 0. First Minute: Determine the Framework

```bash
unzip -l app.apk | grep -i -E "index.android.bundle|libhermes|libapp.so|libflutter|flutter_assets"
```

| Signature | Framework and form | Go to |
|---|---|---|
| `assets/index.android.bundle` + `lib/*/libhermes.so` | **RN + Hermes bytecode** (mainstream) | §1 |
| `assets/index.android.bundle` + no libhermes | RN plain JS bundle | §2 |
| `lib/arm64-v8a/libapp.so` + `libflutter.so` + `assets/flutter_assets/` | **Flutter (AOT snapshot)** | §4 |

The RN bundle may also be renamed / tucked into an `assets/` subdirectory — fuzzy-search by `*.bundle`; in Flutter the business lives entirely in `libapp.so` (Dart AOT snapshot) and the Java layer is just a shell.

## 1. RN Hermes: The Full Bytecode Workflow

### 1.1 Version-Header Identification

```bash
file ext/assets/index.android.bundle
# Hermes JavaScript bytecode, version 84; file reports the version directly
xxd -l 16 ext/assets/index.android.bundle
# c6 1f bc 03 c1 03 c1 03 | 54 00 00 00 ...
# Fixed magic bytes; little-endian u32 at offset 8 gives the bytecode version (0x54 = 84)
```

The version decides the tool choice: **hbctool supports only the 76/84/85/86/89/90 subset**; **94~96 (RN 0.73~0.83, and 0.84+ with Hermes V1 disabled) use hermit (§1.3b)**; everything else (older / 98+) falls back to hermes-dec (§1.3).

### 1.2 The Full hbctool Workflow (disassemble → edit → reassemble)

```bash
UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python hbctool
# Disassemble:
hbc-disasm ext/assets/index.android.bundle hbc_out
# Outputs under hbc_out/:
# metadata.js: version, function count, flags
# string_id_table.js: complete string table, the main locating surface in Section 1.4
# instruction.hasm: all functions disassembled, grouped by function and directly editable
# Reassemble after editing:
hbc-asm hbc_out patched.bundle
# Put the bundle back into the APK and sign again; see the repackaging section of ../05-toolbox/tool-detection-and-modding.md
```

Example edits: locate the target function in `instruction.hasm` (via §1.4 string locating first), change `StrictEqual` to `StrictNotEqual`, change the immediate of `LoadConstUInt8`, or insert `ReturnUndefined` at the top of a whole function to short-circuit a check — after editing, hbc-asm verifies whether the length change stays within bounds (the hasm comments carry range hints).

### 1.3 hermes-dec (all-version fallback + approximate source)

```bash
uv tool install hermes-dec          # Requires only the Python 3 standard library; pipx is an alternative
hbc-file-parser ext/assets/index.android.bundle            # Inspect the header structure
hbc-disassembler ext/assets/index.android.bundle out.hasm  # Disassemble without a version restriction
hbc-decompiler ext/assets/index.android.bundle out.js      # Generate approximate JS pseudocode; control-flow recovery is incomplete
```

Use hbctool for locating (its string table is handy) and hermes-dec's decompiler for reading logic — the two are often used together.

### 1.3b hermit (94~96 decompile + structured patching, new)

```bash
# Prebuilt release from github.com/xV4L3x/hermit, for macOS arm64:
tar -xzf hermit-0.1.0-macos-arm64.tar.gz
xattr -dr com.apple.quarantine hermit-0.1.0-macos-arm64   # Unsigned binary; remove quarantine once
hermit-0.1.0-macos-arm64/hermit ext/assets/index.android.bundle   # GDB-style REPL with a full-screen bytecode editor
# CLI package hermit-tools: hbc_disasm / hbc_dump / hbc_strings / hbc_functions / hbc_patch / hbc_roundtrip / hbc_section_map
```

Unlike hbctool's hasm text editing, hermit does **structured patching**: instructions can be added or removed (jumps/exception tables/string tables are automatically relocated), and after editing a byte-level round-trip check is available; it also ships deterministic (non-AI) decompilation to readable JS plus CFG/DOT. Versions outside 94~96 (98 = RN 0.84+ with default Hermes V1) are still unsupported — fall back to hermes-dec. Added to the library 2026-10; smoke-tested 0.1.0 passing.

### 1.4 Working the Hermes String Table (the proper way to locate business functions)

1. Grep business keywords in `string_id_table.js`: `grep -n -i "login\|sign\|encrypt\|token\|vip" hbc_out/string_id_table.js` to get the **string id**;
2. Grep that id in `instruction.hasm` (`LoadConstString  r0, 12345`) — every function referencing this string is a target;
3. Copy the function name from the function-block header (Hermes function names also live in the string table) and cross-confirm;
4. For dynamic verification: runtime hooking — RN's JS execution lives in libhermes and the frida side has no ready-made bridge like V8's, so statically reading hasm + editing and reassembling is more practical; dynamically following the protocol still goes through the §3 native bridge.

### 1.5 The Hermes Runtime Surface (dynamic verification)

When static edits will not do / you need to verify a function is actually called, the landing point is `libhermes.so`:

```bash
frida-trace -U -f com.target.app -i '*Evaluate*JavaScript*' -i '*hermes*parse*'
# Observe the JS execution entry; to inspect individual JS function calls, prefer static locating in Section 1.4 plus edit-and-reassembly in Section 1.2
```

The Java shell of an RN app (ReactInstanceManager/ReactHost) loading the bundle can also be hooked (the loadScript family of `com.facebook.hermes.reactexecutor.HermesExecutorImpl`); dumping the arguments in onEnter yields "the bundle source exactly as the engine swallowed it" — **for variants that add another runtime decryption/concatenation layer on the bundle, this is the only point to get the full original**.

### 1.6 Put It Back into the APK (repackaging flow)

```bash
# 1. Replace the bundle
cp patched.bundle ext/assets/index.android.bundle
cd ext && zip -r ../patched.apk . && cd ..
# 2. Align and sign; zipalign/apksigner are in Android SDK build-tools
zipalign -p -f 4 patched.apk aligned.apk
apksigner sign --ks debug.keystore --out signed.apk aligned.apk
# 3. Install and verify
adb install -r signed.apk
```

Re-signing breaks the original package's signature verification (games/shells that verify must be defeated: the repackaging chain and V1/V2 signature-bypass sections of `../05-toolbox/tool-detection-and-modding.md`).

## 2. RN Without Hermes (plain JS bundle)

### 2.1 Direct Read

```bash
head -c 300 ext/assets/index.android.bundle   # __d(function...{...}) indicates plaintext modular Metro JavaScript
```

Split modules by metro format: `__d(function(require,module,exports){...},<id>,[dependency ids])` — write a script to split at top-level `),` or read with editor folding; the business code may be minified/obfuscated (short variable names), but the structure and strings are all there.

### 2.2 source-map Restoration (when a .map exists)

```bash
unzip -l app.apk | grep -i "\.map"           # index.android.bundle.map is rarely shipped; if present, use it for source recovery
npx reverse-sourcemap -v -o restored/ ext/assets/index.android.bundle.map
# Recover the original src/ tree and variable names, then inspect TypeScript/JSX source
```

With no map: deobfuscate the obfuscated JS following the js-obfuscation ideas in `../../platforms/01-windows/languages.md` §2 (synchrony-class tools).

## 3. The RN Native Bridge Surface (when the logic/crypto sits in Java or the so layer)

- Search jadx for `ReactMethod`/`NativeModule`/`TurboModule` — every native method RN exposes to JS is here; crypto/device-fingerprinting is often made a native module;
- Java layer: hook directly with frida `Java.use` (use the whole 02-frida/java-layer/crypto-and-self-dump.md kit as-is);
- so layer: the `../02-frida/native-hook-cheatsheet.md` RegisterNatives set;
- New-architecture (JSI/TurboModule) bridges are C++ (the so next to libhermes); JS-layer arguments are already JSI values, so statically reading hasm + dynamically hooking the Java endpoint is the low-effort combo.

## 4. Complete Flutter Reverse Engineering (beyond capture)

### 4.1 Material and Version

```bash
unzip -o ../app.apk "lib/arm64-v8a/*" "assets/flutter_assets/*" -d ext
strings ext/lib/arm64-v8a/libflutter.so | grep -o 'Dart_VM.*' | head -1   # Engine/Dart version fingerprint
```

Key points: **the business logic is entirely in `libapp.so`** (Dart AOT snapshot, a pure data blob with no exports); `libflutter.so` is the engine (the BoringSSL network stack lives here). arm64 is the mainstream; emulator packages may be x64 — blutter eats arm64 only.

### 4.2 The blutter Toolchain (the symbol-restoration workhorse)

```bash
git clone https://github.com/worawit/blutter && cd blutter
# Dependencies: g++>=13 or clang>=16, Python 3 with pyelftools and requests, cmake/ninja
# macOS: brew install cmake ninja pkg-config icu4c capstone && pip3 install pyelftools requests
python3 blutter.py path/to/ext/lib/arm64-v8a blutter_out
# First run fetches and builds the matching Dart source; expensive, cached per version; use --rebuild after upgrading
```

Outputs: `asm/` (symbolized assembly), `blutter_frida.js` (a hook template specific to this app), `objs.txt`/`pp.txt` (the Object Pool object tree — **classes/methods/string literals with their offsets**).

### 4.3 dae (already in the radar toolbox; pure static, compile-free, query-style workflow)

```bash
brew install ejfkdev/tap/dae        # Single binary; does not execute the target or require the Dart SDK
dae info ext/lib/arm64-v8a/libapp.so                 # Snapshot/SDK overview
dae strings ext/lib/arm64-v8a/libapp.so -f sign      # Search business terms in the string table
dae findrefs ext/lib/arm64-v8a/libapp.so string sign # Find references to this literal
dae getmethod ext/lib/arm64-v8a/libapp.so 'ApiClient.makeSign'   # Pseudocode for one method
dae functions ext/lib/arm64-v8a/libapp.so login      # Filter the function list
dae callers ext/lib/arm64-v8a/libapp.so <NAME|0xADDR>  # Call chain
dae export ext/lib/arm64-v8a/libapp.so dae_out --app --decompile   # Full export; --app skips the dart:/flutter libraries
```

The full export contains: `ida_script/addNames.py` + `ida_dart_struct.h` (IDA: File→Script file), `r2_script/addNames.r2` (`r2 -i r2_script/addNames.r2 libapp.so`), the `frida.js` hook template, `text/pp.txt|objs.txt|strings.txt`, and `callgraph.dot`.
**Selection: dae first (seconds-level) for locating; blutter as the fallback (for new Dart versions dae does not recognize — at the cost of compiling on the spot).**

### 4.4 Hands-on frida Hooking of Dart Functions

blutter/dae addresses are all **file offsets**; the runtime address = libapp base + offset:

```js
// dart_hook.js: hook the business signature function to inspect plaintext arguments
const libapp = Process.findModuleByName("libapp.so");
const makeSign = libapp.base.add(0x2C3B40);   // Copy the offset from objs.txt/getmethod

Interceptor.attach(makeSign, {
    onEnter(args) {
        // Dart calling convention: x0 holds argument 1, etc.; a Dart String is an object, so read length and data at the correct offsets
        // Prefer the Dart-object readers already supplied in blutter_frida.js
        console.log("makeSign hit");
    },
    onLeave(retval) { console.log("ret", retval); }
});
```

```bash
frida -U -f com.target.app -l dart_hook.js --no-pause
# Or use the generated template directly: frida -U -f com.target.app -l blutter_out/blutter_frida.js
```

### 4.5 Locating so-Layer Encryption Parameters in Practice (end to end)

1. **Capture to confirm the ciphertext form** (via `../04-evasion/capture-all-scenarios.md` §2.7: Flutter ships its own BoringSSL — clear the certificate layer first, `../04-evasion/ssl-pinning-bypass.md` §3.3);
2. `dae strings … -f <encrypted-field-name>/sign` (copy the field name from the captured JSON and search backwards) → `dae findrefs` → `dae getmethod` for pseudocode to confirm where the algorithm sits:
   - Algorithm in the **Dart layer** → hook per §4.4; the arguments are the plaintext/key; go offline via `../10-algo-restore/protocol-offline-rpc.md`;
   - Algorithm in a **native so** (self-built so or a third-party crypto library) → back to the regular Java/JNI/native chain (`../02-frida/native-hook-cheatsheet.md`);
3. **The BoringSSL-boundary backstop**: hook `ssl_write` in `libflutter.so` (symbol/offset per engine version, located via the §4.1 version fingerprint); what you get is always the **pre-encryption plaintext** — sidestepping every business-layer encryption-locating difficulty;
4. When certificate verification cannot be bypassed: the frida-free options are **FlutterTap** (Zygisk, has a row in the tool master table) or **reFlutter** (repackage with a modified engine: `pip install reflutter && reflutter app.apk` → install `release.RE.apk`; traffic prints straight to screen / lands in dump.dart).

## 5. Troubleshooting Quick Table

| Symptom | Most likely cause | Action |
|---|---|---|
| hbc-disasm reports unsupported version | version not in 76/84/85/86/89/90 | the hermes-dec trio (§1.3) |
| hbc-asm reassembly fails | instruction length out of bounds / bad operand | equal-length replacement within the hasm block; change constants, not structure |
| blutter errors compiling Dart | local compiler too old (g++<13) | switch to clang>=16; on macOS `brew install llvm` |
| dae does not recognize the snapshot | Dart version too new | back to blutter (compiles that version on the spot) |
| Hooking the libapp offset has no effect | the so is an x64 emulator package / the offset is a VA, not a file offset | re-download the arm64 package; the base + file-offset convention |
| Dart arguments read as garbage | the Dart String object was not read via the helper | use the blutter_frida.js template's reading helpers |
| Flutter requests cannot be captured | goes through BoringSSL + self-parsed DNS | `../04-evasion/capture-all-scenarios.md` §2.7 → `../04-evasion/ssl-pinning-bypass.md` §3.3 |

## 6. Corpus Search Terms (data/ essence index)

「Flutter 逆向初探」「Flutter Android 逆向介绍」「某修仙肉鸽游戏协议逆向分析折腾记录」「UNI-APP渗透测试-抓包」 (the same hybrid-framework family) 「APP加密报文Burp明文抓包方案」.
