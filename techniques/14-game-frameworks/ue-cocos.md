# UE and Cocos Mobile-Game Reverse Engineering

> Positioning: **a command-flow tutorial** — the full unpacking, symbol restoration, and script-layer decryption workflow for the two families: UE (Unreal) and Cocos2d-x/Creator.
> Division of labor: Unity/IL2CPP goes to unity-il2cpp.md; detection and ban boundaries go to framework-detection-counter.md; once lua is reversed and you need the protocol, continue with `../10-algo-restore/protocol-offline-rpc.md`.
> Note: the lua bytecode reversing in this piece has nothing to do with heap exploitation (`../../platforms/06-binary-vuln/`); the methodology comes entirely from the game-reversing corpus (search terms in §7).

## 0. First Minute: Determine the Engine

```bash
unzip -l app.apk | grep -i -E "\.pak|\.utoc|\.ucas|\.uexp|\.umap|libUE|libUnreal|libAnarchy"
unzip -l app.apk | grep -i -E "libcocos|\.jsc|\.luac|src/.*lua|libgame"
```

| Signature | Engine | Go to |
|---|---|---|
| `*.pak` (old) or `*.pak + *.utoc + *.ucas` (IoStore, 4.23+/UE5) + `libUE4.so`/`libUnreal.so` | **UE** | §1-§2 |
| `libcocos2djs.so` + `assets/*.jsc`/`src/*.jsc` | **Cocos2d-x JS (jsb)** | §3 |
| `libcocos2dlua.so`/`libgame.so` + `assets/src/*.lua` | **Cocos2d-x Lua** | §4 |
| `libcocos2djs.so` + `assets/assets/` + `config.yml`/`application.cfg`? | **Cocos Creator build** | §3+§5 |

Big UE packages also often put the pak in the obb or download it on first launch to `/sdcard/Android/data/<pkg>/files/…`; when unzip shows nothing, look on the device: `adb shell find /sdcard/Android/data/<pkg> -name "*.pak" -o -name "*.utoc"`.

## 1. UE: The Unpacking Chain

### 1.1 pak Unpacking (repak command flow)

```bash
cargo install repak            # Or download the release binary; on brew-family hosts cargo installation is also available
repak info Game.pak            # Inspect version, encryption state, and mount point
repak list Game.pak | head -50 # List contents; encrypted pak files can still be listed, but reading requires the key
repak unpack Game.pak          # Unpack into the current directory; for an encrypted pak:
repak --aes-key 0x<64-hex-digits> unpack Game.pak
repak get Game.pak Content/Scripts/main.lua > main.lua   # Extract one file
```

IoStore (`.utoc/.ucas`) is not repak's business: open it directly with FModel (see §1.3), or convert first with ZenTools-class tools.

### 1.2 Locating the AES Key

When the pak is encrypted, the key (0x + 64 hex) is burned into the so; two routes:

- **Static**: open `libUE4.so` in IDA and search for the function `FAES::DecryptData` (present directly when symbols are not stripped); the 32-byte buffer passed at the cross-reference site is the key;
- **Dynamic**: after the pak mounts, frida scans the heap near the so for 32-byte high-entropy blocks (the classic approach: hook the pak-mount function and dump the key structure in onLeave; or scan everything for the `?b?b?b` high-entropy pattern and eyeball the hits).
- When unsure, confirm the encryption flag with `repak info` before spending effort.

### 1.3 Viewing Assets: FModel / umodel

- **FModel** (GUI): point it at the game directory and AES key to browse/export textures, models, blueprints, and configs; native utoc/ucas support;
- **umodel** (UE Viewer, GUI): exports mesh/texture/animation and can also dump blueprints to text (pick UnrealScript/Blueprint mode) — **the fastest way to read designer configs, stat tables, and hidden items**.

### 1.4 Blueprints and UAsset

- Blueprints = visual scripts compiled into bytecode inside `*.uasset`; textualization relies on umodel/FModel blueprint views, and complex logic still has to be reversed in libUE4.so (§2);
- The bulk of stats/configs is usually DataTables (`*.uasset`/`.json`/`.csv` mixed into Content), directly readable after unpacking — **for UE games, flip through the assets before gnawing on the so; you often never need to reverse the so at all**.

## 2. The Hard Part of UE Reversing: the Reflection System and GNames/GObjects Dump

### 2.1 Why the UE so Is Hard to Chew

libUE4.so is tens of MB with all symbols stripped; but UE's C++ object system runs on **reflection** — the names, field offsets, and function pointers of every `UClass`/`UFunction` live at runtime in two tables: `GNames` (FNamePool, 4.23+) and `GObjects` (FUObjectArray). **Dumping these two tables = restoring the entire SDK**.

### 2.2 Locating GNames/GObjects (Android in Practice)

```js
// ue_scan.js: conceptual skeleton; signatures vary with the UE version, so locate statically before dynamic confirmation
const m = Process.findModuleByName("libUE4.so");
// 1. GNames: the first entry in FNamePool's first block is "None"; scan the data segment for the pool structure referencing that string
Memory.scan(m.base, m.size, "4e 6f 6e 65 00", {   // "None\0"
    onMatch(addr) { console.log("None entry @", addr.sub(m.base)); }
});
// 2. GObjects: FUObjectArray.Objects is an array referencing chunks
// Tracing IDA cross-references from GetNameByIndex/FName::ToString is a more reliable route to the pool base
```

Static route: in IDA search for leftover symbols like `?FName::ToString@`/`FNamePool` or the string `"/Script/CoreUObject"` (the first path FName) as anchors, then xref backwards to derive the two table bases.

### 2.3 The UEDumper Approach (producing SDK headers)

The desktop UEDumper flow ports as-is to Android: **inject → find the GNames/GObjects bases → walk every UClass in the FUObjectArray → emit C++ headers along the SuperClass chain (class names / field offsets / function addresses)**. On Android this lands as a frida-based walker:

```js
// Skeleton after locating GObjects
for (let i = 0; i < objCount; i++) {
    const obj = readObjPtr(GObjects, i);       // Read the chunked pointer array using this version's layout
    const cls = obj.vtable_class;              // UClass
    emitHeader(cls.name, cls.super, cls.fields /* FProperty chain, including offsets */);
}
```

Once `SDK/*.h` is produced: bulk-import into IDA structs and member access of any UObject subclass in the so becomes fully readable; game-logic function addresses come from UFunction, hooked directly with frida.

### 2.4 UE Games with lua Hot Updates

In UE + xLua/UnLua/slua mobile games the business logic is all in lua (see the corpus piece 「Unity il2cpp lua 手游」 for the same idea): unpack the pak (§1) → the lua layer usually adds another luajit/encryption layer → switch to the §4 Cocos lua workflow, **an identical toolchain**; only when protocol encryption alone remains at the UE engine layer do you come back to the §2.3 SDK locating.

## 3. Cocos2d-x JS (jsb): jsc Decryption

### 3.1 Form and Encryption Principle

- `*.jsc` = JS code encrypted with **XXTEA** (the key set at cocos build time via `setXXTEAKey` is burned into the so); the file is a sign header (default `XXTEA`, 5 plaintext bytes) + ciphertext; after decryption most of it is **plaintext JS** (a minority wraps SpiderMonkey bytecode on top — header check in §3.4);
- There are also plaintext `game.json`/`project.json` configs worth reading first; they often leak the directory structure and hot-update URLs.

### 3.2 Three Routes to the Key

```bash
# Route 1, fastest: inspect strings; a readable 8-32-byte key is often in libcocos2djs.so rodata
strings -n 6 ext/lib/arm64-v8a/libcocos2djs.so | grep -E "^[0-9a-zA-Z_-]{8,32}$" > cand.txt
# Try candidate keys manually or with the script in Section 3.3

# Route 2, precise: use direct key cross-references if symbols remain in the shared object
nm -D ext/lib/arm64-v8a/libcocos2djs.so | grep -i xxtea
# If xxtea_decrypt is exported, follow IDA cross-references and read the global key

# Route 3: observe the key at runtime through a hook
```

```js
Interceptor.attach(Module.findExportByName("libcocos2djs.so", "xxtea_decrypt"), {
    onEnter(a) { console.log("key:", a[2].readCString? a[2].readUtf8String(), "keylen:", a[3].toInt32()); }
});
```

### 3.3 Decryption Commands (once you have the key)

```bash
UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python xxtea-py
python - <<'EOF'
import xxtea, pathlib
KEY, SIGN = b"THEKEY_YOU_FOUND", b"XXTEA"      # Adapt both values to the actual sample
for p in pathlib.Path("ext/assets").rglob("*.jsc"):
    d = p.read_bytes()
    if not d.startswith(SIGN): continue
    out = xxtea.decrypt(d[len(SIGN):], KEY)
    if out: p.with_suffix(".js").write_bytes(out); print("ok", p)
EOF
```

### 3.4 Telling What It Is When the Output Is Not Plaintext JS

`xxd out.js | head -1`: seeing `78 56 78 56`? or a SpiderMonkey bytecode magic (`53 50 41 4D`? defer to the actual engine version) → genuine old-jsb bytecode: the fallback is "hook the JS engine's pre-execution point at runtime to grab the source" (after spawn, hook `JSScript`/`EvaluateString`-class entry points and dump the plaintext); Cocos Creator 3.x js runs on V8, so this form is basically never seen.

## 4. Cocos2d-x Lua: LuaJIT Bytecode

### 4.1 Identification

```bash
xxd ext/assets/src/main.lua | head -2
# 1b 4c 4a xx identifies LuaJIT bytecode (escape 0x1b followed by LJ); read ordinary plaintext Lua directly
```

The outer layer is often another xxtea shell (find the key as in §3.2, with the so swapped to `libcocos2dlua.so`/`libgame.so`); only after peeling it do you see `1b 4c 4a`.

### 4.2 The Standard Chain: Decrypt → Bytecode → Decompile

```bash
# 1. Disassemble with a matching-version LuaJIT host; build the official repository with make
luajit -bl main.lua > main.bl            # -bl lists bytecode; inspect opcodes manually when necessary
# 2. Decompile to Lua source with luajit-decompiler v2 or ljd, choosing by bytecode version
# Input is .lua bytecode, output is .lua source; complex control flow may require manual -bl inspection
```

The two big causes of decompilation failure: the opcode table has been altered (§4.3), or the bytecode is a header-less memory dump (patch the `1b 4c 4a` header + flags byte back on).

### 4.3 Altered-Opcode Variant (modified luajit)

When the game vendor rebuilds luajit they shuffle the bytecode numbering in `lj_bcdef.h` — every public decompiler outputs garbage right away. Restoration approach (the 「Cocos2d-x与LuaJIT汇编的初步解密」 corpus series):

1. Build the same luajit version yourself and write a reference lua snippet that **exercises every opcode signature** (loops / closures / string concatenation / compare-and-branch …);
2. If the game can be made to compile it (hot-update upload / console), dump the bytecode the target engine produces; with no entry point, infer from function bodies the game already ships;
3. Compare the two bytecode versions instruction by instruction and build a "standard opcode ↔ modified opcode" mapping table;
4. Patch the decompiler's opcode table (or write a converter that rewrites modified bytecode back to standard numbering), then proceed with §4.2.
5. Lazy route: skip source restoration; frida-hook the lua VM's execution entry / luaL_loadbuffer directly and grab the decrypted buffer at runtime + follow the VM interpret loop.

## 5. Cocos Creator Encrypted Assets

- Creator image/atlas encryption often uses made-up extensions like `.cpb`: xxtea (the same key) or XOR; locate the key as in §3.2, only with the decryption function changed from `xxtea_decrypt` to the so's asset-loading function (`Image::initWithString` class);
- Discriminator: compare the ciphertext headers of two known PNGs — a constant first N bytes = fixed XOR / stream-cipher header; full entropy = xxtea;
- Config-class files (`config.json`/`*.csv`) are mostly unencrypted — read them first.

## 6. Troubleshooting Quick Table

| Symptom | Most likely cause | Action |
|---|---|---|
| repak unpack reports wrong key | wrong AES key / version mismatch | verify the encryption flag with `repak info`; the §1.2 dynamic route |
| utoc/ucas will not open | IoStore is not repak's business | FModel/ZenTools |
| jsc decrypts to all-empty | wrong key (xxtea failure returns empty) | §3.2 route 3 is guaranteed |
| luajit decompile is all garbage | opcodes altered | §4.3 mapping table |
| UE cannot find GNames | version difference (pre-4.22 uses TNameEntryArray) | swap the structure per engine version; §2.2 static anchors |
| lua/js fully decrypted but no protocol logic | the logic lives in the engine layer | UE: back to §2.3 SDK; Cocos: back to the so layer `../02-frida/native-hook-cheatsheet.md` |

## 7. Corpus Search Terms (data/ essence index)

「Cocos2d-x与LuaJIT汇编的初步解密」「cocos2dx lua 反编译」「cocos2d游戏的lua脚本解密」「新手向unity+xlua解密lua脚本」「Cocos for Lua 伪网游的破解」「cocos2d游戏图片资源解密」「unreal engine逆向学习之反射设计/FName/dump工具使用(一二三)」「某修仙肉鸽游戏协议逆向分析折腾记录」.
