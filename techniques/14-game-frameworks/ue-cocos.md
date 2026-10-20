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
cargo install repak            # 或直接下 release 二进制;brew 系机器 cargo 装
repak info Game.pak            # 看版本/是否加密/挂载点
repak list Game.pak | head -50 # 列内容(加密 pak 也能列,读文件才要 key)
repak unpack Game.pak          # 解到当前目录;加密 pak:
repak --aes-key 0x<64位hex> unpack Game.pak
repak get Game.pak Content/Scripts/main.lua > main.lua   # 抽单个文件
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
// ue_scan.js —— 思路骨架，签名随 UE 版本变，先静态后动态
const m = Process.findModuleByName("libUE4.so");
// 1) GNames: FNamePool 首块第一个条目恒为 "None"；扫 so 数据段找指向 "None" 字符串的池结构
Memory.scan(m.base, m.size, "4e 6f 6e 65 00", {   // "None\0"
    onMatch(addr) { console.log("None entry @", addr.sub(m.base)); }
});
// 2) GObjects: FUObjectArray 的 Objects 指针数组成员恒指向 Chunk;
//    在 IDA 里找 GetNameByIndex/FName::ToString 的 xref 反推池基址更稳
```

Static route: in IDA search for leftover symbols like `?FName::ToString@`/`FNamePool` or the string `"/Script/CoreUObject"` (the first path FName) as anchors, then xref backwards to derive the two table bases.

### 2.3 The UEDumper Approach (producing SDK headers)

The desktop UEDumper flow ports as-is to Android: **inject → find the GNames/GObjects bases → walk every UClass in the FUObjectArray → emit C++ headers along the SuperClass chain (class names / field offsets / function addresses)**. On Android this lands as a frida-based walker:

```js
// 骨架:拿到 GObjects 后
for (let i = 0; i < objCount; i++) {
    const obj = readObjPtr(GObjects, i);       // chunked 指针数组按版本分块
    const cls = obj.vtable_class;              // UClass
    emitHeader(cls.name, cls.super, cls.fields /* FProperty 链,含偏移*/);
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
# 路1(最快): 静态 strings 猜——key 是可读短串(8-32 字节),常在 libcocos2djs.so 的 rodata
strings -n 6 ext/lib/arm64-v8a/libcocos2djs.so | grep -E "^[0-9a-zA-Z_-]{8,32}$" > cand.txt
# 人肉/脚本逐个试解(§3.3 脚本化)

# 路2(准): so 没裁符号时直接定位 key 交叉引用
nm -D ext/lib/arm64-v8a/libcocos2djs.so | grep -i xxtea
# 有 xxtea_decrypt 导出 → IDA 看 xref,取 key 全局变量

# 路3(必中): 运行时 hook
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
KEY, SIGN = b"THEKEY_YOU_FOUND", b"XXTEA"      # 按实际改
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
# 1b 4c 4a xx = LuaJIT 字节码(\x1bLJ);  普通明文 lua 直接读
```

The outer layer is often another xxtea shell (find the key as in §3.2, with the so swapped to `libcocos2dlua.so`/`libgame.so`); only after peeling it do you see `1b 4c 4a`.

### 4.2 The Standard Chain: Decrypt → Bytecode → Decompile

```bash
# 1) 反汇编(需要同版本 luajit 宿主;luajit 官方仓库 make 即可)
luajit -bl main.lua > main.bl            # -bl = bytecode list,能读 opcode 就能人肉跟
# 2) 反编译到 lua 源码:luajit-decompiler v2 / ljd 之类,按字节码版本选
#    输入 .lua(字节码)出 .lua(源码);控制流还原不完美,复杂函数回 -bl 人肉读
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
