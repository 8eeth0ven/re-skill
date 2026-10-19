# Unity and IL2CPP Mobile-Game Reverse Engineering: Full Workflow

> Positioning: **a command-flow tutorial** — given a Unity mobile-game APK, from determining the engine form to dumping symbols to hands-on frida, every step comes with copy-paste commands.
> Division of labor: this piece covers the full Unity workflow; cross-engine detection / ban boundaries are in framework-detection-counter.md; the capture layer goes through `../04-evasion/capture-all-scenarios.md`; the PC side (Windows standalone GameAssembly.dll) shares the same concepts, see `../../platforms/01-windows/languages.md` §3; the tool-row index is in `../05-toolbox/tool-master-table.md` (the four rows Il2CppDumper / Zygisk-Il2CppDumper / frida-il2cpp-bridge / ReShift).

## 0. First Minute: Determine Whether the APK Is Unity, and Which Form

```bash
unzip -l app.apk | grep -i -E "libil2cpp|global-metadata|libmono|libunity|Assembly-CSharp|libarmo"
```

| What you see | Form | Go to |
|---|---|---|
| `lib/arm64-v8a/libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat` | **IL2CPP main form** | §1 full workflow |
| `lib/*/libmono.so` + `assets/bin/Data/Managed/Assembly-CSharp.dll` | **Legacy Mono form** | §2 straight to dnSpy |
| libil2cpp.so present but the global-metadata header is wrong (§3.1 header check fails) | **Encrypted/hardened metadata** | §3 variant handling |
| Only libunity.so, none of the above | Unity but the script layer hides elsewhere (embedded mini-engine / hot-update framework) | Unpack assets first and check the hot-update directory (§4.3) |

Extract the material (this directory is used uniformly below):

```bash
mkdir -p u3d && cd u3d
unzip -o ../app.apk "lib/arm64-v8a/*" "assets/bin/Data/Managed/*" -d ext
ls ext/lib/arm64-v8a/ | head    # 确认 libil2cpp.so / libunity.so
ls -la ext/assets/bin/Data/Managed/Metadata/   # 确认 global-metadata.dat
```

Note: 32-bit packages (`lib/armeabi-v7a/`) follow exactly the same workflow — just pick the arm architecture in IDA; for split APKs use `adb shell pm path <pkg>` to pull all splits before unpacking.

## 1. IL2CPP Main Workflow: the Full Il2CppDumper Chain

### 1.1 The Principle in One Sentence

IL2CPP compiles C# into the native `libil2cpp.so`, but class names / method names / string literals / field offsets all stay in `global-metadata.dat` — the dumper parses this pair, restoring the "big symbol-less so" back to "C#-semantics readable".

### 1.2 Run the Dumper

```bash
# 任何平台: 装 .NET runtime 后
git clone https://github.com/Perfare/Il2CppDumper && cd Il2CppDumper
dotnet Il2CppDumper.dll \
  ../u3d/ext/lib/arm64-v8a/libil2cpp.so \
  ../u3d/ext/assets/bin/Data/Managed/Metadata/global-metadata.dat \
  ../u3d/dump_out
# Windows 下即 Il2CppDumper.exe <so> <metadata> <outdir>
```

Answer arm64 when it interactively asks for the architecture; if automatic metadata-version detection fails, check the version manually per §3.1.

### 1.3 Output Inventory and Uses

| File | Use |
|---|---|
| `dump.cs` | All classes/methods/fields + a `// RVA: 0x… VA: 0x…` header comment per method — **the main search battleground** |
| `script.py` | IDA symbol-apply script (§1.4) |
| `ghidra.py` | The Ghidra equivalent script |
| `il2cpp.h` | Structure header; use together with structs in IDA |
| `stringliteral.json` | All string literals with reference sites; search business copy / error strings to locate functions |
| `script.json` | Machine-readable symbol table (for your own tools to consume) |

### 1.4 Applying the Script in IDA (address-correction essentials)

```
1. Open libil2cpp.so in IDA (File → Open, load as ELF, wait for auto-analysis to finish or Stop it first)
2. Zero the base: Edit → Segments → Rebase program… → enter 0
   (the dumper's RVAs assume so base 0; newer script.py self-checks and prompts, old versions must be done by hand)
3. File → Script file… → pick dump_out/script.py, wait for the output pane to print completion
4. From then on RVA/VA in dump.cs jump directly with G; function names = full C# names, annotate with ;
```

Ghidra works the same way: CodeBrowser → Script Manager → Run `ghidra.py`; no manual rebase needed (Ghidra loads ELF at base 0 by default).

On the frida side, no script injection is needed — use RVAs directly:

```js
const base = Module.findBaseAddress("libil2cpp.so");
const TakeDamage = base.add(0x123456);   // dump.cs 里抄 RVA
Interceptor.attach(TakeDamage, { onEnter(a) { console.log("hit", a[0], a[1]); } });
```

### 1.5 The frida-il2cpp-bridge (hands-on C# method hooking)

Steadier than bare offsets (immune to hardening/reordering); hook directly by C# name:

```bash
mkdir ui3d && cd ui3d && npm init -y && npm i frida-il2cpp-bridge
```

`hook.js`:

```js
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;

    // 枚举找类: 名字不确定时先 dump 类清单
    // for (const c of img.classes) console.log(c.name);

    const cls = img.class("PlayerController");
    const m = cls.method("TakeDamage");
    m.implementation = function (dmg) {
        const hp = this.field("currentHp").value;   // 读字段
        console.log(`TakeDamage(${dmg}) hp=${hp}`);
        return m.invoke(this, 0);                   // 原逻辑照跑但伤害改 0(免伤)
    };
});
```

```bash
frida -U -f com.target.game -l hook.js --no-pause
```

Bridge API quick notes: `Il2Cpp.domain.assemblies` lists assemblies; `cls.field(name).value` reads/writes instance fields; `Il2Cpp.gc()`; `cls.method(name).overload("System.Int32")` picks an overload; `Il2Cpp.applicationVersion`. For a PC-free on-device option see the ReShift row in the tool master table (Zygisk + IL2CPP SQLite inspector).

## 2. Mono Form: Straight to dnSpy

```bash
ls ext/assets/bin/Data/Managed/ | head
# Assembly-CSharp.dll / Assembly-CSharp-firstpass.dll / UnityEngine.*.dll
```

Drag `Assembly-CSharp*.dll` into dnSpy/ILSpy and read the C# source directly — **the mono form has no IL2CPP dump step**; it is IL to begin with.

**Encrypted-dll variant** (common hardening: ciphertext on disk, decrypted in memory before mono loads it):

1. Signature: dnSpy fails to open / all sections are garbage; the file header is not `MZ` + `BSJB`;
2. Solution (memory-dump method): run it, then fish the decrypted image out of memory —
   - frida memory-scans for the `MZ` header + `BSJB` at offset 0x?? (the .NET metadata signature), dumps the whole segment back to a dll, then repairs the header;
   - or hook `mono_image_open_from_data_with_name` in `libmono.so` and dump the buffer to disk in onEnter;
3. When the repair is incomplete, follow the header-repair procedures in the corpus pieces 「手游之u3d之dll文件加密之手动修复」「U3D逆向-Mono另类解密」 (findable via the data/ essence index).

## 3. Encrypted global-metadata Variants (Hardened Games)

### 3.1 Header Check: First See Whether It Is Encrypted

```bash
xxd -l 16 ext/assets/bin/Data/Managed/Metadata/global-metadata.dat
# 明文头: af bb b1 fa <版本u32 LE> ...   magic = 0xFAB11BAF
```

| Symptom | Conclusion |
|---|---|
| First four bytes `af bb b1 fa` | Plaintext metadata; Il2CppDumper eats it directly |
| Magic wrong but the rest looks structured | **Only the header / first N bytes encrypted** (the most common cheap hardening) |
| Whole file high-entropy, structureless | Whole-file encryption / a custom format |
| The file is not in assets at all | Delivered at runtime from the network / encrypted resources |

Rough mapping of the version number (offset 4, little-endian u32): 27≈Unity 2019-2021, 29≈2022, 31≈Unity 6. At dump time the tool picks structure offsets by version; if it reports a version error, check here first.

### 3.2 Static Restoration of Header-Only Encryption

Header-only encryption: most keep the file length and merely XOR/overwrite the first 0x?? bytes. Take a known plaintext header (`af bb b1 fa` + version), XOR it byte-by-byte with the ciphertext header, and see whether a repeating key emerges:

```python
hdr = open("global-metadata.dat","rb").read(0x40)
plain = bytes.fromhex("afbb1bfa") + (29).to_bytes(4,"little")
xor = bytes(a ^ b for a, b in zip(hdr, plain[:8]))
print(xor.hex())   # 单字节循环 = 直接整段还原;无规律 = 换运行时 dump
```

### 3.3 Runtime Dump (heavy encryption; timing is everything)

Core insight: **the game itself must decrypt the plaintext metadata to run** — place the dump point at "decryption finished, before use":

- **First choice Zygisk-Il2CppDumper** (has a row in the tool master table): with root+Zygisk, install the module and the game dumps as it comes up; artifacts land automatically in `/storage/emulated/0/Android/data/<包名>/files/` (dump.cs + script.py + plaintext metadata); continue with §1.4/§1.5;
- **Manual frida scanning** (no Zygisk): once the game reaches the main screen, scan for the `af bb b1 fa` + valid-version combination:

```js
// scan_meta.js —— 找到疑似明文 metadata 并按长度 dump
const found = [];
for (const r of Process.enumerateRanges("rw-")) {
    Memory.scanSync(r.base, r.size, "af bb b1 fa 1d 00 00 00").forEach(m => {   // 1d=29, 按实际版本改
        try { found.push([m.address, r.size]); } catch (e) {}
    });
}
found.forEach(([addr]) => {
    const len = addr.add(0x10).readU32? 0 : 0;   // sanitizedLength/s fileSize 字段按版本结构读
    console.log("candidate @", addr);
});
```

After candidates turn up, cross-validate length plausibility with that version's `Il2CppGlobalMetadataHeader` `sanitizedMetadataSize`/`stringLiteralOffset`, dump the whole segment to disk, then go back to §1.2 and re-dump.

### 3.4 Variant: libil2cpp Exports Stripped (Il2CppApi Obfuscation)

Signature: the so has no exports like `il2cpp_domain_get`, and frida-il2cpp-bridge reports initialization failure. Idea: the bridge's initialization depends on the export table; when it is stripped, locate the il2cpp domain object from the internal call chains of `JNI_OnLoad`/`il2cpp_init` instead. The corpus piece 「解决Il2Cppapi混淆，通杀DumpUnityCs文件」 gives a universal dump approach that does not depend on the export table (findable via the data/ essence index). The static route falls back to the §1.4 pure-RVA analysis.

## 4. Three Opening Shots in Practice (what to hit first once set up)

### 4.1 First Shot: Hook a Game Function to Verify Control

Use the §1.5 bridge script to produce a visible effect (zero damage / more coins / invincible jumps) and confirm the hook works — this is the foundation of everything after. If confrontation fails (crash), open `../12-bypass/bypass-playbook.md` first to determine the detection layer.

### 4.2 Second Shot: Change Values (memory scanning, in brief)

- Emulator route: rooted Android emulators such as LDPlayer/MuMu; in PC-side Cheat Engine pick the emulator's VM process directly from the process list (Ld9BoxHeadless/MuMuVmSeries etc.), scan memory values → rewrite/freeze;
- Rooted real-device route: GameGuardian or CE's ceserver;
- Precise route (no value scanning): the §1.5 bridge does `field.value = 999999` directly, with the field name copied from dump.cs — steadier than CE and immune to pointer offsets.

### 4.3 Third Shot: Protocol Location (get plaintext at the il2cpp layer)

After capture yields ciphertext (workflow in `../04-evasion/capture-all-scenarios.md` §2.9), return to the dump layer to find the encryption point:

1. Search `dump.cs` / `stringliteral.json` for keywords like `encrypt|sign|send|Packet|ProtoBuf|msgId` to narrow down classes;
2. Bridge-hook the narrowed serialization/encryption functions and print the arguments in onEnter — for most games this layer is already plaintext;
3. Once you have the "plaintext→ciphertext" function pair, go offline/replay via the three-stage rocket in `../10-algo-restore/protocol-offline-rpc.md`.

## 5. Detection Surfaces (il2cpp-specific + general)

| Detection | Means | Countermeasure entry |
|---|---|---|
| metadata/so integrity hash | hashes `global-metadata.dat` / the `.text` section at startup and reconciles | Do not touch the file — modify in memory only; principle in framework-detection-counter.md §1 |
| dump detection | reads maps for frida / checks `/proc` status | `../04-evasion/frida-anti-detection.md` |
| mono-injection detection | scans IL-injection signatures (the legacy mono-cheat arms race) | same as above |
| in-game risk control (behavior / input stream) | server-side behavior analysis | framework-detection-counter.md §3 |

## 6. Troubleshooting Quick Table

| Symptom | Most likely cause | Action |
|---|---|---|
| Il2CppDumper reports ERROR: Magic | metadata encrypted | §3 in full |
| Dump succeeds but IDA jumps land wrong | base not zeroed / so and metadata versions mismatched | §1.4 step 2; re-download the correct split apk |
| bridge reports Il2Cpp not found | exports stripped / packer shell | §3.4; unpack first via `../03-unpacking/` |
| Hooked but no response | the function is never called (implemented in the hot-update/lua layer) | see §4.3 — the logic may live in the script layer, not C# |
| Changing the field has no effect | the value is server-verified / periodically refreshed | patch at the setter-function layer; for online games see the ban boundaries in framework-detection-counter.md §5 |

## 7. Corpus Search Terms (data/ essence index)

「安卓U3D逆向从Assembly-CSharp到il2cpp」「记录一款Unity il2cpp lua手游的逆向全过程」「记录一款Unity il2cpp 手游封包的逆向」「解决Il2Cppapi混淆」「Unity加固的探索与实现」「Unity Mono 安卓游戏逆向 Frida Hook」「某单机斗地主手机游戏的分析」「旅行的青蛙Unity游戏逆向修改」.
