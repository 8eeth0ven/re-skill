# Android File Formats in Depth — dex / elf(so) / oat / vdex / cdex / arsc / AXML

> Corresponding tree node: the whole "file formats" [1001533] subtree (DEX/ODEX [1001305]/OAT [1001307]/ELF and so [1001341]/AXML [1001303]/ARSC [1001304]/apk files [1001539]/class bytecode [1001301]/library files [1001536])
> The techniques library (same skill, re/techniques) only touches "so repair dump" and "dex dump repair" in passing; this file is the **byte-level format foundation** — the common substrate for unpacking repair / repackaging / parser development.

## 0. What is an APK (zip container)

```
app.apk (ZIP)
├── AndroidManifest.xml      ← 二进制 AXML(§6)
├── classes.dex [classes2.dex ...]   ← 代码(§1/§2)
├── res/                     ← 编译后资源(二进制 AXML + arsc 索引,§7)
├── resources.arsc           ← 资源表(§7)
├── assets/                  ← 原样打包文件(壳的第二 dex / so / 配置常藏此)
├── lib/<abi>/libxxx.so      ← native 库(§3 ELF)
├── META-INF/                ← MANIFEST.MF / *.SF / *.RSA(DSA/EC) 签名文件
└── (V2+ 签名块:ZIP 中央目录前的 APK Signing Block,	key-value:0x7109871a=V2)
```

- ZIP details: entries may be STORED (uncompressed; dex can be page-aligned at API27+ via `zipalign -p 4` for direct loading) or DEFLATED; **ZIP repackaging pitfalls**: central-directory offset recomputation, and packers that hide payload in the comment field (some whole-file packers put the original dex in the zip comment).
- Signature evolution: V1 = JAR per-entry SHA1 + PKCS7; V2 = APK Signing Block over the whole zip (segments 1-3); V3 = proof of key rotation; V4 = fs-verity. Inspect with `apksigner verify --verbose`; **the existence of V2 means repackaging must re-sign the whole block** (zipalign runs before the signing block; order: zip data → signing block → central directory).

## 1. The DEX format (core of tree DEX/ODEX [1001305])

### 1.1 header (112 bytes, field by field by offset)

| Offset | Length | Field | Description |
|---|---|---|---|
| 0x00 | 8 | magic | `dex\n035\0` (035 = format version, progressing 037/038/039: min-api/hidden-api/dynamic-debug bits); **cdex is `cdex001`** |
| 0x08 | 4 | checksum | **Adler-32**, covers everything from offset 12 on |
| 0x0C | 20 | signature | **SHA-1**, covers everything from offset 32 on |
| 0x20 | 4 | file_size | size of the whole dex |
| 0x24 | 4 | header_size | 0x70 |
| 0x28 | 4 | endian_tag | 0x12345678 |
| 0x2C/0x30 | 4+4 | link_size / link_off | link section (for dynamic linking, usually 0) |
| 0x34 | 4 | map_off | map_list offset |
| 0x38.. | — | string_ids_size/off | seven subsequent size+offset pairs: strings→types→protos→fields→methods→class_defs→data |

**Repair iron rule** (mandatory after a dump-based unpack; verified in the techniques library): any byte change → recompute `signature=SHA-1(dex[32..])` → then recompute `checksum=Adler-32(dex[12..])`, otherwise jadx/baksmali reject the file.

### 1.2 map_list

The header's tail map_off points here; an array of `map_item{uint16 type;uint16 unused;uint32 size;uint32 offset}` + a trailing 0. The type constants are the complete list of dex sections (0x0001 header/0x0002 string_id/0x0003 type_id/0x0005 proto_id/0x0006 field_id/0x0007 method_id/0x0008 class_def/0x1002 string_data/0x2000 map_list/0x2001 type_list/0x2002 annotation_set/0x2003 class_data/0x2004 code/0x2005 static values…/0x2006 debug_info). **Write dex parsers against the map, not by linearly walking the header** — packers tamper with header table entries while the map stays self-consistent.

### 1.3 The five index tables (two-level id → data)

- **string_id_item**: `uint32 string_data_off` → MUTF-8 encoded (`uleb128 utf16_size + bytes + \0`); MUTF-8 = a UTF-8 variant (\0 encoded as 0xC0 0x80, supplementary characters via surrogate pairs). The string pool is sorted (by MUTF8 code point) and indexed by string_id.
- **type_id_item**: `uint32 descriptor_idx` (points into strings) → class descriptors `Ljava/lang/String;`, `[I`.
- **proto_id_item**: `shorty_idx + return_type_idx + parameters_off(type_list)` — the method prototype (without class or name).
- **field_id_item**: `class_idx(u16) + type_idx(u16) + name_idx(u32)`.
- **method_id_item**: `class_idx + proto_idx + name_idx`. **method_id is the usual anchor for hooking/obfuscation** (frida `Java.use` goes through here).

### 1.4 class_def and class_data_item

- **class_def_item** (32 bytes): `class_idx / access_flags / superclass_idx / interfaces_off(type_list) / source_file_idx / annotations_off / class_data_off / static_values_off`.
- **class_data_item** (all uleb128 variable-length, unaligned): `static_fields_size/instance_fields_size/direct_methods_size/virtual_methods_size` + four groups of **encoded_field/encoded_method** — **field_idx_diff / method_idx_diff are differentially encoded** (deltas relative to the previous one); parsers must accumulate.
- **encoded_method**: `method_idx_diff + access_flags + code_off` → points to the code_item.

### 1.5 code_item (method body)

```
code_item {
  u16 registers_size;   // 本方法 v 寄存器总数
  u16 ins_size;         // 传入参数占的寄存器(含 this)
  u16 outs_size;        // 调用别人时要借的寄存器
  u16 tries_size;
  uleb128 debug_info_off;  // 常为 0(壳抹掉)
  uleb128 insns_size;      // 16-bit 代码单元数
  u16 insns[insns_size];   // 指令流(switch 表按 4 字节对齐,nop 填充)
  [padding]
  try_item tries[tries_size];   // {start_addr(u4) insn_count(u2) handler_off(u2)}
  encoded_catch_handler_list handlers;
}
```
(based on the AOSP `libdexfile/DexFile.proto` structure)

- **Where extraction packers land**: insns all NOP/emptied + access_flags gets native — "method empty but registered" is exactly the extraction-packer signature (restoration approaches are cross-linked to the active-invocation family in the techniques library `../../techniques/03-unpacking/dex-unpacking.md`).
- **debug_info wiped**: packers often strip line numbers, `jadx` shows `/* compiled code */`.

### 1.6 ODEX (the old Dalvik optimized format)

The 4.4-era `dexopt` output: ODEX header + dependency list + optimized dex (quickened instructions); replaced from 5.0+ by ART's oat/vdex, now archaeology only. The tree merges DEX/ODEX into one node; today only dex and the dex inside vdex (§5) matter.

### 1.7 Parsing and modification tools (tree DEX parsing tools [1001670]/DEX modification [1001599])

- **baksmali/smali** (tree Smali/Baksmali [1001598]): the de-facto standard for dex↔smali round trips; `baksmali d x.dex`/`smali b out/ -o x.dex` (3.x maintained by the baksmali org (originally google/smali), published to Google Maven as `com.android.tools.smali:smali-baksmali` up to 3.0.10+; Android 13-era odex/vdex covered by OatHeader key-value parsing and other repairs; Android 10+ odex often lacks the dex body, extract the vdex first with vdexExtractor).
- **dexlib2** (baksmali's library) is the substrate for programmatic dex editing; **redex** (Facebook) does dex-level optimization/reordering.
- 010 Editor has a dex template; Androguard (py3) for scripted parsing (axml/dex dual-purpose).
- Representative posts: "DexFile format analysis" (boyliang, 2014-09), "Analyzing a simple .dex file", "Dex analysis demo", "Data construction when loading DEX files in memory (part C)", "The Android DEX security arms race", "DexGuard analysis & cracking TitaniumBackup"; for the "hand-written dex parser" direction see also the IDC script family "IDC scripts: parsing elf, vdex, cdex formats" (X.D, 2021).

## 2. class bytecode (tree class bytecode [1001301])

- JVM stack-based: the .class structure (magic 0xCAFEBABE/constant pool/access/fields/methods/attributes); mapping to dex: constant pool → string pool, method → method_id+code, attribute Code → code_item.
- The subtree contains the AOP tool family: **Javassist [1001575]** (source-level bytecode editing, runtime `CtClass`) / **ASM [1001576]** (visitor pattern, lowest level and fastest, the mainstream for class-stage injection before dex editing on Android) / Javasnoop (archaeology).
- RE perspective: seeing ASM/Javassist embedded in an APK = runtime self-generated code (common in risk-control SDKs; use frida `Java.enumerateClassLoaders` to find dynamically defined classes).

## 3. ELF and so (tree ELF and so files [1001341])

### 3.1 ELF basics

- Header: `\x7fELF` + class (1=32/2=64) + data (LSByte) + e_type (ET_DYN, so has no fixed base) + e_machine (EM_ARM=40/EM_AARCH64=183) + Program Headers (`p_type=PT_LOAD` segment mapping).
- **Segments vs sections**: the loading view uses Program Headers (LOAD/_DYNAMIC/GNU_RELRO); the static-analysis view uses Section Headers (`.text/.rodata/.data/.bss/.got/.got.plt/.plt/.init_array/.fini_array/.dynsym/.dynstr/.rela.dyn/.rela.plt`) — **a so can wipe/scramble its Section Header Table (the loader does not depend on it), while IDA still relies on it**; packers often break the section table against static analysis.

### 3.2 The dynamic-linking trio (core of RE)

- **`.dynamic` (pointed to by PT_DYNAMIC)**: an array of d_tag/d_val; key tags: `DT_STRTAB/DT_SYMTAB/DT_STRSZ/DT_SYMENT` (symbol tables), `DT_PLTGOT` (GOT address), `DT_JMPREL/DT_PLTRELSZ` (.rela.plt), `DT_RELA/DT_RELASZ` (.rela.dyn), `DT_INIT_ARRAY/DT_INIT_ARRAYSZ`, `DT_NEEDED` (dependencies), `DT_SONAME`; Android-specific: `DT_ANDROID_REL(A)` (packed relocations).
- **Relocation entries** `Elf64_Rela{r_offset(where to write)/r_info(sym<<32|type)/r_addend}`:
  | Type (arm64) | Meaning | Timing |
|---|---|---|
  | R_AARCH64_RELATIVE (1027) | write base+offset (internal GOT pointers) | early relocation |
  | R_AARCH64_GLOB_DAT (1025) | symbol address → GOT data slot | symbol resolution |
  | R_AARCH64_JUMP_SLOT (1026) | symbol address → PLT jump slot | **lazy binding** (Android's linker mostly uses BIND_NOW in practice; the key point for GOT hooks) |
  | R_AARCH64_ABS64 (257) | symbol+addend written anywhere | embedded pointers |
- **GOT/PLT**: PLT stub `adrp x16, GOT; ldr x17,[x16,off]; br x17`; external calls go `.plt` → look up the `.got` slot. **GOT hook = swap the slot without touching code** — steadier than inline hooks against packer-protected functions; two complete implementations (pure JS parsing the ELF dynamic → finding JUMP_SLOT entries / walking linker soinfo via `plt_rela/symtab/strtab`) are cross-linked to the techniques library `../../techniques/02-frida/advanced/gothook.md`, not duplicated.
- **init_array/fini_array**: arrays of constructors the linker calls in reverse/forward order after relocations — **the self-start point of packers/anti-debug**; the full so-load sequence (dlopen→linker→relocation→init_array) and "grabbing the injection window" are cross-linked to the techniques library `../../techniques/11-syscall-chain/process-memory-chain.md`.

### 3.3 Android linker essentials (tree Linker analysis [1001566])

- `/system/bin/linker64` (the user-mode dynamic loader, not of the glibc ld.so lineage): `dlopen`→`find_library`→the soinfo chain (solist/somain)→`linker_sonames`/`linker_namespace` (classloader namespaces: the app's `classloader-namespace` restricts visible so — **the source of unidbg environment-completion pitfalls**).
- `android_dlopen_ext` (with `android_dlextinfo`: can load by fd/mem_fd; packers use it to load so from memory).
- soinfo structure offsets and traversal (the substrate for dumping hardened so) are cross-linked to the techniques library `../../techniques/03-unpacking/so-repair-dump.md` (494 lines, incl. segment-backfill repair).
- Tools: readelf/objdump, LIEF (py), pyelftools, 010 templates, IDA's ELF processor.
- Representative posts: "Notes on the SO file format and linker mechanics (1)(2)", "Android Linker in depth", "android linker read-through 2 — find_library", "Building and replacing the android linker", "Running android_server with a custom linker", "A traceless so_loader based on Bionic/linker modifications", "Foundations of SO packing via the linker"; hands-on init_array breakpointing see "Notes on breaking at JNI_OnLoad and init_array".

## 4. The OAT format (tree OAT file format [1001307])

- ELF container: OAT header (magic `oat\n` + version + checksum + key-value store of dex-file digests) + OAT dex files (per dex: location/class-offset table) + quickened/AOT machine-code sections.
- Symbiosis with vdex: `base.odex` + `base.vdex` in the same directory; **from A10 on, machine code can move into the vdex's quickening info**, and odex grows thinner.
- Extracting dex: the vdex holds the original (see §5); `oatdump --export-dex-to=dir` (an old flag; after A10 oatdump gradually degraded and dex extraction mainly goes the vdexExtractor/dexdump route — newer AOSP removed --export-dex-to, defer to the current `oatdump --help`); the tree's "smali conversion [1001683]" = take the dex out of oat/vdex then run baksmali. For OAT structure see: "Notes on the Android OAT file format", "Parsing OAT files on Android 4.4.2", "oat_file_manager and oat_file_assistant", "The OatFile::Open flow and obtaining OatDexFile".

## 5. VDEX and cdex (verified in the techniques library; structure given here)

- **vdex**: header (magic `vdex` + version, verifier version/feature flags) + dex section (original or compact dex) + quickening info; introduced in A8.0 and evolving per release (019/021/025/027… versions differ a lot; parsers must branch by version). Local reference: "IDC scripts: parsing elf, vdex, cdex formats" (X.D, 2021, incl. IDC parsing implementations for all three formats); the version-to-Android mapping still defers to AOSP `art/runtime/vdex_file.h` per tag.
- **cdex (compact dex)**: the compact form dexlayout rearranges by profile — magic `cdex001`, the header adds `container_size_`, **multiple dex share the data section, and index tables become variable-length (u4→uleb)**; ART runs the compact form directly in memory without restoring it.
- **The cdex→dex repair chain**: convert with vdexExtractor, or after dumping at minimum recompute SHA-1 (signature)/Adler-32 (checksum) — the full pipeline (techniques library `../../techniques/03-unpacking/ebpf-unpacking-deep.md` §5.2) is not duplicated.

## 6. AXML — binary AndroidManifest (tree AXML file format [1001303])

- Principle: at packaging time aapt2 compiles XML into binary: chunking (`ResChunk_header{uint16 type;uint16 headerSize;uint32 size}`) + a **string pool** (globally deduplicated indexed strings) + namespace mapping + attributes referencing resource IDs.
- Top-level structure: STRING_POOL (0x0001) → (optional RESOURCE_MAP 0x0180) → START_NAMESPACE (0x0100) → START_ELEMENT (0x0102, with the attribute array: ns/name/typedValue) → … → END_ELEMENT (0x0103).
- **The typedValue three-state trap**: an attribute value can be a string reference (rawValue into the pool) or a compiled value (Res_value: data+dataType, e.g. `0x12`=int, `0x01`=reference → resource ID); boolean `true` is stored as int 0xffffffff. The most common hand-written-parser bug = missing the dataType branch.
- RE usage: ① check component exports (`exported`/intent-filter), ② the permission surface (`uses-permission`/custom permission protectionLevel), ③ packer signatures (`android:name` pointing at the packer's Application, meta-data hiding keys); ④ **AXML is the alignment target of resource obfuscation (aab/arsc obfuscation)** — resource IDs and the string pool change together.
- Tools: apktool (axml→text), androguard `AXMLPrinter`, jadx auto-restores; pure libraries: **pyaxmlparser** (0.3.31, no androguard dependency) and **androguard/axml** (standalone dependency-free library).

## 7. resources.arsc (tree ARSC file format [1001304]/apk files [1001539])

- Purpose: the global resource index — resource ID (0xPPTTEEEE: package+type+entry) → type/name/config/value.
- Structure: RES_TABLE_TYPE header + global string pool (resource names) + package chunks (RES_TABLE_PACKAGE_TYPE: id/name + type string pool + key string pool) + typeSpec (RES_TABLE_TYPE_SPEC_TYPE, marks variable configs) + type (RES_TABLE_TYPE_TYPE: config such as zh/hdpi, entry → Res_value or offset into a string pool/complex types).
- **High-frequency RE points**: ① where strings live: `public.xml` (apktool restores)/reverse lookup by resource ID (type×entry); ② **resource obfuscation/hardening**: ID shuffling + emptied string pools make apktool/jadx error — the repair idea = rebuild from the reference graph (the ROSAL anchor approach in the techniques library `../../techniques/05-toolbox/static-analysis-tools.md`); ③ after renaming/deleting resources and repackaging, the arsc must be recompiled (aapt2 or apktool built-in).
- Tree res directory [1001541]/assets [1001540]: res = compiled resources indexed into arsc; assets = verbatim, not indexed (the packer's hidden channel).
- Tools: aapt2 dump (`aapt2 dump resources`), apktool, androguard, arsc teardown scripts.

## 8. Library files (tree library files [1001536])

- **jar [1001537]**: a zip container holding .class (desktop JVM); on the Android side = `libs/*.jar` as dex-compile input.
- **aar [1001538]**: an Android library package = classes.jar + res/ + R.txt + AndroidManifest.xml + libs/; unpacking to see an SDK's real classes is step one of third-party-SDK RE (`unzip sdk.aar`).

## 9. Six-format comparison table

| Format | magic | Container | RE focus | Parsing tools |
|---|---|---|---|---|
| dex | `dex\n035` | native | header 8 tables/map/class_data diff encoding/code_item; cdex variant | baksmali/androguard/010 |
| odex | ELF (oat) | ELF | deprecated since A10, archaeology | oatdump |
| oat | ELF `oat\n` | ELF | machine-code sections and dex digests | oatdump |
| vdex | `vdex` | native | **the dex original / compressed original lives here** | vdexExtractor |
| so | `\x7fELF` | ELF | dynamic/GOT-PLT/init_array/section-table destruction | IDA/LIEF/readelf |
| arsc | `0x02 0x00 0x0C 0x00` | chunk | ID→value mapping, resource-obfuscation repair | aapt2/androguard |
| AXML | `0x03 0x00 0x08 0x00` | chunk | string pool/typedValue/component surface | apktool/androguard |

> Note: the arsc/axml type values count the first u16 of the chunk header (RES_TABLE_TYPE=0x0002/RES_XML_TYPE=0x0003); the table shows the raw first-chunk bytes (little-endian), restored per AOSP `ResourceTypes.h`; concrete values evolve with versions, compare against source.

## 10. Representative posts and further reading

- dex vmp restoration (incl. ART bytecode replacement, involving dex structures in practice):
- Techniques library (same skill, re/techniques) cross-links (absolute paths):
  - dex dump and repair (cdex/signature checksums): `~/.zcode/skills/re/techniques/03-unpacking/ebpf-unpacking-deep.md` §5
  - so dump repair (soinfo/segment backfill): `~/.zcode/skills/re/techniques/03-unpacking/so-repair-dump.md`
  - GOT hook, two implementations (landing §3.2 of this file): `~/.zcode/skills/re/techniques/02-frida/advanced/gothook.md`
  - linker/soinfo load sequence: `~/.zcode/skills/re/techniques/11-syscall-chain/process-memory-chain.md`
  - the five chains of dex load-and-execute: `~/.zcode/skills/re/techniques/11-syscall-chain/dex-load-exec-chain.md`
- Official structure sources: AOSP `libdexfile/dex/dex_file.h` (dex structure and map type constants), `frameworks/base/libs/androidfw/ResourceTypes.h` (arsc/axml), the `bionic linker` (so). Source is authoritative; the numbers in this file should be compared against the current source.
