# DEX Loading and Execution Chains (ART user space -> syscall -> kernel)

> Positioning: expands the complete chain of a DEX from "bytes inside the APK" to "a method being executed" as a timeline, five chains (memory entry / class definition / method execution / JNI registration / OAT-VDEX), each with an observation-point matrix. Division of labor with existing documents: the eBPF piece (`../03-unpacking/ebpf-unpacking-deep.md`) already proved "the x1 shapes of DexFile::DexFile / DexFileLoader::OpenOne" and the repair pipeline; this piece expands the **full-chain timeline** and the execution segment; the frida piece (`../02-frida/frida-api-reference.md` sec.6) already has ArtMethod offset probing; this piece supplies the versioned-layout basis.
> Version basis: AOSP googlesource source compared item by item (tags: android-8.0.0_r1 / 9.0.0_r1 / 10-11.0.0_r1 / 12.0.0_r1 / 13.0.0_r1 / 14.0.0_r1 / 15.0.0_r1 / 16.0.0_r1 / refs/heads/main, plus libcore android-13.0.0_r1). Markers: **[source:tag]** = pinned to a concrete AOSP tag; **[unverified]** = not seen in public source / needs on-device checking; unmarked = generic kernel/ART common knowledge, multi-source consistent.
> Wording convention: observation/extraction, all in an authorized reversing context.

## 0. Overview timeline (build the panorama first)

```text
[Installation] apk install → pm/installd → dex2oat → /data/app/*/oat/<arch>/base.{odex,vdex}(chain 5)
[Loading]      Construct ClassLoader(upper half of chain 1)
                 └→ DexFile.loadDex/constructor → native openDexFileNative → OatFileAssistant checks odex/vdex
                      └→ Neither exists → DexFileLoader/MapRootContainer → MemMap::MapFile → mmap(svc, kernel part of chain 1)
                           └→ DexFile object(begin_/size_)→ ClassLinker::RegisterDexFile → link DexCache
[Class phase]  Class.forName/loadClass → DexFile.loadClass → DefineClass(chain 2)
                 └→ Parse class_def → mirror::Class → ArtMethod array → Link/Verify → clinit
[Execution]    invoke → entry_point_from_quick_compiled_code_(chain 3)
                 ├→ nterp interpreter(A12+) / mterp(A7-A11) / switch fallback
            ├→ JIT/AOT quick code
                 └→ JNI(chain 4: System.loadLibrary→dlopen→JNI_OnLoad→RegisterNatives→entry_point_from_jni_)
```

## Chain 1: the full chain of APK -> DEX entering memory

### 1.1 The Java layer (the BaseDexClassLoader family)

- `DexClassLoader`/`PathClassLoader` are both `BaseDexClassLoader` subclasses; the difference is only constructor arguments (whether optimizedDirectory is usable); the packers' favorite `InMemoryDexClassLoader` is also a `BaseDexClassLoader`.
- At construction, `DexPathList.makePathElements` splits dexPath into `Element[]`; each Element lazily constructs a `dalvik.system.DexFile` internally; the actual open happens on the first class lookup or an explicit `DexFile.loadDex`.
- The `DexFile` constructor finally goes native: `openDexFileNative(String sourceName, String outputName, int flags, ClassLoader, Element[])`, returning a jlong-array cookie (each element a `const DexFile*`). (A8/A9/main, runtime/native/dalvik_system_)
- `InMemoryDexClassLoader` goes through `openInMemoryDexFilesNative(ByteBuffer[] buffers, byte[][] arrays, int[] starts, int[] ends, ClassLoader, Element[])` (A12+ split into the three args arrays/starts/ends; older versions take a single ByteBuffer[]). [source:main]

### 1.2 The evolution of ART-internal symbols (the core table)

| Android | File | Entry symbol family | Notes |
|---|---|---|---|
| 8.x | `runtime/dex_` (top level, no dex/ subdir) | `art::DexFile::Open(const uint8_t* base, size_t size,...)`, `DexFile::OpenFile(int fd,...)`, `DexFile::OpenZip`, `DexFile::OpenCommon` | no DexFileLoader class; static Open constructs DexFile directly |
| 9-11 | libdexfile split: `libdexfile/dex/dex_file_` | `art::DexFileLoader::Open(base,size,...)` / `OpenWithDataSection` / `OpenAll` / `OpenCommon` / `OpenOneDexFileFromZip`; `ArtDexFileLoader` in `runtime/dex/art_dex_file_` | OpenCommon is the final choke point, **a favorite unpacking attach point** |
| 12-13 | same; `ArtDexFileLoader` moved to `libdexfile/dex/` (the android-mainline-12.0 tag's test files prove it) | same symbol family as 9-11; **no `OpenOne`** (full-text search of A12/A13 tags finds only `OpenOneDexFileFromZip`) | nterp becomes the default interpreter (see chain 3) |
| 14 | `libdexfile/dex/dex_file_` | member `DexFileLoader::Open(uint32_t location_checksum, const OatDexFile*, bool verify, bool verify_checksum, string*)` + static `DexFileLoader::Open(const uint8_t* base, size_t size,...)` | the containerization (RootContainer/DexFileContainer) refactor lands |
| 15-16+ | same | member renamed **`DexFileLoader::OpenOne(size_t header_offset, uint32_t location_checksum, const OatDexFile*, bool, bool, string*)**; the static `Open(base,size,...)` remains | **Correction [source:A15/main]**: in AOSP source, OpenOne's first parameter is `size_t header_offset` (member function x0=this, x1=header_offset) - **not the base pointer**; eBPFDexDumper-rs's source comment "OpenOne x1=base, x2=size" contradicts the AOSP source; the symbol's ABI on real-device ROMs is **[unverified]** - before attaching, you must disassemble the current libart in IDA and confirm the parameter shape |
**Stripped/inlined symbols and fallbacks (combined with the eBPF piece's findings)**:
- Android 16/17 strip/inlined the `DexFile::DexFile` constructor -> fall back to `DexFileLoader::OpenOne` (eBPF piece sec.4.1, per the tool's source comments; but note the correction in the table above: the x1 semantics need on-device re-verification);
- On most stripped ROMs, OpenOne sits in dynsym as a mere `st_value=0` placeholder - attach skips it; only a true export attaches;
- Generic fallback techniques: string xrefs (e.g. RegisterNatives' `"This is slow, consider changing your RegisterNatives calls."`, Execute's `"Interpreting "` - proven in the eBPF piece sec.3.3/sec.4.4), ARM64 prologue byte-pattern scanning.

### 1.3 mmap: the precise path from user space into the kernel

File-path dex (classes.dex inside the APK / standalone .dex) all eventually reach:

```text
ArtDexFileLoader(dex_location).Open(...)            [source: main runtime/oat/oat_file_manager.cc]
  └→ DexFileLoader::MapRootContainer()              [source: main libdexfile/dex/dex_file_loader.cc:324]
       └→ fstat(fd) obtains size
       └→ MemMap::MapFile(size, PROT_READ, MAP_PRIVATE, fd, 0, ...)
            └→ bionic mmap(pure syscall wrapper, no user-space processing)
                 └→ svc #0, x8=__NR_mmap(arm64=222; arm32 uses mmap2=192)
                      └→ sys_mmap → ksys_mmap_pgoff → vm_mmap_pgoff → mmap_region
                           ├→ call_mmap(f_op->mmap: ext4/generic_file_mmap, f2fs_file_mmap)→ establish page-cache mapping
                           └→ Actual reads occur **on page faults**: filemap_fault → readahead(kernel details depend on GKI 5.x/6.x)
```
- The key meaning of `MAP_PRIVATE`: copy-on-write. The packer mmaps the encrypted dex in, then mprotect+w decrypts it in memory - the on-disk APK never changes - **a memory dump gets the decrypted state**; this is the kernel-level basis for the observable plaintext window between "after mmap, before constructing the DexFile".
- bionic has no intermediate layer here: mmap goes straight to `__NR_mmap`, no libc buffering (unlike the fread/fopen family), so syscall-layer observation never misses.

### 1.4 The InMemory path difference (why eBPF must hook memcpy)

`DexFile_openInMemoryDexFilesNative` (the main version verified line by line):
1. `AllocateDexMemoryMap(start,end)` -> **anonymous mmap** (no file, no fd);
2. Direct ByteBuffer: `memcpy(anonymous page, direct_buffer+start, length)`; the array variant: `GetByteArrayRegion` copies;
3. Hands the MemMap to `OatFileManager::OpenDexFilesFromOat(std::vector<MemMap>&&, ...)` -> one by one `ArtDexFileLoader(MemMap, location).Open(checksum, verify, verify_checksum, &err)`.
Corollary: when the whole packer goes through InMemoryDexClassLoader, **there is no file mmap to grab anywhere in the process**; the plaintext exists in full only for the instant of the memcpy -> eBPFDexDumper-rs's paired uprobe+uretprobe on libc `memcpy/memmove` (params at entry, return value at exit) is exactly the patch for this window (proven by its source's SEC list, see the eBPF piece sec.5.1).

### 1.5 The DexFile object and RegisterDexFile

- `DexFile::DexFile(const uint8_t* base, size_t size, ...)` [source:main libdexfile/dex/dex_:152]: x0=this, **x1=base, x2=size** (this is where the eBPF piece's "x1=DEX begin" entry comes from); the object's `begin_`/`size_` members are the dump fields. On 64-bit, old tools read `begin_` at +8 and `size_` at +16 (the A9 shape); newer versions reorder fields - **before hooking, disassemble the current libart's DexFile constructor in IDA to confirm [(per-version offset table)]**.
- `ClassLinker::RegisterDexFile(const DexFile&, ObjPtr<ClassLoader>)` [source:main class_:4618, internally RegisterDexFileLocked]: creates/gets the `mirror::DexCache` and CHECKs `dex_cache->GetDexFile == &dex_file` - the DexCache<->DexFile cross-link is the pivot of the classic "chain back from ArtMethod to DexFile" (ArtMethod->declaring_class->dex_cache->DexFile->begin_).
- Packers reflect `DexFile.mCookie` from the Java layer (a long array whose elements are `const DexFile*`) -> read begin_ directly: BlackDex's cookie route and JDex's mCookie dump are both built on this.

### 1.6 verify / cdex / oat branches (all at the same layer during loading)

- Structural validation + verify happens inside Open (when verify=true); A12+ also has background validation `DexFile_verifyInBackgroundNative` [source:main dalvik_system_: around :396];
- The odex/vdex priority path is inside `OatFileManager::OpenDexFilesFromOat` (OatFileAssistant), see chain 5;
- cdex (compact dex) inside vdex is the norm; it keeps the `CompactDexFile` shape in memory (magic `cdex001`); dump repair per chain 5.3.

### 1.7 Chain 1 observation-point matrix + frida/eBPF timing differences

| Stage | Observation point | What you get | Timing | Notes |
|---|---|---|---|---|
| Java layer | hook `DexFile.$init` (the ByteBuffer variant) | the decrypted plaintext buffer | mid | dex-unpacking.md sec.2; the natural fit when the packer goes InMemory |
| ART lifecycle | uprobe `DexFile::DexFile` (x1=base) | the plaintext dex start address | early (pre-parse) | A16/17 stripped -> fall back to OpenOne (ABI) |
| ART choke point | uprobe `DexFileLoader::OpenCommon` (A9-13)/`Open` (A14+) | the base/size arguments | early | symbols differ by version; pick per the 1.2 table |
| ART registration | uprobe `ClassLinker::RegisterDexFile` (x1=DexFile*, dereference again) | begin_/size_ | mid | eBPF piece sec.4.2: pin the symbol suffix to avoid mis-attaching the unique_ptr overload |
| ART mapping | uprobe `DexFileLoader::MapRootContainer` / `MemMap::MapFile` | fd/size/return address | earlier than parse | mandatory for file-path dex |
| libc | uprobe/tracepoint `mmap`, `mprotect` | mapping region + fd; the packer's decrypting mprotect | **earliest** (may be ciphertext/the whole APK) | what mmap catches is not necessarily plaintext: file packers first mmap ciphertext then decrypt in place |
| libc | uprobe `memcpy/memmove` (paired) | the InMemory plaintext window | early | patches the InMemory-packer blind spot (proven by eBPF-rs) |
| kernel | tracepoint `sys_enter_mmap` / `sys_enter_openat` | indiscriminate full IO | earliest but noisy | filter by pid/path |
**Why frida dumps and eBPF dumps catch different moments**:
- The classic frida method hooks `DefineClass` (chain 2): it fires only when a class is **first used** - by then the packer has usually finished processing that dex, so what you catch is a "class-loading-period" snapshot - later but stable;
- eBPF hooks the DexFile ctor/OpenCommon/RegisterDexFile: **dex parse time**, one beat earlier than DefineClass, and independent of any class being loaded;
- eBPF hooking mmap/interpreter entries: the two extremes - mmap precedes decryption (file packers may yield ciphertext), while the nterp entry is later than everything (method-execution period) but naturally carries the ArtMethod context;
- So the same target can yield different dex sets from the two: frida="loaded and class-triggered", eBPF-lifecycle="everything ever opened", eBPF-interpreter="at least one method executed".

## Chain 2: the class loading and definition chain (DefineClass)

### 2.1 Call path

```text
Class.forName(name, initialize, loader)
  └→ loader.loadClass → BaseDexClassLoader.findClass
       └→ DexPathList.findClass → Element→DexFile.loadClass
            └→ DexFile.defineClass(native: DexFile_defineClassNative; obtain DexFile* from cookie)
                 └→ ClassLinker::DefineClass(...)          ← standard unpacking hook point
```

### 2.2 DefineClass's signature and argument position (version table)

| Version | Signature essentials | DexFile argument position (arm64) |
|---|---|---|
| 8-9 | `DefineClass(Thread* self, const char* descriptor, size_t hash, Handle<ClassLoader>, const DexFile&, const ClassDef&)` [source:A9 class_] | **x5/args[5]** (the frida-dump convention) |
| main (15/16+) | gains `size_t descriptor_length`: `DefineClass(Thread*, const char* descriptor, size_t descriptor_length, size_t hash, Handle<ClassLoader>, const DexFile&, const ClassDef&)` [source:main class_:3520] | **x6/args[6]** |
| 10-14 | The exact version where descriptor_length was introduced is **[unverified]**, somewhere between 10 and main | Count arguments in IDA first on a new device |
Note: in every version, the `const DexFile&` passes an object pointer; the `Handle<>` is a wrapper (a stack-slot pointer), not the ClassLoader pointer itself - reading ClassLoader at x5 is wrong; unpacking scripts need only the DexFile, don't over-read.

### 2.3 Parsing and mirror::Class creation (timeline)

1. `dex_file.FindClassDef(descriptor)`: class_def_item (idx->off->item);
2. `LoadClass`/`SetupClass`: walk direct/static/virtual fields and methods with `ClassDataItemIterator`; **allocate mirror::Class (GC space)**, the method array (ArtMethods laid out contiguously) hangs off the back of the Class object (the methods_ region); each ArtMethod is backfilled with declaring_class/dex_method_index/method_index;
3. `LinkClass`: build vtable/IfTable, resolve superclasses/interfaces (triggering DefineClass of dependent classes recursively);
4. `VerifyClass`: structural validation (A12+ may be async in the background); on failure, soft-fail;
5. `InitializeClass`: the clinit trigger point (see 2.4).
Extraction packers' hook points mostly sit between 1-2 (the packer writes its own DexFile proxy/replaces the GetCodeItem path) or later (see 2.5).

### 2.4 clinit (class initialization) execution entry

- Triggered by first active use (new/static call/reflection);
- A12+ nterp: `ExecuteNterpWithClinitImpl` (a separate variant whose entry sets the clinit barrier); A13 has no separate WithClinit variant (the barrier is inside `ExecuteNterpImpl`) - proven in the eBPF piece sec.4.4;
- Observation: a uprobe on both Nterp variant entries covers clinit and ordinary methods.

### 2.5 Extraction-packer backfill timing and the theoretical basis of FART's active-invocation method

- **Whole-dex packers**: the whole dex is decrypted -> a DexFile is constructed -> DefineClass already sees full plaintext -> dumping at any chain-1 lifecycle point gets everything;
- **Class-load-period backfill** (some packers): hook/replace DefineClass-related paths, decrypting and backfilling each class's code_item as the class is defined -> memory near the DefineClass breakpoint is self-consistent; a chain-1 lifecycle dump also gets that class;
- **Invoke-period backfill** (dpt-shell and kin, README self-description "hollows out Dex method implementations and reconstructs them at runtime"): at dex load the method bodies are empty/nop; only when a method actually executes does the packer's native bridge decrypt that code_item and backfill - **what DefineClass/lifecycle dumps get is the hollowed shell**;
- The theoretical basis of FART/JDex: actively walk and **force-invoke** every method (constructors first), turning "backfill" from passive waiting into active triggering, then dump the code_item. FART's modified-ART flashing is dead on A12+ (layouts/accessorization, see the eBPF piece sec.7.1); the current usable carrier is the LSPosed-line JDex.

### 2.6 Chain 2 observation-point matrix

| Observation point | Shape | Notes |
|---|---|---|
| frida `ClassLinker::DefineClass` | symbol match `ClassLinker+DefineClass+Thread+DexFile`, args[5]/[6] for the DexFile* -> begin_/size_ | dex-unpacking.md sec.4; versions per the 2.2 table |
| eBPF uprobe DefineClass | same offset logic | eBPF-rs has verifyClass/DefineClass probes |
| Java layer `DexFile.loadClass`/`defineClass` | hook the Java methods | gets only the Cookie, not memory directly; pair with mCookie reads |
| `ClassLinker::EnsureResolved`/FindClass | supplement | boot classes go FindClass, not loadClass |
| The Nterp WithClinit variant | x0=ArtMethod | observing method-body backfill during the clinit period (a chain 3 technique) |

## Chain 3: the method execution chain (the three ArtMethod execution modes)

### 3.1 The dispatch paths

- Reflection/internal bridges (`Method.invoke`->`art::InvokeMethod`->`InvokeWithArgArray`) pass through the C++ **`ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result, const char* shorty)`** - signatures identical across A9/A13/main [source:per-tag art_:A9:318/A13:313/main:365];
- Ordinary calls (compiled-to-compiled / interpreted) **do not pass through the C++ Invoke**: they jump straight to `entry_point_from_quick_compiled_code_`, which points per the method's current state to nterp/JIT/AOT/JNI stubs;
- That is the structural reason "hooking ArtMethod::Invoke misses calls": it is a bridge, not the mandatory path.

### 3.2 ArtMethod layout (64-bit, version table, based on art_method.h)

| Offset | A8-A11 | A12+ (incl. main) |
|---|---|---|
| 0x0 | `declaring_class_` (GcRoot, **4-byte compressed reference**) | same |
| 0x4 | `access_flags_` (u32) | same |
| 0x8 | `dex_code_item_offset_` (u32) | **`dex_method_index_`** (u32; A12 deleted dex_code_item_offset_, fields shifted forward) |
| 0xC | `dex_method_index_` (u32) | `method_index_` (u16)+`hotness_count_/imt_index_` (u16) |
| 0x10/0x12 | `method_index_` (u16)+`hotness_count_` (u16) | padding (source comment "Fake padding field") |
| 0x18 | `ptr_sized_fields_.data_` (**entry_point_from_jni_**) | **0x10**: `data_` |
| 0x20 | `entry_point_from_quick_compiled_code_` | **0x18** |
| size | **40** | **32** |
Basis: the A11 tag still has `dex_code_item_offset_`; from the A12 tag it's gone (the main visitor order: declaring_class->access_flags->dex_method_index->method_index->hotness->data_->quick, verified). Cross-check: the frida-API piece sec.6.1 example `{size:40, jniCode:24, quickCode:32}` matches <=A11; the eBPF Go version's `+0x8` read of dex_method_index matches A12+. **Re-run offset probing when switching versions; never copy the table**.
Two hard rules (shared by every observation in this chain):
1. `declaring_class_` is a 4-byte HeapReference - read as u32 then zero-extend; reading 8 bytes is always wrong;
2. Untag the top byte (MTE tag/PAC) before every dereference, or memory reads on the tagged address fail (the eBPF piece sec.4.5).

### 3.3 The three execution modes

| Mode | Version | Entry | Observation essentials |
|---|---|---|---|
| nterp assembly interpreter | **A12+ default** [source: main comment "The entrypoint for nterp, which ArtMethods can directly point to"] | `extern "C" void ExecuteNterpImpl` (a C symbol, no mangling) + `ExecuteNterpWithClinitImpl` | fast-ABI entry, **x0=ArtMethod** (the eBPF piece sec.4.3 correction: not x1=DEX); to get the DEX chain: ArtMethod->declaring_class (+0, u32, untag)->Class `+0x10` dex_cache->DexCache `+0x10` DexFile->`+0x8` begin |
| mterp | A7-A11 | `ExecuteMterpImpl` | the workhorse on old devices; A12+ is fallback only |
| switch interpreter | the fallback everywhere | `interpreter::Execute` (C++) | **main made it `static inline` (:248) -> the produced symbol disappears; A15+ failing to attach is normal** (see the eBPF piece sec.4.4) |
| quick compiled | all | `entry_point_from_quick_compiled_code_` points at JIT code (anonymous code cache) or AOT (odex) | the JIT region is an anonymous mapping that gets reclaimed and relocated |
| JNI native | all | `data_` holds the fnPtr; the quick entry points at the `art_quick_generic_jni_trampoline` stub which jumps to data_ | see chain 4 |
Dispatch details: at invoke time, unresolved quick entries go through the resolution trampoline (`art_quick_resolution_trampoline`) -> backfilled; `kAccCompileDontBother` blocks recompilation; `kAccNterpInvokeFastPathFlag`/`kAccFastInterpreterToInterpreterInvoke` influence fast-path selection (the frida-API sec.6.1 probing script uses exactly these masks to back-derive the accessFlags offset); deopt pulls compiled code back into interpretation.

### 3.4 Chain 3 observation-point matrix

| Observation point | Tool | Shape | Pitfalls |
|---|---|---|---|
| `ExecuteNterpImpl` | eBPF uprobe | x0=ArtMethod | A13 has no separate WithClinit variant; A15+ Execute inlining doesn't affect this point |
| all `nterp_op_invoke_*` sites | eBPF uprobe | PARM1=ArtMethod | covers the invoke blind spots inside nterp (the eBPF Go technique) |
| quick code entries | inline hook (frida Interceptor/Dobby) | hook the JIT/AOT code head | JIT code lives in anonymous regions whose addresses shift on reclamation - **a saved hook target may expire at any time** |
| Stalker following JIT code | frida | translate the compiled code | big pitfall: the JIT region has no symbols and blocks get moved - `Stalker.exclude` irrelevant regions + unfollow/GC promptly (see ../02-frida/advanced/stalker.md) |
| `ArtMethod::Invoke` | frida/eBPF | args: x0=this, x1=self, x2=args, x3=args_size, x4=result, x5=shorty | covers only the reflection/bridge paths - **incomplete** |

### 3.5 The unpacking view: the optimal interception layer for the three packer types (summary table)

| Packer type | When plaintext exists in full | Optimal layer | Rationale |
|---|---|---|---|
| Whole-dex packer (one-shot decrypt) | the instant before DexFile construction (memory buffer/InMemory) | chain-1 lifecycle points (DexFile ctor/OpenCommon/RegisterDexFile) + memcpy for InMemory | complete, single-point, controllable timing |
| Extraction packer (invoke-time backfill) | each method's first execution | chain 3 (Nterp entry/nterp_op_invoke) + method-bytecode backfill; for completeness, add active invocation (JDex/FART family) | passive gets only what executed; active invocation turns backfill into a controlled trigger |
| VMP/dex virtualization | never exists as standard dex bytecode | handler tracing after chain-3 dispatch (the instruction-dispatch loop); **there is no "dump the dex" solution in the usual sense** | method bodies are translated to private opcodes; conventional dumping is meaningless (VMP restoration: `../10-algo-restore/deobfuscation-practice.md` sec.6) |

## Chain 4: the JNI registration and call chain

### 4.1 The loading chain (timeline, matched against source)

```text
System.loadLibrary("foo")
  └→ Runtime.loadLibrary0(name, classLoader)                    [libcore]
       └→ ClassLoader.findLibrary → nativeLibraryDirectories constructs libfoo.so path
       └→ Runtime.nativeLoad(filename, loader, caller)          [libcore Runtime.java]
            └→ Runtime_nativeLoad → JVM_NativeLoad              [source: A13 libcore/ojluni/src/main/native/Runtime.c:77;
                                                                 thin bridge only; A8 used art/runtime/native/java_lang_Runtime.cc]
                 └→ JavaVMExt::LoadNativeLibrary(env, path, class_loader, caller_class, error_msg)
                                                                 [source: A13 runtime/jni/java_vm_ext.cc:921;
                                                                  ≤A11 used runtime/java_vm_ext.cc; note directory differences]
                      ├→ Deduplicate in libraries_ table(reuse directly for same loader)
                      └→ android::OpenNativeLibrary(env, targetSdk, path, class_loader, caller_location, library_path, ...)
                           [libnativeloader: ClassLoader namespace isolation controls visibility]
                           └→ linker dlopen/android_dlopen_ext → soinfo linking/relocation
                                └→ call_constructors(init_array/DT_INIT) ← anti-debug logic often starts here(corpus: call_constructors timing case)
                                     └→ dlsym("JNI_OnLoad") → JNI_OnLoad(vm, reserved)
                                          └→(packer/ordinary code)env->RegisterNatives(clazz, methods, n)
```

The so file's own path into memory (openat->read->mmap PROT_EXEC) is referenced from `../09-function-map/android-function-layers.md` L3-L5; the linker-side full timeline (dlopen->relocation->call_constructors->the JNI_OnLoad injection race) already has a dedicated piece in the same area - see process-memory-chain.md chain 2; not repeated here; soinfo structures/dumping referenced from `../03-unpacking/so-repair-dump.md`.

### 4.2 Static vs dynamic registration

- **Static (lazy)**: first call of a method -> quick entry = `art_quick_generic_jni_trampoline` -> the `JniDlsymLookup` stub -> `dlsym("Java_<mangled>")` -> backfilled. `UnregisterNatives` just restores the entry to `GetJniDlsymLookupStub` [source:main class_:UnregisterNative];
- **Dynamic (explicit)**: inside `JNI_OnLoad`, `RegisterNatives(env, jclass, const JNINativeMethod* methods, jint n)`:
 1. `art::JNI<kQuick>::RegisterNatives` (**static member: x0=env, x1=clazz, x2=methods, x3=n**; consistent with the eBPF piece's PARM3/PARM4) [source:main runtime/jni/jni_:2560];
 2. reads each `methods[i] = {name, signature, fnPtr}` (24 bytes on 64-bit: name+0/sig+8/fnPtr+16);
 3. on `FindMethod<native-only>` failure, retry `FindMethod<full>`, walking the superclass chain for the ArtMethod; only on a total miss does it print "This is slow, consider changing your RegisterNatives calls." (the anchor of the string-xref locating method);
 4. `class_linker->RegisterNative(self, m, fnPtr)` [source:main class_:469] -> **`method->SetEntryPointFromJni(fnPtr)`** (writes the `data_` field); @CriticalNative has a clinit visibility check - if not yet initialized, it hangs the entry in a table and defers;
 5. native-bridge (mixed x86/arm) scenarios wrap a trampoline first.

### 4.3 Chain 4 observation-point matrix

| Observation point | Tool | Shape | Notes |
|---|---|---|---|
| `art::JNI::RegisterNatives` | frida (../02-frida/native-hook-cheatsheet.md §1.14 has full code) | args[2]=methods, args[3]=count; walk reading name/sig/fnPtr | the main point for symbol recovery of dynamic registrations |
| the same, eBPF edition | uprobe | x2/x3 same shape; use TGID for after-the-fact maps resolution | the eBPF piece sec.3.3 three-tier offset identification |
| `JavaVMExt::LoadNativeLibrary` | frida | x2=the path string | catches the path of a self-decrypting so before it lands |
| linker `dlopen`/`android_dlopen_ext` | frida/inline | returns soinfo* | pairs with soListRemove/unlinking analysis (area 02) |
| `call_constructors`/init_array | inline | per constructor | anti-debug initialization timing (corpus cases) |
| the `JniDlsymLookup` stub | uprobe | the lazy-registration backstop | the supplementary catch point for statically-registered packers |

## Chain 5: the OAT/VDEX/ART service chain (condensed)

### 5.1 When dex2oat (AOT compilation) triggers

- **At install**: PackageManagerService -> installd `dexopt` -> `/system/bin/dex2oat64` (arguments assembled by ArtService/the ART module), output `/data/app/<pkg>~~<rand>/oat/<arch>/base.{odex,vdex}`;
- **In the background**: BackgroundDexOptService when idle/charging (the mainstay before A12) -> from A12+ gradually ceding to **ART Service/the ART daemon** (A14's artd system, the `pm art` command surface) - the exact division of responsibilities **[unverified: component names per version]**;
- **At boot**: zygote uses the precompiled boot image (`/system/framework/<arch>/boot.art`);
- After runtime profiles (JIT sampling) flow back, background re-runs dex2oat by profile.

### 5.2 The odex/vdex-priority loading path (verified against main source)

Inside `OatFileManager::OpenDexFilesFromOat` via OatFileAssistant:

```text
Try odex(oat/<arch>/base.odex; contains quickened/compiled code)
  ↓ Mismatch/missing
Try vdex(base.vdex: contains dex, often cdex, plus validation information)
  ↓ Mismatch/missing
fallback: ArtDexFileLoader(dex_location).Open(...) ← mmap original DEX directly from APK(chain 1.3 mmap point)
Finally: Jit->RegisterDexFiles(...) + Runtime::NotifyDexFileLoaded() [source: main oat_file_manager.cc:466-494]
```
- Anonymous-memory dex can also come with an **anonymous vdex**: `AnonymousDexVdexLocation` + `VdexFile::Open` + `MatchesDexFileChecksums` (reused only when checksums match, skipping structural validation) [source:main oat_file_:533-600] - the AOT cache channel for InMemory dex;
- Corollary: whether the same APK "has odex/vdex" changes the first plaintext location the process sees (mmap of the APK directly vs mapping from vdex) - before dumping, check `--clean-oat` (the principle behind eBPFDexDumper deleting the oat directory by default to prevent cdex/empty results).

### 5.3 The cdex problem (relation to dump repair)

- The dex inside vdex is mostly **compact dex** (magic `cdex001`): dexlayout reorders by profile, multiple dex share the data section, the header carries `container_size_` [source:main libdexfile/dex/dex_: around :118/266];
- ART **keeps the compact form** in memory and runs it directly (no expansion back to standard dex), so a memory dump may yield cdex - tools that don't recognize it report a corrupt file;
- Repair relation (the full pipeline is in the eBPF piece sec.5.2): the complete cdex->dex conversion uses vdexExtractor; after dumping, the minimum is recomputing **signature=SHA-1 (covering dex[32..])** and **checksum=Adler-32 (covering dex[12..])**, or jadx/baksmali refuse the file;
- eBPFDexDumper only recognizes and warns, it doesn't convert (stated in the README) - know that boundary.

### 5.4 New items on A16+ (frontier markers)

- main's `runtime/oat/` gained files with the `sdc_` prefix (a signed-dex-container signature, an ART-side new primitive; the table's sdc_file row) - **[unverified: purpose/version/impact on dumping]**, just track it;
- the runtime/dex directory on main holds only annotations: all loading code is concentrated in libdexfile - **look for symbols in libdexfile first; the old runtime/dex_ top-level path is dead** (only A8 and earlier had runtime/dex_).

## Appendix: five-chain observation-point master table (one-page quick reference)

| Chain | First-choice observation point | Alternatives | Version notes |
|---|---|---|---|
| 1 Memory entry | `DexFile::DexFile` (x1=base)/`OpenCommon` | `RegisterDexFile`, memcpy/mmap | A16/17 ctor stripped; the OpenOne ABI |
| 2 Class definition | `ClassLinker::DefineClass` | loadClass (Java), Nterp WithClinit | args[5]->args[6] (main adds descriptor_length) |
| 3 Method execution | `ExecuteNterpImpl` (x0=ArtMethod) | nterp_op_invoke_*, ArtMethod::Invoke | Execute inlined (A15+); the ArtMethod layout A11/A12 boundary |
| 4 JNI | `art::JNI::RegisterNatives` (x2=methods) | the JniDlsymLookup stub, dlopen, call_constructors | the JavaVMExt path's A11/A12 directory boundary |
| 5 AOT | File-state: odex/vdex directory comparison | re-run after `--clean-oat` | the cdex repair chain is fixed (SHA-1/Adler) |

## Source version comparison table

| Item | Status |
|---|---|
| DexFileLoader/OpenOne/OpenCommon symbols and paths per version | source:A8/9/12/13/14/15/16/main tags grepped one by one |
| The OpenOne x1=header_offset correction (conflicts with the eBPF-rs comment) | source:A15/main; real-device ABI `[unverified]` |
| MapRootContainer->MemMap::MapFile (the mmap call site) | source:main |
| openInMemoryDexFilesNative (anonymous mmap+memcpy) | source:main |
| DefineClass signature (A9 vs main) | source; the 10-14 intermediate versions `[unverified]` |
| ArtMethod layout (dex_code_item_offset_ present in A11, absent in A12) | source:A9-A15 tags' art_method.h |
| Execute static inline (the root cause of the symbol vanishing on A15+) | source:main :248 |
| ExecuteNterpImpl extern "C" + nterp as A12+ default | source:main |
| ArtMethod::Invoke signature identical across three versions | source:A9/A13/main art_ |
| RegisterNatives->ClassLinker::RegisterNative->SetEntryPointFromJni | source:main jni_:2560/class_:469 |
| The nativeLoad bridge (libcore ojluni Runtime.c->JVM_NativeLoad) | source:A13 libcore |
| odex->vdex->APK fallback + anonymous vdex | source:main oat_file_ |
| The kernel mmap chain (vm_mmap_pgoff->mmap_region->filemap) | generic kernel knowledge (GKI 5.x/6.x) |
| ART Service/ARTd component evolution, sdc_file | `[unverified]` |
| The mmap syscall number (arm64 222/arm32 mmap2 192) | consistent with area 09's function-panorama syscall table |

## Related documents

- The x1=DEX begin shape and the full eBPF observation/repair set: ebpf-unpacking-deep.md (../03-unpacking/ebpf-unpacking-deep.md)
- The frida DefineClass method/ByteBuffer constructor method: dex-unpacking.md (../03-unpacking/dex-unpacking.md)
- ArtMethod offset auto-probing/Stalker; the RegisterNatives hook: frida-api-reference.md sec.6, native-hook-cheatsheet.md sec.1.14, advanced/stalker.md (../02-frida/advanced/)
- File syscall layering (openat L3-L5), arm64 syscall numbers: android-function-layers.md (../09-function-map/)
- so loading/soinfo/call_constructors: so-repair-dump.md (../03-unpacking/)
