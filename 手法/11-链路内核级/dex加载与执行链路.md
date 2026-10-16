# DEX 加载与执行链路(ART 用户态 → syscall → 内核)

> 定位:把一份 DEX 从「APK 里的字节」到「方法被执行」的完整链路按时序展开,五条链(内存进入/类定义/方法执行/JNI 注册/OAT-VDEX),每链给观测点矩阵。与既有文档分工:eBPF 篇(`../03-脱壳dump/eBPF脱壳深挖.md`)已实证「DexFile::DexFile / DexFileLoader::OpenOne 的 x1 形态」与修复管线,本篇展开**全链时序**与执行段;frida 篇(`../02-frida/frida-API详解.md` §6)已有 ArtMethod 偏移探测,本篇给版本化布局依据。
> 版本口径:AOSP googlesource 源码逐条对照(tag:android-8.0.0_r1 / 9.0.0_r1 / 10-11.0.0_r1 / 12.0.0_r1 / 13.0.0_r1 / 14.0.0_r1 / 15.0.0_r1 / 16.0.0_r1 / refs/heads/main,以及 libcore android-13.0.0_r1)。标注:**[源码·tag]**=已对到具体 AOSP tag;**[]**=公开源码未见/需真机对照;不标=通用内核/ART 常识且多源一致。
> 措辞约定:观测/提取,均为授权逆向语境。

## 〇、总览时序(先建立全景)

```text
[安装期]  apk 安装 → pm/installd → dex2oat → /data/app/*/oat/<arch>/base.{odex,vdex}(链5)
[加载期]  ClassLoader 构造(链1 上半)
            └→ DexFile.loadDex/构造 → native openDexFileNative → OatFileAssistant 查 odex/vdex
                 └→ 都没有 → DexFileLoader/MapRootContainer → MemMap::MapFile → mmap(svc,链1 内核段)
                      └→ DexFile 对象(begin_/size_)→ ClassLinker::RegisterDexFile → DexCache 互链
[类期]    Class.forName/loadClass → DexFile.loadClass → DefineClass(链2)
            └→ class_def 解析 → mirror::Class → ArtMethod 数组 → Link/Verify → clinit
[执行期]  invoke → entry_point_from_quick_compiled_code_(链3)
            ├→ nterp 解释(A12+) / mterp(A7-A11) / switch 兜底
            ├→ JIT/AOT quick code
            └→ JNI(链4:System.loadLibrary→dlopen→JNI_OnLoad→RegisterNatives→entry_point_from_jni_)
```

## 链1:APK → DEX 进入内存全链

### 1.1 Java 层(BaseDexClassLoader 系)

- `DexClassLoader`/`PathClassLoader` 都是 `BaseDexClassLoader` 子类,差别只在构造参数(optimizedDirectory 是否可用);壳常用的 `InMemoryDexClassLoader` 也归 `BaseDexClassLoader`。
- 构造时 `DexPathList.makePathElements` 把 dexPath 拆成 `Element[]`,每个 Element 内部延迟构造 `dalvik.system.DexFile`;真正打开发生在第一次类查找或显式 `DexFile.loadDex`。
- `DexFile` 构造最终进 native:`openDexFileNative(String sourceName, String outputName, int flags, ClassLoader, Element[])`,返回 jlong 数组 cookie(每个元素是一个 `const DexFile*`)。(A8/A9/main,runtime/native/dalvik_system_)
- `InMemoryDexClassLoader` 走 `openInMemoryDexFilesNative(ByteBuffer[] buffers, byte[][] arrays, int[] starts, int[] ends, ClassLoader, Element[])`(A12+ 拆成 arrays/starts/ends 三参;旧版单 ByteBuffer[])。[源码·main]

### 1.2 ART 内部符号沿革(核心表)

| Android | 文件 | 入口符号族 | 备注 |
|---|---|---|---|
| 8.x | `runtime/dex_`(顶层,无 dex/ 子目录) | `art::DexFile::Open(const uint8_t* base, size_t size,...)`、`DexFile::OpenFile(int fd,...)`、`DexFile::OpenZip`、`DexFile::OpenCommon` | 无 DexFileLoader 类;静态 Open 直接构造 DexFile |
| 9-11 | libdexfile 拆分:`libdexfile/dex/dex_file_` | `art::DexFileLoader::Open(base,size,...)` / `OpenWithDataSection` / `OpenAll` / `OpenCommon` / `OpenOneDexFileFromZip`;`ArtDexFileLoader` 在 `runtime/dex/art_dex_file_` | OpenCommon 是最终收口,**脱壳常用挂点** |
| 12-13 | 同上;`ArtDexFileLoader` 移到 `libdexfile/dex/`(android-mainline-12.0 tag 的 test 文件可证) | 符号族同 9-11;**无 `OpenOne`**(A12/A13 tag 全文检索只有 `OpenOneDexFileFromZip`) | nterp 成为默认解释器(见链3) |
| 14 | `libdexfile/dex/dex_file_` | 成员 `DexFileLoader::Open(uint32_t location_checksum, const OatDexFile*, bool verify, bool verify_checksum, string*)` + 静态 `DexFileLoader::Open(const uint8_t* base, size_t size,...)` | 容器化(RootContainer/DexFileContainer)重构落地 |
| 15-16+ | 同上 | 成员改名 **`DexFileLoader::OpenOne(size_t header_offset, uint32_t location_checksum, const OatDexFile*, bool, bool, string*)`**;静态 `Open(base,size,...)` 保留 | **纠偏[源码·A15/main]**:AOSP 源码中 OpenOne 第一参是 `size_t header_offset`(成员函数 x0=this,x1=header_offset)——**不是 base 指针**;eBPFDexDumper-rs 源码注释「OpenOne x1=base,x2=size」与 AOSP 源码不符,真机 ROM 上该符号 ABI **[]**,挂之前必须拿 IDA 对当前 libart 反汇编确认参数形态 |
**符号被剥/内联与 fallback(结合 eBPF 篇实证)**:
- Android 16/17 把 `DexFile::DexFile` 构造剥符号/内联 → 回退挂 `DexFileLoader::OpenOne`(eBPF 篇 §4.1,工具源码注释;但注意上表纠偏:x1 语义需真机复核);
- 多数剥离 ROM 里 OpenOne 在 dynsym 仅 `st_value=0` 占位,attach 跳过,只有真导出才挂得上;
- 通用 fallback 手法:字符串 xref(如 RegisterNatives 的 `"This is slow, consider changing your RegisterNatives calls."`、Execute 的 `"Interpreting "`,eBPF 篇 §3.3/§4.4 已实证)、ARM64 前导字节模式扫描。

### 1.3 mmap:用户态到内核的精确链路

文件路 dex(APK 内 classes.dex / 独立 .dex)最终都会走到:

```text
ArtDexFileLoader(dex_location).Open(...)            [源码·main runtime/oat/oat_file_manager.cc]
  └→ DexFileLoader::MapRootContainer()              [源码·main libdexfile/dex/dex_file_loader.cc:324]
       └→ fstat(fd) 取 size
       └→ MemMap::MapFile(size, PROT_READ, MAP_PRIVATE, fd, 0, ...)
            └→ bionic mmap(纯 syscall 包装,无用户态加工)
                 └→ svc #0, x8=__NR_mmap(arm64=222;arm32 走 mmap2=192)
                      └→ sys_mmap → ksys_mmap_pgoff → vm_mmap_pgoff → mmap_region
                           ├→ call_mmap(f_op->mmap:ext4/generic_file_mmap、f2fs_file_mmap)→ 建页缓存映射
                           └→ 真实数据读在**缺页时**:filemap_fault → readahead(内核细节以 GKI 5.x/6.x 为准)
```
- `MAP_PRIVATE` 的关键含义:写时复制。壳把加密 dex mmap 进来后在内存里 mprotect+w 解密,盘上 APK 不变——**内存 dump 拿到的是解密后状态**,这是「mmap 之后、构造 DexFile 之前」存在一个可观测明文窗口的内核级依据。
- bionic 侧没有中间层:mmap 直接 `__NR_mmap`,没有 libc 缓冲(区别于 fread/fopen 家族),所以 syscall 层观测不会漏。

### 1.4 InMemory 路径差异(为什么 eBPF 要挂 memcpy)

`DexFile_openInMemoryDexFilesNative`(main 版已逐行核对):
1. `AllocateDexMemoryMap(start,end)` → **匿名 mmap**(无文件、无 fd);
2. Direct ByteBuffer:`memcpy(匿名页, direct_buffer+start, length)`;数组型:`GetByteArrayRegion` 拷贝;
3. 把 MemMap 交给 `OatFileManager::OpenDexFilesFromOat(std::vector<MemMap>&&, ...)` → 逐个 `ArtDexFileLoader(MemMap, location).Open(checksum, verify, verify_checksum, &err)`。
推论:整壳走 InMemoryDexClassLoader 时,**全程没有任何文件 mmap 可抓**,明文只在 memcpy 的一瞬间完整存在 → eBPFDexDumper-rs 对 libc `memcpy/memmove` 挂 uprobe+uretprobe 成对(入口取参数/出口取返回值)正是补这个窗口(其源码 SEC 列表实证,见 eBPF 篇 §5.1)。

### 1.5 DexFile 对象与 RegisterDexFile

- `DexFile::DexFile(const uint8_t* base, size_t size, ...)`[源码·main libdexfile/dex/dex_:152]:x0=this,**x1=base,x2=size**(这就是 eBPF 篇「x1=DEX begin」入口的源头);对象内 `begin_`/`size_` 成员即 dump 用字段。64 位下旧工具按 `begin_` 在 +8、`size_` 在 +16 读(A9 形态);新版本字段顺序有调整,**hook 前用 IDA 对当前 libart 的 DexFile 构造函数反汇编确认 [(逐版本偏移表)]**。
- `ClassLinker::RegisterDexFile(const DexFile&, ObjPtr<ClassLoader>)`[源码·main class_:4618,内部 RegisterDexFileLocked]:建/取 `mirror::DexCache`,并 CHECK `dex_cache->GetDexFile == &dex_file`——DexCache↔DexFile 互链是后续「从 ArtMethod 链回 DexFile」(ArtMethod→declaring_class→dex_cache→DexFile→begin_)那条经典链的枢纽。
- 壳在 Java 层反射拿 `DexFile.mCookie`(long 数组,元素是 `const DexFile*`)→ 直接读 begin_:BlackDex 的 cookie 法、JDex 的 mCookie dump 都建立在这上面。

### 1.6 verify / cdex / oat 分支(加载期同层发生)

- 结构校验+verify 在 Open 内(verify=true 时);A12+ 还有后台校验 `DexFile_verifyInBackgroundNative`[源码·main dalvik_system_:396 附近];
- odex/vdex 优先路径在 `OatFileManager::OpenDexFilesFromOat` 内部(OatFileAssistant),详见链5;
- cdex(compact dex)在 vdex 内是常态,内存中保持 `CompactDexFile` 形态(magic `cdex001`),dump 修复见链5.3。

### 1.7 链1 观测点矩阵 + frida/eBPF 时机差异

| 阶段 | 观测点 | 拿到什么 | 时机早晚 | 备注 |
|---|---|---|---|---|
| Java 层 | hook `DexFile.$init`(ByteBuffer 版) | 解密后明文 buffer | 中 | dex脱壳.md §二;壳走 InMemory 时最自然 |
| ART 生命周期 | uprobe `DexFile::DexFile`(x1=base) | 明文 dex 起址 | 早(解析前) | A16/17 剥符号→回退 OpenOne(ABI) |
| ART 收口 | uprobe `DexFileLoader::OpenCommon`(A9-13)/`Open`(A14+) | base/size 参数 | 早 | 版本符号不同,按 1.2 表选 |
| ART 注册 | uprobe `ClassLinker::RegisterDexFile`(x1=DexFile* 再解引用) | begin_/size_ | 中 | eBPF 篇 §4.2:符号后缀钉死防误挂 unique_ptr 重载 |
| ART 映射 | uprobe `DexFileLoader::MapRootContainer` / `MemMap::MapFile` | fd/size/返回地址 | 早于解析 | 文件路 dex 必经 |
| libc | uprobe/tracepoint `mmap`、`mprotect` | 映射区+fd;壳解密的 mprotect | **最早**(可能是密文/整包 APK) | mmap 抓到的未必是明文:文件壳先 mmap 密文再原地解密 |
| libc | uprobe `memcpy/memmove`(成对) | InMemory 明文窗口 | 早 | 补 InMemory 壳盲区(eBPF-rs 实证) |
| 内核 | tracepoint `sys_enter_mmap` / `sys_enter_openat` | 全量 IO 无差别 | 最早但噪音大 | 需按 pid/路径过滤 |
**为什么 frida dump 和 eBPF dump 抓到的时机不同**:
- frida 经典法挂 `DefineClass`(链2):类**第一次被用到**才触发,壳此时往往已把该 dex 处理完,抓到的是「类加载期」快照——晚但稳;
- eBPF 挂 DexFile ctor/OpenCommon/RegisterDexFile:**dex 解析期**,比 DefineClass 早一拍,且不依赖任何类被加载;
- eBPF 挂 mmap/解释器入口:更早/更晚各极端——mmap 早于解密(文件壳)可能拿密文,nterp 入口晚于一切(方法执行期)但天然带 ArtMethod 上下文;
- 所以同一目标两者 dump 出的 dex 集合可能不同:frida=「被加载且类被触发的」,eBPF 生命周期=「全部打开过的」,eBPF 解释器=「至少执行过一个方法的」。

## 链2:类加载与定义链(DefineClass)

### 2.1 调用路径

```text
Class.forName(name, initialize, loader)
  └→ loader.loadClass → BaseDexClassLoader.findClass
       └→ DexPathList.findClass → Element→DexFile.loadClass
            └→ DexFile.defineClass(native: DexFile_defineClassNative,自 cookie 取 DexFile*)
                 └→ ClassLinker::DefineClass(...)          ← 脱壳经典挂点
```

### 2.2 DefineClass 签名与参数位置(版本表)

| 版本 | 签名要点 | DexFile 实参位置(arm64) |
|---|---|---|
| 8-9 | `DefineClass(Thread* self, const char* descriptor, size_t hash, Handle<ClassLoader>, const DexFile&, const ClassDef&)` [源码·A9 class_] | **x5/args[5]**(frida-dump 定式) |
| main(15/16+) | 多了 `size_t descriptor_length`:`DefineClass(Thread*, const char* descriptor, size_t descriptor_length, size_t hash, Handle<ClassLoader>, const DexFile&, const ClassDef&)` [源码·main class_:3520] | **x6/args[6]** |
| 10-14 | descriptor_length 引入的确切版本 **[]**,介于 10 与 main 之间 | 换机器先 IDA 数参数 |
注意:无论哪版,`const DexFile&` 传的都是对象指针;`Handle<>` 是包装(栈槽指针),不是直接 ClassLoader 指针,按 x5 读 ClassLoader 会错——脱壳脚本只需要 DexFile,别多读。

### 2.3 解析与 mirror::Class 创建(时序)

1. `dex_file.FindClassDef(descriptor)`:class_def_item(idx→off→item);
2. `LoadClass`/`SetupClass`:按 `ClassDataItemIterator` 遍历 direct/static/virtual 字段与方法;**分配 mirror::Class(GC 区)**,方法数组(ArtMethod 连续排布)挂在 Class 对象后部(methods_ 区域),每个 ArtMethod 回填 declaring_class/dex_method_index/method_index;
3. `LinkClass`:建 vtable/IfTable、解析父类接口(此时触发依赖类的 DefineClass,递归);
4. `VerifyClass`:结构校验(A12+ 可后台异步);失败进 soft-fail;
5. `InitializeClass`:clinit 触发点(见 2.4)。
抽取壳的挂钩点多在 1-2 之间(壳自写 DexFile 代理/替换 GetCodeItem 路径)或更晚(见 2.5)。

### 2.4 clinit(类初始化)执行入口

- 首次主动使用(new/static 调用/反射)触发;
- A12+ nterp:`ExecuteNterpWithClinitImpl`(独立变体,入口做 clinit 屏障);A13 无独立 WithClinit 变体(屏障在 `ExecuteNterpImpl` 内)——eBPF 篇 §4.4 已实证;
- 观测:uprobe 两个 Nterp 变体入口即可覆盖 clinit 与普通方法。

### 2.5 抽取壳回填时机与 FART 主动调用法的理论依据

- **整体壳**:dex 整体解密→构造 DexFile→DefineClass 看到的已是全量明文 → 在链1 任意生命周期点 dump 即全量;
- **类加载期回填**(部分壳):hook/替换 DefineClass 相关路径,在类被定义时把该类 code_item 解密回填 → DefineClass 断点附近内存自洽,链1 生命周期 dump 也能拿到该类;
- **invoke 期回填**(dpt-shell 这类,README 自述 "hollows out Dex method implementations and reconstructs them at runtime"):dex 装载时方法体是空/nop,真正执行某方法时才由壳的 native 桥解密该 code_item 回填——**DefineClass/生命周期 dump 拿到的就是空的**;
- FART/JDex 的理论依据:主动遍历并**强制 invoke** 每个方法(构造方法优先),把「回填」从被动等待变成主动触发,再 dump code_item。FART 改 ART 源码刷机在 A12+ 失效(布局/Accessor 化,见 eBPF 篇 §7.1),当前可用载体是 LSPosed 系的 JDex。

### 2.6 链2 观测点矩阵

| 观测点 | 形态 | 备注 |
|---|---|---|
| frida `ClassLinker::DefineClass` | 符号匹配 `ClassLinker+DefineClass+Thread+DexFile`,args[5]/[6] 取 DexFile* → begin_/size_ | dex脱壳.md §四;版本按 2.2 表 |
| eBPF uprobe DefineClass | 同上偏移逻辑 | eBPF-rs 有 verifyClass/DefineClass probe |
| Java 层 `DexFile.loadClass`/`defineClass` | hook Java 方法 | 只能拿 Cookie,不直接拿内存,配合 mCookie 读 |
| `ClassLinker::EnsureResolved`/FindClass | 补充 | boot class 走 FindClass 不走 loadClass |
| Nterp WithClinit 变体 | x0=ArtMethod | clinit 期方法体回填观测(链3 手法) |

## 链3:方法执行链(ArtMethod 三种执行方式)

### 3.1 分派总路径

- 反射/内部桥(`Method.invoke`→`art::InvokeMethod`→`InvokeWithArgArray`)会经过 C++ 的 **`ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result, const char* shorty)`** —— A9/A13/main 三版签名一致[源码·各 tag art_:A9:318/A13:313/main:365];
- 普通调用(编译码调编译码/解释码)**不经过 C++ Invoke**:直接跳 `entry_point_from_quick_compiled_code_`,该入口按方法当前状态指向 nterp/JIT/AOT/JNI 桩;
- 这就是「hook ArtMethod::Invoke 抓不全」的结构性原因:它只是桥,不是必经路。

### 3.2 ArtMethod 结构布局(64 位,版本表,基于 art_method.h)

| 偏移 | A8-A11 | A12+(含 main) |
|---|---|---|
| 0x0 | `declaring_class_`(GcRoot,**4 字节压缩引用**) | 同左 |
| 0x4 | `access_flags_`(u32) | 同左 |
| 0x8 | `dex_code_item_offset_`(u32) | **`dex_method_index_`**(u32;A12 删除了 dex_code_item_offset_,字段整体前移) |
| 0xC | `dex_method_index_`(u32) | `method_index_`(u16)+`hotness_count_/imt_index_`(u16) |
| 0x10/0x12 | `method_index_`(u16)+`hotness_count_`(u16) | padding(源码注释 "Fake padding field") |
| 0x18 | `ptr_sized_fields_.data_`(**entry_point_from_jni_**) | **0x10**:`data_` |
| 0x20 | `entry_point_from_quick_compiled_code_` | **0x18** |
| size | **40** | **32** |
依据:A11 tag 仍有 `dex_code_item_offset_`,A12 tag 起消失(main visitor 顺序:declaring_class→access_flags→dex_method_index→method_index→hotness→data_→quick,已核)。对照:frida-API 篇 §6.1 示例 `{size:40, jniCode:24, quickCode:32}` 对应 ≤A11;eBPF Go 版 `+0x8` 读 dex_method_index 对应 A12+。**换版本先重跑偏移探测,禁抄表**。
两条硬规矩(链所有观测共用):
1. `declaring_class_` 是 4 字节 HeapReference,只能 u32 读再零扩展,按 8 字节读必错;
2. 每次解引用前 untag 清顶字节(MTE tag/PAC),否则带 tag 地址读内存失败(eBPF 篇 §4.5)。

### 3.3 三种执行方式

| 方式 | 版本 | 入口 | 观测要点 |
|---|---|---|---|
| nterp 汇编解释器 | **A12+ 默认**[源码:main 注释 "The entrypoint for nterp, which ArtMethods can directly point to"] | `extern "C" void ExecuteNterpImpl`(C 符号,无 mangling)+ `ExecuteNterpWithClinitImpl` | 快速 ABI 进入,**x0=ArtMethod**(eBPF 篇 §4.3 纠偏:不是 x1=DEX);DEX 要链式:ArtMethod→declaring_class(+0,u32,untag)→Class `+0x10` dex_cache→DexCache `+0x10` DexFile→`+0x8` begin |
| mterp | A7-A11 | `ExecuteMterpImpl` | 旧机主力;A12+ 只作 fallback |
| switch 解释器 | 全系兜底 | `interpreter::Execute`(C++) | **main 已改 `static inline`(:248)→ 产物符号消失,A15+ 挂不上属正常**(见 eBPF 篇 §4.4) |
| quick compiled | 全系 | `entry_point_from_quick_compiled_code_` 指向 JIT 代码(匿名 code cache)或 AOT(odex) | JIT 区是匿名映射且会被回收搬迁 |
| JNI native | 全系 | `data_` 存 fnPtr,quick entry 指向 `art_quick_generic_jni_trampoline` 桩,桩跳 data_ | 见链4 |
分派细节:invoke 时 quick entry 未解析的走 resolution trampoline(`art_quick_resolution_trampoline`)→ 回填;`kAccCompileDontBother` 阻止再编译;`kAccNterpInvokeFastPathFlag`/`kAccFastInterpreterToInterpreterInvoke` 影响快速路径选择(frida-API §6.1 探测脚本正是用这些 mask 反推 accessFlags 偏移);deopt 把编译码拉回解释执行。

### 3.4 链3 观测点矩阵

| 观测点 | 工具 | 形态 | 坑 |
|---|---|---|---|
| `ExecuteNterpImpl` | eBPF uprobe | x0=ArtMethod | A13 无 WithClinit 独立变体;A15+ Execute 内联不影响本点 |
| `nterp_op_invoke_*` 全站点 | eBPF uprobe | PARM1=ArtMethod | 覆盖 nterp 内 invoke 盲区(eBPF Go 版手法) |
| quick code 入口 | inline hook(frida Interceptor/Dobby) | 挂 JIT/AOT 代码头 | JIT 代码在匿名区、地址随回收变化,**hook 前保存目标随时可能失效** |
| Stalker 跟 JIT 代码 | frida | translate 编译码 | 大坑:JIT 区无符号、块会被搬,须 `Stalker.exclude` 排除无关区+及时 unfollow/GC(02 区高级/stalker.md) |
| `ArtMethod::Invoke` | frida/eBPF | args:x0=this,x1=self,x2=args,x3=args_size,x4=result,x5=shorty | 只覆盖反射/桥路径,**不全** |

### 3.5 脱壳视角:三类壳的最优拦截层(总结表)

| 壳型 | 明文完整存在的时刻 | 最优层 | 理由 |
|---|---|---|---|
| 整体壳(一次解密) | DexFile 构造前的一瞬(内存 buffer/InMemory) | 链1 生命周期点(DexFile ctor/OpenCommon/RegisterDexFile)+ memcpy 补 InMemory | 全量、单点、时机可控 |
| 抽取壳(invoke 回填) | 每个方法第一次执行时 | 链3(Nterp 入口/nterp_op_invoke)+ 方法字节码回填;要全量再上主动调用(JDex/FART 系) | 被动只拿执行过的;主动调用把回填变成可控触发 |
| VMP/dex 虚拟化 | 永不以标准 dex 字节码形态存在 | 链3 dispatch 之后的 handler trace(指令分发循环),**没有「dump dex」意义上的解** | 方法体已翻译成私有 opcode,常规 dump 无意义(VMP 还原见 `../10-纯算法/去混淆实战.md` §6) |

## 链4:JNI 注册与调用链

### 4.1 加载链(时序,已对源码)

```text
System.loadLibrary("foo")
  └→ Runtime.loadLibrary0(name, classLoader)                    [libcore]
       └→ ClassLoader.findLibrary → nativeLibraryDirectories 拼 libfoo.so 路径
       └→ Runtime.nativeLoad(filename, loader, caller)          [libcore Runtime.java]
            └→ Runtime_nativeLoad → JVM_NativeLoad              [源码·A13 libcore/ojluni/src/main/native/Runtime.c:77
                                                                 仅薄桥;A8 老版在 art/runtime/native/java_lang_Runtime.cc]
                 └→ JavaVMExt::LoadNativeLibrary(env, path, class_loader, caller_class, error_msg)
                                                                 [源码·A13 runtime/jni/java_vm_ext.cc:921;
                                                                  ≤A11 在 runtime/java_vm_ext.cc,目录差异注意]
                      ├→ libraries_ 表查重(同 loader 直接复用)
                      └→ android::OpenNativeLibrary(env, targetSdk, path, class_loader, caller_location, library_path, ...)
                           [libnativeloader:按 ClassLoader namespace 隔离做可见性管控]
                           └→ linker dlopen/android_dlopen_ext → soinfo 链接重定位
                                └→ call_constructors(init_array/DT_INIT)      ← 反调试常埋这里(语料:call_constructors 时机帖)
                                     └→ dlsym("JNI_OnLoad") → JNI_OnLoad(vm, reserved)
                                          └→(壳/正常代码)env->RegisterNatives(clazz, methods, n)
```

so 文件本身的进盘链(openat→read→mmap PROT_EXEC)引用 `../09-函数全景/安卓函数分层全景.md` L3-L5;linker 侧完整时序(dlopen→重定位→call_constructors→JNI_OnLoad 抢注入窗口)同区已有专篇,见 `进程时序与内存链路.md` 链2,本篇不重复展开;soinfo 结构/dump 引用 `../03-脱壳dump/so修复dump.md`。

### 4.2 静态注册 vs 动态注册

- **静态(懒)**:方法首次调用 → quick entry = `art_quick_generic_jni_trampoline` → `JniDlsymLookup` 桩 → `dlsym("Java_<mangled>")` → 回填。`UnregisterNatives` 就是把 entry 恢复成 `GetJniDlsymLookupStub`[源码·main class_:UnregisterNative];
- **动态(显式)**:`JNI_OnLoad` 里 `RegisterNatives(env, jclass, const JNINativeMethod* methods, jint n)`:
 1. `art::JNI<kQuick>::RegisterNatives`(**static 成员:x0=env,x1=clazz,x2=methods,x3=n**;eBPF 篇 PARM3/PARM4 之说与此一致)[源码·main runtime/jni/jni_:2560];
 2. 逐条读 `methods[i] = {name, signature, fnPtr}`(64 位 24 字节:name+0/sig+8/fnPtr+16);
 3. `FindMethod<只匹配 native>` 失败再 `FindMethod<全量>`,沿父类链找 ArtMethod;找不到才打 "This is slow, consider changing your RegisterNatives calls."(字符串 xref 定位法的锚点);
 4. `class_linker->RegisterNative(self, m, fnPtr)`[源码·main class_:469] → **`method->SetEntryPointFromJni(fnPtr)`**(写 `data_` 字段);@CriticalNative 有 clinit 可见性检查,未可见初始化时先挂表延迟;
 5. native bridge(混编 x86/arm)场景会先包 trampoline。

### 4.3 链4 观测点矩阵

| 观测点 | 工具 | 形态 | 备注 |
|---|---|---|---|
| `art::JNI::RegisterNatives` | frida(02 区 native层hook速查 §1.14 完整代码) | args[2]=methods,args[3]=count,遍历读 name/sig/fnPtr | 动态注册符号恢复主点 |
| 同上 eBPF 版 | uprobe | x2/x3 同形;用 TGID 保事后 maps 解析 | eBPF 篇 §3.3 三级偏移识别 |
| `JavaVMExt::LoadNativeLibrary` | frida | x2=path 字符串 | 抓自解密 so 落地前的路径 |
| linker `dlopen`/`android_dlopen_ext` | frida/inline | 返回 soinfo* | 配合 soListRemove/摘链对抗(02 区) |
| `call_constructors`/init_array | inline | 逐构造器 | 反调试初始化时机(06 区语料) |
| `JniDlsymLookup` 桩 | uprobe | 懒注册兜底 | 静态注册壳的补抓点 |

## 链5:OAT/VDEX/ART 服务全链(压缩版)

### 5.1 dex2oat(AOT 编译)何时触发

- **安装时**:PackageManagerService → installd `dexopt` → `/system/bin/dex2oat64`(参数由 ArtService/ART 模块拼),产物 `/data/app/<pkg>~~<rand>/oat/<arch>/base.{odex,vdex}`;
- **后台**:闲置/充电时 BackgroundDexOptService(A12 前主力)→ A12+ 逐步让位 **ART Service/ART daemon**(A14 的 artd 体系,`pm art` 指令面)——职责切分细节 **[:逐版本组件名]**;
- **开机**:zygote 用预编译 boot image(`/system/framework/<arch>/boot.art`);
- 运行期 profile(JIT 采样)回流后,后台按 profile 重 dex2oat。

### 5.2 odex/vdex 优先于 dex 的加载路径(已核源码 main)

`OatFileManager::OpenDexFilesFromOat` 内部经 OatFileAssistant:

```text
尝试 odex(oat/<arch>/base.odex,含 quickened/compiled 代码)
  ↓ 不匹配/缺失
尝试 vdex(base.vdex:装着 dex(常为 cdex)+校验信息)
  ↓ 不匹配/缺失
fallback:ArtDexFileLoader(dex_location).Open(...)   ← 直接从 APK mmap 原始 dex(链1.3 的 mmap 点)
最后:Jit->RegisterDexFiles(...) + Runtime::NotifyDexFileLoaded()   [源码·main oat_file_manager.cc:466-494]
```
- 匿名内存 dex 也可能配**匿名 vdex**:`AnonymousDexVdexLocation` + `VdexFile::Open` + `MatchesDexFileChecksums`(checksum 对得上才复用,并跳过结构校验)[源码·main oat_file_:533-600]——InMemory dex 的 AOT 缓存通道;
- 推论:同一 APK「有没有 odex/vdex」会改变进程里看到的首个明文位置(直接 mmap APK vs 从 vdex 映射)——dump 前先看 `--clean-oat`(eBPFDexDumper 默认删 oat 目录防 cdex/空结果的原理)。

### 5.3 cdex 问题(与 dump 修复的关系)

- vdex 里的 dex 多为 **compact dex**(magic `cdex001`):dexlayout 按 profile 重排、多个 dex 共享 data section、header 带 `container_size_`[源码·main libdexfile/dex/dex_:118/266 一带];
- ART 在内存里**保持 compact 形态**直接跑(不展开回标准 dex),所以内存 dump 出的可能是 cdex——工具不识别就报坏文件;
- 修复关系(eBPF 篇 §5.2 已给全流程):cdex→dex 完整转换用 vdexExtractor;dump 后最低限度要重算 **signature=SHA-1(覆盖 dex[32..])** 与 **checksum=Adler-32(覆盖 dex[12..])**,否则 jadx/baksmali 拒收;
- eBPFDexDumper 只识别提示不转换(README 明示),边界要知道。

### 5.4 A16+ 新物(前沿标记)

- main 的 `runtime/oat/` 出现 `sdc_ DEX Container** 签名 dex 容器,ART 侧新原语)——**[:用途/版本/对 dump 的影响]**,跟踪即可;
- runtime/dex 目录在 main 只剩 annotations:加载代码全部集中到 libdexfile——**找符号先去 libdexfile,dex_ 顶层旧路径已死**(A8 及更早才在 runtime/dex_)。

## 附:五链观测点总表(一页速查)

| 链 | 首选观测点 | 备选 | 版本注意 |
|---|---|---|---|
| 1 内存进入 | `DexFile::DexFile`(x1=base)/`OpenCommon` | `RegisterDexFile`、memcpy/mmap | A16/17 ctor 剥符号;OpenOne ABI |
| 2 类定义 | `ClassLinker::DefineClass` | loadClass(Java)、Nterp WithClinit | args[5]→args[6](main 加 descriptor_length) |
| 3 方法执行 | `ExecuteNterpImpl`(x0=ArtMethod) | nterp_op_invoke_*、ArtMethod::Invoke | Execute 已 inline(A15+);ArtMethod 布局 A11/A12 分界 |
| 4 JNI | `art::JNI::RegisterNatives`(x2=methods) | JniDlsymLookup 桩、dlopen、call_constructors | JavaVMExt 路径 A11/A12 目录分界 |
| 5 AOT | 文件态:odex/vdex 目录对比 | `--clean-oat` 后重跑 | cdex 修复链固定(SHA-1/Adler) |

## 源码版本对照表

| 项 | 状态 |
|---|---|
| DexFileLoader/OpenOne/OpenCommon 逐版本符号与路径 | 源码·A8/9/12/13/14/15/16/main tag 逐一 grep |
| OpenOne x1=header_offset 纠偏(与 eBPF-rs 注释冲突) | 源码·A15/main;真机 ABI |
| MapRootContainer→MemMap::MapFile(mmap 调用点) | 源码·main |
| openInMemoryDexFilesNative(匿名 mmap+memcpy) | 源码·main |
| DefineClass 签名(A9 vs main) | 源码;10-14 中间版本 |
| ArtMethod 布局(dex_code_item_offset_ A11 有 A12 无) | 源码·A9-A15 tag art_method.h |
| Execute static inline(A15+ 符号消失根因) | 源码·main :248 |
| ExecuteNterpImpl extern "C" + nterp 为 A12+ 默认 | 源码·main |
| ArtMethod::Invoke 三版签名一致 | 源码·A9/A13/main art_ |
| RegisterNatives→ClassLinker::RegisterNative→SetEntryPointFromJni | 源码·main jni_:2560/class_:469 |
| nativeLoad 桥(libcore ojluni Runtime.c→JVM_NativeLoad) | 源码·A13 libcore |
| odex→vdex→APK fallback + 匿名 vdex | 源码·main oat_file_ |
| 内核 mmap 链(vm_mmap_pgoff→mmap_region→filemap) | 通用内核常识(GKI 5.x/6.x) |
| ART Service/ARTd 组件沿革、sdc_file | |
| mmap syscall 号(arm64 222/arm32 mmap2 192) | 与 09 区函数全景篇 syscall 表一致 |

## 相关文档

- x1=DEX begin 形态与 eBPF 全套观测/修复:eBPF脱壳深挖.md(../03-脱壳dump/eBPF脱壳深挖.md)
- frida DefineClass 法/ByteBuffer 构造法:dex脱壳.md(../03-脱壳dump/dex脱壳.md)
- ArtMethod 偏移自动探测/Stalker:RegisterNatives hook:frida-API详解.md §6、native层hook速查.md §1.14、高级/stalker.md(../02-frida/高级/)
- 文件 syscall 分层(openat L3-L5)、arm64 syscall 号:安卓函数分层全景.md(../09-函数全景/)
- so 加载/soinfo/call_constructors:so修复dump.md(../03-脱壳dump/)
