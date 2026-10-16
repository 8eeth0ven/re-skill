# eBPF 脱壳深挖(当前最深方案)

> 定位:eBPF/libbpf 路线的 Android DEX 脱壳全记录。覆盖原理(为什么比 frida 隐蔽)、eBPFDexDumper(Go)与 eBPFDexDumper-rs(Rust)双实现、ART hook 入口形态实证、修复管线、与 frida dump 对比、FART/JDex/RePairip/BlackDex/dpt-shell 生态定位。

## 一、eBPF 脱壳原理:为什么比 frida 隐蔽

### 1.1 加载与运行机制

- eBPF 程序通过 `bpf(BPF_PROG_LOAD)` 系统调用送入内核,经 verifier 静态验证后由内核 JIT 执行,**不向目标进程注入任何代码**。(两仓库 bpf.c 均为标准 libbpf CO-RE 风格,Go 版用 cilium/ebpf manager,Rust 版用 Aya)
- 用户态探针(uprobe)通过 `perf_event_open` 注册到目标 so 的指定偏移,断点由内核统一管理:目标进程**不新增映射、不新增线程、不被 ptrace 附着**,`/proc/<pid>/maps`、`/proc/<pid>/status`(TracerPid)看不出任何异常。
- 读内存用 `bpf_probe_read_user`(现 `bpf_probe_read_kernel` 的用户态版本):内核态代读,**目标进程无感知、无 syscall 产生**。
- 事件经 **ringbuf**(`bpf_ringbuf_reserve/submit`)异步回传用户态,旁路了目标进程的一切 IO。

### 1.2 frida 的检测面 vs eBPF 的缺失面

| 检测手段 | frida | eBPF |
|---|---|---|
| maps 扫 frida-agent/gum 特征 | 命中(agent 注入目标) | 不命中(零注入) |
| 线程名 `gum-js-loop`/`gmain` | 命中 | 不命中(无目标内线程) |
| TracerPtr / ptrace 自附着检测 | 命中 | 不命中(无 ptrace) |
| 27042 端口/frida-server 进程扫描 | 命中 | 不命中(用户态 dumper 无监听) |
| inline hook 检测(扫描函数头 break/trap) | 可命中 | 难命中(uprobe 断点内核托管,目标自读 text 看到的是原指令语义;仅读 `/sys/kernel/tracing` 等需 root 的接口才可发现) |
| SELinux/内核限制 | 基本无门槛 | 需 root + 内核开 `CONFIG_UPROBES`/BPF;部分厂商内核限制 perf_event_open |

### 1.3 代价与边界

- **只读观察模型**:eBPF 无法强制目标执行方法,抽取壳只回填「运行时真正被执行过的方法」,没跑到的函数体拿不到(Go 版 README 原文明确此限制)。 主动调用仍需 FART/JDex 这类改运行时或注入方案。
- 需 root 装 uprobes + 读 `/proc/<pid>/maps` 与内存;设备需 ARM64 + 带相对完整 BTF 的内核(两仓库 assets 里都带了 a12-5.10-arm64 / rock5b-5.10 的 min.btf 兜底)。

## 二、工具矩阵速查

| 工具 | 路线 | root | 状态/版本 |
|---|---|---|---|
| eBPFDexDumper(LLeavesG, Go) | eBPF uprobe + 内存读 | 要 | A13/16 实测,持续更新 |
| eBPFDexDumper-rs(chinleez, Rust) | eBPF uprobe + ringbuf | 要 | Android 13+ 默认布局,GPL-3.0 |
| BPFDex(论文) | 内核态 eBPF 脱壳 | - | 学术方案 |
| DEX-Tracer | eBPF 拦 syscall 入口(取参数)/出口(取返回值) | ? | **公开渠道未找到该项目** |
| FART(hluwa) | 改 ART 源码主动调用(刷机) | 刷机 | 原版停在老版本,**Android 12-16 直接失效** |
| JDex/JDex2(J5now) | LSPosed 注入+主动调用 | 免刷机 | 抽取壳主力 |
| BlackDex(CodingGay) | 免 root 虚拟化 + DexFile cookie | 不要 | A5.0-12 |
| RePairip(ispointer) | Pairip(Google 加固)专杀 | - | Java 17 |
| dpt-shell(luoyesiqiu) | 函数抽取壳本体(逆向靶子) | - | A5.0+ |

注意:dpt-shell 作者为 **luoyesiqiu**,不是 quintubits。

## 三、eBPFDexDumper(Go 版)用法与 hook 详解

### 3.1 构建与命令

```bash
# 需要 Go 1.19+ 与 Android NDK
./build_env.sh && ./build.sh
adb push eBPFDexDumper /data/local/tmp/

# 主命令:dump(注意 -u 是 uid 不是 pid)
eBPFDexDumper dump -n com.example.app            # 按包名
eBPFDexDumper dump -u 10223                       # 按 uid 过滤
# 常用 flag:
#   --libart   默认 /apex/com.android.art/lib64/libart.so
#   --out      默认 /data/local/tmp/dex_out
#   --trace              实时方法执行跟踪
#   --clean-oat          默认 true:先删 /data/app/.../<pkg>/oat/,避免 cdex/空结果
#   --auto-fix           默认 true:退出时自动修复
#   --execute-offset / --nterp-offset / --register-natives-offset  手动指定偏移
eBPFDexDumper fix    -d <dir>      # 修复 dump 下来的 DEX 头/结构
eBPFDexDumper dumpso -n <pkg> --watch   # dump native so(--lib 过滤 --anon 匿名 ELF)
eBPFDexDumper fixso  -d <dir> -s jni_symbols_xxx.txt   # 修 so 段表+回填 JNI 符号
```

输出:`dex_<begin>_<size>.dex`、`dex_..._code.json`(方法字节码)、`fix/`、`so_<pid>_<base>_<size>_<name>.so`、`jni_symbols_<module>.txt`。

### 3.2 dump 子命令实际挂的 probe

| probe | 作用 | 参数形态 |
|---|---|---|
| `art::interpreter::Execute` | 解释执行入口,拿 ShadowFrame→ArtMethod | PARM3=ShadowFrame* |
| `ExecuteNterpImpl` | Nterp 快速解释器入口 | PARM1(x0)=ArtMethod* |
| `nterp_op_invoke_*`(多站点全挂) | invoke 指令处理,补 nterp 盲区 | PARM1=ArtMethod* |
| `art::JNI<>::RegisterNatives` | JNI 动态注册符号恢复 | PARM3=JNINativeMethod*,PARM4=count |

Nterp handler 源码逻辑(go_bpf.c `uprobe_libart_executeNterpImpl`):x0 取 ArtMethod → `+0x8` 读 dex_method_index、`+0x0` 读 declaring_class(**4 字节压缩引用**)→ `declaring+0x10` dex_cache → `dex_cache+0x10` DexFile(**untag 后**)→ `DexFile+0x8` begin(**untag 后**)→ `begin+0x20` file_size → 校验首字节 `0x64`('d')、size ∈ [0x70, 512MB] → `bpf_map_lookup_elem(dexFileCache_map)` 按 begin 去重 → ringbuf 发 `dex_event` + `submit_dex_chunks_partial` 分片流式传输 → `read_method_bytecode` 抓方法体。

### 3.3 RegisterNatives 偏移自动识别(三级)

1. 手动 `--register-natives-offset`;
2. libart 符号表/dynsym 扫描(优先 `art::JNI<false>` 实例化符号);
3. 字符串 xref:AOSP 警告串 `"This is slow, consider changing your RegisterNatives calls."`(失败再用另一 JNI 警告串),解析引用处的 ADRP+ADD/ADR 指令求地址,并在 JNINativeInterface 函数表中取**紧邻 UnregisterNatives 的槽位**定案。

handler 侧(go_bpf.c `uprobe_libart_registerNatives`):按 64 位 24 字节步长(`name+0 / sig+8 / fnPtr+16`)遍历方法数组(上限 512),ringbuf 逐条发 `{fn_ptr, name, sig}`;用 **TGID**(线程组长寿命)而非 TID,保证 Go 侧事后还能拿 `/proc/<pid>/maps` 解析 fn_ptr 所属模块。32 位目标(12 字节结构)读失败会安全丢弃而非发错符号。

### 3.4 dumpso / fixso

- `dumpso` **不走 eBPF**:解析 `/proc/<pid>/maps`,把散落的 r--/r-x/rw- 映射合并成完整 so,`process_vm_readv` 读取;用 `\x7fELF` magic 识别匿名映射的自解密 so;`--watch` 周期轮询运行时才解密的模块。
- `fixso` 从 `.dynamic`(DT_SYMTAB/STRTAB/GNU_HASH/RELA/RELR/JMPREL)重建 section header table,让 IDA/Ghidra 认符号;支持 ARM64/ELF64、ARM32/ELF32、APS2/RELR 打包重定位;PT_DYNAMIC 缺失时退化用 p_offset 归一化。思路致敬 SoFixer。JNI 符号经 `fixso --symbols` 注入。
- cdex:能识别并提示,但**不做 cdex→dex 完整转换**,README 建议转 vdexExtractor。

## 四、ART hook 入口形态:x1-DEX-begin 实证

依据 eBPFDexDumper-rs `src/art.rs` 与 `bpf/bpf.c` 源码。

### 4.1 共享同一 BPF handler 的「x1 = DEX begin」入口

rs_bpf.c `uprobe/libart_dexFileCtor` 原文注释:*"DexFile::DexFile constructor. On AArch64 C++ ABI, x1 is base."* handler 只做:`begin = PT_REGS_PARM2(ctx)`,再 `looks_like_dex_header()` 验 magic/header 后发事件。

两个符合该形态的符号(art.rs `is_art_dex_file_constructor_symbol`):

```text
_ZN3art7DexFileC1/C2   DexFile::DexFile(const uint8_t* base, size_t size, ...)
                       ABI: x0=this, x1=base, x2=size        → x1 直接是 DEX 起始
_ZN3art13DexFileLoader7OpenOne
                       OpenOne(uintptr_t base, uint32_t size, OatDexFile const*, ...)
                       ABI: x0=this(DexFileLoader*), x1=base, x2=size
                       → 与 ctor 同 x1=base 形态,同一个 uprobe 程序直接复用
```

关键背景(源码注释原文):**Android 16/17 把 DexFile 构造函数剥符号/内联掉了**,此时回退挂 `DexFileLoader::OpenOne`;注意多数剥离 libart 里该符号在 dynsym 中 `st_value=0`(仅导入占位),attach 会跳过,只有 ROM 真导出地址时才能挂上。

### 4.2 RegisterDexFile:从 DexFile* 读信息

`ClassLinker::RegisterDexFile(DexFile const&, ObjPtr<ClassLoader>)`:**PARM2(x1) = DexFile\***(引用形态,传裸指针),handler 从该指针读 begin/size。符号匹配**钉死后缀** `_ZN3art11ClassLinker15RegisterDexFileERKNS_7DexFile`,防止误挂到 `unique_ptr<DexFile>` 重载——那个重载的 x1 不是裸 DexFile*,ABI 假设会崩。

### 4.3 Nterp 入口:纠正——不是 x1=DEX begin

注意:有说法称「Nterp 解释器入口也符合 x1 位置可取得 DEX begin」,**实测不成立**:

- `ExecuteNterpImpl` / `ExecuteNterpWithClinitImpl` / `nterp_op_invoke_*`:**PARM1(x0) = ArtMethod\***,DEX 地址要靠链式解引用:ArtMethod `+0`(4 字节压缩 declaring_class)→ Class `+0x10` dex_cache → DexCache `+0x10` DexFile → `+0x8` begin。
- `art::interpreter::Execute`:**PARM3 = ShadowFrame\***,经 `shadow_frame.method` 偏移拿 ArtMethod。
- 「x1 直接是 DEX begin」的形态覆盖 **DexFile::DexFile ctor 与 DexFileLoader::OpenOne**(二者可共用同一 BPF handler);注意 A15+ 的 OpenOne 真实首参是 `size_t header_offset`(见 11 区 dex 链的版本符号表),真机上 x1 语义随版本可能漂移,写 BPF 前先在目标 ROM 验证寄存器;RegisterDexFile 是「x1 是 DexFile*」再解引用。三类别混用。

### 4.4 偏移探测兜底链

符号匹配(`name.contains("3art")&&contains("11interpreter")&&contains("7Execute")`)→ 失败则字符串 xref `"Interpreting "`(IDA 里同样技巧:搜串、选 6 参数引用函数)→ 再失败 ARM64 字节模式扫 `ExecuteNterpImpl` 前导序列 → `ExecuteNterpWithClinitImpl` 从 ExecuteNterpImpl 分支扫描。Android 15+ 把 `art::interpreter::Execute` 剥符号/内联进 nterp 主入口,**Execute 挂不上属正常**,nterp 覆盖主路径即可;Android 13 无独立 WithClinit 变体(clinit 屏障在 ExecuteNterpImpl 内)。

### 4.5 两条 ART 硬规矩(写 handler 必守)

1. **压缩引用**:64 位 ART 的对象引用默认是 32 位 `HeapReference`(compressed),ArtMethod 的 declaring_class 只能按 `u32` 读,再零扩展成指针——按 8 字节读必错。
2. **untag**:每次解引用前过 `untag()` 清 ARM64 顶字节(MTE tag / PAC pointer code),`begin`、`dex_file_ptr`、code_item 指针全都要过,否则带 tag 地址读内存直接失败。

## 五、eBPFDexDumper-rs:数据流与修复管线

Rust + Aya 实现,Android 13+ 默认布局;API 35 部分 ROM JNI 自动定位不准,需 `--register-natives-offset` 手动给。

### 5.1 端到端数据流

```text
uprobe 命中(Execute/Nterp/dexFileCtor/RegisterDexFile/verifyClass/RegisterNatives
            + libc memcpy/memmove/mmap/mprotect 的 uprobe+uretprobe)
  → bpf_probe_read_user 读寄存器+用户态内存(BPF 侧只做分类:DEX 发现/方法捕获/native buffer)
  → 多个 ringbuf(method_events / 事件 / 分块 / debug / native)
  → Rust 用户态持续 drain
  → 按 DEX begin 地址去重 → 分块拼装 → fix.rs 回填字节码 → 重算校验和 → jadx/baksmali 可直接处理
```

probe 三档模式:`full`(默认,解释器+生命周期+libc,有卡顿)/ `lifecycle`(仅生命周期,无感)/ `maps-only`(不加载 BPF,纯扫 maps)。libc 的 memcpy/memmove 挂了 **uprobe+uretprobe 成对**(入口取参数、出口取返回值)——这就是「native buffer 操作」观察点的实现方式。

### 5.2 修复管线七步

1. **分块拼装**:`DEX_READ_CHUNK=4096` 逐块读,`DEX_CHUNK_HEADER_SIZE=24` 的 chunk 头带 offset/size,乱序到达也能拼;
2. **缺页兜底**:`bpf_probe_read_user` 不能触发缺页——探测时未驻留内存的页读不到,用户态对 miss 的 offset 用 `process_vm_readv` 补读(Go 版同款:`[dex-fallback] eBPF read miss at offset ... trying process_vm_readv`);
3. **去重**:按 DEX begin 地址索引,重复事件不重建条目;
4. **CodeItem 反扫**:`CODE_ITEM_BACKSCAN_LIMIT=64MB`、`STEP=0x1000`,method 事件的 code_item 指针为 0 时按方法线索回扫;
5. **方法字节码回填**:dump 的 `dex_..._code.json` 与 DEX 匹配,把执行过的方法 code_item 写回 DEX(fix 子命令);
6. **校验和重算**:SHA-1 覆盖 `dex[32..]`(signature 字段)、Adler-32 覆盖 `dex[12..]`(checksum 字段)——不重算 jadx/baksmali 直接报坏文件;
7. **结构校验**:`repair` 只做有界结构+校验和检查,非零退出码报失败;输出 `fix/`、`final/`、`missed.json` 覆盖率报告。每进程隔离命名 `dex_<pid>_<begin>_<size>.dex`(十六进制),每次跑建议换空目录。

### 5.3 子命令

`dump`(默认 full 模式退出时自动 repair 到 `repair/`)、`fix`(回填字节码,汇总进 `final/`)、`repair`、`dumpso`、`fixso`(修 so 段偏移)、`offsets`(检查 ART 布局偏移)。正常退出会排干 JNI/事件队列,第二次停止信号才中断排空。

```bash
sh build_android.sh
adb push target/aarch64-linux-android/release/eBPFDexDumper /data/local/tmp/
adb shell su -c '/data/local/tmp/eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

## 六、与 frida dump(库内 DefineClass 法)对比

对比对象:本 wiki `dex脱壳.md` 第四节(hook `ClassLinker::DefineClass`,args[5]=DexFile,读 begin_/size_ 落盘)。

| 维度 | frida DefineClass 法 | eBPFDexDumper / -rs |
|---|---|---|
| 注入形态 | frida-server+ptrace 注入 agent 进目标 | bpf() 加载进内核,目标零注入 |
| 隐蔽性 | 差:maps/线程名/端口/TracerPid 全可被扫 | 好:上述面全缺失,仅内核 tracing 接口可见(需 root) |
| 环境依赖 | root 或可调试 app,frida 环境 | root + 内核 CONFIG_UPROBES/BTF,ARM64,特定 Android 版本偏移 |
| 挂点 | DefineClass 单点,符号随版本变要手改 | Execute/Nterp/dexFileCtor/OpenOne/RegisterDexFile/verifyClass 多点+libc,自动偏移识别链 |
| 抽取壳方法体 | 拿不到(没执行的方法是 nop) | 同样只拿到执行过的(但 nterp_op_invoke 全站点+方法字节码回填,覆盖率高) |
| dump so/JNI | 另写脚本 | dumpso/fixso/jni_symbols 一条龙 |
| 修复 | 手工修 magic/checksum | 自动 fix/repair+SHA-1/Adler-32 重算 |
| 失败模式 | anti-frida 检测杀进程;符号不匹配静默失败 | 偏移识别错(需手动 offset);内核不支持;cdex 不转换;full 模式卡顿影响时序 |
| 上手成本 | 低(现成脚本) | 中(要懂内核/偏移,版本敏感) |

结论:目标有 anti-frida/风控强 → eBPF;快速临场、无对抗 → frida 脚本最快。两者产物可互补(eBPF 拿隐蔽 dump,frida 做后处理分析)。

## 七、生态其他工具

### 7.1 FART:Android 12-16 失效问题

FART(FUPK3 的 ART 延续,hluwa)靠**修改 ART 源码刷机**,在 `dumpArtMethod` 里主动调用全部方法再 dump CodeItem。失效根因:① `ArtMethod` 字段布局硬编码(`entry_point_from_quick_compiled_code_`、`dex_code_item_offset` 等),Android 12+ 布局/访问方式(Accessor 化)全变;② ClassLinker→Invoke 执行链改动,主动调用时机触发不了;③ odex/vdex 布局升级,内容可能只在 vdex 里且是 compact dex。原版实测在 Android 10(LineageOS 17.1)已是移植上限,12-16 需按新 AOSP 重移植。社区路线:重移植(cyrus-studio 修复实录)、MikRom 集成刷机、Youpk、或直接换 BlackDex/FRIDA-DEXDump/eBPF 方案。

### 7.2 JDex/JDex2:LSPosed 主动调用抽取壳

**JDex/JDex2**(开源 J5now/JDex2):「基于 Xposed/LSPosed 的主动调用抽取壳脱壳工具」。流程:LSPosed 注入目标 → 反射 LoadedApk 拿真实 ClassLoader → 遍历 DexPathList 拿全部 DexFile → **主动调用各类构造方法触发壳回填方法体** → Native 层经 mCookie dump。实测:LSPosed+JDex 批量触发构造函数后 dump,可破 Frida16/Xposed90 被对抗的场景。

### 7.3 RePairip:Pairip(Google 加固)专杀

**RePairip**(Java 17,Apache-2.0):「dump 所有 VMRunner 快照并完整重打包,彻底移除保护层」。

### 7.4 BlackDex:免 root

**BlackDex**(CodingGay):Android 5.0-12,独立 app,零依赖(无 Xposed/Frida/Magisk/root);VirtualApp 式虚拟化 + hook 系统 API;双路输出 `hook_xxxx.dex`(hook 法)/`cookie_xxxx.dex`(DexFile cookie 法);深度模式把内存指向的指令写回 DEX 修 nop 函数体(实验性,慢且可能崩);32/64 位是两个 app。局限:主动调用才能解密的方法修不了、不对抗环境检测。

### 7.5 dpt-shell:抽取壳靶子本体

**dpt-shell**(luoyesiqiu,A5.0+):「hollows out Dex method implementations and reconstructs them at runtime」——函数抽取壳**本身**,是练手/验证脱壳工具的首选靶。配套反制:`dpt-unpacker`(Python)、`dpt-unpack`(Kotlin 静态)、`SuiAnc/dpt-tool`(还原新版抽离)。

### 7.6 BPFDex 论文与 DEX-Tracer

- BPFDex:《Enabling Robust Android Apps Unpacking via Android Kernel》,内核态 eBPF 脱壳,真机+模拟器均有验证。
- **DEX-Tracer**(用户材料,无公开项目):声称「eBPF 拦截 syscall 入口(访问参数)或出口(访问返回值)」。同线索的「libc 代码段扫 ARM 指令特征 `0xE1A0C007`(ARM32 `mov r12,r7`)从 r7 赋值指令提取 syscall 号、对 open/read/mmap2 装 syscall 拦截、原函数指针做 trampoline、IO 透明解密(RC4/XOR 0xAA)」整套属 inline-hook/syscall-hook 老派手法,未见公开项目这么用(0xE1A0C007 指令语义本身可查证,mov r12,r7 常见于 syscall 号装填序列)。

## 八、选型决策

```text
目标有 anti-frida/风控强、可 root 真机  → eBPFDexDumper(-rs 修复更全,Go 版文档全)
目标无对抗、要最快出结果              → frida DefineClass 法(本库 dex脱壳.md)
抽取壳且方法体不全(eBPF/黑盒都不够)   → JDex(LSPosed 主动调用)或重移植 FART
免 root / 模拟器 / 不想刷机           → BlackDex(A5-12)
Pairip(Google 加固)                  → RePairip
练手靶                                → dpt-shell 自加壳再打
学术深读                              → BPFDex 论文
```

