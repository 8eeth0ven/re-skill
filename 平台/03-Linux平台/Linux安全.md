# Linux 安全(知识库 · Linux平台 1001248)

> 对应目录树:Linux平台 [1001248] 共 16 节点(9 个二级)。本文按「原理 → 工具 → 实战 → 代表帖」组织。

## §1 ELF 格式详解 [1001020]

### 1.1 总体布局

ELF(Executable and Linkable Format)是 Linux 平台一切逆向的地基。双视角:链接视角看 Section,执行视角看 Segment。

```
+-----------------------------+ 0x0
| ELF Header (64B/52B)       |  e_ident/e_type/e_machine/e_entry/e_phoff/e_shoff
+-----------------------------+
| Program Header Table        |  执行视角:内核 loader 只认这里(PT_LOAD/PT_DYNAMIC...)
+-----------------------------+
| .text / .rodata / .data    |  ← 节(Section)按功能切分
| .bss(仅占位)/.got/.plt    |
+-----------------------------+
| Section Header Table        |  链接视角:ld/readelf -S 消费(可被 strip 删掉)
+-----------------------------+
```
(自绘 ASCII)

关键差异:**病毒、注入类样本经常删 Section Header Table 或伪造节名**——因为内核加载只依赖 Program Header,静态分析工具却被"惯性地"引导。反向利用:`readelf -h` 看 section 数为 0 但程序能跑 = 典型加壳/感染特征。

- 64 位 ELF Header:`e_phoff`(program header 偏移)、`e_shoff`(section header 偏移)、`e_entry`(入口虚拟地址,OEP 相关)。
- 常用节:`.text`(代码)、`.rodata`(常量)、`.data`(已初始化数据)、`.bss`(未初始化数据)、`.got`/`.got.plt`(全局偏移表)、`.plt`(过程链接表)、`.rela.plt`/`.rela.dyn`(重定位表)、`.dynamic`(动态段信息)、`.init_array`/`.fini_array`(构造/析构回调)、`.interp` 动态链接器路径(`/lib64/ld-linux-x86-64.so.2`)。
- 常用段(Segment):`PT_LOAD`(可加载)、`PT_DYNAMIC`(动态链接信息)、`PT_INTERP`(解释器)、`PT_NOTE`(运行时不需要——**经典感染注入点**)、`PT_GNU_STACK`(NX 标志所在)。

代表帖:
- ELF Format(2020,节结构与运行时视角)
- Linux 可执行文件——ELF 文件分析学习笔记及 C 语言实现(手工解析 ELF;文中专门讨论 PT_NOTE 为何极易被病毒感染利用)

### 1.2 动态链接与重定位

静态看共享库的"符号引用",核心是 `.dynamic` 段里两组指针:`DT_SYMTAB`(符号表 `.dynsym`)+ `DT_STRTAB`(符号名字符串表 `.dynstr`),再配 `DT_JMPREL`(指向 `.rela.plt`)+ `DT_PLTGOT`(指向 `.got.plt`)。

x86-64 重点重定位类型:

| 类型 | 所在表 | 含义 |
|---|---|---|
| `R_X86_64_JUMP_SLOT` | `.rela.plt` | **函数符号**经 PLT 的 GOT 表项,延迟绑定主角 |
| `R_X86_64_GLOB_DAT` | `.rela.dyn` | 已在启动时解析的数据/函数地址 |
| `R_X86_64_RELATIVE` | `.rela.dyn` | 基址重定位(load bias + addend),PIE 用 |
| `R_X86_64_64` | `.rela.dyn` | 绝对地址 64 位嵌入 |
| `R_X86_64_COPY` | `.rela.dyn` | (32 位传统)libc 变量拷贝进 .bss,64 位已基本绝迹 |

逆向意义:找"程序调了哪些 libc 函数"就 dump `.rela.plt`(`objdump -R` / `readelf -r`);GOT Hook(改函数指针)与 GOT 保护(RELRO:Full 把 `.got` 变只读)的攻防全在这张表上。

代表帖:通过 ELF 函数劫持,理解 Linux 系统的动态链接生命周期(2024,从 ELF 感染算法切入动态链接全流程)、ELF Hook 总结与代码实现(`.rela.plt`/`.rela.dyn` 修改实战)。

### 1.3 GOT/PLT 延迟绑定(手推一遍)

```
call printf@plt
  └─ printf@plt:  jmp *GOT[n]        ← 第一次:GOT[n] 指向 plt[0]push 序列
       ┌─(首次)──────────────────────┐
       │ push reloc_index           │ plt 尾巴
       │ jmp  plt[0]                │
       │   push link_map            │
       │   jmp  _dl_runtime_resolve │ ← ld.so:查 .dynsym+.dynstr
       └────────────────────────────┘
  解析后 GOT[n] = 真实 printf 地址
  第二次起:jmp *GOT[n] 直达 libc
```
(自绘 ASCII)

要点:
1. 延迟绑定 = 把符号解析开销推迟到首次调用,`LD_BIND_NOW=1` 可强制启动时全解析(配合 Full RELRO)。
2. 逆向时机技巧:断在 `_dl_runtime_resolve` 之后、或让函数被调用一次后,直接 dump GOT 拿真实地址,绕过静态分析只有 stub 的困境。
3. 恶意利用面:GOT 覆写(旧式感染)、伪造 reloc_index 做 **ret2dl_resolve**(无 libc 基址也能解析任意符号,利用归 06 区)。

### 1.4 dlopen/dlsym 内部

- `dlopen(path, flag)`:glibc 里走 `__dlopen` → `_dl_open`(dlfcn/ld.so 内部),核心步骤:mmap 映射加载 → `_dl_map_object` 查找/映射 so → 处理 `DT_NEEDED` 依赖树 → `_dl_relocate_object` 重定位(此时 `R_X86_64_JUMP_SLOT` 按是否 BIND_NOW 决定立即/延迟)→ 执行 `.init_array`。
- `dlsym(handle, name)`:`_dl_sym` → `do_dlsym`,先在 handle 的符号表(含依赖链,受 `RTLD_LOCAL/GLOBAL` 作用域影响)查,查不到再走默认作用域;返回值即真实函数地址——**等于程序自带的一次"符号爆破接口"**,逆向时用它读任意导出符号。
- 实战钩子:LD_PRELOAD/LD_DEBUG=all 是逆向三大免费武器:第一个改行为,第二个把 ld.so 的符号查找、绑定过程全部打日志。
- Android 侧变体:`/system/bin/linker`(bionic)完成同样的事,流程帖:浅谈 ELF 可执行文件的启动流程。

### 1.5 加载视图(执行链)

`execve` → 内核 `load_elf_binary`:读 ELF Header → 按 `PT_LOAD` 逐段 mmap(load bias = 随机基址,PIE)→ `PT_INTERP` 找到 ld.so 并把它也映射 → 转 ld.so 入口 `_start`→`_dl_start`→`_dl_start_user`:重定位、初始化、跑 `.init_array`、最后 jump `e_entry`。**逆向加壳样本时,真正的 OEP 就是最后那个 jump 的目标。**

### 1.6 自实现 Linker(软件开发节点 [1001347] 的顶流)

社区经典路线:理解 ELF 最好的方式是手写 loader/linker。代表帖:
- 从零手写 ARM64 自定义 Linker:自己解析 ELF、映射段、处理重定位、跑 init_array——把 §1.1~§1.5 全部代码化。
- 把 .o 变成 .ko(三):自己写 Loader 才知道的事:ELF 格式转换 + 自写 Loader,链接视角与内核加载视角的缝合篇。
- 工具级:elfspirit:Linux 平台下的静态分析和注入框架(2021,支持增删 section、静态注入 so——本身就是"用工具复刻 linker 行为")。

## §2 Linux 逆向工具 [1001459/1001460/1001480/1001481]

### 2.1 GDB 体系(GDB [1001481])

| 层 | 内容 |
|---|---|
| 原生 | `break/watch/catch`(catch syscall/load)、`info proc mappings`、`disas`、`x/`、`generate-core-file`、`set follow-fork-mode`、`checkpoint`(fork 快照回滚)、`gdb --args`、远程 `target remote :1234`(gdbserver/qemu -g) |
| GEF | 一屏装机量最大:上下文面板、`heap`/`pattern`、checksec 集成、ROP gadget 搜索 |
| pwndbg | CTF pwn 向最强:pwntools 亲和、`vmmap`/`telescope`/`find_fake_fast`、调试 heap 的 `vis_heap_chunks` |
| 选择 | 分析恶意样本/大程序用 GEF;打 pwn 用 pwndbg;两者只装一个(都钩 prompt,混装冲突) |

### 2.2 GDB Python 自动化

GDB 内置解释器直接 `import gdb`,无需装任何模块。核心 API:

```python
class ScanBP(gdb.Breakpoint):          # 类断点:停了自动做事
    def stop(self):
        v = gdb.parse_and_eval("$rdi") # 取寄存器/表达式
        s = gdb.selected_inferior().read_memory(int(v), 64).tobytes()
        open("dump.bin","ab").write(s)
        return False                   # 不真正停,继续跑 → 无感批量 dump

gdb.execute("set pagination off")      # 跑任意 gdb 命令
gdb.events.stop.connect(on_stop)       # 事件回调:断点/信号/退出
gdb.write(gdb.execute("info functions", to_string=True))  # 捕获输出
```
用法三种:命令行 `-ex "source sc.py"`;gdb 内 `source`;`~/.gdbinit` 常驻。典型场景:循环读写内存、批量下桩、脱壳时"循环 dump+比对"直到内存不再变化(找 OEP 自动化的雏形)。
代表帖:gdb——结合 python 自动化调试(2024-01)。

### 2.3 DynamoRIO [1001461] 与静态工具

- **DynamoRIO**:运行时插桩框架(DBI),Linux 原生支持好。写 client(回调 `dr_register_bb_event`)对每个 basic block 做事:统计执行覆盖率、trace 指令、监控 syscall——恶意样本行为分析的全量记录器,和 Frida(DBI 同类、hook 粒度更细)互补。同类还有 Intel Pin、Valgrind。
- **radare2**:命令行开源逆向全家桶:`r2 -A` 分析,`aaa`/`pdf`/`axt`(xref)/`izz`(字符串)/`/r`(搜 gadget)。脚本用 r2pipe(Python);图形前端 Cutter。适合服务器上无 GUI 的快速 triage,和 IDA/Ghidra 互补。架构支持广(含 MIPS/ARM——IoT 样本首选之一)。(专题帖:nYale 翻译三部曲《radare2入门》/《radare2进阶》/《radare2高阶》——译自 megabeets.net 系列(1=入门,2=进阶写 exp,3=分析 ROM),另有《使用radare2进行调试》、《RADARE2+FRIDA搭建》、《Radare2文档》)
- **静态辅助**:`readelf -a/-r/-S`、`objdump -d/-R`、`nm -D`、`strings -a`、`file`、checksec(看 NX/Canary/PIE/RELRO——分析前第一枪)、010 Editor(带 ELF 模板)。

### 2.4 分析环境(基础操作 [1001353])

最小集:`file/readelf/objdump/strings/ltrace/strace/gdb/python3`;进阶: qemu-user(跨架构跑 MIPS/ARM ELF,-g 挂 gdb)、binutils 工具链、angr(符号执行,详见基础知识区 [1001369])。容器化分析环境是这两年的主流做法(见《其他平台.md》§3)。

## §3 Linux 反调试与追踪

### 3.1 ptrace 体系(反调试的心脏)

ptrace 是 Linux 唯一的"原生调试协议",strace/gdb/ldb 全基于它:
- `PTRACE_TRACEME`:子进程自我声明"被父进程 trace"→ fork 自检型反调试常用。
- `PTRACE_ATTACH/SEIZE`:附加目标;`PTRACE_PEEKTEXT/POKETEXT`:读写内存(断点即 0xCC + POKETEXT);`PTRACE_GETREGS/SETREGS`;`PTRACE_CONT/STEP`;`PTRACE_SYSCALL`:syscall 级拦截(strace 的实现)。
- 反调试四板斧(样本侧):
  1. **占坑**:进程启动即 fork 子进程,子 `PTRACE_TRACEME` 父再 ptrace 自己——同一进程同一时刻只能被一个 tracer 附加,gdb 再附加就 EPERM。
  2. **自检**:读 `/proc/self/status` 的 `TracerPid:` 字段,非 0 即被调试。
  3. **时间差**:rdtsc/`clock_gettime` 两侧取差,断点停顿放大差值。
  4. **int3 自校验**:对自身 .text 做 CRC,0xCC 污染即发现硬件/软件断点。
- 破法:内核源码视角理解检查逻辑后 patch/绕过;或"用 ptrace 打 ptrace"。

代表帖:
- 某车联网 APP 梆反调试分析(2023,ptrace 占坑原理与实现)
- 一道带 ptrace 反调试的 CTF 逆向题目分析(Linux 反调试实战入门范本)
- 【从源码过反调试】二、过 PTRACE_TRACEME(从内核源码分析原理与绕过)
- 使用 ptrace 过 ptrace 反调试(以毒攻毒)

### 3.2 strace / ltrace / perf

| 工具 | 挂点 | 逆向用途 |
|---|---|---|
| strace | ptrace(PTRACE_SYSCALL) | 看样本摸了哪些文件/网络/进程——行为画像第一枪;`-f` 跟子进程,`-e trace=file,network` 过滤 |
| ltrace | 断在 PLT | 库函数级追踪(原理即 §1.2 的 PLT 拦截,所以对静态链接/手写 syscall 的样本失效) |
| perf | perf_event(非 ptrace) | 采样热点:找加密函数/校验循环的位置,`perf record -g` + 火焰图 |

配合:`/proc/<pid>/maps` 看段映射(找 so 注入、找 dump 范围)、`/proc/<pid>/fd` 看打开的文件。样本会检测 strace(附加会被 TracerPid 暴露)→ 高隐蔽需求走 §3.3 的模拟执行。

### 3.3 信号与多进程

Linux 下"异常"= 信号(SIGTRAP/SIGSEGV/SIGILL)。调试器靠 SIGTRAP 拿回控制权;反调试就伪造信号流(自己 `raise(SIGTRAP)` + 预埋 handler 判断是否真调试器)。多进程样本:daemonize(fork 两代)+ 父子互 ptrace 是 Linux 壳的主流防身组合,gdb 侧用 `set follow-fork-mode child` + `detach-on-fork off` 应对。

## §4 UPX 与 Linux 壳

### 4.1 UPX 结构(Linux ELF 版)

```
原文件: [ELF头|原段们|........]  --压缩-->
UPX文件:[ELF头|PT_LOAD×2|UPX stub|压缩数据(LZ/NRV)]
              │         └── 解压后 mmap RWX 区,自恢复 section
              └── 入口指向 stub;特征串 "UPX!" / "$Info: This file is packed..."
```
(自绘 ASCII)

- stub 逻辑:mmap 解压目标区 → NRV/LZMA 解压原段 → 重建原入口跳转 → (卸载壳痕迹)。特征:`readelf` 只剩 2 个 PT_LOAD、入口点在壳代码段、尾部 `UPX!` 魔数。
- `upx -d` 直接还原(前提:未改魔数/未抹特征;样本常改 `UPX!` 为垃圾字节让 -d 拒绝,手工改回即可)。
- 变体对抗:UPX 加 scrambling、修改 l_info/p_info 结构、双重 UPX(套两层)。

### 4.2 Linux 商用/恶意壳生态

与 Windows 的 VMProtect/Themida 对应,Linux 侧:UPX 改造壳(挖矿样本最爱,魔数抹改)、自研压缩壳(IoT 样本常带 MIPS/ARM 版 UPX)、加解密 stub(勒索样本运行时解密 payload)。详见 §6 脱壳。

## §5 Linux 恶意软件 [1001394]

### 5.1 ELF 病毒(感染式)

与木马(独立进程)不同,病毒寄生宿主文件。经典感染算法四型:
1. **数据段注入(注入 padding/空洞)**:把病毒体塞进 `.text` 后的对齐空洞或数据段,改 `e_entry` 指过去,执行完再跳回原入口——**不增大文件体积**,隐蔽性最强。社区代表帖:ELF 数据段注入 virus 分析(2024-09:宿主运行时病毒代码与宿主代码一起映射进进程空间,病毒先跑、找下一个宿主、再交还控制权)。
2. **PT_NOTE 覆写**:把运行时无用的 PT_NOTE 段改成 PT_LOAD 并注入代码(§1.1 提到,有原理)。
3. **追加新节**:加 section/segment,文件变大但结构最稳(elfspirit 支持增删 section 即此理)。
4. **函数劫持**:改 GOT/符号指向,如 通过 ELF 函数劫持理解动态链接生命周期。
早期讨论:对网上一个 ELF 文件感染的小代码理解。

### 5.2 物联网/僵尸网络样本(Mirai 系)

- **Mirai**(2016):telnet 字典暴破感染,感染后扫描扩散 + DDoS。结构特征:多架构交叉编译(x86/ARM/MIPS)、表驱动字符串混淆(索引表 XOR 解密)、watchdog 关闭、随机删除自身。分析入门首选,大量变种(RapperBot、Sora、Gafgyt/Bashlite)只是换了字符串表与 C2 协议。
- **RapperBot**:不走 telnet 而是暴破 SSH,代表帖 RapperBot,你在酝酿什么?。
- 宏观趋势帖:SSH 暴力破解趋势:从云平台向物联网设备迁移(植入恶意文件超 50% 是 ELF,x86 占 63%)。
- 体系化教材:ELF 恶意软件分析 101:Linux 威胁防御不再滞后(2020 翻译长文,Mirai 为典型案例)。

### 5.3 挖矿/勒索/Rootkit

- 挖矿:样本量最大的类别,UPX 壳 + `kworker` 伪装 + crontab 持久化,代表帖 双系统挖矿,新型 AutoUpdate 挖矿病毒分析。
- 勒索:RaaS 移植 Linux 侧,如 Sodinokibi(REvil) 勒索病毒攻击 Linux 平台(重点看密钥生成与文件遍历加密路径)。
- Rootkit:用户态(LD_PRELOAD 劫持)与内核态(LKM,eBPF 型新变种),案例 服务器被黑,安装 Linux RootKit 木马。检测对抗与内核机制见 §7。

## §6 Linux 脱壳 [1001376/1001377]

### 6.1 通用流程(Linux 版四步)

1. **找 OEP**:壳解压完跳回原始入口。手法:`catch`(在 `mprotect`/`brk`/write 返回处下断)、入口断点 + 单步跟 jump 链、或 gdb python 自动化"周期性 dump .text 段,内容稳定即 OEP"(§2.2 代码思路直接复用)。
2. **Dump**:进程内存里把各 PT_LOAD 段拉回文件(`gdb dump binary memory` / 自写 /proc/pid/mem 读取器;Linux 不需要 Windows 式的 ImpREC)。
3. **修复**:重建 section 头(或干脆无节表——Linux 能跑)、修正 `e_entry`=OEP、把动态段的 `DT_JMPREL` 项还原成 PLT 未绑定初值(或直接 LD_BIND_NOW 跑一次后 dump,GOT 即完整)。
4. **验证**:能执行 + `strace` 行为与原样本一致。

Linux 脱壳比 Windows 舒服的根因:**动态链接信息在 .dynamic/GOT,运行时自洽**;dump 出来的映像天生带已解析符号,不需要"重建输入表"这一步。

### 6.2 UPX 实例 [1001378]

- 快速道:`upx -d sample -o unpacked`(抹了魔数的先 hex 改回 `UPX!`)。
- 手动道(教学价值):gdb 跑到 stub 解压完 → 断在跳 OEP 的 jmp → dump 三段 → 修 ELF 头。语料有多篇 UPX 脱壳实例帖(树节点 1001378 专设; Windows 侧:《upx脱壳及附加数据处理》、《UPX加壳的DLL》、《unUPX.dll插件的逆向》——Linux 侧专帖站内可检)。
- 与 SMC 补丁联动:不脱壳直接内存补丁(gdb `set {char}addr=0x90`),适合只改一两个跳转的破解场景——Linux 破解主流做法,免重建文件。

## §7 系统内核入口 [1001348](机制与逆向,利用归 06)

### 7.1 逆向入口

- **vmlinux 提取**:`/boot/vmlinuz` 是压缩过的 → `extract-vmlinux` 脚本解压出带符号 vmlinux;发行版可装 `dbgsym` 包。无符号场景:`vmlinux-to-elf`(从 kallsyms 表重建符号)是标准武器。
- **kallsyms**:`/proc/kallsyms` 暴露内核符号地址(受 `kptr_restrict` 限制,root 或调 0 才见真值);提取脚本/模块开发都靠它。
- **源码**:`/usr/src` 或 elixir.bootlin.com 在线读。逆向 so 看的是 ld.so,逆向内核看的就是这些入口。

### 7.2 与用户态逆向的接口

- 系统调用:syscall 表(sys_*)是用户态样本行为的"最终去向";`strace` 即其用户态镜像(§3.2)。
- LKM(可加载内核模块):`.ko` 本身就是 ELF(ET_REL),逆它 = 逆链接视角的 ELF + 内核符号。`把 .o 变成 .ko` 系列正是这条链的玩法。
- `/proc`、`/sys`、netfilter、eBPF:Rootkit 挂载面;检测侧(取证)同样从这些机制的"被篡改痕迹"入手。

### 7.3 边界声明

提权链、内核堆利用、模块加载漏洞利用 → 全部见 **06-二进制漏洞 区**(Linux Kernel Exploit 学习 [1001433]、实战 [1001442]、CTF Linux内核态利用 [1001691])。

## §8 虚拟机与模拟 [1001266]:Qiling / Unicorn 在 Linux ELF 上

### 8.1 两层栈

- **Unicorn**:纯 CPU 仿真(QEMU TCG 拆出来的引擎),只有指令层——没有 syscall、没有内存布局。逆向用途:单函数仿真(爆破注册码、模拟执行解密例程)、伪造堆栈喂参数。知识库 Android 区有 Unicorn 专题 [1001648],方法直接平移。
- **Qiling**:在 Unicorn 之上补齐"操作系统层"——ELF loader、rootfs 路径重定向、syscall 仿真、动态库加载。于是可以:在 x86 机器上直接跑 MIPS/ARM 的 Linux ELF 恶意样本,不碰真机。

### 8.2 Qiling 逆向工作流

```python
from qiling import Qiling
ql = Qiling(["/samples/arm_bin"], "/rootfs/armhf")  # rootfs 提供 libc 等
ql.hook_address(oep_cb, 0xADDR)      # 地址钩子:到 OEP dump
def sys_hook(ql, syscall_id, params):  # syscall 钩子:行为画像
    log(params)
ql.os.set_syscall(0x1000, sys_hook)
ql.run()
```
价值:①跨架构样本分析;②**天然反反调试**(没有 ptrace,TracerPid 永远 0,时间差可调时钟);③模拟器内脱壳(等解压完成 dump,环境完全受控)。局限:rootfs 依赖匹配、部分 syscall 未实现需自补。

代表:
- 初探 Qiling framework(2024-11)
- Qiling 框架模拟运行固件配合 IDA 动态调试(Qiling + IDA 联动)
- 智能硬件版块精华汇总(Qiling/固件分析索引总入口)

## §9 参考速查

| 主题 | 资料 | 链接 |
|---|---|---|
| ELF 格式 | ELF Format |  |
| ELF 格式 | ELF 文件分析学习笔记及 C 实现 |  |
| 动态链接 | ELF 函数劫持理解动态链接生命周期 |  |
| ELF Hook | ELF Hook 总结与代码实现 |  |
| 启动流程 | 浅谈 ELF 可执行文件的启动流程 |  |
| 自实现 Linker | 从零手写 ARM64 自定义 Linker |  |
| Loader | 把 .o 变成 .ko(三):自己写 Loader |  |
| ELF 工具 | elfspirit 静态分析与注入框架 |  |
| gdb python | gdb——结合 python 自动化调试 |  |
| 反调试 | 某车联网 APP 梆反调试分析 |  |
| 反调试 | 带 ptrace 反调试的 CTF 逆向题 |  |
| 反调试 | 从源码过反调试:过 PTRACE_TRACEME |  |
| 反调试 | 使用 ptrace 过 ptrace 反调试 |  |
| ELF 病毒 | ELF 数据段注入 virus 分析 |  |
| ELF 病毒 | ELF 文件感染小代码讨论 |  |
| 恶意软件 | ELF 恶意软件分析 101 |  |
| 恶意软件 | RapperBot 分析 |  |
| 恶意软件 | SSH 暴破趋势(ELF 占比) |  |
| 恶意软件 | Linux RootKit 木马案例 |  |
| 恶意软件 | Sodinokibi 勒索攻 Linux |  |
| 恶意软件 | AutoUpdate 挖矿分析 |  |
| 模拟执行 | 初探 Qiling framework |  |
| 模拟执行 | Qiling 模拟固件 + IDA 动态调试 |  |
| 索引 | 智能硬件版块精华汇总 |  |
