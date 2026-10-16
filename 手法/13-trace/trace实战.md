# trace 实战(全层次跟踪工具:从函数级到指令级到时移回放)

> 主题:什么时候用哪层 trace、怎么真跑、怎么控量、怎么后处理。
> 分工:Stalker 汇编级原理与 transform 写法在 [02-frida/高级/stalker.md](../02-frida/高级/stalker.md),本篇只讲**可跑实操+全景选型+后处理**。
> 环境:macOS arm64(darwin 25.6.0,SIP 开)、frida 17.23.3(`tools-env/.venv/bin/`)、radare2 6.2.4。标「本机实测」的均为 2026-10-16 真跑输出。

## 0. 一句话总纲

trace 的本质是**按层次买信息**:syscall 层买「碰了什么资源」,函数层买「谁调用了谁」,块/指令层买「控制流真面目」,录制回放层买「时间倒流」。层次越深,数据量与减速比越大——**先函数级定位,再降层取证**,不要上来就 Stalker 全开。

---

## 1. trace 全景对比表(选型核心)

| 工具 | 跟踪层次 | 平台 | 开销 | 侵入性 | 输出形式 | 最佳场景 | 最短命令 |
|------|---------|------|------|--------|---------|---------|---------|
| frida-trace | 函数级(libc/任意导出+JNI/OC) | 全平台 | 低(仅被 hook 函数) | 注入 agent | 每调用一行:ms+参数 | 快答「谁调用了 X、传了什么参」 | `frida-trace -p PID -i open` |
| frida Stalker | 基本块/指令级(DBI 重编译) | 全平台 | 高(本机实测 1.5~N 倍减速) | 注入+代码膨胀 | call/ret/block/exec 事件流 | 完整控制流、脱壳 dump、覆盖率 | 见本篇 §3 驱动脚本 |
| QBDI | 指令级(独立 DBI,可与 frida 同会话) | x64/AArch64(0.10.0+) | 高,但纯指令 trace 比 Stalker 快(社区实测) | 注入(经 frida-qbdi 绑定) | 指令回调/基本块事件 | 不想吃 Stalker 膨胀时的替代引擎 | `pip install qbdi` 后 Python 回调 |
| strace | syscall 级 | Linux | 中(ptrace 停走) | ptrace(可被检测) | 每系统调用一行 | 看 IOC:文件/网络/execve 面 | `strace -f -e trace=openat,connect ./bin` |
| ltrace | 库函数级 | Linux | 高 | ptrace | 库调用行 | 看 libc 层调用面 | `ltrace -e malloc+free ./bin` |
| dtruss/dtrace | syscall 级(DTrace 探针) | macOS | 低(内核探针) | 无注入但**SIP 限制** | 每系统调用一行 | macOS 上 strace 等价物,要关 SIP+root | `sudo dtruss -t open ./bin`(SIP 开时被拒,本机实测) |
| `log stream` | 系统日志/统一日志 | macOS | 极低 | 零 | 结构化日志流 | 蓝队视角看进程行为面,免 SIP | `log stream --predicate 'process == "x"'` |
| DynamoRIO | 指令级(DBI,进程外启动) | Win/Linux(无 mac) | 中高 | 无注入,换代码缓存 | 覆盖率/自定义回调 | WinAFL 覆盖引导底座 | `drrun -c winafl.dll -- target.exe`(见 win-vuln 工具链篇) |
| Triton | 指令级+符号执行 | 全平台(Python) | 极高 | 仿真执行 | 指令流+约束+污点 | 自动求解输入、算法还原 | `python -c 'from triton import *; ...'`(ASTContext 逐指令喂) |
| rr | 全 syscall 录制+时移回放 | Linux | 2~20 倍慢 | gdb 远程 | 确定性回放 gdb 会话 | 「只崩一次」的竞态/非确定 bug | `rr record ./bin && rr replay` |
| WinDbg TTD | 全指令级录制回放 | Windows | 高 | 调试器 | .trace 文件,双向单步 | 恶意样本取证、事后 `!analyze` | `windbgx -TTD.exe` 详见平台 01 调试篇 |
| eBPF tracepoint/uprobe | 内核函数/syscall/用户态函数 | Linux 4.x+ | 极低(内核聚合) | 零注入,root | 聚合统计/事件 | 全局观测多进程、蓝队监控、脱壳 | `bpftrace -e 'uprobe:...:func { @[ubpfarg0] = count(); }'`(详见 07 区 eBPF 篇) |
| r2 dts/ESIL | 调试 trace 会话/离线仿真 | 全平台 | 仿真速度 | 零(不碰真进程) | trace session 快照 | 样本不想跑时的静态执行流 | `r2 -q -c 'dts+; 10 aes; dts' -d bin`(ESIL:`aei; aes`) |

注意两点(本机实测纠偏):
- r2 的 `aht` **不是** trace 命令——6.2.4 里它是「把立即数标成结构体偏移」的类型提示;r2 的 trace 面是 `dts`(调试 trace session)、`aes`(单步)与 ESIL `ae*`(仿真执行)。
- QBDI 与 frida Stalker**没有继承关系**:QBDI 是独立 DBI 引擎(稳定版 0.12.1),通过 frida-qbdi 绑定可把 QBDI JS API 加载进 frida 会话(其 JS `QBDI` 类对应 C++ `VM` 类),即「frida 管注入、QBDI 管跟踪」的组合;纯指令级跟踪场景社区报告比 Stalker 快。

---

## 2. 函数级:frida-trace 实操(本机实测)

### 2.1 环境坑三连(macOS)

| 坑 | 现象 | 解 |
|----|------|-----|
| 缓存目录无权限 | `error creating directory ~/.cache/frida/...: Permission denied` | `export XDG_CACHE_HOME=/tmp/xdgcache` |
| SIP 平台二进制 | spawn `/bin/ls` 报 `unable to access process with pid ... from the current user account` | 换非平台二进制(自编译/venv python);`/bin/*`、`/usr/bin/*` 都被 SIP 罩着 |
| spawn 模式无日志行 | 见 §2.3 | 改 attach 模式 |

### 2.2 attach 模式(标准姿势,输出干净)

先自起一个循环开文件的进程,再 attach:

```bash
python3 -c "
import time,os
print('READY', flush=True)
while True:
    open('/etc/hosts').read(); os.stat('/tmp'); time.sleep(0.5)
" &
frida-trace -p <pid> -i open -i stat64
```

本机实测输出(要点):

```
Instrumenting...
open: Loaded handler at "/private/tmp/ft-ls/__handlers__/libsystem_kernel.dylib/open.js"
stat64: Loaded handler at ...
           /* TID 0x103 */
   137 ms  open(path="/etc/hosts", oflag=0x1000000, ...)
   138 ms  stat64(path="/tmp", buf=0x16d4e2050)
   643 ms  open(path="/etc/hosts", oflag=0x1000000, ...)
   ...
```

看什么:相对毫秒(时序)、TID(线程归属)、参数自动解码(path 直接读出字符串)。handlers 目录里每个函数一个 js 文件,模板:

```js
defineHandler({
  onEnter(log, args, state) {
    log(`open(path="${args[0].readUtf8String()}", oflag=${args[1]}, ...)`);
  },
  onLeave(log, retval, state) {}
});
```

改 handler 加 `onLeave(log, retval){ log('ret=' + retval) }` 即回填返回值——**热改生效**,这是 frida-trace 比 strace 强的点:参数语义自己定义。

### 2.3 spawn 模式坑(本机实测,重要)

frida 17.23.3 在 macOS 上 spawn 模式(`frida-trace -f`)虽然 spawn/注入/自动生成 handler 都正常、进程也正常跑完,但**调用日志行一条都不出**(v8/qjs 两个 runtime 都试过,进程跑 4 秒持续 open 也为 0)。attach 模式一切正常。结论:**macOS 上函数级 trace 用「自起进程 + attach」,别赌 spawn**。

### 2.4 通配与模块限定

- `-i open`:按名字精确/通配匹配任意模块导出(`-i 'stat*'` 实测会命中 stat64/statfs64/statvfs/statx_np/stat_with_subsystem 等 7 个)。
- `-I libsystem_kernel.dylib`:**整个模块全函数**——本机实测直接生成 100+ handler,日志被 Auto-generated 洪水淹没,排查时慎用;正确姿势是 `-i` 精确点名或 `-I 模块 -i 名字` 组合。
- Android 目标时函数级还有三层速查:`-j java方法名`(Java 层)、`-I libnative-*.so -i Java_导出名`(JNI 层)、OC 层 `-i "*[Cls method:]"` 通配;Java/JNI/OC hook 细节走 02-frida 区各篇,本篇不重复。

### 2.5 函数级 trace 的判读三问

1. **时序**(ms 列):两次调用间隔≈轮询周期;同一 ms 内连发≈循环体/初始化。
2. **线程**(TID 列):跨线程交替说明有工作线程/handler 线程,深挖前先按 TID 分流。
3. **参数语义**:默认模板只解码第一参,socket fd/结构体指针要手改 handler(读 `args[1]`、`hexdump(args[0], 32)`)——这是 frida-trace 相对 strace 的核心增量:strace 只知道 fd,你能顺着 fd 指针挖到对象。

---

## 3. 块级:Stalker 实操(本机实测)

### 3.1 三个 macOS 大坑(踩过的顺序就是排查顺序)

1. **spawn 挂起期一切无效**:挂起期 load 的脚本,resume 后 `recv()` 回调不触发、follow 也不出事件;换成「Popen 起进程 → sleep 0.4s → attach → load(follow 在 load 时做)」全部正常。
2. **线程选择**:macOS 上 `Process.enumerateThreads()` 只回主线程一个,且 tid ≠ pid(本机恒见 259 这类小号),直接 `[0].id` 即主线程;但**别跟 agent 自己的线程**——跟错线程表现为 0 事件+JS 定时器全灭。
3. **exclude 对共享缓存模块失效**:`Stalker.exclude({base,size})` 排掉 348 个 dylib 后,libsystem_kernel 的事件照样来(dyld 共享缓存地址区不匹配)。**JS 侧 `findModuleByAddress` 过滤才是最终兜底**。

另有事件解析细节:`Stalker.parse(blob, {annotate:true})` 必须开 annotate,否则 e[0] 是地址不是 `'call'/'block'` 类型名。

### 3.2 可复用驱动(scripts/stalker_trace.py)

```bash
# 采集:call+block 事件、只留主模块、3000 条封顶、JSONL 落盘
python3 scripts/stalker_trace.py --target $(which python3) --args workload.py \
    --events call,block --limit 3000 --exclude-all-but-main --filter-main --out ev.jsonl
```

脚本内三大控量开关(对应任务里的 3 个关键参数):

| 参数 | 位置 | 作用 | 实测效果 |
|------|------|------|---------|
| 模块排除 | `Stalker.exclude({base,size})` ×N | 不重编译这些区,防事件爆炸 | 348 个 dylib 排除;但共享缓存模块部分失效→再叠 JS filterMain |
| 事件开关 | `events:{call,ret,block,exec,compile}` | 每级粒度差一个数量级 | call/block 混合 3000 条 16ms 收满;exec 同送达率但目标侧膨胀更狠 |
| 队列缓冲 | `queueCapacity`/`queueDrainInterval` | 事件缓冲区大小与刷出间隔 | 送达管线实测 ~6.5 万事件/秒封顶,见 §5.1 |

本机实测采集输出:

```
[cfg] {"excluded": 348, "keep": "Python"}
[cfg] {"tid": 259, "module": "Python", "base": "0x102260000", "events": ["call","block"], "limit": 3000}
[done] seen=3000 elapsed=16ms
    2747  block
     309  Python!0x187eb4      ← 块热点 top1
     253  call
     104  Python!0x187ee4
     ...
{"type": "block", "at": "Python!0x245cfc"}
{"type": "call", "from": "Python!0x245d04", "to": "Python!0x1c9a10", "depth": -2}
{"type": "block", "at": "Python!0x245d08"}
```

### 3.3 符号化闭环(atos)

`Mod!off` 只是偏移;macOS 用 atos 批量还原(本机实测,热点地址 → 最近导出符号):

```bash
atos -o /path/Python -l 0x0 0x3e9d4 0x256b64 0x25263c
# PyMapping_GetOptionalItem / _io_TextIOWrapper_read / textiowrapper_dealloc ...
```

循环热点链一眼可读:`read 调用链 → TextIOWrapper_read → 对象 dealloc 群`——正是 `open().read()` 的 CPython 机器。trace 完不做符号化=白 trace。

---

## 4. 调用链提取:call 事件 → 树(本机实测)

`scripts/calltree.py` 读 stalker_trace.py 的 JSONL,用 depth 相对值维护调用栈聚合成树+热点+去重率:

```bash
python3 scripts/calltree.py ev.jsonl --top 8 --children 2
```

10 万条 call 事件(本机实测)输出要点:

```
== 调用树 ==
|- Python!0xc39a8 x99988            ← PyObject_GenericGetAttr
|  |- Python!0x256b64 x99981        ← _io_TextIOWrapper_read
|  |  `- Python!0x25263c x99980
|  |     `- Python!0x120650 x99979
|  |        |- Python!0x7fcc0 x99971
|  |        |  |- Python!0x241f74 x99967
== 热点目标 ==
   31244  Python!0x3e9d4            ← PyMapping_GetOptionalItem
== 去重统计 ==
  call 事件总数: 100000
  唯一 from->to 边: 31 (去重率 100.0%)
  唯一目标符号: 27
```

**关键读法:循环型负载 10 万事件只有 31 条唯一边**——trace 数据大爆炸在「时间维度重复」,后处理第一刀永远是 `(from,to) 去重 + 频次`,信息不丢、体积归零。

---

## 5. syscall 级:macOS 怎么办(本机实测)

### 5.1 macOS 原生路径

| 路径 | 状态(本机实测) | 结论 |
|------|----------------|------|
| dtruss | `dtrace: system integrity protection is on` + `DTrace requires additional privileges` | SIP 开着就没戏;恢复模式 `csrutil disable` + root 才可用,代价全系统 |
| dtrace 脚本 | 同上,仅未签名进程+root 部分可用 | 生产机别赌 |
| `log stream` | 正常,`--predicate 'process=="x"'` 过滤 | 零成本兜底,看系统日志面 |
| strace/ltrace | 不存在 | Linux 专属 |

### 5.2 frida Interceptor 模拟 syscall trace(可用等价物)

macOS 的 syscall 经 libsystem_kernel.dylib 导出函数转发(用户态几乎没有裸 `svc` 可 hook,syscall 指令在共享缓存里 hook 不了),所以**Interceptor 挂这一族导出函数 = 用户态 strace**。`scripts/syscall_sim.py`(本机实测,32 个函数挂上):

```
[ready] hooked 32 functions in libsystem_kernel
open           "/etc/hosts"                    ret=3
read           fd=3                            ret=213     ← 字节数
close          fd=3                            ret=0
stat64         "/tmp"                          ret=0
getcwd         ""                              ret=1757872128
access         "/etc/hosts"                   ret=0
write          fd=1                            ret=8       ← 正是 "W2_DONE\n" 8 字节
```

覆盖面按需扩 `fam` 表(openat/fstatat64/posix_spawn/mmap/connect…);fd 类与 path 类参数解码已在脚本里分流(注意 fstat* 第一参是 fd,别被 stat 正则吞了)。与 strace 等价性:能看到同一层信息(路径、返回值、时序),差别是只见 libsystem 转发面、不见内核侧失败细节(errno 级语义要自己读 retval)。
API 提醒:frida 17 删了两参 `Module.findExportByName(mod, name)`,用 `Module.findGlobalExportByName(name)`。

### 5.3 控量实测数字(写死在认知里)

| 实验(同一 8 秒 busy 循环负载) | 数字 |
|------|------|
| 无 attach 基线 | 475687 次 open |
| Stalker call+block 全程跟 | 320607 次 → **减速 1.48 倍**,落盘 458747 事件(≈5.7 万事件/秒) |
| 10 万事件收满耗时(A 无过滤/B exclude+filter/C block-only) | 1524/1522/1521ms——**宿主侧送达管线 ~6.5 万事件/秒是硬顶**,过滤不提速只省盘 |
| exec 事件(全指令级) | 同送达率,目标侧膨胀更狠,快速刷盘 38 万条/6 秒 |

推论:①想快,减**事件产生**(exclude/filter/事件开关),别指望后端;②长跑务必 `--limit` + JSONL 落盘,内存里攒必炸;③指标永远盯「事件/秒」与「目标减速比」两个数。

### 5.4 strace 族速查(Linux,对照记)

| 姿势 | 命令 | 用途 |
|------|------|------|
| 只看面 | `strace -f -e trace=openat,connect,execve ./bin` | IOC 三件套:文件/网络/执行 |
| 统计摘要 | `strace -c ./bin` | 每系统调用次数+耗时排行,先看分布再细跟 |
| fd 还原路径 | `strace -yy ./bin` | fd=3 显示成 `/etc/hosts</etc/hosts>` |
| 追子进程 | `-f`(fork/vfork/clone 全跟) | 样本落地释放器时的标准姿势 |
| 解码字符串 | `-s 4096` | 默认 32 字节截断,read 到的载荷要拉长 |
| 网络载荷 | `-e trace=network -xx` | hex 出收发缓冲(密文面判断) |

macOS 上每一条的等价物:面=syscall_sim.py 的 fam 表;统计=后处理 defaultdict;fd 还原=onLeave 时 `/dev/fd/N` 读链接或自己维护 fd 表(脚本可加 20 行实现)。

---

## 6. 后处理方法论

1. **过滤**(在源头上做):
   - 按模块:exclude 失效就 JS filterMain(§3.1 坑 3);
   - 按线程:只 follow 主线程,业务线程另开一轮;
   - 按深度/频次:树展示时 `--depth-max`、`--children` 截断(calltree.py 内置)。
2. **聚合**:
   - 去重:`(from,to)` 边集——循环负载去重率可达 100%(§4 实测);
   - 热点:块/目标地址频次 top-N(stalker_trace.py 的 done 包直接吐 top15);
   - 符号化:离线 atos / addr2line 批量,别在事件回调里做。
3. **离线分析**:事件 JSONL 落盘后就是普通数据——`grep '"type": "call"'`、python defaultdict 聚合、导入表格画分布;大文件按 `Mod!off` 前缀 grep 即粗过滤。
4. **控量三板斧**(按收益排序):事件开关(call 代替 block 代替 exec)> limit 封顶+早 unfollow > 模块过滤。
5. **覆盖率模式**(不回放、只要去重块集):`events:{compile:true}` 只记 Stalker **编译出的块**(每块只来一次,天然去重),比 block 事件低一个数量级,适合做 fuzz 覆盖引导/脱壳后的执行面清单;要指令级覆盖率才上 exec。

---

## 6.5 trace 工具自己的检测面(对抗场景)

被跟目标带反调试时,选层先看「谁会被看见」(完整检测面矩阵见 [04-对抗攻防/检测原理全景.md](../04-对抗攻防/检测原理全景.md),hook 被干后的绕法走 [12-绕过决策/绕过决策手册.md](../12-绕过决策/绕过决策手册.md)):

| 工具 | 可检测特征 | 隐蔽性排序 |
|------|-----------|-----------|
| ptrace 族(strace/ltrace/gdb) | 目标自查 `ptrace(PTRACE_TRACEME)` 失败、`/proc/self/status` TracerPid | 最差,样本带反调试必炸 |
| frida 注入(trace/Stalker) | 扫线程名/映射名 frida-agent、gum 内存段、task 线程数 | 中;可用 gadget 改名缓解(04 区对抗篇) |
| QBDI(经 frida) | 同 frida 注入面 | 中 |
| DynamoRIO | 代码缓存段(无 frida 特征但有非映像可执行段) | 中 |
| dtrace/eBPF | 内核侧观测,进程内零痕迹;但需要 root/内核权限 | 最好(这就是 eBPF 脱壳篇选它的原因) |
| rr/TTD | 调试器语义,同 ptrace 族但可配反检测 | 差~中 |

一句话:**目标越能打,trace 越往内核层走**;进程内 DBI(frida/QBDI/DR)是给「目标打不动你」或「对抗已胜利」之后的取证阶段用的。

---

## 7. 场景决策树

```
想看「谁调用了 X / X 的参数」──────────→ 函数级:frida-trace attach / Interceptor(§2)
想看「完整执行流/覆盖率/控制流篡改」────→ Stalker call+block 起步(§3),控量三参数
想看「指令级且嫌 Stalker 慢」──────────→ QBDI(frida 会话内并行引擎,§1 表)
想看「系统调用面/资源触碰(IOC)」──────→ Linux:strace/eBPF;macOS:syscall_sim.py(§5)
想看「全局多进程、零注入观测」─────────→ eBPF tracepoint/uprobe(07 区 eBPF 篇)
想「录制后时间倒流、只崩一次的 bug」───→ Linux:rr;Windows:WinDbg TTD(平台 01)
想「不跑样本拿到执行流」─────────────→ r2 ESIL 仿真 / Triton 符号执行(§1 表)
想「自动探索输入(fuzz)」────────────→ DBI 底座:DynamoRIO+WinAFL(win-vuln 工具链)
```

降层纪律:每层拿到的地址/路径/调用点,作为下一层更细 trace 的**锚点**(先 frida-trace 定位函数,再对单函数 Stalker),全进程全指令 Stalker 是最后手段。

锚点降层实例(本机实测路径复盘):frida-trace 发现 open 高频 → Stalker call 事件聚合出 10 万次中的 31 条唯一边 → 热点 `_io_TextIOWrapper_read` → atos 符号化 → 下一轮只对这一个函数 `Interceptor.attach` 下条件断点(参数/返回值/调用栈)。**每一层的产物都是下一层的过滤器**,这就是 trace 的工程本质。

---

## 8. 与既有篇互链清单

| 想深入 | 开哪篇 |
|--------|--------|
| Stalker 汇编级原理/transform/putCallout/卡死排查 | [02-frida/高级/stalker.md](../02-frida/高级/stalker.md) |
| 全链观测点矩阵(L1-L5 每层该挂哪) | [11-链路内核级/观测点矩阵与使用路径.md](../11-链路内核级/观测点矩阵与使用路径.md) 与 [11-链路内核级/进程时序与内存链路.md](../11-链路内核级/进程时序与内存链路.md) §6 |
| eBPF tracepoint/uprobe/bpftrace 实操 | [07-内核级/Android内核与eBPF.md](../07-内核级/Android内核与eBPF.md) |
| eBPF 脱壳(Stalker 的无注入替身) | [03-脱壳dump/eBPF脱壳深挖.md](../03-脱壳dump/eBPF脱壳深挖.md) |
| WinDbg TTD/Windows 调试体系 | [平台/01-Windows安全/调试篇.md](../../平台/01-Windows安全/调试篇.md) §5 |
| DynamoRIO/WinAFL 覆盖引导 fuzz | [平台/01-Windows安全/win-vuln/工具链搭建.md](../../平台/01-Windows安全/win-vuln/工具链搭建.md) §3.1 |
| 模拟执行(unidbg 补环境) | [05-工具矩阵/模拟执行框架.md](../05-工具矩阵/模拟执行框架.md) |
| Linux 平台细节(rr/strace 生态) | [平台/03-Linux平台/Linux安全.md](../../平台/03-Linux平台/Linux安全.md) |

## 本篇脚本清单(scripts/)

| 脚本 | 用途 | 实测状态 |
|------|------|---------|
| stalker_trace.py | Stalker 采集驱动:spawn 坑规避+三大控量参数+热点统计 | 本机实测通过 |
| calltree.py | call 事件→调用树/热点/去重率 | 本机实测通过 |
| syscall_sim.py | Interceptor 挂 libsystem_kernel 模拟 strace | 本机实测通过(32 函数) |

## 9. 边界与勘误

- 「本机实测」= 2026-10-16,macOS arm64(darwin 25.6.0,SIP 开)+ frida 17.23.3。spawn 模式不出日志行、Stalker spawn 挂起期无效这两条**是版本行为不是协议**,换 frida 版本/系统要先复测 §2.3、§3.1 的最小用例。
- rr、DynamoRIO、Triton、WinDbg TTD、strace 本机没装/不适用 macOS,表中行为通用知识,以各自官方文档为准;rr 需 Linux+特定 CPU 功能(环形缓冲录制),TTD 只在 Windows。
- QBDI 现状:独立 DBI,稳定版 0.12.1,AArch64 自 0.10.0,经 frida-qbdi 绑定进 frida 会话;「比 Stalker 快」是社区 tracer 的报告,不同负载差异大,关键路径自测。
- r2 `aht` 是类型提示命令不是 trace(6.2.4 实测帮助原文),r2 的 trace 面是 `dts`/`aes`/ESIL `ae*`。
- dtruss 在 SIP 开着时无解,别在生产机上动 csrutil;要 syscall 面就用 §5.2 的用户态等价物。
