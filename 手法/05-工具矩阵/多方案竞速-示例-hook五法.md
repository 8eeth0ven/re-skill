# 多方案竞速示例:hook 住目标进程 open 的五种等价方式(全实测)

> 方法论演示:**同一目标先提出多种等价方案 → 同一 harness 全部真跑 → 按实测结果择优**。
> 不进死胡同的核心不是"每次都选对",而是"错了有下一条道,且换道依据是数据不是感觉"。
> 测试日:2026-10-16。所有探针值遵守 `测试值规范.md`:`[RE]` 前缀 / `/tmp/re_probe_*.txt` / 魔法值 `0x52455052`("REPR") / `REPROBE-20261016-NNN`。

## 0. 环境快照与任务定义

| 项 | 值 |
|----|----|
| 系统 | macOS 26.6.2 (25G83), arm64 |
| frida | 17.23.3(Python 侧 `~/re-skill/tools-env/.venv/bin/`) |
| 靶子 | `/opt/homebrew/opt/python@3.13/bin/python3`(pyenv `which python3` 解析出的真实 Mach-O;`/usr/bin/python3` bundle 版会卡,弃) |
| 靶行为 | 循环 14 次:`os.open("/tmp/re_probe_target.txt")` → 写 `REPROBE-20261016-NNN`+`0x52455052` → sleep 1s |
| 任务 | 观测/接管/阻断靶子对探针文件的 open——五种等价手法竞速 |

靶子脚本(`/tmp/re_race_20261016/re_target.py`,五方案共用):

```python
import os, time
PROBE = "/tmp/re_probe_target.txt"
MAGIC = 0x52455052  # "REPR"
for n in range(1, 15):
    try:
        fd = os.open(PROBE, os.O_RDWR | os.O_CREAT, 0o644)
        os.pwrite(fd, ("REPROBE-20261016-%03d" % n).encode() + MAGIC.to_bytes(4, "big"), 0)
        os.close(fd)
        print("[TARGET] iter %02d ok fd=%d" % (n, fd), flush=True)
    except OSError as e:
        print("[TARGET] iter %02d open FAILED errno=%s" % (n, e), flush=True)  # S5 打 patch 后走这里
    time.sleep(1)
```

## 1. 竞速前的地面工作:三连归因(每条都省了后面五方案的命)

竞速不是上来就开五枪。先花三次小成本归因,把地基数据拿到手:

### 1.1 API 变迁坑:frida 17 删了 `Module.findExportByName`

老写法 `Module.findExportByName(null, "open")` 在 17.23.3 直接 `TypeError: not a function`。
实测新名:**`Module.findGlobalExportByName("open")`** → `0x18f6438b0`(libsystem_kernel.dylib)。

### 1.2 通道坑:spawn+resume 在本机会弄死 agent,attach-to-running 全稳

按惯例"macOS attach 他人进程被拒 → 用 spawn 自己的子进程"。本机实测**反了**:

| 通道 | 实测 |
|------|------|
| `device.spawn()` → attach → load → `device.resume()` | agent 在 resume 后**静默死亡**:timer 不走、hook 回调无消息、RPC 报 `script has been destroyed`、session `process-terminated`(crash=None);偶发靶子也死 |
| `subprocess.Popen` 起靶 → sleep 1.2s → `device.attach(pid)` | **5/5 稳定**:timer 正常 tick、hook 消息全通 |

> 教训:已知坑清单是"起点假设",不是"本机事实"。通道本身也要先小成本验证——这就是竞速思维在 harness 层的第一次应用。
> 副产物:attach 晚 1.2s,前 2~3 轮 open 漏看,各方案如实记录(对结论无影响,靶子跑 14 轮)。

### 1.3 流量地基:探针 open 到底走哪层(不猜,挂表数)

同时挂 `open` / `openat` / `fopen` / `open_nocancel` 四层,跑 10s 计数:

```
[RE] DIAG 已挂 open @ 0x18f6438b0
[RE] DIAG open_nocancel -> 无此导出符号
[RE] DIAG 已挂 openat @ 0x18f6541bc
[RE] DIAG 已挂 fopen @ 0x18f5196e0
[RE] DIAG 计数 open(total=10, probe=10) | openat(total=0, probe=0) | fopen(total=0, probe=0)
```

**结论:CPython 的 `os.open` 流量 100% 走 `open` 符号;`openat`/`fopen` 是空道。** 这条数据直接决定了 S3 的命运和 S1 的胜局。

## 2. 竞速对照表(总览)

| 方案 | 一句话 | 结果 | 侵入性 | 开销 | 适用场景 | 本轮排名 |
|------|--------|------|--------|------|----------|----------|
| **S1 Interceptor.attach** | 出入口插回调,只看不改 | ✅ 10/10 命中,调用点符号化到 `Python!os_open` | 低(trampoline 5 条指令级) | 极低(仅每次 open 一次回调) | 默认首选:观测参数/返回值/调用栈 | **1** |
| **S2 Interceptor.replace** | 整体换实现,手工转发原函数 | ✅ 10/10 接管,转发后靶子零感知 | 高(所有调用者都过我的 NativeCallback) | 低(一次 JS 边界+一次转发) | 要改参数/改返回值/短路逻辑 | **2** |
| **S3 等价函数替换** | open 不便挂 → 换 openat/fopen 等价层 | ❌ 本靶空道:openat/fopen 流量=0(`open_nocancel` 无符号) | 低 | 低(但白挂) | 目标走 stdio(fopen)或静态链 openat 时才有意义;**换道前必须先验流量(§1.3)** | 4(方法论价值高于战绩) |
| **S4 Stalker 拦调用点** | 不碰函数,trace 指令流过滤 open 地址 | ✅ 6/6 精确命中(须用 exec 入口法,call-target 法因 stub 中转全漏) | **零**(目标函数零修改,无 trampoline) | 高:6s 窗口 96101 个 exec 事件,全量解析 | 函数被反 hook 盯死 / 要还原完整调用链 / 一次性取证 | 3 |
| **S5 patch 入口(ret 改造)** | 直接改机器码:`mov x0,#-1; ret` 恒失败 | ✅ patch 窗口 7 轮 FAILED 精确对应;字节回读+行为+文件系统三重验证;可恢复 | **最高**(进程级全局生效,连 frida 自己的 open 都废) | 极低(2 条指令) | 要"物理级"改变行为(熔断/白名单);必须留底可回滚 | 5(本任务是观测而非阻断,故垫底;若任务是"让 open 永远失败"它直接第一) |

> 排名是**任务绑定**的:本题要"观测探针文件被打开",S1 完胜。任务换成"阻断",S5 第一;任务换成"绕过反 hook 检测",S4 第一。竞速表每轮重排,没有永久冠军。

## 3. 各方案实测记录(命令 + 真实输出 + 坑)

通用 runner(`/tmp/re_race_20261016/run.py`,Popen+attach 路线,§1.2):

```python
import datetime, subprocess, sys, time, frida

REALPY = "/opt/homebrew/opt/python@3.13/bin/python3"

def ts(): return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

agent_src = open(sys.argv[1]).read()
t0 = time.time()
proc = subprocess.Popen([REALPY, "/tmp/re_race_20261016/re_target.py"],
                        stdout=sys.stdout, stderr=sys.stderr)
time.sleep(1.2)                       # 等靶子进循环,躲开 python 启动期
session = frida.get_local_device().attach(proc.pid)
script = session.create_script(agent_src)
script.on("message", lambda m, d: print("[%s] %s" % (ts(), m.get("payload") or m), flush=True))
script.load()
proc.wait(timeout=60)
```

### S1 Interceptor.attach —— 本轮冠军

```javascript
const openAddr = Module.findGlobalExportByName("open");   // frida 17 新名!
let hits = 0, others = 0;
Interceptor.attach(openAddr, {
  onEnter(args) {
    const p = args[0].readCString();
    if (p && p.indexOf("/tmp/re_probe_") === 0) {
      hits++;
      if (hits <= 3) send('[RE] S1 命中#' + hits + ' open("' + p + '", flags=0x' +
        (args[1].toInt32() >>> 0).toString(16) + ") 调用点=" +
        DebugSymbol.fromAddress(this.returnAddress).toString());
    } else others++;
  }
});
setInterval(() => send("[RE] S1 累计: 探针命中=" + hits + " 非探针 open=" + others), 5000);
```

实测输出(节选):

```
[RE] S1 open @ 0x18f6438b0 (libsystem_kernel.dylib)
[RE] S1 命中#1 open("/tmp/re_probe_target.txt", flags=0x1000202) 调用点=0x1017f57d8 Python!os_open
[RE] S1 命中#2 ... 调用点=0x1017f57d8 Python!os_open
[RE] S1 累计: 探针命中=10 非探针 open=0
=== S1 finished, target rc=0, total 14.1s ===
```

- 成功标准全达:路径读出、flags=`0x1000202`(O_RDWR|O_CREAT|O_CLOEXEC)、**返回地址直接符号化 `Python!os_open`**(白捡调用者归属)。
- 坑:① `findExportByName` 已删(§1.1);② 高频函数要按前缀过滤,否则刷屏。

### S2 Interceptor.replace —— 语义接管验证

```javascript
const openAddr = Module.findGlobalExportByName("open");
const origOpen = new NativeFunction(openAddr, "int", ["pointer", "int", "int"]);
let seen = 0;
Interceptor.replace(openAddr, new NativeCallback(function (path, flags, mode) {
  const p = path.readCString();
  const isProbe = p && p.indexOf("/tmp/re_probe_") === 0;
  const fd = origOpen(path, flags, mode);      // 手工转发原实现
  if (isProbe && ++seen <= 3) send('[RE] S2 接管 open("' + p + '") 转发原实现 -> fd=' + fd);
  return fd;
}, "int", ["pointer", "int", "int"]));
```

实测输出(节选):

```
[RE] S2 已整体替换 open,语义=原样转发;靶子应无感知地继续写探针文件
[RE] S2 接管 open("/tmp/re_probe_target.txt") 转发原实现 -> fd=3 (第1次)
[TARGET] iter 03 ok fd=3 ...        ← 靶子全程无感知,14/14 轮正常
[RE] S2 累计接管探针 open 次数=10
```

- 验证点:替换后**所有** open 都过手,转发原实现后行为零变化(靶子 rc=0、探针文件内容照写)。
- 坑:可变参函数(`open(path, oflag, ...)` )的 NativeCallback 签名要按**最大参数个数**声明(3 参),漏了 mode 会在 O_CREAT 场景埋雷;遗忘转发=目标全废,侵入性自负。

### S3 等价函数替换 —— 空道也是战果

场景假设:open 入口被反调试盯死/符号不可用,换等价函数观测。三等价道全挂(`openat`/`fopen`/`open_nocancel`),open 本尊不碰:

```
[RE] S3 已挂等价道 openat @ 0x18f6541bc
[RE] S3 已挂等价道 fopen @ 0x18f5196e0
[RE] S3 open_nocancel 无导出符号,跳过
[RE] S3 等价道计数 openat(total=0, probe=0) | fopen(total=0, probe=0)
[TARGET] iter 03~14 全 ok(探针照开,等价道全程没看见)
```

- **败因是数据不是姿势**:CPython `os.open` 直落 `open` 符号(§1.3),等价道物理上没有流量。
- 方法论价值最高的一条:**"等价函数" ≠ "等价流量"**。换道前先挂表数 10 秒(§1.3),别拿姿势赌流量。
- 什么时候 S3 是对的道:目标用 C stdio(`fopen` 层才有流量,比如很多 C/C++ 客户端)、Linux 静态链musl(go/rust 静态二进制大量走 `openat`)、或上层封装(ObjC `NSFileHandle`、Swift `FileHandle`)。

### S4 Stalker 拦调用点 —— 零侵入,但两个深坑

v1 的 call-target 过滤法**全漏**(靶子 6 次 open,命中 0)。归因(T4/T5):

```
[RE] T4 call总数=1230 ... open精确地址 0x18f6438b0 计数=0   ← call 事件里根本没有 open
[RE] T5 exec总数=48055 | open 内指令执行=42 样例@0x18f6438b0,0x18f6438b4   ← open 明明在执行
[RE] T5 call总数=1097 | target==open 的 call=0
```

**根因:os_open 到 open 之间隔着 stub(BL stub → `br x16` → open),call 事件的 target 是 stub 地址,不是 open 本尊。** 正确姿势是 **exec 入口法**:open 第一条指令被执行 == open 被调用一次,顺带用"最近一个 call 事件的 location"关联出有效调用点:

```javascript
const openAddr = Module.findGlobalExportByName("open");
const tid = Process.enumerateThreads()[0].id;          // 主线程跑循环
let openEntryHits = 0, execTotal = 0, lastCallLoc = null;
Stalker.follow(tid, {
  events: { call: true, exec: true },
  onReceive(events) {
    const parsed = Stalker.parse(events, { stringify: false });  // 坑:annotate:false 会剥掉类型标签!
    for (const ev of parsed) {
      if (ev[0] === "call") lastCallLoc = ev[1];
      else if (ev[0] === "exec") {
        const loc = ev[1];
        if (loc.compare(openAddr) >= 0 && loc.compare(openAddr.add(4)) < 0) {
          openEntryHits++;   // open 入口指令命中==一次 open 调用
          ...
        }
      }
    }
  },
});
setTimeout(() => { Stalker.unfollow(tid); Stalker.flush(); /* 汇报 */ }, 6000);
```

实测输出(v2):

```
[RE] S4 结果: 6 秒窗口 exec 事件=96101, call 事件=2203
[RE] S4 open 入口指令执行次数=6 (每次==一次 open 调用)     ← 窗口内正好 6 轮探针 open,精确对应
[RE] S4 调用点关联采样: 入口#1 前序call点=0x104ee97d4 Python!os_open
[RE] S4 结论: 未碰 open 一个字节(无 trampoline),纯旁路指令流 trace 确认探针 open
```

- 坑 1:`Stalker.parse(..., {annotate:false})` 把事件类型标签剥掉,`ev[0]` 变指针,`ev[0]==='call'` 永假 → 静默 0 命中(最难查的一类 bug:不报错,只是什么都没拿到)。
- 坑 2:stub 中转让 call-target 过滤失效(见上)。
- 坑 3:中途 `unfollow` 后立刻重新 `follow` 同线程曾把靶子打到 `rc=-4`(SIGILL),重配窗口宁可一次 follow 分阶段统计。
- 开销:6s 采集 96101 exec + 2203 call 事件,全量 JS 侧解析——比 S1 重三个数量级,但换来"目标函数零修改"。

### S5 patch 入口(ret 改造)—— 字节级真落地

目标:open 入口写 `mov x0,#-1; ret`(`0x92800000` + `0xd65f03c0`),恒失败;9.5s 后恢复。三个 API 坑全踩过:v1 `Arm64Writer.putBytes` 不存在,v2 `putInstruction` 也不存在——**frida 17 的 `Memory.patchCode` 回调参数是"可写代码指针"(NativePointer 系方法),直接 `writeU32`**:

```javascript
const openAddr = Module.findGlobalExportByName("open");
const hex8 = p => Array.from(new Uint8Array(p.readByteArray(8)))
  .map(b => ("0" + b.toString(16)).slice(-2)).join(" ");
send("[RE] S5 原始 8 字节: " + hex8(openAddr) + " (首指令 pacibsp)");

setTimeout(() => {
  Memory.patchCode(openAddr, 8, function (code) {      // code 是可写代码指针,不是 writer
    code.writeU32(0x92800000);                         // mov x0, #-1
    code.add(4).writeU32(0xd65f03c0);                  // ret
  });
  send("[RE] S5 patch 后字节回读: " + hex8(openAddr));  // 地面真相验证
}, 2500);

setTimeout(() => {                                     // 9.5s 恢复
  Memory.patchCode(openAddr, 8, function (code) {
    code.writeU32(0xd503237f);                         // pacibsp(原始第一条)
    code.add(4).writeU32(0xd10103ff);                  // sub sp,sp,#0x40(原始第二条)
  });
  send("[RE] S5 恢复后字节回读: " + hex8(openAddr));
}, 9500);
```

实测输出(v3,全功):

```
[RE] S5 原始 8 字节: 7f 23 03 d5 ff 03 01 d1 (首指令 pacibsp)
[RE] S5 patch 前全新探针 -> fd=3 errno=0 (期望 fd>=0)
[RE] S5 patch 后字节回读: 00 00 80 92 c0 03 5f d6     ← 共享缓存页 COW 写入成功,字节精确匹配
[RE] S5 patch 后全新探针 -> fd=-1 errno=0 (期望 fd=-1)
[TARGET] iter 06 open FAILED errno=[Errno 60] Operation timed out: '/tmp/re_probe_target.txt'
[TARGET] iter 07~12 同上 FAILED                        ← patch 窗口 2.5~9.5s,正好 7 轮,严丝合缝
[RE] S5 恢复后字节回读: 7f 23 03 d5 ff 03 01 d1        ← 原字节回归
[RE] S5 恢复后全新探针 -> fd=4 errno=0 (期望 fd>=0)
[TARGET] iter 13 ok fd=5 / iter 14 ok                  ← 行为复原
```

- 法证细节:三次探针调用只产生 `re_probe_s5_1.txt`、`re_probe_s5_3.txt` 两个文件——**`re_probe_s5_2.txt` 不存在**,patch 窗口内那次 open 从未真正建文件。文件系统层面独立佐证 patch 生效。
- 坑 1(行为层):patch 成 `恒 -1 + ret` 后 **errno 不再更新**,python 报的是陈旧 errno 60(ETIMEDOUT)——调用方看到"文件打开超时"纯属误导。要干净就 patch 成 `mov x0,#-1; mov w20,#ENOENT...` 的 errno 设置序列,或接受噪声。
- 坑 2(本机沙箱):agent 侧对**已存在**探针文件再 `O_RDWR|O_CREAT` 会 EACCES(errno=13),新建则正常——验证一律用全新文件名,免得把沙箱噪声误判成 patch 效果(v1 就差点被它骗:patch 失败了但 fd=-1)。
- 坑 3(验证纪律):**patch 必须字节回读**。v1/v2 两次 patchCode 回调抛异常、patch 根本没落地,若只看返回值/行为,会得出相反结论。
- 附:open 原始首指令 `pacibsp`(arm64e PAC)——共享缓存是 arm64e;Interceptor 能驯服 PAC,手动 patch 就整条替换、恢复时原样写回,别想"部分保留"。

## 4. 横向对比与择优结论

**本任务(观测探针文件被谁/如何打开)择优:S1 Interceptor.attach。**

理由链:流量在 `open` 符号上(§1.3)→ 符号可挂无检测阻力 → S1 以最低侵入、最低开销拿到全部观测字段(路径/flags/fd/调用点符号化)。S2 在"只观测"场景是杀鸡用牛刀;S3 空道;S4/S5 观测够用但成本/侵入不对等。

**什么情况换哪个(死胡同切换表雏形):**

| 死胡同信号 | 切换动作 | 本轮实测依据 |
|------------|----------|--------------|
| attach 他人进程被拒 | 换 spawn 自己的子进程;**spawn+resume 也死(agent 静默)→ 再降级 Popen+attach** | §1.2:spawn 通道 agent 死,Popen+attach 5/5 |
| `Module.findExportByName` 报 not a function | 换 `Module.findGlobalExportByName`(frida 17+) | §1.1 实测 |
| hook 挂上了但零命中 | 先挂表数流量(多等价层同挂 10s)再谈姿势;流量不在就换层(S3 教训) | openat/fopen=0,open=10/10 |
| 函数被反 hook 盯死(trampoline 被扫) | attach→replace→**等价函数层→Stalker(零 trampoline)**→patch | S4:目标函数零修改仍拿到 6/6 |
| 只想改变行为、连观测都要省 | 直接 patch 入口(恒失败/白名单跳板),留底字节+可回滚 | S5:7 轮 FAILED 精确对应窗口 |
| patch 后行为"没变"或"变了" | **一律字节回读**,别信单一信号;用全新探针文件名避开沙箱 EACCES 噪声 | v1 假阳性险情;§S5 坑 2/3 |
| Stalker call-target 过滤全 0 | 中间有 stub/尾调用;换 exec 入口法(入口指令执行==一次调用) | T4/T5 归因数据 |
| `Stalker.parse` 后过滤永假 | `annotate:false` 剥掉了类型标签,去掉该选项 | S4 坑 1 |
| `__error` 读 errno 是乱码 | 它是函数 `int*(void)`,要 `NativeFunction` 调用后解引用 | T6 |

## 5. 复盘:这轮竞速本身的结构价值

1. **五方案共用同一靶子、同一 runner**——唯一变量是手法,结果可比。harness 有坑先修 harness(§1.2),别让通道噪声污染方案评分。
2. **两个方案"失败/降级"但都有产出**:S3 空道贡献了"等价≠等流量"的地基数据;S4 的 v1 失败逼出了 stub 中转的归因结论,比一次顺利通过值钱。
3. **每条"成功"至少两重独立证据**:S5 是字节回读+行为+文件缺席三重;S4 是窗口计数精确对应+调用点符号化。单信号(尤其返回值)会骗人(v1 的 fd=-1)。
4. 排名绑定任务语义,换任务重排:观测→S1;改参/改返回→S2;绕检测→S4;硬阻断→S5。

## 6. 收尾清场(测试值规范 §三)

```
$ ls /tmp/re_probe_* → (探针文件已清零)
$ ps aux | grep re_target → (无残留进程)
```

脚本与完整日志存档:`/tmp/re_race_20261016/`(s1~s5.log + 归因 _t 系列 + diag.log),复跑:
`cd /tmp/re_race_20261016 && XDG_CACHE_HOME=./cache ../../../../../../.zcode/skills/re/tools-env/.venv/bin/python run.py s1_attach.js S1`
(注:XDG_CACHE_HOME 重定向是因为默认 `~/.cache/frida` 在沙箱内不可写。)
