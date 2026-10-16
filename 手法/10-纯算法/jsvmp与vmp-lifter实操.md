# JSVMP 与 VMP Lifter 实操：把五步法落成流水线

> 定位：`去混淆实战.md` §6 给了 VMP 还原五步法（方法论层），本文是它的 **lifter 实操层**——手已摸到 VM 了，怎么把 handler 语义表、翻译器、重放验证真的做出来。
> 交叉引用：`去混淆实战.md`（VM 识别与五步法）、`纯算还原方法论.md`（L1/L2/L3 分层与 §1.3 还原边界）、`协议脱机与RPC.md`（不还原走 RPC 的三级火箭）、`../13-trace/trace实战.md` + `../02-frida/高级/stalker.md`（native/dex 侧 trace）、`../04-对抗攻防/设备指纹与风控.md`（环境采集面）。

## 0. 流水线总图与验收门

```
①识别解剖 → ②语义提取(静态+动态) → ③语义表 → ④lifter 两件套 → ⑤验证闭环 → ⑥交付
 JSVMP        babel 分类 + trace 反推    op→语义    翻译器 + 重放器    输出 diff + trace diff    伪代码/可跑 JS
 dex/native   IDA 标注 + stalker trace   同左       同左(借 unidbg)    逐 opcode 对比            方法级还原
```

两条铁律（比五步法更靠前的先验判断）：
1. **lifter 的验收门只有一个：重放闭环**——用你还原的语义表重跑原始 bytecode，同输入下与原 VM 输出逐字节一致、且 trace 逐条对齐。翻译器写得再漂亮，重放 diff 不过就是零分；
2. **先决定要不要 lifter**：输入含强设备指纹/动态 challenge（`纯算还原方法论.md` §1.3）或只要低频出参 → 不写 lifter，直接走 `协议脱机与RPC.md` 三级火箭。lifter 投入按「周」计，RPC 按「小时」计。

---

## 1. JSVMP 识别与结构解剖（网页风控主力）

### 1.1 识别特征（三层）

| 层 | 特征 | 说明 |
|---|---|---|
| 文件级 | 单 js 几百 KB~几 MB；文件名/内容每次刷新变（防存档）；外链前还有一段内联引导 js | 瑞数系典型：内联 js 生成 meta/外链，外链本体才是 VM |
| 代码级 | 巨型 IIFE 自解密；超长字符串或大数组（bytecode 载体）；`switch` 数百 case 或「函数数组 + 下标调用」；`eval`/`Function` 链 | case 数 ≈ handler 数，几十到上千 |
| 行为级 | `charCodeAt`/`at`/`fromCharCode` 调用次数爆炸（取指+解码）；同一函数内循环调用频率极高；开 console 就触发 `debugger` 语句或检测 `toString` | 取指热点 = dispatcher 内部 |

十分钟判断法：Chrome DevTools Performance 跑一次签名，火焰图里一个函数占 80%+ 自耗时、调用次数上万 → 基本就是 dispatcher/handler；Sources 里格式化后搜 `charCodeAt(` 命中点密集区即 bytecode 读取区。

### 1.2 通用结构解剖（五件套）

```
入口 stub(导出的 sign/frontier 函数)
   │  组装 ctx、解密 bytecode
   ▼
bytecode 载体 ── 长字符串 / charCode 数组 / Uint8Array / base64 段（可能运行时自解密重写）
   │
   ▼
dispatcher ── while(1){ op=取指(pc); pc+=步长; dispatch(op) }
   │            形态A: switch(op){case 0x23:...}    形态B: tbl[op](ctx) 表驱动
   ▼
handler 表 ── N 个小函数，每个对应一个虚拟 opcode（或一族）
   │
   ▼
ctx（上下文对象）── 字段即寄存器:pc / st(栈数组)或 sp / regs(数组或 r0..rn) / cp(常量池) / scope(作用域链) / ret
```

### 1.3 部件定位实操

1. **dispatcher**：格式化后找「超长 switch」或「`arr[op]`（或 `arr[op&0xff]`、`arr[map[op]]`）后面紧跟函数调用」的循环体；确认标准：循环体内有 `pc`/`ip` 类计数器自增；
2. **bytecode**：dispatcher 里取指表达式回溯——`s.charCodeAt(pc++)` 的 `s`、`a[pc++]` 的 `a`；解密型先在入口 IIFE 找一次性解密循环（异或/base64 变体），hook 后 dump 解密结果存档（**后续所有分析对着解密后的 bytecode 做**）；
3. **handler 表**：形态 B 直接是数组/对象；形态 A 的 handler 是 switch 的 case 体（§2.2 给「手工表化」改写法）；
4. **ctx 寄存器**：dispatcher 首参几乎必是 ctx；把 ctx 的字段名列出来就是 VM 的寄存器清单，这一步 30 秒定架构（栈机/寄存器机：有 `st` 数组是栈机，有 `r[]` 下标密集读写是寄存器机）；
5. **opcode 变体**：`op` 不一定直接进表——常见 `tbl[(op^k)&255]`、`tbl[op%len]`、两级映射。先把映射式抄下来，lifter 取指要复刻同一式子。

### 1.4 环境对抗清单（动手前先拆雷）

- `debugger` 语句 + 时间差检测（`Function('debugger')` 卡顿判定）：一律用「条件断点 Never pause here」或 AST 删；
- `Function.prototype.toString` 完整性检测：hook/wrap 任何函数前先透传 toString（骨架见 §2.2）；
- console/DevTools 检测（`console.log` 触发 getter、窗口尺寸差）：用 CLI Node 重放时无此面，优先脱到 Node 做（§3.2）。

---

## 2. Handler 语义提取实操（lifter 的核心成本）

### 2.1 方法 A：静态分类（babel 辅助）

先把 handler 逐个读一遍，按八类贴标签：

| 语义类 | 长相（case 体内） | 标注 |
|---|---|---|
| 栈操作 | `st.push(x)` / `st.pop()` / 连续两次 pop 再 push | PUSH/POP/DUP/SWAP |
| 常量加载 | `st.push(imm)` / `st.push(cp[k])` | LDC_IMM / LDC_CP |
| 算术逻辑 | 两次 pop 一次 push，中间 `+ - * ^ << >> &` | ADD/SUB/XOR/SHL... |
| 比较/跳转 | pop 比较 + `pc = imm`（或 `pc += imm`） | CMP+JCC / JMP |
| 变量/作用域 | `regs[i]=` / `scope[n][m]` 读写 | LOAD/STORE |
| 属性访问 | `.length` / `[k]` / `Object.keys` | GETPROP/SETPROP |
| 调用 | `f.apply` / `new f`，参数个数从栈弹或 imm | CALL/CALL_M/NEW |
| 环境/宿主 | 读 `window/navigator/document/screen` | ENV（风控采集面在这，对照 `设备指纹与风控.md`） |

静态读的效率工具是 babel：抽出 dispatcher 函数源码 → `@babel/parser` 转 AST → 按 case 收集每个 handler 体 → 生成「case 号 ↔ 源码」对照表贴到笔记里逐个标（上百 handler 时不做这步会标串）：

```javascript
// extract_handlers.mjs —— node + @babel/parser；从已格式化的 vmp.js 抽 handler 对照表
// npm i @babel/parser 后: node extract_handlers.mjs vmp.js dispatcher行号 > handlers.txt
import { readFileSync } from "fs";
import { parse } from "@babel/parser";
import generate from "@babel/generator";

const src = readFileSync(process.argv[2], "utf8");
const ast = parse(src);
let out = [];
// 找超长 switch:cases 数 > 50 的 SwitchStatement 即 dispatcher 主体
(function walk(n) {
  if (!n || typeof n.type !== "string") return;
  if (n.type === "SwitchStatement" && n.cases.length > 50) {
    for (const c of n.cases) {
      const code = c.test ? generate(c.test).code : "default";
      const body = c.consequent.map(st2 => generate(st2).code).join("; ");
      out.push(`${code}\t${body.slice(0, 200)}`);   // 每个handler先看前200字符即可分类
    }
  }
  for (const k in n) Array.isArray(n[k]) ? n[k].forEach(walk) : walk(n[k]);
})(ast);
console.log(out.join("\n"));
```

静态辅助 hook（补静态读盲区）：临时替换 `console.log`/`Object.defineProperty`、hook `Function.prototype.call` 打调用序列，观察哪些 handler 触发了原生方法——ENV/CALL 类 handler 优先用这招确认。

### 2.2 方法 B：动态 trace 推断（推荐主线）

静态读上百个 handler 又慢又容易错；推荐**先动态后静态**：trace 拿结构特征，静态只验证存疑的。

探针设计（两种 dispatcher 形态各一招）：

- **形态 B（表驱动）**：wrap handler 数组，记录每次分发 `(handlerIdx, 入参快照, 返回后快照)`——快照差 = 栈效应，无需懂 handler 内部；
- **形态 A（switch 型）**：先「手工表化」——babel 把每个 case 体抽成函数 `h0x23(ctx){...}` 存进表、switch 改 `tbl[op](ctx)`，再按形态 B 处理。改写是纯机械操作且不碰语义，改完先对拍原 VM 输出确认改写无损。

```javascript
// 骨架①：dispatcher hook（浏览器 console 注入版）——trace 收集
// 前置:已定位 vmCtx(handler 所在对象)与 handlers 表;浏览器 DevTools console 粘贴
(function () {
  var H = vmCtx.handlers, seq = 0, traces = [];
  var snap = function (c) {                      // ctx 快照:只拷数组与标量,对象打标记
    var o = {};
    for (var k in c) {
      var v = c[k];
      if (typeof v === "number" || typeof v === "string" || typeof v === "boolean") o[k] = v;
      else if (Array.isArray(v)) o[k] = v.slice(0, 64).map(function (x) {   // 栈顶64格足够
        return (typeof x === "object" && x !== null) ? "[obj:" + Object.prototype.toString.call(x).slice(8, -1) + "]" : x;
      });
      else o[k] = "[obj:" + Object.prototype.toString.call(v).slice(8, -1) + "]";
    }
    return o;
  };
  var passthrough = function (f) {               // 防 toString 完整性检测(§1.4)
    var g = function () { return f.apply(this, arguments); };
    g.toString = function () { return f.toString(); };
    return g;
  };
  for (var i = 0; i < H.length; i++) (function (idx, orig) {
    H[idx] = passthrough(function () {
      var a0 = snap(vmCtx), r = orig.apply(this, arguments), a1 = snap(vmCtx);
      traces.push({ seq: seq++, op: idx, s0: a0, s1: a1, ret: (r === undefined ? null : String(r).slice(0, 128)) });
      return r;
    });
  })(i, H[i]);
  window.__dumpTrace = function () {             // 触发一次签名后:copy(window.__dumpTrace()) 落盘
    return JSON.stringify(traces);
  };
})();
```

frida 版（app 内嵌 H5 场景）：`WebView.evaluateJavascript` 注入同一段（hook 点见 `../02-frida/java层/网络与webview.md`），或直接对 `String.prototype.charCodeAt` 下 hook 记取指序列（bytecode 是字符串时取指必经此处，比 wrap 表更通用但只有 (pc,op) 没有栈快照，当辅助）。

### 2.3 差分 probe：从 trace 反推语义

关键动作是**可控输入重复调用**：找到页面全局入口（`window.sign` / 导出的 frontier 函数），用 probe 组多次调用、每组各收一份 trace：

| probe 组 | 反推目标 |
|---|---|
| `f(1,1)` vs `f(1,2)` vs `f(2,3)` | trace 中 ret/栈顶等于 2/3/5 的 op = ADD 候选；等于 2/3/6 的是 MUL 候选 |
| `f("a","b")` vs `f("ab","c")` | 结果 "ab"/"abc" 的 op = CONCAT/字符串处理 |
| `f(x)` vs `f(x')`（只改一字段） | **两份 trace 的公共前缀 = 与该输入无关的环境码；首个分叉 op = 该字段的消费点**——拼接结构、字段→密文段映射从这里直接读出（同 `纯算还原方法论.md` §7.2 差分测试思想） |

统计面：op 频次表 + 每个 op 的栈效应分布（`|st|` 变化量稳定 = 弹几压几）。汇总脚本：

```python
# 骨架②：语义统计(python) —— 消费骨架①的多份 trace_json,产出 sem_table.json
import json, sys, collections

def load(path): return json.load(open(path))

def stack_len(snap):                      # 栈字段名按目标样本改(st/stack/_) 
    return len(snap.get("st", []))

def main(traces):                         # 传多个 trace 文件路径:trace_11.json trace_12.json ...
    freq = collections.Counter(); effect = collections.defaultdict(collections.Counter)
    for p in traces:
        for e in load(p):
            op = e["op"]; freq[op] += 1
            effect[op][stack_len(e["s1"]) - stack_len(e["s0"])] += 1
    sem = {}
    for op, eff in effect.items():
        stable = eff.most_common(1)[0]            # 主栈效应(多态handler看次高频)
        sem[op] = {"count": freq[op], "delta_stack": stable[0], "guess": None}
    # 语义候选:人工比对 probe 组 trace 填 guess;diff_trace(见骨架③)验证后回填确认
    json.dump(sem, open("sem_table.json", "w"), indent=1, ensure_ascii=False)
    for op, s in sorted(sem.items(), key=lambda kv: -kv[1]["count"]):
        print(f"op 0x{op:x}: n={s['count']:6d}  dStack={s['delta_stack']:+d}  {s['guess']}")

if __name__ == "__main__":
    main(sys.argv[1:])
```

产出即**语义表**（`sem_table.json`：op → {栈效应, 猜测语义, 置信}），op 取 handler 索引；若存在 opcode 映射式（§1.3 第 5 条），表里再存 `raw_op → handler_idx` 一层。语义表是 §3 翻译器与重放器的唯一共享输入——**三段脚本靠它咬合**。

---

## 3. Lifter 构建实操

### 3.1 翻译器：bytecode → 伪代码（python 递归下降模板）

栈式 bytecode 的翻译两遍走：第一遍线性扫描收集跳转目标（给目标 pc 打 label）；第二遍逐指令翻译成栈机 IR，再做**栈消解**（把 push/pop 序列折叠成表达式树）：

```python
# lifter 模板:bytecode + sem_table → 伪代码文本
import json

OPS = json.load(open("sem_table.json"))          # op -> {"guess": "ADD", ...}

def disasm(bc):                                   # 第一遍:跳转目标收集
    pc, labels = 0, set()
    while pc < len(bc):
        op = bc[pc]; info = OPS.get(op)
        if not info: raise SystemExit(f"未知op 0x{op:x} @ {pc} —— 语义表缺口,先回§2.3补")
        name = info["guess"]; pc += 1             # 步长按目标样本改(变长指令按语义表operandWidth走)
        if name in ("JMP", "JCC"): labels.add(read_imm(bc, pc)); pc += imm_w
        elif name in ("LDC_IMM",): pc += imm_w
    return labels

def lift(bc):
    labels = disasm(bc); pc = 0; out = []; stack = []      # stack 存"表达式字符串"做栈消解
    while pc < len(bc):
        if pc in labels: out.append(f"L{pc}:")
        op = bc[pc]; name = OPS[op]["guess"]; pc += 1
        if name == "LDC_IMM": stack.append(str(read_imm(bc, pc))); pc += imm_w
        elif name == "ADD":   b, a = stack.pop(), stack.pop(); stack.append(f"({a}+{b})")
        elif name == "STORE": out.append(f"v{bc[pc]} = {stack.pop()}"); pc += 1
        elif name == "JMP":   out.append(f"goto L{read_imm(bc, pc)}"); pc += imm_w
        elif name == "JCC":   out.append(f"if {stack.pop()} goto L{read_imm(bc, pc)}"); pc += imm_w
        # ...其余语义类同构展开;CALL 从栈弹函数与参数个数
        else: raise SystemExit(f"未折叠语义 {name} @ {pc}")
    return "\n".join(out)
```

产出是类汇编伪码（label + goto + 折叠表达式）；够手读算法即可，**不必追求还原成可编译 JS**——需要可跑版本走 §3.2 重放器而不是翻译器。

### 3.2 自定义解释器重放（验收门）

用语义表直接实现一个 mini 解释器重跑**原始 bytecode**（不经过翻译器，排除二次引入错误的可能）：

```python
# 骨架③：重放 diff(python) —— sem_table + bytecode 重跑,与原 VM 输出/trace 对拍
import json

OPS = {0x23: ("LDC_IMM", 1), 0x35: ("ADD", 0)}   # 结构:op -> (语义, 立即数宽度)——由骨架②回填
BC  = open("bc.bin", "rb").read()                 # hook dump 的解密后 bytecode(§1.3)

def replay(inp):
    pc, st, regs, out = 0, [], {}, None
    trace = []                                    # 重放自身 trace:供 §3.3 对齐
    while pc < len(BC):
        op = BC[pc]; name, iw = OPS.get(op, (None, None)); pc += 1
        imm = int.from_bytes(BC[pc:pc+iw], "little") if iw else None; pc += iw
        trace.append((pc, name, tuple(st[-4:])))
        if   name == "LDC_IMM": st.append(imm)
        elif name == "ADD":     b, a = st.pop(), st.pop(); st.append(a + b)
        elif name == "ENV":     st.append(env_shim(imm))    # 环境面:见下文 shim 说明
        elif name == "EXIT":    return st.pop(), trace
        else: raise SystemExit(f"语义缺口 {name} @ {pc} —— 继续回§2.3补表")
    return st[-1], trace

out, trace = replay({"ts": 1760000000, "input": "..."})
orig = open("orig_out.txt").read()                # 原 VM 同输入(freeze 时间后)的输出
print("输出一致" if out == orig else f"FAIL: replay={out} orig={orig}")
json.dump([{"pc": p, "op": n, "st": list(s)} for p, n, s in trace], open("replay_trace.json", "w"))
```

两个实操要点：
1. **渐进式重放**：OPS 表只填已确认语义，跑到 `语义缺口` 报错 → 回 §2.3 补那一个 op → 再跑。「跑到哪修到哪」比一次写全可靠，每轮 diff 都在收敛；
2. **ENV 类 op 是重放成败的分水岭**：算术面几乎不会错，环境面（navigator/screen/document 值）要在 python 侧造假数据 shim——先从原 VM trace 里把 ENV op 实际返回值抄进 shim 表（「环境快照移植」），输出对上后再逐项改假值做敏感性测试，确认哪些环境项真的入参。

### 3.3 trace diff 法（分歧点定位）

输出 diff 只告诉你「错了」，trace diff 告诉你「错在哪条」：

```python
# 对齐两份 trace:原 VM(骨架①导出) vs 重放(骨架③产出),找第一个分歧
orig  = json.load(open("orig_trace.json"))        # [{seq,op,s1...}] -> 先整理成 (op, 栈顶元组)
repl  = json.load(open("replay_trace.json"))
for i, (a, b) in enumerate(zip(orig, repl)):
    if a["op"] != b["op"]:
        print(f"#{i} 控制流分歧: orig op={a['op']} vs replay op={b['op']} —— 前一条 op 的语义(尤其JCC/比较类)错了"); break
    if list(a["st"]) != list(b["st"]):
        print(f"#{i} 数据分歧 @ op={a['op']}: {a['st']} vs {b['st']} —— 该op语义或ENV shim取值错"); break
else:
    print("trace 全对齐" if len(orig) == len(repl) else "前缀对齐但长度不等:EXIT/跳转语义错")
```

分歧二分法：控制流分歧看前一条（跳转条件算错）；数据分歧看当前条（本 op 语义错，或 ENV 返回值错——按 §3.2 第 2 点区分）。**验证闭环 = 输出 diff 过 + trace 全对齐**，两个都过才算 lifter 交付。

---

## 4. dex VMP lifter 补实操（与 §6/§6.3 方法论衔接）

`去混淆实战.md` §6.3 只给了口诀，这里落成四步工程（思路承接 dex VMP 还原系列帖的工程化做法）。

### 4.1 VM handler 提取（IDA 脚本模式）

1. jadx 侧定位：方法变 `native` + so 内 RegisterNatives 注册（hook 拿注册表，`../02-frida/native层hook速查.md`）；
2. IDA 侧识别 dispatch 循环：`BR Xn` 高频 + 只被间接调用的短函数池（§6.1 特征）；注意**分发取指块被复制进每个 handler 尾部**的对抗——按「重复出现的取指序列」聚类而不是找唯一 dispatcher；
3. IDAPython 批量标注：从跳转表基址扫出 handler 地址集合，逐个建函数并命名 `vm_op_XX`，同步把 `XX`（索引）写进注释——这就是 native 版语义表雏形：

```python
# IDAPython: 从跳转表批量提取 handler 并命名(arm64, 表在 jump_tbl_ea, N 项)
import ida_bytes, idc
BASE = 0x7A0000                                   # so 内跳转表地址(静态认出 LDR X9,[X19,X9] 的 X19)
for i in range(256):
    ea = ida_bytes.get_qword(BASE + i * 8)
    if ea and idc.get_func(ea) or True:
        idc.add_func(ea); idc.set_name(ea, f"vm_op_{i:02x}", idc.SN_NOWARN)
        idc.set_cmt(ea, f"handler idx={i} 表项@{BASE + i*8:X}", 0)
```

### 4.2 dispatch 循环 trace

真机跑目标方法，stalker 只 follow dispatch 地址段，`putCallout` 逐次记录 `(pc, 关键寄存器)`——取指点寄存器值即 (pc_vm, op) 序列。写法、卡死排查（mutex_lock 开关法）与控量后处理全按 `../13-trace/trace实战.md` 与 `../02-frida/高级/stalker.md` 的现成脚本改：只跟一小段地址区间，输出先落盘再离线统计（op 频次/栈效应同 §2.3 骨架②，寄存器快照替代 ctx 快照）。

### 4.3 opcode 映射表构建（白盒对照法）

JSVMP 侧靠 probe 输入差分；dex 侧更省的路子是**白盒对照**：自己写含各指令类型的 demo Java 方法（iadd/if_icmple/aget/invokevirtual/stringbuilder 链），若能拿到同加固器就加固后对照 trace；拿不到加固器就对目标方法做「行为对照」——trace 中 JNIEnv 调用密集的 handler 即 invoke 语义 handler（§6.3 口诀），JNI 函数名直接给出该 invoke 的目标。逐类填表：handler 地址 ↔ dex 指令语义 ↔ 操作数编码。

### 4.4 方法还原工具化（frida 主动调用逐 opcode 对比）

映射表初步齐后做**单 opcode 验证**：frida 主动调用目标 native 方法（`frida-API详解.md` 的 ArtMethod/fromJni 主动调用），构造只含某一条虚拟指令的最小 bytecode（或截取 trace 中该 op 的现场重放），对比执行结果与语义表预期——批量跑完每个 op 一次，即 native 版「重放 diff」。全 op 过后再做整方法还原：bytecode 段 → dex 指令流 → smali/伪代码，与真机输出对拍收尾（同 §3.3 验收门）。

---

## 5. 大厂风控场景定位表（什么参数背后是什么 VM）

| 场景 | 保护形态 | 识别锚点 | lifter 还原成本 | 不还原的替代（决策点） |
|---|---|---|---|---|
| 网页风控参数（a_bogus web 侧/瑞数/同盾/数美类） | **JSVMP** | §1.1 三层特征；火焰图单函数热点 | 中：handler 数百内，probe 差分 1~3 天出核心 op | 浏览器 RPC（playwright 常驻）最便宜；要规模化才上 lifter |
| app 内嵌 H5 的风控参数 | JSVMP（同网页，套 WebView） | WebView 里 js 特征同左 | 中（同左） | 直接走 R1 frida RPC（`协议脱机与RPC.md` §2），比还原省一个量级 |
| shield 类加固的方法保护（梆梆/360/爱加密系商业 VMP） | **dex VMP** | 方法 native 化 + so JNI 密集 | 高：§4 四步全走，周级 | 通常不值得整包还原——只还原承载签名的那几个方法，其余走 R1/R2 |
| 头条系/美团/拼多多 native 层签名（mtgsig 类/anti_content 类） | **native VM + OLLVM** | `去混淆实战.md` §6 特征 | 极高（周~月级） | 默认 R2 unidbg 黑盒复算（`纯算还原方法论.md` §6），VM 完整还原只在 unidbg 补不动时才上 |

决策口径（复用既有文档，不另造标准）：输入可离线构造 + 业务要规模化 → 才考虑 lifter（L1）；输入含强设备指纹/服务端 challenge → 停 R1/R2，lifter 无意义（`纯算还原方法论.md` §1.3 判据）。**lifter 的适用带很窄：高价值、多版本长期维护、且语义表可脚本化重建（换版本只换 bytecode）时才回本**。

## 6. 工具箱

三段骨架的数据流契约（自洽性检查表）：

```
骨架①(浏览器/frida 注入) --JSON: [{seq,op,s0,s1,ret}]--> 多组 probe trace
        │
骨架②(语义统计)         <-- trace_*.json ; 输出 sem_table.json(op→{delta_stack,guess})
        │
骨架③(重放 diff)         <-- sem_table.json + bc.bin + orig_out/orig_trace
                              输出: 输出 diff + trace 对齐报告(§3.3)
```

咬合点：①的 `op` = handler 索引（不是 raw opcode，映射式单列一层）；②的 `delta_stack` 与 `guess` 是③的唯一输入；③的 `语义缺口` 异常回流②继续补表——**闭环三件套，任何一环独立可跑、产物可存档复用**。

其余工具：

| 工具 | 用途 | 备注 |
|---|---|---|
| babel（parser/traverse/generator） | handler 抽取（§2.1）、switch 表化（§2.2）、字符串解密与常量折叠预处理 | 网页 VMP 分析第一站；配合 ast explorer 网页版快速试 transform |
| Node `vm` 模块 + jsdom/手造 window | JSVMP 脱浏览器重放（§3.2 ENV shim 的宿主） | 先「环境快照移植」再逐项替换；比浏览器里调试可控 |
| Chrome DevTools Performance | dispatcher 热点定位（§1.1 十分钟判断法） | 配合 Sources 格式化 |
| frida + WebView 注入 | app 内嵌 H5 的 JSVMP trace | 与 §2.2 同一段脚本 |
| IDAPython / stalker / unidbg | dex 与 native VMP（§4） | 引用 `../13-trace/trace实战.md`、`../05-工具矩阵/模拟执行框架.md` |

最后一条纪律：lifter 是「最后一个才用的武器」。动手前先过 §0 铁律 2 的决策门；动手后每一步都有 diff 收敛证据（语义表渐满、重放缺口递减）才继续投——连续两天无收敛立即降级到 RPC（`协议脱机与RPC.md`）。
