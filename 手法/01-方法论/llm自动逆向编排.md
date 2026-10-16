# LLM 自动逆向编排:从 r0re/Cairn/muteki 抽象的可移植方法论

> 目标:把三个项目的多 Agent 协作机制去 Docker 化,提炼成「主 agent 编排 + subagent 并行」即可复刻的通用打法,并给出可直接照抄的 APK 逆向任务拆分模板。
> 事实依据见同目录《r0re-架构解析.md》。

## 1. 三项目协作模式的抽象

三个项目表面不同(Cairn 通用状态空间搜索、muteki 异构引擎安全自动化、r0re Android 逆向),内核是同一套**编排者-执行者-黑板**三元组:

```
┌─────────────┐   派发任务(渲染好的 prompt)    ┌─────────────┐
│  编排者       │ ───────────────────────────→ │  执行者 ×N    │
│ (reason/race)│ ←─────────────────────────── │ (explore)    │
└──────┬──────┘    结构化 JSON 结果回传          └──────┬──────┘
       │ read/write                                     │ read/write
       ▼                                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    共享黑板(唯一真相源)                       │
│  Fact(已确认,含 verified 标志)/ Intent(待认领方向)          │
│  DeadEnd(已证伪路线)/ Hint(人工注入)                        │
└─────────────────────────────────────────────────────────────┘
```

三角色职责(综合 Cairn dispatcher-design.md 与 r0re/muteki 实现):

**编排者(= reason 任务)**:不碰目标文件,只读黑板图快照,做三件事——① Goal 分解:把总目标拆成子问题,逐个对照已有 Fact 找缺口;② 覆盖度检查:r0re 的六层清单(Manifest / Java-smali / Resource / Native / Network / Storage)缺哪层补哪层;③ 产 Intent:每个 intent 必须满足四性——Specific(指向具名类/方法/文件/偏移)、Actionable(执行者知道用什么工具看哪里)、Scoped(单一层)、Independent(可并行)。

**执行者(= explore/race 任务)**:认领一个 intent → 真实工具执行 → 即时写回。三条铁律:开工前先 `read + read-deadends`(不重复已确认 fact、不重走死路);「The MOMENT you confirm a finding」立刻写 fact 且只有亲眼见于命令输出的才配 `--verified`;路线证伪立刻 `mark-deadend`(「A dead end is as valuable as a fact」)。大输出落文件、fact 只引用路径。

**黑板**:追加式(append-only)、原子化 fact(一条一个发现,带类/方法/偏移/路径)、人工可插 Hint。r0re 还把「完成」也门控在黑板上:complete 必须引用至少一个真实 fact id,规则 verifier 校验证据链才放行——防止模型口头宣布胜利。

派发节拍(Cairn/r0re 共有):任务分 bootstrap(开局直解)→ race(可选,多执行者抢跑)→ reason ⇄ explore 循环;explore 超时后同一会话进 conclude 阶段抢救已得结论;同 intent 三连败即拉黑;层级化停滞检测(15/25/45 分钟)。工件共享靠统一分析目录(`~/workspace/analysis/`):jadx/apktool 产物只生成一次,后来者先查再建。

## 2. 移植方案:用 ZCode 主 agent + subagent 复刻(无 Docker)

r0re 的四件套映射到 ZCode 一次会话内:

| r0re 组件 | ZCode 等价物 | 落地做法 |
|---|---|---|
| r0re-serve + 黑板 REST | 任务目录下的 Markdown/JSON 文件 | 见 2.2 |
| dispatcher(reason) | 主 agent(自己) | 主 agent 不直接逆向,读黑板→拆 intent→下发 |
| worker 容器 ×3 | 并行 general-purpose subagent | 每个.intent 一个 subagent,prompt 自包含 |
| CompletionVerifier | 主 agent 收尾验收 | 规则校验 + 独立复核 subagent |
| 工具链容器 | 宿主机已装工具 | jadx/apktool/Ghidra/r2/frida 有啥用啥,subagent 里先探测 |

### 2.1 目录约定(进任务先建)
```
{任务}_APK逆向/
├── 黑板.md            # 唯一真相源:facts / deadends / open-intents 三段
├── jadx_out/ apktool_out/ ghidra_out/   # 共享工件,只建一次
├── candidates/        # 每个子任务的报告(对应 r0re 的 report_*.md)
└── flag-验证/         # 等价模型 solve.py / verify.py + 运行输出
```

### 2.2 共享黑板文件格式(直接抄)
```markdown
# 黑板
## Facts(已确认;[V]=亲见于工具输出)
- F01 [V] 入口校验在 com.ctf.app.MainActivity.checkInput()(jadx_out/sources/.../MainActivity.java:87)
- F02 [V] libnative.so 导出 Java_com_ctf_app_NativeLib_verify,JNI_OnLoad 动态注册(nm -D 输出)
- F03     verify 在 0x1A3C 处做 15 轮字节变换后 memcmp(待复核)
## DeadEnds(已证伪,勿重试)
- D01 strings 里的 base64 串是 decoy,未进入比较(F02 反汇编确认)
## Open-Intents(待认领)
- I03 [from F02] 用 Ghidra 反编译 0x1A3C 整个变换链,提取常量表 → 派生等价 Python 模型
- I04 [from F01] 追 checkInput 的失败分支是否有第二阶段校验
## Hints(人工)
- 出题人提示:输入长度 15
```
维护规则照抄 r0re:追加式不改别人的记录;fact 原子化;长输出落文件引路径;每个 subagent 结束时必须回传「本轮新增 F/D 编号 + 一句话」,由主 agent 合并进黑板(这就是 dispatcher 代写协议的简化版)。

### 2.3 APK 分析任务怎么拆片
拆片维度按 r0re 的 phase 分类器 + 六层覆盖,天然并行边界是「层」和「intent」:
- **P0 侦察(串行,主 agent 自己做或单 subagent)**:`apk-recon` 等价物——file/aapt badging/权限/exported 组件/so 清单/证书 → 产出 F 系列基础 fact + 初步 intent 列表。此步必须先行,后续并行才有共享上下文。
- **并行片 A|Java 层**:jadx 一次落盘(谁先到谁建,后到直接用)→ 找 UI 入口/校验类/native 方法声明/加密 API 调用(find-crypto 四类模式:javax.crypto 类名 / 算法关键字 / Base64 / Keystore)。
- **并行片 B|Manifest+资源层**:apktool 落盘 → exported 组件/deep-link/strings.xml 硬编码/asset 配置。
- **并行片 C|Native 层**(有 so 才开):nm -D/readelf -s 定位 JNI 符号 → r2/Ghidra headless 反编译校验函数 → 提取常量/变换链/比较点。r0re 经验:先 `readelf -Ws`,Ghidra 只砸确认过的关键函数,别全量。
- **并行片 D|动态验证**(有设备/模拟器才开):frida crypto/ssl/root/native hook 组合,验证静态推断的算法参数。
- **串行片 E|等价建模+求解**:拿 A/C 的常量与变换链写 Python 等价模型 → 求逆/有界搜索出候选输入。
- **串行片 F|终验**:把候选输入喂回等价模型断言 pass;能装设备就装设备实测;对照 r0re 护栏——「No final answer from strings alone」「单向哈希不得猜测,除非 native 比较证明就是比那个哈希」。

### 2.4 验收标准怎么定(照抄 r0re 的门控)
1. **完成必须有证据链**:flag/结论必须 `from` 至少一条 [V] fact,六步链齐全(Java/UI 入口 → JNI 入口 → native 调用链 → 常量 → 变换 → 比较);
2. **可运行验证器**:「You may return completion only when a runnable verifier prints an explicit pass condition」——solve.py/verify.py 跑通并打印 pass 才算完;
3. **复现命令**:报告里附一条可照抄的命令序列;
4. **decoy 显式标注**:报告必须含「Decoys / false leads」段,说清排除了什么;
5. **主 agent 复核**:独立 subagent(或主 agent)只拿候选+证据重验一遍,不信任执行者自报的 complete——对应 r0re 的 CompletionCandidate → verifier → quarantine 链。

### 2.5 主 agent 节拍(仿 dispatcher)
1. P0 侦察 → 初始化黑板;
2. 一轮 reason:读黑板、按缺口产 2~4 个满足四性的 intent;
3. 同一条消息**并行下发**对应 subagent(片 A/B/C 互不依赖就同时发);每个 prompt 自包含:目标一句话 + 黑板相关段原文 + 工件路径 + 输出格式(新增 F/D + 报告落盘路径)+ 禁止事项(不重走 deadend、不改黑板别人的记录、大输出落文件);
4. 收割:合并 F/D 进黑板;某 intent 连败 2 次换拆法,3 次拉黑(换维度);
5. 循环 2-4 直到 reason 判定 Goal 被事实覆盖 → 进入 E/F 终验 → 出报告;
6. 卡住时:回黑板扫「facts that unblock you」(r0re 原文),或人工 Hint 注入,而不是让单个 subagent 空转。

## 3. LLM APK 逆向任务拆分模板(直接照抄)

```
目标: {APK 路径} → 恢复 {flag / 关键输入 / 校验逻辑},产出可复现验证链
工件根: {任务目录}/  黑板: {任务目录}/黑板.md(所有 subagent 只读+回传增量,主 agent 唯一写入)

P0 侦察(串行,主 agent)
  in : APK
  out: F01..(基础事实) + I01..(初始 intents) + jadx_out/apktool_out 落盘
  验收: 包名/入口/权限/so清单/dex数/证书 六项全有 fact

─── 以下 A/B/C/D 并行(同轮下发) ───
A Java 层 subagent
  in : jadx_out/, 黑板 F/D 段, I(Java相关)
  do : UI 入口→校验类→native 声明→加密 API 四类模式扫描
  out: 新增 F/D + candidates/A-java.md + 疑点 intent 建议
  验收: 每个 finding 带类名/方法/行号;明确列出所有 System.loadLibrary 触点

B Manifest+资源 subagent
  in : apktool_out/, 黑板
  do : exported 组件/deep-link/硬编码串/asset 配置
  out: 新增 F/D + candidates/B-manifest-res.md
  验收: 无漏报 exported;硬编码候选全部标「仅 candidate,未达比较点」

C Native 层 subagent(有 .so 才开)
  in : lib/**/*.so, 黑板, A 派生的 JNI 触点(无则等 A 一轮)
  do : readelf -Ws/nm -D → 关键函数 Ghidra/r2 反编译 → 常量/变换/比较点提取
  out: 新增 F/D(带偏移/符号)+ candidates/C-native.md + 常量附件
  验收: 变换链每步有指令级证据;VA→文件偏移映射记录在案

D 动态验证 subagent(有设备/模拟器才开,可与 C 二轮并行)
  in : 包名, A/C 的算法假设
  do : frida crypto/root/ssl/native hook;跑一次合法输入抓运行时参数
  out: 新增 F/D + candidates/D-dynamic.log
  验收: hook 输出与静态推断的 key/IV/模式一致或不一致都要写明

─── 汇合点:主 agent reason ───
R1: 合并 A/B/C/D → 缺口分析(六层覆盖)→ 补 intents(四性检查)→ 回并行
    (典型二轮:R1 后派 C2「反编译 0xXXXX 变换链」+ E 前置「常量表提取」)

E 等价建模+求解(串行)
  in : C 的常量与变换链
  do : Python 重实现 → 求逆/有界搜索
  out: flag-验证/solve.py + 候选输入
  验收: 模型对已知输入输出与 native 行为一致(至少一组对拍)

F 终验+报告(串行,独立复核)
  in : 候选输入 + 全部 F
  do : solve.py 断言 pass(有设备则装包实测);独立 subagent 只凭黑板+脚本复核
  out: 最终报告(Result/Evidence chain 六步/Decoys/Reproduction)
  验收: ①引用≥1条[V]fact ②验证器打印 pass ③附可复现命令 ④decoy 显式列出
```

并行边界说明:A/B/C/D 四片互不写同一文件、都只读黑板——满足同轮并行;C 依赖 A 的 JNI 触点时可拆两轮(A+B 先行,C+D 次轮);E/F 天然串行。若 native 加壳/SMC,在 C 内套 r0re 的子模板思路:packed→先脱壳(upx_shlib_emu 类思路)、smc→运行时 dump、jni→RegisterNatives 表还原、constants→memcmp 目标表提取。

## 4. 反模式清单(三个项目用血泪换来的)

1. intent 写成「分析整个应用」/「找加密」——不可执行不可并行(r0re reason.md 反模式段);
2. 让执行者自由宣布完成——必须有可运行验证器 + 证据 fact 引用(r0re verifier 门控);
3. 只凭 strings/猜测出 flag——「No final answer from strings alone」;
4. 死路不记录、二次踩坑——deadend 与 fact 同权重;
5. 每个执行者各自反编译一遍——工件只建一次,先查后建(race 策略);
6. 长跑超时全丢——双阶段 conclude 抢救(r0re/Cairn `_conclude` 模板);
7. 大 blob 塞黑板/fact——落文件引路径,保持黑板可扫读;
8. 同 intent 无限重试——2 次换拆法、3 次拉黑;
9. 单线叙事推理 native——「Every native finding must be backed by a command output or a generated analysis script」;
10. 忘了 decoy:CTF 题里「Morse/Base64/MD5-like values are common decoys」,未证明到达最终比较点前一律只是 candidate。
