# r0re 架构解析:Kimi Code 驱动的 Android 逆向多 Agent 编排服务

> 基于 r0re(fyrlove/r0re,main 分支 183 文件全树 + 关键源码)、上游 oritera/Cairn、借鉴对象 FishCodeTech/muteki 的源码审读;文档有中英双语(`docs/README.zh-CN.md` / `docs/README.en.md`)。

## 1. r0re 是什么、解决什么问题

r0re 自述为「一个本地 Android 逆向/CTF 分析编排工具」:通过 Web UI 保存项目状态,由 dispatcher 按 YAML 配置启动 Docker 化的分析 worker(默认 Kimi Code CLI),对放入 `container-android/test_apk/` 的 APK 自动完成逆向分析,直到恢复出 flag / 关键输入 / 业务逻辑。

典型用例(README 运行示例,CTF 样例):
- Origin 描述:分析该 APK 在 Java、JNI 和 native 代码中的校验逻辑;
- Goal:「恢复最终可接受的 flag/输入」并给出可复现验证链路;
- 实跑结果:项目进入 `COMPLETED`,finalizer 完成验证,`FLAG='kboloy0'`,图谱含 27 个 facts、4 个 intents。

它解决的真正问题不是「跑一遍 jadx」,而是:**单个 LLM 会话的上下文和注意力撑不起一次完整逆向**——需要把「谁已确认了什么 / 哪条路已证伪 / 下一步该挖哪」外置成共享状态,让多个模型会话分工推进、互不重复、结论可验证。

血缘(README "Project Lineage"):r0re 二开自 oritera/Cairn(AI 通用状态空间搜索引擎,先在自动化渗透场景验证);开发中借鉴 FishCodeTech/muteki 的多 Agent CTF 共享黑板/共享证据机制。

## 2. 架构组件拆解

整体是「Server(Web UI + 协议真相源)— Dispatcher(调度)— Worker 容器(分析执行)— 共享黑板(REST)」四件套。全部 183 个文件中,核心 Java 源码在 `src/main/java/com/fyr/r0re/` 下分 `server/`(17 个类)、`dispatcher/`(26 个类)、`protocol/`、`config/` 四包。

### 2.1 r0re-serve(Spring Boot Web 服务,端口默认 8001)
- 由根 `Dockerfile` 打包:`FROM eclipse-temurin:17-jre-jammy` + `COPY build/libs/r0re-*.jar` + `EXPOSE 8000`,入口 `java -jar`;`docker-compose.yaml` 只定义这一个服务 `r0re-server`,数据卷挂 `./datas/r0re/ → /root/.local/share/r0re/`(`R0RE_DATA_DIR`),重启策略 unless-stopped。
- 控制器清单(server 包):`ProjectsController`(项目 CRUD/启停)、`BlackboardController`(黑板读写)、`IntentsController`(意图认领/心跳/结论)、`HintsController`(人工注入提示)、`AnalysisController` + `AnalysisArtifactsService`(分析产物索引)、`ExportController`(导出,含 YAML 图快照)、`AutomationController` + `AutomationScheduler`(自动化)、`CompletionPolicyService`(完成门控)、`SystemController`(健康)。
- Web UI 是内嵌静态页:`static/index.html` + Alpine.js + Cytoscape(含 dagre/cola/elk/klay 四种图布局)+ Tailwind,即图谱可视化直接画 Fact/Intent 关系图。
- 协议模型(`protocol/Models.java`):`Fact(id, description, kind, verified, creator)`、`Intent(id, from[], to, description, creator, worker, last_heartbeat_at, ...)`、`Hint(id, content, creator, created_at)`、`RuntimeEvent`(逐步事件流)、`VerificationRecord`(候选 flag 的验证状态机)、`JniMethodEntry`(class/method/signature/ probable_symbol/libraries —— 服务端会从反编译产物里结构化抽取 JNI 方法表)。

### 2.2 r0re-dispatch(调度器)
- `DispatcherRunner.java`(2437 行)是主循环:`runOnceUntilIdle` = `max(8, max_workers×6)` 轮 tick + 等待在途任务;每 tick 拉项目列表 → 按 `max_workers`(全局并发)、`max_running_projects`(默认 1)、`max_project_workers`(默认 3)做配额调度;`interval: 3` 秒兼作心跳节拍(沿袭 Cairn 设计)。
- 多 worker 驱动保留:`KimiWorkerDriver`、`ClaudeCodeWorkerDriver`、`CodexWorkerDriver`、`PiWorkerDriver`、`MockWorkerAdapter`(`ExternalCliWorkerAdapter` 统一包装外部 CLI)。
- 容错常量:`STALLED_LIGHT/MEDIUM/HEAVY = 15/25/45 分钟`(按 phase 分级判停滞)、`INTENT_FAILURE_BLOCK_THRESHOLD = 3`(同一 intent 连败 3 次拉黑)、`REASON_FAILURE_CHECKPOINT_THRESHOLD = 2`。
- Phase 分类器:DispatcherRunner 用一组正则把 intent 文本归类到 phase(native/manifest/resource/signature/constant/verify/report),例如 native 匹配 `\b(jni|native|\.so|zygisk|frida|offset|symbol|elf|arm64|lib[a-z0-9_]+)\b`;phase 又映射到 cost class 和 PromptFactory 的子模板选择。
- swarm 模式下的项目级自治:只有租约过期导致 `health=recovery_required` 的项目才自动恢复(冷却 15/30/20 秒分级),用户手动 stop(health 保持 normal)的项目绝不自动复活。

### 2.3 Worker 容器(container-android/,镜像 `cairn-android-reverse:latest`)
基础镜像 ubuntu:22.04,非 root 用户 `reverser`(免密 sudo),工具链(逐条来自 Dockerfile):
- 反编译:jadx 1.5.0、apktool 2.10.0、Ghidra 11.2.1 PUBLIC(含 headless)、radare2(git 编译安装);
- 动态:frida + frida-tools(pip)、Android SDK platform-tools r37.0.0(adb)+ cmdline-tools(aapt);
- 辅助:androguard、unicorn、capstone(pip)、Node.js v20.18.0、pi-coding-agent 0.73.0;
- Agent CLI:Kimi Code 装到 `/opt/kimi-code` 并软链 `kimi`(`Dockerfile.kimi-patch` 层,因「完整 Dockerfile 从头构建在本机网络下 apktool 层不稳定;此补丁复用已有层」);
- 内置知识:frida hook 模板 JS(`crypto-hook.js`、`native-hook.js`、`root-bypass.js`、`ssl-pinning-bypass.js`、`trace-class.js`、`prelimimnary.js`)、Ghidra 后置脚本(`ListFunctions.java`、`DecompileToStdout.java`)、Android-RE-reference 知识库 git 仓库、r0re-blackboard skill;
- 环境变量打通宿主机设备:`ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`、`FRIDA_HOST=host.docker.internal:14725`。

容器卷挂载(dispatch.kimi.swarm.example.yaml):`test_apk`(只读)、`output/live-analysis/{project_id} → ~/workspace/analysis`(读写,跨 worker 共享产物)、`output/kimi-sessions/{project_id} → /tmp/r0re-kimi`(Kimi 会话持久化);network_mode host,完成后 stop。

### 2.4 共享黑板(REST,worker 直连)
这是 r0re 相对 Cairn 最大的架构反转(见 §5)。实现为 `container-android/skills/r0re-blackboard/`(SKILL.md + blackboard.py,纯标准库 urllib,20 秒超时):
- `GET  {R0RE_BLACKBOARD_URL}/projects/{id}/blackboard` — read / read-deadends / list-intents 共用;
- `POST /projects/{id}/intents/{intent_id}/heartbeat` — claim(body 携 worker,成功打印 `WON`,失败 `LOST` 退出码 1);
- `POST /projects/{id}/blackboard/facts` — write-fact(worker、description、verified、intent_id);
- `POST /projects/{id}/blackboard/deadends` — mark-deadend;
- `POST /projects/{id}/intents/{intent_id}/conclude` — conclude(必调,哪怕「nothing found」);
- `POST /projects/{id}/complete` — complete(body 含 `from` fact id 列表,至少一条,「The server gate will reject unsupported completions」)。
返回的黑板 JSON 含 `facts`、`dead_ends`(id/description/creator)、`open_intents`、`intents`、`hints`。

### 2.5 宿主机 USB 设备桥(`container-android/scripts/bin/device-bridge.sh`)
macOS 上 adb server 监听 TCP → 容器经 host.docker.internal 连接;Mac 上 `adb forward` 转发 frida 14725 端口 → 容器连宿主 frida-server。支持 usb/wifi 两模式,`start-r0re.sh --no-bridge` 可跳过。

### 2.6 启动链路(start-r0re.sh)
预检(`r0re-preflight.sh`)→ USB 桥 → `r0re-repair.sh` 修状态 → `r0re-serve.sh --background --port` → 轮询 `curl /projects` 直到就绪(默认 60 秒超时)→ `r0re-dispatch.sh --background --config=...`;`--supervise` 前台守护(2 秒 `kill -0` 探活,serve 挂则连 dispatch 一起重启);另有 launchd 常驻、`r0re-health.sh`、`r0re-runtime-watch.sh`、`r0re-smoke-task.sh`、`r0re-acceptance.sh` 等运维脚本。

## 3. Worker 的分析流程:拿到 APK 之后走什么步骤

### 3.1 任务类型与 swarm 主链路
三种任务(Cairn 原语 + r0re 扩展):
- **bootstrap**:项目初始态一次性全量尝试(超时 1200s,conclude 收尾 180s);
- **reason**:读图快照判断「Goal 是否已满足 / 提出新 intents」(超时 900s,`max_intents: 3`);
- **explore / swarm_explore**:认领一个 intent 执行并产出 fact(超时 1800s);
- **race**(r0re 新增):swarm 模式开局,多 worker 同时扑向整个目标抢速度。

swarm 派发逻辑(DispatcherRunner 反编译确认):初始项目 → `dispatchRace`(多 racer 并行冲刺);race 结束无结论 → 日志「race phase finished: no conclusive result, entering coordinator loop」,进入协调循环;之后按需 `dispatchReason`(项目级 reason lease,单项目最多一个)→ reason 产出 open intents → `dispatchSwarmExplore` 逐个派发(worker 在容器内自己 claim)。非 swarm 模式则是 Cairn 原版:bootstrap → reason ⇄ explore。

完成链路带**验证门**:`complete` 调用产生 CompletionCandidate(pending)→ Dispatcher 的规则 verifier(`completionCandidateRejectionReason`:candidate_type 必须 goal、value 非空、source facts 必须真实存在且不含 goal、mock worker 不得完成真项目)→ 通过则 approve,失败则 reject 并 `quarantineProject` → approved 后 finalizer(`r0re.finalizer`)落定 + 导出项目 + 快照工作区。

### 3.2 单个 worker 的分析流水线(prompts/android-reverse/bootstrap.md 原文归纳)
bootstrap prompt 给出的标准五步(可按目标类型跳步):
1. **目标识别**:`file`、`aapt dump badging/permissions`(包名/版本/入口 Activity/权限);
2. **解包与反编译**:`jadx --no-res --show-bad-code -d jadx_out/`(出 Java)、`apktool d`(出 smali+资源);疑似加壳(360/腾讯乐固/百度)时查 classes.dex 是否异常小/加密、`lib/` 里的脱壳 stub,转宿主 USB 桥动态路径:`adb-setup.sh connect-usb` → `frida-auto.sh <package> native` 或 `frida -H host.docker.internal:14725 -f <package> --no-pause`,并明确提示「避免假设容器内 `frida -U` 可用」;
3. **字符串/模式快扫**:jadx 源里 grep `password|secret|token|api_key|encrypt|decrypt|cipher|AES|RSA|MD5|SHA|HMAC`、URL、`SharedPreferences|sqlite|ContentProvider`;so 里 `strings -a` + `readelf -s` 查 `JNI_OnLoad|encrypt|sign|verify`;
4. **按 Goal 聚焦**:Crypto(追 `javax.crypto.Cipher/SecretKeySpec/MessageDigest` 的算法/模式/key 来源)、Network(OkHttp/Retrofit→签名头)、Auth(token 存储/pinning)、Native bridge(`System.loadLibrary`/native 声明→对应 so)、组件(manifest exported);
5. **native 深挖**(按需):`readelf -h/-s`、`nm -D`、`r2 -A -q -c 'afl'`,再上 Ghidra headless。

配套辅助脚本(`container-android/scripts/bin/`,7 个):`apk-recon.sh`(file/aapt badging/permissions/exported 组件/lib 下 so/dex 清单/keytool 证书摘要,纯静态不解包)、`quick-jadx.sh`(jadx `--no-res --show-bad-code` + 可选 grep 关键字,输出 `~/workspace/analysis/jadx_out`)、`ghidra-analyze.sh <so> [func]`(analyzeHeadless 导入分析 → `ListFunctions.java` 导函数清单并 grep JNI/加密关键词 → `DecompileToStdout.java` 反编译单函数,失败回退 `nm -D` / r2)、`find-crypto.sh <jadx_out>`(四类模式:javax.crypto API 类名 / 算法关键字 / Base64 / 密钥存储位置)、`so-strings.sh`、`adb-setup.sh`、`device-bridge.sh`。

**动态层**:`frida-auto.sh <package> <mode>` 按场景选 hook 组合——`crypto`(加密 API)、`ssl`(pinning 绕过)、`root`(root 检测绕过)、`native`(native 追踪)、`custom:<script.js>`、`all`/`full`;连接方式自动适配:容器内(`/.dockerenv` 存在)默认 `-H host.docker.internal:14725`。

**确定性求解器**(`tools/android/`,「automation facts vs model conclusions」分离):`android_ctf_runner.py`(自建工作区:解包、工具可用性检测、java/native hints 过滤 `flag|ctf|loadLibrary|native|JNI`、生成 Markdown 报告,可插已知题确定性插件)、`ali_crackme3_solve.py`(阿里 crackme3:还原 native 变换链 `stored encrypted table → xor key 20 8e 13 39 → index rotations → xor 0x29 → PRGA-like S-box xor → byte rotate → first 15 bytes`)、`wbox_solve.py`、`godot_ctf_runner.py`、`upx_shlib_emu.py`(UPX so 脱壳模拟)、`nrv2b.py`、`apply_relocs.py`。

### 3.3 agent 契约与状态机(.agents/android_reverse_ctf_agent.md)
容器内 agent 配置定义了 8 态分析状态机:
`triage`(清点 APK 内容与工具可用性)→ `java_trace`(找 UI 事件/校验类/native 调用/**decoys**)→ `native_trace`(JNI 入口与 native 校验调用链)→ `constant_extract`(比较目标、key、add/xor 表、加密 blob)→ `equivalent_model`(**用 Python 重实现校验逻辑**)→ `invert_or_search`(求逆或有界搜索推输入)→ `verify`(断言等价模型通过,可选 native 模拟验证)→ `report`(最终 flag + 解释 false leads)。

护栏(Guardrails 原文):
- 「No final answer from strings alone.」(禁止只凭 strings 给最终答案);
- 不得凭单向哈希猜测给最终答案,「unless the native compare proves that exact hash is compared」;
- 「No claims about algorithms without evidence from code, constants, or verified behavior.」;
- 禁止隐藏手工步骤:「every important action must be expressible as a script or command」。

报告模板强制六步证据链:Java/UI entry → JNI/native entry → Native call chain → Constants → Transform → Compare,外加 Decoys/false leads 与 Reproduction(`python3 tools/android/android_ctf_runner.py challenge.apk --workspace out`)。

## 4. Prompt 设计精华(值得学的写法)

r0re 的 prompt 组在 `src/main/resources/prompts/` 下分 `default / mock / android-reverse / android-ctf` 四组,每组含 `bootstrap / reason / explore(+_conclude)` 及扩展模板(android-reverse 组:race、swarm_explore、explore_java/manifest/native + 各 conclude;android-ctf 组:explore_native_jni/constants/packed/smc/verify)。`PromptFactory.java` 按 intent 文本关键词路由子模板(如 native intent 命中 `packed|upx|壳` → `explore_native_packed`,命中 `smc|self.modif` → `explore_native_smc`,命中 `jni|java_|registernatives|loadlibrary` → `explore_native_jni`,命中 `constant|memcmp|table` → `explore_native_constants`),并做图快照压缩(compactGraphYaml 限制 maxFacts/maxIntents/maxHints)。

值得摘录的设计模式:

1. **黑板纪律写进 prompt 的「时刻」句式**(bootstrap/swarm_explore 通用段):
   - 「BEFORE choosing a direction: run `read` and `read-deadends` — never repeat a confirmed fact, never retry a dead end.」
   - 「The MOMENT you confirm a finding in real tool output: `write-fact "<finding with exact location>" --verified`. Pass `--verified` only for what you literally saw in command output.」
   - 「The MOMENT a route is disproven: `mark-deadend "<what was tried and why it failed>"`. A dead end is as valuable as a fact.」
   - 「Keep each fact atomic: one finding, exact class/method/offset/path. Large outputs go to files; reference the path.」
   把「何时写、写什么粒度、什么算 verified」全部操作化,而不是抽象要求「及时同步」。

2. **reason prompt 的「分层覆盖检查」**(android-reverse/reason.md):先 Goal 分解成子问题逐个对 fact,再做六层覆盖分析(Manifest / Java-smali / Resource / Native / Network / Storage),缺哪层就发哪层的 intent;附「目标类型 → 高价值 intent 模式」表(找加密算法 = `Cipher.getInstance → SecretKeySpec 来源 → IV 生成 → mode/padding`)和反模式清单(「Analyze the whole application」太宽、「Decompile the APK」bootstrap 已做、「Look at all strings」已扫、禁止发重叠 intent)。

3. **intent 描述的四性标准**:「Specific(指向具名类/方法/文件/偏移)、Actionable(执行者知道用什么工具看哪里)、Scoped(单一层/组件)、Independent(可与其他 intent 并行)」,配正反例:好「Trace SecretKeySpec usage in com.app.crypto.AESUtil to find where the encryption key is constructed」;坏「Find the encryption」「Analyze everything about security」。

4. **严格 JSON 输出契约**:所有 prompt 结尾统一「Return only one raw JSON object. Do not output anything else.」,结构为 `{"accepted": true/false, "data": {fact/complete/intents/description}}`;甚至预置了拒绝模板并注明「(never reject - you must handle the task professionally)」。

5. **双阶段收尾(conclude 覆盖)**:主阶段超时/解析失败后同一 session 进入 `_conclude` prompt,原文:「If you later receive a conclude-phase instruction, obey it immediately - stop everything and return the summary JSON.」——用便宜的第二阶段把已做工作抢救成 fact,不浪费长跑上下文。

6. **race prompt 的防重复劳动策略**:「before a long-running step (Ghidra, full decompile), check the board and the analysis dir」——重活开工前先看板上有没有人做过。

7. **双语报告硬约束**(r0re 特色):bootstrap prompt 要求在返回 JSON 前必须用 write 工具落 `report_en.md` 和 `report_zh.md` 两份等价报告,内容含架构概览、全部确认发现(类名/方法/行号/偏移)、机制详解、bypass 策略、关键代码片段;fact.description 里引用报告路径。这是「结论产物化」而非只留对话记录。

8. **native 专用执行协议**(android-ctf/explore_native.md):「Do not solve native crackmes by narrative reasoning alone. Every native finding must be backed by a command output or a generated analysis script.」并强制维护 `~/workspace/analysis/ctf_state.json` 状态文件;「You may return project completion only when a runnable verifier prints an explicit pass condition for the candidate.」——完成权与可运行验证器绑定。

## 5. 与上游 Cairn 的差异、借鉴 muteki 的黑板机制

### 5.1 Cairn 原版(docs/specs/dispatcher-design.md,1181 行)
- 定位:「Given an origin and a goal, it searches for a path through an unknown state space」,渗透只是首个验证场;
- 三组件:Cairn Server(图真相源)/ Dispatcher(**「Agent 不直接认领 Intent,不直接 heartbeat,不直接调用 Cairn API」,Dispatcher 是唯一协议写入者**)/ 每项目一个 Worker 容器;
- 任务模型:bootstrap(开局直解,超时由 bootstrap_conclude 收尾)/ reason(单项目 lease)/ explore(先 heartbeat claim 再启动),双阶段 conclude;
- Worker 选择规则:任务类型 → max_running 未满 → 健康窗口 → priority 小者优先 → 运行数少者优先 → 随机;
- 战绩:腾讯云 Hackathon 第二届 54/54 唯一 AK;AGPL-3.0;backends: Claude Code / Codex / Pi;local 模式免 Docker 复用宿主机 CLI。

### 5.2 r0re 的关键差异(源码对比)
| 维度 | Cairn | r0re |
|---|---|---|
| 实现 | Python/uv | Java 17 Spring Boot(serve+dispatch 单 jar) |
| 协议写入者 | 仅 Dispatcher,agent 回 JSON 由它代写 | **worker 容器内直连黑板 REST**(blackboard.py:claim/write-fact/mark-deadend/conclude/complete) |
| 开局策略 | bootstrap 单发 | swarm 模式 **race 多 worker 抢跑** + 协调循环 |
| 完成判定 | agent 自报 complete | CompletionCandidate + 规则 verifier 门控 + quarantine + auto-finalize + 导出快照 |
| Prompt | default 通用组 | android-reverse/android-ctf 两组 + phase 正则分类子模板(jni/constants/packed/smc/verify) |
| 执行环境 | 通用渗透容器 | Android 全工具链容器 + 宿主 USB adb/frida 桥 + frida hook 模板库 |
| 确定性求解 | 无 | android_ctf_runner + 题目插件(ali_crackme3/wbox/godot/upx_shlib_emu) |
| 产物 | 图上 fact | 强制双语 report_*.md + ctf_state.json + JNI 方法结构化抽取 |
| 附加 | mock 测试 | launchd 常驻、repair/watch/acceptance 脚本、Web 图谱 UI |

worker 直连黑板的代价与收益:r0re 让 claim 竞争(heartbeat 租约 WON/LOST)、dead_ends 即时广播、卡住时可扫全板自救(muteki 式「When stuck — scan read for facts that unblock you」);代价是 agent prompt 里必须写死纪律防刷板。dead_ends 一等公民化(「A dead end is as valuable as a fact — it stops everyone from repeating it」)在两个项目的图协议里都有体现,r0re 把它前移到了 worker 的每一步操作纪律里。

### 5.3 从 muteki 借到什么
muteki README 自述:「A Coordinator schedules different Agent engines toward one goal, manages their context, and lets them collaborate through shared evidence」;Planner(独立模型端点)做协调决策并 proposes Steps;Worker CLIs 执行;操作员可 Dispatch 创建新 Step,Worker 缺输入走 pending card;预算项含 concurrency/time/worker count/cost cap;多 flag 任务持续收集。仓库本体是重产品(Electron 桌面端 + Next.js Web + Go runtime-agent + 多引擎适配层 claude/codex/cursor/devin/droid 等),r0re 只取了其**共享证据 + 协调者/执行者分层 + 步骤派发**的协作骨架,嫁接到 Cairn 的 Fact/Intent 图协议上。

## 6. 模型配置经验(GPT-5.4/5.5、GLM-5.1、Kimi K3)

- README「模型配置说明」:开发中用过 **GPT-5.4、GPT-5.5、GLM-5.1、Kimi K3**,公开仓库只保留 Kimi K3 模板,「可参考 dispatch.kimi.swarm.example.yaml 自行添加其他模型」——即模型无关:换个 base_url/key/CLI 驱动即可(代码里同时保留了 claudecode/codex/pi 驱动)。
- `.env.example` 关键项:`KIMI_MODEL_NAME=k3`、`KIMI_MODEL_PROVIDER_TYPE=anthropic`(走 Anthropic 兼容协议)、`KIMI_MODEL_BASE_URL`(指向 Kimi coding 端点)、`KIMI_MODEL_MAX_CONTEXT_SIZE=1048576`(1M 上下文)、`KIMI_MODEL_API_KEY` 留空自填;YAML 里全部 `${...}` 间接引用,密钥不进 Git。
- 容器侧:`KIMI_CODE_HOME=/tmp/r0re-kimi`(挂到宿主 `output/kimi-sessions/{project_id}`,会话跨容器重启续存)、`KIMI_CODE_DISABLE_AUTOUPDATE=1`、禁遥测。
- 并发经验:默认模板 3 个 worker(`max_workers: 3`),注释明说「小机器可降到 1 或 2」,且 README 坦承「仅测试到 3 个」;`max_running_projects: 1` 表示单项目专注模式,3 个 worker 全砸一个 APK。
- 超时预算按任务类型分级:bootstrap 1200s > explore 1800s(reason 900s),conclude 统一 180s;`worker_healthcheck: startup_only`。
- 停滞检测分级(15/25/45 分钟)+ intent 三连败拉黑,是大上下文模型「假活」(进程在跑、无产出)的实用护栏。
