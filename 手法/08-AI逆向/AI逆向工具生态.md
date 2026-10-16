# AI 逆向工具生态:MCP 化逆向工具横评与选型

> 核心结论:生态已分成三层——**编排层**(REA/MobileRE-Skill:让 Agent 端到端干活)、**单点能力 MCP 层**(jadx/ghidra/IDA/frida 各自 MCP 化,Agent 按需调用)、**知识查询层**(jniq 这类离线速查)。三层不是竞争关系,是组合关系。
> 工作流怎么串起来 → 见同目录《AI逆向工作流实战.md》;多 Agent 编排方法论 → 见 `../01-方法论/llm自动逆向编排.md`。

## 0. 一句话定位表(先看这个)

| 工具 | 一句话定位 | 它是什么层 |
|---|---|---|
| REA | "Reverse Engineer Anything":给 AI Agent 用的逆向 CLI+MCP,APK/so/网站/固件通吃 | 编排层(工具总线) |
| MobileRE-Skill | AI Agent 移动逆向技能系统:frida 模块+独立工具+决策树,一句话需求自动路由 | 编排层(领域技能) |
| LSPilot | 端上 AI 驱动 LSPosed 动态逆向:意图解析→定位类方法→生成示例→一键注入 | 编排层(端上闭环) |
| mobile-security-mcp | APK 静态分析+RASP 识别/绕过的 MCP(⚠️ 工具列表,见 §4) | 单点能力 |
| jadx-mcp 系 | jadx 反编译能力 MCP 化(AI 读 Java 源码) | 单点能力 |
| GhidraMCP 系 | Ghidra 反编译/函数分析 MCP 化 | 单点能力 |
| ida-pro-mcp | IDA Pro 全功能 MCP 化(本机在用) | 单点能力 |
| frida-mcp 系 | frida 动态插桩 MCP 化(AI 直接操作进程) | 单点能力 |
| dexllm | LLM 面向 DEX/APK 分析器(DexKit+DAD 反编译器封装) | 单点能力 |
| barbatos | 零配置 Android 运行时调试器,内置 Frida API + MCP | 单点能力 |
| R2Droid | 端上 radare2 GUI + AI 助手(OpenAI 兼容 API) | 端上自立门户 |
| jniq | JNIEnv 函数表离线互查(index/offset↔函数名) | 知识查询 |
| lamda | Android 全栈设备控制平台:设备端 server+投屏/UI 自动化/一键 MITM/内置隐藏版 Frida+MCP | 编排层(设备端) |
| agent-device | 移动 App 自动化验证 CLI/MCP(iOS/Android/鸿蒙),accessibility 快照省 token | 单点能力(设备) |
| reverse-skill | 逆向/渗透技能路由包:AI 自动路由+按需自举工具链+自进化经验库 | 编排层(技能路由) |
| reverify | 防幻觉裁决层:AI 提议,确定性工具对照 artifact 裁决 VERIFIED/REFUTED | 验证层(新品类) |
| radare2-mcp | radare2 官方 MCP(C 实现,CLI/插件/HTTP 多态) | 单点能力 |
| x64dbg-mcp-server | x64dbg 原生 MCP 插件(Zig 单二进制,全调试功能) | 单点能力(Windows) |
| mcp-windbg | WinDbg MCP(含内核调试) | 单点能力(Windows) |
| binary_ninja_mcp 系 | Binary Ninja MCP(插件派+headless 180 工具派) | 单点能力 |
| ASC | 「APK 即数据库」零预处理反编译器(为 Agent 设计) | 单点能力(性能) |

## 1. MCP 化逆向工具横评主表

| 工具 | MCP 能力 | 封装的底层 | 状态 |
|---|---|---|---|
| REA | MCP server + 独立 CLI 双形态;支持 Claude Code/Codex/Cursor/Gemini CLI 等 | headless JADX(JDK)、Apktool、ADB、Ghidra/Hopper/IDA(原生深度分析,本机有啥用啥)、Binwalk/Unblob(固件)、Chrome(网站)、Go/Rust/WASM/EVM 字节码 | 260.5k star/65.5k fork、MIT、3300+ commits。Node 22+,`npx rea-agents setup` 一键注册 |
| MobileRE-Skill | 经 kilo.json 挂 jadx-mcp + ghidra-mcp 两个外部 MCP;本体是 skill/决策树+frida 模块+22 个 Python 工具 | frida(monitors 15 + bypass 10 + utils)、unpack.py 脱壳管线、Unicorn 模拟、DexKit 链查询思路 | 184 star、MIT、中英双语 README。Agent 大脑在 `.kilo/agent/reverser.md` |
| LSPilot | 非 MCP——端上 Xposed 模块自带 AI function calling 工具集 | 端上 jadx 反编译(APK/DEX)、DexKit、smali 搜索、ARSC 读取、BeanShell 脚本引擎、LSPosed 注入 | 128 star。要求 LSPosed + Android 14+ + arm64-v8a,API 文档 lspilot.fun |
| mobile-security-mcp | 线索工具集:apk_decompile(apktool)/apk_decompile_java(jadx 硬件加速)/rasp_identify/rasp_bypass(动态生成 frida 绕过) | apktool/jadx/frida | 同名仓库存在但工具列表完全不同(纯静态 13 工具:manifest/权限/secrets 扫描,无 decompile/rasp);所述工具集未见公开仓,以实际起服务为准 |
| jadx-ai-mcp | MCP server(JADX-GUI 内插件) | jadx-gui + AI 插件 | 2.9k star(zinja-coder/jadx-ai-mcp) |
| jadx-mcp-server | 独立 MCP server(Python),配 JADX-AI 插件 | 同上 | 803 star |
| jadx-headless-mcp | headless MCP,无需 GUI,jadx-core 直开 APK | jadx-core | 77 star;另有 Samael-Z/VibRev 两个同类 20/7 star |
| GhidraMCP | MCP Server(Ghidra 插件) | Ghidra 反编译/函数/数据类型 | 11.3k star,生态事实标准,持续更新 |
| bethington/ghidra-mcp | GUI 插件 + headless 双形态,200+ 工具 | Ghidra | 5.6k star |
| reverse-engineering-assistant | MCP + Ghidra 内置 AI 分析(RE-AI) | Ghidra | 874 star(cyberkaida/rea) |
| ida-pro-mcp | 全功能 IDA MCP:decompile/disassemble/xref/重命名/patch/调试 | IDA Pro(Python 插件) | 12.9k star。**本机 ZCode 已在用此套**(get_metadata/decompile_function/…即此仓库工具面) |
| IDA-NO-MCP | 反 MCP 思路:把 IDA 输出直喂模型,省 token | IDA | 2.1k star(P4nda0s/IDA-NO-MCP) |
| ida-mcp-rs | headless IDA MCP(Rust) | idat headless | 869 star |
| dnakov/frida-mcp | stdio MCP 直控 frida(spawn/attach/脚本) | frida | 455 star |
| kahlo-mcp | 面向自治 Agent 的 Android 插桩 MCP | frida | 136 star |
| frida-c2-mcp | C2 风格,root Android/越狱 iOS 长控 | frida | 70 star |
| jshookmcp | AI 逆向工作台,宣称 735 工具 | frida/js hook | 2.1k star |
| open-reverselab | AI 逆向 Agent 平台:MCP 化 Ghidra/Frida/x64dbg/Rizin | 四引擎 | 1.3k star |
| dexllm(dex-analyzer-for-llm) | MCP server + FastAPI/SSE 后端(Claude tool use) | C++ 核心:pybind11 封装 LuckyPray/DexKit + 对齐 DAD 的 C++ Java 反编译器 | 主仓库 2 star(Apache-2.0,C++)。**注意:主仓库不叫 dexllm**,搜 dexllm 只出 demo 仓 |
| barbatos | 内置 MCP 的零配置 Android 运行时调试器 | frida API(Kotlin 实现) | 11 star,持续更新 |
| R2Droid | 非 MCP——App 内 AI 助手,OpenAI 兼容 API 流式对话,`[[cmd]]`/`<js>` 可执行命令脚本 | 端上交叉编译的 radare2 + r2ghidra/r2dec/r2frida | 307 star、MIT |
| jniq | 无 MCP——CLI + Claude Code skill 形态(Skill.md 挂进 agent skills 目录) | 解析真实 jni.h 生成的内置表(233 槽位) | 2 star,MIT,零依赖 |
| radareorg/radare2-mcp | r2 官方 MCP:C 实现,CLI/r2 插件/stdio/HTTP 多态,r2pipe 连本地或远程会话,只读沙箱与工具白名单模式 | radare2 6.x | 百级 star;`r2pm -Uci r2mcp` 一键装 |
| duty1g/x64dbg-mcp-server | x64dbg 原生 MCP 插件:断点/单步/内存/寄存器全功能 HTTP 化 | x64dbg(Zig 插件) | 2.5k 级;单二进制零依赖,dist 拷入 x64dbg 目录即用 |
| svnscha/mcp-windbg | WinDbg 的 MCP(用户态/内核态调试 AI 化) | WinDbg | 1.6k 级 |
| fosdickio/binary_ninja_mcp | Binja 插件形态 MCP,LLM 客户端直连 | Binary Ninja | 450+ 级 |
| mrphrazer/binary-ninja-headless-mcp | headless Binja MCP,180 工具 | headless BN | 250+ 级 |
| firerpa/lamda | Android 设备控制平台 MCP:WebRTC 投屏/UI+OCR 自动化/一键 MITM(系统 CA)/内置最新 Frida 带隐藏 patch/160+ API/多设备集群 | 自研设备端 server(root/非 root) | 8.6k 级;Python 客户端编排 |
| callstack/agent-device | 移动 App 自动化验证:CLI+MCP+Node API 三形态,token 友好 accessibility 快照,跨并行 agent 设备协调 | adb/simctl/wda 等 | 5k 级;npm 可装 |
| sjkim1127/Reversecore_MCP | r2+YARA+LIEF+Capstone 组合的安全分析 MCP(自动化 RE/恶意分析/取证/SAST) | 多引擎 | 200 级 |
| jtsylve/re-mcp | headless 双引擎 MCP:一套通吃 IDA Pro 与 Ghidra | idat/analyzeHeadless | 170 级 |
| PhoenixHairpin/mcp-termux | Termux 端 Android 逆向一体化 MCP:73 工具(eBPF stackplz+paradise 内存 dump+r2 静态) | 端上工具链 | 60 级;ARM64 root |
| 2akouwu/reverify | 验证层 MCP+CLI:AI 主张由确定性工具对照 artifact 裁决(VERIFIED/REFUTED 带证据);含 `reverify rollover` 长会话防漂移 | 逆向引擎输出 | 1.3k 级;PyPI 可装 |
| zhaoxuya520/reverse-skill | 逆向/渗透/安全技能路由包:AI 自动路由+按需自举工具链+自进化经验库 | skill 文档 | 4 万级(Trendshift 榜) |
| SimoneAvogadro/android-reverse-engineering-skill | Claude skill:APK/XAPK/JAR/AAR 反编译+HTTP API 提取(Retrofit/OkHttp/Ktor/Apollo/Koin)+R8 后 Kotlin 元数据名恢复+框架指纹分诊 | jadx/Vineflower | 8k 级 |
| P4nda0s/reverse-skills | 逆向工程 Claude Code Skills 插件(IDA-NO-MCP 作者出品) | skill 文档 | 2.2k 级 |
| haikow/claude-reverse-skills | Claude Code 逆向 skill 集(apk/ida/radare2/js)+IDA MCP 接入,中文 | skill 文档 | 百级 |
| mrphrazer/ghidra-headless-mcp | headless Ghidra MCP | analyzeHeadless | 190 级 |

## 1.5 三种集成形态:MCP / Skill / CLI 怎么分

这批工具接 Agent 的方式并不统一,选型前先认清三种形态(社区对"unidbg 该不该 MCP 化"的争论本质就是这个):

| 形态 | 工作机制 | 适合什么 | 例子 |
|---|---|---|---|
| **MCP server** | Agent 经协议调用工具,拿到结构化返回;工具是现成的、动作是固定的 | 成熟工具的 API 化:反编译、attach、列表查询 | jadx-mcp 系、GhidraMCP、ida-pro-mcp、frida-mcp、REA、dexllm |
| **Skill/技能文档** | 不接协议,把"领域打法+决策树+命令模板"写成文档挂进 Agent;Agent 照文档自己执行/写代码 | 每 target 要定制的环节:unidbg 补环境、so 修复、对抗决策树 | MobileRE-Skill(.kilo/skill 决策树)、jniq(skill/SKILL.md)、本库 re skill 本身;2026-10 后新增量级选手:reverse-skill(路由包)、android-reverse-engineering-skill(API 提取+Kotlin 名恢复)、reverse-skills |
| **CLI** | Agent 用 shell 调用,人也能直接用;JSON 输出便于脚本化 | 离线确定性查询、CI 集成 | REA CLI、jniq、unpack.py/so.py 这类独立脚本 |
**判断口诀**:动作固定→MCP;每目标要写代码→Skill;人和 Agent 都要用→CLI 优先(顺手加 MCP 壳)。一个工具可以同时占多形态(REA=CLI+MCP;jniq=CLI+Skill)。

## 2. REA:工具总线型编排(通用逆向的"瑞士军刀")

**形态**:一条命令两种用法——`npx rea-agents setup` 把 MCP 注册进 Claude Code/Codex/Cursor/Gemini CLI/Grok;或 `npm i -g rea-agents` 当独立 CLI 用(JSON 输出可脚本化)。
**能力面(按目标分)**:
- Android:headless JADX 出 manifest/classes/反编译方法(需 JDK)、ADB 直连设备分析、Apktool 资源解码、Flutter 应用检查、JEB 项目
- 原生二进制:伪代码/汇编/字符串/符号/调用链,走 Ghidra/Hopper/IDA(本机装了哪个用哪个,甚至能经批准帮你装 Hopper)
- 其它:JS/Electron、.NET、网站(Chrome 家族浏览器)、Go/Rust/WASM/EVM 字节码、SQLite、固件(Binwalk/Unblob)、PCAP
**卖点**:分析全本地;**每个结论带证据**(命令输出/反编译片段回传),这是对抗 LLM 幻觉的关键设计——与 r0re 的 `--verified` fact 同一思想。
**生态位**:它不自己造轮子,是把业界既有工具统一成 Agent 可调用的接口 → "工具总线"。第三方衍生已出现:DSH 桥(DeepSeek Harness 插件)、LM Studio 版、ERA 自进化 Agent 等。
**边界**:每个单点能力深度不及专门 MCP(如 GhidraMCP 的 200+ 工具粒度);强项是广度+开箱即用。

### 2.1 REA 衍生生态

| 衍生仓 | 说明 | star |
|---|---|---|
| valorisa/Reverse-Engineer-Anything | 非官方法语教学指南 | 24 |
| rea-githu/REA | "REA 6.3.0 local MCP zip" 分发仓 | 70 |
| ringozzt/rea-research | 对 REA 的技术研究(作为 MCP 工具链) | 52 |
| Fanqi89/dsh-rea(+sheilacraig/dsh-rea-mcp) | DeepSeek Harness 的 MCP 桥插件 | 17/2 |
| Nowng/rea-mcp | LM Studio 接入版 | 0 |
| dav1dngy/era-agent | ERA:基于 REA 的"进化式逆向 Agent" | 2 |
衍生生态本身就是信号:一个工具出现了"桥接版/研究版/教学版",说明主仓已过临界质量。反向也提示风险——分发仓(rea-githu)非官方,装 MCP zip 应认主仓 morluto/rea,防供应链投毒。

## 3. MobileRE-Skill:领域技能型编排(移动逆向专精)

与 REA 的"广而浅"相反,MobileRE-Skill 是"窄而深":只做移动逆向,但把该领域打法全部技能化。
**三层结构**:
1. **Agent 大脑**(`.kilo/agent/reverser.md`):角色定义 + 决策树,输入一句话需求自动选模块/工具;
2. **Skill 文档**(`.kilo/skill/`):任务路由、决策树、模块索引;
3. **领域知识**(`references/` 9 个 wiki 域:脱壳/反检测/加密 hook/行为分析/静态分析/native 分析/排错/frida API 速查/冒烟测试)。
**资产清单**:
- frida 模块 25 个 = monitors/ 15 个(纯观察不改变行为)+ bypass/ 10 个(主动干预反检测);另有 utils/ 辅助脚本目录(so_dump、dex_*、codeitem 内存 dump JS、模板、检测清单脚本,非 hook 模块)
- 独立工具 22 个(`tools/`,不依赖 frida):`so.py`(ELF 静态分析)、`unpack.py`(一键脱壳)、`dex_rebuilder.py`/`dex_dedupe.py`(DEX 回填修复/去重)、`frida_run.py`(无人值守跑 frida)、`emu_run.py`/`uniharness.py`(Unicorn 模拟)、`trace_recon.py`、`cipher_lab.py`、`fsmon_run.py`(内核级文件事件)、`hap_parser.py`(鸿蒙 HAP)、Janus/注入/调试检测脚本
- 外部 MCP:jadx-mcp(AI 直读反编译 Java 源)+ ghidra-mcp(无 GUI 做反汇编分析)
**独门能力**:Dex2C/VMP 三步法(hook 优先→unidbg 重放→Ghidra 伪代码)、符号/结构体恢复(离线 so 侦察+Ghidra 交叉引用推理)、六层下钻(Java→JNI→Native→libc→syscall→SVC)。
**与 REA 差异一句话**:REA 管"什么都能看一点",MobileRE-Skill 管"Android 对抗场景一步到位"——尤其反闪退与脱壳(详见《AI逆向工作流实战.md》§2)。

## 4. LSPilot / mobile-security-mcp / frida-mcp 系

### LSPilot

端上闭环的 AI 动态逆向:你用自然语言说目标(如"hook 会员校验"),AI 解析意图→内置工具 function calling 自动定位目标类/方法→生成可运行示例代码+逆向思路→经 LSPosed 动态注入实时验证。目标是把「找→析→写→注入」整链自动化:新手不用学 Xposed 开发,高手免写重复 `findAndHook` 样板。
**技术栈**:端上 jadx 反编译(APK/DEX)、DexKit 类/方法/字段链查询、smali 搜索、ARSC 资源读取、类型签名解析、字符串引用分析;插件引擎为 BeanShell(Java 脚本,可调 Android API),插件目录 `Android/media/<包名>/LSPilot/Plugin/`(支持 Java/Lua/JS)。
**门槛**:LSPosed + Android 14+ + arm64-v8a;从 GitHub Releases 或 TG 频道装。
**生态位**:与 frida 系互补——LSPosed 注入比 frida 更"原生"(不落 frida-server 特征),适合 frida 一挂就被杀的场景。

### mobile-security-mcp(⚠️ 拆两半看)

- **公开仓**:GitHub 确有 `Serhatcck/mobile-security-mcp`(6 star,TypeScript,npm 可装),但它是**纯静态分析** 13 工具(Android 5 + iOS 8):manifest 解析/权限检查/API 提取/secrets 扫描,依赖仅 apktool+aapt——**没有** apk_decompile_java、rasp_identify、rasp_bypass。
- **线索**:用户线索中的四件套(apktool 反编译/jadx 硬件加速反编译/RASP 识别/动态生成 frida 绕过)在公开仓多组关键词检索未命中,可能为私有仓/内部工具/改名项目。
- **替代**:功能上最接近的是 REA(APK 反编译+设备分析)与 kahlo-mcp/frida-c2-mcp(RASP 类对抗)。

### frida-mcp 生态(按场景选)

| 场景 | 选 |
|---|---|
| Claude/Agent 里直接 spawn/attach/跑脚本 | dnakov/frida-mcp(stdio,最简) |
| 自治 Agent 长时间插桩 Android | FuzzySecurity/kahlo-mcp |
| C2 式长期控制 root 机/越狱机 | s4dp4nd4/frida-c2-mcp |
| JS hook 为主、要工具大而全 | vmoranv/jshookmcp(735 工具宣称) |
| 连 Ghidra/x64dbg/Rizin 一起 MCP 化 | LING71671/open-reverselab |

## 5. dexllm / barbatos / R2Droid:三个"小而specific"

- **dexllm**(实名 `dex-analyzer-for-llm`):解决"LLM 看 APK 太费 token"——C++ 核心(pybind11 封 LuckyPray/DexKit + 对齐 DAD 的 Java 反编译器)本地跑,只把结构化结果给模型;后端 MCP + FastAPI/SSE,天然适配 Claude tool use。适合超大 APK 的类搜索/方法定位预处理,再交给 jadx-mcp 精读。检索坑:仓库名不带 dexllm,直接搜 dexllm 只会搜到 WASM demo 仓(dexllm-web)。
- **barbatos**:零配置 Android 运行时调试器 + Frida API + 内置 MCP(Kotlin)。卖点是"装上就能用"——不写 MCP 配置不装 server,Agent 直连调试。star 少但思路值得盯。
- **R2Droid**:反向路线——**不是把工具交给云端 Agent,而是把 AI 塞进手机**。端上 radare2 全家桶(r2ghidra/r2dec 反编译、r2frida 动态、ESIL 调试、Sugiyama 图布局)+ AI 助手(OpenAI 兼容 API,流式,自定义 prompt,`[[cmd]]` 让 AI 执行 r2 命令、`<js>` 跑脚本)。无网无电脑的现场分析(如只许带手机进场)唯一解。

## 6. jniq:知识查询层的样板(小而美)

**为什么需要**:JNI 函数表 233 个槽位,人和 LLM 都背不住;逆向时从内存 dump 看到 `JNIEnv*` vtable 调用 `*(env + 0x520)`,靠猜必错——LLM 在这恰好会一本正经地幻觉(见《AI逆向工作流实战.md》§4 坑 1)。
**原理**:解析真实 jni.h(NDK 版,兼容 OpenJDK 声明风格)用脚本生成内置表(`src/jniq/table.py`),离线确定式查询,不猜。
**用法(装:`uv tool install jniq` 或 `pipx install jniq`,零依赖)**:

```bash
jniq 164                 # index → GetStringLength
jniq 0x520               # 64 位字节偏移 → GetStringLength
jniq 0x298 -b 32         # 32 位偏移 → ReleaseStringChars
jniq FindClass           # 函数名反查(精确/忽略大小写)
jniq call int            # 模糊搜索
jniq RegisterNatives --json   # JSON 输出给脚本
jniq                     # dump 全表
jniq --jni-h /path/jni.h # 对自定义头(如 JDK21 新函数)一次性查询
```

**Agent 集成**:无 MCP,走 Claude Code skill 形态——把 `skill/SKILL.md` 拷/链到 agent skills 目录,Agent 遇到 JNIEnv 查询就调它而不是背答案。这个模式可复制:任何"LLM 易错的事实表"(ELF 结构偏移、ArtMethod 偏移、syscall 号)都值得做成同类工具。

## 7. 三大反编译 MCP 对比(jadx vs Ghidra vs IDA)

| 维度 | jadx 系 | Ghidra 系 | IDA 系 |
|---|---|---|---|
| 头部仓库 | zinja-coder/jadx-ai-mcp(2.9k)+ jadx-mcp-server(803);headless 派 1013503897/jadx-headless-mcp(77) | LaurieWired/GhidraMCP(11.3k,事实标准);bethington/ghidra-mcp(5.6k,200+ 工具);cyberkaida/rea(874) | mrexodia/ida-pro-mcp(12.9k,**本机在用**);P4nda0s/IDA-NO-MCP(2.1k);blacktop/ida-mcp-rs(869) |
| 擅长 | DEX→Java 源码,类/方法/字符串/资源,LLM 最易读 | 免费全平台 so/elf 反编译+伪代码,headless 成熟,批量分析 | 商业最强反编译质量+F5 伪代码+调试器,插件生态 |
| 短板 | 不能看 native | 伪代码质量略逊 IDA;大 so 慢 | 收费;单实例许可限制(headless 多开要 fork:ida-multi-mcp/IDA-instances-MCP) |
| 形态 | GUI 插件派(zinja,需开着 jadx-gui)vs headless 派(无 GUI 直开 APK) | GUI 插件+socket 派(LaurieWired)vs headless 派(pyghidra-mcp/mrphrazer) | GUI 插件派(mrexodia,IDA 里起 server)vs headless 派(ida-mcp-rs) |
| 选择建议 | APK 第一步永远是它:先 jadx-mcp 让 AI 读完 Java 层再谈别的 | so 分析默认选;无 IDA 许可/要 CI 批量时唯一选 | 有许可就上;本机已配好,工具面含 decompile/disasm/xref/rename/patch/struct |
| Token 策略 | 输出 Java 源,token 友好 | 函数级拉取,注意别全量 list | 同左;IDA-NO-MCP 主打"预处理后直喂"省 token |
**组合套路**(对应《AI逆向工作流实战.md》§1):jadx-mcp 读 Java 层找 JNI 触点 → ida-pro-mcp/ghidra-mcp 进 so 反编译关键函数 → frida-mcp/barbatos 动态验证。三家 MCP 可同挂一个 Agent,不存在互斥。

**调试器/引擎 MCP 补齐情况(2026-10 快照)**
- 已齐:x64dbg(x64dbg-mcp-server,Zig 原生插件)、WinDbg(mcp-windbg)、Binary Ninja(binary_ninja_mcp 插件派 + binary-ninja-headless-mcp 180 工具派)、radare2(radare2-mcp 官方)、IDA/Ghidra/jadx(见 §7)。
- 仍无头部实现:gdb-MCP(检索命中均为零星小仓)、unidbg-MCP(仅 so-rev-mcp 类模板仓)、volatility-MCP(内存取证小仓)——需求真实但尚无事实标准,下轮复核。
- 设备侧新层:lamda(设备端全栈控制+MCP)与 agent-device(轻量验证闭环)把「真机操作」也 MCP 化,与 frida 系(进程内)互补。

### 7.1 稳定性与 token 注意(实测/社区反馈归纳)

- **GUI 插件派的坑**:jadx-ai-mcp/mrexodia 系都要宿主 GUI 进程活着;会话中途 GUI 崩了 MCP 全挂。长任务优先 headless 派(jadx-headless-mcp、ida-mcp-rs、pyghidra-mcp)。
- **多实例**:IDA 许可限制单实例,要并行开多个二进制得用 fork(ida-multi-mcp 452 star/IDA-instances-MCP 456 star,专为多开加固);Ghidra headless 无此限制,批量任务更划算。
- **token 省法**:反编译结果按函数拉,别整 so 全量 decompile;IDA-NO-MCP 的思路(预处理后直喂、绕过 MCP 往返)在超长任务里值得借鉴;jniq `--json` 输出便于脚本比对而非让模型读全表。
- **返回值即证据**:三家 MCP 都返回工具原始输出——把"必须引用工具返回的偏移/伪代码片段"写进 prompt,是防幻觉的第一道闸(详见《AI逆向工作流实战.md》§5)。

## 8. 选型决策树(抄走即用)

```
要逆什么?
├─ Android APK(主流程)
│   ├─ 要端到端自动化、需求一句话说清 → MobileRE-Skill(配 jadx-mcp+ghidra-mcp)
│   ├─ 只想让 Claude/Cursor 能读代码 → jadx-headless-mcp 或 REA
│   ├─ frida 一挂就闪退/强对抗 → LSPilot(LSPosed 路线)或 MobileRE-Skill bypass 模块
│   └─ APK 巨大、token 爆炸 → 先 dexllm 定位,再 jadx-mcp 精读
├─ so/原生二进制
│   ├─ 有 IDA → ida-pro-mcp(本机已用)
│   ├─ 无 IDA/要批量 → GhidraMCP
│   └─ 手机现场分析 → R2Droid
├─ 什么都可能来(APK/网站/固件/字节码混合任务) → REA
├─ 动态插桩
│   ├─ 简单 spawn/attach → dnakov/frida-mcp
│   ├─ 长控/root 机 → frida-c2-mcp / kahlo-mcp
│   └─ 零配置调试 → barbatos
└─ JNI 表查询(jni.h 233 槽位) → jniq(CLI/skill)
```

## 8.5 常见组合配方(社区实践归纳)

| 场景 | 配方 | 出处/依据 |
|---|---|---|
| 协议签名还原 | jadx-headless-mcp + ida-pro-mcp(静态)→ dnakov/frida-mcp(hook)→ unidbg(离线对拍)→ mitmproxy(重放) | 博客园帖 + 社区帖(四段流水线标准形态) |
| 一句话全自动移动逆向 | MobileRE-Skill(大脑/决策树)+ jadx-mcp + ghidra-mcp(手) | MobileRE-Skill README(kilo.json 挂双 MCP) |
| 混合目标任务(今天 APK 明天网站) | REA 单装,按目标自动切引擎 | REA 文档(showcase 含 Electron/网站/固件) |
| 强反调试目标 | LSPilot(LSPosed 路线,绕开 frida 特征)+ MobileRE-Skill bypass 模块兜底 | LSPilot README + MobileRE-Skill 反闪退管线 |
| 超大 APK token 控制 | dexllm 出类索引(结构化摘要)→ 点名 jadx-mcp 读 3-5 个类 | dex-analyzer-for-llm README(面向 Claude tool use 降 token) |
| 现场无电脑 | 手机装 R2Droid(AI 助手+r2 全家桶) | r2droid README |
| JNI 逆向查证 | 任何配方 + jniq(vtable 槽位一律查不背) | jniq README("LLM 一定在猜") |

## 8.6 安装速查

> python 系(pip 类)进本库 tools-env 的装法见《05-工具矩阵》各篇「安装速查」;MCP 一键命令优先 npx/uvx 形态。

```bash
# ── 编排层 ──
# REA(Node 22+;MCP 注册进 Claude Code/Codex/Cursor 等)
npx rea-agents setup
npm install --global rea-agents   # CLI 形态;rea update / rea --help

# MobileRE-Skill:clone 仓库(地址待核)→ Agent 大脑挂 .kilo/;外部 MCP 用下方 jadx/ghidra 两条
# LSPilot:LSPosed 模块,GitHub Releases / TG 频道装 APK(LSPosed+Android 14+arm64;API 文档 lspilot.fun)
# reverse-skill:github.com/zhaoxuya520/reverse-skill(clone 后挂进 agent skills 目录)
# reverse-skills(P4nda0s):github.com/P4nda0s/reverse-skills;android-reverse-engineering-skill:github.com/SimoneAvogadro/android-reverse-engineering-skill
# R2Droid:APK 直装(仓库待核);barbatos:github.com/victorlpgazolli/barbatos(macOS 单二进制)
# lamda(设备端全栈):github.com/firerpa/lamda

# ── 反编译 MCP ──
# jadx-ai-mcp(GUI 插件):github.com/zinja-coder/jadx-ai-mcp — jadx-gui 插件市场/release jar
# jadx-mcp-server:github.com/zinja-coder/jadx-mcp-server(配 JADX-AI 插件)
# jadx-headless-mcp(无需 GUI):github.com/1013503897/jadx-headless-mcp
# GhidraMCP(事实标准):github.com/LaurieWired/GhidraMcp(Ghidra 插件 + python server)
# bethington/ghidra-mcp(200+ 工具)/ mrphrazer/ghidra-headless-mcp:headless 派
# ida-pro-mcp:github.com/mrexodia/ida-pro-mcp(本机 ZCode 已在用,无需重装)
# ida-mcp-rs(headless Rust):github.com/blacktop/ida-mcp-rs

# ── 动态/设备 MCP ──
# frida-mcp(62 工具配方版,依赖 frida@17)
claude mcp add frida-mcp -- npx -y frida-mcp@latest
# dnakov/frida-mcp(最简 stdio):github.com/dnakov/frida-mcp,按 README 配 mcpServers
# kahlo-mcp:github.com/FuzzySecurity/kahlo-mcp;frida-c2-mcp:github.com/s4dp4nd4/frida-c2-mcp
# jshookmcp:github.com/vmoranv/jshookmcp;open-reverselab:github.com/LING71671/open-reverselab
# agent-device(移动 App 验证,npm)
npx agent-device

# radare2 MCP(官方,r2pm 一键)
r2pm -Uci r2mcp

# ── 知识/验证层 ──
# jniq(Python 3.9+,零依赖)
uv tool install jniq              # 或 pipx install jniq
# reverify(防幻觉验证层,PyPI)
uv tool install reverify          # 或 pipx install reverify

# dexllm(主仓,非 demo 仓)
git clone https://github.com/mobile-threat-hunter/dex-analyzer-for-llm

# ── Windows 调试/其他引擎 MCP ──
# mcp-windbg:github.com/svnscha/mcp-windbg
# x64dbg-mcp-server:github.com/duty1g/x64dbg-mcp-server(dist 拷入 x64dbg 目录即用)
# binary_ninja_mcp:github.com/fosdickio/binary_ninja_mcp(插件派)/ github.com/mrphrazer/binary-ninja-headless-mcp(180 工具 headless 派)
# ryuumonbuchi(217 工具 Ghidra MCP)/ knife(CLI/TUI/MCP)/ re-mcp(jtsylve)/ Reversecore_MCP(sjkim1127):仓库待核,见 §1 表
```

注意:mobile-security-mcp(npm 同名包)与用户线索所述工具集**不是同一个东西**(见 §4),装前先核对工具列表。
