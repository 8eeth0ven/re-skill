# AI 逆向工作流实战:分析→hook→验证→重放流水线

> 核心流程参考:博客园《使用 AI 进行自动化 APP 逆向》(2026-07:先 IDA MCP+JADX MCP 分析→AI 写 frida 脚本 hook→AI 写加解密脚本→AI 写 mitmproxy 自动重放);社区《自定义 MCP 辅助 Cursor 实现 APP 逆向》《unidbg 真的适合 MCP 吗》《逆向工程基建:从 GUI 到 API》《AI 工具链环境配置》。
> 工具选型 → 见同目录《AI逆向工具生态.md》;多 Agent 编排 → 见 `../01-方法论/llm自动逆向编排.md`。

## 1. 四段流水线总览

社区已收敛出的标准打法(backlion 帖原文即此流程,Trae/Cursor/Claude 皆可当驾驶舱):

```
[输入:目标 APK + 业务问题,如"还原签名算法"]
   │
   ▼
① 静态分析      jadx-mcp(AI 读 Java 层:入口/网络库/加密类/JNI 声明)
   │            ida-pro-mcp / ghidra-mcp(有 so 时:JNI_OnLoad/导出函数/关键函数伪代码)
   │            辅助:REA(一站式)、dexllm(超大 APK 预定位)、jniq(JNIEnv 偏移查证)
   ▼
② hook 编写     AI 根据①的具名类/方法/偏移生成 frida 脚本
   │            落地工具:dnakov/frida-mcp / barbatos(Agent 直接 spawn+注入)
   │            强对抗:LSPilot(LSPosed 注入)或 MobileRE-Skill bypass 模块
   ▼
③ 验证          运行 hook,抓运行时参数(key/IV/明文/签名输入输出)
   │            对拍:同一输入,静态推断 vs hook 实测必须一致
   │            native 算法离线化:unidbg 补环境重放(更适合 Skill 而非 MCP)
   ▼
④ 重放          AI 写 mitmproxy 脚本:替换请求参数/重放请求/自动过签
                产出:可复现 PoC(请求构造脚本 + 证据链)
```

**为什么这四段是黄金切分**:①③ 有现成 MCP(读代码/跑脚本都是成熟工具的 API 化);②④ 是 AI 的强项(写代码),且产物天然可验证(脚本跑不跑得通、请求过不过签,机器说了算)——每段都有客观验收,不给幻觉留空间。

### 每步工具对照表

| 段 | 首选 | 备选 | Agent 侧动作 |
|---|---|---|---|
| ①静态-Java | jadx-headless-mcp(无 GUI)/jadx-ai-mcp(GUI 开着) | REA、dexllm(大包) | get classes→read source→定位加密类/网络层 |
| ①静态-native | ida-pro-mcp(本机在用) | GhidraMCP、R2Droid(端上) | decompile_function→get_xrefs→提取常量 |
| ②hook 生成 | AI 写+frida-mcp 注入 | barbatos、LSPilot、MobileRE-Skill 模块 | 生成脚本→spawn→看日志报错→自修循环 |
| ③验证 | frida hook 对拍 | unidbg(离线重放 native)、cipher_lab.py | 比对静态推断与运行时实参 |
| ④重放 | mitmproxy 脚本(AI 写) | Burp+AI 生成请求模板 | 跑脚本→断言响应/签名通过 |

## 2. MobileRE-Skill 两张决策图(可直接照抄思路)

### 2.1 反闪退 6 阶段 Pipeline(「挂 frida 就闪退」的标准化解法)

目标:让被保护的进程在 frida 在场时活着,直到我们 hook 到想要的东西。

```
阶段1 定位检测 SO
   └─ 从 crash log / tombstone / so 清单锁定实施检测的 .so
     (对照《04-对抗攻防/检测原理全景.md》的检测分层:svc>libc>JNI>Java)
阶段2 抢占 init_array
   └─ 检测逻辑通常在 init_array/JNI_OnLoad 里开机自启;
      抢在它之前 hook(dlopen/构造函数时机)拿先手
阶段3 符号追踪
   └─ 追检测函数符号(导出表/动态注册表),确定"谁在查 frida"
阶段4 保活
   └─ hook 检测函数返回值/骗过检测(而非杀线程,杀线程易触发完整性校验)
阶段5 shellcode 检测
   └─ 部分壳校验代码段哈希/扫 inline hook;识别这类 shellcode 校验点
阶段6 NOP 闪退函数
   └─ 最后手段:定位主动 abort/exit 的闪退函数,patchCode NOP / 替换返回
```

与库内既有知识互链:阶段 2-3 的手法见《02-frida/native层hook速查.md》(init_array/RegisterNatives);阶段 5-6 见《02-frida/高级/patch与内存操作.md》(nop/ret)与《02-frida/高级/gothook.md》(GOT hook),另见《04-对抗攻防/frida反检测对抗.md》四阶段 checklist(进程活→attach→hook→dump)。MobileRE-Skill 的贡献是把这串人工经验变成 Agent 可按决策树走的技能。

### 2.2 一键脱壳决策树(unpack.py 实际管线)

```
判断壳类型
├─ 一代壳(整体加密,运行时解密加载 dex)
│   └─ 内存 dump 即可 → 走"一键脱壳"6 步管线:
│      ① dump 回填(fixChecksum)→ ② 补充扫描(漏网 dex)
│      → ③ pull 到本地 → ④ 校验和修复 → ⑤ 去重(dex_dedupe)
│      → ⑥ 方法体标记(无效方法体标出)→ 产物直接丢 jadx
├─ 抽取壳(方法体抽走,运行时回填)
│   └─ dump 拿到的 dex 方法体是空的 → 需主动触发各方法加载后再 dump
│      (FART 思路;utils/ dex_* 系列)
├─ Dex2C / VMP
│   └─ dump 无意义 → 三步法:hook 优先(直接 hook 调用点拿输入输出)
│      → unidbg 重放(离线跑 so)→ Ghidra 伪代码(人/AI 读逻辑)
└─ 内存 DEX dump 双 dumper(panda/mem):ptrace-free,反调试场景下隐蔽拉 dex
```

对应库内:《03-脱壳dump/dex脱壳.md》(DexFile/DefineClass 构造法)、《03-脱壳dump/so修复dump.md》(native 壳)。AI 编排时把这张树写给 Agent,Agent 按壳类型自动选管线——这就是"决策树技能化"的实例。

## 3. 可照抄的 Prompt(三段各一)

### Prompt A(①静态分析:给 JADX-MCP/IDA-MCP 的 Recon 指令)

```
目标 APK 已用 jadx-headless-mcp 打开(包名 com.xxx.app)。
任务:定位请求签名算法,只做侦察不改代码。
步骤:
1. 列出网络层入口(okhttp3.OkHttpClient/拦截器列表/WebView shouldInterceptRequest);
2. 搜加密四类模式:javax.crypto.Cipher/Mac/MessageDigest 类引用、
   "HMAC/AES/RSA/SHA"关键字、Base64 编码点、KeyStore/SecretKeySpec 构造;
3. 找 native 声明:System.loadLibrary 全部触点 + 对应 native 方法签名;
4. 对每个发现输出:类名#方法名+行号+一句话证据(引用你实际读到的源码片段),
   严禁推断没有源码依据的结论;
5. 结尾给"下一步 hook 候选清单"(≤5 条,按置信度排序)。
有 so 时追加:用 ida-pro-mcp 对 JNI 触点函数 decompile,
输出伪代码中的常量表与比较点,偏移必须来自 get_function_by_address 实际返回。
```

要点:限定"只侦察";每条结论强制带证据引用——对应《01-方法论/llm自动逆向编排.md》的 `[V]` fact 规则;native 部分明确"偏移必须来自工具返回",堵幻觉(见 §5 坑 1)。

### Prompt B(②③hook+验证:给 Agent 的自修循环指令)

```
基于黑板 F03(com.xxx.security.SignUtil.sign(byte[]) 调用 native signNatively),
写 frida 脚本验证签名算法:
1. Java 层 hook SignUtil.sign 与 signNatives 声明类,打印入参/出参(hex);
2. native 层 hook libsec.so 的 JNI_OnLoad 后 RegisterNatives,
   把注册表(函数名/签名/地址)dump 成文件;
3. 对 signNatives 主动调用一次固定输入 "0000" 捕获输出;
4. 通过 frida-mcp spawn 启动,若进程秒退:按反闪退 6 阶段管线处理
   (先定位检测 so → init_array 抢占 → NOP 闪退点),每阶段输出证据;
5. 验收:拿到一组 (input, output) 对 + RegisterNatives 注册表文件路径;
   若 10 分钟未通过 attach,回报卡在哪一阶段,不要无限重试。
```

要点:把 MobileRE-Skill 的 6 阶段管线名字直接写进 prompt(Agent 有决策树就按树走);"回报卡点+禁止无限重试"对应编排文档反模式 8。

### Prompt C(④重放:给 AI 写 mitmproxy 脚本)

```
结论:签名算法为 HMAC-SHA256(key 已从 hook 抓到:hex 32 字节,见 D-dynamic.log),
请求头 X-Sign = hex(hmac(body + nonce + ts))。
任务:写 mitmproxy addon 脚本 replay_sign.py:
1. 拦截目标域名的请求,重算 X-Sign 后替换(nonce/ts 用当前值);
2. 提供 --replay 模式:读抓包文件,改写 body 后重放并断言响应码/业务码;
3. 断言失败时打印 期望签名 vs 实际签名,不要静默失败;
4. 交付:脚本 + 一次成功重放的完整控制台输出(即 PoC 证据)。
```

要点:验证材料(hook 抓的 key)必须来自 B 段产物——流水线各段只信上一段的实测输出,不信推断;重放成功=闭环完成。

## 4. 两条路线:重编排(r0re 系) vs 重工具 MCP 化(本文工具系)

`../01-方法论/llm自动逆向编排.md` 的路线:**多 Agent + 黑板 + 验证门**——重点在"怎么组织多个 LLM 会话协作",工具是宿主机裸命令(subagent 里自己调 jadx/r2/frida)。
本文工具系的路线:**单 Agent + MCP 工具箱**——重点在"每个工具变成 Agent 的手",编排退化为 Agent 自己按序调用。

| 维度 | 重编排(r0re 移植) | 重 MCP 化(Trae/Claude+MCP) |
|---|---|---|
| 核心资产 | 黑板协议+intent 拆分+验收门 | MCP server 群+技能文档(决策树) |
| 上下文压力 | 每 subagent 只领一个 intent,上下文小 | 单会话累积,大 APK 易爆(需 dexllm 类预处理) |
| 并行度 | 天然多路(subagent 同轮下发) | 单 Agent 串行为主(Trae/Cursor 无黑板) |
| 幻觉防线 | fact 必须 [V]、verifier 门控 | 依赖工具返回值直读(MCP 输出即证据) |
| 工具升级 | 换工具=改 subagent prompt | 换工具=换/加 MCP,即插即用 |
| 适用 | 大型任务:整 APK 六层覆盖、CTF flag、多假设并行验证 | 中型任务:单个算法还原、单功能逆向、快速出 PoC |
**怎么选/怎么混用(推荐姿势)**:
1. **任务大(整包审计/未知目标)→ 编排为骨,MCP 为肉**:主 agent 按 llm自动逆向编排.md 拆 intent 下发 subagent;每个 subagent 的 prompt 里直接指定"用 jadx-headless-mcp/ida-pro-mcp 完成本片"——工具 MCP 化后 subagent 不用再自己探测环境,启动成本大降。
2. **任务中(还原某个签名/协议)→ 纯 MCP 流水线**:Trae/Claude 单会话走 §1 四段即可,别为 2 小时的活搭黑板。
3. **强对抗场景 → 编排+技能系统**:MobileRE-Skill 类决策树(6 阶段反闪退/脱壳树)作为 subagent 的随行技能文档;黑板记录"检测点 D 系/绕过 fact"避免每个 subagent 重新踩坑。
4. **判断口诀**:需要"多假设并行+汇总裁决"→ 编排;需要"一个技能链走到底"→ MCP 流水线;两者都不缺时,黑板(哪怕一个 md)+ MCP 工具箱就是最优性价比。
社区补充观点:unidbg 是否 MCP 化有争议——MCP 适合"Agent 操作现成调试器",而 unidbg 需要按目标写 Java 补环境代码,更适合做成 **Skill**(让 AI 写代码)而非 MCP(让 AI 调工具)。同思路适用于任何"每 targets 定制"的环节:定制代码→Skill,固定动作→MCP。

## 5. AI 逆向的坑与验收门设计

### 坑 1:幻觉偏移/幻觉 API——最致命

**症状**:AI 报"检测函数在 0x1A3C"(实际是 0x2A3C);AI 背 JNIEnv 表把 0x520 说成 NewStringUTF(实为 GetStringLength);编造不存在的类路径/导出符号。
**根因**:LLM 对"精确数字事实"天然弱,训练记忆里没有你这个 so;jniq 的存在理由就是这张表"没人背得住,LLM 一律在猜"。
**验收门**:
- 任何偏移/地址/符号,必须 `get_function_by_address`/`nm`/`readelf` 实际输出在场才能写进 fact(编排文档的 `[V]` 规则);
- JNI vtable 偏移一律过 jniq 查证,禁止模型直答;
- prompt 里显式写"偏移必须来自工具返回值"(见 Prompt A)。

### 坑 2:上下文不够——大 APK 必爆

**症状**:jadx 全量源码塞不进会话;Agent 读到一半开始"总结式幻觉"(把早期结论记错)。
**验收门**:
- 分层摄入:dexllm/DexKit 先出类索引(只回传结构化摘要),再点名读 3-5 个类源码;
- 反模式 7 照抄:大输出落文件,fact 只引路径;
- 编排路线下每个 subagent 只领一个 intent(上下文隔离本来就是黑板模式的优势)。

### 坑 3:验证缺失——"看起来对"≠对

**症状**:AI 宣布"算法已还原",但没有一组对拍;hook 脚本报错后 AI 改成 try-catch 吞异常然后宣称成功;重放脚本断言被注释掉。
**验收门**(照搬 r0re 门控+本文流水线加强):
1. **可运行验证器**:completion 必须附带跑通并打印 pass 的脚本(Prompt C 的断言不许删);
2. **对拍**:静态推断 vs hook 实测至少一组 (input,output) 一致;native 用 unidbg 重放对拍;
3. **证据链引用**:最终结论 `from` ≥1 条 [V] fact(六步链:入口→JNI→native 链→常量→变换→比较);
4. **独立复核**:换一个 subagent 只拿黑板+脚本重验,不信执行者自报;
5. **Decoys 段显式列出**:排除了什么(strings 假 base64、界面上误导按钮),防"回答了错误的问题"。

### 坑 4:对抗场景的"成功率幻觉"

**症状**:反闪退管线走完 Agent 说"已 NOP",但下次 spawn 还是闪退(NOP 的是 decoy 检测点);脱壳 dump 的 dex 打不开却报成功。
**验收门**:6 阶段管线每阶段有中间产物(检测 so 名/注册表文件/存活截图);一键脱壳的验收就是第 6 步"产物直接丢 jadx 能打开+方法体非空标记完整"——工具自己给出的客观结果才算数。

### 坑 5:把 MCP 当银弹

**症状**:给 Agent 挂 8 个 MCP,它轮着乱调,每样浅尝辄止(对应编排文档反模式 1:intent 写成"分析整个应用")。
**验收门**:流水线分段锁工具——①段只许 jadx/IDA MCP,②段只许 frida 系,prompt 里点名;定制类环节(unidbg 补环境、so 修复)走 Skill 让 AI 写代码,不走 MCP。

## 6. 快速上手清单(本机现状)

- 已就位:ida-pro-mcp(本机 ZCode 会话内,工具面 decompile/xref/patch/renames 全套)
- 建议补装(按需):jadx-headless-mcp(APK 必备)、dnakov/frida-mcp(动态段)、jniq(`uv tool install jniq`,再链进 skills 目录)
- 强对抗包:MobileRE-Skill(frida 模块+unpack.py 决策树当技能文档读)、LSPilot(端上 LSPosed 注入,需 Android 14+ 设备)
- 一站式:REA(`npx rea-agents setup`,适合非 Android 目标混入的任务)
- 环境细节:frida 装/启动见《02-frida/环境与快速开始.md》;抓包重放的前置(证书/pinning)见《04-对抗攻防/ssl-pinning绕过.md》;unidbg 补环境见《05-工具矩阵/模拟执行框架.md》

## 7. 相关阅读

- 《AI逆向工具生态.md》(同目录):全部工具横评与选型决策树
- 《../01-方法论/llm自动逆向编排.md》:黑板协议与 intent 四性,本文 §4 混用方案的"骨"
- 《../01-方法论/r0re-架构解析.md》:完成验证门(CompletionVerifier)的原始设计,本文 §5 验收门的出处
- 源帖:博客园《使用 AI 进行自动化 APP 逆向》;社区帖 290247/290311/290832
