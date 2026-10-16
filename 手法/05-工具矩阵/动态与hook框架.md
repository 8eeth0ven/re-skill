# 动态与 Hook 框架深度对比（frida 生态 × Xposed 系 × native inline hook × AI/MCP 新势力）

> 核心结论：**frida 仍是动态分析绝对主力**（16.x 终版与 17.x 并行可用）；Xposed 系靠 LSPosed canary 续命做持久化 Java 层 hook；native inline hook 三家（Dobby/ShadowHook/Renef）覆盖「不用 frida 也要 hook」的场景；**2026 年新趋势是 MCP/AI 驱动的 hook 工具链**（frida-mcp/barbatos/R2Droid）。

## 一、两大体系原理对比

### frida：外部注入 + 动态解释执行

- **注入方式**：`frida-server`（root 常驻）通过 `ptrace` 注入目标进程，把 `frida-agent`（so）写进目标内存并在新线程跑起来；无 root 时用 `frida-gadget`（把 so 塞进 APK 重打包，App 启动即加载）。
- **hook 机制**：
  - Java 层：ART 运行时上扫 `art::Class`，替换方法的 entrypoint（FastNatives/native entry），把调用转发到 JS 回调。支持实例方法/静态方法/构造函数，可主动 `Java.use()` 实例化与调用。
  - Native 层：`Interceptor` 基于 **inline hook**（Gum 引擎改函数入口指令跳 trampoline），`Stalker` 做指令级跟踪（自定义代码生成，可逐指令/逐内存事件回传）。
  - 脚本用 JS（QuickJS/V8）动态下发，**改 hook 不重启进程**，配合 `frida-reload`/热加载体验极好。
- **优势**：Java+Native 双端、spawn/attach 双模式、生态（objection/medusa/r0capture/unpinning 脚本全在它上面）。
- **代价**：特征极其明显（进程名、端口 27042、线程名 `gum-js-loop`/`gmain`、maps 中的 agent so、导出符号、内存特征码），反检测是永恒主题（见《04-对抗攻防》与总表第 7 节）。

### Xposed 系：zygote 预埋 + 静态模块

- **注入方式**：所有分支的共同点——在 **zygote 进程**里先于 App 代码执行，把 hook 引擎放进每个 fork 出来的 App 进程：
  - 老版 Xposed（rovo89）：替换 `app_process`，需要改 system 分区。
  - EdXposed：Magisk 挂 `system`（systemless），引擎 YAHFA/SandHook 可选。
  - LSPosed：**Zygisk**（Magisk 注入 zygote 的机制）加载，Ririn→Zygisk 演进，模块格式沿用 Xposed API。
- **hook 机制**：`XposedHelpers.findAndHookMethod` 把目标 `Method` 的 ART 入口换成跳板（各引擎实现：YAHFA 生成 trampoline、SandHook/Pine 用 ArtMethod 字段替换/入口跳转）。模块是**编译好的 dex/Java 代码**，性能好、无脚本运行时特征。
- **优势**：持久（开机即生效、不依赖宿主进程外组件）、性能高、模块生态（HMA、各类定制模块）。
- **代价**：只覆盖 Java 层（native hook 无官方支持）；兼容性绑 ART 版本，Android 大版本升级要引擎适配——这正是 LSPosed 停更后 Android 15+ 只能靠 canary 的原因。

### 机制差异速查

| 维度 | frida | Xposed/LSPosed |
|---|---|---|
| 注入时机 | 运行中随时注入（attach/spawn） | zygote 期预埋，App 出生即 hook |
| 脚本形态 | JS 动态下发、热改 | 编译好的模块 dex，改动要重启 |
| 覆盖层 | Java + Native + 指令级（Stalker） | 仅 Java 层 |
| 性能 | 解释执行，重 hook 有开销 | native 跳板，开销小 |
| 部署 | root 推 server / gadget 重打包 | root + Magisk+Zygisk + LSPosed |
| 检测面 | 特征大（进程/端口/线程/so） | 隐蔽（无外部进程），但 zygisk 本身可被扫 |
| 适合 | 逆向分析、快速试错 | 产品化模块、长期自动化 |

## 二、frida 版本线：16.7.19 终版 vs 17.x 主线

**frida 16.7.19**：
- **16.x 系列最后一个版本**，17.0.0 随即接棒。
- 16.x 终版配套 **frida-tools 13.7.1**。版本配对纪律：`frida 16.7.x ↔ frida-tools 13.7.x ↔ frida-server 16.7.19`，主版本三端一致。
- 16.7.19 的定位：**稳定保守线**。部分团队锁它在 Android 12-14 的老设备/老 ROM 分析机上，原因是 17.0 的 Barebone 后端与 16.x 行为有差异（Gum 代码生成路径、Java bridge 细节），老脚本（尤其直接摸 ArtMethod 偏移的，如 ARTHookScripts 类）在 17.x 上要重新适配偏移。
- strongR-frida 同步有 16.7.19 patch 版（老设备反检测场景仍够用）。

**frida 17.x 主线**：
- 17.0 → 17.2.x → 17.3.x → 17.4.x … → 17.23.x（当前 latest）。
- 17 系主打：Barebone 后端、包管理器（`frida-pm`）、fruity 性能优化。
- 新工具链按 17.x 设计（如 frida-mcp 依赖 `frida@17`、noxen 默认 `pip install frida==17.7.3`）。

**选线建议**：新开任务一律 17.x 最新；只在做 ART 内部偏移操作或老设备兼容时回落 16.7.19 + frida-tools 13.7.1（二者可在不同 Python venv 并存）。注意 16.7.19 已一年半不再更新，安全修复只进 17.x。

## 三、frida 生态图谱（2026 现状）

| 层 | 组件 | 状态 | 说明 |
|---|---|---|---|
| 核心 | frida 17.x | 活跃（17.23.x） | Barebone 后端、frida-pm、fruity |
| 核心 | frida 16.7.19 | 冻结终版 | 16.x 稳定保守线，配 frida-tools 13.7.1 |
| CLI | frida-tools | 随主线活跃（17 线；16 线终版 13.7.1） | `frida` REPL、`frida-trace`、`frida-ps` |
| 封装 | objection | 维护放缓 | 快速安全检查（绕 SSL pinning、root 检测、keystore dump） |
| 封装 | medusa | 活跃 | 90+ 模块 + Mango CLI，objection 的现代替代 |
| 抓包 | r0capture | 可用 | Java+Native 双层抓包输出 pcap，证书校验免疫的兜底 |
| 组件拦截 | noxen | 活跃 | 组件通信拦截 + 攻击面映射（详见第五节） |
| MCP | frida-mcp | 活跃 | Claude 等 LLM 直连 frida（详见第四节） |
| 脚本库 | frida-scripts（lasting-yang 等） | 社区持续 | hook 安卓常规点位的现成脚本 |
| 反检测 | strongR-frida-android | 活跃 | 上游自动 patch 版 server |
| 反检测 | undetected-frida（zer0def） | 活跃 | 自动 patch + 预编译 |
| 桥 | frida-il2cpp-bridge | 活跃 | Unity il2cpp 结构 dump 与调用 |
| 服务化 | frida-remote / gadget 模式 | 随核心 | 云真机集群远程调试用 `frida -H` |
| 模拟运行 | vardoger | 极新 | Python 驱动的 Android ARM64 模拟运行时（详见第六节） |

**版本纪律**（重要）：`frida`（python 包/CLI）与 `frida-server`（设备端）**主版本必须一致**，否则 `Failed to enumerate processes` 类错误。strongR 版本同理：strongR 17.3.x 配 frida-tools 17.3.x。16.7.19 线则全套 16.7.19 + 13.7.1。

## 四、frida-mcp：LLM 直连 frida

注意与 dnakov/frida-mcp 区分：后者是另一个更简的 attach/spawn 采样器，勿混淆。

- **形态**：TypeScript 实现的 MCP（Model Context Protocol）服务器，专为 **Frida 17** 设计（依赖 `frida@17`，Node.js 20+，MIT）。
- **规模**：约 **62 个工具 + 15 个资源**（分类：设备 4、进程 6、会话 5、脚本管理 4、导出 1、内存 6、Java 6、Native hook 2、Android 6、文档 1、引导 2、配方 8、静态分析 7、反检测 2）。
- **参数化 Hook 模板（Recipe 库）**：
  - `hook_okhttp_requests`——拦截所有 OkHttp 客户端的 `Request$Builder.build`；
  - `hook_java_method_recipe`——hook Java 方法所有重载，支持 where 谓词、max_emits、参数截断；
  - `hook_native_export`——对导出符号做 `Interceptor.attach`；
  - `trace_class_methods`——等效 `frida-trace -j` 批量类方法追踪；
  - `dump_mac_doFinal`——hook `javax.crypto.Mac.doFinal` 抓 HMAC 密钥/数据；
  - `bypass_ssl_pinning`——TrustAllCerts、OkHttp3、Conscrypt 等多路 unpinning；
  - `bypass_root_detection`——root 检测绕过（思路源自 @dzonerzy/fridantiroot）。
- **安装**：`claude mcp add frida-mcp -- npx -y frida-mcp@latest`；也可手动写 `.mcp.json` 或源码构建。手动配置示例：

```json
{
  "mcpServers": {
    "frida-mcp": {
      "command": "npx",
      "args": ["-y", "frida-mcp@latest"]
    }
  }
}
```

- **价值定位**：把「写 frida 脚本」变成「对 Claude 说一句话」——LLM 按需调用 attach/hook/dump 工具组合，适合把逆向经验产品化进 Agent 工作流（新项目，社区采用早期）。

## 五、noxen：组件通信拦截 + 攻击面映射

（GPL-3.0。）

- **一句话**：基于 Frida hook 运行中 Android 进程的 Java 方法，**实时映射组件间通信与攻击面**——把 Android 四大组件的数据流变成可视/可改/可丢的拦截面板。
- **hook 点**：`getIntent`（入站）、`startActivity`/`sendBroadcast`/`startService`（出站）、PendingIntent 创建路径（`getActivity` 等）。
- **每个事件展示**：action、component、data URI、flags、categories、extras、PendingIntent flags、可选 Java 堆栈；并附加目标组件的 **exported 标志与所需权限（含保护级别）**，区分入站接收者与出站解析目标，广播还显示 receiverPermission——**等于自动生成组件攻击面清单**。
- **Info 应用标签页**：应用快照（身份、构建标志、签名、权限）+ 全组件可搜索清单，按 open/weak/protected 分类。
- **干预能力**：转发前可改 intent 的 action/data/categories/flags/extras，可直接丢弃被拦截的 intent——**Intent 级的 Burp Repeater**。
- **工程化**：Intercept/History 独立过滤器；会话保存为 `.noxen` 项目文件；`noxen-analyze app.apk` 用 androguard 离线分析 APK 预生成 hook 配置。
- **使用**：`pip install .` 后运行 `noxen`（要求 PC 端 frida 与设备 frida-server 版本匹配，如 `pip install frida==17.7.3`）。
- **何时选它**：挖组件导出/隐式 intent/PendingIntent 劫持类漏洞（SRC 里 IPC 面一枪出全景）；配合手动 fuzz intent 参数比纯静态看 manifest 快一个量级。

## 六、r0capture 与 vardoger：抓数据与跑 so 的两条腿

### r0capture

- 定位：**Java 层（SSLContext/okhttp/Conscrypt 等 API 点）+ Native 层（SSL_write/SSL_read）双层抓包**，输出 pcap；App 用证书校验/非 HTTP 协议（protobuf 私有协议、MQTT 等）时的兜底。
- 与 noxen 分工：noxen 拦组件通信（Intent 流），r0capture 拦网络流量（socket 流），互不替代。

### vardoger（2026 年新物）

- PyPI 包 `vardoger-vm`（LGPL-3.0，C++ 核心 + Python 绑定；极新，采用自担）。
- **定位**：**Python 驱动的忠实（faithful）Android ARM64 模拟运行时**——unidbg 同赛道（离线跑 so，不碰真机），但交互语言是 Python、设计目标 packer-agnostic（壳无关）。
- **能力**：
  - `vm = VM(package="com.foo.bar", sdk=31)` 配环境，`vm.serve_apk("base.apk")` 喂 APK；
  - `so = vm.load("lib.so")` 返回 Module（bias、jni_onload、size、init_array、lookup）；
  - `vm.run_init(so)` 跑 `DT_INIT + .init_array`——**加固 so 自解密就发生在这里**；
  - `vm.call(so.jni_onload, ...)` / 调任意函数；
  - 读写内存与寄存器、hook 代码与内存、**分配 trampoline 用 Python 实现 libc/JNI stub 并捕获调用**、注册 Java 方法、**捕获 DEX**（跑壳时 dump 解密后 dex）。
- **实现**：后端是 C-ABI 的 `libvardoger_capi.so`，Python 侧纯 ctypes 驱动（无 pybind11，免编译对抗）。
- **典型用法**：

```python
from vardoger import VM, Reg

vm = VM(package="com.foo.bar", sdk=31)
vm.serve_apk("base.apk")          # 把 APK 提供给 loader 查找位置

so = vm.load("lib.so")            # -> Module(bias, jni_onload, size, init_array, lookup)
vm.run_init(so)                   # DT_INIT + .init_array：加固 so 在这里自解密
ver = vm.call(so.jni_onload, ...) # 调 JNI_OnLoad 走完注册流程
# 之后：读写内存/寄存器、hook、Python 侧实现 libc/JNI stub、捕获 DEX
```

- **何时选它**：脱壳（init_array 自解密 + DEX 捕获）、离线还原签名算法（Python 里补 stub 比 unidbg 写 Java 补环境顺手）、CI 自动化跑样本。风险：单人新项目，API 未稳定。

## 七、barbatos / R2Droid / LSPilot：AI 调试器新势力

- **barbatos**：**零配置 Android 运行时调试器，内置 Frida API + MCP Server**，口号「Empowering AI Agents with dynamic instrumentation」。单一原生二进制（macOS，curl 安装脚本一键装），REST 风格 `POST /v0/api/<op>`；能力：实时枚举 Java/Kotlin 类、递归遍历对象层级（字段/Map/集合）、方法 hook 并实时改行为。架构为 Kotlin Multiplatform 原生桥（CInterop 静态链接 Frida Core，注入 JS agent 到 ART/ObjC）。设计目标就是让 LLM 自主调试（崩溃诊断、运行时探索）。目前仅 macOS，Linux/Windows 计划恢复。
- **R2Droid**：**Radare2 系 Android 应用（Kotlin + Compose）**，手机上直接做 native 逆向：r2ghidra/r2dec/r2native/aipdg 反编译切换、Sugiyama 布局图（CFG/调用图/xref 图）、ESIL 调试（断点/单步/寄存器）、hex+patch、**内置 AI 助手（OpenAI 兼容 API，流式对话 + `[[cmd]]`/`<js>` 动作）**、**内置 r2frida 连真机进程**、Frida hook 模板生成、Markdown/HTML/JSON 报告导出。CI 出 Full/Proot-only 两种 APK。等于「口袋版 r2 + frida + AI」。
- **LSPilot**：AI 驱动的 LSPosed 动态逆向助手（模块形态，zygote 期常驻，与 frida 系互补）。本篇只做框架对比定位，原理与用法详见 LSPilot 专篇。
- **三者关系**：frida-mcp（PC 侧 MCP→frida）、barbatos（PC 侧单二进制 REST/MCP→frida）、R2Droid（端侧 GUI+r2+AI）、LSPilot（端侧 LSPosed 模块+AI）——同一条「LLM 直接操作运行时」趋势在四个生态位的投影。

## 八、native inline hook 三家对比：Dobby / ShadowHook / Renef

先厘清关系：**frida 的 Interceptor 本身就是 inline hook**——Gum 引擎在目标函数入口写跳转、把被覆盖的原始指令重定位到 trampoline 执行后跳回，ARM64 上有专用指令分析器处理 PC 相对指令。所以「有 frida 就不需要下面三家」对多数逆向任务成立；下面三家解决的是**没有 frida 运行时、要嵌进自家 so/模块、或要绕 RASP 对 frida 特征检测**的场景。

| 维度 | Dobby | ShadowHook | Renef |
|---|---|---|---|
| 仓库 | jmpews/Dobby（维护放缓） | bytedance/android-inline-hook（持续维护） | Renef（Lua 5.4 脚本，新锐） |
| 出身 | HookZz 继任者，个人/社区项目 | 字节跳动生产级（抖音/TikTok/飞书在用） | 独立工具，灵感来自 frida + radare2 |
| 平台 | 多平台（iOS/Android/macOS/Windows/Linux），arm/arm64/x86 | **仅 Android**，thumb/arm32/arm64 | **仅 Android ARM64** |
| hook 方式 | inline hook（指令重定位 + trampoline） | inline hook（入口改跳 + 指令修复），号称生产级稳定 | **双路：PLT/GOT 重定向 + Capstone 反汇编驱动的 inline trampoline**（重定位修复原指令） |
| 脚本接口 | C/C++ API（编译期链接） | C API + Java 封装（Maven `com.bytedance.android:shadowhook`） | **Lua 5.4**，类 frida API（Module/Memory/Hook/Thread），运行时热下发 |
| Java 层 | 无（纯 native） | 无（配 LSPlant 才有 Java） | 可经 **JNI 拦截 Java 方法** |
| 注入/部署 | 嵌入自己 so；eikarna/DobbyAndroid 有预编译 | 嵌入 App（RASP/性能监控）或自制注入器 | **memfd + shellcode 注入，无需 ptrace**（对 ptrace 检测免疫）；有 magisk-renef 模块（仿 magisk-frida 自动运行）、r2renef（radare2 IO 插件，静态分析活进程）、Gadget Mode |
| Android 支持 | 跟随社区，老 ISSUE 挂多年（#20 hook detach 2018 至今） | **Android 4.1-15（API 16-35）**，MIT | ARM64 主线，版本矩阵以官方文档为准 |
| 姊妹项目 | BepInEx/Dobby（Windows 稳定性分支） | **ByteHook（PLT hook 库，同厂）**——PLT/GOT 偷懒路线 ShadowHook 之外的另一半 | magisk-renef / r2renef 生态 |
| 适用场景 | iOS+Android 双端游戏修改器、需要多平台的注入框架 | 生产 App 埋点/RASP、稳定优先的商用 hook | **RASP 对抗**（无 frida 特征、无 ptrace）、radare2 用户想 hook 活进程 |
| 与 frida 关系 | frida 之外的独立实现；可用于给 frida 失效环境补 native hook | frida Interceptor 的「无 frida 运行时」替代；很多国产 RASP 自己就是它写的 | frida 的轻量替代品，官方提供「Frida to Renef」迁移指南 |

**Renef 快上手**：内置 Lua 5.4 引擎，API 命名刻意对齐 frida（`Module`/`Memory`/`Hook`/`Thread`），从 frida 迁移主要把 JS 语法换成 Lua；`auto-watch` 模式支持加载多个脚本并热重载；配套 TUI 内存扫描器做交互式搜索。部署三形态：直连进程（memfd 注入）、**Gadget Mode**（类 frida-gadget）、**magisk-renef** 模块（Magisk/KernelSU/APatch 开机自启，仿 magisk-frida 思路）；静态侧有 **r2renef**（radare2 IO 插件，r2 命令直接分析活进程内存）。

**选型口诀**：要嵌入自己 so 跨平台 → Dobby；Android 生产级稳定/商用 → ShadowHook（配 ByteHook 做 PLT）；被 RASP 盯死 frida 特征、要 Lua 热脚本 → Renef；只是逆向分析 → 直接 frida Interceptor。

**Cydia Substrate 现状**：实质死亡。2013 年 Saurik 带到 Android，**从未适配 ART**（Android 5.0 起默认运行时），2017-2018 从 Play Store 下架。Android 侧已被 Xposed→LSPosed 彻底取代；iOS 侧也被 Substitute/libhooker 等替代。新项目任何情况下不要选它，考古读代码除外。

## 九、ARTHookScripts：smali 级 inline hook（ShadowFrame 机制）

- **一句话**：frida 运行时**解析 smali 并实现 Java 方法体内任意位置的 inline hook**——突破 frida `Java.use` 只能 hook 方法入口的限制，做到「方法第 N 条字节码处下断改值」。
- **环境限定**：Android 10（Pixel XL / AOSP，BUILD_ID=QP1A.191005.007.A3）+ frida 16.7.0——因为 ART 结构体偏移多为**硬编码**，跨版本要重新适配（repo 已修 Frida 17 兼容问题）。这与第二节「16.7.x 保守线」互为印证：摸 ART 内存的脚本锁旧版最稳。
- **核心 API**：`pathToArtMethod("com.x.Y.z").showSmali()`（dump 方法 smali）、`.showOatAsm()`、`showNativeAsm("libfk.so!0xaa11a0")`、`getFunctionBoundary(addr)`（oat-header/符号表/CFG 多级函数边界识别）。
- **五种思路**：
  1. **JDB/JVMTI**：frida 启动 jdwp 线程，用 JVMTI 实现断点调试（标准调试协议路线）；
  2. **Trace Function 模式匹配**：按符号与指令格式定位 libart 内部关键 trace 函数（参考 AOSP trace.h）；
  3. **Inline Hook Smali（招牌）**：改字节码 + ShadowFrame 操纵，机制链条见下；
  4. **快速执行（oat 模式）**：解析 oat 二进制符号提升反汇编可读性，二进制层面 inlinehook；
  5. **自定义 smali 解释器**：移植 ART `vmInterpret`（Execute 交换解释器）实现，导出函数作 frida bridge 完全代理系统解释器——流程控制最佳、跨版本兼容最好。
- **Inline Hook Smali 机制链条**（原理详解放《02-frida/高级/yahfa与arthook.md》专节,此处速记）：
  `invoke-static` 覆盖原字节码 → 跳到 `Java.registerClass` 注册的 JS 回调 → 经 **ManagedStack 取上级 fragment → ShadowFrame**（= caller Java 方法在解释器里的执行上下文：ArtMethod + dex_pc + VRegs 寄存器组）→ JS 里读出 hook 点现场值 → 手动解释执行被覆盖的原指令 → **SetVReg 改写上一帧寄存器**推进执行。前提：禁用 oat（方法必须走解释器才有 ShadowFrame）+ 处理 dex cache。
- **用途**：抽取壳分析（方法体逐条观察解密过程）、风控函数中途篡改变量、需要「方法内断点」却不能上调试器的对抗场景。

### ART 内部结构参照（AOSP 源码）

理解上述链条所需的三个 ART 结构（读 AOSP `master` 分支即可对上）：

| 结构 | 源码位置 | 关键字段/操作 | 在链条中的角色 |
|---|---|---|---|
| `ManagedStack` | `art/runtime/stack.h` | `PushShadowFrame()` / `PopShadowFrame()`，串起 interpreter 的 ShadowFrame 段与 native QuickFrame 段 | 每个 `art::Thread` 一条；frida 回调里沿它回溯拿「上级 fragment」 |
| `ShadowFrame` | `art/runtime/interpreter/shadow_frame.h` | `ArtMethod* method_`、`dex_pc`、`link_`（caller 帧）、**VRegs 虚拟寄存器数组**（两种布局：解释器布局分离 vregs 与引用数组；也可在 native 栈上分配） | = 当前 Java 方法在解释器里的完整执行上下文；读寄存器现场/`SetVReg` 改值都打在它身上 |
| 解释器循环 | `art/runtime/interpreter/interpreter_common.cc` | `Execute(ShadowFrame&, ...)` 取指执行；`ArtInterpreterToCompiledCodeBridge` 做解释器↔编译代码互跳 | 被覆盖指令「手动执行」= 用 JS 侧移植的解释逻辑模拟一轮这个循环 |

**为什么必须禁 oat**：AOT/JIT 编译后的方法直接跑机器码，线程上只有 QuickFrame 没有 ShadowFrame，寄存器也躺在真实 CPU 寄存器里——字节码替换根本不会被「执行」。禁用后方法回落解释器，ShadowFrame 才存在，整条链才通。这也是 ARTHookScripts 锁定特定 Android 版本的原因：`ShadowFrame`/`ArtMethod` 的字段偏移随版本漂移，脚本里是硬编码。

## 十、frida_unpin.py 与 Android API 34

- **akabe1/my-FRIDA-scripts** 收录四个脚本（均为 **.js**，无 .py，已停更）：`frida_multiple_unpinning.js`（多路 pinning bypass，**首 Case 即替换 `SSLContext.init` 为 accept-all TrustManager**——`Java.registerClass` 注册空实现 TrustManager 后在 init 重载里换掉 trustManager 参数，注释标注该 Case 针对 Android < 7 的老 TrustManager 用法）、`frida_universal_pinning_bypasser.js`（递归 TrustManager）、`frida_netsecconfig_bypass.js`（networkSecurityConfig pinning）、`keystore_spy.js`（Keystore 调用分析）。OWASP MASTG 收录其为最全面的 TLS pinning bypass 脚本之一。
- 「frida_unpin.py」这个 **.py 文件名**与「**API 34 唯一验证有效方案**」的说法无公开出处，本质大概率仍是 SSLContext.init 替换思路的 Python 驱动包装。**API 34（Android 14）实战建议**：通用方案先用 httptoolkit frida-android-unpinning 或 akabe1 multiple-unpinning（v2+ 含 TrustManagerImpl.verifyChain、Conscrypt 等新 Case）；均失败再上 r0capture 在 SSL_write 层直接拿明文，绕开整个 pinning 问题。
- **同类替代**：SSLSlayer（codeshare）同样是 SSLContext.init + allow-all TrustManager 思路的现代维护版，可作为 API 34 场景备选。

## 十一、Xposed 系现状矩阵（2026）

| 框架 | hook 引擎 | Android 支持 | 状态 | 结论 |
|---|---|---|---|---|
| Xposed（原版） | app_process 替换 | ≤8.x 场景 | 停更（2017 后） | 考古 |
| EdXposed | YAHFA / SandHook | 5.0~10 最佳 | 停更 | 老设备备选 |
| TaiChi（太极） | Pine（磁吸）/免 root 虚拟化 | 8~12 | 停更 | 免 root 路线被 gadget 取代 |
| VirtualXposed | 虚拟容器 + Epic | 5~10 | 停更 | 检测重，不建议 |
| **LSPosed** | LSPlant（内联 hook 引擎） | stable 8.1~14；**canary 支持 15** | 官宣停更，之后仍断续发 canary | Java 层持久 hook 唯一主选（AI 线配 LSPilot） |

**LSPosed 时间线**：2024-01 LSPosed 团队官宣停止开发 → 社区恐慌期 → 内部版继续支持 Android 15 → 目前 stable 线停在 8.1~14。**行动建议**：主力分析机留在 Android 14 跑 stable 最稳；15 用 canary 自担稳定性；16 上没有可靠 Xposed 方案，hook 需求全走 frida。

**引擎补充**：LSPlant 是 LSPosed 抽出的通用 ART hook 库（inline hook 实现方法替换），单独可用；YAHFA/SandHook/Epic/Pine/FastHook 属于历史演进链，新项目不要基于它们开发。native 层持久 hook 需求则接第八节 ShadowHook/Dobby。

## 十二、共存与互斥

- **frida ↔ LSPosed 可共存**（同一台 Magisk+Zygisk 机器）：常见组合是 LSPosed 挂 HMA/隐藏模块过检测，frida 做分析注入。注意：
  1. hook 同一方法时后到者覆盖先到者的 entry，可能互相"吃"掉——避免对同一函数双框架同时下钩，或接受"最后 hook 的生效"。
  2. 有些反检测模块（如 Shamiko 的 DenyList）会**隐藏/干扰 frida-server**（进程被 deny 时 frida 连不上），把 `frida-server` 加入排除或改名后再试。
  3. Stalker 与 LSPosed 模块都在 ART entry 上动手，极端时崩溃——逐个排除。
- **frida-server ↔ frida-gadget 互斥**：同一进程两种形态只能选一；gadget 模式下 `frida -U Gadget` 连接。
- **frida ↔ Renef**：理论上可同时注入（不同 agent），但都在改入口指令，同一函数双 inline hook 必炸；Renef 的定位本来就是「frida 被检测时的替补」，二选一。
- **noxen/r0capture 同时挂**：都是 frida 脚本，同一 session 可并行，注意日志混流。
- **双开/平行空间类容器 + frida**：容器内进程名带 `:xxx` 后缀，`frida-ps -Ua` 注意区分。

## 十三、Android 版本 × 框架兼容速查

| Android | frida | LSPosed | native inline hook | 备注 |
|---|---|---|---|---|
| 12/13 | 全功能（16.7.19/17.x 均稳） | stable | ShadowHook 原生支持 | 分析机黄金版本 |
| 14 | 全功能 | stable（最后 stable 线） | ShadowHook 支持（API 34） | 推荐主力停留版本 |
| 15 | 全功能（16.x/17.x 均可） | 仅 canary，偶发崩溃 | ShadowHook 官方支持到 API 35 | 严格任务退回 14 |
| 16 | 可用（17.x 主线跟进，个别机型需最新版） | 无可靠方案 | ShadowHook 官方未确认；Dobby/Renef 社区跟进 | hook 需求走 frida；root 用 Magisk v30+/KSU |

**root 底座对 hook 框架的影响**：
- Magisk v30（UI 重写、隐藏包名增强）内置 Zygisk → LSPosed 原生支持。
- KernelSU/APatch 无内置 Zygisk → 装 **Zygisk Next**（v1.2.2 起闭源）或 **ReZygisk**（开源，SUSUFS 兼容口碑更好）后再挂 LSPosed。
- Zygisk 本身会被部分风控扫（`dlopen` 白名单/`__system_property` 检查），高检测场景用 KernelSU+SUSUFS+ReZygisk 内核级隐藏组合；Renef 的 magisk-renef 模块同样可被 Magisk/KSU/APatch 承载。

## 十四、frida 常用命令速查（老手也常忘）

```bash
# 设备与进程
frida-ls-devices                     # 列设备（USB/远程/云真机）
frida-ps -U                          # 列 USB 设备进程
frida-ps -Ua                         # 只列运行中的 App（带名字）
frida-ps -D <device-id>              # 指定远程设备（frida -H ip:port 场景）

# 注入
frida -U -f com.target.app -l hook.js --no-pause   # spawn：最早时机，过初期检测
frida -U -n "AppName" -l hook.js                    # attach：附加已运行进程
frida -U Gadget -l hook.js                          # gadget 重打包模式
frida-trace -U -i "open" -i "*sscronet*"            # 快速跟 native 导出函数
frida-trace -U -j com.target.CryptoUtil            # 快速跟 Java 类全部方法

# 16.x 保守线（ART 偏移类脚本用）
pip install frida==16.7.19 frida-tools==13.7.1      # venv 隔离，与 17.x 并存

# server 端（设备 shell 内，配合改特征）
./fs16 -l 127.0.0.1:8899 &           # 改名 frida-server + 换端口（去 27042 特征）
```

**spawn vs attach 怎么选**：
- 目标在 `Application.onCreate`/so `JNI_OnLoad` 里做检测或解密 → 必须 **spawn**（`-f`），attach 时早已错过。
- 只分析运行中接口调用 → attach 更省事，别乱重启触发风控。
- spawn 模式记得 `--no-pause`（新版默认），并考虑 `Java.perform` 延迟绑定。

## 十五、常见坑（高频问题）

| 症状 | 原因 | 解法 |
|---|---|---|
| `Failed to enumerate processes` | frida 与 frida-server 版本不匹配 | 两端主版本对齐（strongR 同理；16.7.19 全套对 13.7.1） |
| attach 后无输出、App 卡死 | 目标有反调试 ptrace 自附加 | spawn 模式 + 先 hook `ptrace`/`dl_open` 返回 0；或改用 Renef（memfd 注入无 ptrace） |
| 一 attach 就闪退 | frida 特征检测（端口/线程名/maps） | strongR-frida + 改名改端口 + LIEF 改 so 特征 |
| hook Java 类报 `ClassNotFoundException` | ClassLoader 不对/加固下类未加载 | spawn + `Java.choose`，或枚举 classloader 换 loader |
| native `Module.findExportByName` 返回 null | so 未加载/符号被剥 | `Process.enumerateModules` 确认；剥符号时按基址+IDA 偏移 hook |
| 高版本 Android hook 无效 | 工具链过老（frida <16） | 升 17.x；Android 15/16 用最新版 |
| ARTHookScripts 类脚本崩溃/偏移错乱 | ART 结构体偏移跨版本变化 | 锁 Android 10 + frida 16.7.0 环境，或用其「自定义 smali 解释器」模式 |
| noxen 起不来 | PC 端 frida 版本 ≠ 设备 frida-server | 两端版本必须一致（如 17.7.3），`pip install frida==<server版本>` |

## 十六、选型口诀

- **临时看一眼**：frida REPL，两分钟出结果。
- **成套自动化检查**：medusa（新）> objection（老但资料多）。
- **让 LLM 代驾**：PC 侧 frida-mcp（Claude/MCP 生态）或 barbatos（单二进制 REST）；端侧 R2Droid（r2+AI）。
- **组件/IPC 攻击面**：noxen（自动出攻击面清单 + intent 改包）。
- **抓包兜底**：r0capture（pinning/私有协议免疫）。
- **离线跑 so/脱壳**：vardoger（Python 手感）或 unidbg（成熟稳重，见专篇）。
- **要长期挂在设备上跑**（群控/自动化/自用模块）：LSPosed 模块，前提 ≤Android 15（AI 辅助配 LSPilot）。
- **无 root**：frida-gadget 重打包（配合 apktool + Uber Apk Signer）。
- **检测地狱**：先过检测（strongR-frida + 改名端口 + gadget），frida 特征被 RASP 盯死时换 Renef（Lua + memfd 注入）；再谈 hook 什么。
- **Native 算法**：只有 frida（Interceptor/Stalker）或直接 unidbg/vardoger，Xposed 系帮不上。
- **生产级 native hook**（自研 RASP/监控方向）：ShadowHook（+ByteHook 做 PLT），别碰 Cydia Substrate（已死）。

## 安装速查

> python 系统一进本库 tools-env 虚拟环境装（沙箱坑：HOME 只读时 uv 默认缓存路径会挂）：
> `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p re/tools-env/.venv/bin/python <包>`
> 下表 `uv pip install` 均指此法；版本纪律见第二节（python 包 ↔ frida-server 主版本必须一致）。

| 工具 | 安装 |
|---|---|
| frida 17 线（默认） | `uv pip install frida frida-tools` |
| frida 16.x 保守线 | `uv pip install frida==16.7.19 frida-tools==13.7.1`（独立 venv 与 17 线并存） |
| objection | `uv pip install objection` |
| medusa | 待核 |
| frida-mcp（62 工具配方版） | `claude mcp add frida-mcp -- npx -y frida-mcp@latest` |
| noxen | 源码 `pip install .`（仓库待核） |
| barbatos | github.com/victorlpgazolli/barbatos（macOS 单二进制，curl 脚本装） |
| Renef | github.com/Byterialab/renef（r2renef：github.com/Ahmeth4n/r2renef；magisk-renef 模块） |
| Dobby | github.com/jmpews/Dobby（嵌入自编译） |
| ShadowHook | github.com/bytedance/android-inline-hook（Maven `com.bytedance.android:shadowhook`） |
| LSPosed | github.com/LSPosed/LSPosed（Magisk 模块 zip 刷入；canary 支持 15） |
| LSPilot | GitHub Releases（LSPosed 模块；API 文档 lspilot.fun） |
| R2Droid | APK 直装（仓库待核） |
| r0capture | github.com/r0ysue/r0capture |
| lamda | github.com/firerpa/lamda（设备端 server） |
| strongR-frida-android | github.com/hluwa/strongR-frida-android（release 下对应版本 server） |
| undetected-frida | github.com/zer0def/undetected-frida |
| httptoolkit unpinning 脚本 | github.com/httptoolkit/frida-interception-and-unpinning |
| akabe1 unpinning 系列 | github.com/akabe1/my-FRIDA-scripts |
| stackplz | github.com/SeeFlowerX/stackplz（eBPF，root） |
| ReShift / reconbridge / Veridiff | 待核 |
