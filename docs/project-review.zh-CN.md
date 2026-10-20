# 项目评估与竞品比较

> **状态更新：**下文的缺口表与早期环境检查记录评估基线 `0059a9a`，用于保留
> 原始问题和竞品比较，不能当作当前分支能力清单。现在已有统一 CLI、12 类
> profile、依赖锁、资源/锁/证据底座和回归用例，深度分析仍需补全。
> 见[交付状态](delivery-status.zh-CN.md)、[支持矩阵](runner.zh-CN.md)。
> 最后修改未复验，后续安装与测试使用[交接 Prompt](agent-completion-prompt.zh-CN.md)。

评估日期：2026-10-19。基线：`0059a9a`（`origin/main`）；本文同时记录本地
`codex/readme-review` 分支的修复。基线包含 190 个跟踪文件，其中 Markdown 174 篇、
Python 脚本 11 个、Shell 脚本 3 个。文件数量表示资料规模，不等于验证覆盖率。

评估依据为仓库文档、辅助脚本静态检查、离线复现，以及竞品官方仓库 README。
这次没有对外部资产实施安全扫描，也没有运行完整 APK/固件研究任务。

## 1. 问题与能力概览

项目适合定位为**逆向研究方法与 Agent 工作流层**：平台与技巧覆盖广，场景路由
明确，APK 流程已定义阶段、产物和降级方式，固件分支已有可运行辅助脚本。

从“给一个资产就得到结果”的产品目标来看，主要风险是资料、运行能力与验证结果
混在一起：APK 主流程仍是 Markdown 指令；大部分平台没有可调用执行器；原机器
运行记录没有随公开仓库发布。因此，“全自动”“已验证”等结论需要限定对象和环境。

| 优点 | 仓库依据 | 对用户的价值 |
| --- | --- | --- |
| 平台 × 技术 × 场景的多入口组织 | [SKILL.md](../SKILL.md)、三个分支索引、20 个使用场景 | 不必先读完整库，能按问题选路线 |
| 移动端与底层技术覆盖较细 | `techniques/02-frida/`、脱壳、算法、Syscall、内核、平台文档 | 适合需要反复切换工具或分析层级的研究 |
| APK 工作流有阶段与产物约定 | [pipeline.md](../pipeline/pipeline.md) | 有基础可转成程序化 DAG |
| 固件候选已有脚本和本地台账 | [cve-hunter](../cve-hunter/README.md)、[fw-discover](../fw-discover/README.md) | 比单纯链接合集更接近实际操作 |
| 区分候选与披露，包含设备保护与清理 | 模块 README、[device-testing.md](../device-testing.md)、[test-values.md](../test-values.md) | 提供可复核研究的流程基础 |
| 公开内容排除了大部分机器产物 | [.gitignore](../.gitignore) | 仓库较易下载，也降低误提交风险 |

| 短板 | 具体后果 | 补全方向 |
| --- | --- | --- |
| 没有统一的资产入口和可运行调度器 | 给 URL、本地固件或 PE，无法通过同一命令进入流程 | 输入模型、类型识别、工作流注册、CLI |
| 工具安装与依赖仍由说明文档驱动 | 新机器难以复现原环境，版本兼容性不明确 | 依赖清单、锁文件、按 profile 的健康检查 |
| 分析证据尚未形成共享结构 | 很难跨 APK、后端、固件、二进制合并发现 | Asset/Evidence/ToolRun/Finding 数据模型 |
| 规则偏启发式且新颖性判断有误区 | 候选可能被误当成真实漏洞或新漏洞 | 验证器、对照样例、补丁与公告语义比较 |
| 原机器状态残留在通用流程中 | 新安装会引用不存在的报告、设备、目录 | 环境探测与本地产物降级；历史记录标注日期 |
| 缺少公开基准和完整链路验收 | “已跑通”的证据主要留在忽略目录 | 可再分发样例、集成测试、故障场景 |
| 多平台知识不等于多平台运行 | Windows/macOS/Linux 工具与命令差异会破坏链路 | OS 能力矩阵与真实执行测试 |
| 来源约定前后不一致 | 禁止外链与 `Sources` 附录并存，原文追溯不便 | 明确正文精简、附录保留来源 |

## 2. 技术分析：根因、触发与入口

### 本分支已修复

| 问题 | 根因与触发 | 影响入口 | 修复 |
| --- | --- | --- | --- |
| 技能元数据未被识别 | `SKILL.md` 开头使用 `\---`，不符合 YAML frontmatter 分隔格式；原 description 也过长 | 支持 Agent Skills 的客户端发现技能时 | 使用标准 `---`，缩短 description，整理路由与可选本地产物 |
| 固件 `--status` 没有输出 | 解析了参数，但 `main()` 只处理默认调用与 `--once` | `python fw-discover/fw.py --status` | 无 `--once` 时进入状态输出 |
| gzip 原始样本被改写 | `extract_firmware()` 解压后调用 `binpath.write_bytes(blob[:1])` | gzip 包装固件进入解包流程 | 删除源文件写入，解压层仅在内存中更新 |
| CVE 二进制复核请求路径不完整 | `.ipk` URL 只拼 release 和 Filename，遗漏 `packages/<arch>/<feed>/` | `hunter.py --verify` | 按同一候选的 release/arch/feed/filename 拼接下载路径 |

gzip 问题通过临时样本复现：有效 gzip 输入在基线调用后由 58 字节变为 1 字节，
即使解包失败也会污染原始样本。修复后的验收要求成功与失败路径都保持原始字节。

`.ipk` 问题核对了 OpenWrt 官方索引：
`23.05.0/packages/x86_64/base/Packages.gz` 的 `Filename` 为文件名，
例如 `464xlat_13_x86_64.ipk`。它不能直接相对于 release 根目录下载。

### 仍需下一阶段处理

| 优先级 | 问题 | 代码或文档依据 | 建议 |
| --- | --- | --- | --- |
| P1 | 任意本地固件缺少入口 | `fw.py` 依赖 DD-WRT/OpenWrt 种子队列，无 `--input <local firmware>` | 增加通用 Asset intake 与本地输入 profile |
| P1 | “命令注入候选”不证明数据流 | `analyzers.py:scan_file()` 检查网络标记与 exec 字符串同文件出现 | 保留候选级别，追加调用点、参数传播、配置与行为验证 |
| P1 | NVD 零命中被当成新颖性门槛 | `fw-discover/cve-pipeline.md` 与 `novelty.py` | 比较根因、受影响版本与补丁；同组件已有 CVE 不排除新漏洞 |
| P1 | 新颖性聚合可掩盖检索失败 | `novelty.py` 有 `ERR` 和 `NEW` 时最终仍可能输出 `NEW` | 使用 `unknown`，把失败来源与已完成检索分开保存 |
| P1 | 单实例锁不是原子获取 | 两个脚本均先判断 `.lock` 再 `write_text()` | 使用原子锁/文件锁、所有权与过期处理；测试并发 |
| P1 | 进度不能可靠表达失败重试 | `hunter.py` 在下载前把组合放入 done；`fw.py` 将部分失败记为 done | 区分 completed/skipped/failed/retryable，持久化失败原因 |
| P1 | 网络和解包预算不够严格 | 固件先下载到内存再检查大小，gzip 解压无产物预算 | 流式上限、解压大小/文件数/路径/时间限制 |
| P1 | 缺少多类资产的执行与确认链 | 多个平台只有知识文章或人工步骤 | 可调用 adapters、profiles、验证器及集成测试 |
| P2 | 配置携带本机假设 | `novelty.py` 固定 `127.0.0.1:7897` 代理；`env_scan.py` 使用 macOS 路径与 `system_profiler` | 显式配置、PATH/环境探测、按平台实现 |
| P2 | APK 初始化从 `$0` 推断目录 | Markdown 代码块被复制执行时 `$0` 通常指 shell 而非仓库脚本 | 从加载的技能路径/显式配置确定根目录 |
| P2 | 快照与报告引用无法复现 | 被忽略的 `data/`、雷达报告、私有 CHM，部分历史数字写入通用说明 | 标注 local-only；发布脱敏样例和验证方法 |
| P2 | 覆盖描述落后于目录变化 | 旧入口说 18 场景、11 技术区；实际场景已到 20，技术区继续扩展 | 保持入口与索引一致，用结构校验减少漂移 |

上述优先级表示交付与可靠性问题的处理顺序，不等同于已确认的远程可利用漏洞评级。

## 3. 验证步骤

在仓库根目录执行，Windows 将 `python3` 换为 `python`：

```bash
python3 -m unittest discover -s tests -v
python3 cve-hunter/hunter.py --help
python3 cve-hunter/hunter.py --status
python3 fw-discover/fw.py --help
python3 fw-discover/fw.py --status
python3 pipeline/env_check.py
```

本分支的离线回归用例验证原始样本保留、固件状态输出，以及 CVE 包下载和 Banner
升级条件。测试使用临时目录和合成数据，不访问公开研究目标。

Agent Skill 校验需要带 PyYAML 的技能校验器，验证标准 YAML 与必需字段。
Markdown 检查应同时校验文件链接与章节锚点；不应把“链接目标存在”当成完整业务验收。

本机为 Windows，环境检查返回 `2`：缺少 JADX、Apktool、Android SDK/AVD，且仓库
本地 `tools-env/.venv` 未配置。检查脚本能返回诊断，不表示 APK 主链已验证。
这次没有重新运行历史文档声称的 macOS 完整链路。

## 4. 影响与竞品比较

### 对产品目标的影响

当前知识可帮助 Agent 决定“下一步怎么分析”，但执行、错误恢复、证据校验与
跨资产关联仍要 Agent 临场组织。缺乏共享合同和基准时，Agent 能写报告不代表
报告结论准确，也不能用候选数量证明发现了多少漏洞。

因此，建议把主价值聚焦在方法、路由、证据要求与验证策略；实际反编译、设备操作
和网络工具尽量复用成熟后端。统一工作流仍需自己实现，避免每类工具输出各不相同。

### 比较口径

以下为 2026-10-19 阅读官方仓库 README 后的功能与定位比较，未安装这些竞品做
相同样本的跑分，也没有比较漏洞命中率、模型成本或稳定性。快速变化的 `main`
能力可能与发布包不同，以具体版本为准。

| 项目 | 与 re 的重叠 | 文档呈现的优势 | 取舍与限制 | 可借鉴的部分 |
| --- | --- | --- | --- | --- |
| [REA](https://github.com/morluto/rea) | 多资产逆向、Agent 指令、工具编排 | 可运行 CLI/MCP、安装流程、广泛 artifact 适配、Evidence 合同和案例 | 仍依赖外部引擎；支持程度由 provider、主机和发布版本决定；不是“任意资产必出漏洞” | 统一入口、能力探测、证据引用、provider 层 |
| [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) | AI 辅助原生逆向 | 反编译、Xref、标注、类型、数据库和 headless 会话管理 | 需要 IDA Pro，README 明确 IDA Free 不受支持；不能替代移动/硬件全流程 | 原生 adapter、数据库生命周期、验证数据集 |
| [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | AI 连接 Ghidra | 反编译、列举方法/导入导出、重命名；当前文档给出 PyGhidra headless 用法 | Ghidra/JDK/Python 与扩展版本有要求；作用是 Ghidra 工具桥接 | 安装说明、最小工具面、无界面分析适配 |
| [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) | Agent 逆向任务和 Ghidra | 小粒度工具、关联上下文、GUI/headless 模式及专项调查技能 | 限于 Ghidra 生态；默认本机服务，公共监听要关注认证和脚本权限 | 节省上下文的结果片段、错误反馈、长会话管理 |
| [Rust RE Skill](https://github.com/jingjing2222/rust-reverse-engineering-skill) | 技能化工作流、脚本产物、Claude/Codex 接入 | Rust 指纹、符号/边界恢复、产物收集脚本、Ghidra 任务进度 | 专项范围较窄；深度分析依赖外部引擎；不负责全资产 | 精确触发条件、可运行步骤、进度文件与专项样例 |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | APK/移动安全静态与动态报告 | 可部署平台、静态/动态分析、REST API/CLI、Docker 运行入口 | 主要面向移动应用；动态覆盖依赖设备环境；更深混淆/原生研究仍需其他工具 | APK 基础分析后端、报告产品化、自动化集成与公开检查 |

| 维度 | re 的位置 | 建议 |
| --- | --- | --- |
| 多平台方法库与国内实战语境 | 本仓库的特色 | 保持场景与索引质量，保留出处 |
| 一条命令接入 Agent 和分析后端 | 缺少统一执行层 | 优先参考 REA 的边界与接口设计 |
| 原生二进制数据库和会话 | 主要是资料，没有统一 API | 复用 IDA/Ghidra 后端，避免自建反编译器 |
| 移动安全基础报告 | 有 DAG，但尚无程序化 runner | 可复用 MobSF，再补深入分析路线 |
| 证据可信度与复现 | 尚无全局合同和公开基准 | 定义证据级别、对照样例、失败输出 |
| 全平台漏洞确认 | 各项目都受到样本、权限、环境和目标逻辑制约 | 用明确的支持矩阵与验证证据表述能力 |

### 主来源

- [REA README](https://github.com/morluto/rea)：CLI/MCP、目标类型、工具前提、Evidence 与案例入口。
- [IDA Pro MCP README](https://github.com/mrexodia/ida-pro-mcp)：IDA Pro 前提、分析工具、headless 与会话模型。
- [GhidraMCP README](https://github.com/LaurieWired/GhidraMCP)：扩展安装、工具功能、PyGhidra headless。
- [ReVa README](https://github.com/cyberkaida/reverse-engineering-assistant)：小粒度工具、GUI/headless、插件技能与服务边界。
- [Rust RE Skill README](https://github.com/jingjing2222/rust-reverse-engineering-skill)：专项流程、产物脚本与进度记录。
- [MobSF README](https://github.com/MobSF/Mobile-Security-Framework-MobSF)：移动静态/动态能力、REST API/CLI、部署入口。
- [Codex Skills](https://developers.openai.com/codex/skills)、[Claude Code Skills](https://code.claude.com/docs/en/skills)：技能格式与安装位置。
- [OpenWrt 官方包索引](https://downloads.openwrt.org/releases/23.05.0/packages/x86_64/base/Packages.gz)：Filename 路径验证。

## 5. 修复与检测建议

先解决可靠性，再扩大知识范围：统一 intake、确定性调度、工具适配、状态恢复与
证据校验组成最小运行闭环。对每类资产都定义真实产物，缺工具或缺设备时明确
报告缺失能力，不把空壳适配器标成支持。

规则命中应保留为候选。确认漏洞需记录具体输入、执行条件、真实调用路径或
可观测行为、负向对照、影响与修复建议。新颖性与 CVE 申请是确认后的独立研究环节。

持续检查原始样本 hash、命令/解包预算、状态一致性、证据引用，以及完成与失败的
端到端用例。部署前再用固定样本比较重复运行结果和误报，不用台账数量验收。

下一阶段的详细任务见[全资产差距评估](asset-to-result.zh-CN.md)；
可直接交给另一个 Agent 的要求见[补全 Prompt](agent-completion-prompt.zh-CN.md)。
