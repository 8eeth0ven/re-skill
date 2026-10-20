# re — 资产分析执行器与逆向工程工作流

**面向授权安全研究，按任务组织方法、工具、证据和分析流程。**

re 帮助研究员或 AI Agent 选择分析路线、查阅相关技巧、执行工具，并整理可复核的
报告。仓库包含平台知识、实用技术、历史案例、APK 分析工作流，以及本地固件
漏洞候选脚本。

[English](README.md) · [简体中文](README.zh-CN.md) · [场景导航](usage-scenarios.md) · [项目评估与竞品对比](docs/project-review.zh-CN.md) · [全资产补全路线](docs/asset-to-result.zh-CN.md)

> **当前工作分支已新增 `re-run`：12 类资产共享输入、受限分析、证据、恢复/取消和报告。**
> 格式和分析深度不同，动态脱壳、设备插桩和更多验证器仍需补全适配与验收。
> 改动尚未提交或推送；最后修改未复验。技能安装与工具准备分别进行。

先看[执行指南与全资产矩阵](docs/runner.zh-CN.md)、
[交付状态](docs/delivery-status.zh-CN.md)。给负责执行的 Agent 直接复制
[安装、补全和验收 Prompt](docs/agent-completion-prompt.zh-CN.md)。

以下命令由负责安装和测试的 Agent 在当前工作目录执行：

```bash
uv sync --locked --all-extras --group dev
uv run --no-sync re-run inspect --asset /absolute/path/to/sample.apk
uv run --no-sync re-run analyze --asset /absolute/path/to/sample.apk --output re-runs
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
```

网络和真实设备读取需 `--scope`。每次运行生成独立目录，包含 JSON/Markdown
报告、资产/发现/证据索引、覆盖、日志与状态。`--level verify` 当前只验证
私钥可签名，附改消息负向对照；部署信任和可利用漏洞仍待验证。

## 能解决什么问题

| 任务 | 从哪里开始 | 预期产出 |
| --- | --- | --- |
| 分析 APK | [APK 工作流](pipeline/README.md) | 静态产物、可选动态观察，以及注明跳过项的报告 |
| 编写 Hook、研究混淆 | [技术索引](techniques/INDEX.md) | 对应方法、代码示例和验证思路 |
| 分析原生二进制或特定平台 | [平台索引](platforms/INDEX.md) | 平台分析路线和工具参考 |
| 排查固件已知 CVE | [cve-hunter](cve-hunter/README.md) | 版本匹配候选和可选的二进制 Banner 复核台账 |
| 用静态规则发现固件问题 | [fw-discover](fw-discover/README.md) | 供进一步验证和排序的启发式候选 |
| 查历史案例、选择工具 | [案例索引](corpus/INDEX.md)、[工具总表](techniques/05-toolbox/tool-master-table.md) | 案例摘要、来源线索和工具选项 |
| 验证设备、准备披露 | [设备测试](device-testing.md)、[漏洞披露](disclosure-cve.md) | 受控验证流程和报告准备方法 |

[使用场景](usage-scenarios.md)包含 20 种常见情况：抓不到流量、签名参数不明、
Hook 失败、脱壳、CTF、漏洞根因分析等。首次使用可以从这里选路线。

## 快速开始

### 1. 拉取与浏览

```bash
git clone https://github.com/8eeth0ven/re-skill.git re
cd re
```

阅读 [SKILL.md](SKILL.md) 了解分支路由，或打开[场景导航](usage-scenarios.md)。
只查阅文档时，不需要安装逆向工具。

### 2. 安装为 Agent Skill

把**完整仓库**放入客户端支持的技能目录，保留相对引用和辅助脚本。
选择一个客户端和安装位置。macOS / Linux 用户级安装：

```bash
# Codex
git clone https://github.com/8eeth0ven/re-skill.git "$HOME/.agents/skills/re"

# Claude Code
git clone https://github.com/8eeth0ven/re-skill.git "$HOME/.claude/skills/re"
```

Windows 使用 PowerShell：

```powershell
# Codex
$reSkillPath = Join-Path $HOME '.agents\skills\re'
git clone https://github.com/8eeth0ven/re-skill.git $reSkillPath

# Claude Code
$reSkillPath = Join-Path $HOME '.claude\skills\re'
git clone https://github.com/8eeth0ven/re-skill.git $reSkillPath
```

父目录不存在时先创建；目标已存在时更新原有 checkout。项目级安装使用 Codex 的
`.agents/skills/re`，或 Claude Code 的 `.claude/skills/re`。
发现和调用方式以实际客户端版本为准，参见
[Codex 官方文档](https://developers.openai.com/codex/skills)和
[Claude Code 官方文档](https://code.claude.com/docs/en/skills)。

Codex 可用 `$re` 调用，Claude Code 可用 `/re` 调用。
其他兼容客户端也可以直接读取 [SKILL.md](SKILL.md)。

### 3. 按任务准备环境

参考 [setup.md](setup.md) 安装所需工具，在技能仓库根目录运行检查：

```bash
# macOS / Linux
python3 pipeline/env_check.py
```

```powershell
# Windows
python pipeline/env_check.py
```

退出码 `0` 表示检查全部通过，`1` 表示可选能力缺失，`2` 表示关键工具缺失。
检查可能探测 adb 与本地 MCP 端口；具备 SDK 时会构造临时样本做工具冒烟。
Python 包与版本锁见 `pyproject.toml`、`uv.lock`；外部引擎按需另装。
[环境盘点脚本](pipeline/env_scan.py)已改为跨平台版本探测与串口描述符枚举，
不自动采集真实 Android/iOS。`doctor --profile` 按 12 类给出必需/可选能力与
missing/present/runnable 就绪度；`re-run schema` 导出输入/报告 JSON Schema。
真设备/会话级就绪仍需对应环境。

| 任务 | 所需环境 |
| --- | --- |
| 查阅知识库 | Git 或浏览器 |
| 固件 Python 辅助脚本 | 建议 Python 3.12+；Python 导入使用标准库 |
| APK 静态工作流 | Python、Java、JADX、Apktool；SDK/aapt2、APKiD/apkleaks 可增强覆盖 |
| APK 动态工作流 | adb、合适的模拟器或设备，按需使用 Frida；MCP 可选 |
| 固件提取 | 内置受限 TAR/ZIP/gzip；不透明文件系统需隔离提取器适配 |
| 原生二进制深度分析 | Ghidra、IDA 或 radare2 等外部引擎及其运行环境 |

以下命令只查看本地进度，不下载样本：

```bash
python3 cve-hunter/hunter.py --status
python3 fw-discover/fw.py --status
```

Windows 将 `python3` 换为 `python`。命令可能创建空数据目录。
`--once`、`--seed`、`--verify` 涉及网络或分析操作，执行前阅读对应模块说明。

### 4. 给 Agent 一个具体任务

```text
使用 re 技能分析 /absolute/path/to/sample.apk，范围是我授权的实验环境。
按 S0–S4 执行，保存证据，返回报告路径、分析结论，以及未完成的步骤和原因。
```

```text
使用 re 技能分析 /absolute/path/to/sample.so，定位相关函数并追踪算法。
说明每个结论由哪些静态或动态证据支持。
```

Agent 按 APK 工作流执行后，产物结构如下：

```text
输出/<package>-<date>/
├── 00-环境/       环境检查与运行日志
├── 01-静态/       解码结果、Manifest、字符串、符号
├── 02-动态/       按条件生成设备观察、截图、日志
├── 黑板.md        阶段发现与进度
└── 03-report.md   结论、证据、限制和下一步
```

完整产物约定见 [pipeline/pipeline.md](pipeline/pipeline.md)。
这是工作流的输出定义；仓库尚未附带公开的完整样例运行包。

## 目录导航

| 路径 | 用途 |
| --- | --- |
| [SKILL.md](SKILL.md) | Agent 入口与路由 |
| [src/re_runner/](src/re_runner/cli.py) | 统一 CLI、profiles、执行、证据与报告 |
| [pyproject.toml](pyproject.toml)、[uv.lock](uv.lock) | Python 包与依赖锁 |
| [examples/](examples/README.md)、[tests/](tests/test_runner_profiles.py) | 文本示例与回归 fixtures |
| [usage-scenarios.md](usage-scenarios.md) | 20 个实际使用场景 |
| [platforms/](platforms/INDEX.md) | Windows、Android、Linux、iOS、macOS、Web、二进制漏洞、IoT、业务、AI、区块链及根因 |
| [techniques/](techniques/INDEX.md) | 插桩、脱壳、对抗、算法还原、Trace、内核、框架与工具选择 |
| [corpus/](corpus/INDEX.md) | 历史案例摘要与覆盖台账 |
| [pipeline/](pipeline/README.md) | APK 工作流与环境辅助脚本 |
| [cve-hunter/](cve-hunter/README.md) | 已知 CVE 版本匹配与 Banner 复核 |
| [fw-discover/](fw-discover/README.md) | 固件提取、启发式规则与验证指南 |
| [breach-tables-cve.md](breach-tables-cve.md) | 漏洞调查打法的总路由 |
| [radar/](radar/README.md) | 工具发现流程与基线；调度由宿主负责 |
| [docs/](docs/project-review.zh-CN.md) | 项目评估、竞品比较与实现交接 |

## 能力边界

- **基础分析与深度验证分别标注。** 12 类资产已有执行分支，格式与 L0/L1/L2
  支持见矩阵。旧 APK 动态链仍由 Agent 执行。资源限制不等于恶意代码安全沙箱。
- **候选需要验证。** 版本命中可能包含回移补丁；`binary-confirmed` 仅说明 Banner
  与索引版本一致。固件启发式命中仍需数据流、可达性、配置和行为验证。
  NVD 关键词检索为零也不能证明新颖性。
- **历史记录需要重新核对。** 原机器工具版本、冒烟结果和发现数量不代表当前环境。
  已提供回归 fixtures；生产级基准、跨系统 CI、真实设备和最后修改待执行验收。
- **部分资源仅存在于原机器。** `data/`、原始 CHM、工具二进制、虚拟环境、
  环境快照、雷达运行报告由 [.gitignore](.gitignore) 排除。
  公开案例分支提供的是整理后的笔记。

具体优缺点、已确认问题和竞品来源见[项目评估](docs/project-review.zh-CN.md)。
要补全深度工具、强对抗和执行验收，参考
[差距与补全路线](docs/asset-to-result.zh-CN.md)和
[可直接交给 Agent 的补全 Prompt](docs/agent-completion-prompt.zh-CN.md)。

## 同类项目

| 项目 | 重点 | 与 re 的关系 |
| --- | --- | --- |
| [REA](https://github.com/morluto/rea) | 多类二进制和应用产物的 CLI/MCP 分析 | 可执行集成层更完整，可作为分析后端候选 |
| [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) | IDA 分析、数据库操作与无界面会话 | 已有 IDA Pro 时提供原生分析能力 |
| [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Ghidra 分析与标注工具 | 提供 Ghidra 工具连接 |
| [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) | 小粒度 Ghidra MCP 工具与调查技能 | 适合长任务与无界面调查 |
| [Rust RE Skill](https://github.com/jingjing2222/rust-reverse-engineering-skill) | Rust 专项流程与产物脚本 | Rust 二进制场景的专项补充 |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | 移动应用静态/动态评估、API 与界面 | 移动安全评估的产品化流程更完善 |

这里只比较定位与公开文档支持的能力，不代表跑分或准确率结论。
取舍与证据见[完整对比](docs/project-review.zh-CN.md)。

## 参与贡献

新增内容请说明适用任务、前提、产出证据和限制；更新相关索引，并在 `Sources`
附录或案例条目保留来源。检查相对链接，把实际验证结果与计划能力分开记录。

不要提交私人样本、凭证、机器快照或下载的工具。
研究产物遵循[探针约定](test-values.md)。修改辅助脚本时执行相关检查；
只有实际运行过的工作流才能标记为已验证。

## 许可与授权范围

[MIT](LICENSE)。请在授权研究范围内使用，参见 [DISCLAIMER.md](DISCLAIMER.md)。
单独获取的工具和原始资料仍遵循其自身许可与访问条款。
