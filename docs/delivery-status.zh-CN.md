# 交付状态与执行交接

日期：2026-10-19。目录：`<repo>`。
基线 `0059a9a`，分支 `codex/readme-review`；全部改动未提交、未推送。
用户要求当前 Agent 统筹，并将安装、测试与继续补全交给另一个 Agent。

## 已写入代码

- `pyproject.toml` / `uv.lock` / `src/re_runner/`：统一 CLI、12 类基础 profile、
  输入/scope 合同、快照、受限执行、预算 journal、文件锁、恢复/取消、证据报告。
- 保护指示与后续路线、radare2 静态 adapter、私钥正负对照验证器。
- 旧固件/CVE 脚本的原子写入、核锁、有界下载/解压、有限重试、原始样本保留、
  新颖性 unknown 语义；跨平台 inventory、有限 keepalive。
- 英中 README、Skill 路由、竞品评估、[运行指南/矩阵](runner.zh-CN.md)、示例与回归用例。

## 历史验证与最后修改

用户要求停止前，完整 unittest 运行 **74 项：73 通过、1 跳过**；跳过为 Windows
无创建 symlink 权限。包含合成资产结构、实际本机 HTTP/WebSocket/gRPC/JSON-RPC、
恶意输入、锁/取消/恢复和旧脚本回归。该记录早于后续 provider/fat Mach-O/keepalive
和文档收尾，**不能作为最终版本通过证据**。真实设备与跨系统 CI 没有完整验收。

只读取已有 PE 报告 `re-runs/20261019T081446Z-f5c255f877e5/report.json` 后发现：
radare2 6.2.4 退出 0、函数 `[]`，stderr 为缺失 x86 decoder。原 adapter 将它标成
succeeded；本轮静态修改改为空结果/缺汇编时 degraded，并保存版本 probe 产物。
尚未重跑。禁插件配置可能同时禁用必要官方 decoder，需接手 Agent 核对官方加载机制，
限定可信插件目录并完成非空函数/引用/汇编 oracle，不能直接解除所有限制。

本轮在用户停止要求后只读改文件，没有继续安装、测试、env probe 或样例分析。

## 接手 Agent 执行结果（2026-10-19，第二轮整改）

统筹验收未通过后，F1/F2/F3 三个阻塞项已修复并按审查验证门复验；G1 缺实现
（Android JADX/Apktool、固件 7z extractor、流量 scapy、源码 bandit、AI 行为
oracle、合约 solc、UPX 静态解包路线、Web/WS/gRPC/链读本机实验服务真实 run、
CI 配置）已接线并各有正负对照。测试 180 项（179 过 1 环境跳过），ruff 全绿，
原始日志与逐项证据见 [execution-acceptance.zh-CN.md](execution-acceptance.zh-CN.md)
（含已通过/未通过/缺环境/未实现四分口径与版本摘要算法）。无阻塞遗留的
未实现项（Ghidra/IDA、registry、UBI/TRX 等）与缺环境项（真机/fork/沙箱后端）
在该文档第 6 节分开登记。

## 接手 Agent 执行结果（2026-10-19）

安装（`uv sync --locked --all-extras --group dev` 一次成功）、全量回归与修复已完成，
**逐项证据见 [execution-acceptance.zh-CN.md](execution-acceptance.zh-CN.md)**。要点：

- 测试从 74 项扩到 **106 项：105 通过、1 项环境跳过**（Windows symlink）；ruff 0 告警。
- radare2 根因实锤并修复：`R2_PLUGINS_ORDER` 一经设置（任何值）即令 6.2.4-w64 插件注册
  全失败、内建 x86 decoder 消失；已移除该 env（保留 `R2_NOPLUGINS=1`/`-NN`/`-S`，实测无害），
  档位升为 `aaa` 并兼容 6.2.4 的 `addr` 字段。PE 重跑 run `20261019T095614Z-fba1a224a6bb`
  三 checks succeeded（513 函数 + 48 条反汇编），不再是空结果 succeeded。
- fat Mach-O（加密指示按切片传递、CAFEBABE 消歧、补 sha256/runtime_markers）、runner 五处
  健壮性缺陷（attempt 目录恢复、cancel/timeout 计账、wall 预算持久化、取消路径证据门、
  kill 回收）、`doctor --profile` 真实 required/optional/就绪度矩阵、`re-run schema`
  输入/报告 Schema 导出：全部实现并有对应新增测试。
- fixtures 全 12 类 21 资产 L0 链 succeeded（12 条候选）；examples 5 资产 succeeded。

上表 P0 两行与 P1 的 doctor/schema 行已完成；深度 adapters、强对抗隔离动态、真设备、
跨平台 CI 仍按原表待办（含复验方法）。

## 剩余优先级

| 优先级 | 工作 | 验收证据 |
| --- | --- | --- |
| P0 | 锁定当前含未跟踪文件的工作版本；安装并复验核心、CLI、故障恢复 | 安装锁/版本、准确测试计数、日志与 run 路径 |
| P0 | radare2 decoder/空结果、cancel/timeout journal、validator cancel、fat Mach-O | 非空函数汇编 oracle；取消即停且预算不丢；slice hash/边界 |
| P1 | `doctor --profile` 的真实 required/optional/adapter 就绪度 | 路径存在、版本、协议/环境、adapter 可用分别标注 |
| P1 | 12 类至少一条真实 L0 链与逐格式矩阵 | 预定义 oracle、产物 hash、完成检查、局限 |
| P1 | 移动/native/firmware 深度 adapters 与静态失败升级 | 工具会话、可重放证据、受限 fallback |
| P1 | 强对抗隔离后端与保护对照基准 | 基线/仪器/替代方法对照、成功或具体失败、无口头绕过 |
| P2 | 各类高价值 L1/L2、资产来源关联、schema 导出、OS CI | 验证器正负对照、输入/报告合同、Windows/Linux/macOS 实际结果 |

静态审查还应重点检查：取消分支是否在读取资源 journal 前提前退出、验证器失败/
取消是否改变 coverage、资源总额与产生文件是否累计一致、fat slices 是否传递加密
指示、报告 hash/脱敏索引是否对应正确文件。这些是复核任务，未宣称都存在漏洞。

最终“完成”由支持矩阵逐格验收决定。descriptor 不算真实设备、raw firmware scan
不算解包、版本候选不算漏洞、测试跳过不算通过。完整执行要求见
[交接 Prompt](agent-completion-prompt.zh-CN.md)。
