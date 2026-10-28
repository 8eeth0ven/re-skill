# 统筹验收：未通过最终验收

日期：2026-10-19。审查目录：`<repo>`。
基线 HEAD：`0059a9a`；工作分支 `codex/readme-review`；实现仍为未提交工作树。

结论：本地静态分析与报告链有真实产物，PE/radare2 的空结果问题已有有效修复。
**全资产深度分析、强对抗闭环与执行可靠性尚未达到最终交接标准。**
本次遵循用户之前的分工，只读取代码、文档、既有报告并核对 hash/引用；没有安装、
执行分析器、运行 unittest/ruff 或新增动态测试。高置信代码问题由执行 Agent 修复和复验。

## 1. 问题与威胁概览

| 编号 | 级别 | 验收阻塞项 | 影响 |
| --- | --- | --- | --- |
| F1 | P1 | 真实取消/总时限耗尽时，产物枚举和计账仍检查已触发的取消/超时 | 本次 ToolRun 和资源使用未完整写入取消/失败报告，恢复账目门未验收 |
| F2 | P1 | 导出的报告 Schema 不接受程序实际生成的错误及工具执行状态 | 受阻/失败/超时报告无法被下游按合同消费，成功空报告测试漏检 |
| F3 | P1 | 无分隔符长字符串使 email 脱敏正则出现平方级扫描，发生在工具时限之外 | 敌对输入/工具输出可拖住主执行器，现有输出洪泛测试仅覆盖 4 KiB 缓冲 |
| G1 | 未完成 | 动态脱壳、移动插桩、AI 行为对抗、多个深度 adapters 和 OS CI 尚未实现/验收 | 不能按用户“全链路、强对抗”的目标签收 |

这些等级针对本工具的可用性、可靠性和交付，不表示已验证第三方目标可被远程利用。

## 2. 技术分析：根因、触发与攻击面

### F1：取消与超时计账的实际路径仍被中断

[runner.py](../src/re_runner/runner.py) 第 219–239 行在 `run_command` 返回后，先用
`_artifacts(..., self.budget)` 枚举产物（第 226 行），之后才进入取消/超时计账分支。
[intake.py](../src/re_runner/intake.py) 的 `iter_tree` 会调用 `budget.check()`；
[safety.py](../src/re_runner/safety.py) 第 234–246 行的 `check/consume` 在取消文件
存在或 deadline 耗尽时抛异常。于是正常的真实取消先在产物枚举处退出；即使跳过
枚举，`_consume_attempt_usage` 第 275 行的 `consume` 也会再次中断。

落盘 usage journal 尚可在符合条件的后续恢复中重读，但**本次取消报告的用量、
ToolRun 和 accounted 标志未完成**，不能声称此修复已通过。
`tests/test_runner_robustness.py:53` 只直接调用 consumer，未创建取消文件或过期
deadline，未走完整执行器路径，因此通过该测试不能证明真实取消计账正确。

### F2：报告生成和导出合同不一致

[contracts.py](../src/re_runner/contracts.py) 第 128 行将 coverage.error 限为
string/null，第 164 行将 errors 的元素限为 string。实际
[runner.py](../src/re_runner/runner.py) 第 419–423 行保存 `{code, message}` 对象，
[reporting.py](../src/re_runner/reporting.py) 第 48–64 行将这些对象直接写入报告。

另外，contracts.py 第 150 行把 ToolRun.status 限为 RunState 的 STATES，
而 [execution.py](../src/re_runner/execution.py) 第 209–226 行实际返回
`timed-out`、`output-exceeded`、`budget-exceeded` 等执行状态；runner 将其直接记入
ToolRun。这些状态不在该 enum 内。

`tests/test_schema_export.py:35` 只验证手写的 succeeded 空报告；没有验证真实
blocked/failed/cancelled/工具超时产物。报告生成处也未调用 REPORT_SCHEMA 校验。
因此“导出 schema 与真实报告双向一致”的签收描述超出了已有证据。

### F3：脱敏发生在资源监控外，复杂度无上限

[safety.py](../src/re_runner/safety.py) 第 35 行的
`[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}` 为未锚定模式：一长段 word 字符后没有 @ 时，
搜索会从不同起点反复扫描剩余后缀。
[execution.py](../src/re_runner/execution.py) 第 236 行在 kill/reap 完成后同步
执行 `redact_text`；这里没有剩余时限或取消检查，也没有隔离 worker。

默认工具输出上限是 1 MiB，不能以“有限字节数”替代复杂度控制。
现有 `test_output_flood_is_bounded` 将保留缓冲设为 4096 字节；新 FakePipe 用例
也刻意缩小输入。验收记录将该问题列为“不阻塞”，与强对抗可用性要求不符。
本次未执行耗时复现，结论依据代码路径和正则复杂度；具体耗时由执行 Agent 测量。

### G1：缺实现与缺环境必须分开

`planning.py` 仍只注册 `private-key-possession`，`protections.py` 返回
`bypass_executed: false` 与 next_routes。这能提供可信提示，但没有隔离动态、
失败签名/假设调度、替代观测、dump 重建及行为对照的执行闭环。

Android 的 JADX/Apktool/S0–S4、固件隔离 extractor、tshark、跨过程源码工具、
AI 行为 oracle、合约 fork/编译等不是单纯“装好工具即可”；当前代码没有相应接线。
验收记录第 8 节中的若干复验命令只安装/doctor/chain-read，不会自动生成缺失阶段。
真机/许可是外部条件，可以据实挂起；本机可实现的适配与 CI 配置不能一并归为
环境缺失。

## 3. 证据审查与待执行验证

### 已独立核对的落盘证据

| Run | 内容 | 产物 hash 核对 | 证据引用 | 发现 |
| --- | --- | --- | --- | --- |
| `20261019T095434Z-bb21e2aadd4d` | 21 个本地 fixture，实际 11 类 | 164 个文件一致 | 52 条有效 | 12 candidates，0 verified |
| `20261019T095449Z-59fdc1f6c5b3` | 5 个文本示例 | 35 个文件一致 | 10 条有效 | 0 |
| `20261019T095614Z-fba1a224a6bb` | PE/radare2 | 10 个文件一致 | 2 条有效 | 513 函数、48 条汇编；0 verified |

三份报告/状态一致，请求 hash、ToolRun 产物、finding→evidence 引用均通过本次
只读核对。该核对证明现有文件内部一致，不能替代独立重跑或证明通用准确率。

Web 不在上述 fixtures/examples 中；代码有独立本机 Web 测试，WebSocket/gRPC/
链读也有测试，但相关测试产物位于临时目录。未在此次交接文件中找到完整原始
unittest/ruff 日志来复核执行情况。可核对源码确有 **106 个 test 方法**；
**105 通过/1 跳过仍是执行 Agent 的记录，本次未重跑确认。**

审查版本摘要：`src/ tests/ examples/ pyproject.toml uv.lock` 排除缓存后共 55 文件；
按相对路径 ordinal 排序，将每条 `UTF-8路径 + NUL + 内容SHA256小写 + LF` 连结后
计算 SHA256：`a46da90bd8efafaa7e8908cd5010167d2affddd8e20838bab4ccd383ccf4920f`。
执行记录的 96 文件摘要未说明排除规则/算法，不能直接对比两者作版本结论。

### 交给执行 Agent 的验证门

1. 已有非零 usage 的真实运行中创建 cancel.request；取消后核对状态、ToolRun、
   journal、计数，恢复不得重复累计。相同路径覆盖已耗尽 deadline 与验证器取消。
2. 让真实 Runner 生成 succeeded/degraded/blocked/failed/cancelled、工具 timeout/
   输出上限报告；全部按导出 schema 验证，检查稳定字段类型与执行状态。
3. 以默认上限无 @ 的长字符串验证脱敏，包含主执行器全过程 watchdog/取消和
   成长规模；不能只用 4 KiB 检查。记录实际耗时，不靠缩小样例绕过复杂度问题。
4. 分别补全缺实现、登记缺环境；每条 adapter 产生实际 ToolRun/Evidence。
   强对抗样例要有未插桩基线、正负对照、触发/失败签名及有限替代路线。
5. 保留最终 unittest/ruff/集成原始日志、版本摘要、每类真实 oracle/run；
   CI 配置与实际 Windows/Linux/macOS 结果分别记录。

## 4. 影响与验收范围

可认可的阶段成果：统一入口、已记录本地结构分析、受限证据报告、radare2 实际
函数/汇编产出。不能将该阶段成果称为所有格式/设备 L0、通用 L2 或强对抗通过。

F1/F2 影响失败路径报告和后续自动消费；F3 影响面对恶意输入时的终止能力。
上述问题修复并获得真实边界测试证据前，执行底座也暂不做最终签收。

## 5. 修复与复验交接

F1 将收尾取证、journal 完整校验和原子计账与停止新增执行分开；取消/过期后仍
安全结算既有用量，不能清空取消标志来继续工作。避免部分累计后抛异常造成复计。
F2 明确共享错误模型和 Execution 状态合同，生成端校验实际报告；覆盖非成功路径。
F3 改为有明确复杂度边界的脱敏流程，必要时隔离执行，确保主进程受时限/取消控制。

整改任务见[可复制 Prompt](acceptance-remediation-prompt.zh-CN.md)。
原执行记录保留，下一轮必须按新证据改签收状态，不能沿用“105 通过”结案。
