# 第二轮独立验收复核

复核日期：2026-10-20。结论：**部分通过，整体暂不通过**。当前证据支持已实现的静态链路和正常取消/超时路径；不能据此签收“可独立执行工作全部完成”或“全资产强对抗通过”。

本轮只读取代码、既有日志和产物，并独立重算摘要与文件哈希。没有安装依赖，没有重新运行测试、lint、doctor、分析器或样本。下述缺陷为可从控制流直接确认的静态审查结论；给出的复现步骤尚待执行 Agent 实跑。

## 1. 问题概览与已确认事实

| 项目 | 独立复核结果 |
| --- | --- |
| Git 基线 | `codex/readme-review`，HEAD `0059a9a0d0d843dc5f57b26ad8dc87631b963f5e`；实现仍未提交 |
| 版本摘要 | 使用 PowerShell/.NET 独立实现文档算法：70 文件，`f85ddf59298ce5f0101eca0144f25c7e4ec2e7dd0f9f84c43bb04efcded210cc`，与执行文档一致 |
| 摘要范围 | 仅 `src/ tests/ examples/ pyproject.toml uv.lock`；不据此断言 `tools/`、CI、文档、旧脚本等整个工作树均无漂移 |
| 原始测试日志 | `re-runs/logs/unittest-final.txt`：`Ran 180 tests in 98.419s`，`OK (skipped=1)`。日志为执行方结果，本轮未重跑 |
| 原始 lint 日志 | `re-runs/logs/ruff-final.txt`：`All checks passed!`，本轮未重跑 |
| F1 主路径 | `Budget.settling`、Runner 收尾上下文、journal 先校验后应用在位；测试含 4 个真实 Runner 场景及 3 个 Budget 场景。产物枚举失败分支仍未闭环，见 R1 |
| F2 | `{code,message[,asset_id]}` 错误模型、执行状态枚举、生成端 REPORT_SCHEMA 校验在位；现有失败/取消/超时等测试与模型一致 |
| F3 性能 | email 的 `@` 扫描、assignment 原子组、PEM 字面量扫描及 translate 在位。最终原始日志是无 `@` 1,000,000 字符 78ms、4MiB 422ms、密集邮箱 266ms；不是本轮独立实测。截断脱敏仍有 R3 |
| 留盘完整性 | 9 条终态 run，270 条产物哈希、75 条证据引用一致；request 哈希、路径包含关系、reparse 检查、ToolRun/asset 引用、finding 引用及 state/report 用量一致 |

| run ID（`re-runs/results/`） | 资产 | ToolRun | 产物 | 证据 | findings | 状态 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `20261019T125138Z-4eaa1d38edf4` | 22 | 44 | 190 | 55 | 14 | succeeded |
| `20261019T124756Z-2f9ed1996ce0` | 5 | 10 | 35 | 10 | 0 | succeeded |
| `20261019T124759Z-b8edfb788c26` | 1 | 2 | 10 | 2 | 0 | succeeded |
| `20261019T125220Z-b61faa6e3b1b` | 1 | 2 | 6 | 2 | 1 | succeeded |
| `20261019T125221Z-c221c0de6e7d` | 1 | 2 | 6 | 1 | 0 | succeeded |
| `20261019T125222Z-c2411613cae5` | 1 | 2 | 6 | 1 | 0 | succeeded |
| `20261019T125223Z-b6899c3ffa92` | 1 | 2 | 5 | 1 | 0 | succeeded |
| `20261019T125224Z-8c9e80c5d945` | 1 | 2 | 5 | 1 | 0 | succeeded |
| `20261019T125225Z-b6b37d14a796` | 1 | 2 | 7 | 2 | 0 | succeeded |

全部 run 的 verified 均为 0；这与候选和验证断言的区分一致，不作为失败理由。fixtures 实际是 11 类本地资产；第 12 类 Web 由独立本机服务 run 覆盖基础路径。

新增能力有真实内容，不能笼统认定为空壳：JADX 留有 `org/example/fixture/Fixture.java` 的 `hello()`、`imei()` 方法；Apktool 留有 manifest/smali；Bandit 留有 B605 命中；Solc 留有 `Fixture` 合约、237 字节 bytecode 和 ABI；Scapy 留有 7 包组成的 HTTP 请求/响应及脱敏 URL；gRPC 留有 `demo.Echo`，链读留有 chainId 31337。

## 2. 技术分析：三个阻塞点

### R1 [P1] 产物枚举异常仍能跳过执行记录和用量结算

位置：`src/re_runner/runner.py:24–32,237–263,369–372`，`src/re_runner/intake.py:149–178`。

`_settlement()` 只使 `Budget.check/consume` 不抛停止条件；`_artifacts()` 自身仍在超过文件/字节上限时抛 `BudgetExceeded`，其调用的 `iter_tree()` 仍会因条目数、深度、链接或不安全路径抛异常。这些检查仍发生在构造/记录 ToolRun 和 `_consume_attempt_usage()` **之前**。

因此，worker 已经真实运行并写出非零 usage 后，只要输出目录不能完整枚举，当前终态报告就缺该次 profile ToolRun，state.used 未加本次 journal，accounted 保持 false。正常停止路径的测试不能覆盖这个组合。验证器产物也有同样先枚举再记录的顺序。

另一个已登记但仍未闭环的入口是 intake：`snapshot()` 或随后的产物枚举途中停止，ToolRun 尚未建立；留下的 `inputs/<asset-id>/` 又会使下次 snapshot 因“不完整 intake 目录”失败。

应保留枚举上限。修复应把执行事实/异常、固定 journal 结算与受限产物清单分开：枚举失败也必须保存执行状态、错误、完整已校验用量和不完整清单标记；不允许用无限枚举换取收尾成功。

### R2 [P1] 7z 列表不完整仍解包，总磁盘/条目限制在解包后才检查

位置：`src/re_runner/extractors.py:96–109,173–194`；`src/re_runner/execution.py:129–142,182–192`。

`_parse_listing()` 到 5000 条就停止且不标记不完整。更直接的是，`listing.status != succeeded` 时 `members=[]`，代码仍执行 `7z x`：输出洪泛/超时导致拿不到完整成员表时，预检等价于零文件、零字节。

之后 `_inventory()` 才统计实际解包用量。Windows Job 限制进程、内存和生命周期，没有目录总磁盘配额；POSIX `RLIMIT_FSIZE` 只限制单个文件。因此完整解包可能先超过总字节数/文件数，再被事后拒绝。新增 JADX/Apktool 输出同样需要纳入派生文件用量，不能只在最后枚举清单时拒绝。

该 adapter 也没有在解包前用 `safe_relative` 校验全部成员和链接类型。后验清单检查不是写入时的路径边界。这里**没有声称已实测 7z 路径逃逸或主机任意写入**；已确认的是预检不完整却继续写入、总资源限制生效过晚。

还有一处文档与路径不一致：`_inventory()` 跳过 symlink，而后续 `scan_tree()` 使用拒绝 symlink 的 `iter_tree()`。若特权主机成功创建了 squashfs 样例链接，整个 profile 可能随后失败；不能凭解包工具 exit0 宣称全链路“自动 succeeded”。

修复需对失败/截断/不完整列表拒绝解包，完整检查成员、目录、链接、深度和数量；实际写入使用可强制的目录配额/隔离后端，或逐成员受控流式输出到安全写入器。资源限制与安全沙箱的能力应分别声明。

### R3 [P1] 截断发生在脱敏之前，跨边界 PEM 会保留私钥正文

位置：`src/re_runner/execution.py:156–168,199–205`；`src/re_runner/safety.py:152–162`。

`_settle_output()` 先截到 4MiB 再 `redact_text()`；reader 的默认 1MiB 保留上限也会先截断原始输出。`_redact_private_keys()` 找不到 END 就直接保留原文。

只需把一个完整 PEM 的 BEGIN 与正文放在保留区内、END 放在边界外，原本可脱敏的私钥就变成“未闭合 PEM”，正文被写入 stdout/stderr 日志及 adapter JSON。丢弃尾部并不能证明保留部分安全。现有 `never_leaks` 测试只把秘密放在被丢弃尾部，没有覆盖跨边界秘密；语义对照还沿用了“不闭合 PEM 原样输出”的旧行为。

修复应采用知道截断状态的脱敏策略，或对未闭合 private-key BEGIN 从 header 到缓冲区末尾做保守脱敏；同时验证日志和 JSON 二次输出的边界。继续保持有界复杂度和原有默认输出上限。

## 3. 验证步骤

本轮已执行的仅为只读复核：独立重算工作树摘要；读取原始日志；对上述 9 条 run 的 request、artifact、Evidence、finding 和用量逐项校验；抽查反编译、编译、HTTP 重组与本机协议结果的实际内容。

执行 Agent 下一轮必须保存以下真实验证，当前尚未运行：

1. **R1**：通过真实 Runner 启动受控 worker，先写非零 usage，再产生超过 `max_files/max_unpack_bytes` 的输出；组合 cancel/deadline。验证当前终态就保留该 ToolRun 和精确用量，resume 不复计。补验证器及 intake 中断的对应场景；链接/损坏产物拒绝时也保留执行事实。
2. **R2**：用受控生成的容器覆盖列表输出超限、超过 5000 条、深目录/大量空目录、链接和无效成员，以及每个文件低于单文件上限但总量超限的情况。验证不完整预检不启动 `x`，总量在实际写入时被阻止，root 外哨兵不变。补 squashfs 有/无 symlink 权限的真实 Runner run。
3. **R3**：构造合成 PEM，BEGIN 和可辨识的测试正文刚好在保留边界内，END 在边界外；分别覆盖默认 1MiB reader 截断和 4MiB 收尾截断。验证返回文本、stdout.log、stderr.log、adapter JSON 都不含测试正文；验证未闭合 PEM、quoted assignment、token 等边界；继续运行规模阶梯和 watchdog。

已有 UPX/squashfs 正负对照测试使用 TemporaryDirectory；当前只留有汇总 unittest 日志，不能像上述 9 条 run 一样独立重验其产物哈希。下一轮应留下这两条能力的专门 Runner run、oracle 结果和日志。测试通过证据与可留盘复核证据分别列明。

## 4. 影响与验收范围

| 项目 | 当前影响 / 签收口径 |
| --- | --- |
| R1 | 恶意或过大的派生产物能使当前执行账本和报告不完整；取消、预算与恢复的承诺未覆盖全部失败分支 |
| R2 | 预检失败或截断可绕过声明用量检查，造成目录总资源超限；“固件隔离 extractor/强对抗通过”暂不签收 |
| R3 | 工具输出里的私钥材料可能出现在声称已脱敏的日志中；脱敏性能改善可以确认，保密边界仍不通过 |
| 基础静态链路 | 本轮 9 条留盘 run 的完整性通过；不扩大为动态、深度或所有格式验收 |

原交接仍有实现缺口：AAB/JVM 深度、至少一条深度反编译 adapter、跨语言规则、OCI merged/registry、UBI/TRX、AI 多轮/流式、Vyper/import 布局。Frida/S3、合约 fork 与动态沙箱后端也缺实际接线，不能全部放入“只是缺环境”。真机/许可/TLS 密钥等才是独立外部条件。

CI 三平台 workflow 在位，但没有 Linux/macOS 运行 URL 或日志；配置存在只证明配置交付。不同 OS 的外部工具测试还需区分真正运行与因硬编码本机路径而跳过。

执行文档的四分状态框架可以保留，但需改正“7 个全部真实 Runner 测试”“特权 squashfs 自动全链路成功”和“可独立执行的工作全部完成”等表述。第 6d 节明确列了本机可做而未做的项目，本身就不支持全部完成结论。

## 5. 修复与后续交接

先修 R1/R2/R3，并保存真实终态和边界对照；随后按照原 12 类矩阵补齐实现，将缺代码与缺环境拆开验收。具体可复制执行 Prompt 见 [acceptance-rereview-prompt.zh-CN.md](acceptance-rereview-prompt.zh-CN.md)。

本次只新增复核及交接文档，未修改已验收代码或已有日志/产物；历史执行记录保留。
