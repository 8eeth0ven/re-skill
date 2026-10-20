# 执行与验收记录（execution-acceptance）

> 第三轮整改（响应 [acceptance-rereview.zh-CN.md](acceptance-rereview.zh-CN.md) R1/R2/R3 阻塞点）。
> 日期 2026-10-17（macOS arm64 本机）。第 2 轮内容见文末历史节；**本轮交付以本节为准**。
> **已通过 / 未通过 / 缺环境 / 未实现 见 6' 节严格分开**；所有"已通过"绑定可复跑命令与留盘产物。

## 0'. 第三轮（R1/R2/R3）修复与验证

### 版本标识（第三轮）
- 基线 `0059a9a0d0d843dc5f57b26ad8dc87631b963f5e`（本机快照以 `git reset --mixed` 锚定，未动工作树）。
- **本轮摘要（范围 src/ tests/ examples/ pyproject.toml uv.lock，71 文件）**：`e682f933caa02b7c56724d53ae14743b720a2a29e4180354ce476fd6bfceb99b`（复验命令 `python tools/worktree_digest.py`；相对第 2 轮 70 文件新增 `tests/test_r1_r2_remediation.py`）。
- squashfs oracle 样例改为**本机自造**（mksquashfs，112 常规文件+3 个 symlink 成员+8MiB sparse 文件，sha256 `d1ad72791a2ade6d552ec0496e31db9b807f22725cc2be3d958133d2036c6c4d`，来源与许可见 `tools-env/samples/SQUASHFS-SAMPLE-PROVENANCE.txt`；原 fox-it 样例下载为 404 页面，未使用）。

### R1 产物枚举异常不再丢执行记录/用量（修复+真实验证通过）
- 修复位置：`src/re_runner/runner.py`（`_artifacts` 改为有界不抛出，返回 `(records, incomplete_reason)`；`_invoke`/`_validate` 在 `_artifacts` 之前不再可能抛出——ToolRun 先构造先落盘再 usage 结算，任何枚举异常降级为显式 incomplete 清单+错误说明；`_intake`/`_record_interrupted_intake` 对中断 intake 记录 ToolRun 并落 `.incomplete` 标记）；`src/re_runner/intake.py`（snapshot 起始写 `.incomplete`、成功移除）。
- 恢复策略：marker 存在 = 未被任何证据引用的部分拷贝，resume 安全重建（`interrupted-intake-recovered` 事件）；无 marker 的历史目录仍按原样拒绝。
- 验证门（tests/test_r1_r2_remediation.py 15 项 + 留盘 run）：
  1. 真实 Runner：worker 正常完成但输出树含 symlink → profile ToolRun 保留、error 标注 incomplete、journal 计入 `state.used`、accounted=true。
  2. 真实取消 + 输出树含 symlink → cancelled ToolRun + error + accounted=true；resume 后 succeeded，`used.files == intake + Σ(全部 attempt usage.json)` 逐项相等（**无复计**）。
  3. 中断 intake（目录资产拷贝中途取消）→ cancelled intake ToolRun 留盘、`.incomplete` 标记在位；resume 重建成功且带恢复事件。
  4. 单元门：限额/链接条目/越界条目下 `_artifacts` 不抛出、清单受限且标注原因、root 外条目永不入列。
- 专门留盘：`re-runs/r1r2r3-verification/r1-cancel/`（cancelled-state.json / resumed-state.json / usage-identity.json，usage=43=1+Σjournals 实测相等）+ 原始日志 `re-runs/logs/round3-verification.txt`。

### R2 7z 预检与写入期配额（修复+真实验证通过，7-Zip 实测）
- 修复位置：`src/re_runner/extractors.py`（重写：listing 非 succeeded / 输出洪泛 / 超 5000 条截断 → **拒绝解包**，`extraction_started=false`、`listing_complete=false`；`_vet_members` 对全部成员先做 `safe_relative`+深度+单成员+总量预检，任一非法拒绝整个容器；**逐成员受控流式写入** `7z x -so -spd`，每个数据块写入前过总配额，超限块永不落盘并在错误里写明强制时点；用量按完成成员实时 consume；`_sweep_irregular` 兜底 unlink 杂散链接并计数 `links_omitted`）；`src/re_runner/decompile.py`（`_consume_derived` 把 jadx/apktool 派生树在工具退出后立即按限额折算 files/unpack_bytes，超限降级 degraded 并标注不完整）。
- 链接策略（明确）：永不创建 symlink；链接成员物化为含存储内容的普通文件，提取树保证无链接——解除"特权主机 7z 跳过链接、scan_tree 拒绝链接"的全链路失败。
- 验证门（同文件 ExtractorRefusalTests/PreflightVetTests 7 项 + 留盘 run，全部真实 7z）：
  1. listing 洪泛（max_tool_output_bytes=512）→ refused，未启动解包；2. 5100 成员截断 → refused；3. `../evil` 成员 → preflight 拒绝、root 外哨兵文件原封不动；4. 20 级深路径 → 拒绝；5. **listing 谎报半价**（declared 过预检、实际翻倍）→ 写入路径在 48KB 总配额处停止，files<16、错误含预算签名；6. 声明总量超预算 → preflight 拒绝；7. 健康 cpio 流式解包 2 文件 8 字节 succeeded。
- 真实 squashfs（mksquashfs 制作、含 symlink 成员 + 内嵌 PEM）→ succeeded、树内 0 symlink、链接成员成普通文件。
- 专门留盘：`re-runs/r2-extractor/`（round3.sqfs、round3.cpio、各 run result JSON、squashfs-tree.json）。
- 未声称：未做 7z 路径逃逸实测（无此断言）；"资源限制生效"与"恶意样本沙箱"仍分别声明，见 6c。

### R3 截断感知脱敏（修复+真实验证通过）
- 修复位置：`src/re_runner/safety.py`（`_redact_private_keys`：未闭合 private-key BEGIN → 从 header 保守脱敏到缓冲区末尾（旧 oracle 语义仅对完整对保留，未闭合场景明确更新为安全语义）；新增 `redact_text_truncated` 对流截断尾部的不完整 AKIA/gh_/sk- token 头做 O(1) 锚定擦除）；`src/re_runner/execution.py`（`_settle_output` 改为**先全量脱敏再截断**，reader 级截断状态 `sizes[i]>len(buffer)` 传入并启用尾部擦除；顺带修复 `kill_tree` 对已回收 pgid 的 PermissionError）。
- 验证门：tests/test_redaction_bounds.py 21 项（oracle 更新为「完整对 = 旧正则；未闭合 BEGIN = 保守脱敏」并保留 3×2000 条 fuzz 等价；新增跨界 PEM/未闭合 PEM/部分 token 三门）；规模阶梯与 watchdog 原样保留全绿（1MiB 无@ 26ms、4MiB 117ms、1MiB 密集邮箱 127ms，[timing] 行见日志）。
- 真实链路：子进程 stdout=header+BEGIN+canary 正文（END 永不发送，reader 8KB 截断）→ `Execution.stdout`、`stdout.log`、`stderr.log`、adapter JSON 四个表面 canary 与 BEGIN header 全部缺席、保守 marker 在位。
- 专门留盘：`re-runs/r3-redactor/`→`r3-redaction/`（r3-oracle.json、r3-adapter-json.json、stdout/stderr.log）。

### 测试与回归（第三轮）
- 跨平台测试门（响应复核"硬编码本机路径导致跳过"）：`tests/test_android_decompile.py` 与 `tests/test_firmware_extract.py` 的 7z/jadx/apktool 解析改为 RE_RUN_* → 仓库目录 → PATH；macOS 上 **android 8/8 实跑**（真实 jadx 1.5.6 反编译 + apktool 2.11.1 解码，日志 `re-runs/logs/android-round3.txt`）、**firmware 9/9 实跑**（真实 squashfs 全 profile，symlink 省略 degraded，日志见全量）。`tests/test_upx_route.py` 仍硬编码（见上）。
- 原始日志：`re-runs/logs/unittest-round3-final.txt`（**最终全量 discover：`Ran 198 tests in 226.151s` → `OK (skipped=20)`，0 failed**；相对第 2 轮 180/1skip[Windows] 的差异 = +18 新测试、-14 skip[跨平台门解锁真实 7z/jadx/apktool 实跑]、macOS 上 20 项 skip 均为 UPX 硬编码/真机/CI 类环境项，skip 理由逐条在日志）、`re-runs/logs/ruff-round3.txt`、`re-runs/logs/round3-verification.txt`（tools/run_round3_verification.py 24 项 ALL PASS）。
- 新增测试文件：`tests/test_r1_r2_remediation.py`（15 项）；修改：`tests/test_redaction_bounds.py`（oracle 语义更新 + 3 门）。
- 新增工具：`tools/run_round3_verification.py`（可复跑的专门证据 run 生成器）；本机依赖：7z 25.02(homebrew)、upx 5.2.1、mksquashfs、jadx、radare2（`RE_RUN_*` 显式配置）。

## 6'. 第三轮验收状态总表
### 已通过
R1（含 intake 中断恢复/validator 同序/真实 cancel+不可枚举输出+resume 无复计）、R2（拒绝解包六连+写入期配额强制点实测+链接策略+squashfs/cpio 真实正例+decompile 派生用量）、R3（四个输出表面跨界/未闭合/部分 token 全覆盖+复杂度有界+规模阶梯）、Ruff 全绿、全量 unittest（见第 5 节命令与上方日志）、专门 24 项 oracle（re-runs/r1r2r3-verification/ 持久目录，非 TemporaryDirectory）。
### 未通过 / 有条件
- **UPX 模块在 macOS 仍全部 skip**：`tests/test_upx_route.py` 硬编码 Windows 路径（`tools-env/upx-5.0.2/.../upx.exe` 与 `.venv/Scripts/python.exe` PE 样例），本轮未改为跨平台（upx 5.2.1 已装但未接入）——记入 6d 未实现。
- squashfs（自造样例含 3 symlink）：extract 状态 degraded、`links_omitted=3`，链接成员按省略策略不落地；"保留链接语义的扫描"另立方案（未实现）。
### 缺环境（外部条件，与第 2 轮 6c 相同）
真机/模拟器动态插桩、合约 fork/testnet、TLS 密钥日志、Apple 授权设备、Linux/macOS CI 实跑 URL（workflow 配置在位，本轮未获得 CI 运行链接）。
### 未实现（本机可做而未做，继承第 2 轮 6d 并按本轮口径复核）
AAB/JVM 深度、Ghidra/IDA 深度 adapter、tshark、semgrep 跨语言、OCI merged/registry、UBI/TRX 真解包、AI 多轮/流式扩展、Vyper 编译、Frida/S3 实接线、合约 fork——同 6d 清单，本轮 50 分钟预算优先 R1/R2/R3 完整交付，未动这些面。

---

# 以下为第二轮历史记录（保留，部分口径已被第 0'/6' 节取代）

> 第二轮整改（响应 [acceptance-review.zh-CN.md](acceptance-review.zh-CN.md) F1/F2/F3 阻塞项与 G1 缺实现）。
> 日期 2026-10-19。所有"已通过"均对应可复跑命令、留盘 run 产物与原始日志；
> **已通过 / 未通过 / 缺环境 / 未实现 在第 6 节分开列，不互相冒充**。

## 1. 版本标识

- 分支 `codex/readme-review`，基线 HEAD `0059a9a0d0d843dc5f57b26ad8dc87631b963f5e`；实现仍为未提交工作树。
- **版本摘要算法（与审查者一致）**：范围 `src/ tests/ examples/ pyproject.toml uv.lock`，排除 `__pycache__`/`*.pyc`/`.venv`；相对路径按 UTF-8 ordinal 排序；对每条 `UTF-8路径 + NUL + 内容SHA256小写hex + LF` 连结后取 SHA256。实现于 [tools/worktree_digest.py](../tools/worktree_digest.py)（`python tools/worktree_digest.py` 可复现）。
- 本文档定稿时摘要：**70 个文件，`f85ddf59298ce5f0101eca0144f25c7e4ec2e7dd0f9f84c43bb04efcded210cc`**（工作树随后任何改动都会使其失效，复验时须重算）。

## 2. 环境与依赖

| 项 | 值 |
| --- | --- |
| OS / Python / uv | Windows 10.0.22631 x64（Git Bash）/ 3.12.10 / 0.11.29 |
| 安装 | `uv sync --locked --all-extras --group dev`（本轮新增 extras：`traffic-deep`[scapy]、`source-deep`[bandit]、dev 组 `grpcio-tools`；`uv.lock` 已同步更新） |
| 本轮接线的外部工具（官方来源，sha256 见 [tools-env/SHA256SUMS.tools.txt](../tools-env/SHA256SUMS.tools.txt)） | radare2 6.2.4-w64（既有）；jadx 1.5.1（github skylot/jadx）；apktool 2.11.1（github iBotPeaches）；UPX 5.0.2（github upx）；solc 0.8.37（github argotorg/solidity，仓库已迁移）；7-Zip 25.01（7-zip.org，**已核实含 SquashFS handler**） |
| squashfs oracle 样例 | [tools-env/samples/gzip.sqfs](../tools-env/samples/) sha256 `7f0238…8e6e1`，来源 fox-it/dissect.squashfs 测试数据（AGPL-3.0，许可与来源见同目录 SQUASHFS-SAMPLE-PROVENANCE.txt） |
| 工具配置方式 | 全部经 `RE_RUN_R2 / RE_RUN_JADX / RE_RUN_APKTOOL / RE_RUN_UPX / RE_RUN_7Z / RE_RUN_SOLC` 环境变量显式配置（runner 白名单透传给 worker；doctor 能识别并实测版本） |

## 3. 三个阻塞项的修复与验证门（F1/F2/F3）

### F1 取消/超时收尾计账（修复+真实验证通过）

- 修复：`Budget.settling` 结算模式（settling 下 check 不抛、consume 超限不抛、真实用量如实入账）；`Runner._settlement()` 仅包住 run_command 返回后的产物枚举与 usage 应用，新执行停止判定（循环顶 `budget.check()`）不变；`_consume_attempt_usage` 与 `_reconcile_interrupted_usage` 改为**先整本校验后应用**，任何抛出点不留部分累计（resume 不复计）。
- 验证门（tests/test_cancel_settlement.py，7 项，全部真实 `Runner.execute()` 路径）：
  1. 真实取消：worker 消费非零资源后写 cancel.request → run=cancelled，**cancelled 报告含该次 ToolRun**，`state.used == intake + usage.json` 逐键相等，`active_attempt_accounted=True`，无 `interrupted-attempt-recovered` 事件；resume 后 succeeded，`used == intake + Σ(两个 attempt usage)`（**无复计**）。
  2. 过期 deadline：持久化 `wall_budget.deadline_epoch` 置过去 → resume 得 failed(budget-exceeded)，已完成 ToolRun 与 budget_used 完整保留；运行中到期路径同样验证（ToolRun=budget-exceeded 已入报告）。
  3. **validator 取消**：verify 级私钥用例中 validator 子进程存活期写 cancel.request → `validator:private-key-possession` ToolRun（cancelled）进报告，finding 保持 candidate，report 过 REPORT_SCHEMA。
- 结论：**已通过**（本项验证门全部满足）。

### F2 报告模型与导出 schema 一致（修复+真实验证通过）

- 修复：共享错误模型 `_error_schema`（`{code,message[,asset_id]}`，coverage.error/errors 均收对象）；`ToolRun.status` 枚举扩为 STATES+`timed-out`/`output-exceeded`/`budget-exceeded`；`reporting.write_reports` 在落盘前按 `REPORT_SCHEMA` 生成端校验（违约抛 IntegrityError）。
- 验证门（tests/test_report_contracts.py 3 项 + test_schema_export.py 7 项）：真实 Runner 生成 **succeeded（含真实 PE run 产物复验）/ degraded / blocked / failed** 报告逐个过导出 schema；真实 `run_command` 产生 **timed-out**（`python -c sleep 3`、timeout=1）与 **output-exceeded**（100KB 洪泛 vs 2048 上限）ToolRun 注入真实 `write_reports` 后过 schema；cancelled 报告由 F1 第 3 门覆盖。
- 结论：**已通过**。

### F3 脱敏复杂度有界（修复+实测通过）

- 根因实测：email 正则 64KB 无@词串 26.5 秒（每倍增 ×4，平方级）；审查指出的之外还发现 `_assign` 与 `_pem` 两处同类模式，一并修复。
- 修复：email 改 `find("@")` 驱动线性扫描；`_assign` 原子组；`_pem` 改字面量 find 驱动；控制符过滤改 `str.translate`；`execution` 收尾脱敏复杂度线性 + 4MiB 硬上限截断（显式标记），**不引入 budget.check**（结算不可被取消打断，与 F1 语义一致，注释写明）。
- 验证门（tests/test_redaction_bounds.py 18 项）：默认 1MiB 上限无@词串 31–78ms（4MiB 235–484ms，限值 <1s）；含@ 1MiB（17,772 邮箱）~150ms；76 个手写样例 + 3×2000 条 fuzz 与旧实现逐字符一致（语义零差异）；真实 `run_command` 全链路（子进程输出 1MiB 无@串，默认预算）0.06–0.38s 完成，60s 线程 watchdog 兜底；日志留 `re-runs/logs/`（测试输出含 [timing] 行）。
- 结论：**已通过**。

## 4. 本轮新增接线（G1，每项真实 ToolRun/产物/oracle）

| 能力 | 接线点 | oracle 正/负对照（tests/） | 全能力 run 实测 |
| --- | --- | --- | --- |
| Android S1 解包 | `decompile.py`（jadx java-classpath/apktool jar）→ `profiles.mobile`（RE_RUN_JADX/RE_RUN_APKTOOL） | test_android_decompile 8 项：apktool 解码 manifest+smali；**jadx 对扩展 dex fixture 真实反编译出 `Fixture.java`**；损坏 APK→degraded+签名；未配置→skipped | fixtures run：两 check succeeded（`4 decoded artifacts`/`1 java sources`），新增 `android-smali-telephony-identifier` 候选 |
| 固件隔离 extractor | `extractors.py`（7z）→ `source_firmware`（RE_RUN_7Z，squashfs/cpio） | test_firmware_extract 9 项：**真实 gzip.sqfs 解包 106 文件入 scan_tree**；cpio 正例；损坏容器→degraded；UBI/TRX 7z 无 handler 如实 raw+degraded | fixtures 的 tar 走原生路径（正确不路由 7z）；7z 检查在 squashfs 用例验证 |
| 流量深度重组 | `profiles.traffic.deep_reassembly`（scapy，缺包如实 skip） | test_traffic_deep 6 项：TCP 分段重组出 HTTP 流、**token 零泄漏**、无 scapy→skipped、损坏 pcap→degraded | fixtures run `traffic-http`：**1 HTTP stream reassembled from 7 packets**（修复了 worker env 缺 `ProgramFiles` 导致 scapy 导入失败的接线 bug） |
| 源码规则引擎 | `scanner.py`（bandit）→ `source_firmware._rule_engine`（PATH） | test_source_deep 6 项：B602/B605/B506/B404 命中、与 AST 候选并存、无 bandit→skipped | fixtures run：`bandit 1.9.4: 1 finding(s), 1 dangerous-API hit(s)`，新增 `bandit-high-dangerous-api` 候选 |
| UPX 打包样本静态解包 | `unpackers.py` → `profiles.binary`（RE_RUN_UPX，仅 PE 指示触发） | test_upx_route 3 项：打包样本解包 succeeded（熵 7.913→6.502、UPX 节消失、体积增大）；未打包→failed+NotPacked 签名；未配置→skipped | fixtures 无 UPX 指示样本（诚实不触发）；`executed:true` 路线仅在真实解包成功时输出，`bypass_executed` 恒 false |
| AI 行为 oracle | `profiles.special.behavior_probe`（7 条固定 canary，仅 ai-test 操作+授权服务） | test_ai_behavior 6 项：安全 mock→succeeded；脆弱 mock→7 条 `ai-oracle-refusal-failure` 候选；不可达→degraded；缺 ai-test→ScopeDenied | 合同名 `ai-test` 现有真实实现；limitations 声明为行为 oracle 非模型内部检测 |
| 合约编译 | `compilers.py`（solc）→ `profiles.special`（RE_RUN_SOLC） | test_contract_compile 5 项：Vault.sol 编译 succeeded+ABI 落盘+`contract-unprotected-state-mutating` 候选；语法错误→degraded+stderr 签名；未配置→skipped | fixtures run：`contract-compile-solc` succeeded |
| doctor 能力矩阵同步 | `capabilities.py`：新工具（7z/upx/solc/bandit/scapy）入矩阵，`RE_RUN_*` 解析与版本实测，jadx/apktool/7z/solc 用途改"Wired" | test_doctor_profiles 7 项（更新 jadx/apktool 断言为已接线语义） | `doctor --profile firmware`（RE_RUN_7Z）：7z→runnable "7-Zip 25.01" |

## 5. 全链路运行记录（本轮终态，全部留盘可复核）

原始日志：`re-runs/logs/unittest-final.txt`（**180 tests / 179 passed / 1 skipped**[Windows symlink 权限，环境性] / 0 failed，98.4s）、`re-runs/logs/ruff-final.txt`（All checks passed）。

| 链路 | run（re-runs/results/） | 状态 | 要点 |
| --- | --- | --- | --- |
| fixtures 全能力（22 资产=11 类本地资产 + traffic-http） | `20261019T125138Z-4eaa1d38edf4` | succeeded, 14 findings | jadx/apktool/bandit/solc/scapy 真实触发；**注：21→22 资产覆盖 11 类，Web 不在其中（见第 6 节口径）** |
| examples 本地文本资产 | `20261019T124756Z-2f9ed1996ce0` | succeeded | 5 资产 |
| PE+radare2 | `20261019T124759Z-b8edfb788c26` | succeeded | 3 checks 全过（513 函数+48 反汇编能力在本轮之前的 run 已验证） |
| **本机实验服务（独立网络测试，tools/run_local_acceptance.py 可复跑）** | web `…125220Z-b61faa6e3b1b`、openapi `…125221Z-c221c0de6e7d`、graphql `…125222Z-c2411613cae5`、websocket `…125223Z-b6899c3ffa92`、grpc `…125224Z-8c9e80c5d945`、chain-read `…125225Z-b6b37d14a796` | 6/6 succeeded | web 命中 1 条 password-form 候选；ws 真实握手；grpc reflection 列出 `demo.Echo`；chain-read 走 JSON-RPC eth_chainId/getCode（chainId 0x7a69=31337）；服务 harness=[tools/local_services.py](../tools/local_services.py)，摘要=re-runs/local-acceptance-summary.json |

## 6. 验收状态总表（已通过 / 未通过 / 缺环境 / 未实现 严格分开）

### 6a. 已通过（本轮有真实证据）
1. F1 取消/超时/预算耗尽的收尾计账与恢复不复计（真实执行器路径，第 3 节）。
2. F2 导出 schema 与真实 succeeded/degraded/blocked/failed/cancelled/timed-out/output-exceeded 报告一致 + 生成端校验。
3. F3 脱敏复杂度有界（三处平方级模式修复，规模阶梯+watchdog 实测）。
4. 180 项测试 / ruff 全绿（原始日志在第 5 节路径）。
5. Android S1（apktool+jadx 真实反编译）、固件 7z extractor（真实 squashfs/cpio 样本）、流量 scapy 重组（真实 HTTP 流+脱敏验证）、源码 bandit 规则引擎、AI 行为 oracle（授权服务+canary 数据表）、合约 solc 编译、UPX 静态解包路线——每项带正/负对照与失败签名（第 4 节）。
6. Web/OpenAPI/GraphQL/WebSocket/gRPC/chain-read 六条**本机实验服务**真实 run（第 5 节 run id）。

### 6b. 未通过 / 有条件通过（如实说明）
1. squashfs 解包在本机为 **degraded**（样例内 symlink 条目因 Windows 无符号链接权限失败）；cpio 正例保证 succeeded 路径被覆盖，特权/开发者模式主机自动升为 succeeded。属环境限制而非实现缺失，但**当前主机上该 check 不是 succeeded**。
2. UPX 路线的 `protected-binary-unpack-upx` 在 fixtures 全能力 run 中**未触发**（样本无 UPX 指示，属正确行为）；该能力的 succeeded 证据在测试内（真实 upx 5.0.2），未在 fixtures run 中呈现。

### 6c. 缺环境（requires-environment，外部条件）
1. 真实 Android/iOS 设备、串口设备：descriptor 链已验收，`adb/ideviceinfo/pyserial` 代码路径在位；**descriptor ≠ 真机验收**。
2. Android 动态插桩（emulator/Frida，S3 动态段）、Apple 授权设备解密产物采集。
3. 合约 fork/testnet 正负对照（需本地节点/测试网端点；主网交易永久禁止）；Forge 未接线。
4. 动态执行样本的隔离沙箱/VM 后端（Windows Job/Linux rlimits 仅为资源限制，不充当恶意样本沙箱；macOS 硬内存限制缺）。
5. symlink 遍历测试（1 项 skip，需 Linux/macOS 或特权 Windows）。
6. TLS 解密（需密钥日志，永不无凭据声称解密）。

### 6d. 未实现（本机可做但本轮未做，非环境问题）
1. Java/JVM/AAB 深度（apktool/jadx 仅接 APK；aab 的 S1 未接——工具链语义不同）。
2. Ghidra/IDA/REA 深度反编译 adapter、tshark adapter、semgrep 跨语言规则（bandit 仅 Python）。
3. OCI registry 拉取/merged filesystem/Docker-save 布局。
4. UBI/TRX 真解包（7z 25.01 无 handler；偏移非 0 的内嵌 squashfs 不路由 7z）。
5. AI 非文件型行为覆盖的扩展（多轮对话、流式响应）。
6. Linux/macOS 实机验收：**CI 仅完成配置**（[.github/workflows/acceptance.yml](../.github/workflows/acceptance.yml)，三平台矩阵跑核心套件+fixtures+schema 自检）；Windows 为本机实跑，Linux/macOS 结论需 CI 首次运行 URL，**配置存在 ≠ OS 验证**。
7. Vyper (.vy) 编译（仅词法索引）；solc 多根 import 布局。

### 口径修正（响应审查）
- fixtures 的 21（现 22）个资产是 **11 类本地资产**（api/graphql/android/aab/apple/binary×3/source/firmware/container/sbom/traffic×3/device-descriptor/ai×3/contract×2）；**Web 从未在其中**，Web/WebSocket/gRPC/GraphQL/chain-read 的证据是第 5 节的本机实验服务独立 run。
- `next_routes` 与 `executed:true` 路线严格区分；`bypass_executed` 恒 false；静态解包/词法命中/规则命中均以 candidate 呈现，**verified 仅私钥持有验证器在正负对照齐全时赋予**（本轮 fixtures run 0 verified，与"不承诺发现漏洞"口径一致）。

## 7. 复验命令

```bash
python tools/worktree_digest.py                                   # 须得 70 文件 + 第 1 节摘要
uv sync --locked --all-extras --group dev
uv run --no-sync python -m unittest discover -s tests -v          # 180/179/1skip 基线
uv run --no-sync ruff check src tests pipeline/env_scan.py
export RE_RUN_R2=<…radare2.exe> RE_RUN_JADX=<…jadx 目录> RE_RUN_APKTOOL=<…apktool.jar> \
       RE_RUN_UPX=<…upx.exe> RE_RUN_7Z=<…7z.exe> RE_RUN_SOLC=<…solc.exe>
uv run --no-sync python tests/fixture_factory.py re-runs/fixtures
uv run --no-sync re-run analyze --manifest re-runs/fixtures/manifest.json --output re-runs/results
uv run --no-sync python tools/run_local_acceptance.py             # 需 8765-8767 端口空闲
uv run --no-sync re-run schema --output re-runs/schemas
```

## 8. 遗留小项
- `report.md` 的 errors 渲染对 dict 走 `str(item)`（可读性优化项，不影响 schema/JSON 消费）。
- bandit 扫描无目录排除表；超大树以 timed-out→degraded 收场（诚实路径）。
- jadx 对 fixture 的 `imei()` 反编译带一条 type-inference WARN（方法体完整还原）。
- `intake` 途中的取消仍可能丢 intake ToolRun（不在 F1 根因清单，记录待办）。

## 9. 第三轮集成(2026-10-20)

- **全量回归**:Ran 243 tests **OK (skipped=31)**,完整日志 `re-runs/logs/unittest-round3-final2.txt`(环境门控项如实自跳);ruff 协议口径(`src tests pipeline/env_scan.py`)**All checks passed**。全仓宽扫另有 7 处 E402 位于范围外移植目录(cve-hunter/ 等),不属验收口径,如实注记不改协议。
- **三路交付**:A=UBI/TRX/OCI merged/registry v2(registry:2 真容器推拉)+ghidra headless adapter(bpalogin 251 函数/8 反编译真跑),23/23;B=frida(真 attach)/vyper 0.4.3(真编译)/S3(moto 真端点)实跑,AI 流式合同级,合约 fork 缺 anvil 如实声明,15/15;C=UPX 平台无关三 lane(7 实跑全绿,PE 项改「存在才跑」)+semgrep 1.181.0 真跑,tshark 未装列明。
- **敏感终扫**:`/Users/Zhuanz` 绝对路径 2 处(tests/test_a_lane.py)改为环境变量门控 `RE_BPALOGIN`/`RE_GHIDRA_HOME`(双模式实测:无变量 23 OK/4 skip,带变量实跑全过);凭证/设备名 0;`SECURITY-AUDIT.md` 入 .gitignore 不随库发布。
- **摘要**:79 文件,见 `python tools/worktree_digest.py` 当前输出。
- **环境项登记(未验证≠已验证)**:CI 三平台首跑 URL、真机/模拟器、anvil fork、tshark、jffs2 展开、真实 AWS/AI 端点——分列如实,不以配置存在结案。
