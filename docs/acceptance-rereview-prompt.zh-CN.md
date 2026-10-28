# 第二轮复核整改与补全 Prompt

将下方整体交给负责安装、测试、实现的 Agent。统筹复核仅检查代码与既有证据，本轮没有重跑测试。

```text
你接手 re-skill 的执行整改，在当前工作目录继续：
<repo>
仓库 https://github.com/8eeth0ven/re-skill
分支 codex/readme-review，基线 HEAD 0059a9a。
保留全部未提交/未跟踪文件及历史 run；不 reset/clean，不主动 commit/push/发布。
先读 docs/acceptance-rereview.zh-CN.md、docs/acceptance-remediation-prompt.zh-CN.md、
docs/agent-completion-prompt.zh-CN.md、docs/execution-acceptance.zh-CN.md。

当前事实：70 文件摘要 f85ddf59298ce5f0101eca0144f25c7e4ec2e7dd0f9f84c43bb04efcded210cc；
既有原始日志 180 tests/179通过/1跳过、ruff通过。9条终态run的270条产物hash、75条
证据引用已独立复核。不能沿用这些历史结果给新增修改签收。

优先完成三个阻塞点，不只改文档、缩小样例、删除测试或降低上限掩盖：

R1：runner.py _invoke/_validate先_artifacts后_record_tool和usage结算；settling只
绕开budget.check，_artifacts/iter_tree的文件数、字节、深度、链接异常仍会提前抛出。
使任何已启动执行即使产物不能完整枚举，也在当前终态留下ToolRun、执行状态/错误、
受限且明确不完整的产物清单、完整校验后的usage、accounted。resume不得重复计账。
不能取消枚举上限或无界扫描。补intake中断的记录和安全恢复策略。
用真实Runner/受控worker先消费非零资源，再制造产物超限，并分别组合cancel/deadline；
覆盖validator、intake、损坏/链接产物，断言最终report和state、journal及resume一致。

R2：extractors.py listing失败时members=[]仍执行7z x；_parse_listing到5000条
截断但不标记；_inventory在解包完后才计账。必须在列表失败/输出超限/截断/解析
不完整时拒绝解包；完整验证所有成员的路径、类型、链接、深度、目录/文件数。
总字节/条目限制必须作用于实际写入过程，不能只用Windows Job或单文件RLIMIT_FSIZE。
采用受控逐成员流式写入，或真实可强制总目录配额的隔离后端；保留scope与网络限制。
同时把JADX/Apktool派生输出纳入实际用量和边界，不只事后枚举。
解决7z跳过链接但scan_tree拒绝链接造成的特权主机全链路失败；明确拒绝/省略策略。
实跑不完整列表、超过5000成员、深目录/空目录洪泛、链接、总量超限、root外哨兵；
记录x是否启动及写入限制何时生效。不要声称已验证未复现的路径逃逸。

R3：execution.py reader及_settle_output先截断，safety.py未闭合PEM找不到END时
原样输出，导致跨边界私钥正文漏入日志。做知道截断状态的脱敏，或对private-key
BEGIN到缓冲区末尾保守脱敏；覆盖返回值、stdout/stderr日志和adapter JSON。
用合成私钥/测试canary，BEGIN和正文在保留区、END在界外，覆盖默认1MiB、4MiB硬cap、
未闭合PEM及其它token/assignment边界。保留有界复杂度、默认预算与规模阶梯/watchdog。
不要为了旧oracle的逐字符相同继续保留不安全语义，明确更新预期与安全策略。

然后继续原12类目标，不能自行只验收APK或把缺代码称作缺环境。按asset+operation
列清楚代码实现、测试、留盘证据和外部条件：AAB/JVM、深度反编译、跨语言规则、
OCI merged/registry、UBI/TRX、AI多轮/流式、Vyper/import、Frida/S3、合约fork和隔离
后端等依原交接矩阵完成可独立执行部分。静态→动态只走授权隔离后端；没有环境时
交付完整adapter/合同/失败路径并如实标未运行，不能把mock当真机或动态绕过成功。
真机、许可、TLS密钥与代码未接线分别登记。Linux/macOS需实际CI URL和日志，配置
文件存在不等于通过；不因当前分支未提交自行push触发CI。

证据要求：为UPX打包正例、squashfs/cpio、AI行为正负对照与上述三个阻塞点保留专门
Runner run/oracle/原始日志，不能只留TemporaryDirectory里随后删除的测试产物。
候选不自动成为漏洞；verified只由注册验证器和真实正负对照决定，bypass只凭实际
行为恢复证据。不直接在host运行未知样本，不外发凭证或私密样本。

安装复用当前.venv/tools-env，必要回归和lint由你完成。每次最终代码修改后重跑相关
检查，再运行全量必要回归，保存命令、版本、原始日志、精确通过/跳过理由。重算工作树
摘要，范围须注明；为tools/CI等未包含在70文件范围的交付另记版本/hash。
更新execution-acceptance四分表和支持矩阵；逐项列已通过、未通过、缺环境、未实现。
所有结论绑定具体run、ToolRun、Evidence/hash和oracle，不以exit0或报告存在结案。

完成后给统筹Agent：新版本标识、R1/R2/R3修复位置、原始测试/lint路径、专门run路径、
可复验命令及剩余项。直接实施修复和验证，不只输出计划或再次断言全部完成。
```
