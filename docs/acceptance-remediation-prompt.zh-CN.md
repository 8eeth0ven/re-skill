# 验收整改 Prompt

将下面整体复制给执行 Agent，在当前工作树继续，不重新克隆覆盖已有改动。

```text
接手 <repo>。统筹验收未通过，先读取
docs/acceptance-review.zh-CN.md 与原 docs/agent-completion-prompt.zh-CN.md。
保留全部未提交/未跟踪文件，不reset/clean，不主动push/发布。继续安装、修复与测试。

先修三个阻塞项，不靠降低测试规模或改验收措辞掩盖：

1. runner.py:226 先用带cancel/deadline的budget枚举产物，取消或总时限耗尽会在
   journal计账前抛异常；_consume_attempt_usage:275也通过Budget.consume再次
   检查已触发的停止条件。把停止新增执行与收尾证据/完整校验/原子计账分开。
   真实运行先消费非零资源再取消或到期，核对最终ToolRun、state.used、journal、
   accounted；resume不得复计。覆盖验证器取消，不只直接调用helper且不设取消标志。
2. contracts.py:128/164限error为字符串，但实际失败报告是{code,message}对象；
   ToolRun.status的enum也没有timed-out/output-exceeded/budget-exceeded。
   统一报告模型、生成端schema校验，并以真实Runner的成功/降级/受阻/失败/取消/
   超时/输出洪泛报告验证导出的schema。手写空成功报告不足以验收。
3. safety.py:35 email正则对无@长word串有平方级扫描；execution.py:236在监控
   结束后主进程同步脱敏，默认1MiB输入可拖住。改为复杂度有界的实现并保障总时限/
   取消覆盖。用默认上限和不同规模样例、外部watchdog记录行为，不能仅把buffer调4KiB。

随后补原交接的缺实现：隔离动态/保护替代路线、Android JADX/Apktool/S0–S4、
固件isolated extractor、深度流量/源码、AI行为oracle、合约编译/fork、CI等。
安装工具或doctor出现runnable不会自动接线；每项要实际ToolRun、Evidence、oracle。
只保留真正需要真机/许可/账号的requires-environment，完成所有可独立执行的工作。

修正文档证据口径：21个fixture是11类本地资产，Web属于独立网络测试；保存Web/
WebSocket/gRPC/链读的实际run/日志。不要把descriptor当真机、next_routes当绕过。
强对抗要基线/正负对照/失败签名/有限替代/行为恢复，bypass只凭真实证据赋值。

补齐每个验收项后运行必要回归及集成，保存原始unittest/ruff日志、精确计数、跳过
理由、当前工作树摘要算法和run路径；更新docs/execution-acceptance.zh-CN.md，
明确已通过、未通过、缺环境、未实现。继续推进，不以现有105通过或报告存在结案。
最终将代码、证据和剩余项交统筹Agent复验。
```
