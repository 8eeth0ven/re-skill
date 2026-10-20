# re-run：执行指南与全资产支持矩阵

当前工作分支的统一入口为 `re-run`，Python 3.11+。代码尚未提交或推送。
本轮按用户要求停止安装和测试；以下命令由接手 Agent 执行。
[交付状态](delivery-status.zh-CN.md)与[交接 Prompt](agent-completion-prompt.zh-CN.md)
说明剩余工作和验收要求。

## 输入到报告

```bash
uv sync --locked --all-extras --group dev
uv run --no-sync re-run inspect --asset /absolute/path/to/sample.apk
uv run --no-sync re-run doctor --profile android
uv run --no-sync re-run schema --output re-runs/schemas
uv run --no-sync re-run analyze --asset /absolute/path/to/sample.apk --output re-runs
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
uv run --no-sync re-run analyze --asset http://127.0.0.1:8765/ --scope examples/scope.localhost.json
uv run --no-sync re-run analyze --asset /absolute/path/to/rootfs --type firmware --level verify
uv run --no-sync re-run status --run-id <run-id> --output re-runs
uv run --no-sync re-run resume --run-id <run-id> --output re-runs
uv run --no-sync re-run cancel --run-id <run-id> --output re-runs
```

URL/IP/域名进入 Web；HTTP API 使用 `--type api`。设备使用
`android://<serial>`、`ios://<udid>`、`serial://COM3` 等明确身份。
不透明格式可显式指定类型，但显式类型不会凭空增加解析能力。
源码/固件目录的输出必须在输入目录之外。

`inspect` 不访问网络。`doctor` 读取包元数据和 PATH；`--profile` 按 12 类给出
required/optional 能力与 missing/present/runnable 就绪度（工具做 5 秒版本实测，
设备类标注 requires-environment，汇总见 `profile_requirements.required_ready`）。
`re-run schema` 导出与 `contracts.py` 同步的输入/报告 JSON Schema。`triage` 为
基础分析与候选；`verify` 仅运行已注册验证器，目前只有私钥持有验证，不能保证出现已确认漏洞。

创建 run 前的无效参数/schema 返回错误 JSON；已创建的正常、降级、受阻、失败和
取消任务会尝试写结果报告。进程被强杀或磁盘写入失败需恢复/诊断，不能保证当场有报告。

## manifest 与 scope

```json
{
  "version": 1,
  "assets": [
    {"id": "app", "locator": "./sample.apk", "type": "android"},
    {"id": "api-spec", "locator": "./openapi.json", "type": "api"}
  ]
}
```

manifest 内已有本地路径按 manifest 所在目录解析；不负责克隆 Git URL、拉取镜像
标签或下载模型。输入合同见 [contracts.py](../src/re_runner/contracts.py)，未知字段拒绝。

```json
{
  "version": 1,
  "allow_urls": ["http://127.0.0.1:8765/"],
  "exclude_urls": ["http://127.0.0.1:8765/admin/"],
  "operations": ["read", "api-query"],
  "budgets": {"max_requests": 12, "max_wall_seconds": 300, "max_retries": 1}
}
```

未提供 scope 默认可读取显式本地输入，网络/设备读取被阻止。`allow_paths` 若非空
则限制本地根目录；相对路径按 scope 文件目录解析。允许设备必须给
`allow_devices` 精确 locator 和 `device-read`；链查询需要 `chain-read`。
`ai-test` 是合同操作名，当前 AI profile 没有行为测试适配器。

凭证通过 `headers_env` 引用环境变量，例如 `{"Authorization":"RE_LAB_AUTH"}`。
变量值由执行环境提供，不写进 manifest/scope；凭证 scope 只允许一个 origin。
发现的链接、DEX 端点、固件地址和合约引用登记为数据，不自动扩展网络测试范围。

默认预算：输入 128 MiB、下载 16 MiB、解包 256 MiB、10000 文件、16 层、压缩比
200、12 请求、4 请求/秒、300 秒总时限、90 秒工具时限、1 MiB 工具输出、
768 MiB 内存、1 次重试。按任务在 scope 中显式调节，范围以 schema 为准。

## 产物与状态

```text
re-runs/<UTC时间>-<12位随机ID>/
├── report.md / report.json
├── assets.json / findings.json
├── evidence/index.json
├── request.json / state.json / plan.json / capabilities.json
├── events.jsonl
├── inputs/    原始输入只读快照与 hash
├── work/      分析/验证产物、工具 stdout/stderr、资源 journal
└── logs/
```

恢复重新核验请求、原始输入、快照和成功阶段产物，不重复有效成功阶段。
取消通过 `cancel.request` 通知执行器。中断后资源用量无法确认时保留失败 run，
修复条件后新建 run，不将未知用量当零。所有这些行为需接手 Agent 对最终代码复验。

`analyze/resume` 退出码：`0=succeeded`、`1=degraded`、
`2=blocked/failed`、`130=cancelled`。成功仅表示当前声明检查完成；
必须结合 checks、limitations 和具体断言判断分析深度。

## 全资产矩阵

L0=结构/身份/入口与证据；L1=有证据的候选；L2=验证器执行与对照支持的具体断言。
下表为代码状态，**不是最终版本测试认证**。历史 74 项回归发生在本轮后续修改之前。

| 类别 | 已有真实执行路径 | 当前 L1/L2 与限制 | 需要补全/环境 |
| --- | --- | --- | --- |
| Web | scoped HTTP 入口、页面/forms/links/headers | 单入口结构；没有完整爬取/角色业务测试 | 认证会话、范围内采集与行为验证 |
| API | OpenAPI JSON/YAML、GraphQL SDL/读查询、proto 声明、WebSocket 握手、gRPC reflection | 规范/服务索引；不等于鉴权漏洞确认 | grpc extras、请求回放/角色对照、协议深度 |
| Android | APK/AAB 安全提取、binary/protobuf Manifest、DEX 索引、Native 清单 | 组件权限候选；DEX 非完整 CFG | JADX/Apktool、AAB 转换、adb/Frida 动态接入 |
| Apple | IPA/App plist、Mach-O、可用 XML entitlements、加密范围 | 配置候选；未验证签名 trust/加密代码 | codesign/匹配解密产物、授权设备动态 |
| Binary | PE/ELF/Mach-O、入口汇编、.NET/JVM/JAR/WASM 结构、Go/Rust marker | radare2(aaa) 深度链已验收（RE_RUN_R2 指向原生 exe；空函数/缺汇编如实 degraded）；保护指示含 fat Mach-O 切片级加密 | Ghidra/IDA/REA adapters；无通用反混淆验证 |
| Firmware | rootfs、TAR/ZIP/gzip、文件/config/banner 扫描 | 字符串/配置候选；可用私钥持有可验证 | squashfs/UBI/TRX 等仅 raw scan，需隔离提取/仿真，不能算完整 rootfs 支持 |
| Source | 文件/语言/依赖/literal、Python 函数内 AST 路径 | 局部路径候选；可用私钥持有可验证 | 跨过程/控制流、其他语言工具；不执行仓库 build/hooks |
| Container | OCI layout/archive digest、config、layer/whiteout 索引；CycloneDX/SPDX/依赖 | 默认 root 候选；无实时公告/回移判定 | merged filesystem、registry/runtime、公告快照；Docker-save 尚不支持 |
| Traffic | PCAP/PCAPNG header/flows、HAR 脱敏索引、radiotap metadata | 不含 TCP 重组/TLS 解密/无线深度分析 | tshark 或同类解析器 adapters |
| Device | descriptor 索引；scoped adb/ideviceinfo 身份、串口被动读代码 | descriptor 测试不等于真实设备验收 | 实际设备、pyserial、精确身份；无线/MCU 深度采集未实现 |
| AI | Agent 配置权限、safetensors shape/offset、GGUF 元数据、服务 metadata | 配置候选；没有 prompt 对抗行为验证 | 行为测试/oracle；PT/pickle/joblib/ONNX 目前 blocked，不能算 L0 解析支持 |
| Contract | Solidity/Vyper 词法、EVM opcode、scoped chainId/block/code | tx.origin/delegatecall 候选；PUSH4 不等于真实 ABI dispatch | 编译器、权限/代理恢复、fork/testnet 正负对照；不交易 |

目前唯一 L2 验证器确认“资产内含可用未加密私钥”：正向签名验证成功，改消息
验证失败，保存公钥 fingerprint。它不确认该私钥仍被部署信任或存在可利用漏洞。

## 强对抗与可信结果

已写保护指示与升级路线：UPX 节、高熵、anti-debug 导入、缺符号、Mach-O 加密、
Android native-heavy 等。输出 `bypass_executed: false`，尚未自动完成动态绕过。
接手 Agent 要实现“假设→失败证据→有限替代路径→隔离验证→重新关联证据”。

执行器已有受限解包、严格 JSON/YAML/XML、参数化 subprocess、输出/超时、进程树
清理、核锁、DNS pin 与 redirect scope 复核、脱敏和证据/hash 门。
Windows Job 和 Linux rlimits 是资源控制；macOS 硬内存限制不可用。
这些不构成恶意代码安全沙箱，动态样本执行需单独隔离后端。

报告逐条 finding 包含概览、技术根因/触发/攻击面、验证、影响、修复/检测。
版本字符串、共现、关键词零命中和模型文字不能将候选升级为 verified。
