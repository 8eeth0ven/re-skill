# 可复制输入

以下为纯文本演示资产，未在本轮执行。它们说明输入合同，不代表真实设备或漏洞验证。
安装和测试由接手 Agent 执行：

```bash
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
```

本地 manifest 包含 API 规范、AI 配置、设备 descriptor、EVM 字节码和 SBOM。
API server/link 与设备 observations 只登记，不自动联系。
`scope.localhost.json` 仅允许本机 8765 端口；测试服务由执行 Agent 准备。

完整 12 类合成资产通过 `tests/fixture_factory.py <output>` 生成，包括 APK/AAB、
IPA、ELF/JVM/WASM、rootfs、OCI 和 PCAP。fixtures 是确定结构 oracle，不能替代
生产资产、真实设备或强对抗运行验收。
