# fw-discover · 固件静态候选筛选

此模块维护DD-WRT/OpenWrt公开固件种子队列与本地候选台账。规则命中需要继续验证；
[CVE流程](cve-pipeline.md)分别处理真实性、新颖性和披露。

通用本地资产入口已经在统一执行器中实现：

```bash
re-run analyze --asset /absolute/path/to/rootfs --type firmware --output re-runs
re-run analyze --asset /absolute/path/to/firmware.tar --type firmware --output re-runs
```

支持rootfs和受限TAR/ZIP/gzip；opaque squashfs/UBI/TRX等仅有界扫描，不能称解包成功。
深度提取需隔离provider。见[支持矩阵](../docs/runner.zh-CN.md)与[交接](../docs/agent-completion-prompt.zh-CN.md)。

## 旧队列脚本

```bash
python3 fw-discover/fw.py --seed
python3 fw-discover/fw.py --once
python3 fw-discover/fw.py --status
```

数据在 `data/fw-discover/`，不随仓库发布。脚本使用核文件锁、原子写入、限定下载
host和大小、有界gzip；保留原始样本。成功才done，下载/分析错误有限重试，
缺提取器或范围不符记blocked，具体原因持久化。

**行为变更：旧脚本不会在host自动执行unsquashfs/sasquatch。**
未经隔离适配的不透明文件系统提取返回blocked；不要把队列结束写成全部分析成功。
已提取rootfs可交统一CLI分析。

## 规则含义

| 规则 | 可支持的证据 | 仍需核实 |
| --- | --- | --- |
| cmdi-candidate | 同文件网络参数与system/popen/exec字符串共现；已降优先级 | 参数传播、调用点、配置与可达性 |
| cmdi-script | shell/CGI文本可疑使用 | 实际输入控制和触发行为 |
| shipped-private-key | 文件含私钥块 | 可用性、部署trust及影响 |
| verified-weak-cred | 实际本地hash对照命中时的密码匹配 | 账号启用/登录入口；不等于产品漏洞确认 |
| telnetd-enabled/default-cred/hardcoded-account | 启动/config/账号文本 | 实际默认配置与暴露范围 |

旧台账分类名不对应统一runner的verified级别。100条是候选展示目标，不是漏洞数。
版本、字符串、私钥与NVD零命中不能自动赋漏洞确认。

## 可选有限循环

`keepalive-fw.sh` 包装 `python -m re_runner.keepalive --profile firmware`，需先准备
runner环境；最多40轮，默认间隔1800秒，停止于无可重试队列。没有自动安装计划任务。
本轮keepalive最新代码未执行，安装与复验交执行Agent。
