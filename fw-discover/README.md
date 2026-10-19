# fw-discover · 固件自主漏洞发现(0day 候选,非 CVE 比对)

**与 ../cve-hunter 的分工**:cve-hunter 是「已知 CVE × 版本比对」的 N-day 台账;这边是**自己发现**——下载公开路由器固件 → 解出文件系统 → 用本目录规则(`analyzers.py`)挖出候选,每条都来自本机静态分析,不是查表。

**要拿真 CVE 先看 [`CVE-流水线.md`](CVE-流水线.md)**:候选→四杀门(双证据/新颖性/可达性/PoC)→披露就绪→人工报送;口径账本也在里面。静态扫描电池的装机与双 lane 用法见 `静态扫描工具矩阵.md`。

## 流程

```
种子队列(DD-WRT betas 真路由器固件 + OpenWrt 工厂镜像验证通道)
  → 下载(curl;DD-WRT 有 Anubis 反爬,必须走 curl 默认 UA,urllib 会被挑战页挡)
  → 魔数扫描(TRX HDR0 / uImage / squashfs 四字节序 / gzip,最多剥 3 层)
  → unsquashfs 4.7.5 解包(老式魔改 lzma 变体解不开 → 标记跳过,sasquatch macOS 编不过已弃)
  → analyzers 六类规则 → findings.jsonl + 台账.md
```

## 发现规则(全部本机规则,命中即候选)

| 类别 | 优先级 | 什么意思 |
|---|---|---|
| verified-weak-cred | 4 | passwd/shadow 的 DES 哈希被小字典本地命中(openssl passwd -crypt 实测) |
| shipped-private-key | 4 | 固件自带 PEM 私钥 |
| cmdi-candidate | 3 | 同一二进制里 QUERY_STRING/websGetVar/nvram_get 等网络参数源 × system/popen/exec 家族 |
| cmdi-script | 3 | CGI/shell 脚本 eval 吃外部参数 |
| telnetd-enabled | 2 | 启动脚本默认拉起 telnetd |
| default-cred | 2 | nvram/配置里非空默认口令字面量 |
| hardcoded-account | 1 | passwd/shadow 带活动哈希的账号 |

## 用法

```bash
cd fw-discover
python3 fw.py --seed     # 建种子队列(去重增量)
python3 fw.py --once     # 处理一小批:下载→解包→发现(可反复,单实例锁)
python3 fw.py --status   # 进度
```

数据在 `../data/fw-discover/`(queue/findings/台账/固件与解包树)。目标 100 条,**半小时保活**:`keepalive-fw.sh`(<100 跑 --once;达标后提示进入人工/subagent 筛选阶段并收尾)。

## 筛选阶段(达标后必做,人工或 subagent)

台账是候选不是结论。按优先级抽 top-20:①对 cmdi-candidate 用 r2 `axt @ sym.imp.system` 看调用者函数是否真收参数(假点:仅启动期调用);②私钥用 `openssl rsa -in <f> -check -noout` 验真;③弱凭证给出复现命令。产出写 `../data/fw-discover/筛选/`,过三问(安全策略违反+可利用证明+影响面)再进披露。

## 红线

- 台账全部是**自主发现的候选**,禁止自动提交任何外部平台;外报走人工 + `../漏洞披露与CVE申请.md`
- 动态仿真(FirmAE/qemu system-mode 跑起固件再打)是下一阶段,本机 macOS 不做
- 只测公开发布的固件镜像;不碰在线设备
