# BLE 蓝牙与 Zigbee


## 1. BLE 栈与攻击面

```
GATT(服务/特征值:数据模型,读写/Notify)
ATT(属性协议:handle 读写)
L2CAP / SMP(配对加密)
LL(链路层:37 数据信道跳频+3 广播信道)
```

攻击面:**配对缺加密(Just Works)**→中间人;**未鉴权特征值**→任意读写(多数廉价设备);**广播配网信息**→嗅探。

社区帖群(CTF+实战一体):
- 通过BLECTF入门BLE(BLECTF 靶场通关=BLE 工具链速成)
- BLECTF低功耗蓝牙CTF挑战(题解)
- 一个BLE智能手环的分析、手环BLE蓝牙认证绕过,可实现远程控制(实战见 §3)
- 锁:Nokelock蓝牙锁破解、某蓝牙马蹄锁的分析、云丁鹿客门锁BLE通信分析
- 高阶:基于模拟仿真的蓝牙协议栈漏洞挖掘(协议栈内部 bug 用仿真+ fuzz 挖)
- 环境:基于树莓派的蓝牙调试环境

工具:Ubiqua/BLEsniffer/nRF Sniffer/Android nRF Connect;hci 命令族。

## 2. Zigbee

- 浅析Zigbee协议攻击面(IEEE 802.15.4 上 NWK/APS 层,网络 key 全网同钥、无重放保护的重传窗口、join 流程滥用)
- 工具:Atmel RZUSBstick/KillerBee/Attify-Zigbee;CC2531 sniffer 固件。
- 核心结论(帖内):拿到 network key 即全网明文;key 常在设备固件硬编码(回 [../iot/固件提取.md](../iot/固件提取.md) 翻 strings)。

## 3. 实战:BLE 手环认证绕过——抓包→逆认证协议→重放控制

路径:手机开发者选项「蓝牙 HCI 信息收集日志」→ APP 绑定/操作手环 → 分析 btsnoop 日志确认重放 handle/value → nRF Connect/BLE 调试助手重放。

**认证协议还原**(未绑定流,已绑定=少写 key 一步):
```
APP ──写 desc 0x0100(CCCD 开 notify)──▶ 手环
APP ──写 0x0100+key(16B)──────────────▶ 手环   ← 未绑定时先写 key
APP ──发 0x020002(要随机数)───────────▶ 手环
APP ◀──0x100201+rand(16B)────────────── 手环
APP ──发 0x0300+AES_ECB(key,rand)(16B)▶ 手环
APP ◀──0x100301(认证通过)/0x100304(失败)─ 手环
```
(key 明文传输+ECB 无 IV,由已知 key/rand/密文三元反推即 AES_ECB)

**漏洞与利用**:①未绑定时可写**任意 key**,随后按该 key 加密随机数回送即通过认证;②**已绑定态再写 key 会覆盖旧 key**(原绑定设备失联)——认证形同虚设。绕过后按 HCI 日志定位短信提示/来电提示/寻找手环的 handle+value,重放即远程控制手环。

坑:评论质疑「key 不是 ECDH 协商的吗」——实测为明文传输且可覆盖,协议设计与实现差距本身就是漏洞面。
