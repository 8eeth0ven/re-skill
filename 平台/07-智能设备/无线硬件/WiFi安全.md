# WiFi 安全


## 0. 无线安全总纲

攻击者视角分层:`物理(射频)→ 链路(802.11/15.4)→ 协议栈实现 → 应用语义`。各介质分篇展开;**通用三连**:嗅探(重放面)→ 重放(无计数器面)→ 注入(无鉴权面)。

## 1. WPA2 四次握手与 KRACK

```
AP                          STA
 │ M1(ANonce) ────────────►│
 │ M2(SNonce,MIC)◄─────────│  PT KDF(ANonce,SNonce,PMK)
 │ M3(KCK MIC) ───────────►│  ← KRACK:重放 M3 → STA 重装已用 key
 │ M4(MIC) ◄───────────────│     nonce 复用 → TKIP/GCMP 明文恢复/注入
```

- 从WPA2四次握手看KRACK密钥重装攻击(2018 峰会议题文字版,协议层攻击范本)
- 要点:KRACK 打**客户端**不打 AP;修复靠 key reinstall 防护(802.11 补充修订)。
- WPA3:Dragonfly(SAE)握手侧信道+降级(Dragonblood);社区无专帖;降级面(强制回退 WPA2 过渡模式)与蜂窝降级([SDR与无线.md](SDR与无线.md))同理。
- WPS Pixie-Dust:离线爆破 WPS pin(打 Reaver 型 WPS 注册协议 E-S1/E-S2 弱随机,工具线 pixiewps/reaver);社区散见于无线破解帖(wpa2 psk 破解原理、802.11 包注入为同族无线破解正本)。

## 2. WiFi 固件漏洞

WiFi 固件(博通/赛普拉斯芯片,CVE-2017-9414 Broadpwn 等):《在高度流行的 WiFi 芯片固件中发现漏洞》(WiFi 芯片固件 so 审计正本);Broadpwn(BCM43xx WiFi 固件 RCE→安卓提权)为该方向的标志性案例;方法论=固件 so 逆向同 [../iot/固件提取.md](../iot/固件提取.md) §6。

## 3. 实用攻击面帖群

- 打造Wi-Fi "DOS"攻击工具——Wi-Fi_deauther(deauth 帧广播,ESP8266 即可)
- 非加密Wifi环境中抓取其他主机无线数据流(monitor 模式+Wireshark)
- 打造属于自己的渗透神器——wifi-ducky(BadUSB over WiFi)
- wifi安全(基础科普)
