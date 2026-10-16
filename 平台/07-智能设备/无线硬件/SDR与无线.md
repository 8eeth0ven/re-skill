# SDR 与 4G/5G 基带


## 1. SDR 入门链

```
rtl-sdr(2832U+R820T2,~100元) → GNURadio(流图) → 分析/重放
   │                            │
   ▼                            ▼
433/315 遥控抄表            inspectrum 看时频
HackRF One(发射+宽带)        Universal Radio Hacker(解调/重放 GUI)
```

## 2. SDR 社区帖群

- 软件无线电在智能硬件漏洞挖掘中的应用(总纲帖:从遥控器到协议还原)
- 拦截射频信号破解小区车牌识别(抓 433 遥控→重放开闸)
- 无线钥匙克隆指南(滚动码入门,延伸 [汽车安全.md](汽车安全.md))
- 大疆PHANTOM 3遥控信号嗅探
- 查找和终结快捷宾馆中摄像头的一种方法(射频探测应用)

典型流:`rtl_sdr 采样 → inspectrum 目视脉冲 → URH 自动解调(ASK/FSK)→ 提取帧格式 → HackRF 重放`;有滚动码则进 [汽车安全.md](汽车安全.md) 玩转滚动码系列。

## 3. 4G/5G 与基带

### 3.1 体系与攻击面

```
手机 ── IMSI(明文,GSM/部分LTE) ──► 基站
        A3/A8 COMP128(卡侧)          │
        A5/1 A5/2 空口加密(弱)       ▼
                          伪基站(IMSI catcher):伪造小区强制驻留→下发短信/吸费
5G:SUCI 加密 IMSI(公钥隐藏)+ 网络对卡鉴权增强 → 伪基站大幅失效,但降级(5G→2G)仍是现实面
```

### 3.2 帖群与方法

- 伪基站和空中信息拦截(GSM 单向鉴权缺陷:卡无法鉴权网络,主动攻击无解——伪基站原理帖)
- GSM 嗅探/建站工具链:摩托罗拉C118基于Osmocom-BB与OpenBTS搭建小型短信基站、利用osmocom+c118+openbts自己搭建基站发短信、Kali下Osmocom-BB GSM-SMS嗅探、GSM Sniffing入门
- SIM 卡侧:COMP128 碰撞克隆(COMP128-1 pair-compression 攻击、「Rooting SIM Cards」破 COMP128-2 变体——均外部经典帖);蜂窝网络讨论帖(反映降级/双卡槽问题)。
- 基带芯片逆向:高通基带 so(现成面见 02-Android安全 so 分析帖群);社区无基带专帖,路线=baseband 固件按 [../iot/固件提取.md](../iot/固件提取.md) §6.3 RTOS/加载地址方法逆向,伪基站帖群是空口侧正本。
