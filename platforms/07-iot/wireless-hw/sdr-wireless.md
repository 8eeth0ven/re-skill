# SDR and the 4G/5G Baseband


## 1. The SDR On-Ramp

```
rtl-sdr(2832U+R820T2,~100元) → GNURadio(流图) → 分析/重放
   │                            │
   ▼                            ▼
433/315 遥控抄表            inspectrum 看时频
HackRF One(发射+宽带)        Universal Radio Hacker(解调/重放 GUI)
```

## 2. The SDR Community Thread Cluster

- "Software-defined radio in smart-hardware vulnerability hunting" (the master thread: from remote controls to protocol recovery)
- "Intercepting RF signals to crack a residential community's license-plate recognition system" (capture a 433 MHz remote → replay to open the gate)
- "A guide to cloning wireless keys" (a rolling-code primer; extends [automotive.md](automotive.md))
- "Sniffing DJI PHANTOM 3 remote-control signals"
- "A method for finding and killing the hidden cameras in budget hotels" (an RF-detection application)

Typical flow: `rtl_sdr` capture → eyeball the pulses in inspectrum → URH auto-demodulation (ASK/FSK) → extract the frame format → replay with HackRF; if rolling codes show up, move on to the rolling-code series in [automotive.md](automotive.md).

## 3. 4G/5G and the Baseband

### 3.1 The System and Attack Surface

```
手机 ── IMSI(明文,GSM/部分LTE) ──► 基站
        A3/A8 COMP128(卡侧)          │
        A5/1 A5/2 空口加密(弱)       ▼
                          伪基站(IMSI catcher):伪造小区强制驻留→下发短信/吸费
5G:SUCI 加密 IMSI(公钥隐藏)+ 网络对卡鉴权增强 → 伪基站大幅失效,但降级(5G→2G)仍是现实面
```

### 3.2 Thread Cluster and Methods

- "Rogue base stations and over-the-air interception" (the GSM one-way authentication flaw: the SIM cannot authenticate the network, so active attacks are inherently unsolvable — the rogue-base-station primer thread)
- The GSM sniffing/station-building toolchain: "Building a small SMS base station with the Motorola C118, Osmocom-BB, and OpenBTS", "Building your own base station to send SMS with osmocom + c118 + openbts", "Osmocom-BB GSM-SMS sniffing under Kali", "Getting started with GSM sniffing"
- The SIM side: COMP128 collision cloning (the COMP128-1 pair-compression attack, and "Rooting SIM Cards" breaking a COMP128-2 variant — both external classics); the cellular-network discussion thread (reflecting downgrade/dual-SIM-slot issues).
- Baseband-chip reversing: Qualcomm baseband .so files (a ready-made surface: the .so analysis thread cluster in 02-android); no dedicated baseband thread in the community — the route = reverse the baseband firmware per the RTOS/load-address method in [../iot/firmware-extraction.md](../iot/firmware-extraction.md) §6.3; the rogue-base-station thread cluster is the over-the-air original.
