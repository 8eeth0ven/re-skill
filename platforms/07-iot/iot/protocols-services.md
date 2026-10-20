# IoT Protocols, Malware, and Industrial Control


## 1. MQTT protocol security

```
Publisher ──PUBLISH(topic)──► Broker(1883/8883) ──推送──► Subscriber
                                 │
                                 ├─ 认证:匿名/弱口令/anyclean 常见默认
                                 ├─ ACL:topic 级权限,`#` 通配订阅=全量窃听
                                 └─ topic 本身即路由:无需预创建,谁都能 pub/sub
```

- "The Cornerstone of the IoT: a First Look at the mqtt Protocol" (the protocol's three roles / the topic mechanism)
- "Xihu Lunjian 2024 IOT Post-Contest Retrospective and mqtt RCE in Detail" (the full chain from a broker implementation bug -> RCE)
- "Getting Started with mqtt Protocol Pwn" (ciscn2025 finals, the broker memory-corruption direction)

The three audit checks: whether anonymous clients can connect / whether the `#` wildcard subscription is gated by an ACL / what rides on the topics (lock open/close, coordinates, tokens).

## 2. CoAP

The REST protocol for constrained devices (UDP 5683); `.well-known/core` open by default = "Hunting CoAP Protocol Bugs on a Certain Device". Tools: coap-client/Copper.

## 3. IoT malware: the Mirai family

### 3.1 Family mechanics

```
扫描器(telnet 23/2323 弱口令表+CVE 表) → 感染 → 下载对应架构 payload
(busybox wget/tftp) → 运行 → 上报 C2(域名硬编码) → 加入 DDoS/挖矿/代理
架构表:x86 x64 ARM ARM5 ARM6 ARM7 MIPS MIPSel PPC SPARC SH4 M68K
反调试:watchdog 喂狗线程 + ptrace(PTRACE_TRACEME) 自挂
```

(flow reconstructed from the Mirai source structure)
- Variant lineage: Satori (vulnerabilities instead of weak passwords for propagation) / OMG (monetization via proxying) / JenX / Wicked / TBOT (group-run operations as of 2024).
- The IoT-side defensive view: change telnet passwords, shut down WAN-side management, patch the CVEs (all pointing at the vulnerability matrix of [router-practice.md](router-practice.md)).

## 4. Industrial-control security

- Protocols: "Parsing Siemens S7comm Read SZL", "Analyzing the CodeSys V3 Protocol and Its Licensing Mechanism"
- Worms: "Schneider PLC Worm Techniques", the BlackHat PLC fuse talk
- Devices: "Beckhoff PLC Bug Hunting", "KUKA Robot High-Risk Vulnerabilities", "ASP File Extraction in the GoAhead Framework" (the Web middleware on industrial devices)
- Firmware: "A Hands-On Reverse of Schneider Controller Firmware", HMI firmware decryption (see [firmware-decryption.md](firmware-decryption.md)), "ICS Device Firmware Extraction and Analysis" (see [firmware-extraction.md](firmware-extraction.md) §3)
- The common protocol-stack base: Modbus TCP (502, function codes with no auth) / S7comm (102) / EtherCAT / Profinet; the infection surface in the PLC-worm post = Modbus coil writes + firmware-to-firmware transfer.

## 5. Cross-links: in-vehicle and hardware protocols

In-vehicle CAN/UDS, RS-485 building intercoms, and the other hardware bus protocols -> [../wireless-hw/hw-interfaces.md](../wireless-hw/hw-interfaces.md) §4 and [../wireless-hw/automotive.md](../wireless-hw/automotive.md).
