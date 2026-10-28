# IoT Protocols, Malware, and Industrial Control


## 1. MQTT protocol security

```
Publisher ──PUBLISH(topic)──► Broker(1883/8883) ──push──► Subscriber
                                 │
                                 ├─ Authentication: anonymous/weak passwords/anyclean as a common default
                                 ├─ ACL: topic-level authorization; `#` wildcard subscriptions receive all topics
                                 └─ Topics provide routing without pre-creation; any client may pub/sub if access is unrestricted
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
Scanner (telnet 23/2323 weak-password list + CVE list) → infection → download architecture-specific payload
(busybox wget/tftp) → execute → report to C2 (hardcoded domain) → join DDoS/mining/proxy operations
Architectures: x86 x64 ARM ARM5 ARM6 ARM7 MIPS MIPSel PPC SPARC SH4 M68K
Anti-debugging: watchdog-feeding thread + self-attach with ptrace(PTRACE_TRACEME)
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
