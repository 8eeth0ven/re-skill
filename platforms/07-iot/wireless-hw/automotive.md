# Automotive Security: CAN/UDS/Keys


## 1. The CAN Bus

```
节点(ECU) ──┐
节点(网关) ──┼── CAN_H/CAN_L(差分,120Ω 双端)── 广播无地址
节点(仪表) ──┘   仲裁:ID 小优先级高;无认证无加密
帧: [SOF|ID(11/29)|RTR|DLC|DATA(0-8B)|CRC|ACK|EOF]
```

- "CAN protocol analysis" (message structure and experimental methods)
- "Hacking the automotive CAN protocol" (an early domestic trailblazer thread)
- Hands-on: the OBD-II port + CANable/Kvaser + SavvyCAN/candump; `cansend can0 123#DEADBEEF` probing ID by ID for semantics (windows/steering/unlock); replaying messages is the fastest verification.
- UDS (the ISO 14229 diagnostics protocol): 0x10 session / 0x27 security access / 0x2E write DID / 0x31 routine — "Hands-on automotive UDS diagnostics with an STM32 dev board"; reversing the seed-key algorithm of service 27 = ECU firmware reversing (back to [../iot/firmware-extraction.md](../iot/firmware-extraction.md)).
- ECU firmware: "A first look at powertrain ECU firmware reverse engineering", "A first look at automotive ECU upgrading", "Implementing an automotive diagnostics tool"
- Head-unit cross-links: the full toolchain for reversing Android-based head units (APK/so/system services) cross-links the techniques library (same as skill re/techniques) (`01-methodology/` and `02-frida/`); the head-unit firmware extraction threads live in [../iot/firmware-extraction.md](../iot/firmware-extraction.md) §3.

## 2. Keys: Fixed Code/Rolling Code/Keyless Entry

- "Playing with fixed codes" (parts 1/2) (direct SDR replay; the preceding article is [sdr-wireless.md](sdr-wireless.md))
- "Grand Theft Auto — playing with rolling codes" (parts 1/2/3) (KeeLoq-class: record + block + predict; a digest-section series)
- "A remote attack on the Model X keyless system", "GhostPeak: a distance-shortening attack on smart-key ranging (a flaw in the relay-defense ranging)", "A not-so-'elegant' way to unlock a car"
- "Reading the Tesla attack cases: hardware reverse-engineering analysis"
- Others: "Vehicle navigation GPS spoofing", "Reverse-engineering the BMW in-car apps protocol", "Analyzing the security issues of a smart car alarm"

## Supplementary Field Cases

### Zero-Cost Entry into Vehicle-Network Security Research
Author: kxliping

A simulation environment approaching a real domain architecture, with no physical car (one machine is enough):

- Architecture: the VCU vehicle-control domain (BDCAN body + ASCAN autonomous driving, joined by a cangw gateway) + the HU infotainment domain (ICCAN instrument cluster + CAMCAN cameras), the domains interconnected over Ethernet; the two Ethernet links are VLAN-separated by security level (ADAS messages and ordinary control messages in separate broadcast domains).
- Vehicle functions simulated with ICSim: `./icsim vcanic` drives the instrument cluster, `./controls vcanbd` simulates body components emitting CAN frames; create the vcan:
```
sudo ip link add name vcanic type vcan && sudo ip link set dev vcanic up   # vcanbd 同理
```
- CAN-ETH cross-domain bridging with cannelloni (SocketCAN over UDP; a single machine tells the domains apart by port):
```
cannelloni -I vcanbd -R 192.168.20.100 -r 20001 -l 20000
cannelloni -I vcanic -R 192.168.20.100 -r 20000 -l 20001 -p
```
- VLAN: `sudo vconfig add enp0s31f6 20/30` creates the vlan-id sub-interfaces; after assigning IPs per subnet, mutual pings losing 100% of packets = isolation achieved.
- A least-privilege firewall (the HU only receives body messages, only sends camera messages): iptables with precise ACCEPT on UDP sport/dport + a catch-all DROP.
- The in-domain gateway: `sudo cangw -A -s vcanbd -d vcanas -e` (one rule per direction); cangw + cannelloni together already approximate a real CAN gateway (a real one also carries LIN/FlexRay).

### Analyzing the Security Issues of a Smart Car Alarm
Author: 0xbird (translation)

IDOR plays against the cloud APIs of aftermarket smart alarms (Viper/Clifford, Pandora):

- The chain: unauthorized API parameter tampering to change any account's registered email → the password reset lands in the attacker's mailbox → account takeover → locate-and-track / unlock the doors / arm and disarm the alarm / kill the engine while driving / remotely open the microphone for eavesdropping (the SOS mic). Roughly 3 million vehicles affected.
- Viper (backend colt.calamp-ts.com): every other API checks authorization; only `POST /users/Update/{uid}` misses it → directly overwrite any user's Email+Password fields for takeover.
- Pandora (pro.p-on.ru): `POST /api/sputnik/workers?id={uid}` — change the email field of the JSON body to overwrite the original email; sequential user IDs are enumerable, and reaching an admin account exposes every vehicle under it.
- The entry trick: both vendors offer free registration of test/demo accounts — no product purchase needed to hold a legitimate session against real account data (the lowest-cost IDOR entry).
- Deep-dive thread of thought: "absent from the UI ≠ absent from the API": the app has no "engine kill" button, yet the API exposes the function; to save wiring, the alarm taps CAN directly and can emit custom CAN frames, and when vehicle-model auto-detection fails it falls back to installer-side local programming (a laptop tool / a Bluetooth app) — analyzing the firmware + manuals + changelogs can surface hidden wireless-programming APIs.
- The impact surface: on affected models (Mazda 6 / Range Rover Sport / RAV4 etc.) one can remotely change the cruise speed and forge brake-pedal messages; the alarms add no extra relay protection and instead open a new attack surface on keyless cars.

### Reverse-Engineering the Automotive Wiring-Terminal Blocks
Author: 星舆实验室

Reverse-engineering the vehicle network starting from ECU wiring terminals, black-box, with no manuals:

- The universal first step: among a pile of pins, find the power pins first (VBAT/IG/GND); only after power-on does hunting for CAN/UART/USB debug ports make sense; the terminal pinout is the map for black-box physical analysis (measured on an A/C controller: A11/A12 = IBUS CAN-H/CAN-L; the sensor/actuator pins separate at a glance).
- Use the gateway terminal as the backbone to map the vehicle topology: 8 subnets — DiagBUS (diagnostics), TBUS (remote monitoring, T-BOX only), EVBUS (energy/powertrain), FCBUS (fast charging), CBUS (chassis), IBUS (infotainment), EBUS (body), and LIN.
- High-value terminal signatures:
  - The T-BOX (exclusive to TBUS): CAN + SPK/MIC (eCall) + wake-up; some models add USB (simulated Ethernet) and a UART debug serial port — the front door to remote vehicle control.
  - The BMS acts as the EVBUS↔FCBUS gateway inside the fast-charging network; the PEU motor controller straddles EVBUS and CBUS (a cross-domain springboard).
  - The combination instrument and the head unit share IBUS and interconnect directly without passing through the gateway: take the head unit and you reach the cluster.
- Fast elimination of non-surfaces: the rear USB has power pins only, no data lines; the cigarette lighter is power only — one glance at the terminal diagram rules them out, saving test time.
- An overlooked control chain: the DVR dashcam hangs on the EBUS body-domain CAN → a contactless vulnerability yields DVR system privileges → enter the body domain → the same-net BCM controls the doors/lights. Everyone stares at the cloud/T-BOX/IVI; the DVR is the under-watched entry (the lab has already taken a production car's DVR privileges in the field).
- Teardown/bench indexing: locate ECUs by harness — T-BOX/EPB/GPS/reversing radar on the body harness; the gateway/OBD port/BCM/PEPS/steering-column lock on the instrument harness; the ADAS front camera/sunroof/rain sensor on the roof harness.

### The Future and Outlook of Vehicle-Network Security in the 5G Era
Author: Editor (SDC roundtable notes; selected viewpoints)

- Four vehicle-network attack directions: the bus/ECU (physical access needed); the vehicle-network chain (app → cloud TSP → T-BOX → body; called TCU in Japan); autonomous-driving sensors (visual adversarial: a straight line recognized as a curve); V2X.
- The hard V2X bottleneck: vehicle-to-vehicle signature verification demands ~3500/s, beyond what current security means can deliver → message-layer attacks are the focus; one forged message propagated vehicle-to-vehicle through the "school-of-fish algorithm" can paralyze traffic over a wide area.
- Cases: the Tesla Model S key used the outsourced, outdated DST40 algorithm — cloned in seconds; the T-BOX has only 512K of storage and cannot fit mobile-grade hardening — protection for resource-constrained systems needs dedicated design.
