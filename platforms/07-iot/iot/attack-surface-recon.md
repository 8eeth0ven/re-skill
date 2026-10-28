# IoT Attack Surface and Reconnaissance


## 1. One diagram for the whole attack surface

```
                        ┌─────────────────────────────────────────┐
                        │            Cloud / mobile app             │
                        │  Cloud APIs · accounts · OTA · push       │
                        └───────▲─────────────────────▲───────────┘
                                │ HTTPS/MQTT/private TCP │ BLE provisioning
                        ┌───────┴───────┐     ┌───────┴────────┐
   LAN attack surface           │ Home gateway/router   │     │ Smart device │
   ├ Web admin UI        ◄──────│ Firmware/kernel/drivers│     │ MCU firmware │
   ├ UPnP/private protocol ◄────│ goahead/lighttpd        │     │ Raw Flash read│
   ├ WAN services        ◄─────└─────────┬───────────────┘     └──┬────┬─────┘
   └ Neighbor devices (SSDP etc.)        │ 802.11                  │    │
                        ┌───────▼───────┐    Zigbee│    │BLE/Zigbee/Sub-1G
                        │ Wireless medium │         lora/433   │    │
                        └───────────────┘          ▼   ▼
                                               RF remotes/sensors
   Physical attack surface: UART/JTAG/SPI debug ports · Flash-chip removal · side channels · fault injection
```
(self-drawn ASCII)

Layered essentials:
- **Firmware layer**: kernel misconfiguration, old busybox/lighttpd/goahead, hardcoded credentials — the birthplace of the overwhelming majority of RCEs (see firmware-extraction / router-practice).
- **Web interface layer**: goahead/lighttpd + cgi (`htdocs/web/*.cgi`) is the most common combo and the command-injection hotspot (router-practice §1).
- **Cloud API layer**: device identity (serial number/MAC) doubles as the credential, predictable tokens, missing OTA package signatures; the community posts concentrate on app reversing (filed under 02-android) plus joint testing against the cloud APIs.
- **Near-field wireless layer**: BLE provisioning broadcasts keys, Zigbee has no replay protection (filed under wireless-hw / BLE and Zigbee).
- **Physical layer**: debug ports, flash chips (filed under wireless-hw / hardware interfaces).

## 2. The standard workflow (the shared skeleton of the community IoT posts)

1. **Get the firmware** (vendor-site download / OTA capture / SPI dump / uboot console / backdoor account — firmware-extraction)
2. **Decrypt** (if there is an encryption header — firmware-decryption)
3. **Unpack** (`binwalk -Me` — firmware-extraction §3)
4. **Comb the filesystem for evidence**: hardcoded credentials, `/etc/passwd`, the rcS boot script, the cgi directory, `strings | grep -i pass`
5. **Emulate or use the real device** (firmware-emulation)
6. **Strike the bugs from the Web/cgi/private-protocol entries** (router-practice / protocols-services)

Representative posts:
- "Getting Started with Smart Hardware" (the USBPcap/Wireshark toolchain and the firmware upgrade mechanism; the top beginner pick)
- "A Smart-Home Security Mind Map" (an attack-surface taxonomy diagram; content merged into §1)
- "An IoT Firmware Analysis Tutorial: How Firmware Is Stored" (the flash-partition-layout foundation)
- "IOT Basic Devices and Firmware Extraction Analysis"
- The aggregated entry point: the smart-hardware board essentials digest

## 3. Device research (watches/locks/cameras/building intercoms/meters)

### 3.1 Smart watches / wearables

- "How to fxxk a Huaqiangbei Watch" (the total-compromise surface of the low-cost watch ecosystem)
- "Analysis and Attack of a Certain Smart Watch"
- "Cracking the Xiaomi Watch S3 to Launch Genshin Impact" (loading arbitrary apps onto a WatchOS-like closed system; cross-link the counterplay ideas in the techniques library `techniques/01-methodology`)
- "Hacking the TomTom Runner Smart Watch" (three parts, see §3.4)
- The companion toy: "Developing a Flipper Zero App with JS"

### 3.2 Locks / building intercoms / cameras / meters / drones

- Smart locks: "A Full Analysis of the Guojia Smart Lock", "The Hikvision Ezviz Lock Gateway", "The Nuki Smart Lock"
- Building intercoms: "Reversing the RS-485 Control Protocol of a DiX Building Intercom" (an RS-485 half-duplex bus protocol reversal, see ../wireless-hw/hw-interfaces.md §1.4)
- Cameras: "A Brief Talk on Network Camera Analysis", "A Camera Reverse-Engineering Journey", "The Xiaotu AI Camera", "the tenda camera"
- Meters: "Smart Meter Security: Communication Analysis"
- Drones: "DJI Drone Security and the DroneID Vulnerability"

### 3.3 Frontier interaction surfaces

- Smart-voice / sonic-provisioning research, voiceprint-spoofing research (parts I and II)
- GhostTouch touchscreen attacks, GhostTalk charging-cable data injection
- "A Capture Scheme for the QUIC Protocol" (the app's cloud-traffic side)

### 3.4 The TomTom Runner smart-watch trilogy (hands-on)

The full flow of hardware teardown -> firmware extraction -> modified re-flash on a low-cost sports watch, the 2017 series that opened up the smart-watch attack surface (the body ships as 3 PDF attachments: part1/2/3); the modern companions are in §3.1 (the Huaqiangbei watch / the Xiaomi S3).

## 4. The learning route (this group's wrap-up)

1. Beginner: the smart-hardware intro post -> the board digest post -> the DIR-815 post (stack overflow) -> CVE-2018-17066 (command injection)
2. Intermediate: the FirmAE emulation posts -> the D-Link decryption posts -> the Qiling posts -> the boofuzz posts
3. Deep water: VxWorks symbol recovery -> the ICS PLC worms -> MQTT/CoAP implementation bugs
4. Every router CVE post shares one meta-method: **get the firmware -> emulate -> find system/xref in the cgi -> verify with packets**; switching vendors only changes the structure, never the method.
