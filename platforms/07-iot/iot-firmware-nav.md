# IoT and Firmware Security (multi-level split · navigation page)

> This article has been split into focused sub-articles under the `iot/` subdirectory; this file is kept as the entry-point navigation. Sister article: [hardware-wireless-nav.md](hardware-wireless-nav.md) (split into `wireless-hw/`); for CTF patterns see [ctf-writeup-methodology.md](ctf-writeup-methodology.md).

## Split Destinations

| Sub-article | Content |
|------|------|
| [iot/attack-surface-recon.md](iot/attack-surface-recon.md) | Attack-surface panorama / standard workflow / device research (watches, locks, cameras, building systems, novel interaction surfaces) / learning path |
| [iot/firmware-extraction.md](iot/firmware-extraction.md) | Five extraction routes / U-Boot manipulation hands-on / SPI dumping / Zyxel / ten-method summary table / binwalk unpacking / static analysis / RTOS load addresses and symbol recovery |
| [iot/firmware-decryption.md](iot/firmware-decryption.md) | Encryption landscape and three approaches / entropy plots / D-Link transitional-version diff method / AES-CBC case study |
| [iot/firmware-emulation.md](iot/firmware-emulation.md) | Firmadyne · FAT / FirmAE (incl. manually reviving a Zyxel device) / QEMU user mode · Qiling / Cisco RV340 full-system emulation walkthrough and the three-step debugging toolkit for fork-style cgi |
| [iot/router-practice.md](iot/router-practice.md) | Command-injection CVE matrix / MIPS · ARM stack overflows / backdoors and auth bypass / fuzzing / Huawei HG532 CVE-2017-17215 hands-on |
| [iot/protocols-services.md](iot/protocols-services.md) | MQTT / CoAP / Mirai-family malware / industrial control (S7comm · PLC worms · Modbus) |
