# Firmware Extraction and Unpacking


## 1. Extraction: five routes

| Route | Precondition | Cost | Output quality |
|------|----------|------|----------|
| Vendor site / FTP download | None | Very low | May be an encrypted package (needs firmware decryption) |
| OTA man-in-the-middle | A controllable app for capture | Medium | Yields the upgrade package + the download-URL structure |
| U-Boot console | A UART port (../wireless-hw/hw-interfaces.md §1.2) | Medium | The factory image off the real device (including partitions never released officially) |
| SPI/NAND chip-off | Soldering / a clamp fixture | High | The most complete (including runtime data) |
| Backdoor account / interface | None | Low | Straight to a shell, then dump |

Representative posts: the two "D-Link Firmware Analysis Record" articles (the vendor-site route), "Getting Started with Smart Hardware" (the OTA route), "Manipulating a Certain Router with uboot" (the U-Boot route), "In-Vehicle Hardware Analysis and Firmware Extraction" (the SPI route), "Those Backdoors in Wireless Routers: the D-Link Edition" (the backdoor route).

## 2. U-Boot extraction and "manipulation"

U-Boot is the de-facto standard embedded bootloader. Once the serial port (UART) is hooked up, interrupt with `Hit any key to stop autoboot` to drop into the U-Boot shell; common commands:

```
# Inspect the partition layout (typical SPI NOR layout)
=> printenv bootargs mtdparts     # MTD partition table passed to the kernel
=> mtdparts default; mtdparts
# Three operations for memory/Flash extraction
=> md.b 0x9F000000 0x100    # Memory display at the Flash memory-mapped base address
=> sf probe 0; sf read <RAM> <FL_OFF> <LEN>   # Read SPI NOR into RAM
=> md.b <RAM> <LEN>          # Dump in chunks, or use tftp <RAM> to upload to the host
```
(base addresses/offsets differ per vendor; trust `printenv` and the board schematic)

Foolproofing notes: on some devices U-Boot is locked (autoboot cannot be interrupted, password-protected); the fallbacks are the `bootdelay` race, glitch hardware attacks (../wireless-hw/hw-interfaces.md §1.6 side channels), or going straight to an SPI chip-off dump.

## 3. SPI/Flash chip-off dumping (the tooling side is detailed in ../wireless-hw/hw-interfaces.md §1)

- **The clamp method**: an SOP8 test clip + a programmer (RTL8185/CH341A/NorWriter), no desoldering; the in-vehicle post demonstrates the full run from teardown to a `flashrom` read.
- **Live in-system reading**: an SOIC8 clip grips the flash chip while the host runs `flashrom -p ch341a_spi -r dump.bin`; when the board's power supply conflicts with the programmer's, isolate them (cut VCC or lift a resistor).
- After the read, run `binwalk -E dump.bin` for the entropy profile: high-entropy regions = encrypted/compressed, low-entropy = the firmware body — **step one of judging "is it encrypted"**.
- The same playbook on the ICS side: "ICS Device Firmware Extraction and Analysis".

### 3.1 U-Boot "manipulation" of a router in practice: from interrupting autoboot to porting telnet

A ZTE ONU (ZX279127S/8S family, 360T6GV2) walkthrough, ARM:
1. Interrupt autoboot over UART into the U-Boot shell (`h` lists all commands: md/mw/cp/nand/tftp/printenv/setenv/saveenv/bootm...).
2. `printenv` shows bootargs without init -> `setenv bootcmd '...init=/bin/sh;bootm 0x440001e0;'` + `saveenv` -> `bootm` errors with `can't get kernel image!`: pull the u-boot-2013 source and grep the error string to locate the uimage header check (64B header, magic `0x27051956`).
3. `md.b 0x440001e0 100` is all garbage (the kernel never got loaded into memory) -> hand-carry per the boot log's NAND partition table (kernel0@0x200000): `nand read 0x44000000 0x200000 500000` -> `md.b 0x440001e0` now shows `27 05 19 56` + `Linux Kernel Image` -> `bootm` succeeds.
4. But `init=/bin/sh` panics (error -2) -> switch to the filesystem route: binwalk the official firmware, grep the programs for the string `close console` to locate `/bin/cspd` (the culprit that closes the console after boot) and patch it out; blank the root password field in `/etc/passwd`.
5. Repack jffs2: `mkfs.jffs2 -d ./fs_1/ -l -e 0x20000 -o jffs2.img --no-cleanmarkers`.
6. The tftp environment: install `tftpd-hpa` on the PC, add `--create` to `TFTP_OPTIONS`, `chmod 777 /var/lib/tftpboot`, direct ethernet (serverip=192.168.1.100); in uboot, tftp the file into RAM, `nand write` it into the rootfs partition, reboot -> a root shell straight on the console.
7. Porting telnet: `objdump -s --section=.comment Simulator` identifies buildroot+glibc -> configure buildroot 2017.05 for the firmware's ARM/ELF32/LSB/EABI5, `make busybox-menuconfig`, enable telnetd, copy the built busybox into /bin, add `busybox2 telnetd` autostart to `/etc/rcS.d`, repack and flash.

Pitfalls: changes living only in RAM are lost — they must hit the flash via nand write; domestic ONUs can open telnet directly with the chinadsl toolchain.

## 4. Zyxel firmware extraction (hands-on)

"Zyxel Device Firmware Extraction" (2024): while responding to the Zyxel VPN unauthenticated RCE, the official `.bin` upgrade package turned out to be a **password-protected ZIP image**, and a plain `unzip` fails. Two routes: (1) extract directly from the already-decrypted partition on the device side; (2) locate the ZIP-password generation/storage logic in the device firmware (vendors often hardcode the passphrase inside the upgrade-validation program). Later from the same vendor: "Practicing Zyxel Router Firmware Emulation with FirmAE" (firmware-emulation.md).

## 5. The extraction-methodology master table

"A Few Breakthrough Points in Smart-Device Bug Hunting" ("ten firmware-extraction methods + uboot firmware extraction + vendor backdoor accounts"): the ten methods, summarized: vendor site / OTA / debug port / uboot tftp / flash chip-off / backdoor-account telnet / firmware-decryption back-derivation / memory DMA / partition dump / the after-sales toolchain; the full hands-on of uboot extraction is in §3.1.

## 6. Firmware unpacking and static analysis

### 6.1 After the one-shot binwalk

```
$ binwalk -Me fw.bin
├── squashfs-root/          ← Full Linux root filesystem in 99% of cases
│   ├── bin/ sbin/ usr/bin  ← busybox + vendor programs (httpd/goahead/cfm)
│   ├── etc/init.d/rcS      ← Startup script: service initialization
│   ├── htdocs/web/         ← Web frontend + .cgi entry points
│   ├── etc/passwd shadow   ← Common locations for hardcoded credentials
│   └── lib/                ← Shared-library dependencies (architecture: readelf -h)
├── *_jffs2 / *_ubifs       ← JFFS2/UBI (UBI requires ubireader_extract_image)
├── *_cramfs                ← Older devices
└── yaffs/xiaomi.etc        ← Vendor containers requiring manual parsing; see the Huawei optical-modem case
```
(for ubifs scenarios, when `binwalk -Me` fails switch to `ubireader_extract_images`)

**Architecture identification**: `readelf -h squashfs-root/bin/busybox` -> MIPS little/big-endian (the router mainstream), ARM (the camera/watch mainstream), x86 (industrial PCs).

### 6.2 The three must-read spots

1. `/etc/init.d/rcS`: the list of services started at boot -> the attack-surface inventory.
2. `htdocs/web/*.cgi` or `www/`: the Web entries -> a command-injection hotspot (router-practice §1).
3. `strings -n 8 httpd | grep -Ei "passw|secret|key|token"` + `/etc/passwd`: hardcoded credentials (the DWR-932B post confirmed a weak root password and a backdoor).

### 6.3 RTOS/MCU firmware (no filesystem)

Bare firmware without an FS (MCU/VxWorks/RT-Thread/RTEMS):
- **Load address**: if the base is wrong when IDA loads the raw bin, every reference flies off. "Firmware Security: Load-Address Analysis": back-derive the base from the vector table / string cross-references (the STM32 post takes the same approach).
- **Symbol recovery**: when the VxWorks symbol table has been cut, recover via the residual `symtab` structures: "Exploring vxworks Filename Recovery".
- **Algorithm restoration**: for private encryption/checksum algorithms in firmware, run the function directly as a black box with Unicorn: "Analyzing the Algorithms in Firmware with unicorn".
- **Uncommon CPUs Ghidra can't open**: **Ghidra-Rare** (github.com/aleph-void/Ghidra-Rare) ships SLEIGH processor modules for rare ISAs — TI PRU, AMD/Xilinx MicroBlaze, XMOS xCORE (XS1/XS2/XS3), TI C7x DSP, NVIDIA GPU SASS (Kepler→Blackwell), Zilog Z8, ST9 — plus community modules collected from GitHub and unmerged Ghidra PRs, tested and fixed. Drop the per-ISA extension zip into `Ghidra/Extensions/` and reboot Ghidra; release builds track the three newest Ghidra releases (v1.0.0 2026-10-25, zip structure smoked). When binwalk extracts firmware whose `readelf -h` says an architecture stock Ghidra rejects, check here before hand-rolling a loader.
- Full cases: "An Embedded Firmware Reversing Session", "A Simple STM32 Firmware Analysis", "STM32 Firmware Reversing", "An STM32 Firmware Dump Tutorial" (STM32 dumps go over SWD, ../wireless-hw/hw-interfaces.md §1.3).

### 6.4 Automated scanners

- **EMBA** (the full firmware-security-audit suite bundling binwalk + CVE matching + NVD comparison): "EMBA Installation, Usage, and Source-Code Analysis".
- Fact/Firmwalker and peers; the conclusions agree: **scanners only surface leads; bug qualification must come back to a human reading the cgi/so** (the community-post consensus).
