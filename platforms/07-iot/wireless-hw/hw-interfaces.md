# Hardware Interfaces: Identification, Extraction, and Chip-Level Attacks


## 1. Master Table of the Four Debug Interfaces

```
         ┌─────── Device PCB ───────┐
  UART ──► TX RX GND (3–4 pads in a row; the most common layout)
  JTAG ──► TCK TMS TDI TDO RST GND (8–14 pins/test points)
  SPI  ──► CLK MOSI MISO CS + VCC GND (attached Flash chip)
  I2C  ──► SDA SCL + VCC GND (attached EEPROM/sensor)
         └────────────────────────┘
```

| Interface | Purpose | How to identify | Tools |
|------|------|--------|------|
| UART | system console (prints + shell) | find GND with a multimeter; TX idles high; a row of 4 holes | USB-TTL (PL2303/CP2102/FT232) + Dupont wires |
| JTAG | boundary scan / halt the CPU / dump | chip datasheet + test-point silkscreen | JLink/OpenOCD |
| SPI | read the attached NOR/NAND flash | look up the flash chip silkscreen (W25Q64/EN25Q/MX25L) in the datasheet | CH341A + SOIC8 clip / flashrom |
| I2C | read small EEPROMs (24Cxx) | silkscreen such as 24C02 | same as above (CH341A supports I2C) |

## 2. UART in Practice (the router first shot)

Representative threads: "Basic router debugging 1: locating the UART" (locating method + manual baud-rate probing), "Getting started with router vulnerabilities — the Tenda F6 on TTL" (TTL = the colloquial name for UART), and the "Huawei ONT HG8245H unbricking notes" series (UART unbricking + a full rescue flow).

Steps:
1. Open the board and find the pads (a row of 4 points/holes along the board edge); 2. multimeter black probe on GND, red probe hunting for a TX that idles at 3.3V; 3. hook up USB-TTL with RX←TX crossed; 4. `screen /dev/tty.usbserial 115200` (115200/57600/38400 are the usual suspects); 5. power on and watch the prints, press Enter for a shell — or mistype the password three times and wait for dropbear.

## 3. SPI/Flash Dumping

- **Clip approach**: SOP8 test clip + programmer (RTL8185/CH341A/NorWriter), no desoldering needed; the head-unit thread demonstrates the full run from teardown to a `flashrom` read (see [../iot/firmware-extraction.md](../iot/firmware-extraction.md) §3).
- **Powered in-system read**: clamp the SOIC8 clip onto the flash chip and run `flashrom -p ch341a_spi -r dump.bin` from the host; when the board's own supply conflicts with the programmer's, isolate first (cut VCC or lift a resistor).
- After dumping, run `binwalk -E dump.bin` to inspect the entropy profile and judge whether the image is encrypted (→ [../iot/firmware-decryption.md](../iot/firmware-decryption.md)).

## 4. SWD: Dumping STM32/MCUs

ARM Cortex-M uses SWD (two wires, SWDIO+SWCLK). ST-Link/JLink + OpenOCD, `flash read_bank 0 fw.bin`; with read protection (RDP), the Level1→Level0 downgrade erases the flash, and Level2 requires a voltage glitch (§7). For the supporting reverse-engineering, see [../iot/firmware-extraction.md](../iot/firmware-extraction.md) §6.3.

## 5. Bus Protocols: RS-485/CAN/USB

- **RS-485** (half-duplex differential, A/B two-wire; the mainstay of building intercoms and industrial sensors): "Reverse-engineering the 485 control protocol of a DiX building intercom" (RS-485 half-duplex bus protocol reverse engineering, UART frame format + vendor-private command set recovery, sniff → replay → command table).
- **CAN**: see [automotive.md](automotive.md); **USB protocol analysis**: USBPcap + Wireshark (a smart-hardware getting-started thread).
- LoRa: "Modifying the LoRa firmware library to support receiving corrupted packets".

## 6. Dev Boards and Forward Development

The reverse engineer's "build it yourself once" side:
- The Arduino family (11 threads in digest 17: programming and applications / basics / syntax / simple experiments / serial communication / components and modules / with Teensy / with robots / WiFi communication / a DIY IoT router).
- Raspberry Pi: the Raspberry Pi B basics series + "Building a Bluetooth debugging environment on a Raspberry Pi" (→ [ble-zigbee.md](ble-zigbee.md)).
- An STM32 board as an automotive tool: "Hands-on automotive UDS diagnostics with an STM32 dev board" (→ [automotive.md](automotive.md)).
- DIY: "Developing a WiFi device from zero", "A USB Rubber Ducky clone in 10 lines of code", "Building your own NFC watch".
- Hardware interface types: the USB/HID thread cluster (analyzing the USB HID device interface protocol, HID communication analysis of a USB dongle, a summary of Windows USB function-driver development).

## 7. Side-Channel and Fault Injection (chip attacks)

A four-thread set from the community:
- A clock-glitch attack to bypass a password check
- Differential power analysis to recover an AES key (DPA: collect N power traces, align them, group by key hypothesis, take the difference of means)
- Power analysis to crack a password
- Clock fault injection

The principles in one breath: a glitch = break the timing at the instant of a conditional branch so the jump misfires; DPA = CMOS power draw correlates with the Hamming weight of the data being processed. Equipment: the open-source ChipWhisperer kit is the mainstay. For the glitch fallback when U-Boot is locked, see [../iot/firmware-extraction.md](../iot/firmware-extraction.md) §2.

## 8. Appendix: Attack Surface → Tools Quick Reference (the whole wireless-hardware area)

| Surface | Core tools |
|----|----------|
| UART | USB-TTL |
| SWD | ST-Link/OpenOCD |
| SPI/Flash | CH341A/flashrom |
| M1 | Proxmark3/ACR122U (rfid-nfc.md) |
| WiFi | aircrack/ESP8266 (wifi-security.md) |
| BLE | nRF/BLECTF (ble-zigbee.md) |
| Zigbee | KillerBee/CC2531 (ble-zigbee.md) |
| SDR | rtl-sdr/URH/HackRF (sdr-wireless.md) |
| GSM | C118+OsmocomBB (sdr-wireless.md) |
| CAN | CANable/SavvyCAN (automotive.md) |
| UDS | STM32 board (automotive.md) |
| Side channel | ChipWhisperer (this article, §7) |
| UEFI | UEFITool/IDA (bios-uefi.md) |
