# BLE Bluetooth and Zigbee


## 1. The BLE Stack and Attack Surface

```
GATT (services/characteristics: data model, read/write/Notify)
ATT (attribute protocol: handle reads/writes)
L2CAP / SMP (pairing encryption)
LL (link layer: frequency hopping across 37 data channels + 3 advertising channels)
```

Attack surface: **pairing without encryption (Just Works)** → man-in-the-middle; **unauthenticated characteristics** → arbitrary read/write (most cheap devices); **broadcast provisioning information** → sniffing.

Community thread cluster (CTF + field work in one):
- "Getting into BLE through BLECTF" (clearing the BLECTF range = a BLE toolchain crash course)
- "BLECTF: a low-energy Bluetooth CTF challenge" (writeup)
- "Analysis of a BLE smart wristband", "Wristband BLE authentication bypass, enabling remote control" (field case in §3)
- Locks: "Cracking the Nokelock Bluetooth lock", "Analysis of a Bluetooth hoof lock", "BLE communication analysis of the YunDing Lockin door lock"
- Advanced: "Bluetooth protocol-stack vulnerability hunting based on simulation" (digging stack-internal bugs with simulation + fuzzing)
- Environment: "A Bluetooth debugging environment on the Raspberry Pi"

Tools: Ubiqua/BLEsniffer/nRF Sniffer/Android nRF Connect; the hci command family.

## 2. Zigbee

- "A brief analysis of the Zigbee attack surface" (NWK/APS layers over IEEE 802.15.4; one network key for the whole net, a replay-unprotected retransmission window, join-flow abuse)
- Tools: Atmel RZUSBstick/KillerBee/Attify-Zigbee; CC2531 sniffer firmware.
- Core conclusion (in-thread): with the network key in hand, the whole network is plaintext; the key is usually hardcoded in the device firmware (back to [../iot/firmware-extraction.md](../iot/firmware-extraction.md) — grep the strings).

## 3. In Practice: BLE Wristband Authentication Bypass — Capture → Reverse the Auth Protocol → Replay Control

Path: phone developer options "Bluetooth HCI snoop log" → bind/operate the wristband in the app → analyze the btsnoop log to pin down the replayable handle/value → replay with nRF Connect / a BLE debugging assistant.

**The recovered auth protocol** (unbound flow; already-bound = one fewer write-key step):
```
APP ──write desc 0x0100 (CCCD: enable notify)──▶ Wristband
APP ──write 0x0100+key(16B)───────────────────▶ Wristband ← write the key first when unbound
APP ──send 0x020002 (request random value)─────▶ Wristband
APP ◀──0x100201+rand(16B)────────────────────── Wristband
APP ──send 0x0300+AES_ECB(key,rand)(16B)───────▶ Wristband
APP ◀──0x100301 (authentication success)/0x100304 (failure)── Wristband
```
(key transported in plaintext + ECB with no IV; deduced to be AES_ECB from the known key/rand/ciphertext triple)

**Vulnerabilities and exploitation**: ① while unbound, you can write **any key** — then just encrypt the random with that key and send it back to pass authentication; ② **writing a key in the already-bound state overwrites the old key** (the originally bound device drops off) — authentication exists in name only. After bypassing, locate the handle+value for SMS alerts / incoming-call alerts / find-wristband in the HCI log; replaying them is remote control of the band.

Pitfall: the comments objected, "isn't the key negotiated via ECDH?" — measured behavior: it is transported in plaintext and can be overwritten; the gap between protocol design and implementation is itself a vulnerability surface.
