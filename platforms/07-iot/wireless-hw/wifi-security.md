# WiFi Security


## 0. The Wireless Security Master Outline

Attacker's-eye layering: `physical (radio) → link (802.11/15.4) → protocol-stack implementation → application semantics`. Each medium gets its own article; **the universal triple**: sniffing (the replay surface) → replay (surfaces without counters) → injection (surfaces without authentication).

## 1. The WPA2 Four-Way Handshake and KRACK

```
AP                          STA
 │ M1(ANonce) ────────────►│
 │ M2(SNonce,MIC)◄─────────│  PT KDF(ANonce,SNonce,PMK)
 │ M3(KCK MIC) ───────────►│  ← KRACK: replay M3 → STA reinstalls an already-used key
 │ M4(MIC) ◄───────────────│     Nonce reuse → TKIP/GCMP plaintext recovery/injection
```

- "Understanding the KRACK key-reinstallation attack from the WPA2 four-way handshake" (the text version of a 2018 conference talk; a model protocol-layer attack)
- Key points: KRACK hits the **client**, not the AP; the fix is key-reinstall protection (an 802.11 supplementary revision).
- WPA3: Dragonfly (SAE) handshake side channels + downgrade (Dragonblood); no dedicated community thread; the downgrade surface (forcing fallback to the WPA2 transition mode) works just like the cellular downgrade ([sdr-wireless.md](sdr-wireless.md)).
- WPS Pixie-Dust: offline cracking of the WPS pin (attacks the weak randomness of E-S1/E-S2 in the Reaver-style WPS registration protocol; the tool line is pixiewps/reaver); scattered across the community's wireless-cracking threads (the "WPA2 PSK cracking principles" and "802.11 packet injection" threads are the same-family originals).

## 2. WiFi Firmware Vulnerabilities

WiFi firmware (Broadcom/Cypress chips, CVE-2017-9414 Broadpwn etc.): "Finding vulnerabilities in the firmware of highly popular WiFi chips" (the canonical audit of WiFi-chip firmware .so files); Broadpwn (RCE in BCM43xx WiFi firmware → Android privilege escalation) is the landmark case in this direction; the methodology = firmware .so reversing, same as [../iot/firmware-extraction.md](../iot/firmware-extraction.md) §6.

## 3. The Practical Attack-Surface Thread Cluster

- "Building a Wi-Fi 'DoS' attack tool — Wi-Fi_deauther" (deauth-frame broadcast; an ESP8266 is enough)
- "Capturing other hosts' wireless traffic on an open, unencrypted WiFi network" (monitor mode + Wireshark)
- "Building your own pentest gadget — the wifi-ducky" (BadUSB over WiFi)
- "WiFi security" (a basics primer)
