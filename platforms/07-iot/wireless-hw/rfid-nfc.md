# RFID and NFC: The M1 Card Encryption System and Its Fall


## 1. The M1 (Mifare Classic) System

```
卡结构:16 扇区 × 4 块(每块 16B);每扇区末块 = KeyA(6B)+访问位(4B)+KeyB(6B)
认证:三次握手 → CRYPTO1 流密码(NXP 专有)
                  │
      ┌───────────┴────────────┐
  明文扇区(0钥匙默认)        加密扇区(默认钥匙改过)
  nested 攻击可恢复          需伪随机数弱点/字典/侧信道
```

## 2. Attack Genealogy

| Attack | Preconditions | Effect |
|------|------|------|
| Default-key dictionary | any card | ~60% of domestic cards fall to one sweep (FKF and other default key lists) |
| Nested authentication | one sector key known | PRNG correlation → recover the other sectors' keys |
| Darkside/NACK | old firmware | parity leaks in the error responses → offline key recovery |
| moebiu/parity bits | fully encrypted cards | needs a sniffer or a reader-side flaw to pair with |
| CPU cards | — | go protocol-level (see §4) |

Community thread cluster:
- "RFID security: a few words on card cracking" (the best system primer)
- "RFID: my M1 offline card cracking run" (offline dictionary cracking in practice)
- "After a fully encrypted M1 card falls" (**the domestic counterpart chip FM11RF08S**: billed as NACK/Nested-proof; the thread lays out a cracking path built on new side-channel/PRNG weaknesses — the landmark 2024 thread in this direction)
- "Understanding ACR122U read/write principles through NFC card cracking" / "An ACR122U rookie's first contact" / "ACR122U control commands and parameters" (access-control/elevator card cases)
- "Data-structure analysis of a certain M1 card", "Cracking a campus all-in-one card quickly", "Cracking a canteen meal card", "Post-mortem on cracking a school water card", "Meal card cracking"
- Contact IC: "Decrypting the 4442 password with the two-card simultaneous method", "Cracking a contact IC card password with logic sniffing"
- ID access-card attacks (EM4100 cloning)

Toolchain: Proxmark3 (full-featured) / ACR122U (cheap) / MTools / a phone's PN53x; **the workhorse combo against fully encrypted cards = sniff one genuine-card authentication (hf mf sniff) → recover the keys offline with mfkey32/nonce2key** (in-thread consensus; command naming follows the official Proxmark3 docs).

## 3. NFC/EMV Advanced

- "An NFC relay attack writeup" (two phones, one near one far, racing the time window)
- "An account of analyzing a CPU card" (CPU cards speak APDU, with a file + key system — no dumping; you fight at the protocol layer)
- EMV bank cards: no dedicated community thread; the system knowledge (SDA static/DDA dynamic authentication, magstripe fallback) comes from the public EMVCo specs — bridge with the CPU-card protocol-layer threads and the NFC relay threads for first contact.

## 4. In Practice: Cracking an M1 Offline Card — the Full "Data-Pattern Reverse Engineering" Flow After the Key

A water-card engagement. Toolchain: Android MCT (read the card, determine which sectors are encrypted) → ACR122U (~150 RMB, run the default-key dictionary) → 010editor to read the dump + color-coded comparison in Excel + CheckTool (parity/checksum derivation); plus two UID-magic blank cards.

**Flow**:
1. MCT read: sectors 10/11 encrypted (default keys cannot read them) → put the ACR122U on a key dictionary → crack succeeds, import into MCT and read the whole card.
2. Locate the business blocks: only block 0 of sector 10 changes with spending (block 2 mirrors block 0; block 1 varies from card to card) — **find the changing blocks before hunting for patterns**.
3. Known balances (e.g. 4.00→49.98) converted to hex and compared: hits the "reversed byte order balance" field; a field that +1s per tap = the tap counter; another field = the running sum of the counter; a pair of fields that are each other's bitwise complement; red + dark-red accumulating = the first blue field; **the XOR of positions 1–14 equals position 15** (checksum 1), **position 2 summed through to the end equals 0xFF** (checksum 2); and one position cycles daily on the "machine calendar" (a date field, out of sync with the natural day — the rollover lands at some afternoon moment).
4. Verify: compose a data set per the hypothesis and write it back to the card → the reader accepts it as normal (the unknown positions measured to vary within 00–09, treatable as random) → the crack closes the loop.

**Pitfalls and methodology** (thread author + comment section):
- Three days hunting patterns, four days tracing data, 100+ sample sets in total; **annotate the field meanings with colors** and then draw the relationship diagram — the fastest analysis posture.
- The check is usually just the "XOR sum + additive sum" pair: pin down the raw data positions first, then invert their arithmetic.
- Writing the same UID onto a different card works unaffected → the business logic only looks at block-0 data; UID/block 1 are irrelevant.
- Comments: some schools' cards add an "every ten values the cycle restarts" extra check (insufficient data will lead you astray); some card systems sync server-side (the clone and the original get charged in sync) — judge offline vs. networked before cloning.
