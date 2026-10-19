# fw-discover · Autonomous Firmware Vulnerability Discovery (0day candidates, not CVE matching)

**Division of labor with ../cve-hunter**: cve-hunter is the "known CVE × version matching" N-day ledger; this side **discovers on its own** — download public router firmware → unpack the filesystem → mine candidates with the rules in this directory (`analyzers.py`). Every entry comes from local static analysis, not from a lookup table.

**To land a real CVE, read [`cve-pipeline.md`](cve-pipeline.md) first**: candidates → four kill-gates (dual evidence / novelty / reachability / PoC) → disclosure-ready → manual reporting; the tally ledger lives in there too. For the static-scan battery's installation and dual-lane usage see `static-scan-tool-matrix.md`.

## Pipeline

```
Seed queue (DD-WRT betas, real router firmware + OpenWrt factory images as the unpack-chain validation channel)
  → download (curl; DD-WRT sits behind the Anubis anti-bot, must go through curl's default UA — urllib gets blocked by the challenge page)
  → magic-number scan (TRX HDR0 / uImage / squashfs four byte-orders / gzip, strip at most 3 layers)
  → unsquashfs 4.7.5 unpack (old modified lzma variants won't unpack → flagged and skipped; sasquatch no longer builds on macOS, dropped)
  → six analyzer rule classes → findings.jsonl + ledger
```

## Discovery rules (all local rules; a hit is a candidate)

| Class | Priority | Meaning |
|---|---|---|
| verified-weak-cred | 4 | DES hash in passwd/shadow cracked locally by a small wordlist (verified with `openssl passwd -crypt`) |
| shipped-private-key | 4 | PEM private key shipped in the firmware |
| cmdi-candidate | 3 | Network parameter sources (QUERY_STRING/websGetVar/nvram_get, etc.) × system/popen/exec family within the same binary |
| cmdi-script | 3 | CGI/shell script eval consuming external parameters |
| telnetd-enabled | 2 | Boot script launches telnetd by default |
| default-cred | 2 | Non-empty default password literal in nvram/config |
| hardcoded-account | 1 | Account with an active hash in passwd/shadow |

## Usage

```bash
cd fw-discover
python3 fw.py --seed     # build the seed queue (dedup + incremental)
python3 fw.py --once     # process a small batch: download → unpack → discover (repeatable; single-instance lock)
python3 fw.py --status   # progress
```

Data lives in `../data/fw-discover/` (queue / findings / ledger / firmware and unpack trees). Target is 100 entries, **half-hour keepalive**: `keepalive-fw.sh` (runs `--once` while below 100; once the target is hit it announces the move to the manual/subagent screening stage and wraps up).

## Screening stage (mandatory after hitting the target; human or subagent)

The ledger holds candidates, not conclusions. Pull the top-20 by priority: ① for cmdi-candidate, use r2 `axt @ sym.imp.system` to check whether the caller function actually takes parameters (false-lead pattern: boot-time-only calls); ② validate private keys with `openssl rsa -in <f> -check -noout`; ③ for weak credentials, write out the reproduction command. Write output to `../data/fw-discover/screening/`; an entry only moves on to disclosure after passing the three questions (security-policy violation + proof of exploitability + impact scope).

## Red lines

- Everything in the ledger is an **autonomously discovered candidate**; auto-submitting to any external platform is forbidden; external reporting goes through a human + `../disclosure-cve.md`
- Dynamic emulation (FirmAE / qemu system-mode running the firmware live) is the next stage — not done on this macOS machine
- Only test publicly released firmware images; never touch live devices
