# re — Unified Reverse Engineering Knowledge Base & Automation Skill

A single-entry, multi-branch reverse engineering knowledge base: platform taxonomy × technique systems × fully automated execution × tool radar × environment inventory, aimed at authorized security research (CTF / SRC / auditing your own assets).

## Quick Start

1. Read `SKILL.md` (branch routing) or `usage-scenarios.md` (18 scenarios matched by situation)
2. New-machine bootstrap: follow `setup.md` for automatic installation (AI-executable); run `pipeline/env_scan.py` first to save an environment snapshot
3. Starting a hunt: `breach-tables-cve.md` master router → the category breach tables (20+ rows of plays per category)

## Structure

| Branch | Contents |
|------|------|
| `techniques/` | frida scripts (java-layer/native/advanced) / unpacking / attack-and-evasion / per-vendor traffic-capture archives / kernel-level / five-layer function panorama / syscall-chain timing / bypass decision-making / trace in practice / pure algorithm restoration / toolbox |
| `platforms/` | Windows (incl. the win-vuln vulnerability-hunting track) / Android / iOS / Linux / WEB / binary vulnerabilities / smart devices / business / AI / blockchain / root-cause analysis |
| `pipeline/` | Fully automated five-stage APK analysis DAG (input APK → report with zero human effort) |
| `radar/` | Daily tool radar mechanism (discover → catalog → local smoke test) |
| `device-testing.md` | Plug-and-test for phones / microcontrollers (with device-protection discipline) |
| `disclosure-cve.md` | The complete flow from finding to CVE ID |

## Usage Rules

- Use only within authorized scope; see `DISCLAIMER.md`
- Knowledge ingestion rules: body text keeps only ideas and code (no external links / attributions / personal names)

## License

MIT (see LICENSE)
