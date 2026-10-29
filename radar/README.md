# Reverse-Engineering Tool Radar (continuous discovery → learning pipeline)

Continuously discover new reverse-engineering-related tools on the internet, evaluate them, and let them flow into the knowledge base. Driven by daily scheduled automation when configured in the host (see `../setup.md` §7); an agent can also run a round manually at any time by following the "discovery process" below.

## Files

| File | Purpose |
|------|------|
| `baseline-tools.md` | Known-tools baseline (entry count at the top of the list), used for diffing; **after cataloging a new tool it must be appended to this list**, otherwise it will be rediscovered |
| `discovery-log.md` | Incremental on-disk log of each discovery round (date / tool / link / one-liner / disposition) |
| `mcp-test-report.md` / `tool-test-report.md` | Dated local MCP/tool observations (what worked then and how it was used; rerun relevant probes for current status) |

The log and two observation reports are optional machine-local records excluded from Git;
a fresh clone may not have them. Create the English discovery log when recording a new round.
The public [setup guide](../setup.md#3-python-re-environment-tools-env) defines venv/tool preparation.

## Discovery process (each round)

1. **Discovery sources** (in priority order; on rate-limit, move to the next):
   - GitHub Search API: `https://api.github.com/search/repositories?q=topic:frida+topic:android created:>N days ago` / `reverse-engineering`, `android`, `ios`, `ghidra`, `unidbg`, `dynamic-analysis` and other topic combos; `sort=stars`
   - GitHub trending: WebFetch github.com/trending?since=weekly, filter for RE-related repos
   - awesome-list diffs: recent commits of awesome-reversing / awesome-android-security / awesome-frida / awesome-ghidra
   - New posts on security-forum tool boards (WebSearch site:bbs.kanxue.com tools)
   - New tools from Hex-Rays / Google Project Zero / developer blogs
2. **diff**: grep each new tool name against `baseline-tools.md`; keep only what the baseline lacks
3. **Evaluate**: for each new tool, read its README/GitHub and judge — star count and growth / whether it solves a problem the library doesn't yet cover / whether it's actively maintained. Mark ★ on the ones worth cataloging
4. **Learn & catalog** (★ items): Edit into the wiki by category — Android RE tools → the matching category in `../techniques/05-toolbox/tool-master-table.md` (+ a dedicated article when necessary); cross-platform/other → the matching section under `../platforms/`; also **append the tool name to the baseline list**
5. **Local smoke test (everything installable must be tested)**: python-family → from the skill root, after `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python <pkg>`, verify via import/version; CLI family (brew / direct download) → run `--version` or a small sample after installing; record the result in the log as "smoke: ✓/✗ reason". Use the configured venv interpreter with uv; do not infer a missing package from a missing pip executable. For MCP probes, use a task-owned directory permitted by the host sandbox rather than assuming /tmp is accessible. A historical local keystone/Python 3.13 incompatibility requires a current compatibility check before choosing the interpreter. Optional `tool-test-report.md` contains dated observations, not required setup instructions
6. **Persist**: append to the discovery log `## YYYY-MM-DD | N discovered, M cataloged` + table (tool | link | one-liner | category | cataloged ✓/✗ | smoke); the round ends when all results are written

## Rules

- Only reverse-engineering / security-analysis tools (no vulnerability PoC collections, no tutorial repos)
- Insufficient information (unreachable / empty repo): log only, do not catalog
- Catalog entries follow library conventions: no author names / exact star counts; status uses "usable / new / unmaintained"

## Portable Intake and Baseline Route

Use the [known-tools baseline](baseline-tools.md) for discovery deduplication.
For host-specific interpreter, cache, SDK, and installation choices, follow the
[host compatibility guide](../docs/compatibility.md) and the setup authority it
links. The earlier `/tmp` and `bin/python` smoke command is a POSIX example, not a
Windows instruction. Record smoke results with host OS/architecture, exact tool
version, date, scope, and evidence kind; one host's smoke does not certify another.
Keep raw per-task logs in the task workspace and promote only the reusable result
and its bounded evidence through [knowledge intake](../docs/knowledge-engineering.md).
