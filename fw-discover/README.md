# fw-discover · Firmware Static-Candidate Triage

Maintain a queue of publicly released DD-WRT/OpenWrt images and a local candidate
ledger. This branch discovers static observations rather than matching component
versions against a CVE table. A rule hit is a hypothesis; the
[verification and disclosure workflow](cve-pipeline.md) separates authenticity,
novelty, reachability and evidence for reporting.

## Local Firmware Through the Runner

```bash
re-run analyze --asset /absolute/path/to/rootfs --type firmware --output re-runs
re-run analyze --asset /absolute/path/to/firmware.tar --type firmware --output re-runs
```

The runner accepts extracted rootfs trees and bounded TAR/ZIP/gzip input.
Opaque filesystems require the appropriate isolated extractor provider; indicator
scans are not proof of successful extraction. The current format/depth matrix
is in the [runner guide](../docs/runner.zh-CN.md), with remaining work in the
[execution handoff](../docs/agent-completion-prompt.zh-CN.md). The optional static
analysis battery is described in [static-scan-tool-matrix.md](static-scan-tool-matrix.md).

## Legacy Public-Image Queue

```bash
python3 fw-discover/fw.py --seed    # discover/deduplicate public catalog seeds
python3 fw-discover/fw.py --once    # one small download/extract/analyze batch
python3 fw-discover/fw.py --status  # local progress; default action
```

State, original images, extracted trees and the ledger live under ignored
`data/fw-discover/`; they are not part of a public clone. The script uses kernel
file locks, atomic state updates, approved catalog hosts, bounded downloads and
gzip expansion, and at most three container-stripping layers. Original inputs
are preserved. Only successful analysis becomes `done`; retryable download or
analysis failures have finite attempts, while unavailable extraction or scope
mismatches become `blocked` with recorded reasons.

**The legacy script does not automatically execute unsquashfs/sasquatch on the
host.** Without an isolated extractor adapter it records the opaque filesystem
as blocked. Queue completion does not mean every firmware was analyzed.
Already extracted rootfs trees remain usable through the unified runner.

## Rule Meaning

| Class | Priority | Observation | Still to establish |
|---|---|---|---|
| verified-weak-cred | 4 | Local password/hash comparison matched | Account enabled, login surface, product impact |
| shipped-private-key | 4 | A private-key block is present | Usability, deployment trust, exposure and impact |
| cmdi-candidate | 1 | Network-source and system/popen/exec strings co-occur in a file | Caller, parameter propagation, configuration and reachability |
| cmdi-script | 3 | Suspicious shell/CGI use of external parameters | Actual input control and trigger behavior |
| telnetd-enabled | 2 | Startup text enables telnetd | Effective default configuration and exposure |
| default-cred | 2 | Configuration contains a password literal | Whether that credential is active/default |
| hardcoded-account | 1 | Account text contains an active hash | Runtime account use and authentication path |

The shared analyzer ignores symlinks. Legacy classification names do not map to
the unified runner's `verified` status. The 100-entry milestone is a candidate
triage target, never a confirmed-vulnerability count.

## Screening and Finite Continuation

Review the top 20 candidates by priority: inspect command callers and input flow
(e.g. r2 cross-references), validate private-key structure, and retain the exact
local credential-reproduction command. Save screening evidence under
`data/fw-discover/screening/`. Security-policy violation, exploitability and
impact scope must be supported before disclosure preparation.

```bash
uv run --no-sync bash fw-discover/keepalive-fw.sh
```

The wrapper requires the prepared runner environment, calls
`python -m re_runner.keepalive --profile firmware`, and retains a maximum of
40 rounds at a default 1800-second interval. It stops when no retryable queue
entries remain; blocked/failed records remain visible. It installs no scheduler,
and its live batch loop was not run during this merge.

Only publicly released firmware images are used by this queue; it does not
access live devices. Dynamic firmware execution belongs in an explicitly
prepared isolated environment, not on the daily host. External reports follow
manual review and [disclosure](../disclosure-cve.md).
