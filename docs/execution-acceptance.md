# Historical Execution and Acceptance Ledger

This is a faithful English maintenance edition of the recorded execution ledger. Dates, counts,
hashes, statuses, and claims below are historical evidence, **not results rerun during this
translation**. The source labels an R1/R2/R3 remediation “2026-10-17” after a review dated
2026-10-20; that chronology is preserved rather than silently corrected. It also contains
conflicting squashfs link/status descriptions, called out where relevant. Current code changes
require new verification. Paths under ignored re-runs/tools-env may be absent from a clone.

## Round 3: R1/R2/R3 Remediation Record

Source date: **2026-10-17, local macOS arm64**, responding to
[acceptance-rereview.md](acceptance-rereview.md). The source designates this section and the
round-3 status table as superseding parts of round 2; later 2026-10-20 integration remains below.
Passed/failed/missing-environment/unimplemented are separate.

### Version and Oracle

- Baseline `0059a9a0d0d843dc5f57b26ad8dc87631b963f5e`; the source says a local `git reset --mixed`
  anchored the snapshot without changing files. This is a historical action, not an instruction.
- Digest scope `src/ tests/ examples/ pyproject.toml uv.lock`, **71 files**:
  `e682f933caa02b7c56724d53ae14743b720a2a29e4180354ce476fd6bfceb99b`.
  Reproduction: `python tools/worktree_digest.py`; one additional file versus round-2 70:
  `tests/test_r1_r2_remediation.py`.
- Self-generated mksquashfs oracle: **112 regular files + 3 symlink members + 8 MiB sparse file**,
  SHA256 `d1ad72791a2ade6d552ec0496e31db9b807f22725cc2be3d958133d2036c6c4d`.
  Provenance/license: `tools-env/samples/SQUASHFS-SAMPLE-PROVENANCE.txt`. The attempted fox-it
  download was a 404 page and was not used in this round.

### R1: Preserve Execution/Usage When Artifact Enumeration Fails

Recorded repair/pass: runner.py _artifacts becomes bounded/nonthrowing and returns
`(records,incomplete_reason)`; _invoke/_validate construct/persist ToolRun before usage settlement,
and enumeration failures become explicit incomplete inventories/errors. _intake/
_record_interrupted_intake record interrupted intake and `.incomplete`; intake.snapshot creates
the marker initially and removes it on success. Marker means a partial copy unreferenced by
Evidence; resume rebuilds with interrupted-intake-recovered. Historical directories without the
marker remain rejected.

`tests/test_r1_r2_remediation.py`: **15 tests**, plus persistent runs:

1. Real Runner worker completes with symlink in output: ToolRun retained, incomplete error,
   journal in state.used, accounted=true.
2. Real cancellation plus symlink output: cancelled ToolRun/error/accounted=true; resume succeeds;
   used.files equals intake + all attempt usage journals, with no duplicate count.
3. Directory-intake cancellation: cancelled intake ToolRun and marker persist; resume rebuilds
   with recovery event.
4. Unit gates: caps/link/out-of-root entries do not throw from _artifacts; inventories stay bounded,
   explain truncation, and exclude external-root entries.

Persistent evidence: `re-runs/r1r2r3-verification/r1-cancel/` cancelled-state.json,
resumed-state.json, usage-identity.json; measured **usage=43=1+Σjournals**.
Raw log: `re-runs/logs/round3-verification.txt`.

### R2: Complete 7z Preflight and Write-Time Quotas

Recorded repair/pass with real 7-Zip: extractors.py rejects non-succeeded/flooded/>5000-truncated
listing with extraction_started=false/listing_complete=false. _vet_members applies safe_relative,
depth/per-member/aggregate preflight to every entry and rejects the entire invalid container.
Per-member `7z x -so -spd` streams through quota checks **before each block write**; over-budget
blocks never land, errors record enforcement point, completed members consume usage immediately.
_sweep_irregular unlinks stray links and counts links_omitted. decompile._consume_derived accounts
JADX/Apktool files/unpack_bytes immediately after tool exit and degrades incomplete over-limit trees.

The R2 narrative says symlinks are never created and stored link contents become regular files,
with successful link-containing squashfs. **The status table later records omitted links and a
degraded squashfs result. Both source claims are retained; they are not one unqualified pass.**

ExtractorRefusalTests/PreflightVetTests: **7 tests**, real 7z, plus persistent runs:
listing flood at max_tool_output_bytes=512 refused before extraction; **5100 members** refused;
`../evil` refused with outside sentinel unchanged; **20-level** path refused; listing declares half
actual size, actual stream stops at **48 KB** aggregate with files<16/budget error; declared aggregate
excess refused; valid cpio **2 files/8 bytes** succeeds. The narrative reports self-built squashfs
with embedded PEM and link members succeeded, no symlinks, regularized members.
Evidence: `re-runs/r2-extractor/` round3.sqfs/round3.cpio/result JSON/squashfs-tree.json.
No 7z path-escape reproduction is claimed. Resource limits remain distinct from a malware sandbox.

### R3: Truncation-Aware Redaction

Recorded repair/pass: safety._redact_private_keys redacts unmatched private-key BEGIN through
buffer end. Full-pair old semantics remain; incomplete-pair oracle intentionally changes to safer
semantics. redact_text_truncated removes incomplete AKIA/gh_/sk- token prefixes at truncated tails
with O(1) anchored erasure. execution._settle_output redacts the full retained text before final
truncation, passing reader truncation `sizes[i]>len(buffer)` for tail erasure. kill_tree also handles
PermissionError for reaped pgids.

test_redaction_bounds: **21 tests**, full-pair equivalence plus conservative unmatched BEGIN,
**3×2000 fuzz cases**, cross-boundary/incomplete/partial-token gates; growth/watchdog retained.
Recorded timings: **1 MiB no-@ 26 ms, 4 MiB 117 ms, 1 MiB dense email 127 ms**, [timing] log lines.
Real subprocess sends header+BEGIN+canary, never END; reader truncates at **8 KB**. Execution.stdout,
stdout.log, stderr.log, adapter JSON omit canary and BEGIN and retain conservative marker.
Evidence: `re-runs/r3-redactor/` → `r3-redaction/`: r3-oracle.json/r3-adapter-json.json/stdout/stderr.

### Round-3 Regression and Environment

Android/firmware test tool lookup changed to RE_RUN_* → repository tools → PATH, addressing
hardcoded-host skips. macOS **Android 8/8** actually ran JADX **1.5.6** and Apktool **2.11.1**
(`re-runs/logs/android-round3.txt`); firmware **9/9** ran real squashfs profile, link omission degraded.
UPX tests remained hardcoded at this stage.

Raw `re-runs/logs/unittest-round3-final.txt`: **Ran 198 tests in 226.151s; OK (skipped=20), 0 failed**.
The source describes +18 tests versus 180, unlocking 14 platform-gated 7z/JADX/Apktool skips;
20 macOS skips concern UPX hardcoding/real devices/CI, with reasons in log. Ruff:
`re-runs/logs/ruff-round3.txt`. Dedicated tool `tools/run_round3_verification.py`:
**24 ALL PASS**, log `re-runs/logs/round3-verification.txt`.
Added test_r1_r2_remediation (15); redaction oracle update +3 gates. Local tools:
7z **25.02 Homebrew**, UPX **5.2.1**, mksquashfs, JADX, radare2, explicitly configured via RE_RUN_*.

### Round-3 Status Table

| State | Recorded scope |
|---|---|
| Passed | R1 interrupted intake/validator ordering/cancel+uninspectable output/resume accounting; R2 six refusal cases/write-time quotas/link policy/squashfs-cpio/decompile usage; R3 four output surfaces/boundary/incomplete/partial-token/complexity/growth; ruff; full unittest; persistent 24-oracle directory re-runs/r1r2r3-verification |
| Failed/conditional | macOS UPX module all skipped: test_upx_route hardcodes tools-env/upx-5.0.2/.../upx.exe and .venv/Scripts/python.exe; installed 5.2.1 not wired at this stage. Self-built squashfs with 3 links: extract degraded, links_omitted=3, links omitted; link-preserving scans unimplemented |
| Missing environment | Physical devices/emulator dynamics, fork/testnet, TLS key logs, authorized Apple device, Linux/macOS CI run URLs (workflow present, no URLs obtained) |
| Unimplemented independent work | AAB/JVM depth, Ghidra/IDA adapter, tshark, semgrep, OCI merged/registry, real UBI/TRX extraction, multiround/streaming AI, Vyper, Frida/S3, contract fork; source says the 50-minute budget prioritized R1/R2/R3 |

## Round 2 Historical Record (2026-10-19)

Responded to [acceptance-review.md](acceptance-review.md) F1/F2/F3 and G1. Some claims were
subsequently superseded by round-3 fixes/status and the independent rereview; preserve attribution.

### Version Digest

Branch codex/readme-review, baseline HEAD `0059a9a0d0d843dc5f57b26ad8dc87631b963f5e`, uncommitted tree.
Scope src/tests/examples/pyproject.toml/uv.lock, exclude __pycache__/pyc/.venv; sort relative paths
by UTF-8 ordinal; concatenate UTF-8 path + NUL + lowercase content-SHA256 hex + LF, then SHA256.
Implementation: [tools/worktree_digest.py](../tools/worktree_digest.py), run with Python.
At document finalization: **70 files**, digest
`f85ddf59298ce5f0101eca0144f25c7e4ec2e7dd0f9f84c43bb04efcded210cc`.
Any subsequent scoped change invalidates it; recompute on retest.

### Environment and Dependencies

| Item | Recorded value |
|---|---|
| OS/Python/uv | Windows 10.0.22631 x64, Git Bash; Python 3.12.10; uv 0.11.29 |
| Installation | uv sync --locked --all-extras --group dev; added traffic-deep scapy, source-deep bandit, dev grpcio-tools, updated uv.lock |
| Official external tools | radare2 6.2.4-w64 existing; JADX 1.5.1 skylot/jadx; Apktool 2.11.1 iBotPeaches; UPX 5.0.2 upx; solc 0.8.37 argotorg/solidity (migrated); 7-Zip 25.01 7-zip.org, SquashFS handler confirmed |
| Tool hashes | Local-only tools-env/SHA256SUMS.tools.txt, not Git-distributed |
| Original squashfs oracle | tools-env/samples/gzip.sqfs, SHA256 abbreviated exactly as source `7f0238…8e6e1`; fox-it/dissect.squashfs test data, AGPL-3.0; provenance file beside sample. Later round-3 download/source correction is above |
| Configuration | RE_RUN_R2/JADX/APKTOOL/UPX/7Z/SOLC explicitly set; runner allowlists propagation to workers; doctor resolves/probes versions |

### F1: Cancel/Timeout Settlement

Budget.settling suppresses stop/over-budget exceptions during settlement while recording real usage.
Runner._settlement wraps only post-run_command artifact enumeration/usage; loop-top budget.check
still stops new work. _consume_attempt_usage/_reconcile_interrupted_usage validate the whole journal
before applying, avoiding partial accumulation and resume duplication.

`test_cancel_settlement.py`: **7 tests**, the source called all real Runner.execute paths (later
review distinguishes **4 Runner + 3 Budget** cases). A real worker consumes usage then writes cancel;
cancelled report includes ToolRun, used equals intake+journal per key, active_attempt_accounted=True,
no interrupted-attempt-recovered; resume succeeds with sum of two attempt journals. Expired persisted
wall_budget.deadline_epoch resumes failed/budget-exceeded with prior ToolRun/usage; in-run expiry
records budget-exceeded ToolRun. Verify-level private-key validator cancellation preserves cancelled
validator ToolRun, candidate finding, REPORT_SCHEMA compliance. Recorded accepted, later R1 extended
the incomplete-enumeration branches.

### F2: Report and Exported Schema

Shared _error_schema `{code,message[,asset_id]}` for coverage.error/errors; ToolRun statuses include
STATES plus timed-out/output-exceeded/budget-exceeded. reporting.write_reports validates REPORT_SCHEMA
before persistence or throws IntegrityError. `test_report_contracts.py` **3 tests** + schema_export
**7**: actual succeeded (including existing PE), degraded, blocked, failed; run_command timeout
`python -c sleep 3`, timeout=1; output-exceeded **100 KB versus 2048** cap, injected into actual
write_reports; cancelled covered by F1 validator test. Recorded passed.

### F3: Bounded Redaction Complexity

Measured old email regex: **64 KB no-@ word string 26.5 seconds**, doubling size about ×4.
_assign/_pem shared quadratic patterns and were fixed too. Email uses find(@)-driven linear scan;
assignment atomic group; PEM literal find; control filtering str.translate. Execution settlement
uses linear redaction and explicit **4 MiB** hard cap; no budget.check during settlement, consistent
with F1. Later R3 corrected truncate-before-redact semantics.

`test_redaction_bounds.py`: **18 tests** at this stage. Default **1 MiB 31–78 ms**, **4 MiB 235–484 ms**
(limit <1s); 1 MiB with @ (**17,772 emails**) about **150 ms**. **76 manual + 3×2000 fuzz** cases matched
old output character-for-character; later unmatched-PEM oracle intentionally changed. Actual default-
budget run_command emits 1 MiB no-@ in **0.06–0.38s**, **60s** thread watchdog. Logs under re-runs/logs
include [timing]. Recorded passed.

### G1 Implemented Integrations and Controls

| Capability | Wiring | Positive/negative oracle | Recorded run |
|---|---|---|---|
| Android S1 | decompile.py JADX classpath/Apktool jar → mobile, RE_RUN_JADX/APKTOOL | 8 android tests: Manifest/smali, actual expanded DEX Fixture.java; corrupt APK degraded/signature; unconfigured skipped | Two checks succeeded, 4 decoded artifacts/1 Java source; android-smali-telephony-identifier candidate |
| Firmware extractor | extractors.py 7z → source_firmware, RE_RUN_7Z, squashfs/cpio | 9 firmware tests: actual gzip.sqfs **106 files** into scan_tree; cpio positive; corrupt degraded; unsupported UBI/TRX raw+degraded | Fixture TAR correctly uses native path; squashfs tests exercise 7z |
| Traffic reassembly | profiles.traffic.deep_reassembly, scapy, missing dependency skip | 6 traffic tests: segmented TCP HTTP, zero token leaks, missing scapy skipped, corrupt pcap degraded | **1 HTTP stream from 7 packets**; fixed worker ProgramFiles omission preventing Scapy import |
| Source rules | scanner.py bandit → source_firmware._rule_engine PATH | 6 tests: B602/B605/B506/B404, coexist AST, missing bandit skipped | Bandit **1.9.4**, 1 finding/1 dangerous API; bandit-high-dangerous-api candidate |
| UPX static unpack | unpackers.py → binary, RE_RUN_UPX, PE indicator only | 3 tests: packed succeeds, entropy **7.913→6.502**, UPX sections disappear/size grows; unpacked fails NotPacked; no config skipped | Fixtures had no UPX marker, correctly not triggered; executed:true only on actual unpack success; bypass_executed remains false |
| AI behavioral oracle | special.behavior_probe, **7 fixed canaries**, ai-test + scoped service | 6 tests: safe mock succeeds, vulnerable mock **7 ai-oracle-refusal-failure** candidates, unreachable degraded, missing operation ScopeDenied | ai-test wired; limitation says behavioral oracle, not model-internal detection |
| Contract compile | compilers.py solc → special, RE_RUN_SOLC | 5 tests: Vault.sol ABI and contract-unprotected-state-mutating candidate; syntax error degraded/stderr; no config skipped | contract-compile-solc succeeded |
| Doctor matrix | capabilities.py adds 7z/upx/solc/bandit/scapy, RE_RUN_* resolution/probes; JADX/Apktool/7z/solc marked Wired | 7 doctor tests with updated assertions | firmware doctor reports runnable 7-Zip 25.01 |

### Persistent Full-Chain Runs

Raw logs: `re-runs/logs/unittest-final.txt`: **180 tests / 179 passed / 1 Windows symlink-permission
skip / 0 failed, 98.4s**; `re-runs/logs/ruff-final.txt`: All checks passed.

| Path/run under re-runs/results/ | Status | Notes |
|---|---|---|
| 20261019T125138Z-4eaa1d38edf4, fixtures | succeeded, 14 findings | **22 assets = 11 local categories + traffic-http**; actual JADX/Apktool/Bandit/solc/Scapy; 21→22 assets still 11 categories, Web absent |
| 20261019T124756Z-2f9ed1996ce0, examples | succeeded | 5 assets |
| 20261019T124759Z-b8edfb788c26, PE/radare2 | succeeded | 3 checks; 513 functions/48 instructions established in earlier run |
| 20261019T125220Z-b61faa6e3b1b, Web | succeeded | Local service, 1 password-form candidate |
| 20261019T125221Z-c221c0de6e7d, OpenAPI | succeeded | Local service |
| 20261019T125222Z-c2411613cae5, GraphQL | succeeded | Local service |
| 20261019T125223Z-b6899c3ffa92, WebSocket | succeeded | Actual handshake |
| 20261019T125224Z-8c9e80c5d945, gRPC | succeeded | Reflection demo.Echo |
| 20261019T125225Z-b6b37d14a796, chain | succeeded | JSON-RPC eth_chainId/getCode, **0x7a69=31337** |

Six local-service runs: **6/6 succeeded**. Harness [tools/local_services.py](../tools/local_services.py),
rerun via tools/run_local_acceptance.py; summary re-runs/local-acceptance-summary.json.

### Round-2 Acceptance States

**Passed as recorded:** F1 normal stop/expiry/accounting/resume, F2 schema across real statuses/
producer validation, F3 complexity/growth/watchdog, 180-test/ruff record, seven integrations above
with controls/failure signatures, six real local-service runs. Later reviews narrow these claims.

**Conditional:** squashfs degraded on Windows due to symlink permission, while cpio covered success.
The source claimed privileged/developer hosts would automatically succeed; the rereview rejected
that generalization. Fixture UPX route correctly did not trigger; success evidence existed only in
real UPX **5.0.2** tests, not persistent fixture run.

**Missing environment (original classification):** real Android/iOS/serial (descriptors accepted,
not physical devices); emulator/Frida S3 and authorized Apple decrypted acquisition; local fork/
testnet endpoints (no mainnet transactions; Forge unwired); dynamic sandbox/VM (Job/rlimits are
resource controls, macOS hard memory missing); one symlink traversal skip; TLS key logs. Later
review separates unwired Forge/sandbox code from genuine external prerequisites.

**Unimplemented independent work:** Java/JVM/AAB depth (APK-only JADX/Apktool); Ghidra/IDA/REA,
tshark, semgrep (Bandit Python-only); OCI registry/merged/Docker-save; UBI/TRX (7z 25.01 no handler,
nonzero-offset embedded squashfs not routed); AI multiround/streaming; Linux/macOS actual acceptance
(CI configuration local `.github/workflows/acceptance.yml`, absent from current Git publication;
host config required; matrix core/fixtures/schema; Windows locally run, Linux/macOS need first URLs);
Vyper lexical-only and multi-root solc imports.

Scope correction: **21, later 22, fixtures represent 11 local categories**, enumerated in source as
api/graphql/android/aab/apple/binary×3/source/firmware/container/sbom/traffic×3/device-descriptor/
ai×3/contract×2. Web was never included. Separate local-service runs establish Web/WS/gRPC/GraphQL/
chain. next_routes differs from executed:true; bypass_executed remains false. Static unpack/lexical/
rule hits stay candidates; only private-key validator with complete controls assigns verified.
Fixture run had **0 verified**, consistent with no guaranteed vulnerability claim.

### Historical Retest Commands

These commands describe the round-2 baseline, not a request to execute them during maintenance.

```bash
python tools/worktree_digest.py  # then 70 files and round-2 digest
uv sync --locked --all-extras --group dev
uv run --no-sync python -m unittest discover -s tests -v  # then 180/179/1 skip
uv run --no-sync ruff check src tests pipeline/env_scan.py
export RE_RUN_R2=<radare2.exe> RE_RUN_JADX=<jadx-directory> RE_RUN_APKTOOL=<apktool.jar> \
       RE_RUN_UPX=<upx.exe> RE_RUN_7Z=<7z.exe> RE_RUN_SOLC=<solc.exe>
uv run --no-sync python tests/fixture_factory.py re-runs/fixtures
uv run --no-sync re-run analyze --manifest re-runs/fixtures/manifest.json --output re-runs/results
uv run --no-sync python tools/run_local_acceptance.py  # ports 8765–8767 free
uv run --no-sync re-run schema --output re-runs/schemas
```

Minor remaining items at that stage: report.md renders dict errors with str(item) (readability,
not JSON/schema); Bandit no directory exclusion (huge tree times out/degrades); JADX imei() has
one type-inference warning with body restored; intake cancellation can lose ToolRun (later R1).

## Integration Record Dated 2026-10-20

- Full regression: **Ran 243 tests, OK (skipped=31)**; raw
  `re-runs/logs/unittest-round3-final2.txt`. Environment-gated skips explicit. Ruff agreed scope
  src/tests/pipeline/env_scan.py: **All checks passed**. Wider repository scan found **7 E402** in
  outside-protocol migrated areas such as cve-hunter; recorded without altering protocol scope.
- Lane A: UBI/TRX/OCI merged/registry v2 (actual registry:2 container push/pull), Ghidra headless
  adapter (real bpalogin **251 functions/8 decompilations**), **23/23**.
- Lane B: real Frida attach, Vyper **0.4.3** compile, S3 actual moto endpoint; AI streaming at
  contract level; contract fork explicitly missing anvil; **15/15**.
- Lane C: platform-independent UPX three lanes (**7 real tests passed**, PE runs only if present),
  actual Semgrep **1.181.0**; tshark not installed.
- Sensitive scan: **2** `/Users/Zhuanz` absolute paths in test_a_lane changed to
  RE_BPALOGIN/RE_GHIDRA_HOME gates. Both modes tested: no vars **23 OK/4 skip**, vars present all real
  tests passed. Credentials/device names **0**. SECURITY-AUDIT.md ignored, not published.
- Digest **79 files**; source directs recomputation with tools/worktree_digest.py, without a fixed
  digest in this subsection.
- Still unverified, separately recorded: first three-OS CI URLs, physical devices/emulator,
  anvil fork, tshark, jffs2 extraction, real AWS/AI endpoints. Configuration presence is not a pass.
