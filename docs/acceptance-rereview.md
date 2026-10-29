# Second Independent Acceptance Review

**2026-10-20: partly accepted, overall not yet accepted.** Evidence supported implemented static
paths and normal cancel/timeout paths, not “all independently executable work complete” or
“all-asset adversarial acceptance.” This round read code/logs/artifacts and independently
recomputed digests/hashes; no install, tests, lint, doctor, analyzers, or samples were rerun.
The defects below are static control-flow conclusions; proposed reproductions awaited execution.

## Independently Confirmed Facts

| Item | Result |
|---|---|
| Baseline | codex/readme-review, HEAD 0059a9a0d0d843dc5f57b26ad8dc87631b963f5e; implementation uncommitted |
| Digest | Independent PowerShell/.NET implementation of documented algorithm: **70 files**, `f85ddf59298ce5f0101eca0144f25c7e4ec2e7dd0f9f84c43bb04efcded210cc`, matches execution document |
| Digest scope | Only src/tests/examples/pyproject.toml/uv.lock; no whole-tree claim about tools/CI/docs/legacy helpers |
| Raw test log | re-runs/logs/unittest-final.txt: `Ran 180 tests in 98.419s`, `OK (skipped=1)`; execution-party result, not rerun |
| Raw lint log | re-runs/logs/ruff-final.txt: `All checks passed!`; not rerun |
| F1 main path | Budget.settling, Runner settlement context, validate-before-apply journal present; tests include 4 real Runner + 3 Budget cases; enumeration-failure branch still R1 |
| F2 | Structured `{code,message[,asset_id]}`, execution enum, producer REPORT_SCHEMA validation and failure/cancel/timeout tests present |
| F3 performance | @ scanning, assignment atomic group, literal PEM scan, translate present; raw timings: no-@ **1,000,000 chars 78 ms**, **4 MiB 422 ms**, dense emails **266 ms**; not independently measured; truncation still R3 |
| Persisted integrity | 9 terminal runs: **270 artifact hashes, 75 evidence references** match; request hashes, containment/reparse, ToolRun/asset/finding refs, state/report usage agree |

| Run under re-runs/results/ | Assets | ToolRuns | Artifacts | Evidence | Findings | Status |
|---|---:|---:|---:|---:|---:|---|
| historical-run-07 | 22 | 44 | 190 | 55 | 14 | succeeded |
| historical-run-05 | 5 | 10 | 35 | 10 | 0 | succeeded |
| historical-run-06 | 1 | 2 | 10 | 2 | 0 | succeeded |
| historical-run-08 | 1 | 2 | 6 | 2 | 1 | succeeded |
| historical-run-09 | 1 | 2 | 6 | 1 | 0 | succeeded |
| historical-run-10 | 1 | 2 | 6 | 1 | 0 | succeeded |
| historical-run-11 | 1 | 2 | 5 | 1 | 0 | succeeded |
| historical-run-12 | 1 | 2 | 5 | 1 | 0 | succeeded |
| historical-run-13 | 1 | 2 | 7 | 2 | 0 | succeeded |

All runs had **0 verified**, consistent with candidate/assertion separation, not itself a failure.
Fixtures had 11 local categories; the twelfth, Web, used a separate service run. New adapters
were substantive: JADX retained `org/example/fixture/Fixture.java` hello()/imei(); Apktool retained
Manifest/smali; Bandit B605; solc Fixture contract, **237-byte** bytecode/ABI; Scapy **7-packet**
HTTP request/response with redacted URL; gRPC `demo.Echo`; chain read chainId **31337**.

## Three Blocking Defects

Historical positions identify the reviewed version, not current line numbers.

### R1 [P1]: Enumeration Failure Still Skips ToolRun and Usage

runner.py:24–32,237–263,369–372; intake.py:149–178. `_settlement()` suppresses Budget stop
conditions, but `_artifacts()` still throws on file/byte caps, and iter_tree can throw on entry
count/depth/link/unsafe path. Enumeration precedes ToolRun recording and usage consumption.
A worker can write nonzero usage, then an unenumerable directory leaves no current profile
ToolRun, state.used unchanged, and accounted false. Normal-stop tests miss this combination;
validator output has the same ordering. Intake snapshot/enumeration can stop before ToolRun
creation; leftover `inputs/<asset-id>/` then blocks resume as incomplete intake.

Preserve enumeration caps. Separate execution fact/error, fixed-journal settlement, and bounded
artifact inventory; save ToolRun/status/error/validated usage/incomplete-inventory marker even
when enumeration fails. Unbounded scanning is not a settlement repair.

### R2 [P1]: Incomplete 7z Listing Still Extracts; Aggregate Limits Apply Too Late

extractors.py:96–109,173–194; execution.py:129–142,182–192. `_parse_listing()` stops at **5000**
without an incomplete marker; non-succeeded listing becomes `members=[]`, yet `7z x` proceeds.
Flood/timeout thus makes preflight look like zero entries/bytes. `_inventory()` counts after
extraction. Windows Job has no directory-total disk quota; POSIX RLIMIT_FSIZE limits one file.
Total disk/file counts can already be exceeded before rejection. JADX/Apktool derived output
also needs actual usage enforcement, not just final inventory rejection.

No complete safe_relative/member/link check occurs before extraction. Post-checks are not
write-time boundaries. This review did **not** reproduce 7z escape/arbitrary host writes; it
confirmed incomplete preflight followed by writes and late aggregate limits. `_inventory()`
skips symlinks while scan_tree rejects them, so privileged squashfs link creation can still fail
the whole profile; extractor exit0 cannot imply automatic full-chain success.

Reject failed/truncated/incomplete listings; validate all member paths/types/links/depth/counts.
Use enforceable directory quota/isolation or controlled per-member streaming into a safe writer.
State resource-control and sandbox capabilities separately.

### R3 [P1]: Truncation Before Redaction Leaks Cross-Boundary PEM Body

execution.py:156–168,199–205; safety.py:152–162. `_settle_output()` truncates at **4 MiB** before
redaction; reader default **1 MiB** likewise truncates raw output. `_redact_private_keys()` retains
unmatched BEGIN when END is absent. Put BEGIN/test body inside the retained region and END beyond
it: a previously complete key becomes incomplete and leaks into stdout/stderr and adapter JSON.
The never_leaks test only put secrets in discarded tails; old semantic controls retained incomplete
PEM verbatim. Use truncation-aware redaction or conservatively redact private-key BEGIN through
buffer end; check logs and secondary JSON, preserving complexity/output bounds.

## Required Next Executions

This round performed only digest/log/integrity review and selected decompiler/compiler/HTTP/
protocol-content checks. The execution agent must save:

1. **R1:** real Runner/controlled worker writes nonzero usage then exceeds max_files/max_unpack_bytes,
   combined with cancel/deadline. Current terminal report retains ToolRun/exact usage and resume
   does not recount. Include validator/intake interruption and malformed/link rejection.
2. **R2:** controlled fixtures for listing flood, >5000 members, deep/empty-directory flood, links,
   invalid members, aggregate bytes with each file below individual cap. Incomplete preflight
   must not launch x; enforce limits while writing and keep outside-root sentinel unchanged.
   Run real squashfs paths with/without symlink privileges.
3. **R3:** synthetic PEM canaries with BEGIN/body inside, END outside **1 MiB** reader and **4 MiB**
   settlement limits. Returned text/stdout/stderr/adapter JSON must omit body. Cover incomplete
   PEM/quoted assignments/tokens, growth sizes/watchdog.

Existing UPX/squashfs controls used TemporaryDirectory; only aggregate unittest logs remained,
so artifacts were not independently hash-recheckable like the nine runs above. Preserve dedicated
Runner runs/oracles/logs and distinguish test-pass evidence from persistent-review evidence.

## Impact and Remaining Scope

R1 breaks complete terminal accounting under hostile/oversized outputs. R2 bypasses declared
preflight/aggregate resources; isolated-extractor/adversarial acceptance withheld. R3 can disclose
private-key output despite improved performance. The nine static runs passed integrity only,
not generalized dynamic/deep/all-format acceptance.

Original implementation gaps persisted: AAB/JVM depth, one deep decompiler, cross-language rules,
OCI merged/registry, UBI/TRX, AI multiround/streaming, Vyper/import layout. Frida/S3, contract fork,
and dynamic sandbox backends also lacked wiring and were not all environment-only. Real devices,
licenses, and TLS keys are separate prerequisites. Three-OS CI existed but Linux/macOS URLs/logs
were absent; host-path-induced skips differ from actual external-tool tests.

Keep the four-state evidence framework, but correct “all 7 are real Runner tests,” “privileged
squashfs automatically succeeds end to end,” and “all independent work complete.” Section 6d itself
listed locally doable unfinished work. Repair R1/R2/R3 first with real terminal/boundary controls,
then complete the 12-category matrix with missing code/environment separately accepted.
[The second remediation handoff](acceptance-rereview-prompt.md) supplies the execution task.
This historical review added documents only; accepted code/logs/artifacts were preserved.
