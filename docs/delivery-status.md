# Delivery History and Execution Handoff

**Historical ledger, 2026-10-19, directory `<repo>`.** The original baseline was `0059a9a`,
branch `codex/readme-review`; all implementation changes were then uncommitted/unpushed.
Coordination and execution were reviewed separately. These are dated records,
not current checkout status or fresh test results.
See [execution-acceptance.md](execution-acceptance.md) for detailed subsequent evidence and
[runner.md](runner.md) for interfaces/limits.

## Implementation Present at Initial Handoff

- `pyproject.toml`, `uv.lock`, `src/re_runner/`: shared CLI, 12 basic profiles, input/scope
  contracts, snapshots, bounded execution, usage journal, file locks, resume/cancel, evidence/reports.
- Protection indicators/escalation routes, static radare2 adapter, private-key positive/negative validator.
- Legacy firmware/CVE helpers: atomic writes/kernel locks, bounded downloads/extraction/retries,
  original retention, unknown novelty semantics, platform inventory, bounded keepalive.
- English/Chinese READMEs, skill routing, competitor review, runner matrix, examples/regressions.

## Initial Tests and Untested Final Edits

The initial regression record reported **74 tests: 73 passed, 1 skipped** for Windows
symlink permission. Coverage included synthetic structure, actual local HTTP/WebSocket/gRPC/
JSON-RPC, adversarial inputs, locks/cancel/resume, legacy helpers. This predates provider/fat
Mach-O/keepalive and final documentation changes, so it does **not** certify the final version.
Real devices and cross-OS CI were not fully accepted.

Read-only inspection of `re-runs/historical-run-01/report.json` showed radare2 6.2.4
exit 0 with `functions=[]` and missing x86 decoder on stderr. The adapter had called that
succeeded; static changes made empty functions/missing assembly degraded and saved version-probe
artifacts. It had not yet been rerun. The receiving agent needed to inspect official plugin
loading, permit only trusted plugin directories, and require nonempty function/reference/assembly
oracles, rather than remove all restrictions. That assessment only read/edited
files; it did not install tools, probe the environment, or execute sample analysis.

## Receiving Agent, First Execution Round (2026-10-19)

The recorded `uv sync --locked --all-extras --group dev` succeeded once; regression/fixes were
completed with detailed evidence in the acceptance ledger:

- **106 tests: 105 passed, 1 Windows symlink skip**; ruff 0 warnings.
- radare2 root cause: setting `R2_PLUGINS_ORDER` to any value in 6.2.4-w64 prevented all plugin
  registration and removed the built-in x86 decoder. Removed that variable; retained
  `R2_NOPLUGINS=1`, `-NN`, `-S` after measured checks. Upgraded analysis to `aaa`, accepted the
  6.2.4 `addr` field. PE rerun `historical-run-04` had three succeeded checks,
  **513 functions + 48 assembly instructions**, replacing empty-result success.
- Fixed fat Mach-O per-slice encryption, CAFEBABE ambiguity, sha256/runtime_markers; five runner
  issues (attempt-directory resume, cancel/timeout accounting, wall-budget persistence,
  cancellation evidence gate, kill/reap). Implemented real `doctor --profile` required/optional
  readiness and `schema` input/report export with tests.
- Recorded fixture run: all 12-category L0 claim, 21 assets succeeded, 12 candidates; examples:
  5 assets succeeded. **Later independent review corrected the local fixtures to 11 categories;
  Web required a separate local service run.** Retain the correction when citing this result.

The original P0 rows and P1 doctor/schema row were marked done by this execution round.
Deep adapters, isolated adversarial dynamics, real devices, and cross-OS CI remained follow-up.

## Receiving Agent, Second Remediation Round (2026-10-19)

After coordinating acceptance failed, F1/F2/F3 were recorded fixed/retested. G1 work added
Android JADX/Apktool, firmware 7z extraction, Scapy traffic, Bandit source, AI behavioral oracle,
solc contract, static UPX route, real local Web/WS/gRPC/chain runs, and CI configuration, each
with positive/negative controls. Recorded total: **180 tests: 179 passed, 1 environment skip**;
ruff passed. The acceptance ledger separates accepted/failed/missing-environment/unimplemented
and defines the version digest. Its section 6 lists Ghidra/IDA, registry, UBI/TRX implementation
gaps separately from real-device/fork/sandbox conditions. Later independent review found
additional R1/R2/R3 blockers; these historical totals cannot certify subsequent changes.

## Original Priority Queue and Acceptance Rules

| Priority | Work | Required evidence |
|---|---|---|
| P0 | Preserve complete working version including untracked files; install/retest core/CLI/recovery | Lock/version, exact counts, logs/run paths |
| P0 | radare2 decoder/empty output, cancel/timeout journal, validator cancellation, fat Mach-O | Nonempty functions/assembly; immediate stop with preserved usage; slice hash/bounds |
| P1 | Real profile required/optional/adapter readiness | Distinguish path/version/protocol/environment/integration |
| P1 | One actual L0 path per 12 categories and per-format matrix | Predefined oracle, artifact hash, completed checks, limits |
| P1 | Mobile/native/firmware deep adapters and static-failure escalation | Tool sessions, replayable evidence, bounded fallback |
| P1 | Isolated adversarial backend/protection controls | Baseline/instrumentation/alternative controls, actual success or specific failure |
| P2 | High-value L1/L2, provenance, schema, OS CI | Validator controls, contracts, actual Windows/Linux/macOS outcomes |

Static re-review should inspect settlement before early cancellation exit, failed/cancelled
validator effects on coverage, cumulative resource/file accounting, slice encryption propagation,
and report hash/redaction-index correspondence. These are review tasks, not claims that every
listed path is vulnerable.

Completion is accepted cell by cell: descriptors are not physical devices, raw firmware scans
are not extraction, version candidates are not vulnerabilities, and skips are not passes.
The [completion handoff](agent-completion-prompt.md) defines the original execution task;
[acceptance-review.md](acceptance-review.md) and [acceptance-rereview.md](acceptance-rereview.md)
record the independent reviews.
