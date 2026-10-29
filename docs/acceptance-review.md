# Coordinating Acceptance Review: Final Acceptance Failed

**Historical review, 2026-10-19**, directory `<repo>`, HEAD `0059a9a`, branch
`codex/readme-review`; implementation was still an uncommitted working tree. Real local static
analysis/report artifacts existed, and the PE/radare2 empty-result repair was effective. However,
all-asset depth, adversarial closure, and reliability did not meet final handoff requirements.
This assessment only read code/docs/existing reports and
checked hashes/references. It did not install, execute analyzers, rerun unittest/ruff, or add
dynamic tests. The execution agent owned fixes and measured retesting.

## Findings

| ID | Priority | Acceptance blocker | Effect |
|---|---|---|---|
| F1 | P1 | Artifact enumeration/accounting rechecks already-triggered cancellation/deadline | Current ToolRun/usage absent from terminal report; recovery accounting not accepted |
| F2 | P1 | Exported report schema rejects real error/tool statuses | Downstream blocked/failed/timed-out reports violate contract; empty-success test misses it |
| F3 | P1 | Unseparated long string triggers quadratic email redaction outside tool deadline | Adversarial output can stall coordinator; flood test retains only 4 KiB |
| G1 | Incomplete | Dynamic unpacking/mobile instrumentation/AI behavior/deep adapters/OS CI absent or unaccepted | Full-chain/adversarial goal cannot be accepted |

These priorities concern this tool's reliability/delivery, not a reproduced remote exploit of a
third-party target. Source line numbers below identify the **reviewed historical version**.

## Root Causes, Triggers, and Surfaces

### F1: Real Cancellation/Timeout Interrupts Settlement

[runner.py](../src/re_runner/runner.py), lines 219–239, calls `_artifacts(..., self.budget)`
(line 226) after run_command but before cancel/timeout settlement. [intake.py](../src/re_runner/intake.py)
iter_tree calls budget.check(); [safety.py](../src/re_runner/safety.py), lines 234–246, check/consume
throws when cancel exists or deadline expires. Thus real cancellation exits during enumeration;
even bypassing it, `_consume_attempt_usage` line 275 calls consume and stops again.

An on-disk journal can sometimes be reread during resume, but current terminal usage, ToolRun,
and accounted are incomplete. `tests/test_runner_robustness.py:53` calls the consumer directly,
without cancel file/expired deadline/full Runner; its pass does not prove real cancellation.

### F2: Report Producer and Contract Disagree

[contracts.py](../src/re_runner/contracts.py):128 restricts coverage.error to string/null;
line 164 restricts errors items to string. [runner.py](../src/re_runner/runner.py):419–423 emits
`{code,message}` objects and [reporting.py](../src/re_runner/reporting.py):48–64 preserves them.
contracts.py:150 restricts ToolRun.status to RunState STATES, but
[execution.py](../src/re_runner/execution.py):209–226 returns timed-out/output-exceeded/
budget-exceeded, which Runner records directly. `tests/test_schema_export.py:35` checks only a
handwritten empty succeeded report; it omits actual blocked/failed/cancelled/tool-timeout output.
Report production did not validate REPORT_SCHEMA. Bidirectional contract acceptance was unsupported.

### F3: Redaction Outside Monitoring Has Unbounded Complexity

[safety.py](../src/re_runner/safety.py):35 uses unanchored
`[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}`. A long word run without @ repeatedly scans suffixes.
[execution.py](../src/re_runner/execution.py):236 calls redact_text synchronously after kill/reap,
without remaining-time/cancel checks or worker isolation. The default output cap is **1 MiB**;
bounded bytes do not bound algorithmic cost. test_output_flood_is_bounded retains **4096 bytes**,
and FakePipe likewise shrinks input. Marking the issue nonblocking conflicted with adversarial
availability. This review inferred complexity from code and did not measure runtime; execution
must measure it.

### G1: Missing Code Versus Missing Environment

planning.py registered only private-key-possession; protections.py returned
`bypass_executed: false` and next_routes. Useful plans did not implement isolated dynamics,
failure-signature/hypothesis scheduling, alternate observation, dump reconstruction, or behavior
controls. JADX/Apktool/S0–S4, isolated firmware extraction, tshark, interprocedural source tools,
AI behavioral oracle, and contract fork/compiler lacked wiring, not merely installation.
Some acceptance section-8 commands only installed/probed/read chains and could not create absent
stages. Device/license conditions could remain pending; independently implementable adapters and
CI configuration could not all be classified as environment gaps.

## Evidence Independently Checked

| Run | Content | Artifact hashes | Evidence refs | Result |
|---|---|---:|---:|---|
| historical-run-02 | 21 local fixtures, actually 11 categories | 164 matched | 52 valid | 12 candidates, 0 verified |
| historical-run-03 | 5 text examples | 35 matched | 10 valid | 0 findings |
| historical-run-04 | PE/radare2 | 10 matched | 2 valid | 513 functions, 48 instructions, 0 verified |

Report/state, request hash, ToolRun artifacts, and finding→evidence matched on read-only review.
This establishes internal consistency, not independent replay or general accuracy. Web was absent
from fixtures/examples; separate local Web and WebSocket/gRPC/chain tests existed, but used temporary
artifacts. Complete original unittest/ruff logs were absent from this handoff. Source contained
**106 test methods**; **105 pass/1 skip** remained the execution agent's record, not rerun evidence.

Independent version digest scope: `src/ tests/ examples/ pyproject.toml uv.lock`, caches excluded,
**55 files**, relative paths sorted ordinally; concatenate `UTF-8 path + NUL + lowercase content
SHA256 + LF`, then SHA256:
`a46da90bd8efafaa7e8908cd5010167d2affddd8e20838bab4ccd383ccf4920f`.
The execution record's 96-file digest lacked exclusions/algorithm and was not directly comparable.

### Required Execution Gates

1. Start a real run with nonzero usage, create cancel.request, then compare state/ToolRun/journal/
   counters/accounted; resume must not double count. Include expired deadlines and validator cancel.
2. Have actual Runner produce succeeded/degraded/blocked/failed/cancelled, timeout/output-cap reports;
   validate all with exported schema and stable error/status types.
3. Measure no-@ long strings at default cap and growth sizes with whole-coordinator watchdog/cancel;
   a 4 KiB buffer test is insufficient. Save actual timings.
4. Complete missing code separately from environment blockers; every adapter produces ToolRun/
   Evidence. Protection fixtures require baseline, positive/negative controls, trigger/failure
   signatures, and bounded alternatives.
5. Preserve original unittest/ruff/integration logs, version digest, per-category oracle/run;
   distinguish CI configuration from actual Windows/Linux/macOS results.

## Accepted Scope and Remediation

Accepted intermediate work: shared entry, recorded local structure analysis, bounded evidence
reports, actual radare2 functions/assembly. This did not establish every-format/device L0,
generic L2, or adversarial acceptance. F1/F2 harm failure reports/automation; F3 harms termination
on hostile inputs. The execution core awaited real boundary tests.

Separate stopping new work from bounded settlement/evidence/journal validation/atomic accounting.
Cancellation/expiry must still settle prior usage without clearing cancel or double counting after
partial failure. Share error/execution-state contracts, validate produced reports, and test failure
paths. Bound redaction complexity, isolate if needed, and keep deadline/cancel control over the
coordinator. Continue with [acceptance-remediation-prompt.md](acceptance-remediation-prompt.md).
Preserve historical records; new acceptance requires new evidence, not the old 105 passes.
