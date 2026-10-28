# Historical Acceptance Remediation Task

Use this with an explicitly assigned execution task in the existing working checkout; preserve
uncommitted/untracked files, avoid reset/clean and unsolicited push/publish. This is the original
post-review brief, not automatic execution authority during documentation maintenance.
Read [acceptance-review.md](acceptance-review.md) and
[agent-completion-prompt.md](agent-completion-prompt.md). Continue authorized installation,
implementation, and testing.

Fix F1/F2/F3 first; do not hide failures by shrinking inputs or relaxing acceptance wording:

1. Historical runner.py:226 enumerates with a cancelled/expired Budget before journal settlement;
   _consume_attempt_usage:275 checks stop again through consume. Separate stop-new-work from
   evidence/complete validation/atomic settlement. Run with nonzero usage before cancellation or
   expiry; assert terminal ToolRun, state.used, journal, accounted and no resume double count.
   Include validator cancel, not only direct helpers without a cancel flag.
2. contracts.py:128/164 expects strings but real errors are `{code,message}`; ToolRun enum omits
   timed-out/output-exceeded/budget-exceeded. Unify models and producer validation. Validate exported
   schema against actual succeeded/degraded/blocked/failed/cancelled/timeout/flood Runner reports,
   not a handwritten empty success.
3. safety.py:35 scans no-@ word strings quadratically; execution.py:236 redacts in the unmonitored
   coordinator after tool monitoring. Default **1 MiB** input can stall it. Bound complexity and
   cover redaction with total deadline/cancel. Measure default and growing sizes under an external
   watchdog; do not reduce the buffer to **4 KiB** as a workaround.

Then finish the original gaps: isolated dynamic/protection alternatives, Android JADX/Apktool/
S0–S4, isolated firmware extractor, deep traffic/source, AI behavioral oracle, contract compilation/
fork, CI. Installation/doctor runnable is not wiring; require ToolRun, Evidence, oracle. Reserve
requires-environment for genuine devices/licenses/accounts and finish all independent work.

Correct evidence scope: 21 fixtures cover **11 local categories**; Web is a separate network test.
Preserve real Web/WebSocket/gRPC/chain run logs. Descriptors are not devices and next_routes are
not bypass execution. Protection acceptance needs baseline/controls/failure signatures/bounded
alternatives/behavior restoration; mark bypass only from actual evidence.

After each acceptance fix run necessary regression/integration, preserve raw unittest/ruff logs,
exact counts/skip reasons, working-digest algorithm and run paths. Update
[execution-acceptance.md](execution-acceptance.md) with passed/failed/missing-environment/
unimplemented. Existing 105 passes or report existence cannot close the task. Return code,
evidence, and remaining work for coordinating re-review.
