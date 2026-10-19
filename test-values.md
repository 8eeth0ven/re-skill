# Test Value Conventions (Recognizability First)

> Every injected/constructed test value must be **recognizable at a glance, greppable, and low-collision**: seeing it in memory, traces, responses, or logs tells you it's a probe; at wrap-up, grep once to confirm zero residue. When old snippets contain low-recognizability values, replace them in place per these conventions.

## I. Unified Value Families

| Scenario | What to use | Example | Why |
|------|--------|------|--------|
| hook/trace log prefix | `[RE]` / `[REPROBE]` | `console.log('[RE] onCreate', ...)` | Zero collision with the app's own logs (TAGs/Chinese); grep `\[RE\]` collects them all |
| Memory-write probe / magic value | `0x52455052` ("REPR") | `ptr.writeU32(0x52455052)` | ASCII-readable, shows as REPR in hexdumps; avoids deadbeef/cafebabe and other common values watchers look for |
| PoC/replay constructed value | string `REPROBE-<date>-<seq>` | `REPROBE-20261016-001` | Unique, traceable to the test day; locatable if it leaks into production data |
| Test account / phone number / ID | Obviously fake segments | `13800138RE` / `probe_<date>@re.local` / id as `910000000+seq` | Avoids real number-segment business logic; risk control can recognize them as tests |
| On-device file/process names | unified prefix `re_` | `/data/local/tmp/re_fs`, `re_probe.js` | Wrap-up `ls /data/local/tmp/re_*` clears them in one go |
| Memory search value (value-editing cases) | segment-style: e.g. coins as `95270001` (non-round, non-zero) | — | Integers/0 collide heavily; segment-style values hit uniquely |
| Trace marker labels | `re_tag_<n>` | `re_tag_hook1` | Tell your own markers apart at a glance in the call tree |

## II. Forbidden List (high-collision / already watched)

- Trivial values like `0x42/0x41/123/test/aaa/111` — they're everywhere in business data; you can't confirm "I wrote that"
- `deadbeef/cafebabe/badc0de` — "debugger traces" that debugger/anti-cheat signature libraries watch for; using them exposes you
- Empty strings / all-zero probes — indistinguishable from uninitialized data
- Fully well-formed real phone numbers/emails — risk control may hurt real people; a `RE` segment is mandatory

## III. Verification and Wrap-up Loop

1. **Before injection**: pick values per the table above; sequence numbers increase monotonically within one task so repeated experiments stay distinguishable
2. **During verification**: grep the value-family strings in responses/memory/traces to confirm arrival (not "probably arrived")
3. **At wrap-up** (hooked into device-testing §I.4 and the unattended master control's closing):
   - `grep -r "\[RE\]" <artifact dir>` should leave only your own logs
   - On the device side, `ls /data/local/tmp/re_*; ps -A | grep re_` to confirm emptiness
   - Grep replayed traffic for `REPROBE-` to confirm no test value leaked into real submissions
4. unicorn/emulation layers likewise: demo values use the `0x52455052` family (replacing the old 0x42 example); when checking register results, state where the expected value came from
