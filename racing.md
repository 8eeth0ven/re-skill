# Multi-Approach Racing (Never Get Stuck in a Dead End)

> Iron rule: **for the same goal, think up at least 3 routes, actually test them all, and pick the one that works; after 2 consecutive failures on a single route, switch — never spin in a dead end.** "In app testing you can swap out the earlier function" — the same holds everywhere: functions, layers, tools, and paths are all swappable equivalents.

## I. Dead-End Signals (switch routes the moment one appears)

- The same approach fails 2 times in a row (re-tuning parameters and failing again counts)
- You start repeatedly tweaking the same detail while the essence of the problem is unchanged
- You've waited on / depended on an uncontrollable condition for over 10 minutes (device not plugged in / permission unobtainable / gateway unreachable)
- The approach's premise got falsified ("it should have root" — it doesn't)

## II. Four Classes of Equivalent Substitution (unfold along these when no route comes to mind)

| Substitution class | App/hook scenarios | Other scenarios |
|---------|--------------|---------|
| **Swap the function** | Can't hook function A → hook its upper-level caller or lower-level implementation (open↔openat↔fopen↔syscall) | Bug won't trigger via entrance A → go via entrance B (component/protocol/parser) |
| **Swap the layer** | Java layer detected → JNI layer → libc → svc → kernel (the five layers of techniques/09) | Web API locked down → mini-program client → app client; static parsing fails → dynamic trace |
| **Swap the tool** | frida detected → gadget/LSPosed/unidbg/static patch (the three lists in tool detection & modification) | jadx crashes → r2; FirmAE won't boot → Qiling/real device |
| **Swap the path** | Direct modification fails → replace the return value / patch the call site / observe via Stalker side channel | Can't fight through → go around (offline replay / change target / change version) |

## III. Racing Process

1. **Propose ≥3 approaches** (unfolded per the table above; include one "least effort" and one "last resort")
2. **Actually test them all** (each approach gets its own minimal verification, with artifacts/output left on record; testing one and declaring another unviable is forbidden)
3. **Best-pick table** (written to the task directory):
   `| Approach | Result (success/fail/partial) | Measured evidence | Intrusiveness/cost | Applicable conditions |`
4. **Write one successful approach into the report**; partially successful ones become backups (switch to a backup if the primary fails — don't return to the dead end)

## IV. Reference Example

Full field test of the five hook approaches racing (attach/replace/equivalent function/Stalker side channel/patching the call site): `techniques/05-toolbox/multi-approach-race-example-hook-five-methods.md` — five routes run against the same target, best pick selected, with a dead-end switching table attached.

## V. Hookup

Discipline item 5 of the unattended master control already embeds this rule; when working manually, read §I and §II of this document first whenever you get stuck.
